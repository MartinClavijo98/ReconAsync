#!/usr/bin/env python3
"""
Enhanced Reconnaissance Toolkit (ERT)
Version: 2.0.1
"""

import os
import sys
import subprocess
import shutil
import platform
import asyncio
import argparse
import tempfile
import venv
import time
import json
import csv
import signal
from urllib.parse import urlparse
from datetime import datetime

# Configuration
VERSION = "2.0.1"
DEFAULT_WORDLIST_NAME = "directory-list-2.3-medium.txt"
WORDLIST_URL = ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
               "Discovery/Web-Content/" + DEFAULT_WORDLIST_NAME)
WORDLIST_DIR = os.path.join(os.getcwd(), "wordlists")
OUTPUT_DIR = os.path.join(os.getcwd(), "recon_results")
TOOL_TIMEOUT = 600  # 10 minutes per tool

# Required Tools
TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "dirsearch": "pip install dirsearch",
    "paramspider": "pip install git+https://github.com/devanshbatham/ParamSpider.git"
}

def setup_environment():
    """Setup necessary environment variables."""
    os.environ["GOPROXY"] = "https://goproxy.io,direct"
    os.environ["GO111MODULE"] = "on"
    gopath = os.environ.get("GOPATH", os.path.join(os.getcwd(), "go"))
    bin_path = os.path.join(gopath, "bin")
    if bin_path not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{bin_path}{os.pathsep}{os.environ['PATH']}"

def check_binary(binary_name):
    """Check if a binary exists in PATH."""
    return shutil.which(binary_name) is not None

def run_command(cmd, capture_output=False, timeout=None):
    """Run a shell command with error handling."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True,
            timeout=timeout
        )
        if capture_output:
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        return result.returncode, None, None
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out: {cmd}")
        return -2, None, "Command timed out"
    except Exception as e:
        print(f"[!] Error running command: {str(e)}")
        return -1, None, str(e)

async def run_async_command(cmd, timeout=TOOL_TIMEOUT):
    """Run a shell command asynchronously."""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return process.returncode, stdout.decode().strip() if stdout else "", stderr.decode().strip() if stderr else ""
    except Exception as e:
        print(f"[!] Async command error: {str(e)}")
        return -1, "", str(e)

def install_tools():
    """Install required tools."""
    setup_environment()
    
    # Install Go tools
    for tool, install_cmd in TOOLS.items():
        if not check_binary(tool):
            print(f"[*] Installing {tool}...")
            if tool in ["dirsearch", "paramspider"]:
                ret, _, err = run_command(install_cmd, True)
            else:
                ret, _, err = run_command(f"go install {install_cmd}", True)
            
            if ret == 0:
                print(f"[+] {tool} installed successfully")
            else:
                print(f"[!] Failed to install {tool}: {err}")

def ensure_wordlist():
    """Download default wordlist if missing."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    wordlist_path = os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST_NAME)

    if not os.path.isfile(wordlist_path) or os.path.getsize(wordlist_path) == 0:
        print("[*] Downloading wordlist...")
        ret, _, err = run_command(f"wget {WORDLIST_URL} -O {wordlist_path}", True)
        if ret != 0:
            print(f"[!] Failed to download wordlist: {err}")
            return False
    return True

async def run_recon_tool(tool_cmd, output_file):
    """Run a recon tool and save output."""
    ret, out, err = await run_async_command(tool_cmd)
    if ret == 0 and out:
        with open(output_file, "w") as f:
            f.write(out + "\n")
        print(f"[+] {tool_cmd.split()[0]} results saved to {output_file}")
    elif err:
        print(f"[!] {tool_cmd.split()[0]} error: {err}")

async def main():
    parser = argparse.ArgumentParser(description='Enhanced Reconnaissance Toolkit')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--url', help='Specific URL for directory scanning')
    parser.add_argument('--install', action='store_true', help='Install tools only')
    args = parser.parse_args()

    if args.install:
        install_tools()
        return

    # Setup output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(OUTPUT_DIR, f"scan_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    # Verify tools and wordlist
    install_tools()
    if not ensure_wordlist():
        print("[!] Wordlist missing - directory scanning disabled")

    # Run reconnaissance
    try:
        # Subdomain discovery
        await asyncio.gather(
            run_recon_tool(f"subfinder -d {args.domain} -silent", 
                         os.path.join(output_dir, "subdomains.txt")),
            run_recon_tool(f"assetfinder --subs-only {args.domain}", 
                         os.path.join(output_dir, "assets.txt"))
        )

        # HTTP probing
        await run_recon_tool(
            f"httpx -l {os.path.join(output_dir, 'subdomains.txt')} -silent -json",
            os.path.join(output_dir, "httpx_results.json")
        )

        # URL discovery
        await asyncio.gather(
            run_recon_tool(f"echo {args.domain} | gau", 
                         os.path.join(output_dir, "urls_gau.txt")),
            run_recon_tool(f"echo {args.domain} | waybackurls", 
                         os.path.join(output_dir, "urls_wayback.txt"))
        )

        # Directory scanning (if URL provided)
        if args.url:
            url = args.url if args.url.startswith(('http://', 'https://')) else f"http://{args.url}"
            await run_recon_tool(
                f"dirsearch -u {url} -w {os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST_NAME)}",
                os.path.join(output_dir, "dirsearch_results.txt")
            )

        print(f"[+] Reconnaissance completed. Results saved to {output_dir}")

    except Exception as e:
        print(f"[!] Error during reconnaissance: {str(e)}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user")
        sys.exit(1)
