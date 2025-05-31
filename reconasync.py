#!/usr/bin/env python3
"""
Enhanced Reconnaissance Toolkit (ERT) - Optimized Final Version
Version: 2.1.0
"""

import os
import sys
import subprocess
import shutil
import platform
import asyncio
import argparse
import time
import json
import csv
import signal
from urllib.parse import urlparse
from datetime import datetime

# Configuration
VERSION = "2.1.0"
DEFAULT_WORDLIST = "directory-list-2.3-medium.txt"
WORDLIST_URL = f"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/{DEFAULT_WORDLIST}"
OUTPUT_DIR = "recon_results"
TOOL_TIMEOUT = 600  # 10 minutes

# Tool Configuration
TOOLS = {
    # Go tools
    "subfinder": {
        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "cmd": "subfinder -d {target} -silent -o {output}"
    },
    "assetfinder": {
        "install": "go install github.com/tomnomnom/assetfinder@latest",
        "cmd": "assetfinder --subs-only {target} > {output}"
    },
    "httpx": {
        "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "cmd": "httpx -l {input} -silent -json -o {output}"
    },
    "gau": {
        "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "cmd": "echo {target} | gau > {output}"
    },
    "waybackurls": {
        "install": "go install github.com/tomnomnom/waybackurls@latest",
        "cmd": "echo {target} | waybackurls > {output}"
    },
    
    # Python tools
    "dirsearch": {
        "install": "pip install dirsearch",
        "cmd": "dirsearch -u {target} -e php,asp,aspx,jsp,html,js,json -w {wordlist} -o {output}"
    },
    "paramspider": {
        "install": "pip install git+https://github.com/devanshbatham/ParamSpider.git",
        "cmd": "paramspider -d {target} -o {output}"
    }
}

def setup_environment():
    """Configure environment variables for Go tools."""
    os.environ.update({
        "GOPROXY": "https://goproxy.io,direct",
        "GO111MODULE": "on"
    })
    
    # Add Go bin to PATH if not present
    go_path = os.path.join(os.environ.get("GOPATH", os.path.join(os.getcwd(), "go")), "bin")
    if go_path not in os.environ["PATH"]:
        os.environ["PATH"] = f"{go_path}{os.pathsep}{os.environ['PATH']}"

def check_requirements():
    """Verify all required binaries are available."""
    missing = []
    for tool in TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    return missing

def install_tools():
    """Install missing tools automatically."""
    setup_environment()
    missing = check_requirements()
    
    if not missing:
        print("[*] All tools are already installed")
        return True
        
    print(f"[*] Installing missing tools: {', '.join(missing)}")
    
    for tool in missing:
        print(f"[*] Installing {tool}...")
        cmd = TOOLS[tool]["install"]
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Successfully installed {tool}")
        else:
            print(f"[!] Failed to install {tool}: {result.stderr.strip()}")
            return False
            
    return True

def download_wordlist():
    """Download default wordlist if missing."""
    os.makedirs("wordlists", exist_ok=True)
    wordlist_path = os.path.join("wordlists", DEFAULT_WORDLIST)
    
    if not os.path.exists(wordlist_path):
        print("[*] Downloading wordlist...")
        result = subprocess.run(f"wget {WORDLIST_URL} -O {wordlist_path}", 
                              shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Wordlist download failed: {result.stderr.strip()}")
            return False
    return True

async def run_tool(tool_name, target, output_file, input_file=None, wordlist=None):
    """Execute a recon tool asynchronously."""
    template = TOOLS[tool_name]["cmd"]
    cmd = template.format(
        target=target,
        output=output_file,
        input=input_file or "",
        wordlist=wordlist or ""
    )
    
    print(f"[*] Running {tool_name}...")
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
        
        if proc.returncode != 0:
            print(f"[!] {tool_name} failed: {stderr.decode().strip()}")
            return False
            
        print(f"[+] {tool_name} completed successfully")
        return True
        
    except asyncio.TimeoutError:
        proc.kill()
        print(f"[!] {tool_name} timed out")
        return False

async def run_recon(domain, url=None):
    """Main reconnaissance workflow."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(OUTPUT_DIR, f"scan_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Starting reconnaissance on {domain}")
    print(f"[*] Results will be saved to: {output_dir}")
    
    # Subdomain discovery
    subdomains_file = os.path.join(output_dir, "subdomains.txt")
    await asyncio.gather(
        run_tool("subfinder", domain, subdomains_file),
        run_tool("assetfinder", domain, subdomains_file)
    )
    
    # HTTP probing
    httpx_file = os.path.join(output_dir, "httpx_results.json")
    await run_tool("httpx", "", httpx_file, input_file=subdomains_file)
    
    # URL discovery
    await asyncio.gather(
        run_tool("gau", domain, os.path.join(output_dir, "urls_gau.txt")),
        run_tool("waybackurls", domain, os.path.join(output_dir, "urls_wayback.txt")),
        run_tool("paramspider", domain, os.path.join(output_dir, "paramspider_results.txt"))
    )
    
    # Directory brute-forcing
    if url:
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
            
        wordlist_path = os.path.join("wordlists", DEFAULT_WORDLIST)
        await run_tool(
            "dirsearch", 
            url, 
            os.path.join(output_dir, "dirsearch_results.txt"),
            wordlist=wordlist_path
        )
    
    print(f"[+] Reconnaissance completed. Results saved to {output_dir}")

async def main():
    parser = argparse.ArgumentParser(description=f"Enhanced Reconnaissance Toolkit v{VERSION}")
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('--url', help='Specific URL for directory scanning')
    parser.add_argument('--install', action='store_true', help='Install tools only')
    args = parser.parse_args()

    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda s, f: (print("\n[!] Scan interrupted"), sys.exit(1)))
    
    if args.install:
        if not install_tools():
            sys.exit(1)
        return
    
    if not check_requirements():
        print("[!] Missing required tools. Run with --install first")
        sys.exit(1)
        
    if not download_wordlist():
        print("[!] Wordlist download failed")
        
    await run_recon(args.domain, args.url)

if __name__ == "__main__":
    asyncio.run(main())
