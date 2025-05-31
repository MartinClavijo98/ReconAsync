#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filename    : recon_async.py
Description : Cross-platform asynchronous reconnaissance script with automatic dependency installation
Usage       : python recon_async.py <target-domain> [--url <example-url>] [--install]
"""

import os
import sys
import subprocess
import shutil
import platform
import asyncio
import aiohttp
import socket
import csv
import re
import argparse
import tempfile
import venv
from pathlib import Path
from urllib.parse import urlparse

# Global Configuration
GO_TOOLS = {
    "subfinder": {
        "install": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "repo": "https://github.com/projectdiscovery/subfinder"
    },
    "assetfinder": {
        "install": "github.com/tomnomnom/assetfinder@latest",
        "repo": "https://github.com/tomnomnom/assetfinder"
    },
    "httpx": {
        "install": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "repo": "https://github.com/projectdiscovery/httpx"
    },
    "gobuster": {
        "install": "github.com/OJ/gobuster/v3@latest",
        "repo": "https://github.com/OJ/gobuster"
    },
    "gau": {
        "install": "github.com/lc/gau/v2/cmd/gau@latest",
        "repo": "https://github.com/lc/gau"
    },
    "waybackurls": {
        "install": "github.com/tomnomnom/waybackurls@latest",
        "repo": "https://github.com/tomnomnom/waybackurls"
    }
}

PYPI_TOOLS = {
    "dirsearch": "dirsearch",
    "paramspider": "paramspider"
}

MAX_HTTP_CONCURRENCY = 50
DEFAULT_WORDLIST_LINUX = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
DEFAULT_WORDLIST_WINDOWS = r"C:\wordlists\directory-list-lowercase-2.3-medium.txt"

# Initialize virtual environment path
VENV_PATH = os.path.join(os.getcwd(), "recon_venv")
PYTHON_BIN = sys.executable

# Helper Functions
def is_windows():
    return platform.system().lower().startswith("win")

def is_linux():
    return platform.system().lower().startswith("linux")

def run_subprocess_sync(cmd, capture_output=False, cwd=None):
    """Run a shell command synchronously with better error handling"""
    try:
        if capture_output:
            proc = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        else:
            ret = subprocess.call(cmd, shell=True, cwd=cwd)
            return ret, None, None
    except Exception as e:
        print(f"[!] Exception while running '{cmd}': {str(e)}")
        return -1, None, str(e)

def check_binary(binary_name):
    """Check if a binary exists in PATH"""
    return shutil.which(binary_name) is not None

def setup_environment():
    """Setup necessary environment variables"""
    # Set GOPROXY for Go tools
    os.environ["GOPROXY"] = "https://goproxy.io,direct"
    os.environ["GO111MODULE"] = "on"

    # Add Go binaries to PATH
    gopath = os.environ.get("GOPATH", os.path.join(os.environ["HOME"], "go"))
    bin_path = os.path.join(gopath, "bin")
    if bin_path not in os.environ["PATH"].split(os.pathsep):
        os.environ["PATH"] = f"{bin_path}{os.pathsep}{os.environ['PATH']}"

def create_virtualenv():
    """Create and activate a Python virtual environment"""
    if not os.path.exists(VENV_PATH):
        print("[*] Creating Python virtual environment...")
        venv.create(VENV_PATH, with_pip=True)

    # Determine the correct pip path based on OS
    pip_path = os.path.join(VENV_PATH, "bin", "pip")
    if is_windows():
        pip_path = os.path.join(VENV_PATH, "Scripts", "pip.exe")

    return pip_path

def install_python_tool(tool_name, package_name):
    """Install Python tools in the virtual environment"""
    print(f"[*] Installing Python tool: {tool_name}...")
    pip_path = create_virtualenv()

    cmd = f"{pip_path} install {package_name} --break-system-packages"
    ret, out, err = run_subprocess_sync(cmd, capture_output=True)

    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
        return True
    else:
        print(f"[!] Failed to install {tool_name}: {err}")
        return False

def install_go_tool(tool_name, go_path):
    """Install Go tools with proper error handling"""
    print(f"[*] Installing Go tool: {tool_name}...")

    # Try standard installation first
    cmd = f"go install {go_path}"
    ret, out, err = run_subprocess_sync(cmd, capture_output=True)

    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
        return True

    # If standard installation fails, try alternative methods
    print(f"[!] Standard installation failed, trying alternatives: {err}")

    if tool_name == "paramspider":
        print("[*] Trying alternative installation for paramspider...")
        alt_cmd = "go install github.com/devanshbatham/ParamSpider@latest"
        ret, out, err = run_subprocess_sync(alt_cmd, capture_output=True)
        if ret == 0:
            print("[+] ParamSpider installed successfully with alternative method.")
            return True

    print(f"[!] Failed to install {tool_name}")
    return False

def install_system_dependencies():
    """Install required system dependencies"""
    print("[*] Checking system dependencies...")

    if is_linux():
        # Install basic dependencies
        print("[*] Installing basic system dependencies...")
        run_subprocess_sync("sudo apt-get update -y")
        run_subprocess_sync("sudo apt-get install -y git golang python3-venv python3-pip")

        # Install wordlist for dirsearch
        if not os.path.exists(DEFAULT_WORDLIST_LINUX):
            print("[*] Installing default wordlist...")
            run_subprocess_sync("sudo apt-get install -y dirbuster")

    elif is_windows():
        print("[*] Please ensure you have Git, Go, and Python installed on Windows")
        print("[*] You may need to install Chocolatey first: https://chocolatey.org/install")
        run_subprocess_sync("choco install git golang python -y", capture_output=False)

def ensure_tools_installed():
    """Ensure all required tools are installed"""
    setup_environment()
    install_system_dependencies()

    # Install Go tools
    for tool, info in GO_TOOLS.items():
        if not check_binary(tool):
            if not install_go_tool(tool, info["install"]):
                print(f"[!] Warning: {tool} installation failed")
        else:
            print(f"[+] {tool} is already installed")

    # Install Python tools
    for tool, pkg in PYPI_TOOLS.items():
        if not check_binary(tool):
            if not install_python_tool(tool, pkg):
                print(f"[!] Warning: {tool} installation failed")
        else:
            print(f"[+] {tool} is already installed")

    print("[+] Tool installation verification complete")

def write_domain_file(domain: str):
    """Write the target domain into 'domain.txt'"""
    with open("domain.txt", "w", encoding="utf-8") as f:
        f.write(domain + "\n")
    print(f"[+] domain.txt created with {domain}")

# Asynchronous Recon Tasks (unchanged from original)
async def run_subprocess_async(cmd: str, outfile: str = None):
    print(f"[+] Running (async): {cmd}")
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    out_text = stdout.decode().strip()
    err_text = stderr.decode().strip()

    if process.returncode != 0:
        print(f"[!] Command failed (rc={process.returncode}): {cmd}")
        if err_text:
            print(f"    Error: {err_text}")
    else:
        if outfile and out_text:
            with open(outfile, "w", encoding="utf-8") as f:
                f.write(out_text + "\n")
            print(f"[+] Output saved to: {outfile}")
        elif out_text:
            print(out_text)

async def recon_subfinder(domain: str):
    await run_subprocess_async(f"subfinder -d {domain}", "subfinder.txt")

async def recon_assetfinder(domain: str):
    await run_subprocess_async(f"assetfinder {domain}", "assetfinder.txt")

async def recon_merge_subs():
    if not (os.path.exists("subfinder.txt") and os.path.exists("assetfinder.txt")):
        print("[!] Cannot merge subs: subfinder.txt or assetfinder.txt missing.")
        return
    subs = set()
    for fn in ["subfinder.txt", "assetfinder.txt"]:
        with open(fn, "r", encoding="utf-8") as f:
            for line in f:
                host = line.strip()
                if host:
                    subs.add(host)
    with open("uniq_subs.txt", "w", encoding="utf-8") as f:
        for host in sorted(subs):
            f.write(host + "\n")
    print("[+] Unique subdomains written to uniq_subs.txt")

async def recon_httpx_cli():
    if not os.path.exists("uniq_subs.txt"):
        print("[!] uniq_subs.txt not found, skipping httpx CLI step.")
        return
    await run_subprocess_async("httpx -l uniq_subs.txt -o httpx_cli.txt", "httpx_cli.txt")

async def recon_httpx_async():
    if not os.path.exists("uniq_subs.txt"):
        print("[!] uniq_subs.txt not found, skipping httpx async step.")
        return

    hosts = []
    with open("uniq_subs.txt", "r", encoding="utf-8") as f:
        for line in f:
            host = line.strip()
            if host:
                hosts.append(host)

    sem = asyncio.Semaphore(MAX_HTTP_CONCURRENCY)
    session_timeout = aiohttp.ClientTimeout(total=10)

    async def fetch_info(session, host):
        url = f"http://{host}"
        data = {"host": host, "status": "N/A", "title": "N/A", "ip": "N/A", "server": "N/A"}
        try:
            async with sem:
                try:
                    ip = socket.gethostbyname(host)
                    data["ip"] = ip
                except Exception:
                    data["ip"] = "N/A"

                async with session.get(url, timeout=10, allow_redirects=True) as resp:
                    data["status"] = str(resp.status)
                    server = resp.headers.get("Server", "N/A")
                    data["server"] = server

                    if resp.status == 200:
                        text = await resp.text()
                        match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                        if match:
                            title = match.group(1).strip()
                            title = re.sub(r"[\r\n]+", " ", title)
                            data["title"] = title
                    return data
        except Exception as e:
            data["title"] = f"Error: {str(e)}"
            return data

    async with aiohttp.ClientSession(timeout=session_timeout) as session:
        tasks = [fetch_info(session, host) for host in hosts]
        results = await asyncio.gather(*tasks)

    with open("httpx_async.csv", "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["host", "status", "title", "ip", "server"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            writer.writerow(item)
    print("[+] httpx async scan saved to httpx_async.csv")

async def recon_gau(domain: str):
    await run_subprocess_async(f"gau {domain}", "gau.txt")

async def recon_waybackurls(domain: str):
    await run_subprocess_async(f"waybackurls {domain}", "waybackurls.txt")

async def recon_paramspider(domain: str):
    await run_subprocess_async(f"paramspider -d {domain}", "paramspider.txt")

async def recon_dirsearch(url: str):
    if not url:
        print("[!] URL not provided, skipping dirsearch.")
        return

    wordlist = DEFAULT_WORDLIST_LINUX if is_linux() else DEFAULT_WORDLIST_WINDOWS
    if not os.path.isfile(wordlist):
        print(f"[!] Wordlist not found: {wordlist}")
        if is_linux():
            print("[*] Attempting to download common wordlist...")
            wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
            wordlist = os.path.join(os.getcwd(), "directory-list-2.3-medium.txt")
            cmd = f"wget {wordlist_url} -O {wordlist}"
            run_subprocess_sync(cmd)
        else:
            print("[!] Please download a wordlist manually")
            return

    if not os.path.isfile(wordlist):
        print("[!] Could not download wordlist, skipping dirsearch")
        return

    cmd = f"dirsearch -u {url} -e php,asp,aspx,jsp,html,js,json -w {wordlist} --plain-text-report=dirsearch.txt"
    await run_subprocess_async(cmd)

async def main():
    parser = argparse.ArgumentParser(description='Automated reconnaissance script with dependency installation')
    parser.add_argument('domain', nargs='?', help='Target domain for reconnaissance')
    parser.add_argument('--url', type=str, help='URL for directory brute-forcing')
    parser.add_argument('--install', action='store_true', help='Install required tools and exit')
    args = parser.parse_args()

    if args.install:
        print("[*] Starting tool installation process...")
        ensure_tools_installed()
        print("[+] Tool installation complete. You can now run the reconnaissance.")
        sys.exit(0)

    if not args.domain and not args.url:
        parser.print_usage()
        sys.exit(1)

    # Extract domain from URL if not provided
    if args.url and not args.domain:
        parsed = urlparse(args.url)
        args.domain = parsed.netloc if parsed.netloc else args.url.split('/')[0]
        print(f"[*] Extracted domain from URL: {args.domain}")

    domain = args.domain
    url = args.url

    print(f"[*] Starting reconnaissance on domain: {domain}")
    if url:
        print(f"[*] URL provided for additional scanning: {url}")

    # Verify all tools are installed
    print("[*] Verifying tool installation...")
    ensure_tools_installed()

    # Check for missing tools
    required_tools = list(GO_TOOLS.keys()) + list(PYPI_TOOLS.keys())
    missing_tools = [tool for tool in required_tools if not check_binary(tool)]

    if missing_tools:
        print(f"[!] The following required tools are missing: {', '.join(missing_tools)}")
        print("[!] Please install them manually or use --install flag")
        print("[!] Some tools might need to be installed with sudo or in a virtual environment")
        sys.exit(1)

    write_domain_file(domain)

    print("[*] Starting reconnaissance tasks...")
    await asyncio.gather(
        recon_subfinder(domain),
        recon_assetfinder(domain)
    )

    await recon_merge_subs()
    await recon_httpx_cli()
    await recon_httpx_async()

    await asyncio.gather(
        recon_gau(domain),
        recon_waybackurls(domain),
        recon_paramspider(domain)
    )

    if url:
        await recon_dirsearch(url)

    print("[+] Reconnaissance complete. Results saved in current directory.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user. Exiting...")
    except Exception as e:
        print(f"[!] An error occurred: {str(e)}")
