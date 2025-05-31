#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filename    : recon_async.py
Description : Enhanced cross-platform asynchronous reconnaissance script with automatic dependency installation
Usage       : python3 recon_async.py <target-domain> [--url <example-url>] [--install]
"""

import os
import sys
import subprocess
import shutil
import platform
import asyncio
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
    "aiohttp": "aiohttp"
}

# Wordlist configuration
DEFAULT_WORDLIST_NAME = "directory-list-2.3-medium.txt"
WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/" + DEFAULT_WORDLIST_NAME
WORDLIST_DIR = os.path.join(os.getcwd(), "wordlists")

MAX_HTTP_CONCURRENCY = 50
VENV_PATH = os.path.join(os.getcwd(), "recon_venv")
PYTHON_BIN = sys.executable

def is_windows():
    """Check if the current OS is Windows."""
    return platform.system().lower().startswith("win")

def is_linux():
    """Check if the current OS is Linux."""
    return platform.system().lower().startswith("linux")

def run_subprocess_sync(cmd, capture_output=False, cwd=None):
    """Run a shell command synchronously with better error handling."""
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
    """Check if a binary exists in PATH."""
    return shutil.which(binary_name) is not None

def setup_environment():
    """Setup necessary environment variables for Go tools."""
    os.environ["GOPROXY"] = "https://goproxy.io,direct"
    os.environ["GO111MODULE"] = "on"

    gopath = os.environ.get("GOPATH", os.path.join(os.environ.get("HOME", ""), "go"))
    bin_path = os.path.join(gopath, "bin")
    if bin_path not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{bin_path}{os.pathsep}{os.environ['PATH']}"

def create_virtualenv():
    """Create and return pip path of a Python virtual environment."""
    if not os.path.exists(VENV_PATH):
        print("[*] Creating Python virtual environment...")
        venv.create(VENV_PATH, with_pip=True)

    pip_path = os.path.join(VENV_PATH, "bin", "pip")
    if is_windows():
        pip_path = os.path.join(VENV_PATH, "Scripts", "pip.exe")

    return pip_path

def install_python_tool(tool_name, package_name):
    """Install a Python tool via pip in the virtual environment."""
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

def install_paramspider():
    """Install paramspider by cloning its GitHub repository and running setup.py."""
    print("[*] Installing Python tool: paramspider...")
    if check_binary("paramspider"):
        print("[+] paramspider is already installed.")
        return True

    tmp_dir = tempfile.mkdtemp(prefix="paramspider_")
    try:
        # Clone the paramspider repo
        repo_url = "https://github.com/devanshbatham/ParamSpider.git"
        clone_cmd = f"git clone {repo_url} {tmp_dir}"
        ret, out, err = run_subprocess_sync(clone_cmd, capture_output=True)
        if ret != 0:
            print(f"[!] Failed to clone paramspider repo: {err}")
            return False

        # Install requirements
        req_file = os.path.join(tmp_dir, "requirements.txt")
        if os.path.isfile(req_file):
            pip_path = create_virtualenv()
            install_reqs_cmd = f"{pip_path} install -r {req_file} --break-system-packages"
            ret, out, err = run_subprocess_sync(install_reqs_cmd, capture_output=True)
            if ret != 0:
                print(f"[!] Failed to install paramspider requirements: {err}")

        # Run setup.py install
        setup_path = os.path.join(tmp_dir, "setup.py")
        if os.path.isfile(setup_path):
            install_cmd = f"{PYTHON_BIN} {setup_path} install"
            ret, out, err = run_subprocess_sync(install_cmd, capture_output=True)
            if ret == 0:
                print("[+] paramspider installed successfully.")
                return True
            else:
                print(f"[!] Failed to run paramspider setup.py: {err}")
                return False
        else:
            print("[!] setup.py not found in paramspider repo.")
            return False
    except Exception as e:
        print(f"[!] Exception during paramspider installation: {e}")
        return False
    finally:
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass

def install_go_tool(tool_name, go_path):
    """Install Go tools with proper error handling."""
    print(f"[*] Installing Go tool: {tool_name}...")

    if not check_binary("go"):
        print("[!] 'go' command not found. Please install Go before proceeding.")
        return False

    cmd = f"go install {go_path}"
    ret, out, err = run_subprocess_sync(cmd, capture_output=True)
    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
        return True

    print(f"[!] Standard installation failed for {tool_name}: {err}")
    return False

def install_system_dependencies():
    """Install required system dependencies."""
    print("[*] Checking system dependencies...")
    if is_linux():
        print("[*] Installing basic system dependencies for Linux...")
        run_subprocess_sync("sudo apt-get update -y")
        run_subprocess_sync("sudo apt-get install -y git golang python3-venv python3-pip wget chromium-browser")
    elif is_windows():
        print("[*] Please ensure you have Git, Go, and Python installed on Windows.")
        print("[*] You may need to install Chocolatey first: https://chocolatey.org/install")
        run_subprocess_sync("choco install git golang python -y")

def ensure_wordlist():
    """Ensure the wordlist is available before starting reconnaissance."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    wordlist_path = os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST_NAME)

    if os.path.isfile(wordlist_path) and os.path.getsize(wordlist_path) > 0:
        print(f"[+] Wordlist found at {wordlist_path}")
        return True

    print("[*] Wordlist not found, attempting to download...")
    try:
        ret, out, err = run_subprocess_sync(f"wget {WORDLIST_URL} -O {wordlist_path}")
        if ret == 0 and os.path.getsize(wordlist_path) > 0:
            print(f"[+] Successfully downloaded wordlist to {wordlist_path}")
            return True
        else:
            print(f"[!] Failed to download wordlist: {err}")
            return False
    except Exception as e:
        print(f"[!] Exception while downloading wordlist: {str(e)}")
        return False

def ensure_tools_installed():
    """Ensure all required tools are installed (Go, Python, paramspider)."""
    setup_environment()
    install_system_dependencies()

    # Install Go tools
    for tool, info in GO_TOOLS.items():
        if not check_binary(tool):
            success = install_go_tool(tool, info["install"])
            if not success:
                print(f"[!] Warning: {tool} installation failed.")
        else:
            print(f"[+] {tool} is already installed.")

    # Install Python tools via pip
    for tool, pkg in PYPI_TOOLS.items():
        if not check_binary(tool):
            success = install_python_tool(tool, pkg)
            if not success:
                print(f"[!] Warning: {tool} installation failed.")
        else:
            print(f"[+] {tool} is already installed.")

    # Install paramspider
    if not check_binary("paramspider"):
        success = install_paramspider()
        if not success:
            print("[!] Warning: paramspider installation failed.")
    else:
        print("[+] paramspider is already installed.")

    print("[+] Tool installation verification complete.")

def write_domain_file(domain: str):
    """Write the target domain into 'domain.txt'."""
    with open("domain.txt", "w", encoding="utf-8") as f:
        f.write(domain + "\n")
    print(f"[+] domain.txt created with {domain}")

async def run_subprocess_async(cmd: str, outfile: str = None):
    """Run a shell command asynchronously and optionally save output."""
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
    """Run subfinder asynchronously and save results to 'subfinder.txt'."""
    await run_subprocess_async(f"subfinder -d {domain} -o subfinder.txt")

async def recon_assetfinder(domain: str):
    """Run assetfinder asynchronously and save results to 'assetfinder.txt'."""
    await run_subprocess_async(f"assetfinder --subs-only {domain} > assetfinder.txt")

async def recon_merge_subs():
    """Merge subfinder.txt and assetfinder.txt into uniq_subs.txt."""
    if not (os.path.exists("subfinder.txt") and os.path.exists("assetfinder.txt")):
        print("[!] Cannot merge subs: subfinder.txt or assetfinder.txt missing.")
        return
    subs = set()
    for fn in ["subfinder.txt", "assetfinder.txt"]:
        with open(fn, "r", encoding="utf-8") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    subs.add(host)
    with open("uniq_subs.txt", "w", encoding="utf-8") as f:
        for host in sorted(subs):
            f.write(host + "\n")
    print("[+] Unique subdomains written to uniq_subs.txt")

async def recon_httpx_cli():
    """Run httpx in CLI mode on uniq_subs.txt and save to 'httpx_cli.txt'."""
    if not os.path.exists("uniq_subs.txt"):
        print("[!] uniq_subs.txt not found, skipping httpx CLI step.")
        return

    # Read the file and process each host individually
    with open("uniq_subs.txt", "r", encoding="utf-8") as f:
        hosts = [line.strip() for line in f if line.strip()]

    # Process hosts in batches
    batch_size = 20
    output_file = "httpx_cli.txt"

    with open(output_file, "w", encoding="utf-8") as out_f:
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            for host in batch:
                # Run httpx for each host individually
                cmd = f"httpx -u http://{host} -silent"
                ret, out, err = run_subprocess_sync(cmd, capture_output=True)
                if ret == 0 and out:
                    out_f.write(f"{host}: {out}\n")
                elif err:
                    out_f.write(f"{host}: Error - {err}\n")

    print(f"[+] httpx CLI scan saved to {output_file}")

async def recon_httpx_async():
    """
    Run httpx asynchronously: resolve IP, fetch HTTP status/title/server.
    Save results to 'httpx_async.csv'.
    """
    if not os.path.exists("uniq_subs.txt"):
        print("[!] uniq_subs.txt not found, skipping httpx async step.")
        return

    hosts = []
    with open("uniq_subs.txt", "r", encoding="utf-8") as f:
        hosts = [line.strip() for line in f if line.strip()]

    # Write CSV header
    with open("httpx_async.csv", "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["host", "status", "title", "ip", "server", "error"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for host in hosts:
            cmd = f"httpx -u http://{host} -silent -json"
            ret, out, err = run_subprocess_sync(cmd, capture_output=True)

            result = {
                "host": host,
                "status": "N/A",
                "title": "N/A",
                "ip": "N/A",
                "server": "N/A",
                "error": err if err else ""
            }

            if ret == 0 and out:
                try:
                    # Parse the JSON output
                    import json
                    data = json.loads(out)
                    if isinstance(data, list) and len(data) > 0:
                        data = data[0]
                    result.update({
                        "status": data.get("status_code", "N/A"),
                        "title": data.get("title", "N/A"),
                        "ip": data.get("a", [{}])[0].get("ip", "N/A"),
                        "server": data.get("webserver", "N/A")
                    })
                except Exception as e:
                    result["error"] = f"JSON parsing error: {str(e)}"

            writer.writerow(result)

    print("[+] httpx async scan saved to httpx_async.csv")


async def recon_gau(domain: str):
    """Run gau to fetch URLs and save to 'gau.txt'."""
    await run_subprocess_async(f"echo {domain} | gau > gau.txt")

async def recon_waybackurls(domain: str):
    """Run waybackurls and save to 'waybackurls.txt'."""
    await run_subprocess_async(f"echo {domain} | waybackurls > waybackurls.txt")

async def recon_paramspider(domain: str):
    """Run paramspider -d <domain> and save to 'paramspider.txt'."""
    if not check_binary("paramspider"):
        print("[!] paramspider binary not found, skipping paramspider step.")
        return

    # Run paramspider with proper arguments
    await run_subprocess_async(f"paramspider --domain {domain} --output paramspider.txt")

async def recon_dirsearch(url: str):
    """
    Run dirsearch on a provided URL with improved wordlist handling.
    Save results to 'dirsearch.txt'.
    """
    if not url:
        print("[!] URL not provided, skipping dirsearch.")
        return

    wordlist_path = os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST_NAME)

    if not os.path.isfile(wordlist_path) or os.path.getsize(wordlist_path) == 0:
        print("[!] Wordlist not available, skipping dirsearch")
        return

    # Construct the dirsearch command with proper path handling
    dirsearch_cmd = (
        f"dirsearch -u {url} "
        f"-e php,asp,aspx,jsp,html,js,json "
        f"-w {wordlist_path} "
        "--plain-text-report=dirsearch.txt"
    )

    print(f"[*] Running dirsearch with command: {dirsearch_cmd}")
    await run_subprocess_async(dirsearch_cmd)

async def main():
    parser = argparse.ArgumentParser(description='Automated reconnaissance script with dependency installation')
    parser.add_argument('domain', nargs='?', help='Target domain for reconnaissance')
    parser.add_argument('--url', type=str, help='URL for directory brute-forcing')
    parser.add_argument('--install', action='store_true', help='Install required tools and exit')
    args = parser.parse_args()

    if args.install:
        print("[*] Starting tool installation process...")
        ensure_tools_installed()
        ensure_wordlist()
        print("[+] Installation complete. You can now run the reconnaissance.")
        sys.exit(0)

    if not args.domain and not args.url:
        parser.print_usage()
        sys.exit(1)

    if args.url and not args.domain:
        parsed = urlparse(args.url)
        args.domain = parsed.netloc if parsed.netloc else args.url.split('/')[0]
        print(f"[*] Extracted domain from URL: {args.domain}")

    domain = args.domain
    url = args.url

    print(f"[*] Starting reconnaissance on domain: {domain}")
    if url:
        print(f"[*] URL provided for additional scanning: {url}")

    print("[*] Verifying tool installation...")
    ensure_tools_installed()

    if not ensure_wordlist():
        print("[!] Wordlist is required but could not be downloaded. Directory brute-forcing will be disabled.")

    write_domain_file(domain)

    print("[*] Starting reconnaissance tasks...")
    await asyncio.gather(
        recon_subfinder(domain),
        recon_assetfinder(domain)
    )

    await recon_merge_subs()

    # Run httpx tasks
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
