#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filename    : recon_async.py
Description : Cross-platform asynchronous reconnaissance script using asyncio and aiohttp
              - Checks and installs required tools (Go, Go tools, Python tools)
              - Runs multiple recon tools asynchronously
              - Merges results and performs HTTP analysis (httpx CLI and aiohttp)
              - Supports scanning domain and optionally URL with directory brute forcing
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

# ----------------------------
#      Global Configuration
# ----------------------------

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

# ----------------------------
#      Helper Functions
# ----------------------------

def is_windows():
    return platform.system().lower().startswith("win")

def is_linux():
    return platform.system().lower().startswith("linux")

def run_subprocess_sync(cmd, capture_output=False):
    """
    Run a shell command synchronously.
    If capture_output=True, return (returncode, stdout, stderr).
    Otherwise, return (returncode, None, None).
    """
    try:
        if capture_output:
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        else:
            ret = subprocess.call(cmd, shell=True)
            return ret, None, None
    except Exception as e:
        print(f"[!] Exception while running '{cmd}': {e}")
        return -1, None, str(e)

def check_binary(binary_name):
    return shutil.which(binary_name) is not None

def append_go_bin_to_path():
    """
    Ensure that GOBIN or GOPATH/bin is in PATH after installing Go tools.
    """
    path = os.environ.get("PATH", "")
    added_paths = []

    gobin = os.environ.get("GOBIN")
    if gobin and os.path.isdir(gobin) and gobin not in path:
        os.environ["PATH"] += os.pathsep + gobin
        added_paths.append(gobin)

    gopath = os.environ.get("GOPATH")
    if gopath:
        bin_path = os.path.join(gopath, "bin")
        if os.path.isdir(bin_path) and bin_path not in path:
            os.environ["PATH"] += os.pathsep + bin_path
            added_paths.append(bin_path)

    if added_paths:
        print(f"[~] Added paths to PATH: {', '.join(added_paths)}")

def install_go_linux():
    print("[*] Installing Go (golang-go) via apt-get...")
    run_subprocess_sync("sudo apt-get update -y")
    code, out, err = run_subprocess_sync("sudo apt-get install -y golang-go", capture_output=True)
    if code == 0:
        print("[+] Go installed successfully.")
        append_go_bin_to_path()
    else:
        print(f"[!] Failed to install Go: {err}")
        sys.exit(1)

def install_go_windows():
    print("[*] Installing Go on Windows via choco or winget...")
    if check_binary("choco"):
        code, out, err = run_subprocess_sync("choco install golang -y", capture_output=True)
        if code == 0:
            print("[+] Go installed successfully via choco.")
            append_go_bin_to_path()
            return
    if check_binary("winget"):
        code, out, err = run_subprocess_sync("winget install --id Go.Go -e --source winget", capture_output=True)
        if code == 0:
            print("[+] Go installed successfully via winget.")
            append_go_bin_to_path()
            return
    print("[!] Could not install Go automatically. Please install Go manually and re-run.")
    sys.exit(1)

def ensure_go_installed():
    """
    Ensure 'go' binary is present. If not, attempt to install on Linux or Windows.
    """
    if not check_binary("go"):
        print("[*] Go is not installed.")
        if is_linux():
            install_go_linux()
        elif is_windows():
            install_go_windows()
        else:
            print("[!] Unsupported OS. Install Go manually.")
            sys.exit(1)
    else:
        print("[+] Go is already installed.")
        append_go_bin_to_path()

def install_go_tool(tool_name, go_path):
    """
    Install a Go-based tool via 'go install <path>@latest'.
    """
    print(f"[*] Installing Go-based tool: {tool_name} ...")
    cmd = f"GO111MODULE=on go install {go_path}"
    ret, out, err = run_subprocess_sync(cmd, capture_output=True)
    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
        append_go_bin_to_path()
    else:
        print(f"[!] Failed to install {tool_name}: {err}")

def install_python_tool(tool_name, package_name):
    """
    Install a Python-based tool via pip.
    """
    print(f"[*] Installing Python-based tool: {tool_name} ...")
    pip_cmd = "pip" if check_binary("pip") else "pip3"
    cmd = f"{pip_cmd} install {package_name}"
    ret, out, err = run_subprocess_sync(cmd, capture_output=True)
    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
    else:
        print(f"[!] Failed to install {tool_name}: {err}")

def ensure_tools_installed():
    """
    Ensure Go is installed, then install each Go tool and Python tool if missing.
    """
    ensure_go_installed()

    for binary, go_info in GO_TOOLS.items():
        if not check_binary(binary):
            install_go_tool(binary, go_info["install"])
        else:
            print(f"[+] {binary} already installed.")

    for binary, pkg in PYPI_TOOLS.items():
        if not check_binary(binary):
            install_python_tool(binary, pkg)
        else:
            print(f"[+] {binary} already installed.")

    print("[+] All required tools are installed or already present.")

def write_domain_file(domain: str):
    """
    Write the target domain into 'domain.txt'.
    """
    with open("domain.txt", "w", encoding="utf-8") as f:
        f.write(domain + "\n")
    print(f"[+] domain.txt created with {domain}")

# ----------------------------
#     Asynchronous Recon Tasks
# ----------------------------

async def run_subprocess_async(cmd: str, outfile: str = None):
    """
    Run a shell command asynchronously.
    If 'outfile' is provided, write stdout into that file; otherwise print stdout.
    """
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
    """
    Run 'subfinder' and save output to 'subfinder.txt'.
    """
    await run_subprocess_async(f"subfinder -d {domain}", "subfinder.txt")

async def recon_assetfinder(domain: str):
    """
    Run 'assetfinder' and save output to 'assetfinder.txt'.
    """
    await run_subprocess_async(f"assetfinder {domain}", "assetfinder.txt")

async def recon_merge_subs():
    """
    Merge 'subfinder.txt' and 'assetfinder.txt' into 'uniq_subs.txt' (deduplicated).
    """
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
    """
    Run 'httpx' CLI on 'uniq_subs.txt', save to 'httpx_cli.txt'.
    """
    if not os.path.exists("uniq_subs.txt"):
        print("[!] uniq_subs.txt not found, skipping httpx CLI step.")
        return
    await run_subprocess_async("httpx -l uniq_subs.txt -o httpx_cli.txt", "httpx_cli.txt")

async def recon_httpx_async():
    """
    Perform HTTP scanning (status, title, IP, server) on uniq_subs.txt using aiohttp asynchronously.
    Results saved to 'httpx_async.csv'.
    """
    if not os.path.exists("uniq_subs.txt"):
        print("[!] uniq_subs.txt not found, skipping httpx async step.")
        return

    # Read hosts
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
                # DNS resolve
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
                        # Extract <title> tag content
                        match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                        if match:
                            title = match.group(1).strip()
                            # sanitize title (remove newlines)
                            title = re.sub(r"[\r\n]+", " ", title)
                            data["title"] = title
                    return data
        except Exception as e:
            data["title"] = f"Error"
            return data

    async with aiohttp.ClientSession(timeout=session_timeout) as session:
        tasks = [fetch_info(session, host) for host in hosts]
        results = await asyncio.gather(*tasks)

    # Write CSV file
    with open("httpx_async.csv", "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["host", "status", "title", "ip", "server"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            writer.writerow(item)
    print("[+] httpx async scan saved to httpx_async.csv")

async def recon_gau(domain: str):
    """
    Run 'gau' on domain and save output to 'gau.txt'.
    """
    await run_subprocess_async(f"gau {domain}", "gau.txt")

async def recon_waybackurls(domain: str):
    """
    Run 'waybackurls' on domain and save output to 'waybackurls.txt'.
    """
    await run_subprocess_async(f"waybackurls {domain}", "waybackurls.txt")

async def recon_paramspider(domain: str):
    """
    Run 'paramspider' on domain, save output to 'paramspider.txt'.
    """
    await run_subprocess_async(f"paramspider -d {domain}", "paramspider.txt")

async def recon_dirsearch(url: str):
    """
    Run 'dirsearch' brute forcing on URL.
    """
    if not url:
        print("[!] URL not provided, skipping dirsearch.")
        return

    # Determine default wordlist path based on OS
    if is_linux():
        wordlist = DEFAULT_WORDLIST_LINUX
    elif is_windows():
        wordlist = DEFAULT_WORDLIST_WINDOWS
    else:
        wordlist = ""

    if not os.path.isfile(wordlist):
        print(f"[!] Wordlist not found: {wordlist}. Please set correct path or install wordlist.")
        return

    cmd = f"dirsearch -u {url} -e php,asp,aspx,jsp,html,js,json -w {wordlist} --plain-text-report=dirsearch.txt"
    await run_subprocess_async(cmd)

# ----------------------------
#      Main Function
# ----------------------------

async def main():
    parser = argparse.ArgumentParser(description='Cross-platform asynchronous reconnaissance script.')
    parser.add_argument('domain', type=str, help='Target domain for reconnaissance')
    parser.add_argument('--url', type=str, help='Optional URL for directory brute-forcing')
    parser.add_argument('--install', action='store_true', help='Install required tools and exit')
    args = parser.parse_args()

    if args.install:
        ensure_tools_installed()
        sys.exit(0)

    domain = args.domain
    url = args.url

    print(f"[*] Starting recon on domain: {domain}")
    if url:
        print(f"[*] URL provided for dirsearch: {url}")

    ensure_tools_installed()

    write_domain_file(domain)

    # Run subfinder and assetfinder concurrently
    await asyncio.gather(
        recon_subfinder(domain),
        recon_assetfinder(domain)
    )

    # Merge results
    await recon_merge_subs()

    # Run httpx CLI scanner on unique subs
    await recon_httpx_cli()

    # Run httpx async HTTP checks
    await recon_httpx_async()

    # Run gau, waybackurls, paramspider concurrently
    await asyncio.gather(
        recon_gau(domain),
        recon_waybackurls(domain),
        recon_paramspider(domain)
    )

    # Run dirsearch if URL is provided
    if url:
        await recon_dirsearch(url)

    print("[*] Recon complete.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
