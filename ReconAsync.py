#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filename    : recon_async.py
Description : Cross-platform asynchronous reconnaissance script using asyncio and aiohttp
              - Checks and installs required tools (Go, Go tools, Python tools)
              - Runs multiple recon tools asynchronously
              - Merges results and performs HTTP analysis (httpx CLI and aiohttp)
              - Supports scanning domain and optionally URL with directory brute forcing
Usage       : python recon_async.py <target-domain> [--url <example-url>]
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

# ----------------------------
#      Global Configuration
# ----------------------------

GO_TOOLS = {
    "subfinder":        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder":      "github.com/tomnomnom/assetfinder@latest",
    "httpx":            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gobuster":         "github.com/OJ/gobuster/v3@latest",
    "paramspider":      "github.com/devanshbatham/ParamSpider@latest",
    "gau":              "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls":      "github.com/tomnomnom/waybackurls@latest"
}

PYPI_TOOLS = {
    "dirsearch":        "dirsearch"
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
    gobin = os.environ.get("GOBIN")
    if gobin and os.path.isdir(gobin):
        if gobin not in os.environ.get("PATH", ""):
            os.environ["PATH"] += os.pathsep + gobin
            print(f"[~] Added GOBIN ({gobin}) to PATH.")

    gopath = os.environ.get("GOPATH")
    if gopath:
        bin_path = os.path.join(gopath, "bin")
        if os.path.isdir(bin_path) and bin_path not in os.environ.get("PATH", ""):
            os.environ["PATH"] += os.pathsep + bin_path
            print(f"[~] Added GOPATH/bin ({bin_path}) to PATH.")

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

    for binary, go_path in GO_TOOLS.items():
        if not check_binary(binary):
            install_go_tool(binary, go_path)
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
    Perform HTTP scanning (status, title, IP, server) on 'uniq_subs.txt' using aiohttp,
    then write results to 'httpx_toolkit_async.csv'.
    """
    infile = "uniq_subs.txt"
    outfile = "httpx_toolkit_async.csv"
    if not os.path.exists(infile):
        print("[!] uniq_subs.txt not found, skipping httpx_async step.")
        return
    with open(infile, "r", encoding="utf-8") as f:
        hosts = [line.strip() for line in f if line.strip()]
    semaphore = asyncio.Semaphore(MAX_HTTP_CONCURRENCY)

    async def fetch_info(session: aiohttp.ClientSession, host: str):
        url = f"http://{host}"
        data = {"host": host, "status": None, "title": None, "server": None, "ip": None}
        # DNS resolution
        try:
            ip_addr = socket.gethostbyname(host)
            data["ip"] = ip_addr
        except Exception:
            data["ip"] = "N/A"
        # HTTP GET
        try:
            async with semaphore:
                async with session.get(url, timeout=15, allow_redirects=True) as resp:
                    data["status"] = resp.status
                    data["server"] = resp.headers.get("Server", "N/A")
                    text = await resp.text()
                    title_match = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
                    data["title"] = title_match.group(1).strip() if title_match else "N/A"
        except Exception as e:
            data["status"] = "Err"
            data["title"] = str(e)
            data["server"] = "N/A"
        return data

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_info(session, h) for h in hosts]
        results = await asyncio.gather(*tasks)

    with open(outfile, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["host", "status", "title", "ip", "server"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for res in results:
            writer.writerow(res)

    print(f"[+] HTTP info collected in {outfile}")

async def recon_gau(domain: str):
    """
    Run 'gau' (GetAllURLs) and save output to 'gau.txt'.
    """
    await run_subprocess_async(f"gau {domain}", "gau.txt")

async def recon_wayback(domain: str):
    """
    Run 'waybackurls' and save output to 'waybackurls.txt'.
    """
    await run_subprocess_async(f"waybackurls {domain}", "waybackurls.txt")

async def recon_paramspider(domain: str):
    """
    Run 'paramspider' and save output to 'paramspider.txt'.
    """
    await run_subprocess_async(f"paramspider -d {domain} -o paramspider.txt", "paramspider.txt")

async def recon_extract_urls(filename: str):
    """
    Extract URLs from a local file and print count (placeholder).
    """
    if not os.path.exists(filename):
        print(f"[!] {filename} not found for URL extraction.")
        return
    with open(filename, "r", encoding="utf-8") as f:
        urls = set(line.strip() for line in f if line.strip())
    print(f"[+] Extracted {len(urls)} URLs from {filename}")
    # Placeholder for further URL processing

async def recon_gobuster(url: str):
    """
    Run 'gobuster' directory brute-forcing on a given URL.
    Save output to 'gobuster.txt'.
    """
    wordlist = DEFAULT_WORDLIST_WINDOWS if is_windows() else DEFAULT_WORDLIST_LINUX
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found at {wordlist}, skipping gobuster.")
        return
    cmd = f"gobuster dir -u {url} -w {wordlist} -t 50 -o gobuster.txt"
    await run_subprocess_async(cmd, "gobuster.txt")

async def recon_dirsearch(url: str):
    """
    Run 'dirsearch' on a given URL.
    Save output to 'dirsearch.txt'.
    """
    cmd = f"dirsearch -u {url} -e * -t 50 -o dirsearch.txt"
    await run_subprocess_async(cmd, "dirsearch.txt")

# ----------------------------
#        Main Entry Point
# ----------------------------

async def main():
    if len(sys.argv) < 2:
        print("Usage: python recon_async.py <target-domain> [--url <example-url>]")
        sys.exit(1)

    domain = sys.argv[1]
    url = None
    if "--url" in sys.argv:
        idx = sys.argv.index("--url")
        if idx + 1 < len(sys.argv):
            url = sys.argv[idx + 1]
        else:
            print("[!] --url provided but no URL specified.")
            sys.exit(1)

    # 1. Install/check all tools before starting scans
    ensure_tools_installed()

    # 2. Write domain to file
    write_domain_file(domain)

    # 3. Run initial subdomain enumeration & URL collection tools in parallel
    await asyncio.gather(
        recon_subfinder(domain),
        recon_assetfinder(domain),
        recon_gau(domain),
        recon_wayback(domain),
        recon_paramspider(domain),
    )

    # 4. Merge subdomains after subfinder and assetfinder complete
    await recon_merge_subs()

    # 5. Run httpx CLI scan on merged subdomains
    await recon_httpx_cli()

    # 6. Run HTTP scan via aiohttp on merged subdomains
    await recon_httpx_async()

    # 7. Run URL-related scans if URL provided
    if url:
        await asyncio.gather(
            recon_gobuster(url),
            recon_dirsearch(url),
        )

if __name__ == "__main__":
    asyncio.run(main())
