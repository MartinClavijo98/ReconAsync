#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filename    : recon_async.py
Description : Advanced cross-platform reconnaissance script using asyncio & aiohttp
              - Checks and installs required tools if missing
              - Executes recon commands as asynchronous subprocesses
              - Performs HTTP scanning with aiohttp for status, title, IP, server header
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

# ----------------------------
#      Global Configuration
# ----------------------------

# Go-based tools: binary name -> go install path
GO_TOOLS = {
    "subfinder":        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder":      "github.com/tomnomnom/assetfinder@latest",
    "httpx":            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gobuster":         "github.com/OJ/gobuster/v3@latest",
    "paramspider":      "github.com/devanshbatham/ParamSpider@latest",
    "gau":              "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls":      "github.com/tomnomnom/waybackurls@latest"
}

# Python-based tools: binary name -> pip package name
PYPI_TOOLS = {
    "dirsearch":        "dirsearch"
}

# Maximum number of concurrent HTTP requests via aiohttp
MAX_HTTP_CONCURRENCY = 50

# Default wordlist path (modify if needed)
DEFAULT_WORDLIST_LINUX = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
DEFAULT_WORDLIST_WINDOWS = r"C:\wordlists\directory-list-lowercase-2.3-medium.txt"

# ----------------------------
#      Helper Functions
# ----------------------------

def is_windows():
    """Return True if running on Windows."""
    return platform.system().lower().startswith("win")

def is_linux():
    """Return True if running on Linux."""
    return platform.system().lower().startswith("linux")

def run_subprocess_sync(cmd, capture_output=False):
    """
    Run a shell command synchronously.
    If capture_output is True, return (stdout, stderr) as strings.
    Otherwise, return (returncode, None).
    """
    try:
        if capture_output:
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return proc.stdout.strip(), proc.stderr.strip()
        else:
            ret = subprocess.call(cmd, shell=True)
            return ret, None
    except Exception as e:
        print(f"[!] Exception while running '{cmd}': {e}")
        return -1, str(e)

def check_binary(binary_name):
    """
    Check if a binary exists in PATH.
    Return True if found, False otherwise.
    """
    return shutil.which(binary_name) is not None

def append_go_bin_to_path():
    """
    If GO binaries were installed to GOPATH/bin or GOBIN, ensure that folder is in PATH.
    """
    # Check GOBIN first
    gobin = os.environ.get("GOBIN")
    if gobin and os.path.isdir(gobin):
        if gobin not in os.environ.get("PATH", ""):
            os.environ["PATH"] += os.pathsep + gobin
            print(f"[~] Added GOBIN ({gobin}) to PATH.")

    # If no GOBIN, check default GOPATH/bin
    gopath = os.environ.get("GOPATH")
    if gopath:
        bin_path = os.path.join(gopath, "bin")
        if os.path.isdir(bin_path) and bin_path not in os.environ.get("PATH", ""):
            os.environ["PATH"] += os.pathsep + bin_path
            print(f"[~] Added GOPATH/bin ({bin_path}) to PATH.")

def install_go_linux():
    """
    Attempt to install Go on Linux via apt-get.
    """
    print("[*] Installing Go (golang-go) via apt-get...")
    run_subprocess_sync("sudo apt-get update -y")
    code, err = run_subprocess_sync("sudo apt-get install -y golang-go", capture_output=True)
    if code == 0:
        print("[+] Go installed successfully.")
        append_go_bin_to_path()
    else:
        print(f"[!] Failed to install Go: {err}")
        sys.exit(1)

def install_go_windows():
    """
    Attempt to install Go on Windows via choco or winget.
    """
    print("[*] Installing Go on Windows via choco or winget...")
    if check_binary("choco"):
        ret, err = run_subprocess_sync("choco install golang -y", capture_output=True)
        if ret == 0:
            print("[+] Go installed successfully via choco.")
            append_go_bin_to_path()
            return
    if check_binary("winget"):
        ret, err = run_subprocess_sync("winget install --id Go.Go -e --source winget", capture_output=True)
        if ret == 0:
            print("[+] Go installed successfully via winget.")
            append_go_bin_to_path()
            return
    print("[!] Could not install Go automatically. Please install Go manually and re-run.")
    sys.exit(1)

def ensure_go_installed():
    """
    Ensure that 'go' binary exists. If not, attempt automatic installation.
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
    Install a Go-based tool via `go install ...@latest`.
    """
    print(f"[*] Installing Go-based tool: {tool_name} ...")
    # Ensure GO111MODULE=on to install from Go modules path
    cmd = f"GO111MODULE=on go install {go_path}"
    ret, err = run_subprocess_sync(cmd, capture_output=True)
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
    ret, err = run_subprocess_sync(cmd, capture_output=True)
    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
    else:
        print(f"[!] Failed to install {tool_name}: {err}")

def ensure_tools_installed():
    """
    Check and install all required tools:
    1. Ensure Go is present for Go-based tools.
    2. Install Go-based tools if missing.
    3. Install Python-based tools if missing.
    """
    # 1. Ensure Go is present
    ensure_go_installed()

    # 2. Install Go-based tools
    for binary, go_path in GO_TOOLS.items():
        if not check_binary(binary):
            install_go_tool(binary, go_path)
        else:
            print(f"[+] {binary} already installed.")

    # 3. Install Python-based tools
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
    with open("domain.txt", "w") as f:
        f.write(domain + "\n")
    print(f"[+] domain.txt created with {domain}")

# ----------------------------
#     Asynchronous Recon Tasks
# ----------------------------

async def run_subprocess_async(cmd: str, outfile: str = None):
    """
    Run a shell command asynchronously.
    If outfile is provided, capture stdout and save into that file.
    Otherwise, print stdout/stderr to console.
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
            with open(outfile, "w") as f:
                f.write(out_text + "\n")
            print(f"[+] Output saved to: {outfile}")
        elif out_text:
            print(out_text)

async def recon_subfinder(domain: str):
    """
    Run subfinder async and save output to subfinder.txt.
    """
    await run_subprocess_async(f"subfinder -d {domain}", "subfinder.txt")

async def recon_assetfinder(domain: str):
    """
    Run assetfinder async and save output to assetfinder.txt.
    """
    await run_subprocess_async(f"assetfinder {domain}", "assetfinder.txt")

async def recon_merge_subs():
    """
    Merge and dedupe subdomains from subfinder.txt & assetfinder.txt → uniq_subs.txt
    """
    if not (os.path.exists("subfinder.txt") and os.path.exists("assetfinder.txt")):
        print("[!] Cannot merge subs: subfinder.txt or assetfinder.txt missing.")
        return

    # Read both files in Python (cross-platform)
    subs = set()
    for fn in ["subfinder.txt", "assetfinder.txt"]:
        with open(fn, "r") as f:
            for line in f:
                host = line.strip()
                if host:
                    subs.add(host)

    # Write unique subdomains
    with open("uniq_subs.txt", "w") as f:
        for host in sorted(subs):
            f.write(host + "\n")
    print("[+] Unique subdomains written to uniq_subs.txt")

async def recon_httpx_async():
    """
    Perform HTTP scanning (status, title, IP, server header) on uniq_subs.txt via aiohttp.
    Save results to httpx_toolkit_async.txt
    """
    infile = "uniq_subs.txt"
    outfile = "httpx_toolkit_async.txt"

    if not os.path.exists(infile):
        print("[!] uniq_subs.txt not found, skipping httpx_async step.")
        return

    # Read all subdomains
    with open(infile, "r") as f:
        hosts = [line.strip() for line in f if line.strip()]

    # Semaphore to limit concurrency
    semaphore = asyncio.Semaphore(MAX_HTTP_CONCURRENCY)

    async def fetch_info(session: aiohttp.ClientSession, host: str):
        """
        Fetch status code, title tag, server header, and IP for a given host.
        Return a dict with results.
        """
        url = f"http://{host}"
        data = {"host": host, "status": None, "title": None, "server": None, "ip": None}

        # Resolve IP synchronously (socket.gethostbyname)
        try:
            ip_addr = socket.gethostbyname(host)
            data["ip"] = ip_addr
        except Exception:
            data["ip"] = "N/A"

        async with semaphore:
            try:
                async with session.get(url, timeout=10) as resp:
                    data["status"] = resp.status
                    # Get Server header if exists
                    data["server"] = resp.headers.get("Server", "N/A")

                    # Try to parse <title> … </title>
                    text = await resp.text()
                    low = text.lower()
                    start = low.find("<title>")
                    end = low.find("</title>")
                    if 0 <= start < end:
                        title_tag = text[start+7:end].strip()
                        data["title"] = title_tag
                    else:
                        data["title"] = "N/A"
            except Exception:
                data["status"] = "ERR"
                data["server"] = "N/A"
                data["title"] = "N/A"

        return data

    # Open aiohttp session
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_info(session, host) for host in hosts]
        results = await asyncio.gather(*tasks)

    # Write results to outfile in CSV format
    with open(outfile, "w", newline='', encoding='utf-8') as csvfile:
        fieldnames = ["host", "status", "ip", "server", "title"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for res in results:
            writer.writerow(res)

    print(f"[+] httpx_toolkit_async results saved → {outfile}")

async def recon_wayback(domain: str):
    """
    Run waybackurls async and save output to waybackurls.txt.
    """
    # Directly pass domain to waybackurls (cross-platform)
    await run_subprocess_async(f"waybackurls {domain}", "waybackurls.txt")

async def recon_gau(domain: str):
    """
    Run gau async and save output to gau.txt.
    """
    await run_subprocess_async(f"gau {domain}", "gau.txt")

async def recon_paramspider(domain: str):
    """
    Run paramspider async with default scan and custom payload.
    Save default scan to paramspider.txt; print custom payload output.
    """
    # Default scan
    await run_subprocess_async(f"paramspider -d {domain} -s", "paramspider.txt")

    # Custom payload
    payload = "--><h1>40sp31</h1>"
    cmd2 = f"paramspider -d {domain} -p '{payload}'"
    print(f"[+] Running (async): {cmd2}")
    process = await asyncio.create_subprocess_shell(
        cmd2,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    out_text = stdout.decode().strip()
    if out_text:
        print(f"[+] paramspider (custom payload) found:\n{out_text}")

async def recon_extract_urls(filename: str):
    """
    Extract URLs from a given file asynchronously using Python regex.
    Print results to console.
    """
    if not os.path.exists(filename):
        print(f"[*] {filename} not found, skipping URL extraction.")
        return

    import re
    pattern = re.compile(r"https?://[^\s'\"<>]+")
    extracted = set()

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for match in pattern.findall(line):
                # Exclude URLs containing '&'
                if "&" not in match:
                    extracted.add(match)

    if extracted:
        print(f"[+] Extracted URLs from {filename}:")
        for url in sorted(extracted):
            print(url)
    else:
        print(f"[*] No URLs found in {filename}.")

async def recon_assetfinder_subs_only(domains_file: str):
    """
    Run `assetfinder --subs-only` on a file named 'domains'.
    Print results to console.
    """
    if not os.path.exists(domains_file):
        print(f"[*] {domains_file} not found, skipping assetfinder --subs-only.")
        return

    # Read domains from file
    subs = set()
    with open(domains_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            dom = line.strip()
            if dom:
                subs.add(dom)

    # Write them to a temp file so we can pipe to assetfinder
    temp_input = "._tmp_domains_for_assetfinder.txt"
    with open(temp_input, "w") as tmpf:
        for dom in sorted(subs):
            tmpf.write(dom + "\n")

    cmd = f"assetfinder --subs-only -list {temp_input}"
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    out_text = stdout.decode().strip()
    if out_text:
        print(f"[+] assetfinder --subs-only output:")
        for line in out_text.splitlines():
            print(line)

    # Clean up temporary file
    try:
        os.remove(temp_input)
    except OSError:
        pass

async def recon_gobuster(url: str):
    """
    Run gobuster dir brute-forcing. URL must be provided by user.
    Save output to gobuster.txt.
    """
    if is_linux():
        wordlist = DEFAULT_WORDLIST_LINUX
    else:
        wordlist = DEFAULT_WORDLIST_WINDOWS

    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found at {wordlist}. Please update DEFAULT_WORDLIST_* accordingly.")
        return

    outfile = "gobuster.txt"
    cmd = f"gobuster dir -u {url} -w {wordlist}"
    await run_subprocess_async(cmd, outfile)

async def recon_dirsearch(url: str):
    """
    Run dirsearch on given URL. Save output to dirsearch.txt.
    """
    outfile = "dirsearch.txt"
    cmd = f"dirsearch -u {url}"
    await run_subprocess_async(cmd, outfile)

# ----------------------------
#       Main Async Routine
# ----------------------------

async def main():
    # 1. Parse command-line arguments
    if len(sys.argv) < 2:
        print("Usage: python recon_async.py <target-domain> [--url <example-url>]")
        sys.exit(1)

    domain = sys.argv[1]
    url = None
    # optional --url argument for gobuster/dirsearch
    if "--url" in sys.argv:
        idx = sys.argv.index("--url")
        if idx + 1 < len(sys.argv):
            url = sys.argv[idx + 1]
        else:
            print("[!] --url provided but no URL specified.")
            sys.exit(1)

    # 2. Ensure all tools are installed (synchronous step)
    ensure_tools_installed()

    # 3. Write domain.txt
    write_domain_file(domain)

    # 4. Prepare and run Recon tasks asynchronously
    tasks = []
    tasks.append(recon_subfinder(domain))
    tasks.append(recon_assetfinder(domain))
    tasks.append(recon_gau(domain))
    tasks.append(recon_wayback(domain))
    tasks.append(recon_paramspider(domain))

    if os.path.exists("filename.txt"):
        tasks.append(recon_extract_urls("filename.txt"))
    else:
        print("[*] filename.txt not found, skipping URL extraction step.")

    if os.path.exists("domains"):
        tasks.append(recon_assetfinder_subs_only("domains"))
    else:
        print("[*] domains file not found, skipping assetfinder --subs-only step.")

    # Gobuster & Dirsearch only if URL is provided
    if url:
        tasks.append(recon_gobuster(url))
        tasks.append(recon_dirsearch(url))
    else:
        print("[*] No --url provided, skipping gobuster & dirsearch steps.")

    # Run all tasks concurrently
    await asyncio.gather(*tasks)

    # 5. After subfinder & assetfinder are done, merge subdomains
    await recon_merge_subs()

    # 6. Run HTTP scanning (replacement for httpx) if uniq_subs.txt exists
    await recon_httpx_async()

    print("\n[+] Recon workflow completed.")

# Entry point
if __name__ == "__main__":
    # For Windows: apply necessary event loop policy
    if is_windows():
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
