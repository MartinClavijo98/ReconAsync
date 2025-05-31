#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filename    : recon.py
Description : Cross-platform reconnaissance automation script
              - Checks for required tools, installs if missing
              - Runs recon commands in parallel
Usage       : python recon.py <target-domain> [--url <example-url>]
"""

import os
import sys
import subprocess
import shutil
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------
#      Global Variables
# ----------------------------

# List of Go-based tools with their Go install paths
GO_TOOLS = {
    "subfinder":        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder":      "github.com/tomnomnom/assetfinder@latest",
    "httpx":            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gobuster":         "github.com/OJ/gobuster/v3@latest",
    "paramspider":      "github.com/devanshbatham/ParamSpider@latest",
    "gau":              "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls":      "github.com/tomnomnom/waybackurls@latest"
}

# Python-based tools (name -> pip package)
PYPI_TOOLS = {
    "dirsearch":        "dirsearch"
}

# ----------------------------
#        Helper Functions
# ----------------------------

def is_windows():
    """Return True if running on Windows."""
    return platform.system().lower().startswith("win")

def is_linux():
    """Return True if running on Linux."""
    return platform.system().lower().startswith("linux")

def run_subprocess(cmd, capture_output=False):
    """
    Run a shell command. 
    If capture_output is True, return (stdout, stderr), else return (returncode, None).
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

def install_go_linux():
    """
    Attempt to install Go on Linux via apt-get.
    """
    print("[*] Installing Go (golang-go) via apt-get...")
    run_subprocess("sudo apt-get update -y")
    code, err = run_subprocess("sudo apt-get install -y golang-go", capture_output=True)
    if code == 0:
        print("[+] Go installed successfully.")
    else:
        print(f"[!] Failed to install Go: {err}")
        sys.exit(1)

def install_go_windows():
    """
    Attempt to install Go on Windows via choco or winget.
    """
    print("[*] Installing Go on Windows via choco or winget...")
    if check_binary("choco"):
        ret, err = run_subprocess("choco install golang -y", capture_output=True)
        if ret == 0:
            print("[+] Go installed successfully via choco.")
            return
    if check_binary("winget"):
        ret, err = run_subprocess("winget install --id Go.Go -e --source winget", capture_output=True)
        if ret == 0:
            print("[+] Go installed successfully via winget.")
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

def install_go_tool(tool_name, go_path):
    """
    Install a Go-based tool via `go install ...@latest`.
    """
    print(f"[*] Installing Go-based tool: {tool_name} ...")
    cmd = f"go install {go_path}"
    ret, err = run_subprocess(cmd, capture_output=True)
    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
    else:
        print(f"[!] Failed to install {tool_name}: {err}")

def install_python_tool(tool_name, package_name):
    """
    Install a Python-based tool via pip.
    """
    print(f"[*] Installing Python-based tool: {tool_name} ...")
    pip_cmd = "pip" if check_binary("pip") else "pip3"
    cmd = f"{pip_cmd} install {package_name}"
    ret, err = run_subprocess(cmd, capture_output=True)
    if ret == 0:
        print(f"[+] {tool_name} installed successfully.")
    else:
        print(f"[!] Failed to install {tool_name}: {err}")

def ensure_tools_installed():
    """
    Check and install all required tools.
    """
    # 1. Ensure Go is present for Go-based tools
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

    # 4. Special note for waybackurls (binary name: waybackurls)
    if not check_binary("waybackurls"):
        # Already covered as Go tool above
        pass

    print("[+] All required tools are installed or already present.")

def write_domain_file(domain):
    """
    Write the target domain into 'domain.txt'.
    """
    with open("domain.txt", "w") as f:
        f.write(domain + "\n")

# ----------------------------
#       Recon Functions
# ----------------------------

def recon_subfinder(domain):
    """
    Run subfinder and save output.
    """
    outfile = "subfinder.txt"
    cmd = f"subfinder -d {domain}"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] subfinder results → {outfile}")

def recon_assetfinder(domain):
    """
    Run assetfinder and save output.
    """
    outfile = "assetfinder.txt"
    cmd = f"assetfinder {domain}"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] assetfinder results → {outfile}")

def recon_merge_subs():
    """
    Merge and dedupe subdomains from subfinder.txt & assetfinder.txt → uniq_subs.txt
    """
    outfile = "uniq_subs.txt"
    cmd = "cat subfinder.txt assetfinder.txt | sort -u"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] Unique subdomains → {outfile}")

def recon_httpx():
    """
    Run httpx on uniq_subs.txt → httpx-toolkit.txt
    """
    infile = "uniq_subs.txt"
    outfile = "httpx-toolkit.txt"
    cmd = f"cat {infile} | httpx -sc -location -ip -title -tech-detect"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] httpx results → {outfile}")

def recon_wayback(domain):
    """
    Run waybackurls on domain → waybackurls.txt
    """
    infile = "domain.txt"
    outfile = "waybackurls.txt"
    cmd = f"cat {infile} | waybackurls"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] waybackurls results → {outfile}")

def recon_gau(domain):
    """
    Run gau on domain → gau.txt
    """
    outfile = "gau.txt"
    cmd = f"gau {domain}"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] gau results → {outfile}")

def recon_paramspider(domain):
    """
    Run paramspider on domain with and without custom payload.
    """
    # 1. Default scan
    outfile1 = "paramspider.txt"
    cmd1 = f"paramspider -d {domain} -s"
    print(f"[+] Running: {cmd1}")
    out1, err1 = run_subprocess(cmd1, capture_output=True)
    if out1:
        with open(outfile1, "w") as f:
            f.write(out1 + "\n")
        print(f"[+] paramspider results → {outfile1}")

    # 2. Custom payload example
    payload = "--><h1>40sp31</h1>"
    cmd2 = f"paramspider -d {domain} -p '{payload}'"
    print(f"[+] Running: {cmd2}")
    out2, err2 = run_subprocess(cmd2, capture_output=True)
    # not saving to file for custom payload, just printing
    if out2:
        print(f"[+] paramspider (custom payload) found:\n{out2}")

def recon_gobuster(url):
    """
    Run gobuster dir brute-forcing. URL must be provided by user.
    """
    wordlist = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
    outfile = "gobuster.txt"
    cmd = f"gobuster dir -u {url} -w {wordlist}"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] gobuster results → {outfile}")

def recon_dirsearch(url):
    """
    Run dirsearch on given URL.
    """
    outfile = "dirsearch.txt"
    cmd = f"dirsearch -u {url}"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        with open(outfile, "w") as f:
            f.write(out + "\n")
        print(f"[+] dirsearch results → {outfile}")

def recon_extract_urls(filename):
    """
    Extract URLs from a given file via grep (regex).
    Filename (e.g. filename.txt) must exist.
    """
    cmd = f"grep -Eo 'https?://[^ ]+?[a-zA-Z0-9\\-_.]+([^& ]+)' {filename} | grep -v '&'"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        print(f"[+] Extracted URLs from {filename}:\n{out}")

def recon_assetfinder_subs_only(domains_file):
    """
    Run `assetfinder --subs-only` on a file named 'domains'.
    """
    cmd = f"cat {domains_file} | assetfinder --subs-only"
    print(f"[+] Running: {cmd}")
    out, err = run_subprocess(cmd, capture_output=True)
    if out:
        print(f"[+] assetfinder --subs-only output:\n{out}")

# ----------------------------
#         Main Workflow
# ----------------------------

def main():
    # 1. Parse command-line arguments
    if len(sys.argv) < 2:
        print("Usage: python recon.py <target-domain> [--url <example-url>]")
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

    # 2. Ensure all tools are installed
    ensure_tools_installed()

    # 3. Write domain.txt
    write_domain_file(domain)

    # 4. Prepare a list of recon tasks to run in parallel
    tasks = []
    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        # subfinder
        tasks.append(executor.submit(recon_subfinder, domain))
        # assetfinder
        tasks.append(executor.submit(recon_assetfinder, domain))
        # After both subfinder & assetfinder finish, merge
        # Note: we wait for them to complete below before merging
        # gau, wayback, paramspider can run immediately
        tasks.append(executor.submit(recon_gau, domain))
        tasks.append(executor.submit(recon_wayback, domain))
        tasks.append(executor.submit(recon_paramspider, domain))

        # Extract URLs from a pre-existing file "filename.txt"
        if os.path.exists("filename.txt"):
            tasks.append(executor.submit(recon_extract_urls, "filename.txt"))
        else:
            print("[*] filename.txt not found, skipping URL extraction step.")

        # assetfinder --subs-only on "domains" if exists
        if os.path.exists("domains"):
            tasks.append(executor.submit(recon_assetfinder_subs_only, "domains"))
        else:
            print("[*] domains file not found, skipping assetfinder --subs-only step.")

        # gobuster & dirsearch require user-provided URL
        if url:
            tasks.append(executor.submit(recon_gobuster, url))
            tasks.append(executor.submit(recon_dirsearch, url))
        else:
            print("[*] No --url provided, skipping gobuster & dirsearch steps.")

        # Wait for subfinder & assetfinder to finish before merging
        for future in as_completed(tasks):
            pass  # just ensuring subfinder/assetfinder finish

    # 5. Now that subfinder.txt & assetfinder.txt exist, merge them
    if os.path.exists("subfinder.txt") and os.path.exists("assetfinder.txt"):
        recon_merge_subs()
        # run httpx on merged subdomains
        recon_httpx()
    else:
        print("[!] subfinder.txt or assetfinder.txt missing, skipping merge and httpx steps.")

    print("\n[+] Recon workflow completed.")

if __name__ == "__main__":
    main()
