#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Linux Reconnaissance Automation Script
- Better error handling and ARM architecture support
- Improved URL/domain handling
- Graceful recovery from interruptions
- Progress tracking
"""

import os
import sys
import subprocess
import shutil
import signal
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

# ----------------------------
#      Configuration
# ----------------------------

# Go tools with installation paths
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gobuster": "github.com/OJ/gobuster/v3@latest",
    "paramspider": "github.com/devanshbatham/ParamSpider@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest"
}

# Python tools
PYPI_TOOLS = {
    "dirsearch": "dirsearch"
}

# Wordlist for directory brute-forcing
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"

# Timeout for subprocesses (seconds)
PROCESS_TIMEOUT = 1800  # 30 minutes

# ----------------------------
#      Helper Functions
# ----------------------------

def print_status(message):
    """Print status messages with consistent formatting"""
    print(f"[*] {message}")

def print_success(message):
    """Print success messages"""
    print(f"[+] {message}")

def print_error(message):
    """Print error messages to stderr"""
    print(f"[!] {message}", file=sys.stderr)

def get_go_bin_path():
    """Get the Go binary path"""
    go_path = os.path.join(os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin")
    return go_path

def setup_environment():
    """Set up PATH environment to include Go binaries"""
    go_bin_path = get_go_bin_path()
    if go_bin_path not in os.environ["PATH"]:
        os.environ["PATH"] = f"{go_bin_path}:{os.environ['PATH']}"

def is_arm_architecture():
    """Check if running on ARM architecture"""
    return platform.machine().lower() in ('arm', 'arm64', 'aarch64')

def check_installed(tool):
    """Check if a tool is installed and in PATH"""
    return shutil.which(tool) is not None

def run_command(cmd, timeout=PROCESS_TIMEOUT, cwd=None):
    """Run a command with timeout and proper error handling"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        print_error(f"Command timed out: {cmd}")
        return None, "Command timed out", -1
    except Exception as e:
        print_error(f"Error running command: {cmd}\n{str(e)}")
        return None, str(e), -1

def install_go():
    """Install Go on Linux with ARM support"""
    print_status("Installing Go...")
    
    if is_arm_architecture():
        print_status("ARM architecture detected - installing Go for ARM")
        install_cmd = """
        wget https://golang.org/dl/go1.20.linux-arm64.tar.gz
        sudo tar -C /usr/local -xzf go1.20.linux-arm64.tar.gz
        rm go1.20.linux-arm64.tar.gz
        """
    else:
        install_cmd = "sudo apt-get update && sudo apt-get install -y golang-go"
    
    stdout, stderr, retcode = run_command(install_cmd)
    if retcode == 0:
        # Add Go to PATH
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write('\nexport PATH=$PATH:/usr/local/go/bin\nexport GOPATH=$HOME/go\n')
        os.environ["PATH"] += ":/usr/local/go/bin"
        os.environ["GOPATH"] = os.path.expanduser("~/go")
        print_success("Go installed successfully")
        return True
    else:
        print_error(f"Failed to install Go: {stderr}")
        return False

def install_go_tool(name, path):
    """Install a Go tool with ARM support"""
    print_status(f"Installing {name}...")
    
    env = os.environ.copy()
    if is_arm_architecture():
        env["GOARCH"] = "arm64"
    
    cmd = f"go install {path}"
    stdout, stderr, retcode = run_command(cmd, env=env)
    
    if retcode == 0:
        print_success(f"{name} installed successfully")
        return True
    else:
        print_error(f"Failed to install {name}: {stderr}")
        return False

def install_python_tool(name, package):
    """Install a Python tool via pip"""
    print_status(f"Installing {name}...")
    pip = "pip3" if shutil.which("pip3") else "pip"
    cmd = f"{pip} install {package}"
    stdout, stderr, retcode = run_command(cmd)
    
    if retcode == 0:
        print_success(f"{name} installed successfully")
        return True
    else:
        print_error(f"Failed to install {name}: {stderr}")
        return False

def ensure_tools():
    """Ensure all required tools are installed"""
    setup_environment()
    
    # Check Go installation
    if not check_installed("go"):
        if not install_go():
            sys.exit(1)
    
    # Install Go tools
    for tool, path in GO_TOOLS.items():
        if not check_installed(tool):
            if not install_go_tool(tool, path):
                print_error(f"Skipping {tool} as installation failed")
                GO_TOOLS.pop(tool)  # Remove from tools to use
    
    # Install Python tools
    for tool, package in PYPI_TOOLS.items():
        if not check_installed(tool):
            if not install_python_tool(tool, package):
                print_error(f"Skipping {tool} as installation failed")
                PYPI_TOOLS.pop(tool)  # Remove from tools to use
    
    print_success("Tool verification complete")

def extract_domain(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc
    return url.split('/')[0]

def write_file(filename, content):
    """Write content to file with error handling"""
    try:
        with open(filename, 'w') as f:
            if isinstance(content, str):
                f.write(content + "\n")
            else:
                f.writelines(line + "\n" for line in content if line.strip())
        return True
    except IOError as e:
        print_error(f"Failed to write {filename}: {str(e)}")
        return False

def handle_interrupt(signum, frame):
    """Handle keyboard interrupt"""
    print_error("\nReceived interrupt signal. Cleaning up...")
    sys.exit(1)

# ----------------------------
#      Recon Functions
# ----------------------------

def run_subfinder(domain):
    """Run subfinder and save results"""
    output_file = "subfinder.txt"
    cmd = f"subfinder -d {domain} -silent"
    print_status(f"Running subfinder on {domain}")
    
    stdout, stderr, retcode = run_command(cmd)
    if stdout and retcode == 0:
        if write_file(output_file, stdout):
            print_success(f"Subfinder results saved to {output_file}")
            return True
    print_error(f"Subfinder failed: {stderr}")
    return False

def run_assetfinder(domain):
    """Run assetfinder and save results"""
    output_file = "assetfinder.txt"
    cmd = f"assetfinder --subs-only {domain}"
    print_status(f"Running assetfinder on {domain}")
    
    stdout, stderr, retcode = run_command(cmd)
    if stdout and retcode == 0:
        if write_file(output_file, stdout):
            print_success(f"Assetfinder results saved to {output_file}")
            return True
    print_error(f"Assetfinder failed: {stderr}")
    return False

def merge_subdomains():
    """Merge and deduplicate subdomain lists"""
    input_files = [f for f in ["subfinder.txt", "assetfinder.txt"] if Path(f).is_file()]
    
    if not input_files:
        print_error("No subdomain files found to merge")
        return False
    
    output_file = "uniq_subs.txt"
    print_status("Merging subdomain lists")
    
    try:
        # Read all lines from all files
        subdomains = set()
        for f in input_files:
            with open(f) as infile:
                subdomains.update(line.strip() for line in infile if line.strip())
        
        if subdomains:
            if write_file(output_file, sorted(subdomains)):
                print_success(f"Merged {len(subdomains)} subdomains to {output_file}")
                return True
    except Exception as e:
        print_error(f"Failed to merge subdomains: {str(e)}")
    
    return False

def run_httpx():
    """Run httpx on subdomains"""
    input_file = "uniq_subs.txt"
    output_file = "httpx_results.txt"
    
    if not Path(input_file).is_file():
        print_error(f"Missing input file: {input_file}")
        return False
    
    print_status("Running httpx on subdomains")
    cmd = f"httpx -list {input_file} -sc -title -tech-detect -ip -o {output_file}"
    _, stderr, retcode = run_command(cmd)
    
    if retcode == 0:
        print_success(f"HTTPX results saved to {output_file}")
        return True
    else:
        print_error(f"HTTPX failed: {stderr}")
        return False

def run_waybackurls(domain):
    """Run waybackurls on domain"""
    output_file = "waybackurls.txt"
    cmd = f"echo {domain} | waybackurls"
    print_status(f"Running waybackurls on {domain}")
    
    stdout, stderr, retcode = run_command(cmd)
    if stdout and retcode == 0:
        if write_file(output_file, stdout.splitlines()):
            print_success(f"Waybackurls results saved to {output_file}")
            return True
    print_error(f"Waybackurls failed: {stderr}")
    return False

def run_gau(domain):
    """Run gau on domain"""
    output_file = "gau_results.txt"
    cmd = f"gau {domain}"
    print_status(f"Running gau on {domain}")
    
    stdout, stderr, retcode = run_command(cmd)
    if stdout and retcode == 0:
        if write_file(output_file, stdout.splitlines()):
            print_success(f"GAU results saved to {output_file}")
            return True
    print_error(f"GAU failed: {stderr}")
    return False

def run_paramspider(domain):
    """Run paramspider on domain with timeout handling"""
    output_file = "paramspider.txt"
    cmd = f"paramspider -d {domain} > {output_file}"
    print_status(f"Running paramspider on {domain}")
    
    _, stderr, retcode = run_command(cmd, timeout=900)  # 15 minute timeout
    
    if retcode == 0 and Path(output_file).is_file():
        print_success(f"Paramspider results saved to {output_file}")
        return True
    print_error(f"Paramspider failed: {stderr}")
    return False

def run_gobuster(url):
    """Run gobuster directory brute-forcing"""
    if not Path(WORDLIST).is_file():
        print_error(f"Wordlist not found: {WORDLIST}")
        return False
    
    output_file = "gobuster.txt"
    cmd = f"gobuster dir -u {url} -w {WORDLIST} -o {output_file}"
    print_status(f"Running gobuster on {url}")
    
    _, stderr, retcode = run_command(cmd)
    if retcode == 0:
        print_success(f"Gobuster results saved to {output_file}")
        return True
    print_error(f"Gobuster failed: {stderr}")
    return False

def run_dirsearch(url):
    """Run dirsearch directory scanning"""
    output_file = "dirsearch.txt"
    cmd = f"dirsearch -u {url} --plain-text-report={output_file}"
    print_status(f"Running dirsearch on {url}")
    
    _, stderr, retcode = run_command(cmd)
    if retcode == 0:
        print_success(f"Dirsearch results saved to {output_file}")
        return True
    print_error(f"Dirsearch failed: {stderr}")
    return False

# ----------------------------
#      Main Execution
# ----------------------------

def main():
    # Set up interrupt handler
    signal.signal(signal.SIGINT, handle_interrupt)
    
    # Check arguments
    if len(sys.argv) < 2:
        print("Usage: python recon.py <target-domain-or-url> [--url <target-url>]")
        sys.exit(1)
    
    target = sys.argv[1]
    domain = extract_domain(target)
    url = None
    
    # Parse optional URL argument
    if "--url" in sys.argv:
        try:
            url_idx = sys.argv.index("--url") + 1
            url = sys.argv[url_idx]
        except IndexError:
            print_error("--url provided but no URL specified")
            sys.exit(1)
    
    # Ensure tools are installed
    ensure_tools()
    
    # Create domain file
    write_file("domain.txt", domain)
    
    # Run recon tasks in parallel where possible
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        
        # Only add tools that were successfully installed
        if "subfinder" in GO_TOOLS:
            futures[executor.submit(run_subfinder, domain)] = "subfinder"
        if "assetfinder" in GO_TOOLS:
            futures[executor.submit(run_assetfinder, domain)] = "assetfinder"
        if "gau" in GO_TOOLS:
            futures[executor.submit(run_gau, domain)] = "gau"
        if "waybackurls" in GO_TOOLS:
            futures[executor.submit(run_waybackurls, domain)] = "waybackurls"
        if "paramspider" in GO_TOOLS:
            futures[executor.submit(run_paramspider, domain)] = "paramspider"
        
        # Wait for parallel tasks to complete
        for future in as_completed(futures):
            task_name = futures[future]
            try:
                success = future.result()
                if not success:
                    print_error(f"{task_name} task failed")
            except Exception as e:
                print_error(f"{task_name} task raised exception: {str(e)}")
    
    # Run sequential tasks that depend on previous results
    if not merge_subdomains():
        print_error("Failed to merge subdomains, skipping httpx")
    elif "httpx" in GO_TOOLS:
        run_httpx()
    
    # Run URL-based tools if URL provided
    if url:
        if "gobuster" in GO_TOOLS:
            run_gobuster(url)
        if "dirsearch" in PYPI_TOOLS:
            run_dirsearch(url)
    
    print_success("Reconnaissance completed")

if __name__ == "__main__":
    main()
