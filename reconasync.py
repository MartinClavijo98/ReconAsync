#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Reconnaissance Toolkit (ERT) - Fixed Version
A comprehensive asynchronous reconnaissance tool with automatic dependency management
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
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# Global Configuration
VERSION = "2.0.1"
AUTHOR = "AIGPTCODE"
LICENSE = "MIT"

# Tool Configuration
GO_TOOLS = {
    "subfinder": {
        "install": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "repo": "https://github.com/projectdiscovery/subfinder",
        "description": "Subdomain discovery tool"
    },
    "assetfinder": {
        "install": "github.com/tomnomnom/assetfinder@latest",
        "repo": "https://github.com/tomnomnom/assetfinder",
        "description": "Find domains and subdomains"
    },
    "httpx": {
        "install": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "repo": "https://github.com/projectdiscovery/httpx",
        "description": "Fast HTTP toolkit"
    },
    "gau": {
        "install": "github.com/lc/gau/v2/cmd/gau@latest",
        "repo": "https://github.com/lc/gau",
        "description": "Fetch known URLs from AlienVault's Open Threat Exchange"
    },
    "waybackurls": {
        "install": "github.com/tomnomnom/waybackurls@latest",
        "repo": "https://github.com/tomnomnom/waybackurls",
        "description": "Fetch archived URLs from Wayback Machine"
    }
}

PYPI_TOOLS = {
    "dirsearch": {
        "package": "dirsearch",
        "description": "Web path scanner"
    },
    "aiohttp": {
        "package": "aiohttp",
        "description": "Async HTTP client/server"
    }
}

# Wordlist configuration
DEFAULT_WORDLIST_NAME = "directory-list-2.3-medium.txt"
WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/" + DEFAULT_WORDLIST_NAME
WORDLIST_DIR = os.path.join(os.getcwd(), "wordlists")

# Performance configuration
MAX_HTTP_CONCURRENCY = 50
BATCH_SIZE = 20

# Path configuration
VENV_PATH = os.path.join(os.getcwd(), "recon_venv")
PYTHON_BIN = sys.executable
OUTPUT_DIR = os.path.join(os.getcwd(), "recon_results")
TOOL_TIMEOUT = 600  # 10 minutes per tool

class Color:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Display the tool banner"""
    banner = f"""
{Color.CYAN}{Color.BOLD}
███████╗██████╗ ███████╗ ██████╗ ██████╗ 
██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗
█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝
██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██╗
███████╗██║  ██║███████╗╚██████╔╝██║  ██║
╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{Color.RESET}
{Color.YELLOW}Enhanced Reconnaissance Toolkit (ERT) v{VERSION}{Color.RESET}
{Color.WHITE}Author: {AUTHOR} | License: {LICENSE}{Color.RESET}
"""
    print(banner)

def is_windows():
    """Check if the current OS is Windows."""
    return platform.system().lower().startswith("win")

def is_linux():
    """Check if the current OS is Linux."""
    return platform.system().lower().startswith("linux")

def create_output_dir():
    """Create the output directory with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(OUTPUT_DIR, f"scan_{timestamp}")
    os.makedirs(output_path, exist_ok=True)
    return output_path

def run_subprocess_sync(cmd, capture_output=False, cwd=None, timeout=None):
    """Run a shell command synchronously with better error handling."""
    try:
        if capture_output:
            proc = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                timeout=timeout
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        else:
            ret = subprocess.call(cmd, shell=True, cwd=cwd, timeout=timeout)
            return ret, None, None
    except subprocess.TimeoutExpired:
        print(f"{Color.RED}[!] Command timed out: {cmd}{Color.RESET}")
        return -2, None, "Command timed out"
    except Exception as e:
        print(f"{Color.RED}[!] Exception while running '{cmd}': {str(e)}{Color.RESET}")
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
        print(f"{Color.BLUE}[*] Creating Python virtual environment...{Color.RESET}")
        venv.create(VENV_PATH, with_pip=True)

    pip_path = os.path.join(VENV_PATH, "bin", "pip")
    if is_windows():
        pip_path = os.path.join(VENV_PATH, "Scripts", "pip.exe")

    return pip_path

def install_python_tool(tool_name, package_info):
    """Install a Python tool via pip in the virtual environment."""
    print(f"{Color.BLUE}[*] Installing Python tool: {tool_name}...{Color.RESET}")
    pip_path = create_virtualenv()
    cmd = f"{pip_path} install {package_info['package']} --break-system-packages"
    ret, out, err = run_subprocess_sync(cmd, capture_output=True)
    if ret == 0:
        print(f"{Color.GREEN}[+] {tool_name} installed successfully.{Color.RESET}")
        return True
    else:
        print(f"{Color.RED}[!] Failed to install {tool_name}: {err}{Color.RESET}")
        return False

def install_paramspider():
    """Install paramspider by cloning its GitHub repository and running setup.py."""
    print(f"{Color.BLUE}[*] Installing Python tool: paramspider...{Color.RESET}")
    if check_binary("paramspider"):
        print(f"{Color.GREEN}[+] paramspider is already installed.{Color.RESET}")
        return True

    tmp_dir = tempfile.mkdtemp(prefix="paramspider_")
    try:
        # Clone the paramspider repo
        repo_url = "https://github.com/devanshbatham/ParamSpider.git"
        clone_cmd = f"git clone {repo_url} {tmp_dir}"
        ret, out, err = run_subprocess_sync(clone_cmd, capture_output=True)
        if ret != 0:
            print(f"{Color.RED}[!] Failed to clone paramspider repo: {err}{Color.RESET}")
            return False

        # Install requirements
        req_file = os.path.join(tmp_dir, "requirements.txt")
        if os.path.isfile(req_file):
            pip_path = create_virtualenv()
            install_reqs_cmd = f"{pip_path} install -r {req_file} --break-system-packages"
            ret, out, err = run_subprocess_sync(install_reqs_cmd, capture_output=True)
            if ret != 0:
                print(f"{Color.YELLOW}[!] Failed to install paramspider requirements: {err}{Color.RESET}")

        # Run setup.py install
        setup_path = os.path.join(tmp_dir, "setup.py")
        if os.path.isfile(setup_path):
            install_cmd = f"{PYTHON_BIN} {setup_path} install"
            ret, out, err = run_subprocess_sync(install_cmd, capture_output=True)
            if ret == 0:
                print(f"{Color.GREEN}[+] paramspider installed successfully.{Color.RESET}")
                return True
            else:
                print(f"{Color.RED}[!] Failed to run paramspider setup.py: {err}{Color.RESET}")
                return False
        else:
            print(f"{Color.RED}[!] setup.py not found in paramspider repo.{Color.RESET}")
            return False
    except Exception as e:
        print(f"{Color.RED}[!] Exception during paramspider installation: {e}{Color.RESET}")
        return False
    finally:
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass

def install_go_tool(tool_name, go_info):
    """Install Go tools with proper error handling."""
    print(f"{Color.BLUE}[*] Installing Go tool: {tool_name}...{Color.RESET}")

    if not check_binary("go"):
        print(f"{Color.RED}[!] 'go' command not found. Please install Go before proceeding.{Color.RESET}")
        return False

    cmd = f"go install {go_info['install']}"
    ret, out, err = run_subprocess_sync(cmd, capture_output=True)
    if ret == 0:
        print(f"{Color.GREEN}[+] {tool_name} installed successfully.{Color.RESET}")
        return True

    print(f"{Color.RED}[!] Standard installation failed for {tool_name}: {err}{Color.RESET}")
    return False

def install_system_dependencies():
    """Install required system dependencies."""
    print(f"{Color.BLUE}[*] Checking system dependencies...{Color.RESET}")
    if is_linux():
        print(f"{Color.BLUE}[*] Installing basic system dependencies for Linux...{Color.RESET}")
        run_subprocess_sync("sudo apt-get update -y")
        run_subprocess_sync("sudo apt-get install -y git golang python3-venv python3-pip wget chromium-browser")
    elif is_windows():
        print(f"{Color.BLUE}[*] Please ensure you have Git, Go, and Python installed on Windows.{Color.RESET}")
        print(f"{Color.BLUE}[*] You may need to install Chocolatey first: https://chocolatey.org/install{Color.RESET}")
        run_subprocess_sync("choco install git golang python -y")

def ensure_wordlist():
    """Ensure the wordlist is available before starting reconnaissance."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    wordlist_path = os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST_NAME)

    if os.path.isfile(wordlist_path) and os.path.getsize(wordlist_path) > 0:
        print(f"{Color.GREEN}[+] Wordlist found at {wordlist_path}{Color.RESET}")
        return True

    print(f"{Color.BLUE}[*] Wordlist not found, attempting to download...{Color.RESET}")
    try:
        ret, out, err = run_subprocess_sync(f"wget {WORDLIST_URL} -O {wordlist_path}")
        if ret == 0 and os.path.getsize(wordlist_path) > 0:
            print(f"{Color.GREEN}[+] Successfully downloaded wordlist to {wordlist_path}{Color.RESET}")
            return True
        else:
            print(f"{Color.RED}[!] Failed to download wordlist: {err}{Color.RESET}")
            return False
    except Exception as e:
        print(f"{Color.RED}[!] Exception while downloading wordlist: {str(e)}{Color.RESET}")
        return False

def ensure_tools_installed():
    """Ensure all required tools are installed (Go, Python, paramspider)."""
    setup_environment()
    install_system_dependencies()

    # Install Go tools
    for tool, info in GO_TOOLS.items():
        if not check_binary(tool):
            success = install_go_tool(tool, info)
            if not success:
                print(f"{Color.YELLOW}[!] Warning: {tool} installation failed.{Color.RESET}")
        else:
            print(f"{Color.GREEN}[+] {tool} is already installed.{Color.RESET}")

    # Install Python tools via pip
    for tool, info in PYPI_TOOLS.items():
        if not check_binary(tool):
            success = install_python_tool(tool, info)
            if not success:
                print(f"{Color.YELLOW}[!] Warning: {tool} installation failed.{Color.RESET}")
        else:
            print(f"{Color.GREEN}[+] {tool} is already installed.{Color.RESET}")

    # Install paramspider
    if not check_binary("paramspider"):
        success = install_paramspider()
        if not success:
            print(f"{Color.YELLOW}[!] Warning: paramspider installation failed.{Color.RESET}")
    else:
        print(f"{Color.GREEN}[+] paramspider is already installed.{Color.RESET}")

    print(f"{Color.GREEN}[+] Tool installation verification complete.{Color.RESET}")

async def run_subprocess_async(cmd: str, outfile: str = None, timeout: int = TOOL_TIMEOUT):
    """Run a shell command asynchronously and optionally save output."""
    print(f"{Color.CYAN}[+] Running (async): {cmd}{Color.RESET}")
    
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise
            
        out_text = stdout.decode().strip() if stdout else ""
        err_text = stderr.decode().strip() if stderr else ""

        if process.returncode != 0:
            print(f"{Color.RED}[!] Command failed (rc={process.returncode}): {cmd}{Color.RESET}")
            if err_text:
                print(f"{Color.RED}    Error: {err_text}{Color.RESET}")
        else:
            if outfile and out_text:
                with open(outfile, "w", encoding="utf-8") as f:
                    f.write(out_text + "\n")
                print(f"{Color.GREEN}[+] Output saved to: {outfile}{Color.RESET}")
            elif out_text:
                print(out_text)
                
    except Exception as e:
        print(f"{Color.RED}[!] Exception while running command: {str(e)}{Color.RESET}")
        raise

async def recon_subfinder(domain: str, output_dir: str):
    """Run subfinder asynchronously and save results."""
    output_file = os.path.join(output_dir, "subfinder.txt")
    await run_subprocess_async(f"subfinder -d {domain} -o {output_file}")

async def recon_assetfinder(domain: str, output_dir: str):
    """Run assetfinder asynchronously and save results."""
    output_file = os.path.join(output_dir, "assetfinder.txt")
    await run_subprocess_async(f"assetfinder --subs-only {domain} > {output_file}")

async def merge_files(input_files, output_file):
    """Merge multiple files into one with unique entries."""
    unique_lines = set()
    for input_file in input_files:
        if os.path.exists(input_file):
            with open(input_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        unique_lines.add(line)
    
    if unique_lines:
        with open(output_file, "w", encoding="utf-8") as f:
            for line in sorted(unique_lines):
                f.write(line + "\n")
        print(f"{Color.GREEN}[+] Merged results written to {output_file}{Color.RESET}")
    else:
        print(f"{Color.YELLOW}[!] No data to merge for {output_file}{Color.RESET}")

async def recon_httpx_cli(output_dir: str):
    """Run httpx in CLI mode on unique subdomains."""
    input_file = os.path.join(output_dir, "uniq_subs.txt")
    output_file = os.path.join(output_dir, "httpx_cli.txt")
    
    if not os.path.exists(input_file):
        print(f"{Color.RED}[!] {input_file} not found, skipping httpx CLI step.{Color.RESET}")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        hosts = [line.strip() for line in f if line.strip()]

    with open(output_file, "w", encoding="utf-8") as out_f:
        for i in range(0, len(hosts), BATCH_SIZE):
            batch = hosts[i:i + BATCH_SIZE]
            batch_input = "\n".join([f"http://{host}" for host in batch])
            
            cmd = f"echo '{batch_input}' | httpx -silent"
            ret, out, err = run_subprocess_sync(cmd, capture_output=True)
            
            if ret == 0 and out:
                for line in out.splitlines():
                    if line.strip():
                        out_f.write(line.strip() + "\n")
            elif err:
                out_f.write(f"Error processing batch {i//BATCH_SIZE + 1}: {err}\n")

    print(f"{Color.GREEN}[+] httpx CLI scan saved to {output_file}{Color.RESET}")

async def recon_httpx_async(output_dir: str):
    """Run httpx asynchronously with detailed information."""
    input_file = os.path.join(output_dir, "uniq_subs.txt")
    output_file = os.path.join(output_dir, "httpx_async.csv")
    
    if not os.path.exists(input_file):
        print(f"{Color.RED}[!] {input_file} not found, skipping httpx async step.{Color.RESET}")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        hosts = [line.strip() for line in f if line.strip()]

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
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

    print(f"{Color.GREEN}[+] httpx async scan saved to {output_file}{Color.RESET}")

async def recon_gau(domain: str, output_dir: str):
    """Run gau to fetch URLs."""
    output_file = os.path.join(output_dir, "gau.txt")
    await run_subprocess_async(f"echo {domain} | gau > {output_file}")

async def recon_waybackurls(domain: str, output_dir: str):
    """Run waybackurls."""
    output_file = os.path.join(output_dir, "waybackurls.txt")
    await run_subprocess_async(f"echo {domain} | waybackurls > {output_file}")

async def recon_paramspider(domain: str, output_dir: str):
    """Run paramspider."""
    output_file = os.path.join(output_dir, "paramspider.txt")
    if not check_binary("paramspider"):
        print(f"{Color.RED}[!] paramspider binary not found, skipping.{Color.RESET}")
        return
    await run_subprocess_async(f"paramspider -d {domain} > {output_file}")

async def recon_dirsearch(url: str, output_dir: str):
    """Run dirsearch on a provided URL with fixed command syntax."""
    if not url:
        print(f"{Color.YELLOW}[!] URL not provided, skipping dirsearch.{Color.RESET}")
        return

    # Ensure URL has proper scheme
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"

    wordlist_path = os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST_NAME)
    if not os.path.isfile(wordlist_path) or os.path.getsize(wordlist_path) == 0:
        print(f"{Color.RED}[!] Wordlist not available, skipping dirsearch{Color.RESET}")
        return

    output_file = os.path.join(output_dir, "dirsearch.txt")
    dirsearch_cmd = (
        f"dirsearch -u {url} "
        f"-e php,asp,aspx,jsp,html,js,json "
        f"-w {wordlist_path} "
        f"-o {output_file}"  # Fixed: Changed from --plain-text-report to -o
    )
    await run_subprocess_async(dirsearch_cmd)

def main():
    print_banner()
    
    # Handle SIGINT (Ctrl+C) properly
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(1))
    
    parser = argparse.ArgumentParser(
        description='Enhanced Reconnaissance Toolkit (ERT) - Comprehensive security reconnaissance tool',
        epilog=f"Example: python3 {sys.argv[0]} example.com --url http://example.com"
    )
    parser.add_argument('domain', nargs='?', help='Target domain for reconnaissance')
    parser.add_argument('--url', type=str, help='Specific URL for directory brute-forcing')
    parser.add_argument('--install', action='store_true', help='Install required tools and exit')
    parser.add_argument('--output', type=str, help='Custom output directory path')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--version', action='store_true', help='Show version information and exit')
    
    args = parser.parse_args()

    if args.version:
        print(f"Enhanced Reconnaissance Toolkit (ERT) v{VERSION}")
        sys.exit(0)

    if args.no_color:
        for color in vars(Color).values():
            if isinstance(color, str):
                color = ""

    if args.install:
        print(f"{Color.BLUE}[*] Starting tool installation process...{Color.RESET}")
        ensure_tools_installed()
        ensure_wordlist()
        print(f"{Color.GREEN}[+] Installation complete. You can now run the reconnaissance.{Color.RESET}")
        sys.exit(0)

    if not args.domain and not args.url:
        parser.print_help()
        sys.exit(1)

    if args.url and not args.domain:
        parsed = urlparse(args.url)
        args.domain = parsed.netloc if parsed.netloc else args.url.split('/')[0]
        print(f"{Color.BLUE}[*] Extracted domain from URL: {args.domain}{Color.RESET}")

    domain = args.domain
    url = args.url

    # Create output directory
    output_dir = args.output if args.output else create_output_dir()
    print(f"{Color.BLUE}[*] Saving results to: {output_dir}{Color.RESET}")

    print(f"{Color.BLUE}[*] Starting reconnaissance on domain: {domain}{Color.RESET}")
    if url:
        print(f"{Color.BLUE}[*] URL provided for additional scanning: {url}{Color.RESET}")

    print(f"{Color.BLUE}[*] Verifying tool installation...{Color.RESET}")
    ensure_tools_installed()

    if not ensure_wordlist():
        print(f"{Color.YELLOW}[!] Wordlist is required but could not be downloaded. Directory brute-forcing will be disabled.{Color.RESET}")

    # Write domain file
    domain_file = os.path.join(output_dir, "domain.txt")
    with open(domain_file, "w", encoding="utf-8") as f:
        f.write(domain + "\n")
    print(f"{Color.GREEN}[+] Domain file created: {domain_file}{Color.RESET}")

    # Start reconnaissance tasks
    start_time = time.time()
    print(f"{Color.BLUE}[*] Starting reconnaissance tasks...{Color.RESET}")
    
    try:
        # Phase 1: Subdomain discovery
        await asyncio.gather(
            recon_subfinder(domain, output_dir),
            recon_assetfinder(domain, output_dir)
        )

        # Merge results
        subfinder_file = os.path.join(output_dir, "subfinder.txt")
        assetfinder_file = os.path.join(output_dir, "assetfinder.txt")
        uniq_subs_file = os.path.join(output_dir, "uniq_subs.txt")
        await merge_files([subfinder_file, assetfinder_file], uniq_subs_file)

        # Phase 2: HTTP probing
        await asyncio.gather(
            recon_httpx_cli(output_dir),
            recon_httpx_async(output_dir)
        )

        # Phase 3: URL discovery
        await asyncio.gather(
            recon_gau(domain, output_dir),
            recon_waybackurls(domain, output_dir),
            recon_paramspider(domain, output_dir)
        )

        # Phase 4: Directory brute-forcing (if URL provided)
        if url:
            await recon_dirsearch(url, output_dir)

        # Calculate execution time
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"{Color.GREEN}[+] Reconnaissance completed in {execution_time:.2f} seconds{Color.RESET}")
        print(f"{Color.GREEN}[+] Results saved in: {output_dir}{Color.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Process interrupted by user. Partial results may be available in {output_dir}{Color.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Color.RED}[!] An error occurred: {str(e)}{Color.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Process interrupted by user. Exiting...{Color.RESET}")
        sys.exit(1)
