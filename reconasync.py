#!/usr/bin/env python3
"""
Enhanced Reconnaissance Toolkit (ERT) - Optimized Final Version
Version: 2.1.1
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
from typing import Optional

# Configuration
VERSION = "2.1.1"
DEFAULT_WORDLIST = "directory-list-2.3-medium.txt"
WORDLIST_URL = f"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/{DEFAULT_WORDLIST}"
OUTPUT_DIR = "recon_results"
TOOL_TIMEOUT = 600  # 10 minutes
MAX_CONCURRENT_TOOLS = 4  # Limit concurrent processes

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
        "cmd": "httpx -list {input} -silent -json -o {output}"
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
        "cmd": "dirsearch -u {target} -e php,asp,aspx,jsp,html,js,json -w {wordlist} > {output}"
    },
    "paramspider": {
        "install": "pip install git+https://github.com/devanshbatham/ParamSpider.git",
        "cmd": "paramspider -d {target} > {output}"
    }
}

class ReconToolkit:
    def __init__(self):
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_TOOLS)
        self.running_processes = set()
        self.shutdown_event = asyncio.Event()

    def setup_environment(self):
        """Configure environment variables for Go tools."""
        os.environ.update({
            "GOPROXY": "https://goproxy.io,direct",
            "GO111MODULE": "on"
        })
        
        # Add Go bin to PATH if not present
        go_path = os.path.join(os.environ.get("GOPATH", os.path.join(os.getcwd(), "go")), "bin")
        if go_path not in os.environ["PATH"]:
            os.environ["PATH"] = f"{go_path}{os.pathsep}{os.environ['PATH']}"

    def check_requirements(self):
        """Verify all required binaries are available."""
        return [tool for tool in TOOLS if not shutil.which(tool)]

    async def install_tools(self):
        """Install missing tools automatically."""
        self.setup_environment()
        missing = self.check_requirements()
        
        if not missing:
            print("[*] All tools are already installed")
            return True
            
        print(f"[*] Installing missing tools: {', '.join(missing)}")
        
        for tool in missing:
            print(f"[*] Installing {tool}...")
            cmd = TOOLS[tool]["install"]
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.running_processes.add(proc)
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
                
                if proc.returncode == 0:
                    print(f"[+] Successfully installed {tool}")
                else:
                    print(f"[!] Failed to install {tool}: {stderr.decode().strip()}")
                    return False
            except asyncio.TimeoutError:
                proc.kill()
                print(f"[!] {tool} installation timed out")
                return False
            finally:
                self.running_processes.discard(proc)
                
        return True

    async def download_wordlist(self):
        """Download default wordlist if missing."""
        os.makedirs("wordlists", exist_ok=True)
        wordlist_path = os.path.join("wordlists", DEFAULT_WORDLIST)
        
        if not os.path.exists(wordlist_path):
            print("[*] Downloading wordlist...")
            proc = await asyncio.create_subprocess_shell(
                f"wget {WORDLIST_URL} -O {wordlist_path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.running_processes.add(proc)
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
                if proc.returncode != 0:
                    print(f"[!] Wordlist download failed: {stderr.decode().strip()}")
                    return False
                return True
            except asyncio.TimeoutError:
                proc.kill()
                print("[!] Wordlist download timed out")
                return False
            finally:
                self.running_processes.discard(proc)
        return True

    async def run_tool(self, tool_name: str, target: str, output_file: str, 
                      input_file: Optional[str] = None, wordlist: Optional[str] = None) -> bool:
        """Execute a recon tool asynchronously with proper resource cleanup."""
        async with self.semaphore:
            if self.shutdown_event.is_set():
                return False
                
            template = TOOLS[tool_name]["cmd"]
            cmd = template.format(
                target=target,
                output=output_file,
                input=input_file or "",
                wordlist=wordlist or ""
            )
            
            print(f"[*] Running {tool_name}...")
            proc = None
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                self.running_processes.add(proc)
                
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT)
                
                if proc.returncode != 0:
                    print(f"[!] {tool_name} failed: {stderr.decode().strip()}")
                    return False
                    
                print(f"[+] {tool_name} completed successfully")
                return True
                
            except asyncio.TimeoutError:
                if proc:
                    proc.kill()
                    await proc.wait()
                print(f"[!] {tool_name} timed out")
                return False
            except Exception as e:
                print(f"[!] {tool_name} encountered an error: {str(e)}")
                return False
            finally:
                if proc:
                    self.running_processes.discard(proc)
                    if proc.returncode is None:
                        proc.kill()
                        await proc.wait()

    async def run_recon(self, domain: str, url: Optional[str] = None):
        """Main reconnaissance workflow with proper task management."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(OUTPUT_DIR, f"scan_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"[*] Starting reconnaissance on {domain}")
        print(f"[*] Results will be saved to: {output_dir}")
        
        try:
            # Subdomain discovery
            subdomains_file = os.path.join(output_dir, "subdomains.txt")
            tasks = [
                self.run_tool("subfinder", domain, subdomains_file),
                self.run_tool("assetfinder", domain, subdomains_file)
            ]
            
            # Wait for subdomain discovery before HTTP probing
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # HTTP probing
            httpx_file = os.path.join(output_dir, "httpx_results.json")
            await self.run_tool("httpx", "", httpx_file, input_file=subdomains_file)
            
            # URL discovery (run in parallel)
            url_tasks = [
                self.run_tool("gau", domain, os.path.join(output_dir, "urls_gau.txt")),
                self.run_tool("waybackurls", domain, os.path.join(output_dir, "urls_wayback.txt")),
                self.run_tool("paramspider", domain, os.path.join(output_dir, "paramspider_results.txt"))
            ]
            await asyncio.gather(*url_tasks, return_exceptions=True)
            
            # Directory brute-forcing
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = f"http://{url}"
                    
                wordlist_path = os.path.join("wordlists", DEFAULT_WORDLIST)
                await self.run_tool(
                    "dirsearch", 
                    url, 
                    os.path.join(output_dir, "dirsearch_results.txt"),
                    wordlist=wordlist_path
                )
            
            print(f"[+] Reconnaissance completed. Results saved to {output_dir}")
            
        except Exception as e:
            print(f"[!] Reconnaissance failed: {str(e)}")
            raise

    async def shutdown(self):
        """Cleanup all running processes."""
        self.shutdown_event.set()
        if self.running_processes:
            print("[*] Shutting down running processes...")
            for proc in self.running_processes:
                if proc.returncode is None:
                    proc.kill()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        pass

def signal_handler(recon_toolkit):
    """Handle interrupt signals."""
    def handler(signum, frame):
        print(f"\n[!] Received signal {signum}, shutting down...")
        asyncio.create_task(recon_toolkit.shutdown())
    return handler

async def main():
    parser = argparse.ArgumentParser(description=f"Enhanced Reconnaissance Toolkit v{VERSION}")
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('--url', help='Specific URL for directory scanning')
    parser.add_argument('--install', action='store_true', help='Install tools only')
    args = parser.parse_args()

    recon = ReconToolkit()
    
    # Setup signal handling
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal_handler(recon))
    
    if args.install:
        if not await recon.install_tools():
            sys.exit(1)
        return
    
    if missing := recon.check_requirements():
        print(f"[!] Missing required tools: {', '.join(missing)}. Run with --install first")
        sys.exit(1)
        
    if not await recon.download_wordlist():
        print("[!] Wordlist download failed")
    
    try:
        await recon.run_recon(args.domain, args.url)
    except Exception as e:
        print(f"[!] Fatal error: {str(e)}")
        sys.exit(1)
    finally:
        await recon.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
