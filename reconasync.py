import subprocess
import shutil
import platform
import sys
import os
import concurrent.futures

# ======================================
#       Check Linux Environment
# ======================================
if platform.system().lower() != "linux":
    print("[-] This script only works on Linux.")
    sys.exit(1)

# ======================================
#      Ensure GOPATH and Local Bin in PATH
# ======================================
# Set default GOPATH if unset
GOPATH = os.environ.get("GOPATH") or os.path.expanduser("~/go")
os.environ["GOPATH"] = GOPATH

# Add GOPATH/bin and ~/.local/bin to PATH so that go install / pip installs are found
go_bin = os.path.join(GOPATH, "bin")
local_bin = os.path.expanduser("~/.local/bin")
current_path = os.environ.get("PATH", "")

for p in (go_bin, local_bin):
    if p not in current_path:
        os.environ["PATH"] = p + os.pathsep + os.environ["PATH"]

# ======================================
#        Tool Installation Map
# ======================================
# Each key is the command name to check; each value is the shell command to install it.
TOOL_INSTALL_CMDS = {
    "subfinder":  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    # httpx-toolkit/install httpx to get httpx binary
    "httpx":      "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "gau":         "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "paramspider": "pip3 install --user paramspider",
    "gobuster":    "go install -v github.com/OJ/gobuster/v3@latest",
    "dirsearch":   (
        "if [ ! -d \"$HOME/tools/dirsearch\" ]; then "
        "git clone https://github.com/maurosoria/dirsearch.git \"$HOME/tools/dirsearch\" "
        "&& ln -sf \"$HOME/tools/dirsearch/dirsearch.py\" /usr/local/bin/dirsearch; "
        "fi"
    )
}

def tool_exists(cmd_name):
    """
    Check if a command exists in PATH.
    """
    return shutil.which(cmd_name) is not None

def install_missing_tools():
    """
    Iterate through TOOL_INSTALL_CMDS and install any tool that's missing.
    """
    for tool_cmd, install_cmd in TOOL_INSTALL_CMDS.items():
        # For httpx-toolkit, actual binary is 'httpx'; for dirsearch use 'dirsearch'
        check_name = tool_cmd
        if tool_cmd == "httpx":
            check_name = "httpx"
        if tool_cmd == "paramspider":
            check_name = "paramspider"
        if tool_cmd == "dirsearch":
            check_name = "dirsearch"

        if not tool_exists(check_name):
            print(f"[!] {check_name} not found. Installing via: {install_cmd}")
            # Use bash so that shell expansions (~, &&) کار کنند
            subprocess.run(install_cmd, shell=True, executable="/bin/bash", check=True)
        else:
            print(f"[+] {check_name} is already installed.")

# ======================================
#        Original Run Command
# ======================================
def run_command(command, output_file=None):
    print(f"[+] Running: {command}")
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.stdout:
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            print(f"[+] Output saved to: {output_file}")
        else:
            print(result.stdout)
    if result.stderr:
        print(f"[!] Error: {result.stderr}")

# ======================================
#     Build Command List for Recon
# ======================================
def build_recon_tasks(domain):
    """
    Return a list of tuples: (command_string, output_filename_or_None)
    according to the original run_recon logic.
    """
    tasks = []

    # 1. echo domain > domain.txt
    tasks.append((f"echo {domain} > domain.txt", None))

    # 2. subfinder -d domain -> subfinder.txt
    tasks.append((f"subfinder -d {domain} -silent", "subfinder.txt"))

    # 3. assetfinder domain -> assetfinder.txt
    tasks.append((f"assetfinder {domain}", "assetfinder.txt"))

    # 4. merge subfinder.txt & assetfinder.txt -> uniq_subs.txt
    tasks.append(("cat subfinder.txt assetfinder.txt | sort -u", "uniq_subs.txt"))

    # 5. httpx on uniq_subs -> httpx-toolkit.txt
    tasks.append(("cat uniq_subs.txt | httpx -silent -sc -location -ip -title -tech-detect", "httpx-toolkit.txt"))

    # 6. waybackurls from domain.txt -> waybackurls.txt
    tasks.append(("cat domain.txt | waybackurls", "waybackurls.txt"))

    # 7. grep URLs from filename.txt (no output file)
    tasks.append(("if [ -f filename.txt ]; then grep -Eo 'https?://[^ ]+?[a-zA-Z0-9\\-_.]+([^& ]+)' filename.txt | grep -v '&'; else echo '[!] filename.txt not found, skipping URL extract'; fi", None))

    # 8. gobuster dir -u https://domain -w wordlist (no output file)
    tasks.append((f"if [ -f /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt ]; then gobuster dir -u https://{domain} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -q -o gobuster.txt; else echo '[!] wordlist not found, skipping gobuster'; fi", None))

    # 9. cat domains | assetfinder --subs-only (no output file)
    tasks.append(("if [ -f domains ]; then cat domains | assetfinder --subs-only; else echo '[!] domains file not found, skipping assetfinder subs-only'; fi", None))

    # 10. dirsearch -u https://domain (no output file)
    tasks.append((f"dirsearch -u https://{domain} -e * -o dirsearch.txt", None))

    # 11. paramspider -d domain -s -> paramspider.txt
    tasks.append((f"paramspider -d {domain} -s -o paramspider.txt", None))

    # 12. paramspider -d domain -p '--><h1>40sp31</h1>' (no explicit output file)
    tasks.append((f"paramspider -d {domain} -p '--><h1>40sp31</h1>' >> paramspider.txt", None))

    # 13. gau domain -> gau.txt
    tasks.append((f"gau {domain} > gau.txt", None))

    return tasks

# ======================================
#    Run Recon in Parallel Threads
# ======================================
def run_recon_parallel(domain):
    """
    Dispatch all recon commands in parallel threads using ThreadPoolExecutor.
    """
    tasks = build_recon_tasks(domain)
    max_workers = min(len(tasks), 10)
    print(f"[+] Running recon with up to {max_workers} parallel workers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for cmd, outfile in tasks:
            futures.append(executor.submit(run_command, cmd, outfile))
        try:
            concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            print("\n[!] KeyboardInterrupt received. Cancelling tasks...")
            for f in futures:
                f.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            print("[+] Graceful shutdown.")
            sys.exit(0)

    print("[+] All recon tasks completed.")

# ======================================
#            Main Execution
# ======================================
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <target-domain>")
        sys.exit(1)

    target_domain = sys.argv[1]

    print("[*] Checking and installing missing tools...")
    install_missing_tools()

    print(f"[*] Starting recon on {target_domain} ...")
    run_recon_parallel(target_domain)

    print("[+] Recon workflow finished. Check generated files in current directory.")
