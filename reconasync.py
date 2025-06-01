import subprocess
import shutil
import platform
import sys
import concurrent.futures

# ======================================
#       Check Linux Environment
# ======================================
if platform.system().lower() != "linux":
    print("[-] This script only works on Linux.")
    sys.exit(1)

# ======================================
#        Tool Installation Map
# ======================================
# Each key is the command to check; each value is the shell command to install it.
TOOL_INSTALL_CMDS = {
    "subfinder":  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    # Note: httpx-toolkit might not be a separate install; we'll install httpx
    "httpx-toolkit": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "gau":         "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "paramspider": "pip3 install paramspider",
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
        # For httpx-toolkit, check if 'httpx' binary exists
        check_name = tool_cmd
        if tool_cmd == "httpx-toolkit":
            check_name = "httpx"
        if not tool_exists(check_name):
            print(f"[!] {check_name} not found. Installing via: {install_cmd}")
            subprocess.run(install_cmd, shell=True, executable="/bin/bash")
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
    tasks.append((f"subfinder -d {domain}", "subfinder.txt"))

    # 3. assetfinder domain -> assetfinder.txt
    tasks.append((f"assetfinder {domain}", "assetfinder.txt"))

    # 4. merge subfinder.txt & assetfinder.txt -> uniq_subs.txt
    tasks.append(("cat subfinder.txt assetfinder.txt | sort -u", "uniq_subs.txt"))

    # 5. httpx-toolkit on uniq_subs -> httpx-toolkit.txt
    # Note: using httpx (installed above) with same flags as toolkit
    tasks.append(("cat uniq_subs.txt | httpx -silent -sc -location -ip -title -tech-detect", "httpx-toolkit.txt"))

    # 6. waybackurls from domain.txt -> waybackurls.txt
    tasks.append(("cat domain.txt | waybackurls", "waybackurls.txt"))

    # 7. grep URLs from filename.txt (no output file)
    tasks.append(("grep -Eo 'https?://[^ ]+?[a-zA-Z0-9\\-_.]+([^& ]+)' filename.txt | grep -v '&'", None))

    # 8. gobuster dir -u <URL> -w wordlist (no output file)
    #    User should replace <URL> with actual value or we could assume https://domain
    tasks.append((f"gobuster dir -u https://{domain} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt", None))

    # 9. cat domains | assetfinder --subs-only (no output file)
    tasks.append(("cat domains | assetfinder --subs-only", None))

    # 10. dirsearch -u <URL> (no output file)
    tasks.append((f"dirsearch -u https://{domain}", None))

    # 11. paramspider -d domain -s -> paramspider.txt
    tasks.append((f"paramspider -d {domain} -s", "paramspider.txt"))

    # 12. paramspider -d domain -p '--><h1>40sp31</h1>' (no explicit output file)
    tasks.append((f"paramspider -d {domain} -p '--><h1>40sp31</h1>'", None))

    # 13. ./gau domain (no output file)
    tasks.append((f"./gau {domain}", None))

    return tasks

# ======================================
#    Run Recon in Parallel Threads
# ======================================
def run_recon_parallel(domain):
    """
    Dispatch all recon commands in parallel threads using ThreadPoolExecutor.
    """
    tasks = build_recon_tasks(domain)

    # Use max_workers = number of tasks or a fixed number, e.g. 10
    max_workers = min(len(tasks), 10)
    print(f"[+] Running recon with up to {max_workers} parallel workers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for cmd, outfile in tasks:
            # Each future will call run_command(cmd, outfile)
            futures.append(executor.submit(run_command, cmd, outfile))

        # Wait for all to complete
        concurrent.futures.wait(futures)

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
