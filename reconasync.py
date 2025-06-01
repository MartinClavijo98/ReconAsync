import subprocess
import shutil
import platform
import sys
import concurrent.futures
import os

# ================================
#     Check Linux Environment
# ================================
if platform.system().lower() != "linux":
    print("[-] This script only works on Linux.")
    sys.exit(1)

# ================================
#     Tool Installation Map
# ================================
TOOL_INSTALL_CMDS = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "paramspider": "pip3 install git+https://github.com/devanshbatham/ParamSpider.git",
    "gobuster": "go install -v github.com/OJ/gobuster/v3@latest",
    "dirsearch": (
        "if [ ! -d \"$HOME/tools/dirsearch\" ]; then "
        "git clone https://github.com/maurosoria/dirsearch.git \"$HOME/tools/dirsearch\" && "
        "ln -sf \"$HOME/tools/dirsearch/dirsearch.py\" /usr/local/bin/dirsearch; "
        "fi"
    )
}

def tool_exists(cmd_name):
    return shutil.which(cmd_name) is not None

def install_missing_tools():
    for tool, install_cmd in TOOL_INSTALL_CMDS.items():
        check_name = "httpx" if tool == "httpx-toolkit" else tool
        if not tool_exists(check_name):
            print(f"[!] Installing {check_name} ...")
            subprocess.run(install_cmd, shell=True, executable="/bin/bash")
        else:
            print(f"[+] {check_name} already installed.")

# ================================
#     Run a Shell Command
# ================================
def run_command(command, output_file=None):
    print(f"[+] Running: {command}")
    try:
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
    except KeyboardInterrupt:
        print("[!] KeyboardInterrupt received. Exiting gracefully...")

# ================================
#     Recon Task Builder
# ================================
def build_recon_tasks(domain):
    tasks = []

    # Prepare files
    tasks.append((f"echo {domain} > domain.txt", None))
    tasks.append((f"subfinder -d {domain} -silent", "subfinder.txt"))
    tasks.append((f"assetfinder --subs-only {domain}", "assetfinder.txt"))
    tasks.append(("cat subfinder.txt assetfinder.txt | sort -u", "uniq_subs.txt"))

    # httpx
    tasks.append(("cat uniq_subs.txt | httpx -silent -status-code -title -tech-detect -ip -location", "httpx-toolkit.txt"))

    # waybackurls
    tasks.append(("cat domain.txt | waybackurls", "waybackurls.txt"))

    # grep example (assuming waybackurls.txt exists)
    tasks.append(("grep -Eo 'https?://[^ ]+?[a-zA-Z0-9\\-_.]+([^& ]+)' waybackurls.txt | grep -v '&'", None))

    # gobuster
    wordlist_path = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
    if os.path.exists(wordlist_path):
        tasks.append((f"gobuster dir -u https://{domain} -w {wordlist_path}", None))
    else:
        print(f"[!] Wordlist not found at: {wordlist_path} - skipping gobuster")

    # dirsearch
    tasks.append((f"dirsearch -u https://{domain}", None))

    # paramspider
    tasks.append((f"paramspider -d {domain} -s", "paramspider.txt"))
    tasks.append((f"paramspider -d {domain} -p 'PLACEHOLDER_PAYLOAD'", None))

    # gau
    gau_bin = shutil.which("gau") or os.path.expanduser("~/go/bin/gau")
    if os.path.isfile(gau_bin):
        tasks.append((f"{gau_bin} {domain}", None))
    else:
        print(f"[!] gau not found at expected path: {gau_bin}")

    return tasks

# ================================
#     Run Recon in Threads
# ================================
def run_recon_parallel(domain):
    tasks = build_recon_tasks(domain)
    max_workers = min(len(tasks), 10)

    print(f"[+] Starting recon with {max_workers} threads ...")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_command, cmd, out) for cmd, out in tasks]
            concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        print("[!] KeyboardInterrupt received. Cancelling tasks...")
    print("[+] Recon completed.")

# ================================
#     Main Execution
# ================================
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <target-domain>")
        sys.exit(1)

    target = sys.argv[1]
    install_missing_tools()
    run_recon_parallel(target)
