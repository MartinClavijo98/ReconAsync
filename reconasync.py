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
TOOL_INSTALL_CMDS = {
    "subfinder":  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    "httpx-toolkit": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "gau":         "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "paramspider": "pip3 install paramspider",
    "gobuster":    "go install -v github.com/OJ/gobuster/v3@latest",
    "dirsearch": (
        "if [ ! -d \"$HOME/tools/dirsearch\" ]; then "
        "git clone https://github.com/maurosoria/dirsearch.git \"$HOME/tools/dirsearch\" "
        "&& ln -sf \"$HOME/tools/dirsearch/dirsearch.py\" /usr/local/bin/dirsearch; "
        "fi"
    )
}

def tool_exists(cmd_name):
    return shutil.which(cmd_name) is not None

def install_missing_tools():
    for tool_cmd, install_cmd in TOOL_INSTALL_CMDS.items():
        check_name = "httpx" if tool_cmd == "httpx-toolkit" else tool_cmd
        if not tool_exists(check_name):
            print(f"[!] {check_name} not found. Installing via: {install_cmd}")
            subprocess.run(install_cmd, shell=True, executable="/bin/bash")
        else:
            print(f"[+] {check_name} is already installed.")

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

def build_recon_tasks(domain):
    tasks = []

    tasks.append((f"echo {domain} > domain.txt", None))
    tasks.append((f"subfinder -d {domain}", "subfinder.txt"))
    tasks.append((f"assetfinder {domain}", "assetfinder.txt"))
    tasks.append(("if [ -f subfinder.txt ] && [ -f assetfinder.txt ]; then cat subfinder.txt assetfinder.txt | sort -u > uniq_subs.txt; fi", None))
    tasks.append(("cat uniq_subs.txt | httpx -title -tech-detect -status-code -location -ip -no-color", "httpx-toolkit.txt"))
    tasks.append(("cat domain.txt | waybackurls", "waybackurls.txt"))
    tasks.append(("grep -Eo 'https?://[^ ]+?[a-zA-Z0-9\\-_.]+([^& ]+)' filename.txt | grep -v '&'", None))
    tasks.append((f"gobuster dir -u https://{domain} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", None))
    tasks.append(("cat domain.txt | assetfinder --subs-only", None))
    tasks.append((f"dirsearch -u https://{domain}", None))
    tasks.append((f"paramspider -d {domain} -s > paramspider.txt", None))
    tasks.append((f"paramspider -d {domain} --placeholder '--><h1>40sp31</h1>'", None))
    tasks.append((f"gau {domain} 2>/dev/null", None))

    return tasks

def run_recon_parallel(domain):
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
            print("[!] KeyboardInterrupt received. Cancelling tasks...")
            executor.shutdown(wait=False, cancel_futures=True)
            print("[+] Graceful shutdown.")

    print("[+] All recon tasks completed.")

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
