import asyncio
import os
import shutil
import platform

TOOLS = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "paramspider": "pip3 install paramspider",
    "gobuster": "go install github.com/OJ/gobuster/v3@latest",
    "dirsearch": "git clone https://github.com/maurosoria/dirsearch.git ~/tools/dirsearch && ln -s ~/tools/dirsearch/dirsearch.py /usr/local/bin/dirsearch"
}

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def is_linux():
    return platform.system().lower() == "linux"

def tool_exists(name):
    return shutil.which(name) is not None

async def install_tool(name, cmd):
    if not tool_exists(name):
        print(f"[!] Installing {name} ...")
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            executable="/bin/bash"
        )
        await proc.communicate()

async def run_command(cmd, output_file=None):
    try:
        print(f"[+] Running: {cmd}")
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await process.communicate()

        if output_file:
            async with aiofiles.open(f"{OUTPUT_DIR}/{output_file}", "wb") as f:
                await f.write(stdout)
    except Exception as e:
        print(f"[!] Error: {e}")

async def recon(domain):
    await asyncio.gather(
        run_command(f"subfinder -d {domain} -silent", "subfinder.txt"),
        run_command(f"assetfinder {domain}", "assetfinder.txt"),
        run_command(f"echo {domain} | waybackurls", "waybackurls.txt"),
        run_command(f"gau {domain}", "gau.txt"),
        run_command(f"paramspider -d {domain} -s", "paramspider.txt"),
        run_command(f"paramspider -d {domain} -p '--><h1>40sp31</h1>'", "paramspider_payload.txt"),
        run_command(f"gobuster dir -u https://{domain} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -q", "gobuster.txt"),
        run_command(f"dirsearch -u https://{domain} -e * -o {OUTPUT_DIR}/dirsearch.txt")
    )

    # Merge subdomains and run httpx
    await run_command("cat output/subfinder.txt output/assetfinder.txt | sort -u > output/uniq_subs.txt")
    await run_command("cat output/uniq_subs.txt | httpx -silent -sc -title -ip -location -tech-detect", "httpx.txt")

async def check_and_install():
    tasks = [install_tool(name, cmd) for name, cmd in TOOLS.items()]
    await asyncio.gather(*tasks)

async def main():
    import sys
    if not is_linux():
        print("[-] This script only works on Linux.")
        return

    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <domain>")
        return

    domain = sys.argv[1]

    await check_and_install()
    await recon(domain)
    print(f"\n[+] Recon finished. Results are in the '{OUTPUT_DIR}' directory.")

if __name__ == "__main__":
    import aiofiles
    asyncio.run(main())
