**Advanced Cross-Platform Reconnaissance Tool**

ReconAsync is an asynchronous, cross-platform reconnaissance automation script. It utilizes Python’s `asyncio` and `aiohttp` for high-concurrency HTTP scanning, along with various powerful external tools (Go-based and Python-based) to perform comprehensive reconnaissance.

---

## Table of Contents

1. [Introduction](#introduction)  
2. [Features](#features)  
3. [Requirements](#requirements)  
4. [Installation](#installation)  
5. [Usage](#usage)  
6. [Configuration](#configuration)  
7. [Project Structure](#project-structure)  
8. [Examples](#examples)  
9. [Contributing](#contributing)  
10. [License](#license)  
11. [Acknowledgments](#acknowledgments)  

---

## Introduction

ReconAsync is designed to automate subdomain enumeration, URL collection, parameter spidering, directory brute-forcing, and HTTP fingerprinting in a highly concurrent manner. By leveraging both **Go-based tools** (e.g., `subfinder`, `assetfinder`, `gobuster`, `paramspider`, `gau`, `waybackurls`, `httpx`) and **Python-based tools** (e.g., `dirsearch`), ReconAsync streamlines the standard recon workflow into a single, easy-to-use script.

Key objectives:

- **Cross-Platform Compatibility**: Works on both Linux and Windows.  
- **Tool Auto-Installation**: Automatically checks for required binaries and installs missing tools.  
- **Asynchronous Execution**: Runs external commands as asynchronous subprocesses and uses `aiohttp` for concurrent HTTP scanning.  
- **Minimal Dependencies**: Avoids reliance on shell utilities like `cat` or `grep`, using Python-native file handling and regex instead.  

---

## Features

- ✅ **Subdomain Enumeration** via `subfinder` and `assetfinder`.  
- ✅ **URL Gathering** using `gau` (GetAllURLs) and `waybackurls`.  
- ✅ **Parameter Spidering** with default scan and custom payload via `paramspider`.  
- ✅ **HTTP Fingerprinting** (status code, title, server header, IP resolution) using `aiohttp` and Python’s `socket`.  
- ✅ **Directory Brute-Forcing** through `gobuster` and `dirsearch`.  
- ✅ **Cross-Platform Auto-Installation** of Go-based tools (via `go install`) and Python-based tools (via `pip install`).  
- ✅ **Asynchronous Workflow**: All reconnaissance tasks are run concurrently to maximize speed.  
- ✅ **Configurable Concurrency**: Limit the number of simultaneous HTTP requests via `MAX_HTTP_CONCURRENCY`.  
- ✅ **Output Management**: Each tool’s output is saved to its own file (e.g., `subfinder.txt`, `assetfinder.txt`, `uniq_subs.txt`, etc.).  

---

## Requirements

- **Python 3.6+** installed and available in `PATH`.  
- **Go (golang)** installed (if not, the script will attempt to install it).  
- **pip** (or `pip3`) available for Python package installations.  
- **On Linux**: `sudo` privileges for installing system packages (e.g., `golang-go`).  
- **On Windows**: `choco` or `winget` for automatic Go installation; otherwise, manual Go installation is required.  
- **Network Connectivity** to download Go modules and PIP packages.

---

## Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/<your-username>/ReconAsync.git
   cd ReconAsync

	2.	(Optional) Create a virtual environment

python3 -m venv venv
source venv/bin/activate       # On Linux/macOS
venv\Scripts\activate          # On Windows


	3.	Ensure Python dependencies
The script uses only aiohttp (for HTTP scanning). Install via:

pip install aiohttp


	4.	Make the script executable (Linux/macOS)

chmod +x recon_async.py

Note: On Windows, simply ensure .py files are associated with Python, or run with python recon_async.py ....

	5.	Run the script

python recon_async.py example.com --url https://sub.example.com

This command will:
	•	Check and install required Go-based tools (subfinder, assetfinder, httpx, gobuster, paramspider, gau, waybackurls).
	•	Check and install Python-based tool dirsearch.
	•	Execute asynchronous reconnaissance tasks.
	•	Save outputs in individual files in the current directory.

⸻

Usage

python recon_async.py <target-domain> [--url <example-url>]

	•	<target-domain>: The main domain for reconnaissance (e.g., example.com).
	•	--url <example-url> (optional): A full URL (e.g., https://sub.example.com) for directory brute-forcing with gobuster and dirsearch.

Example
	•	Basic usage (only subdomain enumeration, URL gathering, params, HTTP scan)

python recon_async.py example.com

This will:
	1.	Enumiate subdomains (subfinder.txt, assetfinder.txt).
	2.	Merge unique subdomains (uniq_subs.txt).
	3.	Run httpx_async (HTTP scanning) → httpx_toolkit_async.txt.
	4.	Gather Wayback URLs (waybackurls.txt) and gau URLs (gau.txt).
	5.	Run paramspider → paramspider.txt.
	6.	Skip gobuster & dirsearch (no --url provided).

	•	Advanced usage (including directory brute-forcing)

python recon_async.py example.com --url https://sub.example.com

This will additionally run:
	•	gobuster dir -u https://sub.example.com -w <wordlist> → gobuster.txt.
	•	dirsearch -u https://sub.example.com → dirsearch.txt.

⸻

Configuration
	1.	MAX_HTTP_CONCURRENCY
Adjust the maximum number of simultaneous HTTP requests. Default is 50. If you have limited bandwidth or face rate-limiting, lower this value near the top of recon_async.py:

MAX_HTTP_CONCURRENCY = 50


	2.	Wordlist Path for Gobuster
	•	Linux (default):

DEFAULT_WORDLIST_LINUX = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"


	•	Windows (example):

DEFAULT_WORDLIST_WINDOWS = r"C:\wordlists\directory-list-lowercase-2.3-medium.txt"


Modify these variables if your wordlist is stored elsewhere.

	3.	Custom Payload for ParamSpider
The default code uses:

payload = "--><h1>40sp31</h1>"

You can change this payload inside async def recon_paramspider(...) if desired.

	4.	Timeouts and Headers for HTTP Scanning
In recon_httpx_async(), the timeout is set to 10 seconds:

async with session.get(url, timeout=10) as resp:
    ...

For custom headers or TLS options, modify the session.get(...) call accordingly.

⸻

Project Structure

ReconAsync/
├── recon_async.py
├── README.md
├── requirements.txt       # (optional) to pin aiohttp version, e.g., "aiohttp>=3.8"
├── docs/                  # (optional) additional documentation, diagrams, examples
└── wordlists/             # (optional) store custom wordlists for gobuster

	•	recon_async.py: Main Python script implementing the asynchronous recon workflow.
	•	README.md: This file, describing project features, usage, and examples.
	•	requirements.txt: (Optional) If you want to pin specific versions:

aiohttp>=3.8


	•	docs/: (Optional) Directory for additional guides, diagrams, or sample outputs.
	•	wordlists/: (Optional) A folder to place local wordlists for Gobuster or Dirsearch.

⸻

Examples

Below are some example command lines and expected outputs:
	1.	Run full recon with directory brute-forcing

python recon_async.py example.com --url https://api.example.com

	•	Creates:
	•	subfinder.txt
	•	assetfinder.txt
	•	uniq_subs.txt
	•	httpx_toolkit_async.txt (CSV with columns: host,status,ip,server,title)
	•	waybackurls.txt
	•	gau.txt
	•	paramspider.txt
	•	gobuster.txt
	•	dirsearch.txt
	•	Sample snippet of httpx_toolkit_async.txt:

host,status,ip,server,title
api.example.com,200,93.184.216.34,nginx,"Example API"
dev.example.com,ERR,N/A,N/A,N/A
...


	2.	Only run basic recon (no directory scanning)

python recon_async.py example.org

	•	Skips gobuster and dirsearch steps.
	•	Outputs relevant .txt files except gobuster.txt and dirsearch.txt.

	3.	Extract URLs from a local file
If you have a file filename.txt containing HTML/content:

cat some_archive.html > filename.txt
python recon_async.py example.com

This will automatically detect filename.txt and print all extracted URLs that do not contain &.

	4.	Run assetfinder --subs-only on a domains list
If you have a file domains with one domain per line:

python recon_async.py example.com

The script will detect domains at runtime and print all subdomains found by assetfinder --subs-only, without saving to a file.

⸻

Contributing

Thank you for considering contributing! To contribute:
	1.	Fork the repository.
	2.	Create a new branch:

git checkout -b feature/your-feature-name


	3.	Make your changes and add appropriate tests or examples.
	4.	Commit your changes:

git commit -m "Add feature XYZ"


	5.	Push to your fork:

git push origin feature/your-feature-name


	6.	Open a Pull Request describing the changes in detail.

Please ensure your code adheres to PEP8 style guidelines. If you introduce new dependencies, update requirements.txt accordingly.

⸻

License

This project is licensed under the MIT License. See the LICENSE file for details.

MIT License

Copyright (c) 2025 <Your Name>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
...


⸻

Acknowledgments
	•	ProjectDiscovery for tools like subfinder, httpx, etc.
	•	TomNomNom for tools like assetfinder, waybackurls, etc.
	•	Devansh Batham for ParamSpider.
	•	LC for gau.
	•	Dirsearch maintainers.
	•	Python community and aiohttp authors for providing a robust asynchronous HTTP client.

