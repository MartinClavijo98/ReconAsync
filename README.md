
# ReconAsync - Advanced Asynchronous Reconnaissance Tool

**ReconAsync** is a powerful, cross-platform reconnaissance automation script that leverages Python's `asyncio` and `aiohttp` for high-concurrency HTTP scanning, combined with industry-standard external tools to perform comprehensive security reconnaissance.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Examples](#examples)
- [Output Files](#output-files)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Introduction

ReconAsync automates the reconnaissance process by combining multiple security tools into a single, efficient workflow. It performs subdomain enumeration, URL collection, parameter discovery, directory brute-forcing, and HTTP fingerprinting concurrently to maximize efficiency.

## Features

✅ **Subdomain Enumeration** - Using `subfinder` and `assetfinder`
✅ **URL Discovery** - With `gau` and `waybackurls`
✅ **Parameter Spidering** - Using `paramspider`
✅ **HTTP Fingerprinting** - Status codes, headers, and server information
✅ **Directory Brute-Forcing** - Through `dirsearch`
✅ **Automatic Tool Installation** - Checks for and installs missing dependencies
✅ **Asynchronous Execution** - All tasks run concurrently for maximum speed
✅ **Cross-Platform Support** - Works on Linux and Windows
✅ **Configurable Concurrency** - Adjustable maximum HTTP requests
✅ **Comprehensive Output** - Results saved to multiple organized files

## Requirements

- Python 3.7+
- Go (for Go-based tools)
- Git
- Basic system utilities (wget, etc.)

### Linux Dependencies:
```bash
sudo apt-get update && sudo apt-get install -y git golang python3-venv python3-pip wget
```

### Windows Dependencies:
- Install [Chocolatey](https://chocolatey.org/install)
- Then run:
```powershell
choco install git golang python -y
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ReconAsync.git
cd ReconAsync
```

2. (Optional) Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install Python dependencies:
```bash
pip install aiohttp dirsearch
```

4. Make the script executable (Linux/macOS):
```bash
chmod +x ReconAsync.py
```

## Usage

Basic syntax:
```bash
python ReconAsync.py <target-domain> [--url <example-url>] [--install]
```

### Options:
- `<target-domain>`: Domain to perform reconnaissance on (e.g., `example.com`)
- `--url`: Specific URL for directory brute-forcing
- `--install`: Install required tools and exit

### Examples:

1. Basic reconnaissance:
```bash
python ReconAsync.py example.com
```

2. With URL for directory brute-forcing:
```bash
python ReconAsync.py example.com --url https://api.example.com
```

3. Install dependencies only:
```bash
python ReconAsync.py --install
```

## Configuration

### Key Configuration Options:

1. **Concurrency Limit** (in script):
```python
MAX_HTTP_CONCURRENCY = 50  # Adjust based on your system/network capabilities
```

2. **Wordlist Paths**:
```python
# Linux default
DEFAULT_WORDLIST_LINUX = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"

# Windows example
DEFAULT_WORDLIST_WINDOWS = r"C:\wordlists\directory-list-lowercase-2.3-medium.txt"
```

3. **Custom Payload** (for paramspider):
```python
payload = "--><h1>40sp31</h1>"  # Can be modified in the paramspider function
```

## Output Files

The script generates several output files:

| File | Description |
|------|-------------|
| `subfinder.txt` | Subdomains found by subfinder |
| `assetfinder.txt` | Subdomains found by assetfinder |
| `uniq_subs.txt` | Merged unique subdomains |
| `httpx_cli.txt` | Basic HTTP probe results |
| `httpx_async.csv` | Detailed HTTP scan results (CSV format) |
| `gau.txt` | URLs found by gau |
| `waybackurls.txt` | URLs from Wayback Machine |
| `paramspider.txt` | Parameters discovered |
| `dirsearch.txt` | Directory brute-forcing results |

## Troubleshooting

### Common Issues and Solutions:

1. **httpx command errors**:
   - Ensure you have the latest version of httpx installed
   - Run: `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`

2. **paramspider errors**:
   - Reinstall paramspider:
   ```bash
   git clone https://github.com/devanshbatham/ParamSpider.git
   cd ParamSpider
   pip install -r requirements.txt
   python setup.py install
   ```

3. **Wordlist issues**:
   - The script will automatically download a default wordlist
   - You can also manually place wordlists in the `wordlists/` directory

4. **Permission issues**:
   - On Linux, you might need to run with `sudo` for installation
   - Consider using a virtual environment to avoid permission problems

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your feature description"
   ```
4. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a Pull Request

Please ensure your code follows PEP8 style guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for subfinder and httpx
- [TomNomNom](https://github.com/tomnomnom) for assetfinder and waybackurls
- [Devansh Batham](https://github.com/devanshbatham) for ParamSpider
- [LC](https://github.com/lc) for gau
- The Python community for asyncio and aiohttp

---

**Note**: This tool is for legal security testing purposes only. Only use it against systems you have explicit permission to test.
