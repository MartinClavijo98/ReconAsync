
# ReconAsync - Advanced Asynchronous Reconnaissance Tool

**ReconAsync** is a powerful, cross-platform reconnaissance automation script that leverages Python's `asyncio` and `aiohttp` for high-concurrency HTTP scanning, combined with industry-standard external tools to perform comprehensive security reconnaissance.


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

