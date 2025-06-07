# ReconAsync: Your Go-To Tool for Reconnaissance Automation 🚀

![ReconAsync](https://img.shields.io/badge/ReconAsync-Ready-brightgreen)

Welcome to the **ReconAsync** repository! This project is designed to automate various tasks in the reconnaissance phase of security assessments. With a focus on speed and efficiency, ReconAsync leverages multiple Go-based tools to help you gather information about your target quickly and effectively.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Tools Used](#tools-used)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Introduction

Reconnaissance is a crucial phase in the security assessment process. It involves gathering information about a target system to identify potential vulnerabilities. ReconAsync simplifies this process by automating tasks such as subdomain enumeration, URL collection, parameter spidering, directory brute-forcing, and HTTP fingerprinting. 

You can start using ReconAsync by downloading the latest release [here](https://github.com/MartinClavijo98/ReconAsync/releases). 

## Features

- **Subdomain Enumeration**: Quickly find subdomains using tools like subfinder and assetfinder.
- **URL Collection**: Gather URLs from various sources to broaden your attack surface.
- **Parameter Spidering**: Automatically discover parameters in web applications.
- **Directory Brute-Forcing**: Use gobuster for efficient directory enumeration.
- **HTTP Fingerprinting**: Identify web server software and versions with httpx.
- **Highly Concurrent**: Leverage Go's concurrency model for faster results.

## Tools Used

ReconAsync integrates several powerful tools to provide comprehensive reconnaissance capabilities:

- **Subfinder**: A subdomain discovery tool that finds valid subdomains for websites.
- **Assetfinder**: Quickly finds assets associated with a domain.
- **Gobuster**: A tool for directory brute-forcing and DNS subdomain enumeration.
- **Paramspider**: A tool for parameter discovery in web applications.
- **Gau**: Collects known URLs from various sources, enhancing your reconnaissance.
- **Waybackurls**: Fetches historical URLs from the Wayback Machine.
- **Httpx**: A fast and multi-purpose HTTP toolkit for probing URLs.

## Installation

To install ReconAsync, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/MartinClavijo98/ReconAsync.git
   cd ReconAsync
   ```

2. Download the latest release from the [Releases section](https://github.com/MartinClavijo98/ReconAsync/releases) and execute the binary.

3. Ensure you have Go installed on your machine. If not, download it from [the official Go website](https://golang.org/dl/).

4. Install the required Go tools by running:
   ```bash
   go get -u github.com/projectdiscovery/subfinder/v2/cmd/subfinder
   go get -u github.com/projectdiscovery/assetfinder
   go get -u github.com/OJ/gobuster/v3
   go get -u github.com/devansh123/paramspider
   go get -u github.com/brianwrf/gau
   go get -u github.com/tomnomnom/waybackurls
   go get -u github.com/projectdiscovery/httpx/cmd/httpx
   ```

## Usage

Using ReconAsync is straightforward. Here’s a simple example of how to run the tool:

1. Execute the following command:
   ```bash
   ./ReconAsync -d example.com
   ```

2. The tool will begin subdomain enumeration, URL collection, parameter spidering, directory brute-forcing, and HTTP fingerprinting.

3. Review the results in the console or save them to a file for further analysis.

### Command-Line Options

- `-d`: Specify the target domain.
- `-o`: Output file to save results.
- `--help`: Display help information.

## Contributing

We welcome contributions to ReconAsync! If you have ideas for new features or improvements, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch and create a pull request.

Please ensure your code follows the project's coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

For support, please check the [Issues section](https://github.com/MartinClavijo98/ReconAsync/issues) or contact the maintainers directly. 

You can also download the latest release from the [Releases section](https://github.com/MartinClavijo98/ReconAsync/releases) to get started.

## Topics

This repository covers a variety of topics related to reconnaissance and security:

- AI
- Hacktoberfest
- Hacking
- HTTPX
- Linux
- Python
- Recon
- Reconnaissance Framework
- Subfinder
- Windows

## Conclusion

ReconAsync is a powerful tool for automating reconnaissance tasks. By combining various Go-based tools, it allows security professionals to gather critical information quickly and efficiently. Whether you are a beginner or an experienced professional, ReconAsync can enhance your reconnaissance efforts.

Feel free to explore the repository, contribute, and help us improve this tool. Together, we can make security assessments more effective and efficient. 

For more details, please visit the [Releases section](https://github.com/MartinClavijo98/ReconAsync/releases) to download the latest version.