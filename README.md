# ReconX - Advanced Bug Hunting Reconnaissance Toolkit

<div align="center">

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**Advanced Bug Hunting Reconnaissance Toolkit**

*Automate your reconnaissance workflow with a comprehensive suite of tools*

</div>

##  Features

ReconX is a comprehensive reconnaissance toolkit designed for bug bounty hunters and penetration testers. It automates the entire reconnaissance workflow, from subdomain enumeration to vulnerability scanning.

### Reconnaissance Modules

- **Subdomain Enumeration**: Subfinder, Amass, Assetfinder
- **Port Scanning**: Nmap, Masscan
- **Web Screenshots**: EyeWitness, Aquatone
- **Directory Bruteforcing**: FFUF, Gobuster
- **JavaScript Analysis**: LinkFinder, GF patterns
- **Parameter Discovery**: Arjun, ParamSpider
- **Vulnerability Testing**:
  - XSS: Dalfox, XSStrike
  - SQL Injection: SQLMap
  - LFI/RFI: LFISuite, Fimap
  - SSRF/RCE: Gopherus, Interactsh
  - Open Redirect: Oralyzer
- **Security Headers**: Nikto, HTTPx
- **API Reconnaissance**: Kiterunner, GAU, Waybackurls
- **Cloud Storage**: S3 Bucket enumeration
- **CMS Detection**: CMSeeK
- **WAF Detection**: wafw00f
- **Information Disclosure**: Git-dumper

##  Installation

### 1. Clone the Repository
```bash
git clone https://github.com/0nsec/ReconX.git
cd ReconX
```

### 2. Run Setup Script
```bash
sudo python3 setup.py
```

The setup script will automatically:
- Install all required tools and dependencies
- Set up Go environment if needed
- Create necessary directories and wordlists
- Install Python packages from requirements.txt

### 3. Make Script Executable
```bash
chmod +x reconx.py
```

##  Usage

### Basic Usage
```bash
# Interactive mode with menu selection
python3 reconx.py -t target.com

# Full automatic scan
python3 reconx.py -t target.com --auto
```

### Command Line Options
```bash
python3 reconx.py -h
usage: reconx.py [-h] -t TARGET [-a]

ReconX - Advanced Bug Hunting Reconnaissance Toolkit

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target domain (e.g., example.com)
  -a, --auto            Run full automatic scan
```

### Interactive Menu

When running in interactive mode, you'll see a menu with the following options:

```
1.  Subdomain Enumeration
2.  Port Scanning
3.  Screenshots
4.  Directory Bruteforce
5.  JavaScript Analysis
6.  Parameter Discovery
7.  XSS Testing
8.  SQL Injection Testing
9.  SSRF/RCE Testing
10. LFI/RFI Testing
11. Open Redirect Testing
12. Security Headers Check
13. API Reconnaissance
14. S3 Bucket Enumeration
15. CMS Enumeration
16. WAF Detection
17. Information Disclosure
18. Full Scan (All tests)
0.  Exit
```

You can select multiple options by entering comma-separated numbers (e.g., `1,2,3,7`).

## Output Structure

ReconX organizes all scan results in a structured directory format:

```
scanning/
└── target.com_20240818_143022/
    ├── subdomains/
    │   ├── subfinder.txt
    │   ├── amass.txt
    │   ├── assetfinder.txt
    │   └── subdomains.txt (combined)
    ├── ports/
    │   ├── nmap_target.txt
    │   └── masscan_target.txt
    ├── screenshots/
    │   ├── eyewitness/
    │   └── aquatone/
    ├── directories/
    │   ├── ffuf_target.txt
    │   └── gobuster_target.txt
    ├── javascript/
    │   └── linkfinder/
    ├── parameters/
    │   ├── arjun_target.json
    │   └── paramspider.txt
    ├── vulnerabilities/
    │   ├── xss/
    │   ├── sql/
    │   ├── lfi/
    │   ├── ssrf/
    │   └── redirect/
    ├── headers/
    ├── api/
    ├── urls/
    ├── s3buckets/
    ├── cms/
    ├── waf/
    └── git/
```

## Tools Included

### Subdomain Enumeration
- **Subfinder**: Fast passive subdomain enumeration
- **Amass**: Advanced attack surface mapping
- **Assetfinder**: Find domains and subdomains

### Port Scanning
- **Nmap**: Network discovery and security auditing
- **Masscan**: Fast port scanner

### Web Application Testing
- **FFUF**: Fast web fuzzer
- **Gobuster**: Directory/file/DNS busting tool
- **Dalfox**: XSS scanner and parameter analysis
- **SQLMap**: Automatic SQL injection tool
- **XSStrike**: Advanced XSS detection suite

### Reconnaissance Tools
- **LinkFinder**: Discover endpoints in JavaScript files
- **Arjun**: HTTP parameter discovery suite
- **ParamSpider**: Parameter mining tool
- **GAU**: Get All URLs
- **Waybackurls**: Fetch all URLs from Wayback Machine

### Security Testing
- **Nikto**: Web server scanner
- **wafw00f**: WAF fingerprinting tool
- **CMSeeK**: CMS detection and exploitation suite

## Configuration

### Custom Wordlists

ReconX creates default wordlists, but you can customize them:

- **API Endpoints**: `wordlists/apis.txt`
- **Redirect Payloads**: `wordlists/redirect_payloads.txt`
- **S3 Buckets**: `wordlists/target-buckets.txt` (auto-generated per target)

### Environment Variables

Make sure Go bin is in your PATH:
```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## Attack Guides

### XSS Testing
1. Run parameter discovery first to find input points
2. Use the discovered parameters for targeted XSS testing
3. Provide specific URLs when prompted (e.g., `https://target.com/search?q=test`)

### SQL Injection Testing
1. Identify potential injection points through parameter discovery
2. Provide URLs with parameters (e.g., `https://target.com/page?id=1`)
3. Review SQLMap output for confirmed vulnerabilities

### LFI/RFI Testing
1. Look for file inclusion parameters (`file=`, `page=`, `include=`)
2. Provide the full URL with the suspected parameter
3. Review results for successful file inclusion

### S3 Bucket Enumeration
1. Tool automatically generates bucket wordlists based on target domain
2. Common patterns: `target`, `target-prod`, `target-dev`, `target-backup`
3. Customize `wordlists/target-buckets.txt` for better results

## Legal Disclaimer

**IMPORTANT**: This tool is for educational and authorized testing purposes only.

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for complying with applicable laws
- The author is not responsible for any misuse or damage

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Thanks to all the amazing tool developers whose work is integrated into ReconX:

- ProjectDiscovery Team (Subfinder, HTTPx, Interactsh)
- OWASP Team (Amass)
- Tom Hudson (Waybackurls, GF)
- And many more security researchers and developers

## Support

If you encounter any issues or have suggestions:

1. Check the [Issues](https://github.com/0nsec/ReconX/issues) page
2. Create a new issue with detailed information
3. Join our community discussions

---

<div align="center">

**Made with ❤️ for the Bug Hunting Community**

[Report Bug](https://github.com/0nsec/ReconX/issues) · [Request Feature](https://github.com/0nsec/ReconX/issues) · [Documentation](https://github.com/0nsec/ReconX/wiki)

</div>