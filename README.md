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

*Automate your reconnaissance workflow with 35+ comprehensive testing modules*

</div>

## Features

ReconX is a comprehensive reconnaissance and vulnerability assessment toolkit designed for bug bounty hunters, penetration testers, and security researchers. It automates the entire security testing workflow with 35+ advanced testing modules.

### Core Reconnaissance Modules

- **Subdomain Enumeration**: Subfinder, Amass, Assetfinder with intelligent combining
- **Port Scanning**: Nmap comprehensive scans, Masscan high-speed discovery
- **Web Screenshots**: EyeWitness, Aquatone for visual reconnaissance  
- **Directory Bruteforcing**: FFUF, Gobuster with smart wordlist selection
- **JavaScript Analysis**: LinkFinder endpoint discovery, GF pattern matching
- **Parameter Discovery**: Arjun HTTP parameter mining, ParamSpider automated discovery

### Advanced Vulnerability Testing

#### Web Application Security
- **XSS Testing**: Dalfox advanced XSS scanner, XSStrike comprehensive suite
- **SQL Injection**: SQLMap automated testing with custom payloads
- **LFI/RFI Testing**: LFISuite, Fimap with intelligent payload selection
- **SSRF/RCE Testing**: Gopherus payload generation, Interactsh OOB testing
- **Open Redirect Testing**: Oralyzer with custom payload lists

#### Advanced Attack Vectors
- **CSRF Testing**: Token analysis and bypass detection
- **JWT Token Testing**: Algorithm confusion and weak key detection  
- **XXE Testing**: XML External Entity with multiple payload types
- **SSTI Testing**: Server-Side Template Injection across multiple engines
- **NoSQL Injection**: MongoDB, CouchDB injection testing
- **Deserialization Testing**: Java, Python, PHP, .NET payload testing

#### Modern Web Security
- **CORS Misconfiguration**: Origin bypass and credential exposure testing
- **WebSocket Testing**: Security analysis of WebSocket implementations
- **File Upload Vulnerabilities**: Extension bypass and execution testing
- **Authentication Bypass**: SQL injection, NoSQL injection, default credentials

#### Business Logic & Advanced Testing
- **Business Logic Testing**: Price manipulation, workflow bypassing
- **Race Condition Testing**: Concurrent request analysis
- **Subdomain Takeover**: Automated detection with multiple service checks
- **Cloud Storage Enumeration**: AWS S3, Google Cloud, Azure Blob testing

### Security Assessment Features

- **SSL/TLS Analysis**: SSLyze, testssl.sh comprehensive certificate analysis
- **Security Headers**: Nikto, HTTPx security header validation
- **WAF Detection**: wafw00f fingerprinting with bypass techniques  
- **CMS Enumeration**: CMSeeK, WhatWeb, custom fingerprinting for 15+ CMS platforms
- **Information Disclosure**: Git-dumper, sensitive file discovery
- **API Reconnaissance**: Kiterunner, GAU, Waybackurls endpoint discovery
- **OSINT & GitHub Dorking**: Automated sensitive information discovery
- **Nuclei Integration**: Template-based vulnerability scanning

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

When running in interactive mode, you'll see a comprehensive menu with 35 testing modules:

```
1.  Subdomain Enumeration          19. JWT Token Testing
2.  Port Scanning                  20. Subdomain Takeover  
3.  Screenshots                    21. GitHub Dorking
4.  Directory Bruteforce           22. SSL/TLS Analysis
5.  JavaScript Analysis            23. CORS Misconfiguration
6.  Parameter Discovery            24. XXE Testing
7.  XSS Testing                    25. SSTI Testing
8.  SQL Injection Testing          26. NoSQL Injection
9.  SSRF/RCE Testing              27. File Upload Vulnerabilities
10. LFI/RFI Testing               28. Authentication Bypass
11. Open Redirect Testing          29. Cloud Storage Enumeration
12. Security Headers Check         30. WebSocket Testing
13. API Reconnaissance            31. Deserialization Testing
14. S3 Bucket Enumeration         32. Race Condition Testing
15. CMS Enumeration               33. Business Logic Testing
16. WAF Detection                 34. Nuclei Template Execution
17. Information Disclosure        35. Full Scan (All tests)
18. CSRF Testing                  0.  Exit
```

You can select multiple options by entering comma-separated numbers (e.g., `1,2,3,7,15,35`).

## Output Structure

ReconX organizes all scan results in a comprehensive, structured directory format:

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
    │   │   ├── dalfox_target.txt
    │   │   └── xsstrike_target.txt
    │   ├── sql/
    │   │   └── sqlmap_target.txt
    │   ├── lfi/
    │   │   ├── lfisuite_target.txt
    │   │   └── fimap_target.txt
    │   ├── ssrf/
    │   ├── redirect/
    │   │   └── oralyzer_target.txt
    │   ├── csrf_target.txt
    │   ├── jwt_target.txt
    │   ├── xxe_target.txt
    │   ├── ssti_target.txt
    │   ├── nosql_target.txt
    │   ├── file_upload_target.txt
    │   ├── auth_bypass_target.txt
    │   ├── cors_target.txt
    │   ├── websocket_target.txt
    │   ├── deserialization_target.txt
    │   ├── race_condition_target.txt
    │   ├── business_logic_target.txt
    │   ├── subdomain_takeover_target.txt
    │   └── nuclei_target.txt
    ├── headers/
    │   ├── nikto_target.txt
    │   └── httpx_target.txt
    ├── ssl/
    │   ├── ssl_analysis_target.txt
    │   ├── testssl_target.txt
    │   └── manual_ssl_target.txt
    ├── api/
    │   ├── kiterunner_target.txt
    │   └── ffuf_api_target.txt
    ├── urls/
    │   ├── gau_target.txt
    │   └── wayback_target.txt
    ├── s3buckets/
    │   └── s3_target/
    ├── cms/
    │   ├── cmseek_target.txt
    │   ├── cmseek_target.json
    │   ├── whatweb_target.txt
    │   ├── whatweb_target.json
    │   ├── technology_detection.json
    │   ├── custom_fingerprinting.json
    │   ├── cms_consolidated_report.html
    │   ├── wordpress/
    │   │   ├── wpscan_target.txt
    │   │   ├── wpscan_vulns_target.txt
    │   │   └── manual_detection.txt
    │   ├── joomla/
    │   │   ├── joomscan_target.txt
    │   │   └── manual_detection.txt
    │   └── drupal/
    │       ├── manual_detection.txt
    │       ├── version_detection.txt
    │       └── vulnerability_check.txt
    ├── waf/
    │   └── wafw00f_target.txt
    ├── git/
    │   └── git-dump_target/
    ├── osint/
    │   └── github_target.txt
    └── cloud/
        └── storage_target.txt
```

## Tools Included

### Subdomain Enumeration
- **Subfinder**: Fast passive subdomain enumeration tool
- **Amass**: Advanced attack surface mapping and asset discovery
- **Assetfinder**: Find domains and subdomains potentially related to a given domain

### Port Scanning & Service Discovery
- **Nmap**: Network discovery and security auditing with comprehensive scripting
- **Masscan**: Fast port scanner for large-scale network reconnaissance

### Web Application Testing
- **FFUF**: Fast web fuzzer for directory/file/parameter discovery
- **Gobuster**: Directory/file/DNS busting tool in Go
- **Dalfox**: Advanced XSS scanner and parameter analysis tool
- **SQLMap**: Automatic SQL injection and database takeover tool
- **XSStrike**: Advanced XSS detection suite with WAF bypass capabilities

### Reconnaissance & OSINT Tools
- **LinkFinder**: Discover endpoints and parameters in JavaScript files
- **Arjun**: HTTP parameter discovery suite with smart detection
- **ParamSpider**: Mining parameters from dark corners of web archives
- **GAU (GetAllUrls)**: Fetch known URLs from multiple sources
- **Waybackurls**: Fetch all the URLs that Wayback Machine has for a domain

### Security Testing & Analysis
- **Nikto**: Web server scanner for vulnerabilities and misconfigurations
- **wafw00f**: Web Application Firewall fingerprinting tool
- **CMSeeK**: CMS detection and exploitation suite for 180+ CMS
- **SSLyze**: Fast and powerful SSL/TLS scanning tool
- **testssl.sh**: Testing TLS/SSL encryption with comprehensive checks

### Advanced Vulnerability Testing
- **LFISuite**: Totally Automatic LFI Exploiter and scanner
- **Fimap**: Little tool for local and remote file inclusion auditing
- **Gopherus**: Tool to generate gopher link for exploiting SSRF
- **Interactsh**: OOB interaction gathering server and client library
- **Oralyzer**: Simple Python script to check for Open Redirect vulnerabilities

### Cloud & Modern Infrastructure
- **S3Scanner**: Scan for open S3 buckets and dump contents
- **AWSBucketDump**: Enumerate AWS S3 buckets to find interesting files
- **Subjack**: Subdomain takeover tool with multiple service checks
- **CORScanner**: CORS misconfiguration scanner

### CMS-Specific Tools
- **WPScan**: WordPress vulnerability scanner with database integration
- **JoomScan**: OWASP Joomla vulnerability scanner
- **WhatWeb**: Web technology identifier with 1800+ plugins

### Specialized Security Tools
- **Nuclei**: Template-based vulnerability scanner
- **Git-dumper**: Tool to dump a git repository from a website
- **Arjun**: Advanced HTTP parameter discovery
- **Kiterunner**: Contextual content discovery tool

## Configuration

### Custom Wordlists

ReconX creates intelligent wordlists automatically, but you can customize them:

- **API Endpoints**: `wordlists/apis.txt` - Common API paths and endpoints
- **Redirect Payloads**: `wordlists/redirect_payloads.txt` - Open redirect test payloads
- **CSRF Tokens**: `wordlists/csrf_tokens.txt` - Common CSRF token names
- **XXE Payloads**: `wordlists/xxe_payloads.txt` - XML External Entity payloads
- **SSTI Payloads**: `wordlists/ssti_payloads.txt` - Server-Side Template Injection payloads
- **S3 Buckets**: `wordlists/target-buckets.txt` - Auto-generated per target
- **SecLists Integration**: Optional download of comprehensive wordlist collection

### Environment Variables

Make sure Go bin is in your PATH for Go-based tools:
```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Advanced Configuration Options

#### CMS Detection
- Supports 15+ CMS platforms including WordPress, Joomla, Drupal, Magento
- Custom fingerprinting with confidence scoring
- Technology stack detection (React, Angular, Vue.js, etc.)
- Consolidated HTML reporting for CMS enumeration

#### Automated vs Interactive Modes
- **Automated Mode**: Pre-configured payloads and parameters for hands-off testing
- **Interactive Mode**: Custom URL input for targeted vulnerability testing
- **Full Scan Mode**: Comprehensive testing across all 35 modules

## 🎯 Testing Guides

### Automated Vulnerability Testing
ReconX provides both automated and interactive testing modes for comprehensive coverage:

#### XSS Testing
1. **Automated Mode**: Tests common XSS injection points automatically
2. **Interactive Mode**: Provide specific URLs with parameters for targeted testing
3. **Tools Used**: Dalfox for advanced parameter analysis, XSStrike for comprehensive detection
4. **Payload Types**: DOM-based, Reflected, Stored XSS with WAF bypass techniques

#### SQL Injection Testing
1. **Parameter Discovery**: Automatically identifies potential injection points
2. **Multi-Database Support**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
3. **Advanced Techniques**: Boolean-based blind, time-based blind, error-based, union-based
4. **Interactive Testing**: Provide URLs with suspected parameters (e.g., `https://target.com/page?id=1`)

#### Advanced Web Application Attacks

##### Business Logic Testing
- **Price Manipulation**: Negative prices, integer overflow testing
- **Workflow Bypassing**: Multi-step process circumvention
- **Authentication Logic**: Privilege escalation through parameter manipulation
- **Rate Limiting**: Bypass detection for various endpoints

##### Modern Attack Vectors
- **JWT Security**: Algorithm confusion attacks, weak signing key detection
- **CORS Misconfiguration**: Origin bypass testing with multiple payload types  
- **XXE (XML External Entity)**: File disclosure and SSRF via XML parsing
- **SSTI (Server-Side Template Injection)**: Multi-engine support (Jinja2, Twig, Smarty, etc.)
- **NoSQL Injection**: MongoDB and CouchDB injection testing
- **Deserialization**: Java, Python, PHP, .NET payload testing

##### Cloud & Infrastructure Testing
- **S3 Bucket Enumeration**: AWS, Google Cloud, Azure storage discovery
- **Subdomain Takeover**: 15+ service provider checks (GitHub Pages, Heroku, etc.)
- **SSL/TLS Analysis**: Certificate validation, cipher analysis, vulnerability detection
- **WebSocket Security**: Authentication bypass, message injection testing

### CMS-Specific Testing

#### WordPress Testing
1. **Automated Enumeration**: Plugins, themes, users, vulnerabilities
2. **Version Detection**: Core WordPress version identification
3. **Security Analysis**: Configuration issues, exposed endpoints
4. **Tools**: WPScan with vulnerability database integration

#### Multi-CMS Support
- **Joomla**: JoomScan + manual detection methods
- **Drupal**: Enhanced detection with version-specific vulnerability checks
- **Magento, PrestaShop, OpenCart**: Custom fingerprinting techniques
- **Generic CMS**: Technology stack analysis for unknown systems

### OSINT & Information Gathering

#### GitHub Dorking
- **Automated Queries**: Credential discovery, configuration exposure
- **Search Patterns**: API keys, passwords, database credentials
- **Manual Review**: Guided approach for sensitive information discovery

#### Advanced Reconnaissance
- **Parameter Mining**: Historical parameter discovery from web archives
- **JavaScript Analysis**: Endpoint discovery from client-side code
- **API Discovery**: REST/GraphQL endpoint identification
- **Technology Profiling**: Framework and library identification

## Legal Disclaimer

**IMPORTANT**: This tool is for educational and authorized testing purposes only.

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for complying with applicable laws
- The author is not responsible for any misuse or damage

## Contributing

Contributions are welcome! ReconX is designed to be extensible and community-driven.

### How to Contribute

1. **Fork the repository**
2. **Create your feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
4. **Push to the branch** (`git push origin feature/AmazingFeature`)  
5. **Open a Pull Request**

### Contribution Areas

- **New Testing Modules**: Add support for additional vulnerability types
- **Tool Integration**: Integrate new security testing tools
- **CMS Support**: Add detection for additional CMS platforms
- **Payload Enhancement**: Improve existing payload collections
- **Documentation**: Improve setup guides and testing methodologies
- **Performance**: Optimize scanning speed and accuracy

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Thanks to all the amazing tool developers and security researchers whose work is integrated into ReconX:

**Core Tools:**
- ProjectDiscovery Team (Subfinder, HTTPx, Interactsh, Nuclei)
- OWASP Project (Amass, JoomScan)
- Tom Hudson (Waybackurls, GF, Assetfinder)
- S0md3v (XSStrike, Photon)
- Devansh Batham (ParamSpider)

**Specialized Tools:**
- CMSeeK Team (Tuhinshubhra)
- SQLMap Development Team
- Dalfox (Hahwul)
- SSLyze (Alban Diquet)
- testssl.sh (Dirk Wetter)

**Security Research Community:**
- Bug bounty hunters who provided testing methodologies
- Penetration testers who contributed vulnerability detection techniques
- Open source security tool developers

## Support & Community

### Getting Help

1. **Documentation**: Check the comprehensive guides above
2. **Issues**: [Report bugs or request features](https://github.com/0nsec/ReconX/issues)
3. **Discussions**: Join community discussions for tips and techniques
4. **Wiki**: Detailed documentation and advanced usage guides

### Staying Updated

- **Star** the repository to stay informed about updates
- **Watch** for new releases and security improvements
- **Follow** [@0nsec](https://github.com/0nsec) for security research updates

### Performance Tips

- **Parallel Execution**: Use automated mode for faster scanning
- **Targeted Testing**: Use interactive mode for specific vulnerability types
- **Resource Management**: Monitor system resources during full scans
- **Result Analysis**: Use provided HTML reports for comprehensive analysis

---

<div align="center">

**Made with ❤️ for the Bug Hunting Community**

[Report Bug](https://github.com/0nsec/ReconX/issues) · [Request Feature](https://github.com/0nsec/ReconX/issues) · [Documentation](https://github.com/0nsec/ReconX/wiki) · [Security Research](https://twitter.com/0nsec)

**⭐ If ReconX helped you find vulnerabilities, please star the repository! ⭐**

</div>