#!/usr/bin/env python3
"""
ReconX Setup Script
Installs all required tools and dependencies
"""

import os
import sys
import subprocess
import requests
from pathlib import Path

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

class ReconXSetup:
    def __init__(self):
        self.tools_dir = "tools"
        self.wordlists_dir = "wordlists"
        self.create_directories()
    
    def create_directories(self):
        """Create necessary directories"""
        dirs = [self.tools_dir, self.wordlists_dir, "scanning"]
        for directory in dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def print_info(self, message):
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    def print_success(self, message):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    def print_error(self, message):
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    def print_warning(self, message):
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    def run_command(self, command, check=True):
        """Run shell command"""
        try:
            self.print_info(f"Running: {command}")
            result = subprocess.run(command, shell=True, check=check, capture_output=True, text=True)
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            self.print_error(f"Command failed: {e}")
            return False
        except Exception as e:
            self.print_error(f"Error: {e}")
            return False
    
    def check_and_install_go(self):
        """Check and install Go if needed"""
        self.print_info("Checking Go installation...")
        if not self.run_command("which go", check=False):
            self.print_warning("Go not found. Installing Go...")
            self.run_command("sudo apt update")
            self.run_command("sudo apt install -y golang-go")
            
            # Set Go environment variables
            go_path = os.path.expanduser("~/go")
            with open(os.path.expanduser("~/.bashrc"), "a") as f:
                f.write(f"\nexport GOPATH={go_path}\n")
                f.write(f"export PATH=$PATH:{go_path}/bin:/usr/local/go/bin\n")
            
            self.print_success("Go installed successfully")
        else:
            self.print_success("Go is already installed")
    
    def install_python_tools(self):
        """Install Python-based tools"""
        self.print_info("Installing Python tools...")
        
        # Install pip packages from requirements.txt
        if self.run_command("pip3 install -r requirements.txt"):
            self.print_success("Python packages installed")
        
        # LinkFinder
        self.print_info("Installing LinkFinder...")
        if self.run_command(f"git clone https://github.com/GerbenJavado/LinkFinder.git {self.tools_dir}/LinkFinder"):
            self.run_command(f"pip3 install -r {self.tools_dir}/LinkFinder/requirements.txt")
            self.print_success("LinkFinder installed")
        
        # XSStrike
        self.print_info("Installing XSStrike...")
        if self.run_command(f"git clone https://github.com/s0md3v/XSStrike {self.tools_dir}/XSStrike"):
            self.run_command(f"pip3 install -r {self.tools_dir}/XSStrike/requirements.txt --break-system-packages")
            self.print_success("XSStrike installed")
        
        # ParamSpider
        self.print_info("Installing ParamSpider...")
        if self.run_command(f"git clone https://github.com/devanshbatham/paramspider {self.tools_dir}/paramspider"):
            os.chdir(f"{self.tools_dir}/paramspider")
            self.run_command("pip3 install .")
            os.chdir("../..")
            self.print_success("ParamSpider installed")
        
        # Gopherus
        self.print_info("Installing Gopherus...")
        if self.run_command(f"git clone https://github.com/tarunkant/Gopherus {self.tools_dir}/Gopherus"):
            os.chdir(f"{self.tools_dir}/Gopherus")
            self.run_command("sudo ./install.sh")
            os.chdir("../..")
            self.print_success("Gopherus installed")
        
        # LFISuite
        self.print_info("Installing LFISuite...")
        if self.run_command(f"git clone https://github.com/D35m0nd142/LFISuite {self.tools_dir}/LFISuite"):
            self.print_success("LFISuite installed")
        
        # Oralyzer
        self.print_info("Installing Oralyzer...")
        if self.run_command(f"git clone https://github.com/r0075h3ll/Oralyzer {self.tools_dir}/Oralyzer"):
            self.run_command(f"pip3 install -r {self.tools_dir}/Oralyzer/requirements.txt")
            self.print_success("Oralyzer installed")
        
        # AWSBucketDump
        self.print_info("Installing AWSBucketDump...")
        if self.run_command(f"git clone https://github.com/jordanpotti/AWSBucketDump {self.tools_dir}/AWSBucketDump"):
            self.print_success("AWSBucketDump installed")
        
        # CMSeeK
        self.print_info("Installing CMSeeK...")
        if self.run_command(f"git clone https://github.com/Tuhinshubhra/CMSeeK {self.tools_dir}/CMSeeK"):
            self.print_success("CMSeeK installed")
        
        # git-dumper
        self.print_info("Installing git-dumper...")
        if self.run_command(f"git clone https://github.com/arthaud/git-dumper {self.tools_dir}/git-dumper"):
            self.run_command(f"pip3 install -r {self.tools_dir}/git-dumper/requirements.txt")
            self.print_success("git-dumper installed")
        
        # Additional CMS Tools
        self.install_cms_tools()
    
    def install_cms_tools(self):
        """Install additional CMS scanning tools"""
        self.print_info("Installing additional CMS tools...")
        
        # JoomScan for Joomla
        self.print_info("Installing JoomScan...")
        if self.run_command(f"git clone https://github.com/OWASP/joomscan.git {self.tools_dir}/joomscan"):
            self.print_success("JoomScan installed")
        
        # WhatWeb (if not already installed)
        self.print_info("Installing WhatWeb...")
        if not self.run_command("which whatweb", check=False):
            if self.run_command("sudo apt install -y whatweb"):
                self.print_success("WhatWeb installed")
            elif self.run_command(f"git clone https://github.com/urbanadventurer/WhatWeb.git {self.tools_dir}/WhatWeb"):
                self.print_success("WhatWeb (source) installed")
        else:
            self.print_success("WhatWeb already installed")
        
        # Wappalyzer CLI (Note: Package is deprecated)
        self.print_warning("Wappalyzer CLI is deprecated - using built-in technology detection instead")
        self.print_info("Skipping Wappalyzer installation (package deprecated)")
        # Alternative: Using enhanced custom technology detection in ReconX
        
        # WordPress Scanner (WPScan)
        self.print_info("Installing WPScan...")
        if not self.run_command("which wpscan", check=False):
            # Install Ruby first if not available
            self.run_command("sudo apt install -y ruby ruby-dev")
            if self.run_command("sudo gem install wpscan"):
                self.print_success("WPScan installed")
            else:
                self.print_warning("WPScan installation failed")
        else:
            self.print_success("WPScan already installed")
        
        # Droopescan for Drupal (Skip due to Python 3.12 compatibility)
        self.print_info("Skipping Droopescan due to Python 3.12 compatibility issues...")
        self.print_info("ReconX includes enhanced manual Drupal detection instead")
        self.print_warning("Droopescan uses deprecated 'imp' module not available in Python 3.12")
    
    def install_go_tools(self):
        """Install Go-based tools"""
        self.print_info("Installing Go tools...")
        
        go_tools = [
            ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
            ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            ("gau", "github.com/lc/gau/v2/cmd/gau@latest"),
            ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
            ("interactsh-client", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
            ("dalfox", "github.com/hahwul/dalfox/v2@latest"),
            ("gf", "github.com/tomnomnom/gf@latest")
        ]
        
        for tool_name, tool_url in go_tools:
            self.print_info(f"Installing {tool_name}...")
            if self.run_command(f"go install -v {tool_url}"):
                self.print_success(f"{tool_name} installed")
            else:
                self.print_error(f"Failed to install {tool_name}")
    
    def install_apt_tools(self):
        """Install tools via apt package manager"""
        self.print_info("Installing APT tools...")
        
        # Update package list
        self.run_command("sudo apt update")
        
        apt_tools = [
            "nmap", "masscan", "gobuster", "ffuf", "nikto", "sqlmap", 
            "wafw00f", "amass", "aquatone", "eyewitness", "fimap"
        ]
        
        for tool in apt_tools:
            self.print_info(f"Installing {tool}...")
            if self.run_command(f"sudo apt install -y {tool}"):
                self.print_success(f"{tool} installed")
            else:
                self.print_warning(f"Failed to install {tool} via apt, may need manual installation")
    
    def install_special_tools(self):
        """Install tools that need special handling"""
        self.print_info("Installing special tools...")
        
        # Assetfinder
        self.print_info("Installing assetfinder...")
        self.run_command("go install -v github.com/tomnomnom/assetfinder@latest")
        
        # Arjun
        self.print_info("Installing Arjun...")
        self.run_command("pipx install arjun")
        
        # Kiterunner
        self.print_info("Installing Kiterunner...")
        kiterunner_url = "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz"
        self.run_command(f"wget -O /tmp/kiterunner.tar.gz {kiterunner_url}")
        self.run_command("tar -xzf /tmp/kiterunner.tar.gz -C /tmp/")
        self.run_command("sudo mv /tmp/kr /usr/local/bin/")
        self.run_command("sudo chmod +x /usr/local/bin/kr")
    
    def create_wordlists(self):
        """Create and download wordlists"""
        self.print_info("Setting up wordlists...")
        
        # Create API endpoints wordlist
        api_endpoints = [
            "api", "api/v1", "api/v2", "api/v3", "rest", "restapi",
            "graphql", "oauth", "auth", "login", "admin", "swagger",
            "api-docs", "docs", "openapi.json", "swagger.json"
        ]
        
        with open(f"{self.wordlists_dir}/apis.txt", "w") as f:
            for endpoint in api_endpoints:
                f.write(f"{endpoint}\n")
        
        # Create redirect payloads
        redirect_payloads = [
            "//evil.com", "///evil.com", "////evil.com",
            "https://evil.com", "http://evil.com",
            "//google.com", "https://google.com",
            "%2F%2Fevil.com", "%2F%2F%2Fevil.com"
        ]
        
        with open(f"{self.wordlists_dir}/redirect_payloads.txt", "w") as f:
            for payload in redirect_payloads:
                f.write(f"{payload}\n")
        
        self.print_success("Wordlists created")
    
    def setup_gf_patterns(self):
        """Setup gf patterns"""
        self.print_info("Setting up gf patterns...")
        self.run_command("git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf")
        self.print_success("Gf patterns installed")

    def install_advanced_security_tools(self):
        """Install advanced security testing tools"""
        self.print_info("Installing advanced security tools...")
        
        # SSLyze for SSL/TLS analysis
        self.print_info("Installing SSLyze...")
        self.run_command("pip3 install sslyze")
        
        # testssl.sh for comprehensive SSL testing
        self.print_info("Installing testssl.sh...")
        if self.run_command("git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh"):
            self.run_command("chmod +x /opt/testssl.sh/testssl.sh")
            self.print_success("testssl.sh installed")
        
        # subjack for subdomain takeover
        self.print_info("Installing subjack...")
        self.run_command("go install github.com/haccer/subjack@latest")
        
        # cors-scanner
        self.print_info("Installing cors-scanner...")
        if self.run_command(f"git clone https://github.com/chenjj/CORScanner.git {self.tools_dir}/CORScanner"):
            self.run_command(f"pip3 install -r {self.tools_dir}/CORScanner/requirements.txt")
            self.print_success("CORScanner installed")

    def install_cloud_tools(self):
        """Install cloud security tools"""
        self.print_info("Installing cloud security tools...")
        
        # AWS CLI
        self.print_info("Installing AWS CLI...")
        self.run_command("curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o awscliv2.zip")
        self.run_command("unzip -q awscliv2.zip && sudo ./aws/install && rm -rf aws awscliv2.zip")
        
        # S3Scanner for S3 bucket enumeration
        self.print_info("Installing S3Scanner...")
        if self.run_command(f"git clone https://github.com/sa7mon/S3Scanner.git {self.tools_dir}/S3Scanner"):
            self.run_command(f"pip3 install -r {self.tools_dir}/S3Scanner/requirements.txt")
            self.print_success("S3Scanner installed")

    def install_osint_tools(self):
        """Install OSINT tools"""
        self.print_info("Installing OSINT tools...")
        
        # theHarvester for email/subdomain gathering
        self.print_info("Installing theHarvester...")
        if self.run_command(f"git clone https://github.com/laramies/theHarvester.git {self.tools_dir}/theHarvester"):
            self.run_command(f"pip3 install -r {self.tools_dir}/theHarvester/requirements.txt")
            self.print_success("theHarvester installed")
        
        # GitDorker for GitHub OSINT
        self.print_info("Installing GitDorker...")
        if self.run_command(f"git clone https://github.com/obheda12/GitDorker.git {self.tools_dir}/GitDorker"):
            self.run_command(f"pip3 install -r {self.tools_dir}/GitDorker/requirements.txt")
            self.print_success("GitDorker installed")

    def create_comprehensive_wordlists(self):
        """Create comprehensive wordlists for various attack types"""
        self.print_info("Creating comprehensive wordlists...")
        
        # CSRF tokens wordlist
        csrf_tokens = ["_token", "authenticity_token", "csrf_token", "csrfToken", "csrf", "token", "_csrf"]
        with open(f"{self.wordlists_dir}/csrf_tokens.txt", 'w') as f:
            f.write('\n'.join(csrf_tokens))
        
        # XXE payloads
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'
        ]
        with open(f"{self.wordlists_dir}/xxe_payloads.txt", 'w') as f:
            f.write('\n'.join(xxe_payloads))
        
        # SSTI payloads
        ssti_payloads = ['{{7*7}}', '${7*7}', '{7*7}', '<%=7*7%>']
        with open(f"{self.wordlists_dir}/ssti_payloads.txt", 'w') as f:
            f.write('\n'.join(ssti_payloads))
        
        self.print_success("Comprehensive wordlists created")
    
    def download_seclists(self):
        """Download SecLists wordlists with user permission"""
        self.print_info("SecLists provides comprehensive wordlists for security testing...")
        self.print_info("SecLists includes:")
        self.print_info("- Directory/file brute-force wordlists")
        self.print_info("- Password and username lists")
        self.print_info("- Fuzzing payloads for various attacks")
        self.print_info("- Common vulnerability patterns")
        self.print_info("- API endpoint wordlists")
        
        while True:
            user_choice = input(f"{Colors.YELLOW}Do you want to download SecLists wordlists? This will take ~200MB of space. (y/n/skip): {Colors.END}").lower().strip()
            
            if user_choice in ['y', 'yes']:
                self.print_info("Downloading SecLists wordlists...")
                if self.run_command("git clone https://github.com/danielmiessler/SecLists.git wordlists/SecLists"):
                    self.print_success("SecLists wordlists downloaded successfully!")
                    self.print_info("SecLists available at: wordlists/SecLists/")
                    self.print_info("Popular wordlists include:")
                    self.print_info("- wordlists/SecLists/Discovery/Web-Content/common.txt")
                    self.print_info("- wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt")
                    self.print_info("- wordlists/SecLists/Passwords/Common-Credentials/")
                    self.print_info("- wordlists/SecLists/Fuzzing/")
                else:
                    self.print_error("Failed to download SecLists")
                break
            elif user_choice in ['n', 'no', 'skip']:
                self.print_warning("Skipping SecLists download")
                self.print_info("You can manually install SecLists later with:")
                self.print_info("git clone https://github.com/danielmiessler/SecLists.git wordlists/SecLists")
                break
            else:
                self.print_warning("Please enter 'y' for yes, 'n' for no, or 'skip' to skip")
        
        return True
    

    
    def print_installation_guide(self):
        """Print installation guide for manual tools"""
        guide = f"""
{Colors.YELLOW}=== Manual Installation Guide ==={Colors.END}

Some tools may require manual installation:

{Colors.GREEN}1. S3 Bucket Wordlist Generation:{Colors.END}
   For S3 bucket enumeration, create target-specific wordlists:
   - {self.wordlists_dir}/target-buckets.txt
   Example content:
     target
     target-prod
     target-dev
     target-staging
     target-backup

{Colors.GREEN}2. Additional Wordlists:{Colors.END}
   SecLists wordlists (if not downloaded during setup):
   - Location: wordlists/SecLists/
   - Manual installation: git clone https://github.com/danielmiessler/SecLists.git wordlists/SecLists
   - Size: ~200MB of comprehensive security testing wordlists
   - Includes: Directory brute-force, password lists, fuzzing payloads, etc.

{Colors.GREEN}3. Manual Tool Verification:{Colors.END}
   Verify these tools are working:
   - EyeWitness: Check if installed via pip or apt
   - Aquatone: May need manual installation from GitHub releases
   - Fimap: Check availability in your distribution

{Colors.GREEN}4. Environment Setup:{Colors.END}
   Add Go bin to PATH if not already done:
   echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
   source ~/.bashrc

{Colors.YELLOW}Run 'python3 reconx.py --help' to get started!{Colors.END}
        """
        print(guide)
    
    def run_setup(self):
        """Run complete setup"""
        print(f"""
{Colors.GREEN}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{Colors.END}
{Colors.YELLOW}ReconX Setup - Installing Tools and Dependencies{Colors.END}
        """)
        
        try:
            self.check_and_install_go()
            self.install_apt_tools()
            self.install_python_tools()
            self.install_go_tools()
            self.install_special_tools()
            self.install_advanced_security_tools()
            self.install_cloud_tools()
            self.install_osint_tools()
            self.create_wordlists()
            self.create_comprehensive_wordlists()
            self.download_seclists()  # Ask user for SecLists download
            self.setup_gf_patterns()
            
            self.print_success("ReconX comprehensive setup completed successfully!")
            self.print_installation_guide()
            
        except KeyboardInterrupt:
            self.print_error("Setup interrupted by user")
            sys.exit(1)
        except Exception as e:
            self.print_error(f"Setup failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    setup = ReconXSetup()
    setup.run_setup()
