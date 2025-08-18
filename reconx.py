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
        
        wordlist = "/usr/share/wordlists/dirb/common.txt"  # Default wordlist
        
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
        
        # Kiterunner (fix the command syntax)
        if self.check_tool_installed('kr'):
            apis_wordlist = "wordlists/apis.txt"
            api_output = f"{self.scan_dir}/api/kiterunner_{self.domain}.txt"
            # Fixed syntax for kiterunner
            self.run_command(f"kr scan https://{self.domain} -w {apis_wordlist} > {api_output}")
        
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
        """Enumerate CMS information"""
        self.print_info("Starting CMS enumeration...")
        
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
                self.print_error(f"Error during CMS enumeration: {e}")
                # Fallback to simple command execution
                self.run_command(f"python3 tools/CMSeeK/cmseek.py -u {self.domain} > {cms_output}")
        
        self.print_success("CMS enumeration completed")
    
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
{Colors.GREEN}18.{Colors.END} Full Scan (All tests)
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
            18: self.full_scan
        }
        
        try:
            if '18' in choices:
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
        self.print_info("Starting full reconnaissance scan...")
        
        # Run all scans in order
        scans = [
            ("Subdomain Enumeration", self.subdomain_enumeration),
            ("Port Scanning", self.port_scanning),
            ("Screenshots", self.take_screenshots),
            ("Directory Bruteforce", self.directory_bruteforce),
            ("JavaScript Analysis", self.javascript_analysis),
            ("Parameter Discovery", self.parameter_discovery),
            ("Security Headers Check", self.security_headers_check),
            ("API Reconnaissance", self.api_reconnaissance),
            ("S3 Bucket Enumeration", self.s3_bucket_enumeration),
            ("CMS Enumeration", self.cms_enumeration),
            ("WAF Detection", self.waf_detection),
            ("Information Disclosure", self.information_disclosure)
        ]
        
        for scan_name, scan_func in scans:
            self.print_info(f"Running {scan_name}...")
            scan_func()
            time.sleep(2)  # Brief pause between scans
        
        self.print_success("Full reconnaissance scan completed!")
        self.print_info(f"Results saved in: {self.scan_dir}")
    
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
