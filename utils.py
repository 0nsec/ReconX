#!/usr/bin/env python3
"""
ReconX Utilities
Additional helper functions for the toolkit
"""

import os
import json
import csv
from datetime import datetime
import requests
from urllib.parse import urlparse

class ReconXUtils:
    @staticmethod
    def parse_nmap_xml(xml_file):
        """Parse Nmap XML output and extract open ports"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts = []
            for host in root.findall('host'):
                host_info = {}
                
                # Get host address
                address = host.find('address').get('addr')
                host_info['address'] = address
                
                # Get open ports
                ports = []
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_info = {
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
                            }
                            ports.append(port_info)
                
                host_info['ports'] = ports
                hosts.append(host_info)
            
            return hosts
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")
            return []
    
    @staticmethod
    def generate_report(scan_dir, target):
        """Generate a comprehensive HTML report"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ReconX Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .vulnerability {{ background-color: #e74c3c; color: white; padding: 10px; border-radius: 3px; margin: 5px 0; }}
                .info {{ background-color: #3498db; color: white; padding: 10px; border-radius: 3px; margin: 5px 0; }}
                .success {{ background-color: #27ae60; color: white; padding: 10px; border-radius: 3px; margin: 5px 0; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 3px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>ReconX Security Assessment Report</h1>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        """
        
        # Add sections for each scan type
        sections = [
            'subdomains', 'ports', 'directories', 'vulnerabilities', 
            'headers', 'api', 'cms', 'waf'
        ]
        
        for section in sections:
            section_path = os.path.join(scan_dir, section)
            if os.path.exists(section_path):
                html_template += f"""
                <div class="section">
                    <h2>{section.title()} Results</h2>
                """
                
                # List files in section
                for file in os.listdir(section_path):
                    file_path = os.path.join(section_path, file)
                    if os.path.isfile(file_path):
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()[:1000]  # First 1000 chars
                                html_template += f"""
                                <h3>{file}</h3>
                                <pre>{content}{'...' if len(content) >= 1000 else ''}</pre>
                                """
                        except:
                            continue
                
                html_template += "</div>"
        
        html_template += """
        </body>
        </html>
        """
        
        report_file = os.path.join(scan_dir, f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(report_file, 'w') as f:
            f.write(html_template)
        
        return report_file
    
    @staticmethod
    def check_alive_subdomains(subdomains_file, output_file):
        """Check which subdomains are alive"""
        alive_subdomains = []
        
        if not os.path.exists(subdomains_file):
            return alive_subdomains
        
        with open(subdomains_file, 'r') as f:
            subdomains = [line.strip() for line in f.readlines() if line.strip()]
        
        for subdomain in subdomains[:50]:  # Limit to first 50 to avoid rate limiting
            try:
                for protocol in ['https', 'http']:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                    if response.status_code < 400:
                        alive_subdomains.append({
                            'url': url,
                            'status_code': response.status_code,
                            'title': ReconXUtils.extract_title(response.text)
                        })
                        break
            except:
                continue
        
        # Save alive subdomains
        with open(output_file, 'w') as f:
            json.dump(alive_subdomains, f, indent=2)
        
        return alive_subdomains
    
    @staticmethod
    def extract_title(html_content):
        """Extract title from HTML content"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else 'No Title'
        except:
            return 'No Title'
    
    @staticmethod
    def merge_subdomain_files(scan_dir):
        """Merge all subdomain files into one unique list"""
        all_subdomains = set()
        subdomains_dir = os.path.join(scan_dir, 'subdomains')
        
        if not os.path.exists(subdomains_dir):
            return []
        
        for file in os.listdir(subdomains_dir):
            if file.endswith('.txt') and file != 'subdomains.txt':
                file_path = os.path.join(subdomains_dir, file)
                try:
                    with open(file_path, 'r') as f:
                        subdomains = [line.strip() for line in f.readlines() if line.strip()]
                        all_subdomains.update(subdomains)
                except:
                    continue
        
        # Save merged subdomains
        output_file = os.path.join(subdomains_dir, 'subdomains.txt')
        with open(output_file, 'w') as f:
            for subdomain in sorted(all_subdomains):
                f.write(f"{subdomain}\n")
        
        return list(all_subdomains)
    
    @staticmethod
    def create_target_wordlist(target_domain):
        """Create target-specific wordlists"""
        base_name = target_domain.split('.')[0]
        domain_parts = target_domain.split('.')
        
        wordlists = {
            'subdomains': [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                'app', 'web', 'portal', 'secure', 'vpn', 'remote', 'blog',
                f'{base_name}-dev', f'{base_name}-test', f'{base_name}-staging',
                f'{base_name}-api', f'{base_name}-admin', f'{base_name}-app'
            ],
            's3buckets': [
                base_name, f'{base_name}-prod', f'{base_name}-dev', f'{base_name}-test',
                f'{base_name}-staging', f'{base_name}-backup', f'{base_name}-data',
                f'{base_name}-uploads', f'{base_name}-assets', f'{base_name}-static',
                target_domain.replace('.', '-'), target_domain.replace('.', ''),
                f'{target_domain}-backup', f'{target_domain}-data'
            ]
        }
        
        return wordlists

if __name__ == "__main__":
    # Example usage
    utils = ReconXUtils()
    print("ReconX Utilities loaded successfully!")
