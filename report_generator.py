#!/usr/bin/env python3
"""
ReconX HTML Report Generator
Creates interactive HTML reports with detailed vulnerability findings
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

class ReconXReportGenerator:
    def __init__(self, scan_dir, domain, target):
        self.scan_dir = scan_dir
        self.domain = domain
        self.target = target
        self.scan_results = {}
        
    def print_info(self, message):
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    def print_success(self, message):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    def print_error(self, message):
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    def collect_scan_results(self):
        """Collect and analyze all scan results"""
        self.print_info("Collecting scan results...")
        
        results = {
            "target": self.target,
            "domain": self.domain,
            "scan_dir": self.scan_dir,
            "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "subdomains": self._collect_subdomains(),
            "ports": self._collect_ports(),
            "vulnerabilities": self._collect_vulnerabilities(),
            "cms": self._collect_cms(),
            "technologies": self._collect_technologies(),
            "security_headers": self._collect_security_headers(),
            "ssl_analysis": self._collect_ssl(),
            "api_endpoints": self._collect_api(),
            "s3_buckets": self._collect_s3(),
            "github_findings": self._collect_github(),
            "nuclei_results": self._collect_nuclei(),
            "screenshots": self._collect_screenshots(),
            "directories": self._collect_directories()
        }
        
        self.scan_results = results
        return results
    
    def _collect_subdomains(self):
        """Collect subdomain enumeration results"""
        data = {"count": 0, "files": [], "data": []}
        
        subdomains_file = f"{self.scan_dir}/subdomains/subdomains.txt"
        if os.path.exists(subdomains_file):
            try:
                with open(subdomains_file, 'r') as f:
                    subdomains = [line.strip() for line in f.readlines() if line.strip()]
                    data["count"] = len(subdomains)
                    data["data"] = subdomains
                    data["files"].append("subdomains.txt")
            except Exception as e:
                self.print_error(f"Error reading subdomains: {e}")
        
        return data
    
    def _collect_ports(self):
        """Collect port scanning results"""
        data = {"count": 0, "files": [], "data": []}
        
        ports_dir = f"{self.scan_dir}/ports"
        if os.path.exists(ports_dir):
            port_files = [f for f in os.listdir(ports_dir) if f.endswith('.txt')]
            data["files"] = port_files
            data["count"] = len(port_files)
            
            # Try to extract open ports from nmap results
            for file in port_files:
                if 'nmap' in file:
                    try:
                        with open(f"{ports_dir}/{file}", 'r') as f:
                            content = f.read()
                            # Simple parsing for open ports
                            lines = content.split('\n')
                            for line in lines:
                                if '/tcp' in line and 'open' in line:
                                    data["data"].append(line.strip())
                    except Exception:
                        pass
        
        return data
    
    def _collect_vulnerabilities(self):
        """Collect vulnerability findings"""
        data = {"count": 0, "categories": {}, "detailed": {}}
        
        vuln_dir = f"{self.scan_dir}/vulnerabilities"
        if os.path.exists(vuln_dir):
            vuln_categories = {
                "XSS": ["xss", "dalfox", "xsstrike"],
                "SQL Injection": ["sql", "sqlmap"],
                "LFI/RFI": ["lfi", "lfisuite", "fimap"],
                "CSRF": ["csrf"],
                "JWT": ["jwt"],
                "XXE": ["xxe"],
                "SSTI": ["ssti"],
                "NoSQL": ["nosql"],
                "CORS": ["cors"],
                "File Upload": ["file_upload"],
                "Auth Bypass": ["auth_bypass"],
                "Race Conditions": ["race_condition"],
                "Business Logic": ["business_logic"],
                "Subdomain Takeover": ["subdomain_takeover"],
                "Deserialization": ["deserialization"],
                "WebSocket": ["websocket"]
            }
            
            total_vulns = 0
            for category, patterns in vuln_categories.items():
                category_files = []
                category_content = []
                
                for pattern in patterns:
                    # Check main vulnerability directory
                    for file in os.listdir(vuln_dir):
                        if pattern in file and file.endswith('.txt'):
                            file_path = f"{vuln_dir}/{file}"
                            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                                category_files.append(file)
                                # Read file content for detailed view
                                try:
                                    with open(file_path, 'r') as f:
                                        content = f.read()
                                        if content.strip():
                                            category_content.append({
                                                "file": file,
                                                "content": content[:2000] + ("..." if len(content) > 2000 else "")
                                            })
                                            total_vulns += 1
                                except Exception:
                                    pass
                    
                    # Check subdirectories
                    subdir_path = f"{vuln_dir}/{pattern}"
                    if os.path.exists(subdir_path) and os.path.isdir(subdir_path):
                        for file in os.listdir(subdir_path):
                            if file.endswith('.txt'):
                                file_path = f"{subdir_path}/{file}"
                                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                                    category_files.append(f"{pattern}/{file}")
                                    try:
                                        with open(file_path, 'r') as f:
                                            content = f.read()
                                            if content.strip():
                                                category_content.append({
                                                    "file": f"{pattern}/{file}",
                                                    "content": content[:2000] + ("..." if len(content) > 2000 else "")
                                                })
                                                total_vulns += 1
                                    except Exception:
                                        pass
                
                if category_files:
                    data["categories"][category] = category_files
                    data["detailed"][category] = category_content
            
            data["count"] = total_vulns
        
        return data
    
    def _collect_cms(self):
        """Collect CMS detection results"""
        data = {"detected": [], "files": [], "detailed": []}
        
        cms_dir = f"{self.scan_dir}/cms"
        if os.path.exists(cms_dir):
            cms_files = [f for f in os.listdir(cms_dir) if f.endswith(('.txt', '.json', '.html'))]
            data["files"] = cms_files
            
            # Try to extract CMS detection from various sources
            for file in cms_files:
                file_path = f"{cms_dir}/{file}"
                try:
                    if file.endswith('.json'):
                        with open(file_path, 'r') as f:
                            cms_data = json.load(f)
                            if isinstance(cms_data, dict):
                                if 'cms_name' in cms_data and cms_data['cms_name']:
                                    data["detected"].append(cms_data['cms_name'])
                                if 'confidence_scores' in cms_data:
                                    for tech, info in cms_data['confidence_scores'].items():
                                        if isinstance(info, dict) and info.get('confidence', 0) > 70:
                                            if tech not in data["detected"]:
                                                data["detected"].append(tech)
                    
                    # Read file content for detailed view
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def _collect_technologies(self):
        """Collect technology detection results"""
        data = {"detected": [], "confidence": {}, "detailed": []}
        
        cms_dir = f"{self.scan_dir}/cms"
        tech_file = f"{cms_dir}/technology_detection.json"
        
        if os.path.exists(tech_file):
            try:
                with open(tech_file, 'r') as f:
                    tech_data = json.load(f)
                    if 'confidence_scores' in tech_data:
                        for tech, info in tech_data['confidence_scores'].items():
                            if isinstance(info, dict) and info.get('confidence', 0) > 50:
                                data["detected"].append(tech)
                                data["confidence"][tech] = info.get('confidence', 0)
                    
                    data["detailed"].append({
                        "file": "technology_detection.json",
                        "content": json.dumps(tech_data, indent=2)[:1500]
                    })
            except Exception:
                pass
        
        return data
    
    def _collect_security_headers(self):
        """Collect security headers analysis"""
        data = {"files": [], "issues": [], "detailed": []}
        
        headers_dir = f"{self.scan_dir}/headers"
        if os.path.exists(headers_dir):
            header_files = [f for f in os.listdir(headers_dir) if f.endswith('.txt')]
            data["files"] = header_files
            
            for file in header_files:
                file_path = f"{headers_dir}/{file}"
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def _collect_ssl(self):
        """Collect SSL/TLS analysis results"""
        data = {"files": [], "issues": [], "detailed": []}
        
        ssl_dir = f"{self.scan_dir}/ssl"
        if os.path.exists(ssl_dir):
            ssl_files = [f for f in os.listdir(ssl_dir) if f.endswith('.txt')]
            data["files"] = ssl_files
            
            for file in ssl_files:
                file_path = f"{ssl_dir}/{file}"
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def _collect_api(self):
        """Collect API endpoint results"""
        data = {"count": 0, "files": [], "detailed": []}
        
        api_dir = f"{self.scan_dir}/api"
        if os.path.exists(api_dir):
            api_files = [f for f in os.listdir(api_dir) if f.endswith('.txt')]
            data["files"] = api_files
            data["count"] = len(api_files)
            
            for file in api_files:
                file_path = f"{api_dir}/{file}"
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def _collect_s3(self):
        """Collect S3 bucket results"""
        data = {"count": 0, "files": [], "detailed": []}
        
        s3_dir = f"{self.scan_dir}/s3buckets"
        if os.path.exists(s3_dir):
            s3_files = [f for f in os.listdir(s3_dir) if os.path.isfile(os.path.join(s3_dir, f))]
            data["files"] = s3_files
            data["count"] = len(s3_files)
            
            for file in s3_files:
                file_path = f"{s3_dir}/{file}"
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def _collect_github(self):
        """Collect GitHub OSINT results"""
        data = {"files": [], "detailed": []}
        
        osint_dir = f"{self.scan_dir}/osint"
        if os.path.exists(osint_dir):
            github_files = [f for f in os.listdir(osint_dir) if 'github' in f.lower()]
            data["files"] = github_files
            
            for file in github_files:
                file_path = f"{osint_dir}/{file}"
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def _collect_nuclei(self):
        """Collect Nuclei scan results"""
        data = {"files": [], "count": 0, "detailed": []}
        
        vuln_dir = f"{self.scan_dir}/vulnerabilities"
        if os.path.exists(vuln_dir):
            nuclei_files = [f for f in os.listdir(vuln_dir) if 'nuclei' in f.lower() and f.endswith('.txt')]
            data["files"] = nuclei_files
            data["count"] = len(nuclei_files)
            
            for file in nuclei_files:
                file_path = f"{vuln_dir}/{file}"
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def _collect_screenshots(self):
        """Collect screenshot results"""
        data = {"directories": [], "count": 0}
        
        screenshots_dir = f"{self.scan_dir}/screenshots"
        if os.path.exists(screenshots_dir):
            screenshot_dirs = [d for d in os.listdir(screenshots_dir) if os.path.isdir(os.path.join(screenshots_dir, d))]
            data["directories"] = screenshot_dirs
            
            # Count total screenshots
            total_screenshots = 0
            for dir_name in screenshot_dirs:
                dir_path = f"{screenshots_dir}/{dir_name}"
                try:
                    files = [f for f in os.listdir(dir_path) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
                    total_screenshots += len(files)
                except Exception:
                    pass
            
            data["count"] = total_screenshots
        
        return data
    
    def _collect_directories(self):
        """Collect directory bruteforce results"""
        data = {"files": [], "count": 0, "detailed": []}
        
        directories_dir = f"{self.scan_dir}/directories"
        if os.path.exists(directories_dir):
            dir_files = [f for f in os.listdir(directories_dir) if f.endswith('.txt')]
            data["files"] = dir_files
            data["count"] = len(dir_files)
            
            for file in dir_files:
                file_path = f"{directories_dir}/{file}"
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        data["detailed"].append({
                            "file": file,
                            "content": content[:1500] + ("..." if len(content) > 1500 else "")
                        })
                except Exception:
                    pass
        
        return data
    
    def generate_html_report(self):
        """Generate interactive HTML report"""
        self.print_info("Generating interactive HTML report...")
        
        # Collect all scan results
        results = self.collect_scan_results()
        
        # Generate HTML content
        html_content = self._create_html_template(results)
        
        # Write HTML file
        report_file = f"{self.scan_dir}/ReconX_Report_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.print_success(f"Interactive HTML report generated: {report_file}")
            self.print_info(f"Open the report in your browser: file://{os.path.abspath(report_file)}")
            
            return report_file
            
        except Exception as e:
            self.print_error(f"Failed to generate HTML report: {e}")
            return None
    
    def _create_html_template(self, results):
        """Create the interactive HTML template"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX Security Assessment Report - {results['domain']}</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #3498db;
            --light-bg: #f8f9fa;
            --dark-bg: #2c3e50;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: var(--light-bg);
        }}
        
        .header {{
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 2rem;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 1rem;
        }}
        
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        
        .info-card {{
            background: rgba(255,255,255,0.1);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
        }}
        
        .section {{
            background: white;
            margin: 2rem 0;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .section-header {{
            background: var(--primary-color);
            color: white;
            padding: 1.5rem;
            font-size: 1.3rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .section-content {{
            padding: 2rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: var(--light-bg);
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid var(--secondary-color);
            transition: transform 0.2s;
            cursor: pointer;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--primary-color);
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }}
        
        .vuln-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }}
        
        .vuln-card {{
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 1.5rem;
            border-left: 4px solid var(--danger-color);
            transition: transform 0.2s;
        }}
        
        .vuln-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .vuln-title {{
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }}
        
        .vuln-files {{
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }}
        
        .btn {{
            background: var(--secondary-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.2s;
        }}
        
        .btn:hover {{
            background: var(--primary-color);
        }}
        
        .btn-small {{
            padding: 0.3rem 0.6rem;
            font-size: 0.8rem;
        }}
        
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }}
        
        .modal-content {{
            background-color: white;
            margin: 5% auto;
            padding: 2rem;
            border-radius: 10px;
            width: 90%;
            max-width: 800px;
            max-height: 80%;
            overflow-y: auto;
        }}
        
        .close {{
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }}
        
        .close:hover {{
            color: black;
        }}
        
        .modal-header {{
            border-bottom: 1px solid #eee;
            padding-bottom: 1rem;
            margin-bottom: 1rem;
        }}
        
        .modal-body {{
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 5px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 0.9rem;
            line-height: 1.4;
        }}
        
        .subdomain-list {{
            max-height: 300px;
            overflow-y: auto;
            background: var(--light-bg);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }}
        
        .subdomain-item {{
            padding: 0.5rem;
            border-bottom: 1px solid #e0e0e0;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }}
        
        .subdomain-item:last-child {{
            border-bottom: none;
        }}
        
        .tech-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .tech-card {{
            background: var(--light-bg);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e0e0e0;
            transition: transform 0.2s;
        }}
        
        .tech-card:hover {{
            transform: translateY(-2px);
        }}
        
        .tech-name {{
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }}
        
        .confidence-bar {{
            background: #e0e0e0;
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
        }}
        
        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--danger-color), var(--warning-color), var(--success-color));
            transition: width 0.3s ease;
        }}
        
        .alert {{
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }}
        
        .alert-info {{
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }}
        
        .alert-warning {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }}
        
        .alert-success {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }}
        
        .tab-container {{
            margin-top: 2rem;
        }}
        
        .tab-buttons {{
            display: flex;
            background: #f8f9fa;
            border-radius: 8px 8px 0 0;
            overflow-x: auto;
        }}
        
        .tab-button {{
            background: none;
            border: none;
            padding: 1rem 1.5rem;
            cursor: pointer;
            white-space: nowrap;
            transition: background 0.2s;
        }}
        
        .tab-button.active {{
            background: white;
            border-bottom: 2px solid var(--secondary-color);
        }}
        
        .tab-button:hover {{
            background: #e9ecef;
        }}
        
        .tab-content {{
            background: white;
            padding: 1.5rem;
            border: 1px solid #e0e0e0;
            border-top: none;
        }}
        
        .tab-pane {{
            display: none;
        }}
        
        .tab-pane.active {{
            display: block;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2rem;
            }}
            
            .container {{
                padding: 0 0.5rem;
            }}
            
            .stats-grid, .vuln-grid, .tech-grid {{
                grid-template-columns: 1fr;
            }}
            
            .modal-content {{
                width: 95%;
                margin: 10% auto;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ReconX Security Assessment Report</h1>
        <p class="subtitle">Comprehensive Security Analysis for {results['domain']}</p>
        
        <div class="scan-info">
            <div class="info-card">
                <strong>Target</strong><br>{results['target']}
            </div>
            <div class="info-card">
                <strong>Scan Date</strong><br>{results['scan_time']}
            </div>
            <div class="info-card">
                <strong>Total Tests</strong><br>35+ Security Modules
            </div>
            <div class="info-card">
                <strong>Report Type</strong><br>Automated Full Scan
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Executive Summary -->
        <div class="section">
            <div class="section-header">
                Executive Summary
            </div>
            <div class="section-content">
                <div class="stats-grid">
                    <div class="stat-card" onclick="showSubdomains()">
                        <div class="stat-number">{results['subdomains']['count']}</div>
                        <div class="stat-label">Subdomains Discovered</div>
                        <button class="btn btn-small">View Details</button>
                    </div>
                    <div class="stat-card" onclick="showVulnerabilities()">
                        <div class="stat-number">{results['vulnerabilities']['count']}</div>
                        <div class="stat-label">Potential Vulnerabilities</div>
                        <button class="btn btn-small">View Details</button>
                    </div>
                    <div class="stat-card" onclick="showTechnologies()">
                        <div class="stat-number">{len(results['technologies']['detected'])}</div>
                        <div class="stat-label">Technologies Identified</div>
                        <button class="btn btn-small">View Details</button>
                    </div>
                    <div class="stat-card" onclick="showCMS()">
                        <div class="stat-number">{len(results['cms']['detected'])}</div>
                        <div class="stat-label">CMS Platforms Detected</div>
                        <button class="btn btn-small">View Details</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Vulnerability Assessment -->
        {self._generate_vulnerability_section_html(results['vulnerabilities'])}

        <!-- Reconnaissance Results -->
        {self._generate_reconnaissance_section_html(results)}

        <!-- Technology Stack -->
        {self._generate_technology_section_html(results['technologies'], results['cms'])}

        <!-- Detailed Analysis -->
        {self._generate_detailed_analysis_section(results)}
    </div>

    <!-- Modals -->
    {self._generate_modals_html(results)}

    <div class="section" style="background: var(--primary-color); color: white; margin-top: 3rem;">
        <div class="section-content" style="text-align: center;">
            <h3>ReconX - Advanced Bug Hunting Reconnaissance Toolkit</h3>
            <p>Generated on {results['scan_time']} | Scan Directory: {results['scan_dir']}</p>
            <p style="margin-top: 1rem; opacity: 0.8;">
                This automated security assessment identified potential security issues. 
                Manual verification and additional testing are recommended.
            </p>
        </div>
    </div>

    <script>
        {self._generate_javascript()}
    </script>
</body>
</html>
        """
    
    def _generate_vulnerability_section_html(self, vuln_data):
        """Generate vulnerability section with interactive buttons"""
        if vuln_data['count'] == 0:
            return f"""
            <div class="section">
                <div class="section-header">Vulnerability Assessment</div>
                <div class="section-content">
                    <div class="alert alert-success">
                        <strong>Great news!</strong> No obvious vulnerabilities detected during automated scanning. 
                        However, manual testing is still recommended for comprehensive security assessment.
                    </div>
                </div>
            </div>
            """
        
        vuln_html = f"""
        <div class="section">
            <div class="section-header">Vulnerability Assessment</div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>⚠️ {vuln_data['count']} potential security issues identified.</strong>
                    Click on each category below to view detailed findings.
                </div>
                
                <div class="vuln-grid">
        """
        
        for category, files in vuln_data['categories'].items():
            vuln_html += f"""
                <div class="vuln-card">
                    <div class="vuln-title">{category}</div>
                    <div class="vuln-files">Files: {len(files)} result(s)</div>
                    <button class="btn" onclick="showVulnDetails('{category}')">View Details</button>
                </div>
            """
        
        vuln_html += """
                </div>
            </div>
        </div>
        """
        
        return vuln_html
    
    def _generate_reconnaissance_section_html(self, results):
        """Generate reconnaissance section with buttons"""
        return f"""
        <div class="section">
            <div class="section-header">Reconnaissance Results</div>
            <div class="section-content">
                <div class="stats-grid">
                    <div class="stat-card" onclick="showPortScan()">
                        <div class="stat-number">{results['ports']['count']}</div>
                        <div class="stat-label">Port Scan Files</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                    <div class="stat-card" onclick="showDirectories()">
                        <div class="stat-number">{results['directories']['count']}</div>
                        <div class="stat-label">Directory Scans</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                    <div class="stat-card" onclick="showAPI()">
                        <div class="stat-number">{results['api_endpoints']['count']}</div>
                        <div class="stat-label">API Endpoints</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                    <div class="stat-card" onclick="showScreenshots()">
                        <div class="stat-number">{results['screenshots']['count']}</div>
                        <div class="stat-label">Screenshots</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_technology_section_html(self, tech_data, cms_data):
        """Generate technology section with interactive elements"""
        tech_html = f"""
        <div class="section">
            <div class="section-header">Technology Stack Analysis</div>
            <div class="section-content">
        """
        
        if cms_data['detected'] or tech_data['detected']:
            tech_html += f"""
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab('cms-tab')">CMS Platforms</button>
                        <button class="tab-button" onclick="showTab('tech-tab')">Technologies</button>
                        <button class="tab-button" onclick="showTab('detailed-tab')">Detailed Analysis</button>
                    </div>
                    
                    <div class="tab-content">
                        <div class="tab-pane active" id="cms-tab">
                            {self._generate_cms_tab(cms_data)}
                        </div>
                        <div class="tab-pane" id="tech-tab">
                            {self._generate_tech_tab(tech_data)}
                        </div>
                        <div class="tab-pane" id="detailed-tab">
                            <button class="btn" onclick="showTechDetails()">View Detailed Technology Analysis</button>
                        </div>
                    </div>
                </div>
            """
        else:
            tech_html += '<div class="alert alert-info">No specific technologies detected during automated analysis.</div>'
        
        tech_html += """
            </div>
        </div>
        """
        
        return tech_html
    
    def _generate_cms_tab(self, cms_data):
        """Generate CMS tab content"""
        if not cms_data['detected']:
            return '<div class="alert alert-info">No CMS platforms detected.</div>'
        
        html = '<div class="tech-grid">'
        for cms in cms_data['detected']:
            html += f"""
                <div class="tech-card">
                    <div class="tech-name">{cms}</div>
                    <div style="color: var(--success-color); font-weight: 600;">Detected</div>
                </div>
            """
        html += '</div>'
        return html
    
    def _generate_tech_tab(self, tech_data):
        """Generate technology tab content"""
        if not tech_data['detected']:
            return '<div class="alert alert-info">No specific technologies identified.</div>'
        
        html = '<div class="tech-grid">'
        for tech in tech_data['detected']:
            confidence = tech_data['confidence'].get(tech, 0)
            html += f"""
                <div class="tech-card">
                    <div class="tech-name">{tech}</div>
                    <div style="margin: 0.5rem 0;">
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {confidence}%"></div>
                        </div>
                        <div style="font-size: 0.8rem; color: #666; margin-top: 0.2rem;">
                            {confidence}% confidence
                        </div>
                    </div>
                </div>
            """
        html += '</div>'
        return html
    
    def _generate_detailed_analysis_section(self, results):
        """Generate detailed analysis section"""
        return f"""
        <div class="section">
            <div class="section-header">Additional Analysis</div>
            <div class="section-content">
                <div class="stats-grid">
                    <div class="stat-card" onclick="showSecurityHeaders()">
                        <div class="stat-number">{len(results['security_headers']['files'])}</div>
                        <div class="stat-label">Security Header Scans</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                    <div class="stat-card" onclick="showSSLAnalysis()">
                        <div class="stat-number">{len(results['ssl_analysis']['files'])}</div>
                        <div class="stat-label">SSL/TLS Analysis</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                    <div class="stat-card" onclick="showS3Buckets()">
                        <div class="stat-number">{results['s3_buckets']['count']}</div>
                        <div class="stat-label">S3 Bucket Scans</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                    <div class="stat-card" onclick="showGitHubFindings()">
                        <div class="stat-number">{len(results['github_findings']['files'])}</div>
                        <div class="stat-label">GitHub OSINT</div>
                        <button class="btn btn-small">View Results</button>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_modals_html(self, results):
        """Generate all modal windows"""
        modals = ""
        
        # Subdomain modal
        modals += f"""
        <div id="subdomainModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="close" onclick="closeModal('subdomainModal')">&times;</span>
                    <h2>Discovered Subdomains ({results['subdomains']['count']})</h2>
                </div>
                <div class="modal-body">
                    {'<br>'.join(results['subdomains']['data']) if results['subdomains']['data'] else 'No subdomains found'}
                </div>
            </div>
        </div>
        """
        
        # Vulnerability modals
        for category, content_list in results['vulnerabilities']['detailed'].items():
            modals += f"""
            <div id="vuln{category.replace(' ', '').replace('/', '')}" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <span class="close" onclick="closeModal('vuln{category.replace(' ', '').replace('/', '')}')">&times;</span>
                        <h2>{category} Vulnerabilities</h2>
                    </div>
                    <div class="modal-body">
                        {'<hr style="margin: 1rem 0;">'.join([f"<strong>File: {item['file']}</strong><br><br>{item['content']}" for item in content_list]) if content_list else 'No detailed results available'}
                    </div>
                </div>
            </div>
            """
        
        # Technology details modal
        tech_content = ""
        for item in results['technologies']['detailed']:
            tech_content += f"<strong>File: {item['file']}</strong><br><br>{item['content']}<hr style='margin: 1rem 0;'>"
        
        modals += f"""
        <div id="techModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="close" onclick="closeModal('techModal')">&times;</span>
                    <h2>Technology Detection Details</h2>
                </div>
                <div class="modal-body">
                    {tech_content if tech_content else 'No detailed technology analysis available'}
                </div>
            </div>
        </div>
        """
        
        # Add other modals for different sections
        sections = [
            ('portModal', 'Port Scanning Results', results['ports'].get('detailed', [])),
            ('dirModal', 'Directory Bruteforce Results', results['directories'].get('detailed', [])),
            ('apiModal', 'API Endpoint Results', results['api_endpoints'].get('detailed', [])),
            ('headerModal', 'Security Headers Analysis', results['security_headers'].get('detailed', [])),
            ('sslModal', 'SSL/TLS Analysis', results['ssl_analysis'].get('detailed', [])),
            ('s3Modal', 'S3 Bucket Results', results['s3_buckets'].get('detailed', [])),
            ('githubModal', 'GitHub OSINT Findings', results['github_findings'].get('detailed', [])),
            ('cmsModal', 'CMS Detection Details', results['cms'].get('detailed', [])),
            ('screenshotModal', 'Screenshot Information', [])
        ]
        
        for modal_id, title, content_list in sections:
            content = ""
            if content_list:
                for item in content_list:
                    content += f"<strong>File: {item['file']}</strong><br><br>{item['content']}<hr style='margin: 1rem 0;'>"
            else:
                if modal_id == 'screenshotModal':
                    content = f"Screenshots captured: {results['screenshots']['count']}<br>Directories: {', '.join(results['screenshots']['directories']) if results['screenshots']['directories'] else 'None'}"
                else:
                    content = f"No {title.lower()} results available"
            
            modals += f"""
            <div id="{modal_id}" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <span class="close" onclick="closeModal('{modal_id}')">&times;</span>
                        <h2>{title}</h2>
                    </div>
                    <div class="modal-body">
                        {content}
                    </div>
                </div>
            </div>
            """
        
        return modals
    
    def _generate_javascript(self):
        """Generate JavaScript for interactivity"""
        return """
        function showModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        function showSubdomains() {
            showModal('subdomainModal');
        }
        
        function showVulnerabilities() {
            // Show first vulnerability category or create a summary
            const vulnModals = document.querySelectorAll('[id^="vuln"]');
            if (vulnModals.length > 0) {
                vulnModals[0].style.display = 'block';
            }
        }
        
        function showVulnDetails(category) {
            const modalId = 'vuln' + category.replace(/ /g, '').replace(/\\//g, '');
            showModal(modalId);
        }
        
        function showTechnologies() {
            showModal('techModal');
        }
        
        function showTechDetails() {
            showModal('techModal');
        }
        
        function showCMS() {
            showModal('cmsModal');
        }
        
        function showPortScan() {
            showModal('portModal');
        }
        
        function showDirectories() {
            showModal('dirModal');
        }
        
        function showAPI() {
            showModal('apiModal');
        }
        
        function showScreenshots() {
            showModal('screenshotModal');
        }
        
        function showSecurityHeaders() {
            showModal('headerModal');
        }
        
        function showSSLAnalysis() {
            showModal('sslModal');
        }
        
        function showS3Buckets() {
            showModal('s3Modal');
        }
        
        function showGitHubFindings() {
            showModal('githubModal');
        }
        
        function showTab(tabId) {
            // Hide all tab panes
            const tabPanes = document.querySelectorAll('.tab-pane');
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            // Remove active class from all buttons
            const tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(button => button.classList.remove('active'));
            
            // Show selected tab pane
            document.getElementById(tabId).classList.add('active');
            
            // Add active class to clicked button
            event.target.classList.add('active');
        }
        
        // Close modals when clicking outside
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
        """

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 report_generator.py <scan_dir> <domain> <target>")
        sys.exit(1)
    
    scan_dir = sys.argv[1]
    domain = sys.argv[2]
    target = sys.argv[3]
    
    # Validate scan directory exists
    if not os.path.exists(scan_dir):
        print(f"Error: Scan directory '{scan_dir}' does not exist")
        sys.exit(1)
    
    # Generate report
    generator = ReconXReportGenerator(scan_dir, domain, target)
    report_file = generator.generate_html_report()
    
    if report_file:
        print(f"Report generated successfully: {report_file}")
        sys.exit(0)
    else:
        print("Failed to generate report")
        sys.exit(1)

if __name__ == "__main__":
    main()
