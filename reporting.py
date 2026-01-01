"""
Advanced Reporting Module
Generate professional reports in multiple formats
"""

import json
import csv
from datetime import datetime
from typing import List, Dict
import logging


class ReportGenerator:
    """Generate scan reports in various formats"""
    
    @staticmethod
    def generate_txt(results: List[Dict], scan_info: Dict, filename: str) -> bool:
        """Generate text report"""
        try:
            with open(filename, 'w') as f:
                # Header
                f.write("="*80 + "\n")
                f.write("NETWORK ANALYZER - SCAN REPORT\n")
                f.write("="*80 + "\n\n")
                
                # Scan Information
                f.write("SCAN INFORMATION\n")
                f.write("-"*80 + "\n")
                for key, value in scan_info.items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
                
                # Results
                open_ports = [r for r in results if r['status'] == 'open']
                filtered_ports = [r for r in results if 'filtered' in r['status']]
                closed_ports = [r for r in results if r['status'] == 'closed']
                
                if open_ports:
                    f.write("OPEN PORTS\n")
                    f.write("-"*80 + "\n")
                    f.write(f"{'Port':<10} {'State':<15} {'Service':<20} {'Version'}\n")
                    f.write("-"*80 + "\n")
                    
                    for result in open_ports:
                        port = result['port']
                        status = result['status']
                        service = result.get('service', 'unknown')
                        version = result.get('version', '')
                        f.write(f"{port:<10} {status:<15} {service:<20} {version}\n")
                    f.write("\n")
                
                if filtered_ports:
                    f.write("FILTERED PORTS\n")
                    f.write("-"*80 + "\n")
                    for result in filtered_ports:
                        f.write(f"Port {result['port']}: {result['status']}\n")
                    f.write("\n")
                
                # Summary
                f.write("="*80 + "\n")
                f.write("SUMMARY\n")
                f.write("="*80 + "\n")
                f.write(f"Total Ports Scanned: {len(results)}\n")
                f.write(f"Open: {len(open_ports)}\n")
                f.write(f"Filtered: {len(filtered_ports)}\n")
                f.write(f"Closed: {len(closed_ports)}\n")
                f.write("="*80 + "\n")
            
            return True
        except Exception as e:
            logging.error(f"Failed to generate TXT report: {e}")
            return False
    
    @staticmethod
    def generate_json(results: List[Dict], scan_info: Dict, filename: str) -> bool:
        """Generate JSON report"""
        try:
            report = {
                'scan_info': scan_info,
                'results': results,
                'summary': {
                    'total_ports': len(results),
                    'open': len([r for r in results if r['status'] == 'open']),
                    'closed': len([r for r in results if r['status'] == 'closed']),
                    'filtered': len([r for r in results if 'filtered' in r['status']])
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            return True
        except Exception as e:
            logging.error(f"Failed to generate JSON report: {e}")
            return False
    
    @staticmethod
    def generate_csv(results: List[Dict], scan_info: Dict, filename: str) -> bool:
        """Generate CSV report"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow(['Port', 'Status', 'Service', 'Version', 'Banner'])
                
                # Results
                for result in results:
                    writer.writerow([
                        result['port'],
                        result['status'],
                        result.get('service', ''),
                        result.get('version', ''),
                        result.get('banner', '')[:100]  # Truncate banner
                    ])
            
            return True
        except Exception as e:
            logging.error(f"Failed to generate CSV report: {e}")
            return False
    
    @staticmethod
    def generate_html(results: List[Dict], scan_info: Dict, filename: str) -> bool:
        """Generate HTML report"""
        try:
            open_ports = [r for r in results if r['status'] == 'open']
            filtered_ports = [r for r in results if 'filtered' in r['status']]
            closed_ports = [r for r in results if r['status'] == 'closed']
            
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Report - {scan_info.get('Target', 'Unknown')}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .open {{ color: #27ae60; font-weight: bold; }}
        .closed {{ color: #e74c3c; }}
        .filtered {{ color: #f39c12; }}
        .info-box {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }}
        .summary-item {{
            text-align: center;
            padding: 20px;
            background-color: #ecf0f1;
            border-radius: 5px;
            flex: 1;
            margin: 0 10px;
        }}
        .summary-item h3 {{
            margin: 0;
            font-size: 32px;
        }}
        .summary-item p {{
            margin: 5px 0 0 0;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Port Scan Report</h1>
        
        <div class="info-box">
            <h2>Scan Information</h2>
"""
            
            for key, value in scan_info.items():
                html += f"            <p><strong>{key}:</strong> {value}</p>\n"
            
            html += """        </div>
        
        <div class="summary">
            <div class="summary-item">
                <h3 class="open">{}</h3>
                <p>Open Ports</p>
            </div>
            <div class="summary-item">
                <h3 class="filtered">{}</h3>
                <p>Filtered</p>
            </div>
            <div class="summary-item">
                <h3 class="closed">{}</h3>
                <p>Closed</p>
            </div>
            <div class="summary-item">
                <h3>{}</h3>
                <p>Total Scanned</p>
            </div>
        </div>
""".format(len(open_ports), len(filtered_ports), len(closed_ports), len(results))
            
            if open_ports:
                html += """
        <h2>Open Ports</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
                <th>Version</th>
                <th>Banner</th>
            </tr>
"""
                for result in open_ports:
                    html += f"""            <tr>
                <td><strong>{result['port']}</strong></td>
                <td class="open">{result['status']}</td>
                <td>{result.get('service', 'unknown')}</td>
                <td>{result.get('version', '')}</td>
                <td>{result.get('banner', '')[:100]}</td>
            </tr>
"""
                html += "        </table>\n"
            
            if filtered_ports:
                html += """
        <h2>Filtered Ports</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
            </tr>
"""
                for result in filtered_ports:
                    html += f"""            <tr>
                <td>{result['port']}</td>
                <td class="filtered">{result['status']}</td>
                <td>{result.get('service', 'unknown')}</td>
            </tr>
"""
                html += "        </table>\n"
            
            html += """
        <div class="info-box" style="margin-top: 40px; text-align: center; color: #7f8c8d;">
            <p>Generated by Network Analyzer v1.0 | github.com/minuka05</p>
            <p>For educational and authorized testing only</p>
        </div>
    </div>
</body>
</html>
"""
            
            with open(filename, 'w') as f:
                f.write(html)
            
            return True
        except Exception as e:
            logging.error(f"Failed to generate HTML report: {e}")
            return False


def export_scan_results(results: List[Dict], scan_info: Dict, format: str, filename: str) -> bool:
    """
    Export scan results in specified format
    
    Args:
        results: Scan results list
        scan_info: Scan metadata
        format: Output format ('txt', 'json', 'csv', 'html')
        filename: Output filename
        
    Returns:
        Success status
    """
    format_lower = format.lower()
    
    if format_lower == 'txt':
        return ReportGenerator.generate_txt(results, scan_info, filename)
    elif format_lower == 'json':
        return ReportGenerator.generate_json(results, scan_info, filename)
    elif format_lower == 'csv':
        return ReportGenerator.generate_csv(results, scan_info, filename)
    elif format_lower == 'html':
        return ReportGenerator.generate_html(results, scan_info, filename)
    else:
        logging.error(f"Unknown format: {format}")
        return False
