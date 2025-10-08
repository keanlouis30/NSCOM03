"""
Report Generator Module
Generates comprehensive reports in JSON, CSV, and PDF formats
for deep IOC analysis results.
"""

import json
import csv
from datetime import datetime
from typing import Dict, List, Any
from io import StringIO, BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER

class DeepAnalysisReportGenerator:
    """Generate comprehensive reports from deep analysis data"""
    
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_json_report(self, analysis_results: List[Dict[str, Any]]) -> str:
        """Generate JSON report"""
        report = {
            'metadata': {
                'report_type': 'Deep IOC Analysis',
                'generated_at': datetime.utcnow().isoformat(),
                'total_iocs': len(analysis_results),
                'version': '2.0'
            },
            'analysis_results': analysis_results
        }
        return json.dumps(report, indent=2, default=str)
    
    def generate_csv_report(self, analysis_results: List[Dict[str, Any]]) -> str:
        """Generate comprehensive CSV report"""
        output = StringIO()
        
        if not analysis_results:
            return "No data to export"
        
        # Define CSV headers for deep analysis
        headers = [
            'IOC', 'Type', 'Timestamp',
            # Geolocation
            'Country', 'City', 'Region', 'Coordinates', 'Timezone', 'ISP',
            # Network
            'ASN', 'ASN Description', 'Network CIDR', 'Subnet',
            # DNS
            'PTR Records', 'Nameservers', 'MX Records',
            # WHOIS
            'Registrar', 'Creation Date', 'Expiration Date',
            # Security
            'Open Ports', 'SSL Certificate Subject', 'SSL Issuer',
            # Reputation
            'Fraud Score', 'Is Proxy', 'Is VPN', 'Is TOR',
            # Network Neighbors & Topology
            'Neighboring IPs', 'Subdomains',
            # VirusTotal Relations - ASSOCIATED DOMAINS & TRAFFIC
            'Associated Domains (VT)', 'Associated IPs (VT)', 
            'Communicating Files (VT)', 'Downloaded Files (VT)',
            'Contacted IPs (Hash)', 'Contacted Domains (Hash)', 'Contacted URLs (Hash)',
            'VT Malicious Count', 'VT Suspicious Count', 'VT Clean Count',
            # Additional
            'Web Technology', 'Domain Age (days)'
        ]
        
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        
        for result in analysis_results:
            row = self._flatten_result_for_csv(result)
            writer.writerow(row)
        
        return output.getvalue()
    
    def _flatten_result_for_csv(self, result: Dict[str, Any]) -> Dict[str, str]:
        """Flatten nested analysis result for CSV format"""
        flat = {
            'IOC': result.get('ioc', ''),
            'Type': result.get('type', ''),
            'Timestamp': result.get('timestamp', ''),
        }
        
        # Extract deep analysis data
        deep_data = result.get('deep_analysis', {})
        
        # Geolocation
        geo = deep_data.get('geolocation', {})
        flat['Country'] = geo.get('country', '')
        flat['City'] = geo.get('city', '')
        flat['Region'] = geo.get('region', '')
        flat['Coordinates'] = geo.get('coordinates', '')
        flat['Timezone'] = geo.get('timezone', '')
        flat['ISP'] = geo.get('isp', '')
        
        # ASN
        asn = deep_data.get('asn_info', {})
        flat['ASN'] = asn.get('asn', '')
        flat['ASN Description'] = asn.get('asn_description', '')
        flat['Network CIDR'] = asn.get('network', {}).get('cidr', '')
        
        # Subnet
        subnet = deep_data.get('subnet_analysis', {})
        flat['Subnet'] = subnet.get('cidr', '')
        
        # DNS
        dns = deep_data.get('dns_records', {})
        if isinstance(dns, dict):
            flat['PTR Records'] = '; '.join(dns.get('ptr_records', []))
        
        ns = deep_data.get('nameservers', [])
        flat['Nameservers'] = '; '.join(ns) if isinstance(ns, list) else ''
        
        mx = deep_data.get('mx_records', [])
        if isinstance(mx, list):
            flat['MX Records'] = '; '.join([f"{r.get('exchange', '')} ({r.get('priority', '')})" for r in mx])
        
        # WHOIS
        whois = deep_data.get('whois_data', {})
        flat['Registrar'] = whois.get('registrar', '')
        flat['Creation Date'] = str(whois.get('creation_date', ''))
        flat['Expiration Date'] = str(whois.get('expiration_date', ''))
        
        # Security
        ports = deep_data.get('open_ports', {})
        if isinstance(ports, dict):
            open_list = ports.get('open_ports', [])
            flat['Open Ports'] = '; '.join([f"{p.get('port', '')}({p.get('service', '')})" for p in open_list])
        
        ssl = deep_data.get('ssl_certificates', {})
        if isinstance(ssl, dict) and ssl.get('status') == 'success':
            flat['SSL Certificate Subject'] = str(ssl.get('subject', {}).get('commonName', ''))
            flat['SSL Issuer'] = str(ssl.get('issuer', {}).get('organizationName', ''))
        
        # Reputation
        rep = deep_data.get('reputation', {})
        flat['Fraud Score'] = str(rep.get('fraud_score', ''))
        flat['Is Proxy'] = str(rep.get('is_proxy', ''))
        flat['Is VPN'] = str(rep.get('is_vpn', ''))
        flat['Is TOR'] = str(rep.get('is_tor', ''))
        
        # Network Neighbors
        neighbors = deep_data.get('network_neighbors', {})
        if isinstance(neighbors, dict):
            neighbor_list = neighbors.get('sampled_neighbors', [])
            flat['Neighboring IPs'] = '; '.join([n.get('ip', '') for n in neighbor_list])
        
        # Subdomains
        subs = deep_data.get('subdomains', {})
        if isinstance(subs, dict):
            sub_list = subs.get('subdomains', [])
            flat['Subdomains'] = '; '.join(sub_list[:20]) if isinstance(sub_list, list) else ''
        
        # Web Technology
        tech = deep_data.get('web_technology', {})
        if isinstance(tech, dict):
            tech_list = tech.get('technologies', [])
            flat['Web Technology'] = '; '.join([t.get('name', '') for t in tech_list])
        
        # Domain Age
        age = deep_data.get('domain_age', {})
        flat['Domain Age (days)'] = str(age.get('age_days', ''))
        
        # ========== VIRUSTOTAL RELATIONAL DATA (ASSOCIATED DOMAINS & TRAFFIC) ==========
        standard_analysis = result.get('standard_analysis', {})
        relational_data = standard_analysis.get('relational_data', {})
        main_analysis = standard_analysis.get('main_analysis', {})
        
        # Associated Domains (for IPs) - Shows what domains point to this IP
        associated_domains = relational_data.get('associated_domains', [])
        if isinstance(associated_domains, list) and associated_domains:
            domain_list = [d.get('domain', '') for d in associated_domains if isinstance(d, dict)]
            flat['Associated Domains (VT)'] = '; '.join(domain_list[:50])  # Limit to 50
        else:
            flat['Associated Domains (VT)'] = ''
        
        # Associated IPs (for Domains) - Shows what IPs this domain resolves to
        associated_ips = relational_data.get('associated_ips', [])
        if isinstance(associated_ips, list) and associated_ips:
            ip_list = [d.get('ip', '') for d in associated_ips if isinstance(d, dict)]
            flat['Associated IPs (VT)'] = '; '.join(ip_list[:50])
        else:
            flat['Associated IPs (VT)'] = ''
        
        # Communicating Files - Network traffic/malware that communicated with this IP/domain
        comm_files = relational_data.get('communicating_files', [])
        if isinstance(comm_files, list) and comm_files:
            file_list = [f"{f.get('sha256', '')[:16]} ({f.get('detections', 0)}/{f.get('total_engines', 0)})" 
                        for f in comm_files if isinstance(f, dict)]
            flat['Communicating Files (VT)'] = '; '.join(file_list[:20])
        else:
            flat['Communicating Files (VT)'] = ''
        
        # Downloaded Files - Files downloaded from this IP
        down_files = relational_data.get('downloaded_files', [])
        if isinstance(down_files, list) and down_files:
            file_list = [f"{f.get('sha256', '')[:16]} ({f.get('detections', 0)}/{f.get('total_engines', 0)})" 
                        for f in down_files if isinstance(f, dict)]
            flat['Downloaded Files (VT)'] = '; '.join(file_list[:20])
        else:
            flat['Downloaded Files (VT)'] = ''
        
        # For file hashes - contacted IPs/Domains/URLs (network behavior)
        contacted_ips = relational_data.get('contacted_ips', [])
        if isinstance(contacted_ips, list) and contacted_ips:
            ip_list = [c.get('ip', '') for c in contacted_ips if isinstance(c, dict)]
            flat['Contacted IPs (Hash)'] = '; '.join(ip_list[:50])
        else:
            flat['Contacted IPs (Hash)'] = ''
        
        contacted_domains = relational_data.get('contacted_domains', [])
        if isinstance(contacted_domains, list) and contacted_domains:
            domain_list = [c.get('domain', '') for c in contacted_domains if isinstance(c, dict)]
            flat['Contacted Domains (Hash)'] = '; '.join(domain_list[:50])
        else:
            flat['Contacted Domains (Hash)'] = ''
        
        contacted_urls = relational_data.get('contacted_urls', [])
        if isinstance(contacted_urls, list) and contacted_urls:
            url_list = [c.get('url', '')[:100] for c in contacted_urls if isinstance(c, dict)]
            flat['Contacted URLs (Hash)'] = '; '.join(url_list[:20])
        else:
            flat['Contacted URLs (Hash)'] = ''
        
        # VirusTotal detection counts
        flat['VT Malicious Count'] = str(main_analysis.get('malicious', ''))
        flat['VT Suspicious Count'] = str(main_analysis.get('suspicious', ''))
        flat['VT Clean Count'] = str(main_analysis.get('clean', ''))
        
        return flat
    
    def generate_pdf_report(self, analysis_results: List[Dict[str, Any]]) -> bytes:
        """Generate comprehensive PDF report"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=18)
        
        # Container for PDF elements
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        title = Paragraph("Deep IOC Analysis Report", title_style)
        story.append(title)
        
        # Metadata
        meta_data = [
            ['Report Type:', 'Deep Network Intelligence Analysis'],
            ['Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Total IOCs Analyzed:', str(len(analysis_results))],
            ['Report Version:', '2.0']
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Add analysis results for each IOC
        for idx, result in enumerate(analysis_results, 1):
            if idx > 1:
                story.append(PageBreak())
            
            story.extend(self._create_ioc_section(result, idx, styles, heading_style))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _create_ioc_section(self, result: Dict[str, Any], index: int, 
                           styles, heading_style) -> List:
        """Create PDF section for a single IOC"""
        elements = []
        
        # IOC Header
        ioc_title = Paragraph(f"IOC #{index}: {result.get('ioc', 'Unknown')}", heading_style)
        elements.append(ioc_title)
        elements.append(Spacer(1, 0.1*inch))
        
        # Basic Info
        basic_info = [
            ['Type:', result.get('type', 'Unknown')],
            ['Analyzed:', result.get('timestamp', 'Unknown')]
        ]
        
        basic_table = Table(basic_info, colWidths=[1.5*inch, 4.5*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f4f8')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6)
        ]))
        elements.append(basic_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Deep Analysis Data
        deep_data = result.get('deep_analysis', {})
        
        if deep_data:
            # Geolocation Section
            geo = deep_data.get('geolocation', {})
            if geo.get('status') == 'success':
                elements.append(Paragraph("<b>Geolocation & Network</b>", styles['Heading3']))
                geo_data = [
                    ['Country:', geo.get('country', 'Unknown')],
                    ['City:', geo.get('city', 'Unknown')],
                    ['Coordinates:', geo.get('coordinates', 'Unknown')],
                    ['ISP:', geo.get('isp', 'Unknown')],
                    ['Timezone:', geo.get('timezone', 'Unknown')]
                ]
                geo_table = Table(geo_data, colWidths=[1.5*inch, 4.5*inch])
                geo_table.setStyle(self._get_standard_table_style())
                elements.append(geo_table)
                elements.append(Spacer(1, 0.15*inch))
            
            # ASN Information
            asn = deep_data.get('asn_info', {})
            if asn.get('status') == 'success':
                elements.append(Paragraph("<b>ASN Information</b>", styles['Heading3']))
                asn_data = [
                    ['ASN:', asn.get('asn', 'Unknown')],
                    ['Description:', asn.get('asn_description', 'Unknown')],
                    ['Country:', asn.get('asn_country', 'Unknown')],
                    ['Network CIDR:', asn.get('network', {}).get('cidr', 'Unknown')]
                ]
                asn_table = Table(asn_data, colWidths=[1.5*inch, 4.5*inch])
                asn_table.setStyle(self._get_standard_table_style())
                elements.append(asn_table)
                elements.append(Spacer(1, 0.15*inch))
            
            # WHOIS Information
            whois = deep_data.get('whois_data', {})
            if whois.get('status') == 'success':
                elements.append(Paragraph("<b>WHOIS Data</b>", styles['Heading3']))
                whois_data = [
                    ['Registrar:', str(whois.get('registrar', 'Unknown'))],
                    ['Created:', str(whois.get('creation_date', 'Unknown'))],
                    ['Expires:', str(whois.get('expiration_date', 'Unknown'))]
                ]
                whois_table = Table(whois_data, colWidths=[1.5*inch, 4.5*inch])
                whois_table.setStyle(self._get_standard_table_style())
                elements.append(whois_table)
                elements.append(Spacer(1, 0.15*inch))
            
            # Open Ports
            ports = deep_data.get('open_ports', {})
            if ports.get('status') == 'success' and ports.get('open_ports'):
                elements.append(Paragraph("<b>Open Ports</b>", styles['Heading3']))
                port_list = ports.get('open_ports', [])
                port_text = ', '.join([f"{p.get('port')} ({p.get('service')})" for p in port_list])
                elements.append(Paragraph(port_text, styles['Normal']))
                elements.append(Spacer(1, 0.15*inch))
            
            # Reputation
            rep = deep_data.get('reputation', {})
            if rep.get('status') == 'success':
                elements.append(Paragraph("<b>Security Reputation</b>", styles['Heading3']))
                rep_data = [
                    ['Fraud Score:', str(rep.get('fraud_score', 'N/A'))],
                    ['Proxy:', 'Yes' if rep.get('is_proxy') else 'No'],
                    ['VPN:', 'Yes' if rep.get('is_vpn') else 'No'],
                    ['TOR:', 'Yes' if rep.get('is_tor') else 'No']
                ]
                rep_table = Table(rep_data, colWidths=[1.5*inch, 4.5*inch])
                rep_table.setStyle(self._get_standard_table_style())
                elements.append(rep_table)
                elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _get_standard_table_style(self):
        """Get standard table style for PDF tables"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ])
    
    def get_filename(self, format_type: str) -> str:
        """Generate filename for report"""
        return f"deep_analysis_report_{self.timestamp}.{format_type}"

