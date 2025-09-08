from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import ipaddress
import hashlib
import requests
import time
from urllib.parse import urlparse
import os
from typing import Dict, List, Any, Optional

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# API Configuration - Set these as environment variables
API_KEYS = {
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY', 'c2a46af380ec8e4900d701e3553f0d36c0689fd93642d22f519966716379cf08'),
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', 'be21307947901961f6b756e90b39937095b635043da7282b3710e09a859f0569bf74e6341137083c'),
    'otx': os.getenv('OTX_API_KEY', '9388e180c71b17aac2a3390e8847b7689cce6ed12378e7ce8ecce4c86e89522a')
}

class IOCClassifier:
    """Classify different types of IOCs using regex patterns"""
    
    @staticmethod
    def is_ipv4(value: str) -> bool:
        """Check if string is a valid IPv4 address"""
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def is_ipv6(value: str) -> bool:
        """Check if string is a valid IPv6 address"""
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def is_ip_address(value: str) -> bool:
        """Check if string is any valid IP address"""
        return IOCClassifier.is_ipv4(value) or IOCClassifier.is_ipv6(value)
    
    @staticmethod
    def is_cidr(value: str) -> bool:
        """Check if string is a valid CIDR block"""
        try:
            ipaddress.ip_network(value, strict=False)
            return '/' in value
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def is_hash(value: str) -> str:
        """Check if string is a hash and return the type"""
        value = value.lower().strip()
        if re.match(r'^[a-f0-9]{32}$', value):
            return 'md5'
        elif re.match(r'^[a-f0-9]{40}$', value):
            return 'sha1'
        elif re.match(r'^[a-f0-9]{64}$', value):
            return 'sha256'
        return None
    
    @staticmethod
    def is_url(value: str) -> bool:
        """Check if string is a valid URL"""
        try:
            result = urlparse(value)
            return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
        except:
            return False
    
    @staticmethod
    def is_domain(value: str) -> bool:
        """Check if string is a valid domain name"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(value)) and '.' in value
    
    @staticmethod
    def classify_ioc(value: str) -> str:
        """Classify an IOC and return its type"""
        value = value.strip()
        
        if IOCClassifier.is_ip_address(value):
            return 'ip'
        elif IOCClassifier.is_cidr(value):
            return 'cidr'
        elif IOCClassifier.is_url(value):
            return 'url'
        elif IOCClassifier.is_hash(value):
            return 'hash'
        elif IOCClassifier.is_domain(value):
            return 'domain'
        else:
            return 'unknown'

class EnhancedThreatIntelligenceAPI:
    """Enhanced API handler with relational endpoint support"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ThreatIntel-Analyzer/2.0'})
    
    def _make_vt_request(self, endpoint: str, params: Dict = None) -> Dict[str, Any]:
        """Helper method to make VirusTotal API requests with error handling"""
        try:
            url = f"https://www.virustotal.com/api/v3/{endpoint}"
            headers = {'x-apikey': API_KEYS['virustotal']}
            
            response = self.session.get(url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'error': 'Resource not found'}
            else:
                return {'error': f'API returned status {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def query_virustotal_ip_enhanced(self, ip: str, include_relations: bool = True) -> Dict[str, Any]:
        """Enhanced IP analysis with relational data"""
        result = {
            'main_report': {},
            'associated_domains': [],
            'communicating_files': [],
            'downloaded_files': []
        }
        
        # Main IP report
        data = self._make_vt_request(f"ip_addresses/{ip}")
        if 'error' not in data:
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            result['main_report'] = {
                'source': 'VirusTotal',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'clean': stats.get('harmless', 0),
                'total_scans': sum(stats.values()) if stats else 0,
                'reputation': attrs.get('reputation', 0),
                'country': attrs.get('country', 'Unknown'),
                'as_owner': attrs.get('as_owner', 'Unknown'),
                'network': attrs.get('network', 'Unknown')
            }
        else:
            result['main_report'] = {'source': 'VirusTotal', 'error': data['error']}
        
        if not include_relations:
            return result
        
        # Associated domains (resolutions)
        domains_data = self._make_vt_request(f"ip_addresses/{ip}/resolutions", {'limit': 20})
        if 'error' not in domains_data:
            for item in domains_data.get('data', []):
                attrs = item.get('attributes', {})
                result['associated_domains'].append({
                    'domain': attrs.get('host_name', ''),
                    'last_resolved': attrs.get('date', ''),
                    'resolver': attrs.get('resolver', 'Unknown')
                })
        
        # Communicating files (malware traffic)
        files_data = self._make_vt_request(f"ip_addresses/{ip}/communicating_files", {'limit': 15})
        if 'error' not in files_data:
            for item in files_data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                result['communicating_files'].append({
                    'sha256': attrs.get('sha256', '')[:16] + '...',  # Truncate for display
                    'full_hash': attrs.get('sha256', ''),
                    'detections': stats.get('malicious', 0),
                    'total_engines': sum(stats.values()) if stats else 0,
                    'file_type': attrs.get('type_description', 'Unknown'),
                    'size': attrs.get('size', 0)
                })
        
        # Downloaded files
        download_data = self._make_vt_request(f"ip_addresses/{ip}/downloaded_files", {'limit': 10})
        if 'error' not in download_data:
            for item in download_data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                result['downloaded_files'].append({
                    'sha256': attrs.get('sha256', '')[:16] + '...',
                    'full_hash': attrs.get('sha256', ''),
                    'detections': stats.get('malicious', 0),
                    'total_engines': sum(stats.values()) if stats else 0,
                    'file_type': attrs.get('type_description', 'Unknown')
                })
        
        return result
    
    def query_virustotal_domain_enhanced(self, domain: str, include_relations: bool = True) -> Dict[str, Any]:
        """Enhanced domain analysis with relational data"""
        result = {
            'main_report': {},
            'associated_ips': [],
            'subdomains': [],
            'communicating_files': [],
            'urls': []
        }
        
        # Main domain report
        data = self._make_vt_request(f"domains/{domain}")
        if 'error' not in data:
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            result['main_report'] = {
                'source': 'VirusTotal',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'clean': stats.get('harmless', 0),
                'total_scans': sum(stats.values()) if stats else 0,
                'reputation': attrs.get('reputation', 0),
                'registrar': attrs.get('registrar', 'Unknown'),
                'creation_date': attrs.get('creation_date', 'Unknown'),
                'whois_date': attrs.get('whois_date', 'Unknown')
            }
        else:
            result['main_report'] = {'source': 'VirusTotal', 'error': data['error']}
        
        if not include_relations:
            return result
        
        # Associated IPs (resolutions)
        ips_data = self._make_vt_request(f"domains/{domain}/resolutions", {'limit': 20})
        if 'error' not in ips_data:
            for item in ips_data.get('data', []):
                attrs = item.get('attributes', {})
                result['associated_ips'].append({
                    'ip': attrs.get('ip_address', ''),
                    'last_resolved': attrs.get('date', ''),
                    'resolver': attrs.get('resolver', 'Unknown')
                })
        
        # Subdomains
        subdomains_data = self._make_vt_request(f"domains/{domain}/subdomains", {'limit': 15})
        if 'error' not in subdomains_data:
            for item in subdomains_data.get('data', []):
                result['subdomains'].append({
                    'subdomain': item.get('id', ''),
                    'last_seen': item.get('attributes', {}).get('last_modification_date', 'Unknown')
                })
        
        # Communicating files
        files_data = self._make_vt_request(f"domains/{domain}/communicating_files", {'limit': 15})
        if 'error' not in files_data:
            for item in files_data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                result['communicating_files'].append({
                    'sha256': attrs.get('sha256', '')[:16] + '...',
                    'full_hash': attrs.get('sha256', ''),
                    'detections': stats.get('malicious', 0),
                    'total_engines': sum(stats.values()) if stats else 0,
                    'file_type': attrs.get('type_description', 'Unknown')
                })
        
        # Associated URLs
        urls_data = self._make_vt_request(f"domains/{domain}/urls", {'limit': 10})
        if 'error' not in urls_data:
            for item in urls_data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                result['urls'].append({
                    'url': attrs.get('url', '')[:50] + '...' if len(attrs.get('url', '')) > 50 else attrs.get('url', ''),
                    'full_url': attrs.get('url', ''),
                    'detections': stats.get('malicious', 0),
                    'total_engines': sum(stats.values()) if stats else 0
                })
        
        return result
    
    def query_virustotal_hash_enhanced(self, file_hash: str, include_relations: bool = True) -> Dict[str, Any]:
        """Enhanced hash analysis with network behavior"""
        result = {
            'main_report': {},
            'contacted_ips': [],
            'contacted_domains': [],
            'contacted_urls': []
        }
        
        # Main file report
        data = self._make_vt_request(f"files/{file_hash}")
        if 'error' not in data:
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            result['main_report'] = {
                'source': 'VirusTotal',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'clean': stats.get('harmless', 0),
                'total_scans': sum(stats.values()) if stats else 0,
                'file_type': attrs.get('type_description', 'Unknown'),
                'file_size': attrs.get('size', 0),
                'md5': attrs.get('md5', ''),
                'sha1': attrs.get('sha1', ''),
                'sha256': attrs.get('sha256', ''),
                'first_submission': attrs.get('first_submission_date', 'Unknown')
            }
        else:
            result['main_report'] = {'source': 'VirusTotal', 'error': data['error']}
        
        if not include_relations:
            return result
        
        # Contacted IPs
        ips_data = self._make_vt_request(f"files/{file_hash}/contacted_ips", {'limit': 20})
        if 'error' not in ips_data:
            for item in ips_data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                result['contacted_ips'].append({
                    'ip': item.get('id', ''),
                    'country': attrs.get('country', 'Unknown'),
                    'as_owner': attrs.get('as_owner', 'Unknown'),
                    'detections': stats.get('malicious', 0),
                    'reputation': attrs.get('reputation', 0)
                })
        
        # Contacted domains
        domains_data = self._make_vt_request(f"files/{file_hash}/contacted_domains", {'limit': 20})
        if 'error' not in domains_data:
            for item in domains_data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                result['contacted_domains'].append({
                    'domain': item.get('id', ''),
                    'detections': stats.get('malicious', 0),
                    'reputation': attrs.get('reputation', 0),
                    'registrar': attrs.get('registrar', 'Unknown')
                })
        
        # Contacted URLs
        urls_data = self._make_vt_request(f"files/{file_hash}/contacted_urls", {'limit': 15})
        if 'error' not in urls_data:
            for item in urls_data.get('data', []):
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                result['contacted_urls'].append({
                    'url': attrs.get('url', '')[:60] + '...' if len(attrs.get('url', '')) > 60 else attrs.get('url', ''),
                    'full_url': attrs.get('url', ''),
                    'detections': stats.get('malicious', 0),
                    'total_engines': sum(stats.values()) if stats else 0
                })
        
        return result
    
    def query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation"""
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': API_KEYS['abuseipdb'],
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'source': 'AbuseIPDB',
                    'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                    'is_public': data.get('isPublic', False),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', 'Never')
                }
        except Exception as e:
            return {'source': 'AbuseIPDB', 'error': str(e)}
        
        return {'source': 'AbuseIPDB', 'error': 'No data available'}

class EnhancedIOCAnalyzer:
    """Enhanced analyzer with relational intelligence"""
    
    def __init__(self):
        self.api = EnhancedThreatIntelligenceAPI()
    
    def analyze_ip(self, ip: str, include_relations: bool = True) -> Dict[str, Any]:
        """Enhanced IP analysis with relational data"""
        results = {
            'ioc': ip,
            'type': 'ip',
            'main_analysis': {},
            'relational_data': {},
            'additional_sources': []
        }
        
        # VirusTotal enhanced analysis
        vt_result = self.api.query_virustotal_ip_enhanced(ip, include_relations)
        results['main_analysis'] = vt_result['main_report']
        
        if include_relations:
            results['relational_data'] = {
                'associated_domains': vt_result['associated_domains'],
                'communicating_files': vt_result['communicating_files'],
                'downloaded_files': vt_result['downloaded_files']
            }
        
        # AbuseIPDB analysis
        abuse_result = self.api.query_abuseipdb(ip)
        results['additional_sources'].append(abuse_result)
        
        # Add rate limiting
        time.sleep(0.5)
        
        return results
    
    def analyze_domain(self, domain: str, include_relations: bool = True) -> Dict[str, Any]:
        """Enhanced domain analysis with relational data"""
        results = {
            'ioc': domain,
            'type': 'domain',
            'main_analysis': {},
            'relational_data': {}
        }
        
        # VirusTotal enhanced analysis
        vt_result = self.api.query_virustotal_domain_enhanced(domain, include_relations)
        results['main_analysis'] = vt_result['main_report']
        
        if include_relations:
            results['relational_data'] = {
                'associated_ips': vt_result['associated_ips'],
                'subdomains': vt_result['subdomains'],
                'communicating_files': vt_result['communicating_files'],
                'associated_urls': vt_result['urls']
            }
        
        time.sleep(0.5)
        return results
    
    def analyze_hash(self, file_hash: str, include_relations: bool = True) -> Dict[str, Any]:
        """Enhanced hash analysis with network behavior"""
        hash_type = IOCClassifier.is_hash(file_hash)
        results = {
            'ioc': file_hash,
            'type': 'hash',
            'hash_type': hash_type,
            'main_analysis': {},
            'relational_data': {}
        }
        
        # VirusTotal enhanced analysis
        vt_result = self.api.query_virustotal_hash_enhanced(file_hash, include_relations)
        results['main_analysis'] = vt_result['main_report']
        
        if include_relations:
            results['relational_data'] = {
                'contacted_ips': vt_result['contacted_ips'],
                'contacted_domains': vt_result['contacted_domains'],
                'contacted_urls': vt_result['contacted_urls']
            }
        
        time.sleep(0.5)
        return results
    
    def analyze_ioc(self, ioc: str, include_relations: bool = True) -> Dict[str, Any]:
        """Analyze any IOC with enhanced relational data"""
        ioc = ioc.strip()
        if not ioc:
            return {'error': 'Empty IOC provided'}
        
        ioc_type = IOCClassifier.classify_ioc(ioc)
        
        if ioc_type == 'ip':
            return self.analyze_ip(ioc, include_relations)
        elif ioc_type == 'domain':
            return self.analyze_domain(ioc, include_relations)
        elif ioc_type == 'hash':
            return self.analyze_hash(ioc, include_relations)
        elif ioc_type == 'url':
            # For URLs, extract domain and analyze that
            try:
                parsed = urlparse(ioc)
                domain = parsed.netloc
                result = self.analyze_domain(domain, include_relations)
                result['ioc'] = ioc  # Keep original URL
                result['type'] = 'url'
                result['extracted_domain'] = domain
                return result
            except:
                return {'ioc': ioc, 'type': 'url', 'error': 'Could not parse URL'}
        else:
            return {
                'ioc': ioc,
                'type': 'unknown',
                'error': f'Unable to classify IOC: {ioc}'
            }

# Initialize the enhanced analyzer
analyzer = EnhancedIOCAnalyzer()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'Enhanced Threat Intelligence API is running'})

@app.route('/analyze', methods=['POST'])
def analyze_iocs():
    """Enhanced endpoint to analyze IOCs with relational data"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Check if relational analysis is requested (default: True)
        include_relations = data.get('include_relations', True)
        
        # Collect all IOCs
        iocs_to_analyze = []
        
        if data.get('ip_address'):
            iocs_to_analyze.append(data['ip_address'].strip())
        
        if data.get('domain_name'):
            iocs_to_analyze.append(data['domain_name'].strip())
        
        if data.get('file_hash'):
            iocs_to_analyze.append(data['file_hash'].strip())
        
        if data.get('url'):
            iocs_to_analyze.append(data['url'].strip())
        
        if data.get('bulk_ioc'):
            bulk_iocs = [ioc.strip() for ioc in data['bulk_ioc'].split('\n') if ioc.strip()]
            iocs_to_analyze.extend(bulk_iocs)
        
        if not iocs_to_analyze:
            return jsonify({'error': 'No IOCs provided for analysis'}), 400
        
        # Remove duplicates while preserving order
        unique_iocs = list(dict.fromkeys(iocs_to_analyze))
        
        # Analyze each IOC
        results = []
        for ioc in unique_iocs:
            try:
                result = analyzer.analyze_ioc(ioc, include_relations)
                results.append(result)
            except Exception as e:
                results.append({
                    'ioc': ioc,
                    'type': 'error',
                    'error': f'Analysis failed: {str(e)}'
                })
        
        return jsonify({
            'success': True,
            'total_analyzed': len(results),
            'enhanced_analysis': True,
            'includes_relations': include_relations,
            'results': results
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/analyze/<ioc_type>/<path:ioc_value>', methods=['GET'])
def analyze_single_ioc(ioc_type: str, ioc_value: str):
    """Quick analysis endpoint for individual IOCs (for interactive features)"""
    try:
        include_relations = request.args.get('relations', 'true').lower() == 'true'
        
        result = analyzer.analyze_ioc(ioc_value, include_relations)
        
        return jsonify({
            'success': True,
            'result': result
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Analysis failed: {str(e)}'
        }), 500

@app.route('/classify', methods=['POST'])
def classify_ioc():
    """Endpoint to classify IOC type without analysis"""
    try:
        data = request.get_json()
        
        if not data or 'ioc' not in data:
            return jsonify({'error': 'No IOC provided'}), 400
        
        ioc = data['ioc'].strip()
        ioc_type = IOCClassifier.classify_ioc(ioc)
        
        result = {
            'ioc': ioc,
            'type': ioc_type,
            'is_ip': IOCClassifier.is_ip_address(ioc),
            'is_domain': IOCClassifier.is_domain(ioc),
            'is_url': IOCClassifier.is_url(ioc),
            'is_cidr': IOCClassifier.is_cidr(ioc)
        }
        
        if ioc_type == 'hash':
            result['hash_type'] = IOCClassifier.is_hash(ioc)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': f'Classification failed: {str(e)}'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Check if API keys are configured
    missing_keys = [key for key, value in API_KEYS.items() if value.startswith('your_')]
    if missing_keys:
        print("⚠️  Warning: The following API keys are not configured:")
        for key in missing_keys:
            print(f"   - {key.upper()}_API_KEY")
        print("Set them as environment variables for full functionality.")
        print()
    
    print("🔍 Enhanced Threat Intelligence IOC Analyzer Starting...")
    print("🚀 New Features:")
    print("   - Relational IOC Analysis")
    print("   - Associated Domains/IPs Discovery")
    print("   - Malware Communication Patterns")
    print("   - Network Behavior Analysis")
    print()
    print("📡 Available endpoints:")
    print("   - POST /analyze - Enhanced IOC analysis with relations")
    print("   - GET /analyze/<type>/<ioc> - Quick single IOC analysis")
    print("   - POST /classify - Classify IOC type")
    print("   - GET /health - Health check")
    print()
    
    app.run(debug=True, host='0.0.0.0', port=5000)