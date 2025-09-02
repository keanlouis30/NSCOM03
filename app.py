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
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY', 'your_virustotal_api_key'),
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', 'your_abuseipdb_api_key'),
    'otx': os.getenv('OTX_API_KEY', 'your_otx_api_key')
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

class ThreatIntelligenceAPI:
    """Handle API calls to various threat intelligence services"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ThreatIntel-Analyzer/1.0'})
    
    def query_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Query VirusTotal IP endpoint"""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {'x-apikey': API_KEYS['virustotal']}
            
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'source': 'VirusTotal',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'clean': stats.get('harmless', 0),
                    'total_scans': sum(stats.values()) if stats else 0,
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                    'country': data.get('data', {}).get('attributes', {}).get('country', 'Unknown')
                }
        except Exception as e:
            return {'source': 'VirusTotal', 'error': str(e)}
        
        return {'source': 'VirusTotal', 'error': 'No data available'}
    
    def query_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal domain endpoint"""
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {'x-apikey': API_KEYS['virustotal']}
            
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'source': 'VirusTotal',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'clean': stats.get('harmless', 0),
                    'total_scans': sum(stats.values()) if stats else 0,
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                    'registrar': data.get('data', {}).get('attributes', {}).get('registrar', 'Unknown')
                }
        except Exception as e:
            return {'source': 'VirusTotal', 'error': str(e)}
        
        return {'source': 'VirusTotal', 'error': 'No data available'}
    
    def query_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Query VirusTotal URL endpoint"""
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {'x-apikey': API_KEYS['virustotal']}
            
            response = self.session.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'source': 'VirusTotal',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'clean': stats.get('harmless', 0),
                    'total_scans': sum(stats.values()) if stats else 0,
                    'final_url': data.get('data', {}).get('attributes', {}).get('last_final_url', url)
                }
        except Exception as e:
            return {'source': 'VirusTotal', 'error': str(e)}
        
        return {'source': 'VirusTotal', 'error': 'No data available'}
    
    def query_virustotal_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal file hash endpoint"""
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {'x-apikey': API_KEYS['virustotal']}
            
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'source': 'VirusTotal',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'clean': stats.get('harmless', 0),
                    'total_scans': sum(stats.values()) if stats else 0,
                    'file_type': data.get('data', {}).get('attributes', {}).get('type_description', 'Unknown'),
                    'file_size': data.get('data', {}).get('attributes', {}).get('size', 0)
                }
        except Exception as e:
            return {'source': 'VirusTotal', 'error': str(e)}
        
        return {'source': 'VirusTotal', 'error': 'No data available'}
    
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
    
    def query_abuseipdb_cidr(self, cidr: str) -> Dict[str, Any]:
        """Query AbuseIPDB for CIDR block"""
        try:
            url = 'https://api.abuseipdb.com/api/v2/check-block'
            headers = {
                'Key': API_KEYS['abuseipdb'],
                'Accept': 'application/json'
            }
            params = {
                'network': cidr,
                'maxAgeInDays': 90
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'source': 'AbuseIPDB',
                    'network_address': data.get('networkAddress', cidr),
                    'num_possible_hosts': data.get('numPossibleHosts', 0),
                    'address_space_desc': data.get('addressSpaceDesc', 'Unknown'),
                    'reported_address_count': len(data.get('reportedAddress', []))
                }
        except Exception as e:
            return {'source': 'AbuseIPDB', 'error': str(e)}
        
        return {'source': 'AbuseIPDB', 'error': 'No data available'}

class IOCAnalyzer:
    """Main analyzer class that coordinates IOC analysis"""
    
    def __init__(self):
        self.api = ThreatIntelligenceAPI()
    
    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze an IP address"""
        results = {
            'ioc': ip,
            'type': 'ip',
            'results': []
        }
        
        # Query VirusTotal
        vt_result = self.api.query_virustotal_ip(ip)
        results['results'].append(vt_result)
        
        # Query AbuseIPDB
        abuse_result = self.api.query_abuseipdb(ip)
        results['results'].append(abuse_result)
        
        # Add rate limiting delay
        time.sleep(0.5)
        
        return results
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a domain name"""
        results = {
            'ioc': domain,
            'type': 'domain',
            'results': []
        }
        
        # Query VirusTotal
        vt_result = self.api.query_virustotal_domain(domain)
        results['results'].append(vt_result)
        
        # Add rate limiting delay
        time.sleep(0.5)
        
        return results
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL"""
        results = {
            'ioc': url,
            'type': 'url',
            'results': []
        }
        
        # Query VirusTotal
        vt_result = self.api.query_virustotal_url(url)
        results['results'].append(vt_result)
        
        # Add rate limiting delay
        time.sleep(0.5)
        
        return results
    
    def analyze_hash(self, file_hash: str) -> Dict[str, Any]:
        """Analyze a file hash"""
        hash_type = IOCClassifier.is_hash(file_hash)
        results = {
            'ioc': file_hash,
            'type': 'hash',
            'hash_type': hash_type,
            'results': []
        }
        
        # Query VirusTotal
        vt_result = self.api.query_virustotal_hash(file_hash)
        results['results'].append(vt_result)
        
        # Add rate limiting delay
        time.sleep(0.5)
        
        return results
    
    def analyze_cidr(self, cidr: str) -> Dict[str, Any]:
        """Analyze a CIDR block"""
        results = {
            'ioc': cidr,
            'type': 'cidr',
            'results': []
        }
        
        # Query AbuseIPDB
        abuse_result = self.api.query_abuseipdb_cidr(cidr)
        results['results'].append(abuse_result)
        
        # Add rate limiting delay
        time.sleep(0.5)
        
        return results
    
    def analyze_ioc(self, ioc: str) -> Dict[str, Any]:
        """Analyze any IOC by first classifying it"""
        ioc = ioc.strip()
        if not ioc:
            return {'error': 'Empty IOC provided'}
        
        ioc_type = IOCClassifier.classify_ioc(ioc)
        
        if ioc_type == 'ip':
            return self.analyze_ip(ioc)
        elif ioc_type == 'domain':
            return self.analyze_domain(ioc)
        elif ioc_type == 'url':
            return self.analyze_url(ioc)
        elif ioc_type == 'hash':
            return self.analyze_hash(ioc)
        elif ioc_type == 'cidr':
            return self.analyze_cidr(ioc)
        else:
            return {
                'ioc': ioc,
                'type': 'unknown',
                'error': f'Unable to classify IOC: {ioc}'
            }

# Initialize the analyzer
analyzer = IOCAnalyzer()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'Threat Intelligence API is running'})

@app.route('/analyze', methods=['POST'])
def analyze_iocs():
    """Main endpoint to analyze IOCs"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Collect all IOCs from different fields
        iocs_to_analyze = []
        
        # Individual field inputs
        if data.get('ip_address'):
            iocs_to_analyze.append(data['ip_address'].strip())
        
        if data.get('domain_name'):
            iocs_to_analyze.append(data['domain_name'].strip())
        
        if data.get('file_hash'):
            iocs_to_analyze.append(data['file_hash'].strip())
        
        if data.get('url'):
            iocs_to_analyze.append(data['url'].strip())
        
        # Bulk IOC input
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
                result = analyzer.analyze_ioc(ioc)
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
            'results': results
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
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
    
    print("🔍 Threat Intelligence IOC Analyzer Starting...")
    print("📍 Available endpoints:")
    print("   - POST /analyze - Analyze IOCs")
    print("   - POST /classify - Classify IOC type")
    print("   - GET /health - Health check")
    print()
    
    app.run(debug=True, host='0.0.0.0', port=5000)