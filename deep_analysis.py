"""
Deep Analysis Module - Enhanced Network Intelligence
Provides comprehensive IOC analysis including DNS, WHOIS, geolocation, 
subnet analysis, SSL/TLS, and passive traffic patterns.
"""

import dns.resolver
import dns.reversename
import whois
import socket
import ssl
import requests
import ipaddress
import subprocess
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
import time

class DeepNetworkAnalyzer:
    """Comprehensive network intelligence analysis"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'IOC-DeepAnalyzer/2.0'})
        
        # Load API keys
        self.ipinfo_key = os.getenv('IPINFO_API_KEY', '')
        self.urlscan_key = os.getenv('URLSCAN_API_KEY', '')
        self.whoisxml_key = os.getenv('WHOISXML_API_KEY', '')
        self.ipquality_key = os.getenv('IPQUALITYSCORE_API_KEY', '')
        self.securitytrails_key = os.getenv('SECURITYTRAILS_API_KEY', '')
        self.shodan_key = os.getenv('SHODAN_API_KEY', '')
        
    def analyze_ip_deep(self, ip: str) -> Dict[str, Any]:
        """Comprehensive IP address analysis"""
        results = {
            'ip': ip,
            'timestamp': datetime.utcnow().isoformat(),
            'dns_records': self.get_reverse_dns(ip),
            'whois_data': self.get_ip_whois(ip),
            'geolocation': self.get_geolocation(ip),
            'asn_info': self.get_asn_info(ip),
            'subnet_analysis': self.analyze_subnet(ip),
            'open_ports': self.get_open_ports(ip),
            'ssl_certificates': self.get_ssl_info(ip),
            'reputation': self.get_ip_reputation(ip),
            'historical_dns': self.get_historical_dns_ip(ip),
            'network_neighbors': self.get_network_neighbors(ip)
        }
        return results
    
    def analyze_domain_deep(self, domain: str) -> Dict[str, Any]:
        """Comprehensive domain analysis"""
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'dns_records': self.get_all_dns_records(domain),
            'whois_data': self.get_domain_whois(domain),
            'historical_ips': self.get_historical_dns_domain(domain),
            'subdomains': self.discover_subdomains(domain),
            'nameservers': self.get_nameservers(domain),
            'mx_records': self.get_mx_records(domain),
            'txt_records': self.get_txt_records(domain),
            'ssl_certificates': self.get_domain_ssl_info(domain),
            'web_technology': self.detect_web_technology(domain),
            'domain_age': self.get_domain_age(domain),
            'registrar_info': self.get_registrar_info(domain)
        }
        return results
    
    # ==================== DNS Functions ====================
    
    def get_reverse_dns(self, ip: str) -> Dict[str, Any]:
        """Get PTR (reverse DNS) records"""
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, 'PTR')
            return {
                'ptr_records': [str(rdata) for rdata in answers],
                'status': 'success'
            }
        except Exception as e:
            return {'ptr_records': [], 'status': 'failed', 'error': str(e)}
    
    def get_all_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get all DNS record types for a domain"""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
        results = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results[record_type] = []
            except Exception as e:
                results[record_type] = {'error': str(e)}
        
        return results
    
    def get_nameservers(self, domain: str) -> List[str]:
        """Get nameserver information"""
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return []
    
    def get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX (mail exchange) records"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return [{'priority': rdata.preference, 'exchange': str(rdata.exchange)} 
                    for rdata in answers]
        except Exception as e:
            return []
    
    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records (SPF, DKIM, DMARC, etc.)"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return []
    
    # ==================== WHOIS Functions ====================
    
    def get_ip_whois(self, ip: str) -> Dict[str, Any]:
        """Get WHOIS data for IP address"""
        try:
            # Try python-whois first
            w = whois.whois(ip)
            return {
                'org': getattr(w, 'org', 'Unknown'),
                'country': getattr(w, 'country', 'Unknown'),
                'registrar': getattr(w, 'registrar', 'Unknown'),
                'creation_date': str(getattr(w, 'creation_date', 'Unknown')),
                'status': 'success'
            }
        except Exception as e:
            # Fallback to ipwhois library
            try:
                from ipwhois import IPWhois
                obj = IPWhois(ip)
                result = obj.lookup_rdap()
                return {
                    'asn': result.get('asn', 'Unknown'),
                    'asn_description': result.get('asn_description', 'Unknown'),
                    'asn_country': result.get('asn_country_code', 'Unknown'),
                    'network': result.get('network', {}).get('cidr', 'Unknown'),
                    'status': 'success'
                }
            except Exception as e2:
                return {'status': 'failed', 'error': str(e2)}
    
    def get_domain_whois(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS data for domain"""
        try:
            w = whois.whois(domain)
            return {
                'domain_name': getattr(w, 'domain_name', 'Unknown'),
                'registrar': getattr(w, 'registrar', 'Unknown'),
                'creation_date': str(getattr(w, 'creation_date', 'Unknown')),
                'expiration_date': str(getattr(w, 'expiration_date', 'Unknown')),
                'updated_date': str(getattr(w, 'updated_date', 'Unknown')),
                'name_servers': getattr(w, 'name_servers', []),
                'status': getattr(w, 'status', 'Unknown'),
                'registrant': getattr(w, 'registrant', 'Unknown'),
                'country': getattr(w, 'country', 'Unknown'),
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    # ==================== Geolocation Functions ====================
    
    def get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get detailed geolocation data"""
        if self.ipinfo_key and not self.ipinfo_key.startswith('your_'):
            return self._get_ipinfo_data(ip)
        else:
            return self._get_free_geolocation(ip)
    
    def _get_ipinfo_data(self, ip: str) -> Dict[str, Any]:
        """Get data from IPinfo.io (premium)"""
        try:
            url = f'https://ipinfo.io/{ip}?token={self.ipinfo_key}'
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'coordinates': data.get('loc', 'Unknown'),
                    'postal': data.get('postal', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'asn': data.get('asn', {}).get('asn', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'status': 'success'
                }
        except Exception as e:
            pass
        return self._get_free_geolocation(ip)
    
    def _get_free_geolocation(self, ip: str) -> Dict[str, Any]:
        """Fallback to free geolocation service"""
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'coordinates': f"{data.get('lat', 0)},{data.get('lon', 0)}",
                    'timezone': data.get('timezone', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown'),
                    'status': 'success'
                }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    # ==================== ASN Functions ====================
    
    def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN (Autonomous System Number) information"""
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            result = obj.lookup_rdap()
            
            return {
                'asn': result.get('asn', 'Unknown'),
                'asn_cidr': result.get('asn_cidr', 'Unknown'),
                'asn_country': result.get('asn_country_code', 'Unknown'),
                'asn_description': result.get('asn_description', 'Unknown'),
                'asn_registry': result.get('asn_registry', 'Unknown'),
                'network': {
                    'cidr': result.get('network', {}).get('cidr', 'Unknown'),
                    'name': result.get('network', {}).get('name', 'Unknown'),
                    'handle': result.get('network', {}).get('handle', 'Unknown'),
                    'range': result.get('network', {}).get('range', 'Unknown'),
                },
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    # ==================== Subnet Analysis ====================
    
    def analyze_subnet(self, ip: str) -> Dict[str, Any]:
        """Analyze the /24 subnet containing this IP"""
        try:
            # Get the /24 network
            ip_obj = ipaddress.IPv4Address(ip)
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask),
                'cidr': str(network),
                'num_addresses': network.num_addresses,
                'first_host': str(network.network_address + 1),
                'last_host': str(network.broadcast_address - 1),
                'is_private': network.is_private,
                'is_global': network.is_global,
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def get_network_neighbors(self, ip: str) -> Dict[str, Any]:
        """Get information about neighboring IPs in the same subnet"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            
            # Sample some neighbors (not all 254!)
            neighbors = []
            current_host = int(ip_obj)
            
            # Check ±5 neighbors
            for offset in range(-5, 6):
                neighbor_int = current_host + offset
                if neighbor_int == current_host:
                    continue
                    
                try:
                    neighbor_ip = ipaddress.IPv4Address(neighbor_int)
                    if neighbor_ip in network:
                        # Quick reverse DNS check
                        try:
                            hostname = socket.gethostbyaddr(str(neighbor_ip))[0]
                        except:
                            hostname = None
                        
                        neighbors.append({
                            'ip': str(neighbor_ip),
                            'offset': offset,
                            'hostname': hostname
                        })
                except:
                    continue
            
            return {
                'subnet': str(network),
                'sampled_neighbors': neighbors,
                'total_possible_hosts': network.num_addresses - 2,
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    # ==================== Port Scanning ====================
    
    def get_open_ports(self, ip: str) -> Dict[str, Any]:
        """Check common ports (basic scan)"""
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # Try to get service banner
                    service = self._get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                sock.close()
            except:
                continue
        
        return {
            'scanned_ports': len(common_ports),
            'open_ports': open_ports,
            'status': 'success'
        }
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
            3389: 'RDP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    # ==================== SSL/TLS Functions ====================
    
    def get_ssl_info(self, ip: str) -> Dict[str, Any]:
        """Get SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', []),
                        'status': 'success'
                    }
        except Exception as e:
            return {'status': 'no_ssl_or_failed', 'error': str(e)}
    
    def get_domain_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate for domain"""
        return self.get_ssl_info(domain)
    
    # ==================== Reputation Functions ====================
    
    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation from multiple sources"""
        if self.ipquality_key and not self.ipquality_key.startswith('your_'):
            return self._get_ipquality_score(ip)
        else:
            return {'status': 'no_api_key', 'message': 'Configure IPQUALITYSCORE_API_KEY for reputation data'}
    
    def _get_ipquality_score(self, ip: str) -> Dict[str, Any]:
        """Get reputation from IPQualityScore"""
        try:
            url = f'https://ipqualityscore.com/api/json/ip/{self.ipquality_key}/{ip}'
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'fraud_score': data.get('fraud_score', 0),
                    'is_proxy': data.get('proxy', False),
                    'is_vpn': data.get('vpn', False),
                    'is_tor': data.get('tor', False),
                    'is_crawler': data.get('is_crawler', False),
                    'bot_status': data.get('bot_status', False),
                    'recent_abuse': data.get('recent_abuse', False),
                    'abuse_velocity': data.get('abuse_velocity', 'Unknown'),
                    'status': 'success'
                }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    # ==================== Historical Data ====================
    
    def get_historical_dns_ip(self, ip: str) -> Dict[str, Any]:
        """Get historical DNS data for IP"""
        if self.securitytrails_key and not self.securitytrails_key.startswith('your_'):
            return self._get_securitytrails_ip_history(ip)
        return {'status': 'no_api_key', 'message': 'Configure SECURITYTRAILS_API_KEY'}
    
    def get_historical_dns_domain(self, domain: str) -> Dict[str, Any]:
        """Get historical DNS data for domain"""
        if self.securitytrails_key and not self.securitytrails_key.startswith('your_'):
            return self._get_securitytrails_domain_history(domain)
        return {'status': 'no_api_key', 'message': 'Configure SECURITYTRAILS_API_KEY'}
    
    def _get_securitytrails_ip_history(self, ip: str) -> Dict[str, Any]:
        """Get IP history from SecurityTrails"""
        try:
            headers = {'APIKEY': self.securitytrails_key}
            url = f'https://api.securitytrails.com/v1/history/{ip}/dns/a'
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _get_securitytrails_domain_history(self, domain: str) -> Dict[str, Any]:
        """Get domain history from SecurityTrails"""
        try:
            headers = {'APIKEY': self.securitytrails_key}
            url = f'https://api.securitytrails.com/v1/history/{domain}/dns/a'
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    # ==================== Subdomain Discovery ====================
    
    def discover_subdomains(self, domain: str) -> Dict[str, Any]:
        """Discover subdomains"""
        if self.securitytrails_key and not self.securitytrails_key.startswith('your_'):
            try:
                headers = {'APIKEY': self.securitytrails_key}
                url = f'https://api.securitytrails.com/v1/domain/{domain}/subdomains'
                response = self.session.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'subdomains': data.get('subdomains', [])[:50],  # Limit to 50
                        'count': len(data.get('subdomains', [])),
                        'status': 'success'
                    }
            except Exception as e:
                return {'status': 'failed', 'error': str(e)}
        return {'status': 'no_api_key', 'message': 'Configure SECURITYTRAILS_API_KEY'}
    
    # ==================== Domain Intelligence ====================
    
    def detect_web_technology(self, domain: str) -> Dict[str, Any]:
        """Detect web technologies used"""
        try:
            response = self.session.get(f'http://{domain}', timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            
            technologies = []
            if 'Server' in headers:
                technologies.append({'type': 'server', 'name': headers['Server']})
            if 'X-Powered-By' in headers:
                technologies.append({'type': 'backend', 'name': headers['X-Powered-By']})
            
            return {
                'technologies': technologies,
                'server_header': headers.get('Server', 'Unknown'),
                'status_code': response.status_code,
                'final_url': response.url,
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def get_domain_age(self, domain: str) -> Dict[str, Any]:
        """Calculate domain age from WHOIS"""
        try:
            w = whois.whois(domain)
            creation_date = getattr(w, 'creation_date', None)
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age_days = (datetime.now() - creation_date).days
                return {
                    'creation_date': str(creation_date),
                    'age_days': age_days,
                    'age_years': round(age_days / 365.25, 2),
                    'status': 'success'
                }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def get_registrar_info(self, domain: str) -> Dict[str, Any]:
        """Get detailed registrar information"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': getattr(w, 'registrar', 'Unknown'),
                'registrar_url': getattr(w, 'registrar_url', 'Unknown'),
                'whois_server': getattr(w, 'whois_server', 'Unknown'),
                'referral_url': getattr(w, 'referral_url', 'Unknown'),
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

