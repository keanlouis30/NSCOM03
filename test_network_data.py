#!/usr/bin/env python3
"""
Quick test to show what network connection data is collected
Run this to see what information the deep analysis provides
"""

from deep_analysis import DeepNetworkAnalyzer
import json

def test_ip_analysis(ip_address):
    """Test deep analysis on an IP address"""
    print(f"\n{'='*60}")
    print(f"DEEP NETWORK ANALYSIS FOR: {ip_address}")
    print(f"{'='*60}\n")
    
    analyzer = DeepNetworkAnalyzer()
    results = analyzer.analyze_ip_deep(ip_address)
    
    # Display Network Location Information
    print("📍 NETWORK LOCATION (Where is this IP?)")
    print("-" * 60)
    geo = results.get('geolocation', {})
    if geo.get('status') == 'success':
        print(f"  Country: {geo.get('country')}")
        print(f"  City: {geo.get('city')}")
        print(f"  Region: {geo.get('region')}")
        print(f"  Coordinates: {geo.get('coordinates')}")
        print(f"  Timezone: {geo.get('timezone')}")
        print(f"  ISP: {geo.get('isp')}")
        print(f"  Organization: {geo.get('org', 'N/A')}")
    else:
        print(f"  ⚠️  {geo.get('error', 'Failed to get geolocation')}")
    
    # Display ASN/Network Information
    print("\n🌐 ASN & NETWORK INFORMATION")
    print("-" * 60)
    asn = results.get('asn_info', {})
    if asn.get('status') == 'success':
        print(f"  ASN: {asn.get('asn')}")
        print(f"  ASN Description: {asn.get('asn_description')}")
        print(f"  ASN Country: {asn.get('asn_country')}")
        print(f"  ASN Registry: {asn.get('asn_registry')}")
        print(f"  Network CIDR: {asn.get('network', {}).get('cidr')}")
        print(f"  Network Name: {asn.get('network', {}).get('name')}")
        print(f"  Network Range: {asn.get('network', {}).get('range')}")
    else:
        print(f"  ⚠️  {asn.get('error', 'Failed to get ASN info')}")
    
    # Display Subnet Analysis
    print("\n🔗 SUBNET ANALYSIS (/24 Network)")
    print("-" * 60)
    subnet = results.get('subnet_analysis', {})
    if subnet.get('status') == 'success':
        print(f"  Network Address: {subnet.get('network_address')}")
        print(f"  Broadcast Address: {subnet.get('broadcast_address')}")
        print(f"  Netmask: {subnet.get('netmask')}")
        print(f"  CIDR: {subnet.get('cidr')}")
        print(f"  Total Addresses: {subnet.get('num_addresses')}")
        print(f"  First Host: {subnet.get('first_host')}")
        print(f"  Last Host: {subnet.get('last_host')}")
        print(f"  Private Network: {subnet.get('is_private')}")
        print(f"  Global Network: {subnet.get('is_global')}")
    
    # Display Network Neighbors
    print("\n👥 NETWORK NEIGHBORS (Same Subnet)")
    print("-" * 60)
    neighbors = results.get('network_neighbors', {})
    if neighbors.get('status') == 'success':
        neighbor_list = neighbors.get('sampled_neighbors', [])
        print(f"  Sampled {len(neighbor_list)} neighboring IPs (±5 range)")
        for n in neighbor_list:
            hostname = n.get('hostname') or 'No hostname'
            offset = n.get('offset')
            symbol = '+' if offset > 0 else ''
            print(f"    • {n.get('ip')} (offset: {symbol}{offset}) - {hostname}")
    
    # Display Reverse DNS
    print("\n🔄 REVERSE DNS (PTR Records)")
    print("-" * 60)
    dns = results.get('dns_records', {})
    if dns.get('status') == 'success':
        ptr_records = dns.get('ptr_records', [])
        if ptr_records:
            for ptr in ptr_records:
                print(f"  • {ptr}")
        else:
            print("  No PTR records found")
    else:
        print(f"  ⚠️  {dns.get('error', 'Failed')}")
    
    # Display Open Ports
    print("\n🔓 OPEN PORTS & SERVICES")
    print("-" * 60)
    ports = results.get('open_ports', {})
    if ports.get('status') == 'success':
        open_ports = ports.get('open_ports', [])
        if open_ports:
            for p in open_ports:
                print(f"  • Port {p.get('port')}: {p.get('service')} ({p.get('state')})")
        else:
            print("  No open ports detected")
    
    # Display WHOIS Data
    print("\n📋 WHOIS REGISTRATION DATA")
    print("-" * 60)
    whois_data = results.get('whois_data', {})
    if whois_data.get('status') == 'success':
        for key, value in whois_data.items():
            if key != 'status':
                print(f"  {key}: {value}")
    
    print("\n" + "="*60)
    print("✅ NETWORK LOCATION DATA COMPLETE!")
    print("="*60)
    print("\n⚠️  NOTE: This test only shows DEEP analysis data.")
    print("To see ASSOCIATED DOMAINS & NETWORK TRAFFIC from VirusTotal:")
    print("  - Run the full web app with deep analysis enabled")
    print("  - The CSV/JSON reports will include:")
    print("    • Associated Domains (what domains point to this IP)")
    print("    • Communicating Files (malware network traffic)")
    print("    • Downloaded Files (files hosted on this IP)")
    print("    • Network behavior patterns")
    print("="*60)
    
    # Save to JSON file
    with open('test_network_analysis.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print("\n💾 Full data saved to: test_network_analysis.json")
    print("📄 Run the web app with deep analysis for PDF/CSV exports!\n")

if __name__ == '__main__':
    # Test with Google's DNS
    test_ip_analysis("8.8.8.8")
    
    print("\n" + "="*60)
    print("To get PDF/CSV/JSON reports via web interface:")
    print("1. python app.py")
    print("2. python -m http.server 8000")
    print("3. Go to http://localhost:8000")
    print("4. Check ☑️ 'Enable Deep Analysis'")
    print("5. Enter IP: 8.8.8.8")
    print("6. Click 'Analyze IOCs'")
    print("7. Download JSON/CSV/PDF reports")
    print("="*60 + "\n")

