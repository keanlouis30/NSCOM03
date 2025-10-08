# Deep Analysis Setup Guide

## What Was Added

Your IOC Analyzer now has **Deep Analysis Mode** that provides comprehensive network intelligence beyond basic threat intel.

### New Capabilities

#### For IP Addresses:
- ✅ **Geolocation**: City, coordinates, timezone, ISP
- ✅ **ASN Information**: Autonomous System Number, CIDR, description
- ✅ **WHOIS Data**: Registration info, abuse contacts
- ✅ **Subnet Analysis**: /24 network metadata
- ✅ **Neighboring IPs**: Sampled IPs ±5 in the same subnet with hostnames
- ✅ **DNS**: Reverse DNS (PTR records)
- ✅ **Open Ports**: Scan of common ports (21,22,23,25,53,80,443,3306,3389,8080,8443)
- ✅ **SSL Certificates**: Subject, issuer, validity dates
- ✅ **Reputation**: Fraud score, proxy/VPN/TOR detection
- ✅ **Historical Data**: DNS history, IP changes over time

#### For Domains:
- ✅ **Complete DNS Records**: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA
- ✅ **WHOIS**: Registrar, creation/expiration dates, registrant
- ✅ **Subdomains**: Discovery of up to 50 subdomains
- ✅ **Historical IPs**: Track IP changes over time
- ✅ **SSL Certificates**: Certificate analysis
- ✅ **Web Technology**: Server headers, technology stack detection
- ✅ **Domain Age**: Calculate age from registration date
- ✅ **Nameservers**: Complete NS records
- ✅ **Mail Servers**: MX records with priorities

#### Export Formats:
- 📄 **JSON**: Complete nested data with all fields
- 📊 **CSV**: 25+ columns with flattened data
- 📑 **PDF**: Professional formatted report

## Setup Instructions

### 1. Install New Dependencies

```bash
# Make sure virtual environment is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install new packages
pip install -r requirements.txt
```

This installs:
- `dnspython` - DNS queries
- `python-whois` - WHOIS lookups
- `ipwhois` - IP WHOIS and ASN data
- `reportlab` - PDF generation
- `pyOpenSSL` - SSL certificate analysis
- `scapy` - Network scanning (optional)

### 2. Configure API Keys

Copy the template and add your API keys:

```bash
cp .env.example .env
# Edit .env with your favorite editor
nano .env  # or vim, code, etc.
```

#### Free API Keys to Get:

1. **IPinfo.io** (Free: 50,000 requests/month)
   - Register: https://ipinfo.io/signup
   - Get: Geolocation, ASN, ISP data

2. **URLScan.io** (Free: Unlimited with rate limits)
   - Register: https://urlscan.io/user/signup
   - Get: URL analysis capabilities

3. **SecurityTrails** (Free: 50 queries/month)
   - Register: https://securitytrails.com/
   - Get: DNS history, subdomain discovery

4. **IPQualityScore** (Free: 5,000 lookups/month)
   - Register: https://www.ipqualityscore.com/create-account
   - Get: Fraud detection, proxy/VPN detection

5. **WhoisXML API** (Free: 500 queries/month)
   - Register: https://whois.whoisxmlapi.com/
   - Get: Enhanced WHOIS data

Add keys to your `.env` file:
```bash
IPINFO_API_KEY="your_actual_key_here"
URLSCAN_API_KEY="your_actual_key_here"
SECURITYTRAILS_API_KEY="your_actual_key_here"
IPQUALITYSCORE_API_KEY="your_actual_key_here"
WHOISXML_API_KEY="your_actual_key_here"
```

**Note**: The app works even without these keys! Missing keys will disable specific features but core functionality remains.

### 3. Start the Application

```bash
# Start Flask backend
python app.py

# In another terminal, serve the frontend
python -m http.server 8000
```

You should see startup messages including:
```
🔑 API Key Status:
   - VIRUSTOTAL: X key(s) configured
   - ABUSEIPDB: X key(s) configured
   - OTX: X key(s) configured
   ...

🔍 Enhanced Threat Intelligence IOC Analyzer Starting...
🚀 Features:
   - Standard: Relational IOC Analysis with Threat Intelligence
   - Deep: Comprehensive Network Intelligence & Relationships
   - Reports: JSON, CSV, PDF export with complete data

📡 Available endpoints:
   - POST /analyze - Standard IOC analysis with relations
   - POST /analyze/deep - Deep analysis with network intelligence
   - GET /download-report/<format> - Download report (json/csv/pdf)
   ...
```

## How to Use Deep Analysis

### Via Web Interface:

1. **Navigate to**: http://localhost:8000

2. **Enable Deep Analysis**:
   - Find the "Analysis Options" section
   - Check the box: ☑️ **Enable Deep Analysis** 🔬
   - You'll see a warning that it includes comprehensive network intelligence

3. **Enter IOCs**:
   - Fill in any IOC fields (IP, domain, URL, etc.)
   - OR paste multiple IOCs in the "Bulk IOC Input" field

4. **Click "Analyze IOCs"**:
   - Modal shows: "Deep Analysis Mode - Performing comprehensive network intelligence..."
   - This takes longer than standard analysis (expect 30-60 seconds per IOC)

5. **View Results**:
   - Standard results display on the page
   - **Download options appear below results**

6. **Download Reports**:
   - Click **Download JSON Report** - Complete data structure
   - Click **Download CSV Report** - Spreadsheet with 25+ columns
   - Click **Download PDF Report** - Professional formatted document

### Via API/CLI:

```bash
# Deep analysis of an IP
curl -X POST http://localhost:5000/analyze/deep \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "8.8.8.8"}'

# Deep analysis of a domain
curl -X POST http://localhost:5000/analyze/deep \
  -H "Content-Type: application/json" \
  -d '{"domain_name": "google.com"}'

# Download reports (must run deep analysis first)
curl http://localhost:5000/download-report/json > report.json
curl http://localhost:5000/download-report/csv > report.csv
curl http://localhost:5000/download-report/pdf > report.pdf
```

## What Data You'll Get

### Example: IP Address Deep Analysis for 8.8.8.8

**JSON Report** includes:
```json
{
  "ioc": "8.8.8.8",
  "type": "ip",
  "timestamp": "2024-12-12T10:30:00Z",
  "standard_analysis": {
    "main_analysis": {...},
    "relational_data": {...}
  },
  "deep_analysis": {
    "geolocation": {
      "city": "Mountain View",
      "country": "United States",
      "coordinates": "37.4056,-122.0775",
      "isp": "Google LLC"
    },
    "asn_info": {
      "asn": "AS15169",
      "asn_description": "GOOGLE",
      "network": {"cidr": "8.8.8.0/24"}
    },
    "subnet_analysis": {
      "network_address": "8.8.8.0",
      "cidr": "8.8.8.0/24",
      "num_addresses": 256
    },
    "network_neighbors": {
      "sampled_neighbors": [
        {"ip": "8.8.8.3", "offset": -5, "hostname": null},
        {"ip": "8.8.8.7", "offset": -1, "hostname": "dns.google"},
        {"ip": "8.8.8.9", "offset": 1, "hostname": null}
      ]
    },
    "open_ports": {
      "open_ports": [
        {"port": 53, "service": "DNS", "state": "open"},
        {"port": 443, "service": "HTTPS", "state": "open"}
      ]
    },
    "ssl_certificates": {...},
    "reputation": {
      "fraud_score": 0,
      "is_proxy": false,
      "is_vpn": false,
      "is_tor": false
    }
  }
}
```

**CSV Report** columns:
- IOC, Type, Timestamp
- Country, City, Region, Coordinates, Timezone, ISP
- ASN, ASN Description, Network CIDR, Subnet
- PTR Records, Nameservers, MX Records
- Registrar, Creation Date, Expiration Date
- Open Ports, SSL Certificate Subject, SSL Issuer
- Fraud Score, Is Proxy, Is VPN, Is TOR
- Neighboring IPs, Subdomains
- Web Technology, Domain Age (days)

**PDF Report** includes:
- Executive summary with metadata
- Geolocation & Network section with maps data
- ASN Information
- WHOIS Data
- Open Ports listing
- Security Reputation scores
- Professional formatting with tables and sections

## Performance Notes

- **Standard Analysis**: ~5 seconds per IOC
- **Deep Analysis**: ~30-60 seconds per IOC (depending on API keys configured)
- **Bulk Analysis**: Sequential processing with 1-second delays
- **Report Generation**: < 1 second

## Troubleshooting

### "No analysis results available" when downloading
- You must run a deep analysis first before downloading reports
- Reports are stored in memory (latest analysis only)

### "Deep analysis failed: Module not found"
- Run: `pip install -r requirements.txt` again
- Check all dependencies are installed

### Slow analysis / timeouts
- Some APIs have rate limits
- DNS queries can be slow for certain domains
- Port scanning adds ~10 seconds per IOC
- Consider using fewer IOCs per batch

### Missing data in reports
- Check which API keys you've configured
- Free tier limits may be reached
- Some IOCs don't have all data types available

### Port scanning not working
- Some networks block port scans
- Firewall may interfere
- Try on local/development networks only

## Security Notes

- **Port scanning**: Only use on IPs you own or have permission to scan
- **Rate limits**: Respect API provider limits (use multiple keys if needed)
- **API keys**: Never commit to version control
- **Data storage**: Deep analysis results stored in memory only (not persisted)

## Next Steps

Your professor asked for "deeper information about Network Connections, Traffic, and Domains" - this implementation provides:

✅ **Network Connections**: 
- Subnet neighbors (sampled ±5 IPs)
- ASN peers (infrastructure sharing)
- Open ports and services

✅ **Traffic Analysis**:
- Historical DNS (IP/domain changes over time)
- Communicating files (from VirusTotal)
- Network behavior patterns

✅ **Domain Intelligence**:
- Complete DNS record enumeration
- Subdomain discovery
- Historical IP associations
- Certificate chains
- Technology stack

All data is exportable in CSV, JSON, and PDF formats for in-depth analysis!

## Questions?

Check:
- `WARP.md` - Complete architecture and development guide
- `READMe.md` - Testing guide with test cases
- `CHANGELOG.md` - Version history
- `.env.example` - API key documentation with links

