# Complete Network Data in Deep Analysis Reports

## What Data You Get for Network & Communications Course

When you run **Deep Analysis** on an IP address, the CSV/JSON/PDF reports contain:

---

## 📍 1. NETWORK LOCATION (Where is this IP?)

From **Geolocation + ASN data**:

| Column | Description | Example |
|--------|-------------|---------|
| Country | Physical location country | United States |
| City | Physical location city | Mountain View |
| Region | State/Province | California |
| Coordinates | GPS coordinates | 37.4056,-122.0775 |
| Timezone | Local timezone | America/Los_Angeles |
| ISP | Internet Service Provider | Google LLC |
| ASN | Autonomous System Number | AS15169 |
| ASN Description | Organization name | GOOGLE |
| Network CIDR | IP range this belongs to | 8.8.8.0/24 |
| Subnet | /24 subnet CIDR | 8.8.8.0/24 |

**This answers**: *"Where is this IP physically located and which network does it belong to?"*

---

## 🔗 2. ASSOCIATED DOMAINS (What domains connect to this IP?)

From **VirusTotal Associated Domains**:

| Column | Description | Example |
|--------|-------------|---------|
| Associated Domains (VT) | Domains that resolve to this IP | dns.google; google.com; ... (up to 50) |

**This answers**: *"What websites/services are hosted on this IP?"*

**Example for 8.8.8.8**: 
- `dns.google`
- `google-public-dns-a.google.com`
- Plus all other domains pointing to it

---

## 👥 3. NETWORK NEIGHBORS (Who else is nearby?)

From **Subnet Analysis**:

| Column | Description | Example |
|--------|-------------|---------|
| Neighboring IPs | IPs within ±5 range in same subnet | 8.8.8.3; 8.8.8.4; 8.8.8.7; 8.8.8.9; ... |

**This answers**: *"What other IPs are in the same network segment?"*

---

## 🚦 4. NETWORK TRAFFIC & COMMUNICATIONS

From **VirusTotal Network Behavior**:

| Column | Description | Example |
|--------|-------------|---------|
| Communicating Files (VT) | Malware samples that communicated with this IP/domain | abc123... (5/65); def456... (12/70) |
| Downloaded Files (VT) | Files downloaded from this IP | xyz789... (0/65); ... |

**Format**: `<hash_prefix> (<detections>/<total_engines>)`

**This answers**: *"What malware or files have been seen communicating with this IP?"*

---

## 🌐 5. IP-TO-DOMAIN RELATIONSHIPS (For Domain Analysis)

When analyzing a **domain**, you get:

| Column | Description | Example |
|--------|-------------|---------|
| Associated IPs (VT) | All IPs this domain has resolved to | 142.250.185.46; 172.217.14.206; ... |
| Subdomains | Discovered subdomains | mail.example.com; www.example.com; ... |

**This answers**: *"What IPs does this domain point to and what are its subdomains?"*

---

## 📡 6. NETWORK BEHAVIOR (For Hash/Malware Analysis)

When analyzing a **file hash**, you get:

| Column | Description | Example |
|--------|-------------|---------|
| Contacted IPs (Hash) | IPs the malware contacted | 192.0.2.1; 198.51.100.1; ... |
| Contacted Domains (Hash) | Domains the malware contacted | evil.com; command.server.net; ... |
| Contacted URLs (Hash) | URLs the malware accessed | http://evil.com/payload; ... |

**This answers**: *"What network connections did this malware make?"*

---

## 🔍 7. DNS & INFRASTRUCTURE

| Column | Description | Example |
|--------|-------------|---------|
| PTR Records | Reverse DNS | dns.google. |
| Nameservers | Domain nameservers | ns1.google.com; ns2.google.com |
| MX Records | Mail servers | mail.google.com (10) |

---

## 🔓 8. OPEN SERVICES

| Column | Description | Example |
|--------|-------------|---------|
| Open Ports | Accessible network services | 53(DNS); 443(HTTPS) |

**This answers**: *"What services are running on this IP?"*

---

## 🛡️ 9. SECURITY REPUTATION

| Column | Description | Example |
|--------|-------------|---------|
| VT Malicious Count | VirusTotal malicious detections | 0 |
| VT Suspicious Count | VirusTotal suspicious detections | 0 |
| VT Clean Count | VirusTotal clean votes | 85 |
| Fraud Score | IP reputation score | 0 |
| Is Proxy | Proxy detection | False |
| Is VPN | VPN detection | False |
| Is TOR | TOR exit node detection | False |

---

## 📋 10. REGISTRATION DATA

| Column | Description | Example |
|--------|-------------|---------|
| Registrar | Domain registrar | MarkMonitor Inc. |
| Creation Date | When registered | 1997-09-15 |
| Expiration Date | When expires | 2028-09-14 |

---

## 💻 Complete Example CSV Row for IP: 8.8.8.8

```csv
IOC,Type,Country,City,ISP,ASN,ASN Description,Network CIDR,Neighboring IPs,Associated Domains (VT),Communicating Files (VT),Open Ports,VT Malicious Count,VT Suspicious Count,VT Clean Count
8.8.8.8,ip,United States,Mountain View,Google LLC,AS15169,GOOGLE,8.8.8.0/24,"8.8.8.3; 8.8.8.4; 8.8.8.7; 8.8.8.9; 8.8.8.13","dns.google; google-public-dns-a.google.com; google.com",abc123...(0/65); def456...(2/70),"53(DNS); 443(HTTPS)",0,0,85
```

---

## 🎯 Summary: What This Means for Your Network Course

Your deep analysis provides **complete network intelligence**:

1. **Geographic Location**: WHERE the IP is physically located
2. **Network Topology**: WHAT network it belongs to (ASN, CIDR, neighbors)
3. **Domain Associations**: WHAT domains are hosted on or connected to this IP
4. **Traffic Patterns**: WHAT malware/files have communicated with it
5. **Infrastructure**: DNS, nameservers, open services
6. **Security Context**: Reputation, proxy/VPN detection

---

## 📊 How to Get This Data

### Step 1: Run the Application
```bash
# Terminal 1
source venv/bin/activate
python app.py

# Terminal 2
python -m http.server 8000
```

### Step 2: Use Deep Analysis
1. Go to http://localhost:8000
2. Check ☑️ **"Enable Deep Analysis"**
3. Enter an IP address (e.g., `8.8.8.8`)
4. Click **"Analyze IOCs"**
5. Wait ~30-60 seconds

### Step 3: Download Reports
Click one of:
- **Download JSON Report** - Complete nested data
- **Download CSV Report** - Spreadsheet with all columns
- **Download PDF Report** - Professional formatted document

---

## 📁 Example Report Files

After analysis, you'll get files like:
- `deep_analysis_report_20241212_143022.csv`
- `deep_analysis_report_20241212_143022.json`
- `deep_analysis_report_20241212_143022.pdf`

---

## 🔬 What Makes This "Deep"?

**Standard Analysis** gives you:
- VirusTotal threat intelligence
- Basic IP reputation

**Deep Analysis** ADDS:
- ✅ Geographic location (city, coordinates)
- ✅ Network topology (ASN, CIDR, neighbors)
- ✅ ALL associated domains (not just a few)
- ✅ ALL communicating files (not just a few)
- ✅ Complete DNS records (PTR, MX, NS, TXT, SOA)
- ✅ WHOIS registration data
- ✅ Open port scanning
- ✅ SSL certificate analysis
- ✅ Subnet neighbor discovery
- ✅ Historical DNS changes
- ✅ Subdomain enumeration

All in **downloadable CSV/JSON/PDF** format! Perfect for your network & communications course assignment! 🎓

