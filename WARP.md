# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

**IOC Analyzer** - Enhanced Threat Intelligence IOC (Indicator of Compromise) Analyzer  
A Flask-based web application for analyzing security IOCs (IP addresses, domains, URLs, file hashes, CIDR blocks) using multiple threat intelligence APIs.

**Stack**: Python 3 (Flask) backend + vanilla JavaScript frontend

**Analysis Modes**:
- **Standard Mode**: Fast threat intelligence analysis with VirusTotal, AbuseIPDB, AlienVault OTX
- **Deep Analysis Mode**: Comprehensive network intelligence including DNS, WHOIS, geolocation, ASN, subnet analysis, open ports, SSL certificates, network neighbors, and more

**Export Formats**: JSON, CSV, PDF reports with complete deep analysis data

## Essential Commands

### Environment Setup

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# venv\Scripts\activate   # On Windows

# Install dependencies (includes deep analysis libraries)
pip install -r requirements.txt

# Copy environment template and configure API keys
cp .env.example .env
# Edit .env with your actual API keys

# Primary threat intelligence APIs
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export OTX_API_KEY="your_key_here"

# Deep analysis APIs (optional but recommended)
export IPINFO_API_KEY="your_ipinfo_key"  # Free: 50k/month
export URLSCAN_API_KEY="your_urlscan_key"  # Free: unlimited with rate limits
export SECURITYTRAILS_API_KEY="your_securitytrails_key"  # Free: 50/month
export IPQUALITYSCORE_API_KEY="your_ipquality_key"  # Free: 5k/month

# For multiple API keys (rate limit management):
export VIRUSTOTAL_API_KEY_2="your_backup_key"
export VIRUSTOTAL_API_KEY_3="your_third_key"
```

### Running the Application

```bash
# Start Flask backend (runs on port 5000)
python app.py

# Serve frontend (choose one method, runs on port 8000):
python -m http.server 8000
# OR
npx live-server --port=8000
# OR
php -S localhost:8000

# Access:
# - Frontend: http://localhost:8000
# - Backend API: http://localhost:5000
# - Health check: http://localhost:5000/health
```

### Testing

```bash
# Manual API testing with curl
curl http://localhost:5000/health

# Standard analysis - single IOC
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "8.8.8.8"}'

# Deep analysis - comprehensive network intelligence
curl -X POST http://localhost:5000/analyze/deep \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "8.8.8.8"}'

# Download deep analysis report
curl http://localhost:5000/download-report/json > report.json
curl http://localhost:5000/download-report/csv > report.csv
curl http://localhost:5000/download-report/pdf > report.pdf

# Classify IOC type
curl -X POST http://localhost:5000/classify \
  -H "Content-Type: application/json" \
  -d '{"ioc": "example.com"}'
```

### Development

```bash
# Check Python dependencies
pip list

# Freeze current dependencies
pip freeze > requirements.txt

# Check for hardcoded API keys (should use env vars)
grep -r "API_KEY" --include="*.py" --include="*.js" .
```

## Architecture

### Backend Architecture

The backend follows a layered architecture with two analysis modes:

#### Core Components (`app.py`)

1. **IOCClassifier** - Static classification layer
   - Pattern-based IOC type detection (IP, domain, URL, hash, CIDR)
   - Regex validation for each IOC type
   - Hash type identification (MD5, SHA1, SHA256)

2. **EnhancedThreatIntelligenceAPI** - API integration layer
   - Manages API key rotation for rate limit mitigation
   - Supports multiple API keys per service (configured via numbered env vars)
   - Makes requests to VirusTotal, AbuseIPDB
   - Fetches relational data (associated domains, IPs, files, network contacts)
   - API request limit: 100 items per relational endpoint

3. **EnhancedIOCAnalyzer** - Business logic layer (standard analysis)
   - Orchestrates analysis workflows
   - Combines data from multiple threat intelligence sources
   - Structures results with main analysis + relational data
   - Automatic rate limiting (0.5s delay between API calls)

#### Deep Analysis Components

4. **DeepNetworkAnalyzer** (`deep_analysis.py`) - Comprehensive network intelligence
   - **DNS Analysis**: PTR records, A/AAAA/MX/NS/TXT/SOA/CAA records
   - **WHOIS Data**: Registration info, registrar, creation/expiration dates, contacts
   - **Geolocation**: City, coordinates, timezone, ISP, carrier
   - **ASN Information**: Autonomous System Number, CIDR, description, registry
   - **Subnet Analysis**: /24 network analysis, neighboring IPs (±5), metadata
   - **Port Scanning**: Common ports (21,22,23,25,53,80,443,3306,3389,8080,8443)
   - **SSL/TLS Certificates**: Subject, issuer, validity, SANs
   - **Security Reputation**: Fraud score, proxy/VPN/TOR detection
   - **Historical Data**: DNS history, domain/IP changes over time
   - **Domain Intelligence**: Subdomains, web technology stack, domain age

5. **DeepAnalysisReportGenerator** (`report_generator.py`) - Multi-format reporting
   - **JSON Export**: Complete nested data structure with metadata
   - **CSV Export**: Flattened comprehensive columns (25+ fields)
   - **PDF Export**: Professional formatted reports with sections
   - Automatic filename generation with timestamps

#### Flask Routes

**Standard Analysis**:
- `POST /analyze` - Standard IOC analysis with threat intelligence
- `GET /analyze/<type>/<ioc>` - Quick single IOC analysis

**Deep Analysis**:
- `POST /analyze/deep` - Comprehensive network intelligence analysis
- `GET /download-report/<format>` - Download reports (json/csv/pdf)

**Utility**:
- `POST /classify` - IOC type classification without analysis
- `GET /health` - Backend health check

### Key Backend Features

- **API Key Rotation**: Automatically cycles through multiple API keys (e.g., `VIRUSTOTAL_API_KEY`, `VIRUSTOTAL_API_KEY_2`) to distribute API load
- **Relational Intelligence**: Fetches comprehensive threat context:
  - **IPs**: Associated domains, communicating files, downloaded files
  - **Domains**: Associated IPs, subdomains, communicating files, URLs
  - **Hashes**: Contacted IPs, domains, URLs (network behavior)
- **No Artificial Limits**: Displays ALL available relational data (up to 100 items per API response)

### Frontend Architecture

**Single-page application** with vanilla JavaScript (no framework):

- **`index.html`** - Main UI structure
- **`static/js/script.js`** - IOCAnalyzer class handles:
  - Form validation (real-time and on-blur)
  - API communication with Flask backend
  - Results rendering (displays full relational data)
  - Export functionality (JSON and CSV with complete relational columns)
  - Configuration persistence (localStorage for API keys)
  - Status monitoring
- **`static/css/style.css`** - Styling

### Data Flow

```
User Input → Frontend Validation → POST /analyze → 
IOCClassifier (type detection) → EnhancedIOCAnalyzer → 
EnhancedThreatIntelligenceAPI (with key rotation) →
[VirusTotal API, AbuseIPDB API] → 
Results + Relational Data → Frontend Display → 
Export (JSON/CSV with full relational data)
```

## Important Implementation Details

### API Configuration

- API keys are loaded from environment variables in `app.py`
- **Multiple keys supported** via numbered suffixes (`_2`, `_3`, etc.)
- Keys with placeholder values (`your_actual_...`) are automatically filtered out
- The app displays key counts at startup
- Frontend can also store keys in localStorage (for demo/testing)

### Relational Data Handling

- Backend fetches up to **100 items** per relational endpoint (VirusTotal limit)
- Frontend displays **ALL items** (no truncation like "+15 more")
- CSV export includes semicolon-separated lists of all relational data
- JSON export preserves complete nested structure

### Rate Limiting Strategy

1. Built-in 0.5-second delay between analyses (`time.sleep(0.5)`)
2. Multiple API key rotation distributes load
3. VirusTotal free tier: 4 requests/minute, 500/day

### IOC Classification Logic

Order of detection (from `IOCClassifier.classify_ioc()`):
1. IP address (IPv4/IPv6)
2. CIDR block (contains `/`)
3. URL (has scheme + netloc)
4. Hash (MD5/SHA1/SHA256 pattern)
5. Domain (domain pattern + contains `.`)
6. Unknown (fallback)

### Validation Patterns

- **IPv4**: Uses `ipaddress.IPv4Address()`
- **IPv6**: Uses `ipaddress.IPv6Address()`
- **CIDR**: Uses `ipaddress.ip_network()`, requires `/`
- **Domain**: Regex pattern `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*...`
- **URL**: `urlparse()` with scheme validation (http/https)
- **Hash**: Regex for 32 (MD5), 40 (SHA1), or 64 (SHA256) hex chars

## Project Structure

```
NSCOM03/
├── app.py                    # Flask backend (main application)
├── deep_analysis.py          # Deep network intelligence module
├── report_generator.py       # Multi-format report generation (JSON/CSV/PDF)
├── index.html                # Frontend HTML
├── static/
│   ├── js/
│   │   └── script.js        # Frontend JavaScript (IOCAnalyzer class)
│   └── css/
│       └── style.css        # Styling
├── requirements.txt          # Python dependencies (includes deep analysis libs)
├── .env                      # Environment variables (API keys) - DO NOT COMMIT
├── .env.example              # Environment variable template with API docs
├── venv/                     # Python virtual environment (ignored)
├── READMe.md                # Testing guide with test cases
├── CHANGELOG.md             # Version history and feature updates
└── WARP.md                  # This file
```

## Environment Variables

See `.env.example` for complete template with registration URLs and API limits.

### Primary Threat Intelligence APIs

```bash
VIRUSTOTAL_API_KEY="your_key"          # Free: 4 req/min, 500/day
ABUSEIPDB_API_KEY="your_key"           # Free: 1,000 daily checks
OTX_API_KEY="your_key"                 # Free: Unlimited
```

### Deep Analysis APIs (Free Tier Available)

```bash
IPINFO_API_KEY="your_key"              # Free: 50,000/month - Geolocation, ASN, ISP
URLSCAN_API_KEY="your_key"             # Free: Unlimited with rate limits
WHOISXML_API_KEY="your_key"            # Free: 500/month - WHOIS data
IPQUALITYSCORE_API_KEY="your_key"     # Free: 5,000/month - Reputation
SECURITYTRAILS_API_KEY="your_key"     # Free: 50/month - DNS history
```

### Optional Paid APIs

```bash
SHODAN_API_KEY="your_key"              # Paid: $59/month - Port scanning, banners
CENSYS_API_ID="your_id"                # Free: 250/month - Certificate data
CENSYS_API_SECRET="your_secret"
```

### Backup Keys (Rate Limit Management)

```bash
VIRUSTOTAL_API_KEY_2="backup_key"
VIRUSTOTAL_API_KEY_3="third_key"
ABUSEIPDB_API_KEY_2="backup_key"
```

**Security Note**: 
- Never commit API keys to version control
- Use `.env` file (git-ignored) or export as environment variables  
- Copy `.env.example` to `.env` and add your keys
- The app works with partial keys - missing keys disable specific features

## Deep Analysis Data Coverage

### IP Address Deep Analysis
- **Network Context**: ASN, CIDR, ISP, hosting provider, geolocation (city/coordinates)
- **DNS**: Reverse DNS (PTR records), historical DNS data
- **WHOIS**: Registration data, abuse contacts, network allocation
- **Subnet**: /24 network analysis, neighboring IPs (sampled ±5)
- **Security**: Open ports scan, SSL/TLS certificates, fraud/reputation scores
- **Infrastructure**: Proxy/VPN/TOR detection, hosting type, abuse history

### Domain Deep Analysis  
- **DNS Records**: All record types (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA)
- **WHOIS**: Registrar, creation/expiration dates, registrant info
- **Historical**: IP address changes over time, DNS history
- **Discovery**: Subdomain enumeration (up to 50), nameserver info
- **Security**: SSL certificate analysis, web technology detection
- **Metadata**: Domain age calculation, mail server configuration

### Network Relationships Mapped
- **IP-to-Domain**: Which domains resolve to this IP
- **Domain-to-IP**: Historical and current IP associations
- **Subnet Neighbors**: Other active hosts in same /24
- **ASN Peers**: Infrastructure sharing same autonomous system
- **Certificate Chains**: SSL/TLS issuer relationships

## Common Development Scenarios

### Adding a New IOC Type

1. Add validation method to `IOCClassifier` class
2. Update `classify_ioc()` method to detect the new type
3. Create analysis method in `EnhancedIOCAnalyzer` (e.g., `analyze_newtype()`)
4. Update `analyze_ioc()` dispatcher to route to new handler
5. Update frontend validation in `script.js` (validation rules and error messages)

### Adding a New Threat Intelligence API

1. Add API key to environment variable loading in `app.py`
2. Create API method in `EnhancedThreatIntelligenceAPI` class
3. Call from appropriate analyzer method in `EnhancedIOCAnalyzer`
4. Extend results structure to include new source data
5. Update frontend result display to show new source

### Modifying Export Format

**CSV Export**: Edit `convertToCSV()` function in `script.js`
- Current columns include: IOC, Type, Threat Level, Main Source, detection counts, infrastructure data, and complete relational data (semicolon-separated)

**JSON Export**: Already includes full nested structure, no changes needed

### Debugging API Rate Limits

1. Check API key count at startup: `python app.py` (shows "X key(s) configured")
2. Monitor Flask logs for API response status codes
3. Add more backup keys using numbered environment variables
4. Increase `time.sleep()` delay in analyzer methods if needed

## Testing Reference

See `READMe.md` for comprehensive test cases including:
- Known malicious IOCs for testing detection
- Validation test cases (invalid formats)
- Bulk analysis test data
- Export functionality verification
- Backend connection failure scenarios

## Known Limitations

- VirusTotal free tier: 4 requests/minute, 500/day (use multiple keys to increase capacity)
- AbuseIPDB free tier: Limited requests per day
- Frontend serves from separate port (CORS enabled in Flask)
- No persistent data storage (results exist only in session)
- No authentication/authorization (meant for local/development use)

## Recent Changes (v2.0 - December 2024)

- Increased API relational data limits from 10-20 to **100 items**
- Removed frontend display truncation (show ALL data, no "+X more")
- Added **multiple API key support** with automatic rotation
- Enhanced CSV export with complete relational data columns
- Improved error handling for rate limit scenarios

See `CHANGELOG.md` for detailed version history.

