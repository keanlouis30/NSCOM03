# IOC Analyzer - Testing Guide & Test Cases

## Setup Instructions

### 1. Backend Setup
```bash
# Clone/setup your project
cd your-project-directory

# Install Python dependencies
pip install flask flask-cors requests

# Set environment variables for API keys
export VIRUSTOTAL_API_KEY="your_actual_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_actual_abuseipdb_api_key" 
export OTX_API_KEY="your_actual_otx_api_key"

# Start Flask backend
python app.py
```

### 2. Frontend Setup
```bash
# Serve HTML files (choose one method):

# Method 1: Python built-in server
python -m http.server 8000

# Method 2: Node.js live-server (if installed)
npx live-server --port=8000

# Method 3: PHP built-in server (if available)
php -S localhost:8000
```

### 3. Access Application
- Frontend: `http://localhost:8000`
- Backend API: `http://localhost:5000`

---

## Test Flow Procedures

### Test Flow 1: Basic Functionality Test
1. **Open Application**: Navigate to `http://localhost:8000`
2. **Check Status**: Verify status indicator shows "Ready" (green)
3. **Single IOC Test**: Enter one IOC in any field
4. **Click Analyze**: Press "Analyze IOCs" button
5. **Verify Loading**: Loading modal should appear with progress bar
6. **Check Results**: Results section should appear with analysis
7. **Verify Export**: Test JSON and CSV export buttons

### Test Flow 2: Validation Testing
1. **Enter Invalid Data**: Input malformed IOCs
2. **Blur Field**: Click outside input field
3. **Check Validation**: Red error messages should appear
4. **Fix Data**: Correct the invalid input
5. **Verify Clear**: Error messages should disappear

### Test Flow 3: Bulk Analysis Test
1. **Clear All Fields**: Click "Clear All" button
2. **Enter Bulk Data**: Paste multiple IOCs in bulk input
3. **Validate Bulk**: Click "Validate Format"
4. **Analyze Bulk**: Click "Analyze IOCs"
5. **Review Results**: Check all IOCs are analyzed

### Test Flow 4: Configuration Test
1. **Open Config**: Click "Configure" button
2. **Enter API Keys**: Add test API keys
3. **Save Config**: Click "Save Configuration"
4. **Verify Storage**: Refresh page and check keys persist

---

## Detailed Test Cases

### Test Case 1: Known Malicious IP Analysis
**Objective**: Test detection of known malicious IP addresses

**Input Data**:
```
IP Address: 185.220.100.240
```

**Expected Results**:
- Type: IP
- VirusTotal: Should show multiple malicious detections
- AbuseIPDB: High abuse confidence (>50%)
- Threat Level: HIGH (red badge)
- Status: Analysis complete

**Test Steps**:
1. Enter `185.220.100.240` in IP Address field
2. Click "Analyze IOCs"
3. Wait for results
4. Verify threat level is HIGH
5. Check both VirusTotal and AbuseIPDB results appear
6. Confirm malicious count > 0

---

### Test Case 2: Clean Domain Analysis
**Objective**: Test analysis of legitimate domain

**Input Data**:
```
Domain Name: google.com
```

**Expected Results**:
- Type: DOMAIN
- VirusTotal: Clean detections, low/no malicious count
- Threat Level: LOW (green badge)
- Additional info: Registrar information shown

**Test Steps**:
1. Clear all previous inputs
2. Enter `google.com` in Domain Name field
3. Click "Analyze IOCs"
4. Verify threat level is LOW
5. Check VirusTotal shows clean results
6. Confirm registrar info is displayed

---

### Test Case 3: Malicious URL Analysis
**Objective**: Test URL classification and analysis

**Input Data**:
```
URL: http://malware-traffic-analysis.net/2019/10/15/index.html
```

**Expected Results**:
- Type: URL
- VirusTotal: May show malicious/suspicious detections
- Threat Level: MEDIUM or HIGH
- Final URL information displayed

**Test Steps**:
1. Enter the test URL in URL field
2. Click "Analyze IOCs"
3. Verify URL is properly classified
4. Check VirusTotal analysis results
5. Confirm final URL is shown if different

---

### Test Case 4: File Hash Analysis
**Objective**: Test hash detection and analysis

**Input Data**:
```
Hash Type: SHA-256
File Hash: 44d88612fea8a8f36de82e1278abb02f  (known test hash)
```

**Expected Results**:
- Type: HASH
- Hash Type: SHA-256 detected
- VirusTotal: File analysis results
- File type and size information

**Test Steps**:
1. Select "SHA-256" from Hash Type dropdown
2. Enter test hash in File Hash field
3. Click "Analyze IOCs"
4. Verify hash type is correctly identified
5. Check file information is displayed

---

### Test Case 5: CIDR Block Analysis
**Objective**: Test CIDR block analysis capability

**Input Data**:
```
CIDR Block: 185.220.100.0/24
```

**Expected Results**:
- Type: CIDR
- AbuseIPDB: Network information
- Possible hosts count
- Reported addresses in range

**Test Steps**:
1. Enter `185.220.100.0/24` in CIDR field
2. Click "Analyze IOCs"
3. Verify CIDR classification
4. Check AbuseIPDB network analysis
5. Confirm host count information

---

### Test Case 6: Bulk Analysis Test
**Objective**: Test multiple IOCs analysis simultaneously

**Input Data** (paste in Bulk Input):
```
8.8.8.8
google.com
https://example.com
185.220.100.240
malicious-domain.tk
d41d8cd98f00b204e9800998ecf8427e
```

**Expected Results**:
- 6 total IOCs analyzed
- Mix of threat levels (HIGH, LOW, MEDIUM)
- Each IOC properly classified
- Summary statistics accurate

**Test Steps**:
1. Clear all individual fields
2. Paste bulk data in "Bulk IOC Input" textarea
3. Click "Analyze IOCs"
4. Verify all 6 IOCs are processed
5. Check variety of threat levels
6. Confirm summary statistics match individual results

---

### Test Case 7: Input Validation Test
**Objective**: Test form validation for invalid inputs

**Invalid Input Examples**:
```
IP Address: 999.999.999.999 (invalid IP)
Domain: invalid-domain-without-tld
URL: not-a-url
Hash: invalid-hash-format
CIDR: 192.168.1.0 (missing /subnet)
```

**Expected Results**:
- Red error messages appear under each invalid field
- Error text describes the validation issue
- "Analyze" button should still work but skip invalid entries
- Validation clears when input is corrected

**Test Steps**:
1. Enter each invalid input in respective fields
2. Click outside each field (blur event)
3. Verify error messages appear
4. Click "Validate Format" button
5. Correct one invalid input
6. Verify error message disappears for corrected field

---

### Test Case 8: Export Functionality Test
**Objective**: Test result export capabilities

**Prerequisites**: Complete Test Case 6 (Bulk Analysis)

**Expected Results**:
- JSON export: Valid JSON file with complete data
- CSV export: Properly formatted CSV with headers
- Filenames include current date
- Files download successfully

**Test Steps**:
1. After completing bulk analysis test
2. Click "Export JSON" button
3. Verify file downloads with correct name format
4. Open JSON file and verify structure
5. Click "Export CSV" button
6. Verify CSV file downloads
7. Open CSV in spreadsheet application
8. Confirm data is properly formatted

---

### Test Case 9: Error Handling Test
**Objective**: Test application behavior with backend errors

**Test Scenarios**:

**A. Backend Offline Test**:
1. Stop Flask backend (`Ctrl+C`)
2. Try to analyze an IOC
3. Verify error notification appears
4. Check status indicator shows "Disconnected"
5. Restart backend and verify recovery

**B. API Key Missing Test**:
1. Ensure API keys are not set in environment
2. Analyze an IOC
3. Check results show API errors
4. Verify application doesn't crash

**Test Steps for Scenario A**:
1. Stop Python Flask application
2. Enter `8.8.8.8` in IP field
3. Click "Analyze IOCs"
4. Verify error notification: "Analysis failed: ..."
5. Check status indicator is red/error state
6. Restart Flask app with `python app.py`
7. Wait for "Ready" status
8. Retry analysis to confirm recovery

---

### Test Case 10: Configuration Persistence Test
**Objective**: Test API key storage and retrieval

**Input Data**:
```
VirusTotal API Key: test-vt-key-12345
AbuseIPDB API Key: test-abuse-key-67890
OTX API Key: test-otx-key-abcdef
```

**Expected Results**:
- Configuration saves to localStorage
- Keys persist after page refresh
- Masked display in password fields

**Test Steps**:
1. Click "Configure" to expand config section
2. Enter test API keys in each field
3. Click "Save Configuration"
4. Verify success notification appears
5. Refresh browser page
6. Click "Configure" again
7. Verify all API keys are still present
8. Check browser DevTools > Application > Local Storage for stored data

---

## 🔧 Debugging Tips

### Common Issues and Solutions:

1. **CORS Errors**: 
   - Ensure Flask app has `CORS(app)` enabled
   - Check browser console for CORS policy errors

2. **Backend Connection Failed**:
   - Verify Flask is running on port 5000
   - Check firewall/antivirus blocking connections

3. **API Rate Limiting**:
   - Built-in 0.5-second delays between API calls
   - Some APIs have daily/hourly limits

4. **Invalid API Keys**:
   - Check environment variables are set correctly
   - Verify API key format and permissions

5. **Results Not Displaying**:
   - Check browser console for JavaScript errors
   - Verify JSON response structure matches expected format

### Browser Console Commands for Testing:
```javascript
// Check if analyzer is loaded
console.log(window.iocAnalyzer);

// Test IOC classification directly
window.iocAnalyzer.isValidIP('8.8.8.8');

// Check saved configuration
console.log(localStorage.getItem('ioc-analyzer-config'));

// Manually trigger analysis (for debugging)
window.iocAnalyzer.analyzeIOCs();
```

---

## Success Criteria

### Minimum Acceptance Criteria:
-  Backend starts without errors
-  Frontend loads and connects to backend
-  At least one IOC type analysis works
-  Results display with proper threat levels
-  Basic input validation functions
-  Export functionality works

### Full Functionality Criteria:
-  All IOC types (IP, Domain, URL, Hash, CIDR) work
-  All API integrations function (VirusTotal, AbuseIPDB)
-  Bulk analysis processes multiple IOCs
-  Input validation catches all invalid formats
-  Export generates valid JSON and CSV files
-  Configuration saves and persists
-  Error handling graceful and informative

## Performance Benchmarks:
- Single IOC analysis: < 5 seconds
- Bulk analysis (10 IOCs): < 30 seconds
- Page load time: < 2 seconds
- Export file generation: < 1 second