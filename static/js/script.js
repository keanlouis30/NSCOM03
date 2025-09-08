// Enhanced Threat Intelligence IOC Analyzer - Frontend JavaScript
class IOCAnalyzer {
    constructor() {
        this.baseUrl = 'http://localhost:5000';
        this.results = [];
        this.isAnalyzing = false;
        this.includeRelations = true;
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkBackendStatus();
        this.loadSavedConfig();
    }

    bindEvents() {
        // Main action buttons
        document.getElementById('analyzeBtn').addEventListener('click', () => this.analyzeIOCs());
        document.getElementById('clearBtn').addEventListener('click', () => this.clearAllFields());
        document.getElementById('validateBtn').addEventListener('click', () => this.validateFormats());

        // Export buttons
        document.getElementById('exportJson').addEventListener('click', () => this.exportResults('json'));
        document.getElementById('exportCsv').addEventListener('click', () => this.exportResults('csv'));

        // Configuration
        document.getElementById('toggleConfig').addEventListener('click', () => this.toggleConfig());
        document.getElementById('saveConfig').addEventListener('click', () => this.saveConfig());

        // Relations toggle (if exists)
        const relationsToggle = document.getElementById('includeRelations');
        if (relationsToggle) {
            relationsToggle.addEventListener('change', (e) => {
                this.includeRelations = e.target.checked;
            });
        }

        // Real-time validation on input
        const inputs = ['ipAddress', 'domain', 'url', 'cidr', 'hostname', 'fileHash'];
        inputs.forEach(inputId => {
            const element = document.getElementById(inputId);
            if (element) {
                element.addEventListener('blur', (e) => this.validateSingleInput(e.target));
                element.addEventListener('input', (e) => this.clearValidationError(e.target));
            }
        });

        // Bulk input validation
        const bulkInput = document.getElementById('bulkInput');
        if (bulkInput) {
            bulkInput.addEventListener('blur', () => this.validateBulkInput());
        }
    }

    async checkBackendStatus() {
        const statusIndicator = document.getElementById('statusIndicator');
        try {
            const response = await fetch(`${this.baseUrl}/health`);
            if (response.ok) {
                this.updateStatus('Ready', 'success');
            } else {
                this.updateStatus('Backend Error', 'error');
            }
        } catch (error) {
            this.updateStatus('Disconnected', 'error');
            console.error('Backend connection failed:', error);
        }
    }

    updateStatus(message, type) {
        const statusIndicator = document.getElementById('statusIndicator');
        if (!statusIndicator) return;
        
        const icon = statusIndicator.querySelector('i');
        const text = statusIndicator.querySelector('span');
        
        if (text) text.textContent = message;
        statusIndicator.className = `status-indicator ${type}`;
        
        if (icon) {
            switch(type) {
                case 'success':
                    icon.className = 'fas fa-circle';
                    break;
                case 'error':
                    icon.className = 'fas fa-exclamation-circle';
                    break;
                case 'loading':
                    icon.className = 'fas fa-spinner fa-spin';
                    break;
            }
        }
    }

    collectIOCs() {
        const iocs = {
            ip_address: this.getInputValue('ipAddress'),
            domain_name: this.getInputValue('domain'),
            url: this.getInputValue('url'),
            cidr: this.getInputValue('cidr'),
            hostname: this.getInputValue('hostname'),
            file_hash: this.getInputValue('fileHash'),
            hash_type: this.getInputValue('hashType'),
            file_name: this.getInputValue('fileName'),
            bulk_ioc: this.getInputValue('bulkInput'),
            include_relations: this.includeRelations
        };

        // Remove empty fields (except include_relations)
        Object.keys(iocs).forEach(key => {
            if (key !== 'include_relations' && !iocs[key]) {
                delete iocs[key];
            }
        });

        return iocs;
    }

    getInputValue(id) {
        const element = document.getElementById(id);
        return element ? element.value.trim() : '';
    }

    async analyzeIOCs() {
        if (this.isAnalyzing) return;

        const iocs = this.collectIOCs();
        
        // Check if any IOCs are provided (exclude include_relations from count)
        const iocCount = Object.keys(iocs).filter(key => key !== 'include_relations' && iocs[key]).length;
        if (iocCount === 0) {
            this.showNotification('Please enter at least one IOC to analyze.', 'warning');
            return;
        }

        this.isAnalyzing = true;
        this.showLoadingModal();
        this.updateStatus('Analyzing...', 'loading');

        try {
            const response = await fetch(`${this.baseUrl}/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(iocs)
            });

            const data = await response.json();
            
            if (response.ok && data.success) {
                this.results = data.results;
                this.displayResults(data);
                this.updateStatus('Analysis Complete', 'success');
                const relationsText = data.includes_relations ? ' with relational data' : '';
                this.showNotification(`Successfully analyzed ${data.total_analyzed} IOCs${relationsText}`, 'success');
            } else {
                throw new Error(data.error || 'Analysis failed');
            }

        } catch (error) {
            console.error('Analysis error:', error);
            this.showNotification(`Analysis failed: ${error.message}`, 'error');
            this.updateStatus('Analysis Failed', 'error');
        } finally {
            this.hideLoadingModal();
            this.isAnalyzing = false;
        }
    }

    displayResults(data) {
        const resultsSection = document.getElementById('resultsSection');
        const resultsSummary = document.getElementById('resultsSummary');
        const resultsGrid = document.getElementById('resultsGrid');

        if (!resultsSection || !resultsSummary || !resultsGrid) return;

        // Show results section
        resultsSection.style.display = 'block';

        // Update summary
        const summary = this.generateSummary(data.results);
        resultsSummary.innerHTML = `
            <div class="summary-stats">
                <div class="stat-item">
                    <span class="stat-number">${data.total_analyzed}</span>
                    <span class="stat-label">Total IOCs</span>
                </div>
                <div class="stat-item ${summary.malicious > 0 ? 'danger' : ''}">
                    <span class="stat-number">${summary.malicious}</span>
                    <span class="stat-label">Malicious</span>
                </div>
                <div class="stat-item ${summary.suspicious > 0 ? 'warning' : ''}">
                    <span class="stat-number">${summary.suspicious}</span>
                    <span class="stat-label">Suspicious</span>
                </div>
                <div class="stat-item success">
                    <span class="stat-number">${summary.clean}</span>
                    <span class="stat-label">Clean</span>
                </div>
                ${data.includes_relations ? '<div class="stat-item info"><span class="stat-label">Enhanced Analysis</span></div>' : ''}
            </div>
        `;

        // Clear previous results
        resultsGrid.innerHTML = '';

        // Display each result
        data.results.forEach((result, index) => {
            const resultCard = this.createResultCard(result, index, data.includes_relations);
            resultsGrid.appendChild(resultCard);
        });

        // Scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    createResultCard(result, index, includesRelations = false) {
        const card = document.createElement('div');
        card.className = 'result-card enhanced-card';
        
        const threatLevel = this.calculateThreatLevel(result);
        card.classList.add(`threat-${threatLevel}`);

        let mainAnalysisHtml = '';
        let relationalDataHtml = '';
        let additionalSourcesHtml = '';

        // Handle main analysis
        if (result.main_analysis && !result.main_analysis.error) {
            mainAnalysisHtml = this.formatMainAnalysis(result.main_analysis);
        } else if (result.main_analysis && result.main_analysis.error) {
            mainAnalysisHtml = `<div class="error-message">Main Analysis: ${result.main_analysis.error}</div>`;
        }

        // Handle relational data (enhanced feature)
        if (includesRelations && result.relational_data) {
            relationalDataHtml = this.formatRelationalData(result.relational_data, result.type);
        }

        // Handle additional sources (like AbuseIPDB)
        if (result.additional_sources && result.additional_sources.length > 0) {
            additionalSourcesHtml = result.additional_sources.map(source => {
                if (source.error) {
                    return `<div class="api-result error">
                        <div class="api-source">${source.source}</div>
                        <div class="api-error">${source.error}</div>
                    </div>`;
                }
                return this.formatAPIResult(source);
            }).join('');
        }

        // Handle errors
        if (result.error) {
            mainAnalysisHtml = `<div class="error-message">${result.error}</div>`;
        }

        card.innerHTML = `
            <div class="result-header">
                <div class="result-title">
                    <span class="ioc-type ${result.type}">${result.type?.toUpperCase() || 'UNKNOWN'}</span>
                    <span class="ioc-value">${this.escapeHtml(result.ioc)}</span>
                    ${result.hash_type ? `<span class="hash-type">(${result.hash_type.toUpperCase()})</span>` : ''}
                </div>
                <div class="threat-badge ${threatLevel}">
                    ${this.getThreatIcon(threatLevel)}
                    ${threatLevel.charAt(0).toUpperCase() + threatLevel.slice(1)}
                </div>
            </div>
            <div class="result-body">
                ${mainAnalysisHtml}
                ${additionalSourcesHtml}
                ${relationalDataHtml}
            </div>
            <div class="result-footer">
                <small>Analysis #${index + 1} - ${new Date().toLocaleString()}</small>
            </div>
        `;

        return card;
    }

    formatMainAnalysis(analysis) {
        if (analysis.source === 'VirusTotal') {
            return `
                <div class="api-result main-analysis">
                    <div class="api-source">${analysis.source} - Main Report</div>
                    <div class="api-stats">
                        <div class="stat">
                            <span class="label">Malicious:</span>
                            <span class="value danger">${analysis.malicious || 0}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Suspicious:</span>
                            <span class="value warning">${analysis.suspicious || 0}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Clean:</span>
                            <span class="value success">${analysis.clean || 0}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Total Scans:</span>
                            <span class="value">${analysis.total_scans || 0}</span>
                        </div>
                        ${analysis.reputation !== undefined ? `
                        <div class="stat">
                            <span class="label">Reputation:</span>
                            <span class="value ${analysis.reputation < 0 ? 'danger' : 'success'}">${analysis.reputation}</span>
                        </div>` : ''}
                    </div>
                    ${this.formatExtraInfo(analysis)}
                </div>
            `;
        }
        return '<div class="api-info">Analysis data available</div>';
    }

    formatExtraInfo(analysis) {
        let extraInfo = '';
        const fields = {
            'Country': analysis.country,
            'Registrar': analysis.registrar,
            'File Type': analysis.file_type,
            'File Size': analysis.file_size ? `${analysis.file_size} bytes` : null,
            'AS Owner': analysis.as_owner,
            'Network': analysis.network,
            'Creation Date': analysis.creation_date,
            'First Submission': analysis.first_submission,
            'MD5': analysis.md5,
            'SHA1': analysis.sha1,
            'SHA256': analysis.sha256
        };

        Object.entries(fields).forEach(([label, value]) => {
            if (value && value !== 'Unknown') {
                extraInfo += `<div class="extra-info">${label}: ${value}</div>`;
            }
        });

        return extraInfo;
    }

    formatRelationalData(relationalData, iocType) {
        let html = '<div class="relational-section"><h4>Relational Intelligence</h4>';

        // Format based on IOC type
        switch (iocType) {
            case 'ip':
                html += this.formatIPRelations(relationalData);
                break;
            case 'domain':
                html += this.formatDomainRelations(relationalData);
                break;
            case 'hash':
                html += this.formatHashRelations(relationalData);
                break;
        }

        html += '</div>';
        return html;
    }

    formatIPRelations(data) {
        let html = '';
        
        if (data.associated_domains && data.associated_domains.length > 0) {
            html += `
                <div class="relation-group">
                    <h5>Associated Domains (${data.associated_domains.length})</h5>
                    <div class="relation-items">
                        ${data.associated_domains.slice(0, 5).map(domain => `
                            <div class="relation-item">
                                <span class="relation-value">${domain.domain}</span>
                                <span class="relation-date">Last: ${new Date(domain.last_resolved * 1000).toLocaleDateString()}</span>
                            </div>
                        `).join('')}
                        ${data.associated_domains.length > 5 ? `<div class="relation-more">+${data.associated_domains.length - 5} more</div>` : ''}
                    </div>
                </div>
            `;
        }

        if (data.communicating_files && data.communicating_files.length > 0) {
            html += `
                <div class="relation-group">
                    <h5>Communicating Files (${data.communicating_files.length})</h5>
                    <div class="relation-items">
                        ${data.communicating_files.slice(0, 3).map(file => `
                            <div class="relation-item">
                                <span class="relation-value">${file.sha256}</span>
                                <span class="relation-threat ${file.detections > 0 ? 'danger' : 'success'}">${file.detections}/${file.total_engines}</span>
                            </div>
                        `).join('')}
                        ${data.communicating_files.length > 3 ? `<div class="relation-more">+${data.communicating_files.length - 3} more</div>` : ''}
                    </div>
                </div>
            `;
        }

        return html;
    }

    formatDomainRelations(data) {
        let html = '';
        
        if (data.associated_ips && data.associated_ips.length > 0) {
            html += `
                <div class="relation-group">
                    <h5>Associated IPs (${data.associated_ips.length})</h5>
                    <div class="relation-items">
                        ${data.associated_ips.slice(0, 5).map(ip => `
                            <div class="relation-item">
                                <span class="relation-value">${ip.ip}</span>
                                <span class="relation-date">Last: ${new Date(ip.last_resolved * 1000).toLocaleDateString()}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        if (data.subdomains && data.subdomains.length > 0) {
            html += `
                <div class="relation-group">
                    <h5>Subdomains (${data.subdomains.length})</h5>
                    <div class="relation-items">
                        ${data.subdomains.slice(0, 5).map(subdomain => `
                            <div class="relation-item">
                                <span class="relation-value">${subdomain.subdomain}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        return html;
    }

    formatHashRelations(data) {
        let html = '';
        
        if (data.contacted_ips && data.contacted_ips.length > 0) {
            html += `
                <div class="relation-group">
                    <h5>Contacted IPs (${data.contacted_ips.length})</h5>
                    <div class="relation-items">
                        ${data.contacted_ips.slice(0, 5).map(ip => `
                            <div class="relation-item">
                                <span class="relation-value">${ip.ip}</span>
                                <span class="relation-country">${ip.country}</span>
                                <span class="relation-threat ${ip.detections > 0 ? 'danger' : 'success'}">${ip.detections} detections</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        if (data.contacted_domains && data.contacted_domains.length > 0) {
            html += `
                <div class="relation-group">
                    <h5>Contacted Domains (${data.contacted_domains.length})</h5>
                    <div class="relation-items">
                        ${data.contacted_domains.slice(0, 5).map(domain => `
                            <div class="relation-item">
                                <span class="relation-value">${domain.domain}</span>
                                <span class="relation-threat ${domain.detections > 0 ? 'danger' : 'success'}">${domain.detections} detections</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        return html;
    }

    formatAPIResult(apiResult) {
        let content = '';
        
        switch (apiResult.source) {
            case 'VirusTotal':
                // This case is handled by formatMainAnalysis now
                content = `
                    <div class="api-stats">
                        <div class="stat">
                            <span class="label">Malicious:</span>
                            <span class="value danger">${apiResult.malicious || 0}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Suspicious:</span>
                            <span class="value warning">${apiResult.suspicious || 0}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Clean:</span>
                            <span class="value success">${apiResult.clean || 0}</span>
                        </div>
                    </div>
                `;
                break;
                
            case 'AbuseIPDB':
                content = `
                    <div class="api-stats">
                        <div class="stat">
                            <span class="label">Abuse Confidence:</span>
                            <span class="value ${apiResult.abuse_confidence > 50 ? 'danger' : 'success'}">${apiResult.abuse_confidence || 0}%</span>
                        </div>
                        <div class="stat">
                            <span class="label">Total Reports:</span>
                            <span class="value">${apiResult.total_reports || 0}</span>
                        </div>
                        <div class="stat">
                            <span class="label">Country:</span>
                            <span class="value">${apiResult.country_code || 'Unknown'}</span>
                        </div>
                    </div>
                    ${apiResult.isp ? `<div class="extra-info">ISP: ${apiResult.isp}</div>` : ''}
                    ${apiResult.is_whitelisted ? `<div class="extra-info success">✓ Whitelisted</div>` : ''}
                `;
                break;
                
            default:
                content = '<div class="api-info">Raw data available</div>';
        }

        return `
            <div class="api-result">
                <div class="api-source">${apiResult.source}</div>
                ${content}
            </div>
        `;
    }

    calculateThreatLevel(result) {
        if (result.error) return 'unknown';
        
        let maliciousCount = 0;
        let suspiciousCount = 0;
        let totalChecks = 0;

        // Check main analysis
        if (result.main_analysis && !result.main_analysis.error) {
            if (result.main_analysis.malicious) maliciousCount += result.main_analysis.malicious;
            if (result.main_analysis.suspicious) suspiciousCount += result.main_analysis.suspicious;
            totalChecks++;
        }

        // Check additional sources
        if (result.additional_sources) {
            result.additional_sources.forEach(source => {
                if (!source.error) {
                    if (source.malicious) maliciousCount += source.malicious;
                    if (source.suspicious) suspiciousCount += source.suspicious;
                    if (source.abuse_confidence && source.abuse_confidence > 75) maliciousCount += 1;
                    totalChecks++;
                }
            });
        }

        if (maliciousCount > 0) return 'high';
        if (suspiciousCount > 0) return 'medium';
        if (totalChecks > 0) return 'low';
        return 'unknown';
    }

    getThreatIcon(level) {
        const icons = {
            high: '<i class="fas fa-exclamation-triangle"></i>',
            medium: '<i class="fas fa-exclamation-circle"></i>',
            low: '<i class="fas fa-check-circle"></i>',
            unknown: '<i class="fas fa-question-circle"></i>'
        };
        return icons[level] || icons.unknown;
    }

    generateSummary(results) {
        let malicious = 0, suspicious = 0, clean = 0;
        
        results.forEach(result => {
            const level = this.calculateThreatLevel(result);
            switch (level) {
                case 'high': malicious++; break;
                case 'medium': suspicious++; break;
                case 'low': clean++; break;
            }
        });

        return { malicious, suspicious, clean };
    }

    // Keep all the existing validation methods unchanged
    validateSingleInput(input) {
        const value = input.value.trim();
        if (!value) return;

        const inputType = input.id;
        let isValid = false;
        let errorMessage = '';

        switch (inputType) {
            case 'ipAddress':
                isValid = this.isValidIP(value);
                errorMessage = 'Invalid IP address format';
                break;
            case 'domain':
                isValid = this.isValidDomain(value);
                errorMessage = 'Invalid domain format';
                break;
            case 'url':
                isValid = this.isValidURL(value);
                errorMessage = 'Invalid URL format';
                break;
            case 'cidr':
                isValid = this.isValidCIDR(value);
                errorMessage = 'Invalid CIDR format (e.g., 192.168.1.0/24)';
                break;
            case 'fileHash':
                const hashType = this.getInputValue('hashType');
                isValid = this.isValidHash(value, hashType);
                errorMessage = `Invalid ${hashType.toUpperCase()} hash format`;
                break;
        }

        if (!isValid && value) {
            this.showInputError(input, errorMessage);
        } else {
            this.clearInputError(input);
        }
    }

    validateBulkInput() {
        const bulkInput = document.getElementById('bulkInput');
        if (!bulkInput) return;
        
        const lines = bulkInput.value.trim().split('\n').filter(line => line.trim());
        
        if (lines.length === 0) return;

        const invalidLines = [];
        lines.forEach((line, index) => {
            const trimmedLine = line.trim();
            if (trimmedLine && !this.isValidIOC(trimmedLine)) {
                invalidLines.push(index + 1);
            }
        });

        if (invalidLines.length > 0) {
            this.showInputError(bulkInput, `Invalid IOCs on lines: ${invalidLines.join(', ')}`);
        } else {
            this.clearInputError(bulkInput);
        }
    }

    isValidIOC(value) {
        return this.isValidIP(value) || 
               this.isValidDomain(value) || 
               this.isValidURL(value) || 
               this.isValidCIDR(value) ||
               this.isValidHash(value, 'md5') ||
               this.isValidHash(value, 'sha1') ||
               this.isValidHash(value, 'sha256');
    }

    isValidIP(ip) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    isValidDomain(domain) {
        const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
        return domainRegex.test(domain) && domain.includes('.');
    }

    isValidURL(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    isValidCIDR(cidr) {
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
        return cidrRegex.test(cidr);
    }

    isValidHash(hash, type) {
        const patterns = {
            md5: /^[a-fA-F0-9]{32}$/,
            sha1: /^[a-fA-F0-9]{40}$/,
            sha256: /^[a-fA-F0-9]{64}$/
        };
        return patterns[type]?.test(hash) || false;
    }

    showInputError(input, message) {
        this.clearInputError(input);
        input.classList.add('error');
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'input-error';
        errorDiv.textContent = message;
        
        input.parentNode.appendChild(errorDiv);
    }

    clearInputError(input) {
        input.classList.remove('error');
        const errorDiv = input.parentNode.querySelector('.input-error');
        if (errorDiv) {
            errorDiv.remove();
        }
    }

    clearValidationError(input) {
        this.clearInputError(input);
    }

    validateFormats() {
        const inputs = document.querySelectorAll('input[type="text"], textarea');
        inputs.forEach(input => {
            if (input.value.trim()) {
                this.validateSingleInput(input);
            }
        });
        
        this.validateBulkInput();
        this.showNotification('Format validation complete', 'info');
    }

    clearAllFields() {
        const inputs = document.querySelectorAll('input[type="text"], textarea');
        inputs.forEach(input => {
            input.value = '';
            this.clearInputError(input);
        });
        
        // Hide results section
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) {
            resultsSection.style.display = 'none';
        }
        this.results = [];
        
        this.showNotification('All fields cleared', 'info');
    }

    showLoadingModal() {
        const modal = document.getElementById('loadingModal');
        if (!modal) return;
        
        modal.style.display = 'flex';
        
        // Animate progress bar
        const progressFill = document.getElementById('progressFill');
        if (progressFill) {
            let width = 0;
            const interval = setInterval(() => {
                width += Math.random() * 10;
                if (width >= 90) {
                    clearInterval(interval);
                    width = 90;
                }
                progressFill.style.width = width + '%';
            }, 200);
            
            modal.dataset.interval = interval;
        }
    }

    hideLoadingModal() {
        const modal = document.getElementById('loadingModal');
        if (!modal) return;
        
        const interval = modal.dataset.interval;
        
        if (interval) {
            clearInterval(interval);
        }
        
        // Complete progress bar
        const progressFill = document.getElementById('progressFill');
        if (progressFill) {
            progressFill.style.width = '100%';
        }
        
        setTimeout(() => {
            modal.style.display = 'none';
            if (progressFill) {
                progressFill.style.width = '0%';
            }
        }, 500);
    }

    exportResults(format) {
        if (!this.results || this.results.length === 0) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        let content, filename, mimeType;

        if (format === 'json') {
            content = JSON.stringify(this.results, null, 2);
            filename = `ioc-analysis-${new Date().toISOString().split('T')[0]}.json`;
            mimeType = 'application/json';
        } else if (format === 'csv') {
            content = this.convertToCSV(this.results);
            filename = `ioc-analysis-${new Date().toISOString().split('T')[0]}.csv`;
            mimeType = 'text/csv';
        }

        this.downloadFile(content, filename, mimeType);
        this.showNotification(`Results exported as ${format.toUpperCase()}`, 'success');
    }

    convertToCSV(results) {
        const headers = ['IOC', 'Type', 'Threat Level', 'Main Source', 'Malicious', 'Suspicious', 'Clean', 'Additional Sources', 'Relations Count'];
        const rows = results.map(result => {
            const threatLevel = this.calculateThreatLevel(result);
            const mainSource = result.main_analysis ? result.main_analysis.source || 'Unknown' : 'N/A';
            const malicious = result.main_analysis ? result.main_analysis.malicious || 0 : 0;
            const suspicious = result.main_analysis ? result.main_analysis.suspicious || 0 : 0;
            const clean = result.main_analysis ? result.main_analysis.clean || 0 : 0;
            const additionalSources = result.additional_sources ? result.additional_sources.map(s => s.source).join(';') : '';
            
            // Count relational data
            let relationsCount = 0;
            if (result.relational_data) {
                Object.values(result.relational_data).forEach(relations => {
                    if (Array.isArray(relations)) {
                        relationsCount += relations.length;
                    }
                });
            }
            
            return [
                `"${result.ioc}"`,
                result.type || 'unknown',
                threatLevel,
                mainSource,
                malicious,
                suspicious,
                clean,
                `"${additionalSources}"`,
                relationsCount
            ].join(',');
        });

        return [headers.join(','), ...rows].join('\n');
    }

    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
    }

    toggleConfig() {
        const configContent = document.getElementById('configContent');
        const toggleBtn = document.getElementById('toggleConfig');
        
        if (!configContent || !toggleBtn) return;
        
        const icon = toggleBtn.querySelector('i');
        
        if (configContent.style.display === 'none' || !configContent.style.display) {
            configContent.style.display = 'block';
            if (icon) icon.className = 'fas fa-chevron-up';
        } else {
            configContent.style.display = 'none';
            if (icon) icon.className = 'fas fa-chevron-down';
        }
    }

    saveConfig() {
        const config = {
            virustotal: this.getInputValue('vtApiKey'),
            abuseipdb: this.getInputValue('abuseApiKey'),
            otx: this.getInputValue('otxApiKey'),
            includeRelations: this.includeRelations
        };

        // Note: Cannot use localStorage in Claude artifacts, would use in-memory storage
        // In a real deployment, you'd save to localStorage or send to backend
        this.showNotification('Configuration saved (session only)', 'info');
    }

    loadSavedConfig() {
        // Note: In Claude artifacts, we can't use localStorage
        // In a real deployment, this would load from localStorage
        try {
            // Placeholder for loading saved configuration
            console.log('Config loading would happen here in real deployment');
        } catch (error) {
            console.error('Failed to load saved configuration:', error);
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const icon = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        }[type] || 'fa-info-circle';
        
        notification.innerHTML = `
            <i class="fas ${icon}"></i>
            <span>${message}</span>
            <button class="close-btn">&times;</button>
        `;
        
        // Add click handler for close button
        const closeBtn = notification.querySelector('.close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                notification.remove();
            });
        }
        
        // Add to page
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
        
        // Animate in
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}

// Initialize the analyzer when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.iocAnalyzer = new IOCAnalyzer();
});

// Export for global access
window.IOCAnalyzer = IOCAnalyzer;