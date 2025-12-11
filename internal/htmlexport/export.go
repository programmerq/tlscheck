package htmlexport

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"

	"github.com/programmerq/tlscheck/internal/runner"
)

// Write generates a self-contained HTML file containing the execution results.
// The HTML includes embedded JSON data and all necessary CSS/JavaScript for visualization.
func Write(w io.Writer, exec runner.Execution) error {
	jsonData, err := json.MarshalIndent(exec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal execution data: %w", err)
	}

	tmpl, err := template.New("tlscheck").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	data := struct {
		JSONData           template.JS
		RawJSONDataEscaped template.JSStr
	}{
		JSONData:           template.JS(jsonData),    // Use template.JS to mark as safe JavaScript
		RawJSONDataEscaped: template.JSStr(jsonData), // JSStr for safe string escaping
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLS Check Results</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2em;
        }

        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
            font-size: 1.5em;
        }

        h3 {
            color: #34495e;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 1.2em;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }

        .summary-card .label {
            font-size: 0.85em;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .summary-card .value {
            font-size: 1.4em;
            font-weight: 600;
            color: #2c3e50;
            margin-top: 5px;
        }

        .status-success {
            border-left-color: #27ae60;
        }

        .status-failure {
            border-left-color: #e74c3c;
        }

        .status-warning {
            border-left-color: #f39c12;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }

        th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
        }

        /* Allow SNI and ALPN columns to wrap */
        td:nth-child(3), td:nth-child(4) {
            word-break: break-all;
            max-width: 200px;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .badge-success {
            background: #d4edda;
            color: #155724;
        }

        .badge-failure {
            background: #f8d7da;
            color: #721c24;
        }

        .badge-info {
            background: #d1ecf1;
            color: #0c5460;
        }

        .cert-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin: 10px 0;
            font-family: "Courier New", monospace;
            font-size: 0.9em;
        }

        .collapsible {
            cursor: pointer;
            padding: 10px;
            background: #ecf0f1;
            border: none;
            width: 100%;
            text-align: left;
            border-radius: 4px;
            font-size: 1em;
            margin: 5px 0;
        }

        .collapsible:hover {
            background: #bdc3c7;
        }

        .collapsible.active {
            background: #34495e;
            color: white;
        }

        .content {
            display: none;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 4px;
            margin-bottom: 10px;
        }

        .content.active {
            display: block;
        }

        pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.9em;
            line-height: 1.5;
        }

        /* JSON syntax highlighting */
        .json-key {
            color: #e67e22;
        }

        .json-string {
            color: #2ecc71;
        }

        .json-number {
            color: #3498db;
        }

        .json-boolean {
            color: #e74c3c;
        }

        .json-null {
            color: #95a5a6;
        }

        .filter-bar {
            margin: 20px 0;
            padding: 15px;
            background: #ecf0f1;
            border-radius: 6px;
        }

        .filter-bar label {
            margin-right: 15px;
            font-weight: 600;
        }

        .filter-bar select, .filter-bar input {
            padding: 8px;
            border: 1px solid #bdc3c7;
            border-radius: 4px;
            margin-right: 10px;
        }

        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }

        .metadata-item {
            padding: 8px;
            background: #f8f9fa;
            border-radius: 4px;
        }

        .metadata-item .key {
            font-weight: 600;
            color: #7f8c8d;
            font-size: 0.9em;
        }

        .metadata-item .value {
            color: #2c3e50;
            margin-top: 3px;
        }

        .error-message {
            color: #e74c3c;
            background: #fadbd8;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }

        .cert-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
            transition: all 0.3s ease;
        }

        .cert-card.highlight {
            background: #fff3cd;
            border-color: #ffc107;
            box-shadow: 0 0 10px rgba(255, 193, 7, 0.5);
        }

        .cert-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .cert-header {
            font-weight: 600;
            font-size: 1.1em;
            margin-bottom: 10px;
            color: #2c3e50;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .cert-actions {
            display: flex;
            gap: 5px;
        }

        .btn-small {
            padding: 4px 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8em;
            background: #3498db;
            color: white;
            transition: background 0.2s;
        }

        .btn-small:hover {
            background: #2980b9;
        }

        .cert-raw {
            margin-top: 10px;
            display: none;
        }

        .cert-raw.show {
            display: block;
        }

        .cert-raw pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.8em;
            max-height: 300px;
        }

        .cert-link {
            color: #3498db;
            text-decoration: none;
            cursor: pointer;
        }

        .cert-link:hover {
            text-decoration: underline;
        }

        .button-group {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }

        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            transition: background 0.2s;
        }

        .btn-primary {
            background: #3498db;
            color: white;
        }

        .btn-primary:hover {
            background: #2980b9;
        }

        .btn-secondary {
            background: #95a5a6;
            color: white;
        }

        .btn-secondary:hover {
            background: #7f8c8d;
        }

        .copy-feedback {
            display: inline-block;
            margin-left: 10px;
            padding: 4px 12px;
            background: #27ae60;
            color: white;
            border-radius: 4px;
            font-size: 0.9em;
            opacity: 0;
            transition: opacity 0.3s;
        }

        .copy-feedback.show {
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>TLS Check Results</h1>
        <div id="app"></div>
        <h2>Raw JSON Data</h2>
        <div class="button-group">
            <button class="btn btn-primary" onclick="downloadJSON()">Download JSON</button>
            <button class="btn btn-secondary" onclick="copyJSON()">Copy to Clipboard</button>
            <span id="copy-feedback" class="copy-feedback">Copied!</span>
        </div>
        <button class="collapsible">Show/Hide Raw JSON</button>
        <div class="content">
            <pre id="raw-json"></pre>
        </div>
    </div>

    <script>
        // Embedded JSON data - directly embedded as JavaScript object literal
        const tlsCheckData = {{.JSONData}};

        function renderSystemInfo() {
            const network = tlsCheckData.network || {};
            const system = network.system || {};
            
            let html = '<h2>System Information</h2>';
            html += '<p style="color: #7f8c8d; margin-bottom: 15px;">Collected from: <strong>' + escapeHtml(system.hostname || 'unknown') + '</strong></p>';
            html += '<div class="metadata">';
            html += createMetadataItem('Hostname', system.hostname || 'N/A');
            html += createMetadataItem('Operating System', system.os || 'N/A');
            html += createMetadataItem('Architecture', system.architecture || 'N/A');
            if (system.captured_at) {
                html += createMetadataItem('Captured At', new Date(system.captured_at).toLocaleString());
            }
            html += '</div>';
            
            return html;
        }

        function renderSummary() {
            const args = tlsCheckData.arguments || {};
            const results = tlsCheckData.results || [];
            const plan = tlsCheckData.plan || {};

            const connectedCount = results.filter(r => !r.failure).length;
            const issuesCount = results.filter(r => r.failure).length;

            let html = '<h2>Cluster Configuration</h2>';
            html += '<div class="summary">';
            html += createSummaryCard('Cluster', args.cluster_name || 'N/A');
            html += createSummaryCard('Proxy Address', args.public_addr || 'N/A');
            html += createSummaryCard('Teleport Version', args.teleport_version || 'N/A');
            html += createSummaryCard('TLS Routing', args.tls_routing_enabled ? 'Enabled' : 'Disabled', 
                args.tls_routing_enabled ? 'status-success' : 'status-warning');
            html += createSummaryCard('Total Probes', results.length.toString());
            html += createSummaryCard('Connected', connectedCount.toString());
            if (issuesCount > 0) {
                html += createSummaryCard('Issues Detected', issuesCount.toString(), 'status-warning');
            }
            html += '</div>';

            return html;
        }

        function createSummaryCard(label, value, statusClass = '') {
            return ` + "`" + `
                <div class="summary-card ${statusClass}">
                    <div class="label">${label}</div>
                    <div class="value">${value}</div>
                </div>
            ` + "`" + `;
        }

        function renderResults() {
            const results = tlsCheckData.results || [];
            const certs = tlsCheckData.certs || {};

            if (results.length === 0) {
                return '<p>No probe results available.</p>';
            }

            let html = '<h2>Connection Behaviors</h2>';
            html += '<div class="filter-bar">';
            html += '<label>Filter: </label>';
            html += '<select id="filter-status" onchange="filterResults()">';
            html += '<option value="all">All Results</option>';
            html += '<option value="success">Connected Only</option>';
            html += '<option value="failure">Issues Only</option>';
            html += '</select>';
            html += '</div>';

            html += '<table id="results-table">';
            html += '<thead><tr>';
            html += '<th>Service</th>';
            html += '<th>Target</th>';
            html += '<th>SNI</th>';
            html += '<th>ALPN</th>';
            html += '<th>Behavior</th>';
            html += '</tr></thead><tbody>';

            results.forEach((result, idx) => {
                const target = result.target || {};
                const failure = result.failure;
                const status = failure ? 'failure' : 'success';
                
                html += ` + "`" + `<tr class="result-row" data-status="${status}">` + "`" + `;
                html += ` + "`" + `<td>${escapeHtml(target.service_key || 'N/A')}</td>` + "`" + `;
                html += ` + "`" + `<td>${escapeHtml(target.address || 'N/A')}:${target.port || 'N/A'}</td>` + "`" + `;
                html += ` + "`" + `<td>${escapeHtml(target.primary_sni || 'N/A')}</td>` + "`" + `;
                html += ` + "`" + `<td>${escapeHtml((target.alpns || []).join(', ') || 'N/A')}</td>` + "`" + `;
                
                if (failure) {
                    html += ` + "`" + `<td>` + "`" + `;
                    html += ` + "`" + `<div><strong>${escapeHtml(failure.kind || 'unknown')}</strong></div>` + "`" + `;
                    html += ` + "`" + `<div style="color: #7f8c8d; font-size: 0.9em;">${escapeHtml(failure.message || 'N/A')}</div>` + "`" + `;
                    html += ` + "`" + `</td>` + "`" + `;
                } else {
                    const details = [];
                    if (result.negotiated_protocol) details.push(` + "`" + `Protocol: ${result.negotiated_protocol}` + "`" + `);
                    if (result.tls_version) details.push(` + "`" + `TLS: ${result.tls_version}` + "`" + `);
                    if (result.leaf_fingerprint) {
                        const cert = certs[result.leaf_fingerprint];
                        if (cert && cert.subject && cert.subject.common_name) {
                            details.push(` + "`" + `Cert: <a class="cert-link" onclick="jumpToCert('${result.leaf_fingerprint}')">${escapeHtml(cert.subject.common_name)}</a>` + "`" + `);
                        }
                    }
                    html += ` + "`" + `<td>` + "`" + `;
                    if (details.length > 0) {
                        html += details.join('<br>');
                    } else {
                        html += 'Connected';
                    }
                    html += ` + "`" + `</td>` + "`" + `;
                }
                
                html += '</tr>';
            });

            html += '</tbody></table>';
            return html;
        }

        function renderNetworkInfo() {
            const network = tlsCheckData.network || {};
            let html = '<h2>Network Configuration</h2>';

            // Proxy info
            if (network.proxy_config) {
                html += '<h3>Proxy Configuration</h3>';
                html += '<div class="metadata">';
                const proxy = network.proxy_config;
                if (proxy.https_proxy) {
                    html += createMetadataItem('HTTPS Proxy', proxy.https_proxy);
                }
                if (proxy.http_proxy) {
                    html += createMetadataItem('HTTP Proxy', proxy.http_proxy);
                }
                if (proxy.no_proxy) {
                    html += createMetadataItem('No Proxy', proxy.no_proxy);
                }
                html += '</div>';
            }

            // VPN detection
            if (network.vpn && (network.vpn.detected || (network.vpn.interfaces && network.vpn.interfaces.length > 0))) {
                html += '<h3>VPN Detection</h3>';
                html += ` + "`" + `<p><strong>VPN Detected:</strong> ${network.vpn.detected ? 'Yes' : 'No'}</p>` + "`" + `;
                if (network.vpn.interfaces && network.vpn.interfaces.length > 0) {
                    html += '<p><strong>VPN Interfaces:</strong></p>';
                    html += '<div class="metadata">';
                    network.vpn.interfaces.forEach(iface => {
                        const details = [];
                        if (iface.name) details.push(` + "`" + `Name: ${iface.name}` + "`" + `);
                        if (iface.type) details.push(` + "`" + `Type: ${iface.type}` + "`" + `);
                        if (iface.status) details.push(` + "`" + `Status: ${iface.status}` + "`" + `);
                        if (iface.addresses && iface.addresses.length > 0) {
                            details.push(` + "`" + `Addresses: ${iface.addresses.join(', ')}` + "`" + `);
                        }
                        html += createMetadataItem(iface.name || 'VPN Interface', details.join(' | '));
                    });
                    html += '</div>';
                }
            }

            return html;
        }

        function renderCertificates() {
            const certs = tlsCheckData.certs || {};
            const certEntries = Object.entries(certs);

            if (certEntries.length === 0) {
                return '';
            }

            let html = '<h2>Certificates</h2>';
            html += '<div class="cert-grid">';
            
            certEntries.forEach(([fingerprint, cert]) => {
                html += ` + "`" + `<div class="cert-card" id="cert-${fingerprint}">` + "`" + `;
                html += '<div class="cert-header">';
                
                // Display common name or "Unknown Certificate"
                html += '<span>';
                if (cert.subject && cert.subject.common_name) {
                    html += escapeHtml(cert.subject.common_name);
                } else {
                    html += 'Unknown Certificate';
                }
                html += '</span>';
                
                // Add action buttons
                html += '<div class="cert-actions">';
                html += ` + "`" + `<button class="btn-small" onclick="toggleRawCert('${fingerprint}')">Show Raw</button>` + "`" + `;
                html += ` + "`" + `<button class="btn-small" onclick="copyCert('${fingerprint}')">Copy</button>` + "`" + `;
                html += '</div>';
                
                html += '</div>';
                
                html += '<div class="metadata">';
                
                // Fingerprint
                html += createMetadataItem('Fingerprint', fingerprint);
                
                // Subject
                if (cert.subject) {
                    const subjectParts = [];
                    if (cert.subject.common_name) subjectParts.push(` + "`" + `CN=${cert.subject.common_name}` + "`" + `);
                    if (cert.subject.organization) subjectParts.push(` + "`" + `O=${cert.subject.organization.join(', ')}` + "`" + `);
                    if (cert.subject.country) subjectParts.push(` + "`" + `C=${cert.subject.country.join(', ')}` + "`" + `);
                    if (subjectParts.length > 0) {
                        html += createMetadataItem('Subject', subjectParts.join(', '));
                    }
                }
                
                // Issuer
                if (cert.issuer) {
                    const issuerParts = [];
                    if (cert.issuer.common_name) issuerParts.push(` + "`" + `CN=${cert.issuer.common_name}` + "`" + `);
                    if (cert.issuer.organization) issuerParts.push(` + "`" + `O=${cert.issuer.organization.join(', ')}` + "`" + `);
                    if (cert.issuer.country) issuerParts.push(` + "`" + `C=${cert.issuer.country.join(', ')}` + "`" + `);
                    if (issuerParts.length > 0) {
                        html += createMetadataItem('Issuer', issuerParts.join(', '));
                    }
                }
                
                // Validity
                if (cert.validity) {
                    if (cert.validity.not_before) {
                        html += createMetadataItem('Valid From', new Date(cert.validity.not_before).toLocaleString());
                    }
                    if (cert.validity.not_after) {
                        html += createMetadataItem('Valid Until', new Date(cert.validity.not_after).toLocaleString());
                    }
                }
                
                // SANs
                if (cert.sans) {
                    const sans = [];
                    if (cert.sans.dns && cert.sans.dns.length > 0) {
                        sans.push(...cert.sans.dns);
                    }
                    if (cert.sans.ip && cert.sans.ip.length > 0) {
                        sans.push(...cert.sans.ip);
                    }
                    if (sans.length > 0) {
                        html += createMetadataItem('SANs', sans.join(', '));
                    }
                }
                
                // Serial Number
                if (cert.serial_number) {
                    html += createMetadataItem('Serial Number', cert.serial_number);
                }
                
                html += '</div>';
                
                // Raw certificate data (hidden by default)
                html += ` + "`" + `<div class="cert-raw" id="cert-raw-${fingerprint}">` + "`" + `;
                html += '<pre>' + escapeHtml(JSON.stringify(cert, null, 2)) + '</pre>';
                html += '</div>';
                
                html += '</div>';
            });

            html += '</div>';
            return html;
        }

        function createMetadataItem(key, value) {
            return ` + "`" + `
                <div class="metadata-item">
                    <div class="key">${escapeHtml(key)}</div>
                    <div class="value">${escapeHtml(value)}</div>
                </div>
            ` + "`" + `;
        }

        function filterResults() {
            const filter = document.getElementById('filter-status').value;
            const rows = document.querySelectorAll('.result-row');
            
            rows.forEach(row => {
                if (filter === 'all') {
                    row.style.display = '';
                } else {
                    row.style.display = row.dataset.status === filter ? '' : 'none';
                }
            });
        }

        function escapeHtml(text) {
            if (text == null) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function syntaxHighlight(json) {
            json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
                let cls = 'json-number';
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        cls = 'json-key';
                    } else {
                        cls = 'json-string';
                    }
                } else if (/true|false/.test(match)) {
                    cls = 'json-boolean';
                } else if (/null/.test(match)) {
                    cls = 'json-null';
                }
                return '<span class="' + cls + '">' + match + '</span>';
            });
        }

        function jumpToCert(fingerprint) {
            const certElement = document.getElementById(` + "`" + `cert-${fingerprint}` + "`" + `);
            if (certElement) {
                // Scroll to certificate
                certElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                
                // Highlight temporarily
                certElement.classList.add('highlight');
                setTimeout(() => {
                    certElement.classList.remove('highlight');
                }, 3000);
            }
        }

        function downloadJSON() {
            const args = tlsCheckData.arguments || {};
            const clusterName = args.cluster_name || 'tlscheck';
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
            const filename = ` + "`" + `${clusterName}-${timestamp}.json` + "`" + `;
            
            const jsonStr = JSON.stringify(tlsCheckData, null, 2);
            const blob = new Blob([jsonStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        function copyJSON() {
            const jsonStr = JSON.stringify(tlsCheckData, null, 2);
            
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(jsonStr).then(() => {
                    showCopyFeedback();
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    fallbackCopy(jsonStr);
                });
            } else {
                fallbackCopy(jsonStr);
            }
        }

        function fallbackCopy(text) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                showCopyFeedback();
            } catch (err) {
                alert('Failed to copy JSON. Please copy manually from the raw JSON section.');
            }
            document.body.removeChild(textarea);
        }

        function showCopyFeedback() {
            const feedback = document.getElementById('copy-feedback');
            feedback.classList.add('show');
            setTimeout(() => {
                feedback.classList.remove('show');
            }, 2000);
        }

        function toggleRawCert(fingerprint) {
            const rawElement = document.getElementById(` + "`" + `cert-raw-${fingerprint}` + "`" + `);
            const button = event.target;
            
            if (rawElement.classList.contains('show')) {
                rawElement.classList.remove('show');
                button.textContent = 'Show Raw';
            } else {
                rawElement.classList.add('show');
                button.textContent = 'Hide Raw';
            }
        }

        function copyCert(fingerprint) {
            const certs = tlsCheckData.certs || {};
            const cert = certs[fingerprint];
            
            if (!cert) {
                return;
            }
            
            const certStr = JSON.stringify(cert, null, 2);
            
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(certStr).then(() => {
                    // Show temporary feedback on the button
                    const button = event.target;
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    setTimeout(() => {
                        button.textContent = originalText;
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy:', err);
                });
            }
        }

        // Initialize the app
        document.addEventListener('DOMContentLoaded', function() {
            const app = document.getElementById('app');
            let content = '';
            
            content += renderSystemInfo();
            content += renderSummary();
            content += renderResults();
            content += renderNetworkInfo();
            content += renderCertificates();
            
            app.innerHTML = content;

            // Display raw JSON with syntax highlighting
            // RawJSONDataEscaped is safely escaped for use in JavaScript string context
            const rawJson = "{{.RawJSONDataEscaped}}";
            document.getElementById('raw-json').innerHTML = syntaxHighlight(rawJson);

            // Setup collapsible sections
            const collapsibles = document.querySelectorAll('.collapsible');
            collapsibles.forEach(coll => {
                coll.addEventListener('click', function() {
                    this.classList.toggle('active');
                    const content = this.nextElementSibling;
                    content.classList.toggle('active');
                });
            });
        });
    </script>
</body>
</html>
`
