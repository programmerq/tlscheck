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
        /* ---- Teleport-inspired theme variables (light default) ---- */
        :root {
            --bg-page:      #F1F2F4;
            --bg-surface:   #FFFFFF;
            --bg-card:      #FBFBFC;
            --text-main:    #000000;
            --text-muted:   rgba(0,0,0,0.54);
            --text-subtle:  rgba(0,0,0,0.36);
            --accent:       #512FC9;
            --accent-hover: #4126A1;
            --border:       rgba(0,0,0,0.18);
            --success:      #007D6B;
            --success-bg:   rgba(0,125,107,0.1);
            --error:        #CC372D;
            --error-bg:     rgba(204,55,45,0.1);
            --warning:      #FFAB00;
            --warning-bg:   rgba(255,171,0,0.1);
            --info:         #0073BA;
            --info-bg:      rgba(0,115,186,0.1);
            --shadow:       rgba(0,0,0,0.08);
            --th-bg:        #512FC9;
            --th-text:      #FFFFFF;
            --tr-hover:     rgba(81,47,201,0.04);
            --btn-bg:       #512FC9;
            --btn-text:     #FFFFFF;
            --btn-hover:    #4126A1;
            --btn-sec-bg:   rgba(0,0,0,0.07);
            --btn-sec-text: #000000;
            --pre-bg:       #222C59;
            --pre-text:     #ECEFF1;
            --code-bg:      rgba(0,0,0,0.06);
            --highlight-bg: rgba(255,171,0,0.15);
            --highlight-bd: #FFAB00;
        }

        /* Dark theme via system preference (unless manually set to light) */
        @media (prefers-color-scheme: dark) {
            :root:not([data-theme="light"]) {
                --bg-page:      #0C143D;
                --bg-surface:   #222C59;
                --bg-card:      #222C59;
                --text-main:    #FFFFFF;
                --text-muted:   rgba(255,255,255,0.54);
                --text-subtle:  rgba(255,255,255,0.36);
                --accent:       #9F85FF;
                --accent-hover: #B29DFF;
                --border:       rgba(255,255,255,0.18);
                --success:      #00BFA6;
                --success-bg:   rgba(0,191,166,0.1);
                --error:        #FF6257;
                --error-bg:     rgba(255,98,87,0.1);
                --warning:      #FFAB00;
                --warning-bg:   rgba(255,171,0,0.1);
                --info:         #009EFF;
                --info-bg:      rgba(0,158,255,0.1);
                --shadow:       rgba(0,0,0,0.3);
                --th-bg:        #344179;
                --th-text:      #FFFFFF;
                --tr-hover:     rgba(255,255,255,0.07);
                --btn-bg:       #9F85FF;
                --btn-text:     #0C143D;
                --btn-hover:    #B29DFF;
                --btn-sec-bg:   rgba(255,255,255,0.13);
                --btn-sec-text: #FFFFFF;
                --pre-bg:       #0C143D;
                --pre-text:     #ECEFF1;
                --code-bg:      rgba(255,255,255,0.07);
                --highlight-bg: rgba(255,171,0,0.15);
                --highlight-bd: #FFAB00;
            }
        }

        /* Explicit dark override (manual toggle) */
        [data-theme="dark"] {
            --bg-page:      #0C143D;
            --bg-surface:   #222C59;
            --bg-card:      #222C59;
            --text-main:    #FFFFFF;
            --text-muted:   rgba(255,255,255,0.54);
            --text-subtle:  rgba(255,255,255,0.36);
            --accent:       #9F85FF;
            --accent-hover: #B29DFF;
            --border:       rgba(255,255,255,0.18);
            --success:      #00BFA6;
            --success-bg:   rgba(0,191,166,0.1);
            --error:        #FF6257;
            --error-bg:     rgba(255,98,87,0.1);
            --warning:      #FFAB00;
            --warning-bg:   rgba(255,171,0,0.1);
            --info:         #009EFF;
            --info-bg:      rgba(0,158,255,0.1);
            --shadow:       rgba(0,0,0,0.3);
            --th-bg:        #344179;
            --th-text:      #FFFFFF;
            --tr-hover:     rgba(255,255,255,0.07);
            --btn-bg:       #9F85FF;
            --btn-text:     #0C143D;
            --btn-hover:    #B29DFF;
            --btn-sec-bg:   rgba(255,255,255,0.13);
            --btn-sec-text: #FFFFFF;
            --pre-bg:       #0C143D;
            --pre-text:     #ECEFF1;
            --code-bg:      rgba(255,255,255,0.07);
            --highlight-bg: rgba(255,171,0,0.15);
            --highlight-bd: #FFAB00;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-main);
            background: var(--bg-page);
            padding: 20px;
            transition: background 0.2s, color 0.2s;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--bg-surface);
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow);
        }

        .page-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            margin-bottom: 16px;
            gap: 16px;
        }

        h1 { color: var(--text-main); font-size: 2em; }

        h2 {
            color: var(--text-main);
            margin-top: 30px;
            margin-bottom: 6px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--accent);
            font-size: 1.5em;
        }

        h3 { color: var(--text-main); margin-top: 20px; margin-bottom: 10px; font-size: 1.2em; }

        .section-desc { color: var(--text-muted); font-size: 0.92em; margin-bottom: 14px; }

        .intro {
            color: var(--text-muted);
            margin-bottom: 24px;
            font-size: 0.97em;
            line-height: 1.7;
            padding: 14px 16px;
            border-left: 3px solid var(--accent);
            background: var(--code-bg);
            border-radius: 0 4px 4px 0;
        }

        .theme-toggle {
            flex-shrink: 0;
            background: var(--btn-sec-bg);
            color: var(--text-main);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 6px 14px;
            cursor: pointer;
            font-size: 0.85em;
            transition: background 0.2s, color 0.2s;
            white-space: nowrap;
        }

        .theme-toggle:hover {
            background: var(--btn-hover);
            color: var(--btn-text);
            border-color: var(--btn-hover);
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .summary-card {
            background: var(--bg-card);
            padding: 15px;
            border-radius: 6px;
            border: 1px solid var(--border);
            border-left: 4px solid var(--info);
        }

        .summary-card .label {
            font-size: 0.82em;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .summary-card .value {
            font-size: 1.3em;
            font-weight: 600;
            color: var(--text-main);
            margin-top: 4px;
        }

        .status-success { border-left-color: var(--success) !important; }
        .status-failure { border-left-color: var(--error)   !important; }
        .status-warning { border-left-color: var(--warning) !important; }

        table { width: 100%; border-collapse: collapse; margin: 16px 0; background: var(--bg-surface); }
        th { background: var(--th-bg); color: var(--th-text); padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid var(--border); }
        td:nth-child(3), td:nth-child(4) { word-break: break-all; max-width: 200px; }
        tr:hover { background: var(--tr-hover); }

        .badge { display: inline-block; padding: 3px 9px; border-radius: 12px; font-size: 0.82em; font-weight: 600; }
        .badge-success { background: var(--success-bg); color: var(--success); }
        .badge-failure { background: var(--error-bg);   color: var(--error);   }
        .badge-info    { background: var(--info-bg);    color: var(--info);    }
        .badge-warning { background: var(--warning-bg); color: var(--warning); }

        .cert-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px; margin: 20px 0; }

        .cert-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 15px;
            transition: border-color 0.3s, box-shadow 0.3s;
        }

        .cert-card.highlight {
            background: var(--highlight-bg);
            border-color: var(--highlight-bd);
            box-shadow: 0 0 10px rgba(255,171,0,0.3);
        }

        .cert-header {
            font-weight: 600;
            font-size: 1.05em;
            margin-bottom: 10px;
            color: var(--text-main);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .cert-badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 0.75em; font-weight: 600; margin-left: 6px; }
        .cert-badge-server { background: var(--info-bg);    color: var(--info);    }
        .cert-badge-client { background: var(--success-bg); color: var(--success); }

        .cert-actions { display: flex; gap: 5px; }

        .btn-small {
            padding: 4px 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8em;
            background: var(--btn-bg);
            color: var(--btn-text);
            transition: background 0.2s;
        }

        .btn-small:hover { background: var(--btn-hover); }

        .cert-raw { margin-top: 10px; display: none; }
        .cert-raw.show { display: block; }
        .cert-raw pre { max-height: 300px; }

        .collapsible {
            cursor: pointer;
            padding: 10px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-main);
            width: 100%;
            text-align: left;
            border-radius: 4px;
            font-size: 1em;
            margin: 5px 0;
            transition: background 0.2s;
        }

        .collapsible:hover { background: var(--tr-hover); }
        .collapsible.active { background: var(--th-bg); color: var(--th-text); }

        .content { display: none; padding: 15px; background: var(--bg-card); border-radius: 4px; margin-bottom: 10px; }
        .content.active { display: block; }

        pre {
            background: var(--pre-bg);
            color: var(--pre-text);
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.9em;
            line-height: 1.5;
        }

        .json-key     { color: #e6855e; }
        .json-string  { color: #2ecc71; }
        .json-number  { color: #74c9ff; }
        .json-boolean { color: #ff6b6b; }
        .json-null    { color: #95a5a6; }

        .filter-bar {
            margin: 10px 0 20px;
            padding: 12px 15px;
            background: var(--bg-card);
            border-radius: 6px;
            border: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .filter-bar label { font-weight: 600; color: var(--text-muted); font-size: 0.9em; }

        .filter-bar select {
            padding: 7px 10px;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: var(--bg-surface);
            color: var(--text-main);
            font-size: 0.9em;
        }

        .metadata { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; margin: 12px 0; }
        .metadata-item { padding: 8px 12px; background: var(--bg-card); border-radius: 4px; border: 1px solid var(--border); }
        .metadata-item .key { font-weight: 600; color: var(--text-muted); font-size: 0.85em; }
        .metadata-item .value { color: var(--text-main); margin-top: 3px; font-size: 0.95em; }

        .cert-link { color: var(--accent); text-decoration: none; cursor: pointer; }
        .cert-link:hover { text-decoration: underline; }

        .button-group { display: flex; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }

        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9em; font-weight: 600; transition: background 0.2s; }
        .btn-primary { background: var(--btn-bg); color: var(--btn-text); }
        .btn-primary:hover { background: var(--btn-hover); }
        .btn-secondary { background: var(--btn-sec-bg); color: var(--btn-sec-text); border: 1px solid var(--border); }
        .btn-secondary:hover { background: var(--btn-hover); color: var(--btn-text); }

        .copy-feedback {
            display: inline-block;
            margin-left: 10px;
            padding: 4px 12px;
            background: var(--success);
            color: #FFFFFF;
            border-radius: 4px;
            font-size: 0.9em;
            opacity: 0;
            transition: opacity 0.3s;
        }

        .copy-feedback.show { opacity: 1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="page-header">
            <h1>TLS Check Results</h1>
            <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()">&#9728; Light</button>
        </div>
        <p class="intro">
            <strong>tlscheck</strong> tests TLS connectivity from this machine to each Teleport cluster
            service, recording certificate details, negotiated ALPN protocols, and any connection errors.
            Use this report to diagnose TLS routing issues, verify that expected protocols are negotiated,
            and confirm that certificates are trusted. Each section below describes what was found for a
            specific aspect of the cluster&apos;s connectivity.
        </p>
        <div id="app"></div>
        <h2>Raw JSON Data</h2>
        <p class="section-desc">Complete JSON output, suitable for sharing with Teleport support.</p>
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

        // ---- Theme management ----
        (function initTheme() {
            const stored = localStorage.getItem('tlscheck-theme');
            if (stored === 'dark' || stored === 'light') {
                document.documentElement.setAttribute('data-theme', stored);
            }
        })();

        function toggleTheme() {
            const html = document.documentElement;
            const current = html.getAttribute('data-theme') || 'auto';
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            let next;
            if (current === 'dark') {
                next = 'light';
            } else if (current === 'light') {
                next = 'dark';
            } else {
                next = prefersDark ? 'light' : 'dark';
            }
            html.setAttribute('data-theme', next);
            localStorage.setItem('tlscheck-theme', next);
            updateToggleLabel();
        }

        function updateToggleLabel() {
            const btn = document.getElementById('theme-toggle');
            if (!btn) return;
            const current = document.documentElement.getAttribute('data-theme') || 'auto';
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const isDark = current === 'dark' || (current === 'auto' && prefersDark);
            btn.innerHTML = isDark ? '&#9728; Light' : '&#9790; Dark';
        }

        // ---- Rendering functions ----

        function renderSystemInfo() {
            const network = tlsCheckData.network || {};
            const system = network.system || {};

            let html = '<h2>System Information</h2>';
            html += '<p class="section-desc">Details about the machine and environment from which this check was run.</p>';
            html += '<div class="metadata">';
            html += createMetadataItem('Hostname', system.hostname || 'N/A');
            html += createMetadataItem('Operating System', system.os || 'N/A');
            if (system.os_version) {
                html += createMetadataItem('OS Version', system.os_version);
            }
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
            const profile = args.profile_source;

            const connectedCount = results.filter(r => !r.failure).length;
            const issuesCount = results.filter(r => r.failure).length;

            let html = '<h2>Cluster Configuration</h2>';
            html += '<p class="section-desc">Teleport cluster and proxy details used for this check run.</p>';
            html += '<div class="summary">';
            html += createSummaryCard('Cluster', args.cluster_name || 'N/A');
            html += createSummaryCard('Proxy Address', args.public_addr || 'N/A');
            html += createSummaryCard('Teleport Version', args.teleport_version || 'N/A');
            html += createSummaryCard('TLS Routing', args.tls_routing_enabled ? 'Enabled' : 'Disabled',
                args.tls_routing_enabled ? 'status-success' : 'status-warning');
            html += createSummaryCard('Total Probes', results.length.toString());
            html += createSummaryCard('Connected', connectedCount.toString(),
                connectedCount > 0 ? 'status-success' : '');
            if (issuesCount > 0) {
                html += createSummaryCard('Issues Detected', issuesCount.toString(), 'status-failure');
            }
            html += '</div>';

            // tsh profile section (only shown when a profile was active)
            if (profile) {
                html += '<h3>tsh Profile</h3>';
                html += '<p class="section-desc">A local tsh profile was detected and used to populate defaults for this run.</p>';
                html += '<div class="metadata">';
                html += createMetadataItem('Profile Name', profile.name || 'N/A');
                if (profile.path) {
                    html += createMetadataItem('Profile Path', profile.path);
                }
                if (profile.username) {
                    html += createMetadataItem('Username', profile.username);
                }
                const certFoundBadge = profile.client_cert_found
                    ? '<span class="badge badge-success">Yes</span>'
                    : '<span class="badge badge-warning">No</span>';
                html += createMetadataItem('Client Cert Found', certFoundBadge, true);
                if (profile.client_cert_path) {
                    html += createMetadataItem('Client Cert Path', profile.client_cert_path);
                }
                html += '</div>';
            }

            return html;
        }

        function createSummaryCard(label, value, statusClass) {
            statusClass = statusClass || '';
            return '<div class="summary-card ' + statusClass + '"><div class="label">' + escapeHtml(label) + '</div><div class="value">' + escapeHtml(value) + '</div></div>';
        }

        function renderResults() {
            const results = tlsCheckData.results || [];
            const certs = tlsCheckData.certs || {};

            if (results.length === 0) {
                return '<p>No probe results available.</p>';
            }

            let html = '<h2>Connection Behaviors</h2>';
            html += '<p class="section-desc">Results for each service endpoint probe. Each row shows one TLS connection attempt, including the negotiated protocol, server certificate, client certificate (if any), and any errors encountered.</p>';
            html += '<div class="filter-bar">';
            html += '<label>Filter:</label>';
            html += '<select id="filter-status" onchange="filterResults()">';
            html += '<option value="all">All Results</option>';
            html += '<option value="success">Connected Only</option>';
            html += '<option value="failure">Issues Only</option>';
            html += '</select>';
            html += '</div>';

            html += '<table id="results-table"><thead><tr>';
            html += '<th>Service</th><th>Target</th><th>SNI</th><th>ALPN</th><th>Client Cert</th><th>Behavior</th>';
            html += '</tr></thead><tbody>';

            results.forEach(function(result) {
                const target = result.target || {};
                const failure = result.failure;
                const status = failure ? 'failure' : 'success';

                html += '<tr class="result-row" data-status="' + status + '">';
                html += '<td>' + escapeHtml(target.service_key || 'N/A') + '</td>';
                html += '<td>' + escapeHtml(target.address || 'N/A') + ':' + (target.port || 'N/A') + '</td>';
                html += '<td>' + escapeHtml(target.primary_sni || 'N/A') + '</td>';
                html += '<td>' + escapeHtml((target.alpns || []).join(', ') || 'N/A') + '</td>';

                // Client cert column
                if (target.use_client_cert === true) {
                    const fp = result.client_cert_fingerprint;
                    if (fp && certs[fp]) {
                        const cert = certs[fp];
                        const cn = (cert.subject && cert.subject.common_name)
                            ? cert.subject.common_name
                            : fp.slice(0, 12) + '\u2026';
                        html += '<td><a class="cert-link" onclick="jumpToCert(\'' + fp + '\')">' + escapeHtml(cn) + '</a></td>';
                    } else {
                        html += '<td><span class="badge badge-info">Used</span></td>';
                    }
                } else if (target.use_client_cert === false) {
                    html += '<td><span style="color:var(--text-subtle);font-size:0.85em">None</span></td>';
                } else {
                    html += '<td><span style="color:var(--text-subtle);font-size:0.85em">\u2014</span></td>';
                }

                if (failure) {
                    html += '<td>';
                    html += '<span class="badge badge-failure">' + escapeHtml(failure.kind || 'unknown') + '</span>';
                    html += '<div style="color:var(--text-muted);font-size:0.88em;margin-top:4px">' + escapeHtml(failure.message || 'N/A') + '</div>';
                    html += '</td>';
                } else {
                    const details = [];
                    if (result.negotiated_protocol) {
                        details.push('Protocol: ' + escapeHtml(result.negotiated_protocol));
                    }
                    if (result.tls_version) {
                        details.push('TLS: ' + escapeHtml(result.tls_version));
                    }
                    if (result.leaf_fingerprint) {
                        const cert = certs[result.leaf_fingerprint];
                        if (cert && cert.subject && cert.subject.common_name) {
                            details.push('Cert: <a class="cert-link" onclick="jumpToCert(\'' + result.leaf_fingerprint + '\')">' + escapeHtml(cert.subject.common_name) + '</a>');
                        }
                    }
                    html += '<td>';
                    html += details.length > 0
                        ? details.join('<br>')
                        : '<span class="badge badge-success">Connected</span>';
                    html += '</td>';
                }

                html += '</tr>';
            });

            html += '</tbody></table>';
            return html;
        }

        function renderNetworkInfo() {
            const network = tlsCheckData.network || {};
            let html = '<h2>Network Configuration</h2>';
            html += '<p class="section-desc">Proxy settings and VPN interfaces detected from the environment at the time of the check.</p>';

            if (network.proxy_config) {
                html += '<h3>Proxy Configuration</h3><div class="metadata">';
                const proxy = network.proxy_config;
                if (proxy.https_proxy) html += createMetadataItem('HTTPS Proxy', proxy.https_proxy);
                if (proxy.http_proxy)  html += createMetadataItem('HTTP Proxy', proxy.http_proxy);
                if (proxy.no_proxy)    html += createMetadataItem('No Proxy', proxy.no_proxy);
                html += '</div>';
            }

            if (network.vpn && (network.vpn.detected || (network.vpn.interfaces && network.vpn.interfaces.length > 0))) {
                html += '<h3>VPN Detection</h3>';
                html += '<p><strong>VPN Detected:</strong> ' + (network.vpn.detected ? 'Yes' : 'No') + '</p>';
                if (network.vpn.interfaces && network.vpn.interfaces.length > 0) {
                    html += '<p style="margin-top:8px"><strong>VPN Interfaces:</strong></p><div class="metadata">';
                    network.vpn.interfaces.forEach(function(iface) {
                        const details = [];
                        if (iface.name)    details.push('Name: ' + iface.name);
                        if (iface.type)    details.push('Type: ' + iface.type);
                        if (iface.status)  details.push('Status: ' + iface.status);
                        if (iface.addresses && iface.addresses.length > 0) {
                            details.push('Addresses: ' + iface.addresses.join(', '));
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
            html += '<p class="section-desc">All TLS certificates observed during probing, including server and client certificates. Click a certificate name in the results table to jump to its entry here.</p>';
            html += '<div class="cert-grid">';

            certEntries.forEach(function(entry) {
                const fingerprint = entry[0];
                const cert = entry[1];
                html += '<div class="cert-card" id="cert-' + fingerprint + '">';
                html += '<div class="cert-header"><span>';

                if (cert.subject && cert.subject.common_name) {
                    html += escapeHtml(cert.subject.common_name);
                } else {
                    html += 'Unknown Certificate';
                }

                if (cert.source === 'client') {
                    html += '<span class="cert-badge cert-badge-client">client</span>';
                } else if (cert.source === 'server') {
                    html += '<span class="cert-badge cert-badge-server">server</span>';
                }
                html += '</span>';

                html += '<div class="cert-actions">';
                html += '<button class="btn-small" onclick="toggleRawCert(\'' + fingerprint + '\')">Show Raw</button>';
                html += '<button class="btn-small" onclick="copyCert(\'' + fingerprint + '\')">Copy</button>';
                html += '</div></div>';

                html += '<div class="metadata">';
                html += createMetadataItem('Fingerprint', fingerprint);

                if (cert.subject) {
                    const subjectParts = [];
                    if (cert.subject.common_name)  subjectParts.push('CN=' + cert.subject.common_name);
                    if (cert.subject.organization) subjectParts.push('O=' + cert.subject.organization.join(', '));
                    if (cert.subject.country)      subjectParts.push('C=' + cert.subject.country.join(', '));
                    if (subjectParts.length > 0)   html += createMetadataItem('Subject', subjectParts.join(', '));
                }

                if (cert.issuer) {
                    const issuerParts = [];
                    if (cert.issuer.common_name)  issuerParts.push('CN=' + cert.issuer.common_name);
                    if (cert.issuer.organization) issuerParts.push('O=' + cert.issuer.organization.join(', '));
                    if (cert.issuer.country)      issuerParts.push('C=' + cert.issuer.country.join(', '));
                    if (issuerParts.length > 0)   html += createMetadataItem('Issuer', issuerParts.join(', '));
                }

                if (cert.validity) {
                    if (cert.validity.not_before) html += createMetadataItem('Valid From', new Date(cert.validity.not_before).toLocaleString());
                    if (cert.validity.not_after)  html += createMetadataItem('Valid Until', new Date(cert.validity.not_after).toLocaleString());
                }

                if (cert.sans) {
                    const sans = [];
                    if (cert.sans.dns && cert.sans.dns.length > 0) sans.push.apply(sans, cert.sans.dns);
                    if (cert.sans.ip  && cert.sans.ip.length  > 0) sans.push.apply(sans, cert.sans.ip);
                    if (sans.length > 0) html += createMetadataItem('SANs', sans.join(', '));
                }

                if (cert.serial_number) html += createMetadataItem('Serial Number', cert.serial_number);

                html += '</div>';
                html += '<div class="cert-raw" id="cert-raw-' + fingerprint + '">';
                html += '<pre>' + escapeHtml(JSON.stringify(cert, null, 2)) + '</pre>';
                html += '</div></div>';
            });

            html += '</div>';
            return html;
        }

        // rawHtml=true skips escaping the value (for trusted badge HTML)
        function createMetadataItem(key, value, rawHtml) {
            const valueContent = rawHtml ? value : escapeHtml(String(value));
            return '<div class="metadata-item"><div class="key">' + escapeHtml(key) + '</div><div class="value">' + valueContent + '</div></div>';
        }

        function filterResults() {
            const filter = document.getElementById('filter-status').value;
            document.querySelectorAll('.result-row').forEach(function(row) {
                row.style.display = (filter === 'all' || row.dataset.status === filter) ? '' : 'none';
            });
        }

        function escapeHtml(text) {
            if (text == null) return '';
            const div = document.createElement('div');
            div.textContent = String(text);
            return div.innerHTML;
        }

        function syntaxHighlight(json) {
            json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function(match) {
                let cls = 'json-number';
                if (/^"/.test(match)) {
                    cls = /:$/.test(match) ? 'json-key' : 'json-string';
                } else if (/true|false/.test(match)) {
                    cls = 'json-boolean';
                } else if (/null/.test(match)) {
                    cls = 'json-null';
                }
                return '<span class="' + cls + '">' + match + '</span>';
            });
        }

        function jumpToCert(fingerprint) {
            const el = document.getElementById('cert-' + fingerprint);
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                el.classList.add('highlight');
                setTimeout(function() { el.classList.remove('highlight'); }, 3000);
            }
        }

        function downloadJSON() {
            const args = tlsCheckData.arguments || {};
            const clusterName = args.cluster_name || 'tlscheck';
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
            const filename = clusterName + '-' + timestamp + '.json';

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
                navigator.clipboard.writeText(jsonStr).then(showCopyFeedback).catch(function() { fallbackCopy(jsonStr); });
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
            } catch (_) {
                alert('Failed to copy JSON. Please copy manually from the raw JSON section.');
            }
            document.body.removeChild(textarea);
        }

        function showCopyFeedback() {
            const feedback = document.getElementById('copy-feedback');
            feedback.classList.add('show');
            setTimeout(function() { feedback.classList.remove('show'); }, 2000);
        }

        function toggleRawCert(fingerprint) {
            const rawEl = document.getElementById('cert-raw-' + fingerprint);
            const btn = event.target;
            if (rawEl.classList.toggle('show')) {
                btn.textContent = 'Hide Raw';
            } else {
                btn.textContent = 'Show Raw';
            }
        }

        function copyCert(fingerprint) {
            const cert = (tlsCheckData.certs || {})[fingerprint];
            if (!cert) return;
            const certStr = JSON.stringify(cert, null, 2);
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(certStr).then(function() {
                    const btn = event.target;
                    const orig = btn.textContent;
                    btn.textContent = 'Copied!';
                    setTimeout(function() { btn.textContent = orig; }, 2000);
                }).catch(function(err) { console.error('Failed to copy:', err); });
            }
        }

        // Initialize the app
        document.addEventListener('DOMContentLoaded', function() {
            updateToggleLabel();

            const app = document.getElementById('app');
            app.innerHTML =
                renderSystemInfo() +
                renderSummary() +
                renderResults() +
                renderNetworkInfo() +
                renderCertificates();

            // Display raw JSON with syntax highlighting
            // RawJSONDataEscaped is safely escaped for use in JavaScript string context
            const rawJson = "{{.RawJSONDataEscaped}}";
            document.getElementById('raw-json').innerHTML = syntaxHighlight(rawJson);

            // Setup collapsible sections
            document.querySelectorAll('.collapsible').forEach(function(coll) {
                coll.addEventListener('click', function() {
                    this.classList.toggle('active');
                    this.nextElementSibling.classList.toggle('active');
                });
            });
        });
    </script>
</body>
</html>
`
