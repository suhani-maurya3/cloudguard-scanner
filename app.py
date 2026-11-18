from flask import Flask, render_template_string, jsonify, Response
import json
from scanner import MultiCloudStorageScanner

app = Flask(__name__)
scanner = MultiCloudStorageScanner()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CloudGuard | Multi-Cloud Storage Misconfiguration Scanner</title>
    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0b1120; color: #e2e8f0; margin: 0; padding: 30px; }
        .container { max-width: 1150px; margin: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 20px; }
        .badge-safe { background: #064e3b; color: #34d399; padding: 6px 12px; border-radius: 20px; font-size: 13px; font-weight: 600; border: 1px solid #059669; }
        .btn { background: #2563eb; color: white; border: none; padding: 12px 22px; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }
        .btn:hover { background: #1d4ed8; }
        .btn-outline { background: transparent; border: 1px solid #475569; color: #cbd5e1; margin-left: 10px; }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 25px 0; }
        .card { background: #1e293b; padding: 20px; border-radius: 10px; border: 1px solid #334155; }
        .card h3 { margin: 0; font-size: 13px; color: #94a3b8; text-transform: uppercase; }
        .card p { margin: 10px 0 0; font-size: 30px; font-weight: 700; }
        .crit { color: #f87171; } .high { color: #fb923c; } .med { color: #facc15; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }
        th, td { padding: 14px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }
        th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        .sev { padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; }
        .sev-CRITICAL { background: rgba(239,68,68,0.2); color: #f87171; }
        .sev-HIGH { background: rgba(249,115,22,0.2); color: #fb923c; }
        .sev-MEDIUM { background: rgba(234,179,8,0.2); color: #facc15; }
        code { background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #38bdf8; font-size: 12px; display: block; margin-top: 4px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 style="margin:0;">CloudGuard Storage Scanner</h1>
            <p style="color:#94a3b8; margin:6px 0 0;">AWS S3 · Azure Blob · Google Cloud Storage Configuration Auditor</p>
        </div>
        <div>
            <span class="badge-safe">Zero-Data-Access Mode: Metadata Only</span>
        </div>
    </div>

    <div style="margin-top: 20px;">
        <button class="btn" onclick="runScan()">Run Multi-Cloud Audit (Demo Environment)</button>
        <a href="/export" class="btn btn-outline" style="text-decoration:none;">Download JSON Report</a>
    </div>

    <div class="grid">
        <div class="card"><h3>Buckets / Containers Audited</h3><p id="total-res">-</p></div>
        <div class="card"><h3>Critical Exposures</h3><p id="crit-cnt" class="crit">-</p></div>
        <div class="card"><h3>High Severity</h3><p id="high-cnt" class="high">-</p></div>
        <div class="card"><h3>Medium Severity</h3><p id="med-cnt" class="med">-</p></div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Cloud Provider</th>
                <th>Storage Resource</th>
                <th>Severity</th>
                <th>Misconfiguration & Remediation</th>
                <th>Benchmark</th>
            </tr>
        </thead>
        <tbody id="results-body">
            <tr><td colspan="5" style="text-align:center; color:#94a3b8;">Click "Run Multi-Cloud Audit" to inspect storage configurations.</td></tr>
        </tbody>
    </table>
</div>

<script>
async function runScan() {
    const res = await fetch('/api/scan');
    const data = await res.json();
    document.getElementById('total-res').innerText = data.summary.total_resources_scanned;
    document.getElementById('crit-cnt').innerText = data.summary.critical;
    document.getElementById('high-cnt').innerText = data.summary.high;
    document.getElementById('med-cnt').innerText = data.summary.medium;

    const tbody = document.getElementById('results-body');
    tbody.innerHTML = '';
    data.findings.forEach(f => {
        tbody.innerHTML += `
            <tr>
                <td><strong>${f.provider}</strong></td>
                <td>${f.resource}</td>
                <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
                <td>
                    <div>${f.issue}</div>
                    <code>Fix: ${f.remediation}</code>
                </td>
                <td>${f.compliance}</td>
            </tr>
        `;
    });
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/scan")
def api_scan():
    return jsonify(scanner.run_demo_scan())

@app.route("/export")
def export_report():
    report = scanner.run_demo_scan()
    return Response(
        json.dumps(report, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=multicloud_audit_report.json"}
    )

if __name__ == "__main__":
    app.run(debug=True, port=5000)