#!/usr/bin/env python3
"""
Prowler Security Dashboard Generator
Reads Prowler JSON scan output and generates a professional HTML dashboard.
Built for AWS Cloud Security Monitoring Lab - Week 3
Author: Kenil (Cybersecurity & Threat Management - Seneca Polytechnic)
"""

import json
import sys
import os
from datetime import datetime
from collections import Counter, defaultdict

# ─── Configuration ───────────────────────────────────────────────────────────
JSON_FILE = os.path.expanduser("~/aws/week3/scan_results/prowler-output-627917840328-20260407132800.json")
OUTPUT_HTML = os.path.expanduser("~/aws/week3/prowler_dashboard.html")


def load_prowler_results(json_path):
    """Load and parse Prowler JSON output."""
    print(f"[*] Loading Prowler results from: {json_path}")
    
    findings = []
    with open(json_path, 'r') as f:
        content = f.read().strip()
        # Prowler 3.x outputs one JSON object per line (JSON Lines format)
        if content.startswith('['):
            findings = json.loads(content)
        else:
            for line in content.split('\n'):
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    
    print(f"[+] Loaded {len(findings)} findings")
    return findings


def analyze_findings(findings):
    """Analyze findings and return statistics."""
    stats = {
        'total': len(findings),
        'by_status': Counter(),
        'by_severity': Counter(),
        'by_service': defaultdict(lambda: {'PASS': 0, 'FAIL': 0, 'WARNING': 0, 'INFO': 0}),
        'severity_by_service': defaultdict(lambda: Counter()),
        'critical_findings': [],
        'high_findings': [],
        'medium_findings': [],
        'low_findings': [],
        'failed_checks': [],
        'scan_date': None,
        'account_id': None,
        'region': None,
    }

    for f in findings:
        # Read Status field first (PASS/FAIL/INFO), not StatusExtended (which is description text)
        status = (f.get('Status') or f.get('status') or 
                  f.get('status_code') or f.get('result', '')).upper().strip()
        
        # Normalize status
        if status == 'PASS':
            status = 'PASS'
        elif status == 'FAIL':
            status = 'FAIL'
        elif status in ('WARNING', 'WARN'):
            status = 'WARNING'
        elif status == 'INFO':
            status = 'INFO'
        else:
            # Fallback: check if status string contains keywords
            if 'PASS' in status:
                status = 'PASS'
            elif 'FAIL' in status:
                status = 'FAIL'
            else:
                status = 'INFO'

        severity = (f.get('Severity') or f.get('severity') or 'medium').lower()
        
        service = (f.get('ServiceName') or f.get('service_name') or 
                   f.get('Service') or f.get('service') or 'unknown')
        
        check_title = (f.get('CheckTitle') or f.get('check_title') or
                       f.get('CheckID') or f.get('check_id') or 'Unknown Check')
        
        status_detail = (f.get('StatusExtended') or f.get('status_extended') or
                         f.get('Description') or f.get('description') or '')
        
        resource = (f.get('ResourceId') or f.get('resource_id') or
                    f.get('ResourceArn') or f.get('resource_arn') or 'N/A')
        
        risk = (f.get('Risk') or f.get('risk') or '')
        remediation = (f.get('Remediation', {}) if isinstance(f.get('Remediation'), dict) else {})
        remediation_text = (remediation.get('Recommendation', {}).get('Text', '') if isinstance(remediation.get('Recommendation'), dict) else
                           f.get('remediation') or f.get('Remediation') or '')
        if isinstance(remediation_text, dict):
            remediation_text = remediation_text.get('Text', '') or remediation_text.get('text', '') or str(remediation_text)

        # Extract metadata
        if not stats['account_id']:
            stats['account_id'] = (f.get('AccountId') or f.get('account_id') or 
                                    f.get('Account') or '')
        if not stats['region']:
            stats['region'] = (f.get('Region') or f.get('region') or '')
        if not stats['scan_date']:
            stats['scan_date'] = (f.get('Timestamp') or f.get('timestamp') or '')

        stats['by_status'][status] += 1
        stats['by_service'][service][status] += 1

        if status == 'FAIL':
            stats['by_severity'][severity] += 1
            stats['severity_by_service'][service][severity] += 1
            
            finding_detail = {
                'service': service,
                'check': check_title,
                'severity': severity,
                'status_detail': status_detail,
                'resource': resource,
                'risk': risk,
                'remediation': remediation_text,
            }
            
            stats['failed_checks'].append(finding_detail)
            
            if severity == 'critical':
                stats['critical_findings'].append(finding_detail)
            elif severity == 'high':
                stats['high_findings'].append(finding_detail)
            elif severity == 'medium':
                stats['medium_findings'].append(finding_detail)
            elif severity == 'low':
                stats['low_findings'].append(finding_detail)

    # Calculate compliance score
    total_checks = stats['by_status']['PASS'] + stats['by_status']['FAIL']
    stats['compliance_score'] = round((stats['by_status']['PASS'] / total_checks * 100), 1) if total_checks > 0 else 0

    return stats


def generate_html(stats):
    """Generate professional HTML dashboard."""
    
    pass_count = stats['by_status'].get('PASS', 0)
    fail_count = stats['by_status'].get('FAIL', 0)
    warn_count = stats['by_status'].get('WARNING', 0)
    score = stats['compliance_score']
    
    critical = stats['by_severity'].get('critical', 0)
    high = stats['by_severity'].get('high', 0)
    medium = stats['by_severity'].get('medium', 0)
    low = stats['by_severity'].get('low', 0)

    # Score color
    if score >= 80:
        score_color = "#22c55e"
        score_label = "GOOD"
    elif score >= 60:
        score_color = "#f59e0b"
        score_label = "NEEDS WORK"
    else:
        score_color = "#ef4444"
        score_label = "AT RISK"

    # Service table rows
    service_rows = ""
    for service in sorted(stats['by_service'].keys()):
        s = stats['by_service'][service]
        sev = stats['severity_by_service'].get(service, Counter())
        total = s['PASS'] + s['FAIL'] + s.get('WARNING', 0)
        svc_score = round(s['PASS'] / (s['PASS'] + s['FAIL']) * 100) if (s['PASS'] + s['FAIL']) > 0 else 100
        
        if svc_score >= 80:
            bar_color = "#22c55e"
        elif svc_score >= 50:
            bar_color = "#f59e0b"
        else:
            bar_color = "#ef4444"
        
        service_rows += f"""
        <tr>
            <td class="svc-name">{service}</td>
            <td class="num pass-num">{s['PASS']}</td>
            <td class="num fail-num">{s['FAIL']}</td>
            <td class="num crit-num">{sev.get('critical', 0)}</td>
            <td class="num high-num">{sev.get('high', 0)}</td>
            <td class="num med-num">{sev.get('medium', 0)}</td>
            <td class="num low-num">{sev.get('low', 0)}</td>
            <td class="score-cell">
                <div class="score-bar-bg">
                    <div class="score-bar-fill" style="width:{svc_score}%; background:{bar_color}"></div>
                </div>
                <span class="score-pct">{svc_score}%</span>
            </td>
        </tr>"""

    # Finding cards
    def make_finding_cards(findings_list, severity_class):
        if not findings_list:
            return '<p class="no-findings">No findings at this severity level.</p>'
        cards = ""
        for i, f in enumerate(findings_list[:25]):  # Limit to 25 per severity
            resource_display = f['resource'] if len(str(f['resource'])) < 80 else str(f['resource'])[:77] + '...'
            remediation_html = f'<div class="remediation"><strong>Remediation:</strong> {f["remediation"]}</div>' if f['remediation'] else ''
            risk_html = f'<div class="risk"><strong>Risk:</strong> {f["risk"]}</div>' if f['risk'] else ''
            cards += f"""
            <div class="finding-card {severity_class}">
                <div class="finding-header">
                    <span class="finding-service">{f['service']}</span>
                    <span class="severity-badge {severity_class}">{f['severity'].upper()}</span>
                </div>
                <div class="finding-title">{f['check']}</div>
                <div class="finding-detail">{f['status_detail']}</div>
                <div class="finding-resource">Resource: {resource_display}</div>
                {risk_html}
                {remediation_html}
            </div>"""
        return cards

    critical_cards = make_finding_cards(stats['critical_findings'], 'critical')
    high_cards = make_finding_cards(stats['high_findings'], 'high')
    medium_cards = make_finding_cards(stats['medium_findings'], 'medium')
    low_cards = make_finding_cards(stats['low_findings'], 'low')

    scan_date = stats.get('scan_date', '')
    if scan_date:
        try:
            dt = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
            scan_date_display = dt.strftime('%B %d, %Y at %H:%M UTC')
        except:
            scan_date_display = scan_date
    else:
        scan_date_display = datetime.now().strftime('%B %d, %Y')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Security Posture Dashboard — Prowler Scan Results</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {{
    --bg-primary: #0a0e1a;
    --bg-card: #111827;
    --bg-card-hover: #1a2332;
    --border: #1e293b;
    --border-accent: #2d3a4f;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --critical: #ff2d55;
    --critical-bg: rgba(255, 45, 85, 0.08);
    --critical-border: rgba(255, 45, 85, 0.25);
    --high: #ff6b35;
    --high-bg: rgba(255, 107, 53, 0.08);
    --high-border: rgba(255, 107, 53, 0.25);
    --medium: #fbbf24;
    --medium-bg: rgba(251, 191, 36, 0.08);
    --medium-border: rgba(251, 191, 36, 0.25);
    --low: #60a5fa;
    --low-bg: rgba(96, 165, 250, 0.08);
    --low-border: rgba(96, 165, 250, 0.25);
    --pass: #22c55e;
    --pass-bg: rgba(34, 197, 94, 0.08);
    --accent: #818cf8;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: 'Outfit', sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    line-height: 1.6;
}}

.noise-overlay {{
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
}}

.container {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 40px 32px;
    position: relative;
    z-index: 1;
}}

/* ─── Header ─── */
.header {{
    margin-bottom: 48px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
}}

.header-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 12px;
}}

.header h1 {{
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, #e2e8f0, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}}

.header-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--text-muted);
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 12px;
}}

.header-meta {{
    font-size: 0.9rem;
    color: var(--text-secondary);
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
}}

.header-meta span {{
    display: flex;
    align-items: center;
    gap: 6px;
}}

.meta-label {{
    color: var(--text-muted);
}}

/* ─── Score Section ─── */
.score-section {{
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 32px;
    margin-bottom: 48px;
}}

.compliance-ring {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 32px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}}

.ring-container {{
    position: relative;
    width: 180px;
    height: 180px;
    margin-bottom: 16px;
}}

.ring-svg {{
    transform: rotate(-90deg);
}}

.ring-bg {{
    fill: none;
    stroke: var(--border);
    stroke-width: 10;
}}

.ring-fill {{
    fill: none;
    stroke: {score_color};
    stroke-width: 10;
    stroke-linecap: round;
    stroke-dasharray: {score * 4.71} {471 - score * 4.71};
    transition: stroke-dasharray 1s ease;
}}

.ring-text {{
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}}

.ring-number {{
    font-size: 2.8rem;
    font-weight: 800;
    color: {score_color};
    line-height: 1;
}}

.ring-pct {{
    font-size: 1rem;
    color: var(--text-muted);
}}

.ring-label {{
    font-size: 0.85rem;
    font-weight: 600;
    color: {score_color};
    letter-spacing: 2px;
    text-transform: uppercase;
}}

.stats-grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    grid-template-rows: repeat(2, 1fr);
    gap: 16px;
}}

.stat-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    position: relative;
    overflow: hidden;
}}

.stat-card::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
}}

.stat-card.pass-card::before {{ background: var(--pass); }}
.stat-card.fail-card::before {{ background: var(--critical); }}
.stat-card.crit-card::before {{ background: var(--critical); }}
.stat-card.high-card::before {{ background: var(--high); }}

.stat-number {{
    font-size: 2.4rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.1;
}}

.stat-number.pass {{ color: var(--pass); }}
.stat-number.fail {{ color: var(--critical); }}
.stat-number.crit {{ color: var(--critical); }}
.stat-number.high {{ color: var(--high); }}

.stat-label {{
    font-size: 0.8rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 4px;
}}

/* ─── Severity Bar ─── */
.severity-strip {{
    display: flex;
    height: 40px;
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 48px;
    border: 1px solid var(--border);
}}

.severity-strip div {{
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 600;
    color: #000;
    min-width: 40px;
}}

.strip-critical {{ background: var(--critical); }}
.strip-high {{ background: var(--high); }}
.strip-medium {{ background: var(--medium); }}
.strip-low {{ background: var(--low); }}
.strip-pass {{ background: var(--pass); }}

/* ─── Service Table ─── */
.section-title {{
    font-size: 1.4rem;
    font-weight: 700;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 10px;
}}

.section-title::before {{
    content: '';
    display: inline-block;
    width: 4px;
    height: 24px;
    background: var(--accent);
    border-radius: 2px;
}}

.service-table {{
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin-bottom: 48px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
}}

.service-table th {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    padding: 16px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    background: rgba(0,0,0,0.2);
}}

.service-table td {{
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
}}

.service-table tr:last-child td {{
    border-bottom: none;
}}

.service-table tr:hover td {{
    background: var(--bg-card-hover);
}}

.svc-name {{
    font-weight: 600;
    color: var(--text-primary);
}}

.num {{
    font-family: 'JetBrains Mono', monospace;
    text-align: center !important;
    font-weight: 600;
}}

.pass-num {{ color: var(--pass); }}
.fail-num {{ color: var(--critical); }}
.crit-num {{ color: var(--critical); }}
.high-num {{ color: var(--high); }}
.med-num {{ color: var(--medium); }}
.low-num {{ color: var(--low); }}

.score-cell {{
    display: flex;
    align-items: center;
    gap: 10px;
}}

.score-bar-bg {{
    flex: 1;
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
}}

.score-bar-fill {{
    height: 100%;
    border-radius: 3px;
    transition: width 0.6s ease;
}}

.score-pct {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: var(--text-secondary);
    min-width: 40px;
    text-align: right;
}}

/* ─── Findings ─── */
.findings-section {{
    margin-bottom: 40px;
}}

.severity-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    padding: 12px 16px;
    border-radius: 10px;
}}

.severity-header.critical {{ background: var(--critical-bg); border: 1px solid var(--critical-border); }}
.severity-header.high {{ background: var(--high-bg); border: 1px solid var(--high-border); }}
.severity-header.medium {{ background: var(--medium-bg); border: 1px solid var(--medium-border); }}
.severity-header.low {{ background: var(--low-bg); border: 1px solid var(--low-border); }}

.severity-header .sev-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
}}

.severity-header.critical .sev-dot {{ background: var(--critical); }}
.severity-header.high .sev-dot {{ background: var(--high); }}
.severity-header.medium .sev-dot {{ background: var(--medium); }}
.severity-header.low .sev-dot {{ background: var(--low); }}

.severity-header h3 {{
    font-size: 1.1rem;
    font-weight: 700;
}}

.severity-header.critical h3 {{ color: var(--critical); }}
.severity-header.high h3 {{ color: var(--high); }}
.severity-header.medium h3 {{ color: var(--medium); }}
.severity-header.low h3 {{ color: var(--low); }}

.sev-count {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-left: auto;
}}

.findings-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
    gap: 12px;
    margin-bottom: 32px;
}}

.finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
    border-left: 3px solid transparent;
}}

.finding-card.critical {{ border-left-color: var(--critical); }}
.finding-card.high {{ border-left-color: var(--high); }}
.finding-card.medium {{ border-left-color: var(--medium); }}
.finding-card.low {{ border-left-color: var(--low); }}

.finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}}

.finding-service {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 1px;
}}

.severity-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 4px;
    letter-spacing: 1px;
}}

.severity-badge.critical {{ background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }}
.severity-badge.high {{ background: var(--high-bg); color: var(--high); border: 1px solid var(--high-border); }}
.severity-badge.medium {{ background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium-border); }}
.severity-badge.low {{ background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border); }}

.finding-title {{
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 6px;
    line-height: 1.4;
}}

.finding-detail {{
    font-size: 0.82rem;
    color: var(--text-secondary);
    margin-bottom: 8px;
    line-height: 1.5;
}}

.finding-resource {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: var(--text-muted);
    margin-bottom: 6px;
    word-break: break-all;
}}

.risk, .remediation {{
    font-size: 0.78rem;
    color: var(--text-secondary);
    margin-top: 6px;
    padding-top: 6px;
    border-top: 1px solid var(--border);
    line-height: 1.5;
}}

.no-findings {{
    color: var(--text-muted);
    font-style: italic;
    padding: 12px 0;
}}

/* ─── Footer ─── */
.footer {{
    text-align: center;
    padding: 32px 0;
    margin-top: 48px;
    border-top: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 0.82rem;
}}

.footer a {{
    color: var(--accent);
    text-decoration: none;
}}

/* ─── Responsive ─── */
@media (max-width: 900px) {{
    .score-section {{ grid-template-columns: 1fr; }}
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .findings-grid {{ grid-template-columns: 1fr; }}
}}

@media print {{
    body {{ background: #fff; color: #000; }}
    .noise-overlay {{ display: none; }}
    .finding-card {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="noise-overlay"></div>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="header-top">
            <h1>AWS Security Posture Dashboard</h1>
            <span class="header-badge">Prowler v3.11.3 · CIS Benchmark</span>
        </div>
        <div class="header-meta">
            <span><span class="meta-label">Account:</span> {stats.get('account_id', 'N/A')}</span>
            <span><span class="meta-label">Region:</span> {stats.get('region', 'ca-central-1')}</span>
            <span><span class="meta-label">Scan Date:</span> {scan_date_display}</span>
            <span><span class="meta-label">Total Checks:</span> {stats['total']}</span>
        </div>
    </div>

    <!-- Compliance Score + Stats -->
    <div class="score-section">
        <div class="compliance-ring">
            <div class="ring-container">
                <svg class="ring-svg" width="180" height="180" viewBox="0 0 180 180">
                    <circle class="ring-bg" cx="90" cy="90" r="75"/>
                    <circle class="ring-fill" cx="90" cy="90" r="75"/>
                </svg>
                <div class="ring-text">
                    <div class="ring-number">{score}</div>
                    <div class="ring-pct">%</div>
                </div>
            </div>
            <div class="ring-label">{score_label}</div>
        </div>
        <div class="stats-grid">
            <div class="stat-card pass-card">
                <div class="stat-number pass">{pass_count}</div>
                <div class="stat-label">Checks Passed</div>
            </div>
            <div class="stat-card fail-card">
                <div class="stat-number fail">{fail_count}</div>
                <div class="stat-label">Checks Failed</div>
            </div>
            <div class="stat-card crit-card">
                <div class="stat-number crit">{critical}</div>
                <div class="stat-label">Critical Findings</div>
            </div>
            <div class="stat-card high-card">
                <div class="stat-number high">{high}</div>
                <div class="stat-label">High Findings</div>
            </div>
        </div>
    </div>

    <!-- Severity Distribution Bar -->
    <div class="severity-strip">
        {"<div class='strip-critical' style='flex:{critical}'>{critical} CRIT</div>" if critical > 0 else ""}
        {"<div class='strip-high' style='flex:{high}'>{high} HIGH</div>" if high > 0 else ""}
        {"<div class='strip-medium' style='flex:{medium}'>{medium} MED</div>" if medium > 0 else ""}
        {"<div class='strip-low' style='flex:{low}'>{low} LOW</div>" if low > 0 else ""}
        <div class="strip-pass" style="flex:{pass_count}">{pass_count} PASS</div>
    </div>

    <!-- Service Breakdown -->
    <h2 class="section-title">Service Breakdown</h2>
    <table class="service-table">
        <thead>
            <tr>
                <th>Service</th>
                <th style="text-align:center">Pass</th>
                <th style="text-align:center">Fail</th>
                <th style="text-align:center">Critical</th>
                <th style="text-align:center">High</th>
                <th style="text-align:center">Medium</th>
                <th style="text-align:center">Low</th>
                <th>Compliance</th>
            </tr>
        </thead>
        <tbody>
            {service_rows}
        </tbody>
    </table>

    <!-- Findings by Severity -->
    <h2 class="section-title">Findings Detail</h2>

    <div class="findings-section">
        <div class="severity-header critical">
            <div class="sev-dot"></div>
            <h3>Critical</h3>
            <span class="sev-count">{critical} finding{"s" if critical != 1 else ""}</span>
        </div>
        <div class="findings-grid">
            {critical_cards}
        </div>
    </div>

    <div class="findings-section">
        <div class="severity-header high">
            <div class="sev-dot"></div>
            <h3>High</h3>
            <span class="sev-count">{high} finding{"s" if high != 1 else ""}</span>
        </div>
        <div class="findings-grid">
            {high_cards}
        </div>
    </div>

    <div class="findings-section">
        <div class="severity-header medium">
            <div class="sev-dot"></div>
            <h3>Medium</h3>
            <span class="sev-count">{medium} finding{"s" if medium != 1 else ""}</span>
        </div>
        <div class="findings-grid">
            {medium_cards}
        </div>
    </div>

    <div class="findings-section">
        <div class="severity-header low">
            <div class="sev-dot"></div>
            <h3>Low</h3>
            <span class="sev-count">{low} finding{"s" if low != 1 else ""}</span>
        </div>
        <div class="findings-grid">
            {low_cards}
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        AWS Cloud Security Monitoring Lab · Week 3: Prowler Misconfiguration Scanning<br>
        Kenil · Cybersecurity &amp; Threat Management · Seneca Polytechnic<br>
        Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')} · Powered by <a href="https://github.com/prowler-cloud/prowler">Prowler</a>
    </div>

</div>
</body>
</html>"""

    return html


def main():
    json_path = JSON_FILE
    
    # Allow command line override
    if len(sys.argv) > 1:
        json_path = sys.argv[1]
    
    if not os.path.exists(json_path):
        print(f"[!] ERROR: JSON file not found: {json_path}")
        print(f"[!] Usage: python3 {sys.argv[0]} <prowler-output.json>")
        print(f"[!] Check your scan_results folder:")
        print(f"    ls ~/aws/week3/scan_results/")
        sys.exit(1)
    
    # Load results
    findings = load_prowler_results(json_path)
    
    if not findings:
        print("[!] ERROR: No findings loaded. Check if JSON file is valid.")
        sys.exit(1)
    
    # Analyze
    print("[*] Analyzing findings...")
    stats = analyze_findings(findings)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"  PROWLER SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Account:     {stats.get('account_id', 'N/A')}")
    print(f"  Region:      {stats.get('region', 'N/A')}")
    print(f"  Total Checks: {stats['total']}")
    print(f"  Compliance:   {stats['compliance_score']}%")
    print(f"")
    print(f"  PASS:    {stats['by_status'].get('PASS', 0)}")
    print(f"  FAIL:    {stats['by_status'].get('FAIL', 0)}")
    print(f"    ├─ Critical: {stats['by_severity'].get('critical', 0)}")
    print(f"    ├─ High:     {stats['by_severity'].get('high', 0)}")
    print(f"    ├─ Medium:   {stats['by_severity'].get('medium', 0)}")
    print(f"    └─ Low:      {stats['by_severity'].get('low', 0)}")
    print(f"{'='*60}\n")
    
    # Generate HTML
    print("[*] Generating HTML dashboard...")
    html = generate_html(stats)
    
    output_path = OUTPUT_HTML
    if len(sys.argv) > 2:
        output_path = sys.argv[2]
    
    with open(output_path, 'w') as f:
        f.write(html)
    
    print(f"[+] Dashboard saved to: {output_path}")
    print(f"[+] Open it with: firefox {output_path}")
    print(f"\n[✓] Done!")


if __name__ == '__main__':
    main()
