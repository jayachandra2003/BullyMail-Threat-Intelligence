import io
import csv
import html
from datetime import datetime

class ReportGenerator:
    """PDF & CSV Threat Report Generator Service with Strict XSS Sanitization"""

    @staticmethod
    def generate_csv_report(analyses):
        """Generates a CSV export of analysis records."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'ID', 'Date', 'Subject', 'From', 'Overall Risk', 'Confidence',
            'Threat Score', 'Bullying Detected', 'Phishing Risk',
            'Suspicious URLs', 'Malware Risk', 'Social Eng Risk', 'Model Used'
        ])
        
        for a in analyses:
            writer.writerow([
                a.get('id', ''),
                a.get('created_at', ''),
                a.get('email_subject', 'No Subject'),
                a.get('email_from', 'Unknown'),
                a.get('overall_risk_level', 'LOW'),
                f"{int(float(a.get('overall_confidence', 0)) * 100)}%",
                a.get('threat_score', 0),
                'Yes' if a.get('is_bullying') else 'No',
                a.get('phishing_risk_level', 'LOW'),
                a.get('suspicious_urls_count', 0),
                a.get('malware_risk_level', 'LOW'),
                a.get('social_eng_risk_level', 'LOW'),
                a.get('model_used', 'Hybrid')
            ])
            
        return output.getvalue().encode('utf-8')

    @staticmethod
    def generate_html_report(analysis):
        """
        Generates a clean, standalone, printable HTML security report (printable to PDF).
        Strictly escapes all untrusted user and email data to prevent HTML/XSS injection.
        """
        created = html.escape(str(analysis.get('created_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))))
        overall_risk = html.escape(str(analysis.get('overall_risk_level', 'LOW')))
        conf_pct = int(float(analysis.get('overall_confidence', 0.0)) * 100)
        report_id = html.escape(str(analysis.get('id', 'N/A')))
        
        # Color coding
        color_map = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        badge_color = color_map.get(overall_risk, '#6c757d')
        
        # Escaped email headers
        subj_clean = html.escape(str(analysis.get('email_subject') or 'No Subject'))
        from_clean = html.escape(str(analysis.get('email_from') or 'Unknown'))
        to_clean = html.escape(str(analysis.get('email_to') or 'N/A'))
        body_clean = html.escape(str(analysis.get('email_text') or 'No content'))
        
        # Evidence items escaping
        evidence_items = analysis.get('evidence_summary') or analysis.get('evidence') or []
        
        html_doc = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>BullyMail Threat Analysis Report - #{report_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #212529; background: #fff; line-height: 1.5; }}
        .header {{ border-bottom: 3px solid #262d4e; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .brand {{ font-size: 26px; font-weight: bold; color: #262d4e; }}
        .report-badge {{ background: {badge_color}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 16px; text-transform: uppercase; }}
        .meta-box {{ background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin-bottom: 25px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
        .metric-card {{ background: #fff; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; }}
        .metric-title {{ font-size: 13px; color: #6c757d; text-transform: uppercase; margin-bottom: 5px; font-weight: 600; }}
        .metric-val {{ font-size: 20px; font-weight: bold; color: #262d4e; }}
        h2 {{ color: #262d4e; font-size: 18px; border-bottom: 2px solid #e9ecef; padding-bottom: 8px; margin-top: 30px; }}
        .evidence-item {{ background: #fff; border-left: 4px solid {badge_color}; border-top: 1px solid #eee; border-right: 1px solid #eee; border-bottom: 1px solid #eee; border-radius: 4px; padding: 12px 15px; margin-bottom: 10px; }}
        .evidence-cat {{ font-size: 12px; font-weight: bold; color: {badge_color}; text-transform: uppercase; }}
        .evidence-title {{ font-size: 15px; font-weight: 600; margin: 3px 0; }}
        .evidence-detail {{ font-size: 14px; color: #495057; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; text-align: center; }}
        @media print {{ body {{ margin: 0; }} .no-print {{ display: none; }} }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="brand">🛡️ BullyMail Security Audit Report</div>
            <div style="color: #6c757d; font-size: 13px;">Generated on {html.escape(datetime.now().strftime('%B %d, %Y at %H:%M:%S'))}</div>
        </div>
        <div>
            <span class="report-badge">{overall_risk} RISK</span>
        </div>
    </div>

    <div class="meta-box">
        <div style="font-size: 18px; font-weight: bold; margin-bottom: 10px;">Subject: {subj_clean}</div>
        <div class="grid">
            <div><strong>Sender:</strong> {from_clean}</div>
            <div><strong>Recipient:</strong> {to_clean}</div>
            <div><strong>Analysis Timestamp:</strong> {created}</div>
            <div><strong>Overall Confidence:</strong> {conf_pct}%</div>
        </div>
    </div>

    <h2>Threat Vector Breakdown</h2>
    <div class="grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 25px;">
        <div class="metric-card">
            <div class="metric-title">Cyberbullying</div>
            <div class="metric-val">{'DETECTED' if analysis.get('is_bullying') else 'NOT DETECTED'}</div>
            <div style="font-size: 12px; color: #6c757d;">Confidence: {int(float(analysis.get('confidence', 0))*100)}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Phishing Intent</div>
            <div class="metric-val">{html.escape(str(analysis.get('phishing_risk_level', 'LOW')))}</div>
            <div style="font-size: 12px; color: #6c757d;">Confidence: {int(float(analysis.get('phishing_confidence', 0))*100)}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Link & URL Risk</div>
            <div class="metric-val">{int(analysis.get('suspicious_urls_count', 0))} Risky Links</div>
            <div style="font-size: 12px; color: #6c757d;">Total: {int(analysis.get('urls_detected', 0))} URLs</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Social Engineering</div>
            <div class="metric-val">{html.escape(str(analysis.get('social_eng_risk_level', 'LOW')))}</div>
            <div style="font-size: 12px; color: #6c757d;">Confidence: {int(float(analysis.get('social_eng_confidence', 0))*100)}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Attachment / Malware</div>
            <div class="metric-val">{html.escape(str(analysis.get('malware_risk_level', 'LOW')))}</div>
            <div style="font-size: 12px; color: #6c757d;">Files: {int(analysis.get('attachments_count', 0))}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Image Forensics</div>
            <div class="metric-val">{html.escape(str(analysis.get('image_risk_level', 'LOW')))}</div>
            <div style="font-size: 12px; color: #6c757d;">Images: {int(analysis.get('images_count', 0))}</div>
        </div>
    </div>

    <h2>Explainable AI Evidence & Findings</h2>
    <div>
"""
        if evidence_items:
            for ev in evidence_items:
                ev_cat = html.escape(str(ev.get('category', 'Threat Indicator')))
                ev_sev = html.escape(str(ev.get('severity', 'MEDIUM')))
                ev_title = html.escape(str(ev.get('title', '')))
                ev_detail = html.escape(str(ev.get('details', '')))
                html_doc += f"""
        <div class="evidence-item">
            <div class="evidence-cat">{ev_cat} &bull; Severity: {ev_sev}</div>
            <div class="evidence-title">{ev_title}</div>
            <div class="evidence-detail">{ev_detail}</div>
        </div>
"""
        else:
            html_doc += """
        <div style="padding: 15px; background: #e8f5e9; color: #2e7d32; border-radius: 6px;">
            ✅ No malicious, hostile, or fraudulent threat indicators were found in this communication.
        </div>
"""

        html_doc += f"""
    </div>

    <h2>Analyzed Email Content</h2>
    <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; white-space: pre-wrap; font-family: monospace; font-size: 13px;">{body_clean}</div>

    <div class="footer">
        BullyMail V2 Enterprise Threat Intelligence Platform &bull; Automated Static Forensics & NLP Analysis &bull; Confidential
    </div>
</body>
</html>"""
        return html_doc.encode('utf-8')
