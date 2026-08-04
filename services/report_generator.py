import io


def build_scan_report(scan, email_data, analysis):
    """Generate a simple PDF report buffer for the scan."""
    pdf_content = (
        f"%PDF-1.4\n"
        f"% PhishGuard Scan Report #{scan.id}\n"
        f"Subject: {scan.subject}\n"
        f"Verdict: {analysis.get('verdict', scan.verdict)}\n"
        f"Score: {analysis.get('score', scan.risk_score)}/100\n"
        f"%%EOF\n"
    ).encode("utf-8")
    return io.BytesIO(pdf_content)
