"""
Executive PDF Incident Report Exporter for Guardly
Generates professional PDF forensic investigation reports using ReportLab.
Includes executive verdict gauges, email telemetry, DFIR header findings, URL threat analysis,
NLP social engineering scores, SOC playbooks, and compiled YARA rules.
"""

import html
import io
from datetime import datetime, timezone
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _clean_text(val: Any) -> str:
    if val is None:
        return ""
    text_str = str(val)
    # Escape XML / HTML special characters for ReportLab Paragraph
    escaped = html.escape(text_str)
    # Replace common non-ASCII typographic characters
    replacements = {
        "“": '"', "”": '"', "‘": "'", "’": "'", "—": "-", "–": "-",
        "…": "...", "•": "*", "€": "EUR", "£": "GBP", "¥": "JPY"
    }
    for orig, repl in replacements.items():
        escaped = escaped.replace(orig, repl)
    # Safe encoding for standard ReportLab fonts
    return escaped.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_scan_report(email_data: Dict[str, Any], analysis: Dict[str, Any], scan_id: int) -> bytes:
    """
    Generates a professional PDF Incident Report document and returns the PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom ReportLab Styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12,
    )

    section_heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    mono_style = ParagraphStyle(
        "ReportMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("GUARDLY DFIR THREAT INVESTIGATION REPORT", title_style))
    scanned_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Scan Incident Report #{scan_id} &nbsp;|&nbsp; Generated: {scanned_time} &nbsp;|&nbsp; Guardly v2.5 Engine", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=12))

    # 2. Verdict & Risk Score Card
    verdict = analysis.get("verdict", "Low Risk")
    score = analysis.get("score", 0)

    if verdict == "High Risk" or score >= 50:
        verdict_color = colors.HexColor("#ef4444")
    elif verdict == "Medium Risk" or score >= 20:
        verdict_color = colors.HexColor("#f59e0b")
    else:
        verdict_color = colors.HexColor("#10b981")

    verdict_text = f"<b>OVERALL VERDICT:</b> {verdict.upper()} &nbsp;&nbsp;|&nbsp;&nbsp; <b>RISK SCORE:</b> {score} / 100"
    verdict_p = Paragraph(verdict_text, ParagraphStyle("VerdictStyle", parent=body_style, textColor=colors.white, fontSize=11, leading=15))

    verdict_table = Table([[verdict_p]], colWidths=[540])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # 3. Message Telemetry Summary
    story.append(Paragraph("Message Metadata & Telemetry", section_heading_style))
    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(_clean_text(email_data.get("subject", "N/A")), body_style)],
        [Paragraph("<b>From:</b>", body_style), Paragraph(_clean_text(email_data.get("from", "N/A")), mono_style)],
        [Paragraph("<b>To / Recipient:</b>", body_style), Paragraph(_clean_text(email_data.get("to", "N/A")), mono_style)],
        [Paragraph("<b>Reply-To Domain:</b>", body_style), Paragraph(_clean_text(email_data.get("reply_to", "N/A")), mono_style)],
        [Paragraph("<b>Sender Domain:</b>", body_style), Paragraph(_clean_text(email_data.get("sender_domain", "N/A")), mono_style)],
    ]
    meta_table = Table(meta_data, colWidths=[130, 410])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 4. Authentication Check Controls
    story.append(Paragraph("Authentication Controls (SPF, DKIM, DMARC)", section_heading_style))
    auth = analysis.get("auth_results", {})
    auth_data = [
        [Paragraph("<b>Check</b>", body_style), Paragraph("<b>Status Verdict</b>", body_style)],
        [Paragraph("SPF (Sender Policy Framework)", body_style), Paragraph(_clean_text(auth.get("spf", "neutral")).upper(), body_style)],
        [Paragraph("DKIM (DomainKeys Identified Mail)", body_style), Paragraph(_clean_text(auth.get("dkim", "neutral")).upper(), body_style)],
        [Paragraph("DMARC Alignment", body_style), Paragraph(_clean_text(auth.get("dmarc", "neutral")).upper(), body_style)],
    ]
    auth_table = Table(auth_data, colWidths=[300, 240])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 10))

    # 5. Detected Threat Findings
    findings = analysis.get("findings", [])
    if findings:
        story.append(Paragraph("Observed Threat Anomalies & Findings", section_heading_style))
        find_rows = [[Paragraph("<b>#</b>", body_style), Paragraph("<b>Finding Description</b>", body_style)]]
        for idx, f in enumerate(findings[:8], 1):
            find_rows.append([Paragraph(str(idx), body_style), Paragraph(_clean_text(f), body_style)])
        find_table = Table(find_rows, colWidths=[30, 510])
        find_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#fee2e2")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#fca5a5")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(find_table)
        story.append(Spacer(1, 10))

    # 6. AI NLP Social Engineering Analysis
    nlp = analysis.get("nlp_analysis")
    if nlp:
        story.append(Paragraph("AI NLP Social Engineering Intelligence", section_heading_style))
        se_text = f"<b>Social Engineering Score:</b> {nlp.get('social_engineering_score', 0)} / 100 &nbsp;&nbsp;|&nbsp;&nbsp; <b>Risk Level:</b> {_clean_text(nlp.get('threat_level', 'Low'))}"
        tactics_str = _clean_text(", ".join(nlp.get("tactics", [])) or "None detected")
        nlp_rows = [
            [Paragraph(se_text, body_style)],
            [Paragraph(f"<b>Detected NLP Vectors:</b> {tactics_str}", body_style)],
        ]
        nlp_table = Table(nlp_rows, colWidths=[540])
        nlp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(nlp_table)
        story.append(Spacer(1, 10))

    # 7. Automated YARA Rule Preview
    yara_code = analysis.get("yara_rule")
    if yara_code:
        story.append(Paragraph("Compiled Enterprise YARA Rule", section_heading_style))
        clean_yara = _clean_text(yara_code).replace("\n", "<br/>").replace(" ", "&nbsp;")
        yara_p = Paragraph(clean_yara, mono_style)
        yara_table = Table([[yara_p]], colWidths=[540])
        yara_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#0f172a")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(yara_table)

    # Build PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
