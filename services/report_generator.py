import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def build_scan_report(scan, email_data, analysis):
    """
    Generate a genuine, production-quality ReportLab PDF threat analysis report.
    Returns an io.BytesIO buffer containing the compiled binary PDF document.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    primary_color = colors.HexColor("#1E3A8A")   # Dark Navy
    accent_blue = colors.HexColor("#2563EB")     # Cyan Blue
    text_dark = colors.HexColor("#1F2937")       # Charcoal
    text_muted = colors.HexColor("#6B7280")      # Gray
    bg_light = colors.HexColor("#F8FAFC")        # Off White
    border_color = colors.HexColor("#E2E8F0")    # Border Gray

    score = analysis.get("score", scan.risk_score)
    verdict = analysis.get("verdict", scan.verdict)

    if score >= 50:
        verdict_color = colors.HexColor("#DC2626")  # Red
        verdict_bg = colors.HexColor("#FEE2E2")
    elif score >= 20:
        verdict_color = colors.HexColor("#D97706")  # Amber
        verdict_bg = colors.HexColor("#FEF3C7")
    else:
        verdict_color = colors.HexColor("#16A34A")  # Green
        verdict_bg = colors.HexColor("#DCFCE7")

    # Typography Styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=text_muted,
        spaceAfter=12,
    )

    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=text_dark,
    )

    mono_style = ParagraphStyle(
        "MonoText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=text_dark,
    )

    story = []

    # 1. Header Banner
    header_data = [
        [
            Paragraph("<b>PhishGuard</b> <font color='#64748B'>| Email Security Telemetry</font>", title_style),
            Paragraph(f"<b>REPORT #{scan.id:05d}</b><br/><font color='#64748B'>{datetime.now().strftime('%b %d, %Y %H:%M UTC')}</font>", ParagraphStyle("HeaderRight", parent=subtitle_style, alignment=2)),
        ]
    ]
    header_table = Table(header_data, colWidths=[340, 200])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1, color=accent_blue, spaceAfter=12))

    # 2. Executive Summary Box
    summary_data = [
        [
            Paragraph(f"<font color='{verdict_color.hexval()}'><b>VERDICT: {verdict.upper()}</b></font><br/><font size=8 color='#4B5563'>Threat Assessment Status</font>", body_style),
            Paragraph(f"<b>RISK SCORE</b><br/><font size=16 color='{verdict_color.hexval()}'><b>{score} / 100</b></font>", ParagraphStyle("ScoreText", parent=body_style, alignment=1)),
            Paragraph(f"<b>ARTIFACT</b><br/>RFC822 Email Sample<br/><b>Date:</b> {email_data.get('date', 'Unknown')}", body_style),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[200, 140, 200])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_light),
        ("BOX", (0, 0), (-1, -1), 1, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 3. Message Context Table
    story.append(Paragraph("Message Metadata & Context", h2_style))
    meta_data = [
        [Paragraph("<b>Subject Line</b>", body_style), Paragraph(str(email_data.get("subject", "(no subject)")), body_style)],
        [Paragraph("<b>From Header</b>", body_style), Paragraph(str(email_data.get("from_address", email_data.get("from", "Unknown"))), mono_style)],
        [Paragraph("<b>Reply-To Header</b>", body_style), Paragraph(str(email_data.get("reply_to") or "None specified"), mono_style)],
        [Paragraph("<b>Recipient (To)</b>", body_style), Paragraph(str(email_data.get("to", "Unknown")), mono_style)],
        [Paragraph("<b>Attachments</b>", body_style), Paragraph(f"{len(email_data.get('attachments', []))} attached files", body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[130, 410])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), bg_light),
        ("GRID", (0, 0), (-1, -1), 0.5, border_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 4. Triggered Security Findings Table
    story.append(Paragraph("Rule Engine Findings & Threat Signals", h2_style))
    findings = analysis.get("findings", [])
    categories = analysis.get("categories", [])

    if findings:
        finding_rows = [[Paragraph("<b>Category</b>", body_style), Paragraph("<b>Detection Finding</b>", body_style)]]
        for idx, finding in enumerate(findings):
            cat = categories[idx] if idx < len(categories) else "Threat Signal"
            finding_rows.append([
                Paragraph(f"<b>{cat}</b>", body_style),
                Paragraph(str(finding), body_style),
            ])
        finding_table = Table(finding_rows, colWidths=[150, 390])
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), bg_light),
            ("GRID", (0, 0), (-1, -1), 0.5, border_color),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(finding_table)
    else:
        story.append(Paragraph("<i>No high-severity threat signals were triggered for this message.</i>", body_style))

    story.append(Spacer(1, 14))

    # 5. Extracted URLs / Indicators
    urls = email_data.get("urls", [])
    if urls:
        story.append(Paragraph(f"Extracted Hyperlinks ({len(urls)})", h2_style))
        url_rows = [[Paragraph("<b>URL Target Indicator</b>", body_style)]]
        for u in urls[:10]:
            url_rows.append([Paragraph(str(u), mono_style)])
        url_table = Table(url_rows, colWidths=[540])
        url_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), bg_light),
            ("GRID", (0, 0), (-1, -1), 0.5, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(url_table)

    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", thickness=0.5, color=text_muted, spaceAfter=8))
    story.append(Paragraph(
        "<b>PhishGuard Security Architecture:</b> All heuristics and parsing algorithms evaluated locally on-device. "
        "Report compiled automatically.",
        subtitle_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer
