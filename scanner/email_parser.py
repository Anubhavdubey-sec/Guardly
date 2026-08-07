import email
from email import policy
from email.utils import parseaddr
import re

from scanner.pdf_scanner import extract_pdf_intel
from scanner.qr_ocr_scanner import scan_attachment_for_quishing
from scanner.timeline import build_delivery_timeline

URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+")
DOMAIN_REGEX = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_email(file_path):
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    subject_header = msg.get("Subject", "")
    date_header = msg.get("Date", "")
    reply_to_header = msg.get("Reply-To", "")

    from_name, from_address = parseaddr(str(from_header))

    body_plain = ""
    body_html = ""
    attachments = []
    pdf_urls = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                att_info = {
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(payload),
                }

                if content_type == "application/pdf" or filename.lower().endswith(".pdf"):
                    pdf_intel = extract_pdf_intel(payload)
                    att_info["pdf_scan"] = {
                        "urls": pdf_intel["urls"],
                        "page_count": pdf_intel["page_count"],
                        "error": pdf_intel["error"],
                    }
                    for pu in pdf_intel["urls"]:
                        if pu not in pdf_urls:
                            pdf_urls.append(pu)

                # Scan inline images & image attachments for Quishing QR Codes
                quishing_res = scan_attachment_for_quishing(payload, filename, content_type)
                if quishing_res["has_qr_code"]:
                    att_info["quishing_scan"] = quishing_res
                    for q_url in quishing_res["qr_urls"]:
                        if q_url not in pdf_urls:
                            pdf_urls.append(q_url)

                attachments.append(att_info)
            elif content_type == "text/plain":
                body_plain += part.get_content() or ""
            elif content_type == "text/html":
                body_html += part.get_content() or ""
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_plain = msg.get_content() or ""
        elif content_type == "text/html":
            body_html = msg.get_content() or ""

    full_body = body_plain or body_html or ""
    body_urls = list(dict.fromkeys(URL_REGEX.findall(full_body)))

    # Combine body URLs and PDF URLs preserving order and de-duplicating
    combined_urls = []
    seen_urls = set()
    for u in body_urls + pdf_urls:
        if u not in seen_urls:
            seen_urls.add(u)
            combined_urls.append(u)

    extracted_domains = list(dict.fromkeys(DOMAIN_REGEX.findall(full_body)))
    extracted_ips = list(dict.fromkeys(IP_REGEX.findall(full_body)))

    timeline_analysis = build_delivery_timeline(msg)

    return {
        "from": str(from_header),
        "from_address": from_address,
        "from_name": from_name,
        "to": str(to_header),
        "subject": str(subject_header),
        "date": str(date_header),
        "reply_to": str(reply_to_header),
        "body": full_body,
        "urls": combined_urls,
        "pdf_urls": pdf_urls,
        "attachments": attachments,
        "headers": dict(msg.items()),
        "has_html": bool(body_html),
        "has_plain_text": bool(body_plain),
        "iocs": {
            "domains": extracted_domains,
            "ip_addresses": extracted_ips,
            "urls": combined_urls,
        },
        "delivery_timeline": timeline_analysis.to_dict(),
    }
