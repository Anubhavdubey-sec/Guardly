"""
Automated YARA & SIEM Sigma Rule Generator for Guardly DFIR Platform
Transforms analyzed email scans and threat indicators into production-grade YARA (.yar)
and SIEM Sigma (.yml) detection rules for Splunk, Elastic, Microsoft Sentinel, and EDRs.
"""

import re
from typing import Any, Dict


def sanitize_rule_name(name: str) -> str:
    """Sanitizes strings into valid YARA rule identifiers (alphanumeric and underscores)."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", name or "phish_indicator").strip("_")
    return clean[:40] if clean else "phishing_email_detection"


def generate_yara_rule(email_data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    """
    Generates a valid, syntax-correct YARA rule targeting headers, subject, body strings, and IOCs.
    """
    subject = str(email_data.get("subject", "") or "Phishing Email Indicator").strip()
    from_addr = str(email_data.get("from_address", "") or email_data.get("from", "")).strip()
    sender_domain = email_data.get("sender_domain") or (from_addr.split("@")[-1] if "@" in from_addr else "")
    urls = email_data.get("urls", [])
    findings = analysis.get("findings", [])
    verdict = analysis.get("verdict", "Suspicious")
    score = analysis.get("score", 50)

    rule_identifier = f"Guardly_Phish_{sanitize_rule_name(subject)}"

    # Build YARA strings section
    yara_strings = []
    string_idx = 1

    if subject:
        safe_subj = subject.replace('\\', '\\\\').replace('"', '\\"')
        yara_strings.append(f'        $subj_{string_idx} = "{safe_subj}" nocase')
        string_idx += 1

    if from_addr:
        safe_from = from_addr.replace('\\', '\\\\').replace('"', '\\"')
        yara_strings.append(f'        $from_{string_idx} = "{safe_from}" nocase')
        string_idx += 1

    for u in urls[:5]:
        safe_u = str(u).replace('\\', '\\\\').replace('"', '\\"')
        yara_strings.append(f'        $url_{string_idx} = "{safe_u}" nocase')
        string_idx += 1

    for f in findings[:3]:
        # Extract keywords
        clean_f = re.sub(r"[^a-zA-Z0-9\s]", "", str(f))[:40].strip()
        if clean_f:
            yara_strings.append(f'        $finding_{string_idx} = "{clean_f}" nocase')
            string_idx += 1

    strings_block = "\n".join(yara_strings) if yara_strings else '        $default_pattern = "phishing" nocase'

    yara_code = f"""/*
  Guardly Automated SOC YARA Rule Generator
  Generated for Scan Threat Indicator: {rule_identifier}
  Risk Verdict: {verdict} (Score: {score}/100)
*/

rule {rule_identifier} {{
    meta:
        description = "Automated YARA threat detection rule derived from Guardly email investigation"
        author = "Guardly Threat Intelligence Subsystem"
        reference = "Internal SOC Report"
        severity = "{verdict}"
        score = {score}

    strings:
{strings_block}

    condition:
        any of them
}}
"""
    return yara_code


def generate_sigma_rule(email_data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    """
    Generates a SIEM Sigma rule (.yml) for ingestion into Splunk, Elastic, Sentinel, and QRadar.
    """
    subject = str(email_data.get("subject", "Suspicious Email Indicator")).strip()
    from_addr = str(email_data.get("from_address", "") or email_data.get("from", "")).strip()
    urls = email_data.get("urls", [])
    verdict = analysis.get("verdict", "Medium Risk")
    score = analysis.get("score", 50)

    title_safe = re.sub(r"[^a-zA-Z0-9\s_-]", "", subject)[:60]

    sigma_code = f"""title: Guardly Phishing Email Indicator - {title_safe}
id: {re.sub(r'[^a-f0-9-]', '', str(hash(subject)))}
status: experimental
description: Detects phishing email campaign matching subject line and sender indicators.
author: Guardly Automated Incident Response Engine
date: 2026/08/07
references:
    - https://guardly.security/soc/investigation
tags:
    - attack.initial_access
    - attack.t1566.001
logsource:
    category: email
    product: m365
detection:
    selection_subject:
        EmailSubject|contains: "{subject.replace('"', '')}"
    selection_sender:
        SenderAddress|contains: "{from_addr.replace('"', '')}"
    condition: selection_subject or selection_sender
falsepositives:
    - Legitimate internal broadcasts with similar subject titles.
level: {"high" if score >= 50 else "medium"}
"""
    return sigma_code
