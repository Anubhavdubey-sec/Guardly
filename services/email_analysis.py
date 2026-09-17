from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Union

from services.email_parser import parse_raw_email
from services.threat_analysis import ThreatAnalysisEngine


class EmailAnalysisService:
    def __init__(
        self,
        threat_engine: Optional[ThreatAnalysisEngine] = None,
        attachment_storage_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self.threat_engine = threat_engine or ThreatAnalysisEngine()
        self.attachment_storage_dir = (
            Path(attachment_storage_dir)
            if attachment_storage_dir
            else None
        )

    def analyze_raw(
        self,
        raw_email: Union[bytes, bytearray],
        fallback_message_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not isinstance(raw_email, (bytes, bytearray)):
            raise TypeError("raw_email must be bytes or bytearray")

        if not raw_email:
            raise ValueError("raw_email cannot be empty")

        parsed_email = parse_raw_email(
            bytes(raw_email),
            fallback_message_id=fallback_message_id,
            attachment_storage_dir=self.attachment_storage_dir,
        )

        analysis = self.threat_engine.analyze(parsed_email)

        return self._build_result(parsed_email, analysis)

    def analyze_file(
        self,
        file_path: Union[str, Path],
        fallback_message_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Email file does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"Email path is not a file: {path}"
            )

        return self.analyze_raw(
            path.read_bytes(),
            fallback_message_id=fallback_message_id,
        )

    def analyze_parsed(
        self,
        parsed_email: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not isinstance(parsed_email, dict):
            raise TypeError("parsed_email must be a dictionary")

        if not parsed_email:
            raise ValueError("parsed_email cannot be empty")

        analysis = self.threat_engine.analyze(parsed_email)

        return self._build_result(parsed_email, analysis)

    @staticmethod
    def _normalize_score(value: Any) -> int:
        try:
            score = int(float(value))
        except (TypeError, ValueError):
            score = 0

        return max(0, min(100, score))

    @staticmethod
    def _normalize_findings(value: Any) -> list:
        if value is None:
            return []

        if isinstance(value, list):
            return value

        return [value]

    @staticmethod
    def _build_result(
        parsed_email: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        risk_score = EmailAnalysisService._normalize_score(
            analysis.get("risk_score", 0)
        )

        severity = analysis.get("severity", "LOW")
        recommendation = analysis.get("recommendation", "ALLOW")
        findings = EmailAnalysisService._normalize_findings(
            analysis.get("findings", [])
        )

        return {
            "message_id": parsed_email.get("message_id"),
            "from": parsed_email.get("from"),
            "to": parsed_email.get("to", []),
            "cc": parsed_email.get("cc", []),
            "bcc": parsed_email.get("bcc", []),
            "reply_to": parsed_email.get("reply_to"),
            "return_path": parsed_email.get("return_path"),
            "subject": parsed_email.get("subject"),
            "date": parsed_email.get("date"),
            "received": parsed_email.get("received", []),
            "auth_results": parsed_email.get("auth_results", ""),
            "headers": parsed_email.get("headers", {}),
            "text_body": parsed_email.get("text_body", ""),
            "html_body": parsed_email.get("html_body", ""),
            "urls": parsed_email.get("urls", []),
            "attachments": parsed_email.get("attachments", []),
            "risk_score": risk_score,
            "severity": severity,
            "recommendation": recommendation,
            "findings": findings,
            "authentication": analysis.get("authentication", {}),
            "sender_analysis": analysis.get("sender_analysis", {}),
            "content_analysis": analysis.get("content_analysis", {}),
            "url_analysis": analysis.get("url_analysis", {}),
            "attachment_analysis": analysis.get(
                "attachment_analysis",
                {},
            ),
            "iocs": analysis.get("iocs", {}),
        }


_default_service: Optional[EmailAnalysisService] = None


def get_email_analysis_service() -> EmailAnalysisService:
    global _default_service

    if _default_service is None:
        _default_service = EmailAnalysisService()

    return _default_service


def analyze_raw_email(
    raw_email: Union[bytes, bytearray],
    fallback_message_id: Optional[str] = None,
) -> Dict[str, Any]:
    return get_email_analysis_service().analyze_raw(
        raw_email,
        fallback_message_id=fallback_message_id,
    )


def analyze_email_file(
    file_path: Union[str, Path],
    fallback_message_id: Optional[str] = None,
) -> Dict[str, Any]:
    return get_email_analysis_service().analyze_file(
        file_path,
        fallback_message_id=fallback_message_id,
    )


def analyze_parsed_email(
    parsed_email: Dict[str, Any],
) -> Dict[str, Any]:
    return get_email_analysis_service().analyze_parsed(
        parsed_email
    )


__all__ = [
    "EmailAnalysisService",
    "get_email_analysis_service",
    "analyze_raw_email",
    "analyze_email_file",
    "analyze_parsed_email",
]