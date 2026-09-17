"""
Mail Policy Engine for Guardly (Phase 4 / Module 4).
Pure, deterministic policy evaluator mapping Threat Analysis risk scores & findings
to policy enforcement decisions: ALLOW (0-29), REVIEW (30-64), QUARANTINE (65-95), REJECT (96-100).
Configurable, auditable, and independently testable with strict threshold validation.
"""

import os
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("guardly.services.mail_policy")


class PolicyConfig:
    """
    Configurable & validated policy thresholds.
    Default inclusive boundaries:
      ALLOW:      0  to 29
      REVIEW:     30 to 64
      QUARANTINE: 65 to 95
      REJECT:     96 to 100
    """

    def __init__(
        self,
        allow_max: Optional[int] = None,
        review_min: Optional[int] = None,
        review_max: Optional[int] = None,
        quarantine_min: Optional[int] = None,
        quarantine_max: Optional[int] = None,
        reject_min: Optional[int] = None,
    ):
        self.allow_max = allow_max if allow_max is not None else int(os.getenv("POLICY_ALLOW_MAX", 29))
        self.review_min = review_min if review_min is not None else int(os.getenv("POLICY_REVIEW_MIN", 30))
        self.review_max = review_max if review_max is not None else int(os.getenv("POLICY_REVIEW_MAX", 64))
        self.quarantine_min = quarantine_min if quarantine_min is not None else int(os.getenv("POLICY_QUARANTINE_MIN", 65))
        self.quarantine_max = quarantine_max if quarantine_max is not None else int(os.getenv("POLICY_QUARANTINE_MAX", 95))
        self.reject_min = reject_min if reject_min is not None else int(os.getenv("POLICY_REJECT_MIN", 96))

        self.validate()

    def validate(self):
        """
        Enforces configuration integrity:
        - Values must be within 0-100 range.
        - Must be strictly increasing without gaps or overlaps.
        """
        vals = [
            ("ALLOW_MAX", self.allow_max),
            ("REVIEW_MIN", self.review_min),
            ("REVIEW_MAX", self.review_max),
            ("QUARANTINE_MIN", self.quarantine_min),
            ("QUARANTINE_MAX", self.quarantine_max),
            ("REJECT_MIN", self.reject_min),
        ]

        for name, val in vals:
            if not isinstance(val, int) or val < 0 or val > 100:
                raise ValueError(f"Invalid policy threshold value for {name}: {val} (must be 0-100 integer)")

        if not (self.allow_max < self.review_min <= self.review_max < self.quarantine_min <= self.quarantine_max < self.reject_min):
            raise ValueError(
                f"Invalid policy threshold sequence: ALLOW_MAX({self.allow_max}) < REVIEW_MIN({self.review_min}) <= REVIEW_MAX({self.review_max}) "
                f"< QUARANTINE_MIN({self.quarantine_min}) <= QUARANTINE_MAX({self.quarantine_max}) < REJECT_MIN({self.reject_min})"
            )

        # Check for gap-free sequence
        if self.review_min != self.allow_max + 1:
            raise ValueError(f"Gap detected between ALLOW_MAX ({self.allow_max}) and REVIEW_MIN ({self.review_min})")

        if self.quarantine_min != self.review_max + 1:
            raise ValueError(f"Gap detected between REVIEW_MAX ({self.review_max}) and QUARANTINE_MIN ({self.quarantine_min})")

        if self.reject_min != self.quarantine_max + 1:
            raise ValueError(f"Gap detected between QUARANTINE_MAX ({self.quarantine_max}) and REJECT_MIN ({self.reject_min})")


class PolicyEngine:
    """
    Evaluates risk score & findings against active PolicyConfig to determine decision:
    ALLOW, REVIEW, QUARANTINE, REJECT.
    """

    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()

    def evaluate_decision(self, risk_score: int, analysis_result: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        """
        Determines the exact policy decision for a given risk score (0-100).

        Returns:
            Tuple[decision (str), reason (str)]
        """
        # Ensure bounds safety
        score = max(0, min(100, int(risk_score)))
        cfg = self.config

        findings = []
        if analysis_result and isinstance(analysis_result.get("findings"), list):
            findings = analysis_result["findings"]

        findings_summary = "; ".join(findings[:3]) if findings else "Deterministic risk score evaluation"

        if score <= cfg.allow_max:
            decision = "ALLOW"
            reason = f"Risk score {score} is within ALLOW threshold (0-{cfg.allow_max})."
        elif score <= cfg.review_max:
            decision = "REVIEW"
            reason = f"Risk score {score} requires analyst REVIEW ({cfg.review_min}-{cfg.review_max}). {findings_summary}"
        elif score <= cfg.quarantine_max:
            decision = "QUARANTINE"
            reason = f"Risk score {score} triggered QUARANTINE policy ({cfg.quarantine_min}-{cfg.quarantine_max}). {findings_summary}"
        else:
            decision = "REJECT"
            reason = f"Risk score {score} triggered REJECT policy ({cfg.reject_min}-100). {findings_summary}"

        logger.info(f"PolicyEngine evaluated score={score} -> Decision={decision}")
        return decision, reason
