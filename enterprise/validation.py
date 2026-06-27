"""
ShieldIQ Enterprise — Output Validation Engine
─────────────────────────────────────────────────
Cross-checks AI verdict against pattern matching.
If the AI says SAFE but 8 risk patterns fire — something is wrong.
This layer catches contradictions and overrides them.

Also performs:
- Score normalisation (ensures 0-100)
- Language bias detection
- Contradiction override with audit log
"""

import re
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Risk patterns ─────────────────────────────────────────────────────────────

RISK_PATTERNS = [
    # Financial urgency
    (r"\b(urgent|urgently|immediately|now now|right now|asap)\b", "urgency"),
    (r"\b(suspend|suspended|block|blocked|deactivat|restrict)\b", "account_threat"),
    (r"\b(verify|verification|confirm|validate)\s+.{0,30}(account|identity|bvn|nin)", "verification_request"),

    # Financial requests
    (r"\b(send|transfer|pay|deposit)\s+.{0,20}(₦|\bnaira\b|\bngn\b|\d+k\b|\d+,\d{3})", "financial_request"),
    (r"\b(processing fee|activation fee|registration fee|clearance fee)\b", "fee_request"),
    (r"\b(recharge|airtime|voucher|scratch card)\s+.{0,20}(send|buy|give)", "airtime_request"),

    # Impersonation signals
    (r"\b(gtbank|access bank|zenith|first bank|uba|fidelity)\b.{0,50}(security|alert|notify|verify)", "bank_impersonation"),
    (r"\b(efcc|firs|frsc|nafdac|cbn|inec)\b.{0,50}(notice|alert|warning|summon|invite)", "govt_impersonation"),
    (r"\b(opay|palmpay|moniepoint|kuda)\b.{0,50}(suspend|block|verify|alert)", "fintech_impersonation"),

    # Suspicious links
    (r"https?://[^\s]+\.(xyz|top|click|loan|info|biz|site|online)\b", "suspicious_tld"),
    (r"https?://[^\s]*-(secure|verify|alert|update|confirm)[^\s]*", "suspicious_subdomain"),
    (r"bit\.ly|tinyurl|t\.co|rb\.gy|cutt\.ly", "link_shortener"),

    # Prize and opportunity fraud
    (r"\b(congratulation|you (have|has|ve) won|winner|selected|chosen)\b", "prize_claim"),
    (r"\b(scholarship|grant|loan)\s+.{0,30}(approved|awarded|won|selected)", "fake_award"),
    (r"\b(double|triple|multiply|invest).{0,20}(return|profit|income|money)", "investment_fraud"),

    # Social engineering
    (r"\b(don.t tell|keep (this|it) secret|between us|confidential)\b", "secrecy_demand"),
    (r"\b(new number|saved me|my number (has )?change)\b", "number_change_scam"),
    (r"\b(otp|one.time.password|token|pin).{0,30}(send|share|give|provide)", "otp_request"),
]


def score_to_band(score: int) -> str:
    """Convert numeric score to risk band."""
    if score <= 30:
        return "SAFE"
    elif score <= 69:
        return "CAUTION"
    else:
        return "HIGH_RISK"


def scan_patterns(message: str) -> tuple:
    """Scan message for risk patterns. Returns (count, fired_pattern_names)."""
    message_lower = message.lower()
    fired = []
    for pattern, name in RISK_PATTERNS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            fired.append(name)
    return len(fired), fired


def validate_result(verdict: dict) -> dict:
    """
    Validate and normalise AI verdict JSON structure.
    Ensures required fields exist and scores are within range.
    """
    # Ensure risk_score is in range
    score = verdict.get("risk_score", 50)
    try:
        score = int(score)
    except (ValueError, TypeError):
        score = 50
    score = max(0, min(100, score))
    verdict["risk_score"] = score

    # Ensure risk_band matches score
    verdict["risk_band"] = score_to_band(score)

    # Default missing fields
    verdict.setdefault("verdict_summary", "Analysis complete.")
    verdict.setdefault("reasons", [])
    verdict.setdefault("score_explanation", "")
    verdict.setdefault("recommendation", "")
    verdict.setdefault("fraud_type", None)
    verdict.setdefault("fired_patterns", [])
    verdict.setdefault("was_overridden", False)

    return verdict


def apply_bias_correction(verdict: dict, message: str) -> tuple:
    """
    Apply pattern-based correction to AI verdict.

    Override rules:
    - AI says SAFE but 5+ patterns fire → upgrade to CAUTION
    - AI says SAFE but 8+ patterns fire → upgrade to HIGH_RISK
    - AI says HIGH_RISK but 0 patterns fire → downgrade to CAUTION
      (unless suspicious links present)

    Returns (corrected_verdict, bias_detected)
    """
    pattern_count, fired_patterns = scan_patterns(message)
    ai_score = verdict.get("risk_score", 50)
    ai_band = score_to_band(ai_score)

    was_overridden = False
    bias_detected = False

    has_suspicious_link = any(
        p in fired_patterns
        for p in ["suspicious_tld", "suspicious_subdomain", "link_shortener"]
    )

    if ai_band == "SAFE" and pattern_count >= 8:
        verdict["risk_score"] = 75
        verdict["risk_band"] = "HIGH_RISK"
        was_overridden = True
    elif ai_band == "SAFE" and pattern_count >= 5:
        verdict["risk_score"] = 45
        verdict["risk_band"] = "CAUTION"
        was_overridden = True
    elif ai_band == "CAUTION" and pattern_count >= 8:
        verdict["risk_score"] = 80
        verdict["risk_band"] = "HIGH_RISK"
        was_overridden = True
    elif ai_band == "HIGH_RISK" and pattern_count == 0 and not has_suspicious_link:
        verdict["risk_score"] = 50
        verdict["risk_band"] = "CAUTION"
        was_overridden = True
        bias_detected = True

    if was_overridden:
        verdict["was_overridden"] = True
        verdict["fired_patterns"] = fired_patterns
        logger.warning(
            "Verdict overridden: ai_score=%d final_score=%d patterns=%d",
            ai_score, verdict["risk_score"], pattern_count
        )

    return verdict, bias_detected
