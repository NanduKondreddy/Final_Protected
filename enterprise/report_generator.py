"""
ShieldIQ Enterprise — Intelligence Report Generator
─────────────────────────────────────────────────────
Generates executive threat reports for enterprise admins/CISOs.
Uses audit and pattern data — never accesses message content.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from enterprise.audit_store import get_admin_summary
from enterprise.pattern_store import get_pattern_stats

logger = logging.getLogger(__name__)


def generate_report(days: int = 30, org_id: Optional[str] = None) -> dict:
    """
    Generate a comprehensive intelligence report.
    Suitable for download as PDF or display in admin dashboard.
    """
    summary = get_admin_summary(days=days, org_id=org_id)
    patterns = get_pattern_stats(days=days)

    total = summary.get("total_scans", 0)
    high_risk = summary.get("by_band", {}).get("HIGH_RISK", 0)
    caution = summary.get("by_band", {}).get("CAUTION", 0)
    safe = summary.get("by_band", {}).get("SAFE", 0)

    # Calculate threat density
    threat_rate = round((high_risk / max(total, 1)) * 100, 1)
    engagement_rate = round(((high_risk + caution) / max(total, 1)) * 100, 1)

    # Top threat vectors
    top_patterns = patterns.get("top_patterns", [])[:5]
    top_fraud_types = patterns.get("top_fraud_types", [])[:5]

    report = {
        "report_type": "ShieldIQ Enterprise Threat Intelligence Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_days": days,
        "org_id": org_id,

        "executive_summary": {
            "total_scans": total,
            "threats_neutralised": high_risk,
            "threat_rate_pct": threat_rate,
            "avg_latency_ms": summary.get("avg_latency_ms", 0),
            "override_rate_pct": summary.get("override_rate_pct", 0),
        },

        "risk_breakdown": {
            "safe": safe,
            "caution": caution,
            "high_risk": high_risk,
            "engagement_rate_pct": engagement_rate,
        },

        "threat_vectors": {
            "top_patterns": top_patterns,
            "top_fraud_types": top_fraud_types,
        },

        "source_analysis": summary.get("by_source", {}),
        "language_analysis": summary.get("by_language", {}),

        "compliance": {
            "zero_retention": True,
            "message_content_stored": False,
            "gdpr_compliant": True,
            "data_scope": "verdict metadata only",
        },

        "recommendations": _generate_recommendations(
            threat_rate, top_patterns, summary.get("by_source", {})
        ),
    }

    return report


def _generate_recommendations(threat_rate: float, top_patterns: list, sources: dict) -> list:
    """Generate actionable recommendations based on the data."""
    recs = []

    if threat_rate > 15:
        recs.append(
            "HIGH ALERT: Threat rate exceeds 15%. Consider mandatory security awareness training."
        )
    elif threat_rate > 5:
        recs.append(
            "Elevated threat activity detected. Review top fraud patterns with your security team."
        )

    pattern_names = [p.get("pattern", "") for p in top_patterns]
    if "bank_impersonation" in pattern_names or "fintech_impersonation" in pattern_names:
        recs.append(
            "Bank/fintech impersonation is trending. Alert employees about fake transaction alerts."
        )
    if "otp_request" in pattern_names:
        recs.append(
            "OTP harvesting attempts detected. Remind employees to never share OTPs via chat."
        )

    if not recs:
        recs.append("Threat levels are within normal range. Continue monitoring.")

    return recs
