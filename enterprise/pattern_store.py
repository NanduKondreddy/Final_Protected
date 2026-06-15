"""
ShieldIQ Enterprise — Pattern Intelligence Store
──────────────────────────────────────────────────
Stores aggregate pattern data — the "data moat" from every scan.
Every scan teaches ShieldIQ what fraud looks like in this region.

This stores ONLY:
- Which fraud patterns were detected
- Which source triggered them
- Which language they appeared in

NEVER stores message content.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import Counter

from database import SessionLocal
import db_models

logger = logging.getLogger(__name__)


def write_pattern(
    request_id: str,
    risk_band: str,
    fired_patterns: list = None,
    fraud_type: Optional[str] = None,
    detected_language: str = "en",
    source: str = "web_app",
    api_key_id: Optional[str] = None,
) -> None:
    """
    Write a pattern intelligence record.
    Only stores the pattern signals — never message content.
    """
    db = SessionLocal()
    try:
        record = db_models.PatternRecord(
            request_id=request_id,
            risk_band=risk_band,
            patterns=fired_patterns or [],
            fraud_type=fraud_type,
            detected_language=detected_language,
            source=source,
            api_key_id=api_key_id,
        )
        db.add(record)
        db.commit()
    except Exception as e:
        logger.error("Pattern DB write failed (non-fatal): %s", str(e))
    finally:
        db.close()


def get_pattern_stats(days: int = 30) -> dict:
    """
    Returns aggregate pattern intelligence.
    Shows which fraud signals are most common, language breakdown,
    override rate, and accuracy trends.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db = SessionLocal()
    try:
        records = db.query(db_models.PatternRecord).filter(db_models.PatternRecord.timestamp >= cutoff).all()
    except Exception as e:
        logger.error("Pattern DB read failed: %s", str(e))
        return _empty_stats()
    finally:
        db.close()

    if not records:
        return _empty_stats()

    # Count patterns
    pattern_counter = Counter()
    for r in records:
        for p in (r.patterns or []):
            pattern_counter[p] += 1

    # Count by band
    by_band = Counter(r.risk_band for r in records)

    # Count by language
    by_language = Counter(r.detected_language for r in records)

    # Count by source
    by_source = Counter(r.source for r in records)

    # Count fraud types
    fraud_types = Counter(
        r.fraud_type for r in records if r.fraud_type
    )

    top_patterns = [
        {"pattern": p, "count": c}
        for p, c in pattern_counter.most_common(15)
    ]

    return {
        "total_scans": len(records),
        "by_band": dict(by_band),
        "by_language": dict(by_language),
        "by_source": dict(by_source),
        "top_patterns": top_patterns,
        "top_fraud_types": [
            {"type": t, "count": c}
            for t, c in fraud_types.most_common(10)
        ],
    }


def _empty_stats() -> dict:
    return {
        "total_scans": 0,
        "by_band": {},
        "by_language": {},
        "by_source": {},
        "top_patterns": [],
        "top_fraud_types": [],
    }
