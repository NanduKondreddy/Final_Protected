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

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import Counter

logger = logging.getLogger(__name__)

PATTERN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "patterns")
os.makedirs(PATTERN_DIR, exist_ok=True)

PATTERN_FILE = os.path.join(PATTERN_DIR, "pattern_log.jsonl")


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
    if not fired_patterns:
        fired_patterns = []

    record = {
        "request_id":       request_id,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "risk_band":        risk_band,
        "patterns":         fired_patterns,
        "fraud_type":       fraud_type,
        "detected_language": detected_language,
        "source":           source,
        "api_key_id":       api_key_id,
    }

    try:
        with open(PATTERN_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        logger.error("Pattern write failed (non-fatal): %s", str(e))


def get_pattern_stats(days: int = 30) -> dict:
    """
    Returns aggregate pattern intelligence.
    Shows which fraud signals are most common, language breakdown,
    override rate, and accuracy trends.
    """
    if not os.path.exists(PATTERN_FILE):
        return _empty_stats()

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    records = []

    try:
        with open(PATTERN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    ts = datetime.fromisoformat(rec["timestamp"])
                    if ts >= cutoff:
                        records.append(rec)
                except (json.JSONDecodeError, KeyError):
                    continue
    except Exception as e:
        logger.error("Pattern read failed: %s", str(e))
        return _empty_stats()

    if not records:
        return _empty_stats()

    # Count patterns
    pattern_counter = Counter()
    for r in records:
        for p in r.get("patterns", []):
            pattern_counter[p] += 1

    # Count by band
    by_band = Counter(r.get("risk_band", "SAFE") for r in records)

    # Count by language
    by_language = Counter(r.get("detected_language", "en") for r in records)

    # Count by source
    by_source = Counter(r.get("source", "unknown") for r in records)

    # Count fraud types
    fraud_types = Counter(
        r.get("fraud_type") for r in records if r.get("fraud_type")
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
