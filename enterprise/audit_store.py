"""
ShieldIQ Enterprise — Audit Trail Store
────────────────────────────────────────
Records every scan verdict (metadata only — never message content).
Provides aggregate queries for the admin dashboard and reports.

Zero-Retention Compliance:
  - Message content is NEVER passed to or stored by this module
  - Only verdict metadata (score, band, language, latency, source)
  - GDPR/privacy safe by design
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from database import SessionLocal
import db_models

logger = logging.getLogger(__name__)


def write_audit(
    request_id: str,
    risk_score: int,
    risk_band: str,
    detected_language: str = "en",
    provider_used: str = "gemini",
    latency_ms: int = 0,
    source: str = "web_app",
    was_overridden: bool = False,
    fraud_type: Optional[str] = None,
    api_key_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> None:
    """
    Write a single audit record. This NEVER receives message content.
    """
    db = SessionLocal()
    try:
        record = db_models.AuditRecord(
            request_id=request_id,
            risk_score=risk_score,
            risk_band=risk_band,
            detected_language=detected_language,
            provider_used=provider_used,
            latency_ms=latency_ms,
            source=source,
            was_overridden=was_overridden,
            fraud_type=fraud_type,
            api_key_id=api_key_id,
            org_id=org_id,
        )
        db.add(record)
        db.commit()
    except Exception as e:
        logger.error("Audit DB write failed: %s", str(e))
    finally:
        db.close()


def _read_records(days: int = 30, org_id: Optional[str] = None) -> list:
    """Read audit records from the database, filtered by time and optionally by org."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    db = SessionLocal()
    try:
        query = db.query(db_models.AuditRecord).filter(db_models.AuditRecord.timestamp >= cutoff)
        if org_id:
            query = query.filter(db_models.AuditRecord.org_id == org_id)
        records = query.all()
        return [
            {
                "request_id": r.request_id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "risk_score": r.risk_score,
                "risk_band": r.risk_band,
                "detected_language": r.detected_language,
                "provider_used": r.provider_used,
                "latency_ms": r.latency_ms,
                "source": r.source,
                "was_overridden": r.was_overridden,
                "fraud_type": r.fraud_type,
                "api_key_id": r.api_key_id,
                "org_id": r.org_id,
            }
            for r in records
        ]
    except Exception as e:
        logger.error("Audit DB read failed: %s", str(e))
        return []
    finally:
        db.close()


def get_user_history(
    api_key_id: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    days: int = 30
) -> dict:
    """Get scan history filtered by API key (for partner access)."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    db = SessionLocal()
    try:
        query = db.query(db_models.AuditRecord).filter(db_models.AuditRecord.timestamp >= cutoff)
        if api_key_id:
            query = query.filter(db_models.AuditRecord.api_key_id == api_key_id)

        total = query.count()
        records = query.order_by(db_models.AuditRecord.timestamp.desc()).offset(offset).limit(limit).all()

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "records": [
                {
                    "request_id": r.request_id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "risk_score": r.risk_score,
                    "risk_band": r.risk_band,
                    "detected_language": r.detected_language,
                    "provider_used": r.provider_used,
                    "latency_ms": r.latency_ms,
                    "source": r.source,
                    "was_overridden": r.was_overridden,
                    "fraud_type": r.fraud_type,
                    "api_key_id": r.api_key_id,
                    "org_id": r.org_id,
                }
                for r in records
            ]
        }
    except Exception as e:
        logger.error("get_user_history failed: %s", str(e))
        return {"total": 0, "limit": limit, "offset": offset, "records": []}
    finally:
        db.close()


def get_admin_summary(days: int = 30, org_id: Optional[str] = None) -> dict:
    """
    Returns aggregate dashboard metrics. Admin only.
    """
    records = _read_records(days=days, org_id=org_id)

    if not records:
        return {
            "total_scans": 0,
            "by_band": {"SAFE": 0, "CAUTION": 0, "HIGH_RISK": 0},
            "by_source": {},
            "by_language": {},
            "avg_latency_ms": 0,
            "confirmed_fraud_reports": 0,
        }

    by_band = {"SAFE": 0, "CAUTION": 0, "HIGH_RISK": 0}
    by_source = {}
    by_language = {}
    total_latency = 0
    overrides = 0

    for r in records:
        band = r.get("risk_band", "SAFE")
        by_band[band] = by_band.get(band, 0) + 1

        source = r.get("source", "unknown")
        by_source[source] = by_source.get(source, 0) + 1

        lang = r.get("detected_language", "en")
        by_language[lang] = by_language.get(lang, 0) + 1

        total_latency += r.get("latency_ms", 0)
        if r.get("was_overridden"):
            overrides += 1

    return {
        "total_scans": len(records),
        "by_band": by_band,
        "by_source": by_source,
        "by_language": by_language,
        "avg_latency_ms": total_latency // max(len(records), 1),
        "confirmed_fraud_reports": overrides,
        "override_rate_pct": round(overrides / max(len(records), 1) * 100, 1),
    }


def write_user_activity(
    user_id: Optional[int],
    email: str,
    action: str,
    details: Optional[dict] = None
) -> None:
    """Record user activity (login, signup, logout, upgrade, etc.)."""
    db = SessionLocal()
    try:
        record = db_models.UserActivity(
            user_id=user_id,
            email=email,
            action=action,
            details=details or {},
        )
        db.add(record)
        db.commit()
    except Exception as e:
        logger.error("User activity DB write failed: %s", str(e))
    finally:
        db.close()


def write_platform_metric(
    endpoint: str,
    method: str,
    status_code: int,
    latency_ms: int,
    client_ip: str
) -> None:
    """Record platform usage metrics (latency, status codes, endpoint hit)."""
    db = SessionLocal()
    try:
        record = db_models.PlatformMetric(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            latency_ms=latency_ms,
            client_ip=client_ip,
        )
        db.add(record)
        db.commit()
    except Exception as e:
        logger.error("Platform metric DB write failed: %s", str(e))
    finally:
        db.close()


def get_user_activities(limit: int = 50) -> list:
    """Retrieve recent user activities."""
    db = SessionLocal()
    try:
        records = db.query(db_models.UserActivity).order_by(db_models.UserActivity.timestamp.desc()).limit(limit).all()
        return [
            {
                "user_id": r.user_id,
                "email": r.email,
                "action": r.action,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "details": r.details,
            }
            for r in records
        ]
    except Exception as e:
        logger.error("Failed to read user activities: %s", str(e))
        return []
    finally:
        db.close()


def get_platform_metrics(limit: int = 50) -> list:
    """Retrieve recent platform metrics."""
    db = SessionLocal()
    try:
        records = db.query(db_models.PlatformMetric).order_by(db_models.PlatformMetric.timestamp.desc()).limit(limit).all()
        return [
            {
                "endpoint": r.endpoint,
                "method": r.method,
                "status_code": r.status_code,
                "latency_ms": r.latency_ms,
                "client_ip": r.client_ip,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            }
            for r in records
        ]
    except Exception as e:
        logger.error("Failed to read platform metrics: %s", str(e))
        return []
    finally:
        db.close()


import httpx

def resolve_and_write_user_activity(
    user_id: Optional[int],
    email: str,
    action: str,
    client_ip: str,
    details: Optional[dict] = None
) -> None:
    """Resolve IP location and write user activity log in the background."""
    details = details or {}
    details["ip"] = client_ip

    if client_ip not in ("127.0.0.1", "localhost", "unknown", ""):
        try:
            res = httpx.get(f"http://ip-api.com/json/{client_ip}", timeout=2.0)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    city = data.get("city", "")
                    country = data.get("country", "")
                    country_code = data.get("countryCode", "")
                    parts = [p for p in [city, country or country_code] if p]
                    if parts:
                        details["location"] = ", ".join(parts)
        except Exception as e:
            logger.error("Failed to geolocate IP %s: %s", client_ip, str(e))

    if "location" not in details:
        details["location"] = "Localhost (Dev)" if client_ip in ("127.0.0.1", "localhost") else "Unknown Location"

    write_user_activity(user_id, email, action, details)

