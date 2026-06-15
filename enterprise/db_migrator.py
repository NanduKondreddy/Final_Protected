import os
import json
import logging
from datetime import datetime, timezone
from database import SessionLocal
import db_models

logger = logging.getLogger(__name__)

def migrate_all():
    logger.info("Checking for flat-file log migrations...")
    migrate_audit_records()
    migrate_pattern_records()
    migrate_user_activities()
    migrate_platform_metrics()

def migrate_audit_records():
    db = SessionLocal()
    try:
        if db.query(db_models.AuditRecord).first() is not None:
            return
        
        audit_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "audit", "audit_log.jsonl")
        if not os.path.exists(audit_file):
            return
        
        records = []
        with open(audit_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    # Support parsing timestamp
                    ts_str = data.get("timestamp")
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    else:
                        ts = datetime.now(timezone.utc)
                    
                    record = db_models.AuditRecord(
                        request_id=data.get("request_id"),
                        timestamp=ts,
                        risk_score=data.get("risk_score"),
                        risk_band=data.get("risk_band"),
                        detected_language=data.get("detected_language", "en"),
                        provider_used=data.get("provider_used", "gemini"),
                        latency_ms=data.get("latency_ms", 0),
                        source=data.get("source", "web_app"),
                        was_overridden=data.get("was_overridden", False),
                        fraud_type=data.get("fraud_type"),
                        api_key_id=data.get("api_key_id"),
                        org_id=data.get("org_id")
                    )
                    records.append(record)
                except Exception as e:
                    logger.error("Error parsing audit log line: %s", str(e))
        
        if records:
            db.bulk_save_objects(records)
            db.commit()
            logger.info("Migrated %d AuditRecord objects from JSONL to DB.", len(records))
    except Exception as e:
        logger.error("Audit log migration failed: %s", str(e))
    finally:
        db.close()

def migrate_pattern_records():
    db = SessionLocal()
    try:
        if db.query(db_models.PatternRecord).first() is not None:
            return
        
        pattern_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "patterns", "pattern_log.jsonl")
        if not os.path.exists(pattern_file):
            return
        
        records = []
        with open(pattern_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    ts_str = data.get("timestamp")
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    else:
                        ts = datetime.now(timezone.utc)

                    record = db_models.PatternRecord(
                        request_id=data.get("request_id"),
                        timestamp=ts,
                        risk_band=data.get("risk_band"),
                        patterns=data.get("patterns", []),
                        fraud_type=data.get("fraud_type"),
                        detected_language=data.get("detected_language", "en"),
                        source=data.get("source", "web_app"),
                        api_key_id=data.get("api_key_id")
                    )
                    records.append(record)
                except Exception as e:
                    logger.error("Error parsing pattern log line: %s", str(e))
        
        if records:
            db.bulk_save_objects(records)
            db.commit()
            logger.info("Migrated %d PatternRecord objects from JSONL to DB.", len(records))
    except Exception as e:
        logger.error("Pattern log migration failed: %s", str(e))
    finally:
        db.close()

def migrate_user_activities():
    db = SessionLocal()
    try:
        if db.query(db_models.UserActivity).first() is not None:
            return
        
        activity_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "audit", "user_activity.jsonl")
        if not os.path.exists(activity_file):
            return
        
        records = []
        with open(activity_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    ts_str = data.get("timestamp")
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    else:
                        ts = datetime.now(timezone.utc)

                    record = db_models.UserActivity(
                        user_id=data.get("user_id"),
                        email=data.get("email"),
                        action=data.get("action"),
                        timestamp=ts,
                        details=data.get("details", {})
                    )
                    records.append(record)
                except Exception as e:
                    logger.error("Error parsing user activity line: %s", str(e))
        
        if records:
            db.bulk_save_objects(records)
            db.commit()
            logger.info("Migrated %d UserActivity objects from JSONL to DB.", len(records))
    except Exception as e:
        logger.error("User activity migration failed: %s", str(e))
    finally:
        db.close()

def migrate_platform_metrics():
    db = SessionLocal()
    try:
        if db.query(db_models.PlatformMetric).first() is not None:
            return
        
        metrics_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "audit", "platform_metrics.jsonl")
        if not os.path.exists(metrics_file):
            return
        
        records = []
        with open(metrics_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    ts_str = data.get("timestamp")
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    else:
                        ts = datetime.now(timezone.utc)

                    record = db_models.PlatformMetric(
                        endpoint=data.get("endpoint"),
                        method=data.get("method"),
                        status_code=data.get("status_code"),
                        latency_ms=data.get("latency_ms"),
                        client_ip=data.get("client_ip"),
                        timestamp=ts
                    )
                    records.append(record)
                except Exception as e:
                    logger.error("Error parsing platform metrics line: %s", str(e))
        
        if records:
            db.bulk_save_objects(records)
            db.commit()
            logger.info("Migrated %d PlatformMetric objects from JSONL to DB.", len(records))
    except Exception as e:
        logger.error("Platform metrics migration failed: %s", str(e))
    finally:
        db.close()
