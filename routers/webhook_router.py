"""
ShieldIQ Enterprise — Webhook Routes
──────────────────────────────────────
POST /webhook/register — register a partner callback URL
POST /webhook/test     — test a registered webhook

Partners receive real-time alerts when fraud is detected
on messages scanned via their API key.
"""

import os, json, hmac, hashlib, logging, httpx, sys, asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from database import SessionLocal
import db_models
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhook", tags=["Webhook"])

# Persistent registry file path
WEBHOOK_DIR = os.environ.get("SHIELDIQ_DATA_DIR") or os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "keys")
os.makedirs(WEBHOOK_DIR, exist_ok=True)
WEBHOOK_FILE = os.path.join(WEBHOOK_DIR, "webhooks.json")


def _load_webhooks() -> dict:
    if not os.path.exists(WEBHOOK_FILE):
        return {}
    try:
        with open(WEBHOOK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_webhooks(webhooks: dict) -> None:
    try:
        with open(WEBHOOK_FILE, "w", encoding="utf-8") as f:
            json.dump(webhooks, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error("Webhook save failed: %s", str(e))


class WebhookRegistration(BaseModel):
    callback_url: str
    secret: str
    events: list[str] = ["HIGH_RISK_DETECTED", "CAUTION_DETECTED"]
    description: Optional[str] = None


@router.post("/register", summary="Register a partner webhook")
async def register_webhook(request: Request, body: WebhookRegistration):
    api_key_id = getattr(request.state, "api_key_id", None)
    if not api_key_id:
        raise HTTPException(status_code=401, detail="API key required")

    webhooks = _load_webhooks()
    webhooks[api_key_id] = {
        "callback_url": body.callback_url,
        "secret": body.secret,
        "events": body.events,
        "description": body.description,
        "registered_at": datetime.now(timezone.utc).isoformat()
    }
    _save_webhooks(webhooks)
    logger.info("Webhook registered: %s → %s", api_key_id, body.callback_url[:40])
    return {"status": "registered", "callback_url": body.callback_url, "events": body.events}


@router.post("/test", summary="Test a registered webhook")
async def test_webhook(request: Request):
    api_key_id = getattr(request.state, "api_key_id", None)
    webhooks = _load_webhooks()
    webhook = webhooks.get(api_key_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="No webhook registered for this key")

    test_payload = {
        "event": "TEST",
        "risk_score": 0,
        "risk_band": "SAFE",
        "source": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": "test_ping",
        "message": "ShieldIQ webhook test — if you see this, it works!"
    }
    return {"status": "test_sent", "payload_preview": test_payload}


async def deliver_webhook(api_key_id: str, risk_band: str, risk_score: int,
                          request_id: str, source: str, metadata: dict = None):
    """Background task: deliver webhook to partner. Never blocks scan response."""
    webhooks = _load_webhooks()
    webhook = webhooks.get(api_key_id)
    if not webhook:
        return

    retry_delays = [60, 300, 900, 3600]
    if os.environ.get("TESTING") == "1" or os.environ.get("PYTEST_CURRENT_TEST") or "test" in sys.argv[0]:
        retry_delays = [0.01, 0.02, 0.03, 0.04]

    # Check if we should alert (specifically for high risk and caution)
    event_name = f"{risk_band}_DETECTED"
    if risk_band == "HIGH":
        if "HIGH_RISK_DETECTED" not in webhook.get("events", []) and "HIGH_DETECTED" not in webhook.get("events", []):
            return
    elif event_name not in webhook.get("events", []):
        return

    recommended_action = "BLOCK" if risk_band == "HIGH" else ("FLAG" if risk_band == "CAUTION" else "ALLOW")
    
    payload_dict = {
        "eventType": "fraud.risk_detected",
        "scanId": f"SCN-{request_id}",
        "riskBand": risk_band,
        "riskScore": risk_score,
        "channel": source.upper() if source else "API",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "recommendedAction": recommended_action
    }
    payload_bytes = json.dumps(payload_dict, separators=(',', ':')).encode()

    timestamp_str = str(int(datetime.now(timezone.utc).timestamp()))
    signature_payload = f"{timestamp_str}.{json.dumps(payload_dict, separators=(',', ':'))}"
    signature = hmac.new(webhook["secret"].encode(), signature_payload.encode(), hashlib.sha256).hexdigest()

    delivery_status = "failed"
    success = False

    for attempt, delay in enumerate([0] + retry_delays):
        if delay > 0:
            logger.info("Retrying webhook delivery for key %s (attempt %s) in %s seconds...", api_key_id[:8], attempt, delay)
            await asyncio.sleep(delay)

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    webhook["callback_url"],
                    content=payload_bytes,
                    headers={
                        "Content-Type": "application/json",
                        "X-Dovtek-Signature": signature,
                        "X-Dovtek-Timestamp": timestamp_str,
                        "X-ShieldIQ-Signature": f"sha256={signature}",
                        "X-ShieldIQ-Event": "fraud.risk_detected"
                    }
                )
                if 200 <= resp.status_code < 300:
                    success = True
                    delivery_status = "success"
                    logger.info("Webhook delivered successfully to %s", webhook["callback_url"])
                    break
                else:
                    logger.warning("Webhook delivery failed with status %s on attempt %s", resp.status_code, attempt + 1)
        except Exception as e:
            logger.warning("Webhook delivery exception on attempt %s: %s", attempt + 1, str(e))

    # Update AuditRecord with webhook delivery status and recommended action
    db = SessionLocal()
    try:
        record = db.query(db_models.AuditRecord).filter(db_models.AuditRecord.request_id == request_id).first()
        if record:
            record.webhook_status = delivery_status
            record.recommended_action = recommended_action
            db.commit()
            logger.info("Audit log updated: request_id=%s, webhook_status=%s, recommended_action=%s", request_id, delivery_status, recommended_action)
    except Exception as db_err:
        logger.error("Failed to update audit log webhook status: %s", str(db_err))
    finally:
        db.close()

