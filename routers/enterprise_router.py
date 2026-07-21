"""
ShieldIQ Enterprise — Client Self-Service API Key Management
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from auth import get_current_user
import db_models
from enterprise.api_key_manager import generate_key, list_keys, revoke_key, _load_keys

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/enterprise", tags=["Enterprise API Management"])


class KeyGenerateRequest(BaseModel):
    partner_name: Optional[str] = None
    daily_limit: Optional[int] = 10000


class KeyRevokeRequest(BaseModel):
    key_id: str


@router.get("/keys", summary="List enterprise client's API keys")
def get_client_keys(
    current_user: db_models.User = Depends(get_current_user)
):
    """List all API keys belonging to the logged-in enterprise user."""
    if current_user.plan != "enterprise":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to Enterprise subscription plan."
        )
    return list_keys(org_id=str(current_user.id))


@router.post("/keys/generate", summary="Generate a new API key")
def generate_client_key(
    body: KeyGenerateRequest,
    current_user: db_models.User = Depends(get_current_user)
):
    """Generate a new API key for the logged-in enterprise user."""
    if current_user.plan != "enterprise":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to Enterprise subscription plan."
        )
    
    partner_name = body.partner_name or current_user.full_name or "Enterprise Partner"
    daily_limit = body.daily_limit or 10000

    result = generate_key(
        partner_name=partner_name,
        tier="enterprise",
        daily_limit=daily_limit,
        org_id=str(current_user.id),
        retention_days=current_user.retention_days or 0
    )
    return result


@router.post("/keys/revoke", summary="Revoke/Deactivate an API key")
def revoke_client_key(
    body: KeyRevokeRequest,
    current_user: db_models.User = Depends(get_current_user)
):
    """Revoke an API key belonging to the logged-in enterprise user."""
    if current_user.plan != "enterprise":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to Enterprise subscription plan."
        )

    # Validate that this key actually belongs to the current user
    keys = _load_keys()
    key_meta = keys.get(body.key_id)
    if not key_meta or key_meta.get("org_id") != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API Key not found or does not belong to your organization."
        )

    success = revoke_key(body.key_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key."
        )
    return {"status": "success", "message": f"API Key {body.key_id} has been revoked."}


@router.get("/metrics", summary="Get usage metrics for enterprise keys")
def get_client_metrics(
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """Retrieve API usage metrics, request counts, and status logs."""
    if current_user.plan != "enterprise":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to Enterprise subscription plan."
        )

    # 1. Get all keys belonging to this user
    user_keys = list_keys(org_id=str(current_user.id))
    key_ids = [k["key_id"] for k in user_keys]

    if not key_ids:
        return {
            "total_requests": 0,
            "requests_today": 0,
            "keys_count": 0,
            "logs": []
        }

    # 2. Get history of scans for these keys
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Query total scans
    total_requests = db.query(db_models.AuditRecord).filter(
        db_models.AuditRecord.api_key_id.in_(key_ids)
    ).count()

    # Query scans today
    requests_today = db.query(db_models.AuditRecord).filter(
        db_models.AuditRecord.api_key_id.in_(key_ids),
        db_models.AuditRecord.timestamp >= today_start
    ).count()

    # Query recent 50 logs
    recent_records = db.query(db_models.AuditRecord).filter(
        db_models.AuditRecord.api_key_id.in_(key_ids)
    ).order_by(db_models.AuditRecord.timestamp.desc()).limit(50).all()

    logs = [
        {
            "request_id": r.request_id,
            "api_key_id": r.api_key_id,
            "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat() if r.timestamp else None,
            "status_code": 200,  # All successful audits are status 200
            "risk_band": r.risk_band,
            "risk_score": r.risk_score,
            "latency_ms": r.latency_ms,
            "fraud_type": r.fraud_type,
            "webhook_status": getattr(r, 'webhook_status', None),
            "recommended_action": getattr(r, 'recommended_action', None),
        }
        for r in recent_records
    ]

    return {
        "total_requests": total_requests,
        "requests_today": requests_today,
        "keys_count": len(user_keys),
        "logs": logs
    }


# B2B Scan request/response models
class EnterpriseScanRequest(BaseModel):
    message: str


class EnterpriseScanResponse(BaseModel):
    verdict: str
    score: int
    action: str
    threatType: Optional[str] = "None"
    timestamp: str


@router.post("/scan", response_model=EnterpriseScanResponse, summary="Enterprise B2B Scan Endpoint")
async def enterprise_scan(
    request: Request,
    body: EnterpriseScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Analyze a message for fraud risk. Only accessible via active B2B API Key (AC2).
    Never stores message body content (AC6).
    """
    api_key_id = getattr(request.state, "api_key_id", None)
    partner_name = getattr(request.state, "partner_name", None)
    tier = getattr(request.state, "tier", None)
    org_id = getattr(request.state, "org_id", None)

    if not api_key_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid API Key required in X-API-KEY or Authorization: Bearer header."
        )

    # 1. Perform message analysis
    try:
        from analyzer import analyze_message
        result = await analyze_message(body.message, user_plan=tier or "enterprise")
    except Exception as e:
        logger.error(f"Enterprise scan failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )

    # 2. Write metadata only (never message content - AC6)
    import uuid
    from datetime import datetime, timezone
    now_utc = datetime.now(timezone.utc)
    timestamp_str = now_utc.isoformat().replace("+00:00", "Z")

    try:
        scan_record = db_models.Scan(
            user_id=None,
            message="[Message content not stored]",
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            summary=result.summary,
            reasons=result.reasons,
            action=result.action,
            what_to_do=result.what_to_do,
            pass1_blocked=result.pass1_blocked,
            expires_at=None,
            api_key_id=api_key_id,
        )
        db.add(scan_record)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to save scan record: {str(e)}")

    # 3. Write audit trailing
    try:
        from enterprise.audit_store import write_audit, resolve_country_code
        from enterprise.pattern_store import write_pattern
        from enterprise.validation import scan_patterns

        _raw_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown").split(",")[0].strip()
        location = resolve_country_code(_raw_ip)
        _count, _fired = scan_patterns(body.message)
        request_id = uuid.uuid4().hex[:16]
        from routers.webhook_router import _load_webhooks
        webhooks = _load_webhooks()
        has_webhook = api_key_id in webhooks
        recommended_action = "BLOCK" if result.risk_level == "HIGH" else ("FLAG" if result.risk_level == "CAUTION" else "ALLOW")
        
        is_triggered = False
        if has_webhook:
            wh = webhooks[api_key_id]
            event_name = f"{result.risk_level}_DETECTED"
            if result.risk_level == "HIGH":
                is_triggered = "HIGH_RISK_DETECTED" in wh.get("events", []) or "HIGH_DETECTED" in wh.get("events", [])
            else:
                is_triggered = event_name in wh.get("events", [])
                
        webhook_status = "pending" if is_triggered else None

        write_audit(
            request_id=request_id,
            risk_score=result.risk_score,
            risk_band=result.risk_level,
            detected_language="en",
            provider_used="gemini",
            source="api",
            api_key_id=api_key_id,
            org_id=org_id,
            client_ip=location,
            fraud_type=result.fraud_type,
            webhook_status=webhook_status,
            recommended_action=recommended_action,
        )
        write_pattern(
            request_id=request_id,
            risk_band=result.risk_level,
            fired_patterns=_fired,
            fraud_type=result.fraud_type,
            detected_language="en",
            source="api",
            api_key_id=api_key_id,
        )

        # Trigger webhook in background if webhooks are registered
        from routers.webhook_router import deliver_webhook
        from fastapi import BackgroundTasks
        # Try to deliver webhook
        deliver_webhook_task = deliver_webhook
    except Exception as e:
        logger.warning(f"Failed to set up audit trailing tasks: {str(e)}")
        deliver_webhook_task = None
        request_id = None

    if deliver_webhook_task and request_id:
        try:
            background_tasks.add_task(
                deliver_webhook_task,
                api_key_id=api_key_id,
                risk_band=result.risk_level,
                risk_score=result.risk_score,
                request_id=request_id,
                source="api",
                metadata={"partner_name": partner_name}
            )
        except Exception:
            pass

    return EnterpriseScanResponse(
        verdict=result.risk_level,
        score=result.risk_score,
        action=result.action,
        threatType=result.fraud_type or "None",
        timestamp=timestamp_str
    )
