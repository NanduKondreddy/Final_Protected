# backend/routers/scan_router.py
import uuid
import logging
from enterprise.audit_store import write_audit
from enterprise.pattern_store import write_pattern
from enterprise.validation import scan_patterns

logger = logging.getLogger(__name__)
from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File, Form, Request, BackgroundTasks
from sqlalchemy.orm import Session
from database import get_db
from auth import get_optional_user, get_current_user
import db_models
from models import ScanRequest, ScanResult, ScanHistoryItem, ScanHistoryResponse
from analyzer import analyze_message
from typing import Optional
from routers.webhook_router import deliver_webhook

router = APIRouter(tags=["Scans"])

MESSAGE_NOT_STORED = "[Message content not stored]"


@router.post("/scan", response_model=ScanResult)
async def scan(
    request: Request,
    background_tasks: BackgroundTasks,
    message: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: Optional[db_models.User] = Depends(get_optional_user),
):
    """Analyze a message or uploaded file for fraud signals."""

    image_bytes = None
    image_media_type = None
    request_id = uuid.uuid4().hex[:16]
    api_key_id = getattr(request.state, "api_key_id", None)
    partner_name = getattr(request.state, "partner_name", None)
    tier = getattr(request.state, "tier", None)
    org_id = getattr(request.state, "org_id", None)

    if file:
        image_bytes = await file.read()
        image_media_type = file.content_type

    if not message and not image_bytes:
        raise HTTPException(status_code=400, detail="Please provide a message or upload a file")

    if not current_user and not api_key_id:
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        guest_count = db.query(db_models.Scan).filter(
            db_models.Scan.user_id.is_(None),
            db_models.Scan.scanned_at >= today_start,
        ).count()
        if guest_count >= 1:
            raise HTTPException(
                status_code=402,
                detail={
                    "error": "quota_exceeded",
                    "tier": "guest",
                    "message": "Guest limit reached. Create a free account for 3 scans/day.",
                    "upgrade_url": "/?signup=1",
                }
            )

    if current_user and current_user.plan == "free" and not api_key_id:
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        scan_count = db.query(db_models.Scan).filter(
            db_models.Scan.user_id == current_user.id,
            db_models.Scan.scanned_at >= today_start
        ).count()
        if scan_count >= 3:
            raise HTTPException(
                status_code=402,
                detail={
                    "error": "quota_exceeded",
                    "tier": "free",
                    "message": "Daily limit reached. Upgrade to Pro for unlimited scans.",
                    "upgrade_url": "/checkout?plan=pro",
                }
            )
        
    # PDF/image gate — add after quota check in /scan endpoint
    if image_media_type and current_user and current_user.plan == "free":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "feature_locked",
                "feature": "pdf_image_scanning",
                "message": "PDF and image scanning requires Pro.",
                "upgrade_url": "/checkout?plan=pro",
            }
        )

    try:
        if api_key_id:
            user_plan = tier or "enterprise"
        else:
            user_plan = current_user.plan if current_user else "free"

        result = await analyze_message(
            message=message,
            image_bytes=image_bytes,
            image_media_type=image_media_type,
            user_plan=user_plan,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    # Save scan to DB — user_id is None for anonymous scans
    if current_user:
        scan_record = db_models.Scan(
            user_id=current_user.id,
            message=MESSAGE_NOT_STORED,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            summary=result.summary,
            reasons=result.reasons,
            action=result.action,
            what_to_do=result.what_to_do,
            pass1_blocked=result.pass1_blocked,
        )
        db.add(scan_record)
        db.commit()

    # ── Enterprise: Write audit + pattern data (metadata only, non-blocking) ──
    try:
        _pattern_count, _fired = scan_patterns(message or "") if message else (0, [])
        source_name = "api" if api_key_id else "web_app"

        write_audit(
            request_id=request_id,
            risk_score=result.risk_score,
            risk_band=_score_to_band(result.risk_score),
            detected_language="en",
            provider_used="gemini",
            source=source_name,
            api_key_id=api_key_id,
            org_id=org_id,
        )
        write_pattern(
            request_id=request_id,
            risk_band=_score_to_band(result.risk_score),
            fired_patterns=_fired,
            detected_language="en",
            source=source_name,
            api_key_id=api_key_id,
        )

        # Trigger webhook in background if B2B API Key is used
        if api_key_id:
            background_tasks.add_task(
                deliver_webhook,
                api_key_id=api_key_id,
                risk_band=_score_to_band(result.risk_score),
                risk_score=result.risk_score,
                request_id=request_id,
                source=source_name,
                metadata={"partner_name": partner_name}
            )
    except Exception as e:
        logger.warning("Enterprise audit write failed (non-fatal): %s", str(e))

    return result


@router.post("/scan/json", response_model=ScanResult)
async def scan_json(
    request: Request,
    background_tasks: BackgroundTasks,
    body: ScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[db_models.User] = Depends(get_optional_user),
):
    """Analyze a text message (JSON body) for fraud signals. Restrict usage to paid subscribers and B2B keys."""
    request_id = uuid.uuid4().hex[:16]
    api_key_id = getattr(request.state, "api_key_id", None)
    partner_name = getattr(request.state, "partner_name", None)
    tier = getattr(request.state, "tier", None)
    org_id = getattr(request.state, "org_id", None)

    # ── Web app quota (non-extension requests) ───────────────────────────────
    if not api_key_id:
        if not current_user:
            # Guest quota
            from datetime import datetime, timezone
            today_start = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0)
            guest_count = db.query(db_models.Scan).filter(
                db_models.Scan.user_id.is_(None),
                db_models.Scan.scanned_at >= today_start,
            ).count()
            if guest_count >= 1:
                raise HTTPException(
                    status_code=402,
                    detail={
                        "error": "quota_exceeded",
                        "tier": "guest",
                        "message": "Guest limit reached. Create a free account for 3 scans/day.",
                        "upgrade_url": "/?signup=1",
                    }
                )
        elif current_user.plan == "free":
            # Free user quota
            from datetime import datetime, timezone
            today_start = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0)
            scan_count = db.query(db_models.Scan).filter(
                db_models.Scan.user_id == current_user.id,
                db_models.Scan.scanned_at >= today_start
            ).count()
            if scan_count >= 3:
                raise HTTPException(
                    status_code=402,
                    detail={
                        "error": "quota_exceeded",
                        "tier": "free",
                        "message": "Daily limit reached. Upgrade to Pro for unlimited scans.",
                        "upgrade_url": "/checkout?plan=pro",
                    }
                )

    # ── Extension / JSON endpoint plan check ─────────────────────────────────
    # /scan/json is called by the Chrome extension — requires Plus or Enterprise
    if not api_key_id and current_user:
        if current_user.plan not in ("pro", "plus", "enterprise"):
            raise HTTPException(
                status_code=403,
                detail="Shield Plus or Enterprise subscription is required to use the Chrome Extension."
            )

    # ── Set user_plan for analyzer ───────────────────────────────────────────
    if api_key_id:
        user_plan = tier or "enterprise"
    else:
        user_plan = current_user.plan if current_user else "free"

    try:
        result = await analyze_message(body.message, user_plan=user_plan)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    if current_user:
        scan_record = db_models.Scan(
            user_id=current_user.id,
            message=MESSAGE_NOT_STORED,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            summary=result.summary,
            reasons=result.reasons,
            action=result.action,
            what_to_do=result.what_to_do,
            pass1_blocked=result.pass1_blocked,
        )
        db.add(scan_record)
        db.commit()

    # ── Enterprise audit ──
    try:
        _count, _fired = scan_patterns(body.message)
        source_name = "api" if api_key_id else "web_app"

        write_audit(
            request_id=request_id,
            risk_score=result.risk_score,
            risk_band=_score_to_band(result.risk_score),
            detected_language="en",
            provider_used="gemini",
            source=source_name,
            api_key_id=api_key_id,
            org_id=org_id,
        )
        write_pattern(
            request_id=request_id,
            risk_band=_score_to_band(result.risk_score),
            fired_patterns=_fired,
            detected_language="en",
            source=source_name,
            api_key_id=api_key_id,
        )

        # Trigger webhook in background if B2B API Key is used
        if api_key_id:
            background_tasks.add_task(
                deliver_webhook,
                api_key_id=api_key_id,
                risk_band=_score_to_band(result.risk_score),
                risk_score=result.risk_score,
                request_id=request_id,
                source=source_name,
                metadata={"partner_name": partner_name}
            )
    except Exception:
        pass

    return result


@router.get("/scans/history", response_model=ScanHistoryResponse)
def get_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),  # must be logged in
):
    """Get scan history for the current authenticated user."""
    query = db.query(db_models.Scan).filter(db_models.Scan.user_id == current_user.id)

    total = query.count()
    scans = (
        query.order_by(db_models.Scan.scanned_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return ScanHistoryResponse(
        total=total,
        page=page,
        page_size=page_size,
        scans=[
            ScanHistoryItem(
                id=s.id,
                user_id=s.user_id,
                message=s.message,
                risk_score=s.risk_score,
                risk_level=s.risk_level,
                summary=s.summary,
                reasons=s.reasons,
                action=s.action,
                what_to_do=s.what_to_do,
                pass1_blocked=s.pass1_blocked,
                scanned_at=s.scanned_at,
            )
            for s in scans
        ],
    )


def _score_to_band(score: int) -> str:
    """Map ShieldIQ's existing score to enterprise risk bands."""
    if score <= 30:
        return "SAFE"
    elif score <= 69:
        return "CAUTION"
    else:
        return "HIGH_RISK"


from fastapi.responses import StreamingResponse
import io
import csv
from auth import decode_token

@router.get("/scans/export")
def export_history(
    format: str = Query("csv", pattern="^(csv|json)$"),
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Optional[db_models.User] = Depends(get_optional_user),
):
    """Export scan history as CSV or JSON."""
    user = current_user
    if not user and token:
        try:
            payload = decode_token(token)
            user = db.query(db_models.User).filter(db_models.User.id == int(payload["sub"])).first()
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if user.plan == "free":
        raise HTTPException(status_code=403, detail="Exporting scan history is a Pro, Plus, and Enterprise plan feature.")

    scans = db.query(db_models.Scan).filter(db_models.Scan.user_id == user.id).order_by(db_models.Scan.scanned_at.desc()).all()

    if format == "json":
        import json
        data = [
            {
                "id": s.id,
                "risk_score": s.risk_score,
                "risk_level": s.risk_level,
                "summary": s.summary,
                "reasons": s.reasons,
                "action": s.action,
                "what_to_do": s.what_to_do,
                "pass1_blocked": s.pass1_blocked,
                "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
            }
            for s in scans
        ]
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=2).encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=shieldiq_history_{user.id}.json"}
        )

    # Export as CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Risk Score", "Risk Level", "Summary", "Reasons", "Action", "What To Do", "Pass 1 Blocked", "Scanned At"])
    for s in scans:
        writer.writerow([
            s.id,
            s.risk_score,
            s.risk_level,
            s.summary,
            "; ".join(s.reasons) if isinstance(s.reasons, list) else str(s.reasons),
            s.action,
            s.what_to_do,
            s.pass1_blocked,
            s.scanned_at.isoformat() if s.scanned_at else ""
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=shieldiq_history_{user.id}.csv"}
    )
