"""
ShieldIQ Enterprise — Audit Trail API Routes
──────────────────────────────────────────────
GET /audit/history  — user/partner scan history
GET /audit/summary  — admin aggregate summary
GET /audit/patterns — pattern intelligence (admin)
GET /audit/report   — generate intelligence report (admin)

No message content in any response.
"""
import os
import logging
from fastapi import APIRouter, Request, HTTPException, Query, Depends
from sqlalchemy.orm import Session
from database import get_db
import db_models
from pydantic import BaseModel

from enterprise.audit_store import get_user_history, get_admin_summary, get_user_activities, get_platform_metrics
from enterprise.pattern_store import get_pattern_stats
from enterprise.report_generator import generate_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["Audit Trail"])

ADMIN_KEY = os.environ.get("ADMIN_SECRET_KEY", "shieldiq_admin_2026")


class ContactRequest(BaseModel):
    name: str
    email: str
    subject: str
    message: str


class ChangePlanRequest(BaseModel):
    user_id: int
    plan: str


class ResolveTicketRequest(BaseModel):
    ticket_id: int


@router.get("/history", summary="Scan history (metadata only)")
async def get_history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    days: int = Query(default=30, ge=1, le=365)
):
    """Returns scan history — timestamps and verdicts only. No message content."""
    api_key_id = getattr(request.state, "api_key_id", None)
    result = get_user_history(api_key_id=api_key_id, limit=limit, offset=offset, days=days)
    return result


@router.get("/summary", summary="Admin — aggregate summary")
async def get_summary(
    days: int = Query(default=30, ge=1, le=365),
    admin_key: str = Query(default="")
):
    """Admin only. Returns aggregate statistics across all scans."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_admin_summary(days=days)


@router.get("/patterns", summary="Admin — pattern intelligence")
async def get_patterns(
    days: int = Query(default=30, ge=1, le=365),
    admin_key: str = Query(default="")
):
    """Admin only. Returns aggregate pattern statistics — the data moat view."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_pattern_stats(days=days)


@router.get("/report", summary="Admin — intelligence report")
async def get_report(
    days: int = Query(default=30, ge=1, le=365),
    admin_key: str = Query(default="")
):
    """Admin only. Generates an executive intelligence report for download."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return generate_report(days=days)


@router.get("/activities", summary="Admin — recent user activities")
async def get_activities(
    limit: int = Query(default=50, ge=1, le=500),
    admin_key: str = Query(default="")
):
    """Admin only. Returns recent user activities (signup, login, logout, etc.)."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_user_activities(limit=limit)


@router.get("/metrics", summary="Admin — recent platform usage metrics")
async def get_metrics(
    limit: int = Query(default=50, ge=1, le=500),
    admin_key: str = Query(default="")
):
    """Admin only. Returns recent platform usage metrics (requests, latency, client ip)."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_platform_metrics(limit=limit)


# ── Super Admin Suite Endpoints ──────────────────────────────────────────────

@router.post("/contact", summary="Submit a customer support ticket")
def submit_contact(body: ContactRequest, db: Session = Depends(get_db)):
    ticket = db_models.SupportTicket(
        name=body.name,
        email=body.email,
        subject=body.subject,
        message=body.message
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return {"status": "success", "message": "Ticket submitted successfully", "ticket_id": ticket.id}


@router.get("/users", summary="Admin — get all registered users")
def get_users(admin_key: str = Query(default=""), db: Session = Depends(get_db)):
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    users = db.query(db_models.User).order_by(db_models.User.created_at.desc()).all()
    return [
        {
            "id": u.id,
            "full_name": u.full_name,
            "email": u.email,
            "plan": u.plan,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "subscription_status": u.subscription_status
        }
        for u in users
    ]


@router.post("/users/change-plan", summary="Admin — manually change user plan")
def change_user_plan(body: ChangePlanRequest, admin_key: str = Query(default=""), db: Session = Depends(get_db)):
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    user = db.query(db_models.User).filter(db_models.User.id == body.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    old_plan = user.plan
    user.plan = body.plan
    # Reset pending plan if set manually
    user.pending_plan = None
    
    db.commit()
    
    # Record user activity
    from enterprise.audit_store import write_user_activity
    write_user_activity(
        user_id=user.id,
        email=user.email,
        action="admin_plan_change",
        details={"old_plan": old_plan, "new_plan": body.plan}
    )
    return {"status": "success", "message": f"Plan updated from {old_plan} to {body.plan}"}


@router.get("/tickets", summary="Admin — get support tickets")
def get_tickets(admin_key: str = Query(default=""), db: Session = Depends(get_db)):
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    tickets = db.query(db_models.SupportTicket).order_by(db_models.SupportTicket.created_at.desc()).all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "email": t.email,
            "subject": t.subject,
            "message": t.message,
            "status": t.status,
            "created_at": t.created_at.isoformat() if t.created_at else None
        }
        for t in tickets
    ]


@router.post("/tickets/resolve", summary="Admin — mark support ticket as resolved")
def resolve_ticket(body: ResolveTicketRequest, admin_key: str = Query(default=""), db: Session = Depends(get_db)):
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    ticket = db.query(db_models.SupportTicket).filter(db_models.SupportTicket.id == body.ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    ticket.status = "Resolved"
    db.commit()
    return {"status": "success", "message": "Ticket marked as resolved"}

