# backend/routers/security_router.py
"""
Vulnerability Disclosure / Security Reporting — backend routes.
 
AC1 — /security page exists (served as static HTML)
AC2 — auto-acknowledgment email sent on submission
AC3 — unique SEC-YYYY-NNN reference ID generated per report
AC4 — status update endpoint (team calls PATCH to notify researcher)
AC5 — reports only readable via admin-token-protected endpoints
AC6 — PATCH endpoint lets team mark report resolved
"""
 
import os
import logging
from datetime import datetime, timezone
from typing import Optional
 
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
 
from database import get_db
from db_models import SecurityReport
from email_service import send_security_acknowledgment, send_security_status_update
 
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/security", tags=["Security"])
 
# ── Admin auth — simple shared secret (store in .env as SECURITY_ADMIN_TOKEN)
SECURITY_ADMIN_TOKEN = os.environ.get("SECURITY_ADMIN_TOKEN", "")
 
 
def _require_admin(x_admin_token: str = Header(None)):
    if not SECURITY_ADMIN_TOKEN:
        raise HTTPException(503, detail="Security admin access not configured")
    if x_admin_token != SECURITY_ADMIN_TOKEN:
        raise HTTPException(403, detail="Invalid admin token")
 
 
# ── Schemas ───────────────────────────────────────────────────────────────
 
class ReportSubmission(BaseModel):
    researcher_name:    str
    researcher_email:   EmailStr
    vulnerability_type: str        # e.g. "Auth Flaw", "Data Exposure", "API"
    severity:           str        # "critical" | "high" | "medium" | "low"
    description:        str
    reproduction_steps: str
    impact_assessment:  str
    contact_preference: Optional[str] = "email"  # "email" | "none"
 
 
class StatusUpdate(BaseModel):
    status:  str         # "received" | "investigating" | "resolved" | "wont_fix"
    message: str         # message to send to the researcher
 
 
# ── Reference ID generator ────────────────────────────────────────────────
 
def _generate_ref_id(db: Session) -> str:
    """
    Generates a sequential SEC-YYYY-NNN ID (AC3).
    Thread-safe because SQLite serialises writes.
    """
    year  = datetime.now(timezone.utc).year
    count = (
        db.query(SecurityReport)
        .filter(SecurityReport.year == year)
        .count()
    ) + 1
    return f"SEC-{year}-{count:03d}"
 
 
# ── Routes ────────────────────────────────────────────────────────────────
 
@router.post("/report")
async def submit_report(body: ReportSubmission, db: Session = Depends(get_db)):
    """
    Public — no auth required. Stores the report and sends an auto-ack email.
    AC2, AC3.
    """
    if len(body.description.strip()) < 30:
        raise HTTPException(400, detail="Description too short — please provide more detail.")
    if len(body.reproduction_steps.strip()) < 20:
        raise HTTPException(400, detail="Reproduction steps too short — please describe the steps.")
 
    ref_id = _generate_ref_id(db)
 
    report = SecurityReport(
        ref_id             = ref_id,
        year               = datetime.now(timezone.utc).year,
        researcher_name    = body.researcher_name.strip(),
        researcher_email   = body.researcher_email,
        vulnerability_type = body.vulnerability_type,
        severity           = body.severity,
        description        = body.description.strip(),
        reproduction_steps = body.reproduction_steps.strip(),
        impact_assessment  = body.impact_assessment.strip(),
        contact_preference = body.contact_preference,
        status             = "received",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
 
    # AC2 — auto-acknowledgment email
    if body.contact_preference != "none":
        await send_security_acknowledgment(
            to_email        = body.researcher_email,
            researcher_name = body.researcher_name,
            ref_id          = ref_id,
            severity        = body.severity,
            vuln_type       = body.vulnerability_type,
        )
 
    logger.info("Security report received: %s severity=%s from=%s",
                ref_id, body.severity, body.researcher_email)
 
    return {
        "ref_id":   ref_id,
        "status":   "received",
        "message":  "Your report has been received. Thank you for helping keep ShieldIQ secure.",
    }
 
 
@router.get("/reports", dependencies=[Depends(_require_admin)])
def list_reports(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Admin only — AC5: restricted to authorized security personnel."""
    q = db.query(SecurityReport).order_by(SecurityReport.submitted_at.desc())
    if status:
        q = q.filter(SecurityReport.status == status)
    if severity:
        q = q.filter(SecurityReport.severity == severity)
 
    reports = q.limit(200).all()
    return [
        {
            "ref_id":             r.ref_id,
            "researcher_name":    r.researcher_name,
            "researcher_email":   r.researcher_email,
            "vulnerability_type": r.vulnerability_type,
            "severity":           r.severity,
            "status":             r.status,
            "submitted_at":       r.submitted_at.isoformat() if r.submitted_at else None,
            "resolved_at":        r.resolved_at.isoformat() if r.resolved_at else None,
            "description":        r.description,
            "reproduction_steps": r.reproduction_steps,
            "impact_assessment":  r.impact_assessment,
        }
        for r in reports
    ]
 
 
@router.patch("/reports/{ref_id}", dependencies=[Depends(_require_admin)])
async def update_report_status(
    ref_id: str,
    body: StatusUpdate,
    db: Session = Depends(get_db),
):
    """
    Admin only — AC4 (notify researcher), AC6 (mark resolved).
    """
    report = db.query(SecurityReport).filter_by(ref_id=ref_id).first()
    if not report:
        raise HTTPException(404, detail=f"Report {ref_id} not found")
 
    valid_statuses = ("received", "investigating", "resolved", "wont_fix")
    if body.status not in valid_statuses:
        raise HTTPException(400, detail=f"Status must be one of: {', '.join(valid_statuses)}")
 
    report.status = body.status
    if body.status == "resolved":
        report.resolved_at = datetime.now(timezone.utc)
 
    db.commit()
    db.refresh(report)
 
    # AC4 — notify researcher of status change if they want updates
    if report.contact_preference != "none":
        await send_security_status_update(
            to_email        = report.researcher_email,
            researcher_name = report.researcher_name,
            ref_id          = ref_id,
            new_status      = body.status,
            message         = body.message,
        )
 
    logger.info("Security report %s updated to status=%s", ref_id, body.status)
    return {"ref_id": ref_id, "status": body.status}
 
 
@router.get("/reports/{ref_id}", dependencies=[Depends(_require_admin)])
def get_report(ref_id: str, db: Session = Depends(get_db)):
    """Admin only — full report detail including internal notes. AC5."""
    report = db.query(SecurityReport).filter_by(ref_id=ref_id).first()
    if not report:
        raise HTTPException(404, detail=f"Report {ref_id} not found")
    return {
        "ref_id":             report.ref_id,
        "researcher_name":    report.researcher_name,
        "researcher_email":   report.researcher_email,
        "vulnerability_type": report.vulnerability_type,
        "severity":           report.severity,
        "status":             report.status,
        "description":        report.description,
        "reproduction_steps": report.reproduction_steps,
        "impact_assessment":  report.impact_assessment,
        "contact_preference": report.contact_preference,
        "submitted_at":       report.submitted_at.isoformat() if report.submitted_at else None,
        "resolved_at":        report.resolved_at.isoformat() if report.resolved_at else None,
        "internal_notes":     report.internal_notes,
    }
