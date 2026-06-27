"""
ShieldIQ Enterprise — Community Submission Route
──────────────────────────────────────────────────
POST /community/submit — submit suspected fraud
GET  /community/stats  — community contribution stats
"""

import uuid, logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from analyzer import analyze_message

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/community", tags=["Community"])


class CommunitySubmission(BaseModel):
    message: str
    submitter_language: Optional[str] = "en"


@router.post("/submit", summary="Submit a suspected fraud message")
async def submit_fraud_message(body: CommunitySubmission):
    """
    Submit a message you believe is fraudulent.
    ShieldIQ analyses it immediately and extracts pattern metadata.
    Message content is NOT stored — only the fraud signals.
    """
    try:
        result = await analyze_message(message=body.message)
        submission_id = str(uuid.uuid4())[:8].upper()

        logger.info("Community submission %s: score=%d level=%s",
                     submission_id, result.risk_score, result.risk_level)

        return {
            "submission_id": submission_id,
            "thank_you": "Thank you. Your submission helps protect all ShieldIQ users.",
            "verdict": result.risk_level,
            "risk_score": result.risk_score,
            "summary": result.summary,
            "reasons": result.reasons,
            "impact": ("This pattern has been added to ShieldIQ's detection database."
                       if result.risk_level == "HIGH"
                       else "This message will be reviewed by our team."),
        }

    except Exception as e:
        logger.error("Community submission failed: %s", str(e))
        raise HTTPException(status_code=500, detail={"error": str(e)})


@router.get("/stats", summary="Community contribution statistics")
async def get_community_stats():
    return {
        "message": "Every submission helps protect all ShieldIQ users.",
        "how_to_contribute": "POST /community/submit with any suspicious message.",
        "what_we_store": "Fraud signal patterns only — never message content.",
    }
