"""
ShieldIQ — Reviews API
──────────────────────
POST /reviews        — submit a review (auth optional)
GET  /reviews        — list approved reviews
GET  /reviews/all    — admin: see all reviews including unapproved
PATCH /reviews/{id}/approve  — admin: approve a review
PATCH /reviews/{id}/unapprove — admin: unapprove a review
DELETE /reviews/{id}          — admin: delete a review
 
Follows the same conventions as your existing routers:
  - SQLAlchemy session via Depends(get_db)
  - JWT via Depends(get_current_user_optional) for soft-auth
  - Admin gated by ADMIN_SECRET_KEY query param
"""
 
import os
import logging
from datetime import datetime, timezone
from typing import Optional
 
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, conint, ConfigDict
from sqlalchemy.orm import Session
 
from database import get_db
from db_models import Review
 
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reviews", tags=["Reviews"])
 
ADMIN_KEY = os.environ.get("ADMIN_SECRET_KEY", "shieldiq_admin_2026")
 
 
# ── Pydantic schemas ────────────────────────────────────────────────────────
 
class ReviewCreate(BaseModel):
    reviewer_name : str              = Field(..., min_length=1, max_length=80)
    rating        : conint(ge=1, le=5)
    review_text   : Optional[str]    = Field(None, max_length=600)
    location      : Optional[str]    = Field(None, max_length=80)
 
 
class ReviewOut(BaseModel):
    id: int
    reviewer_name: str
    rating: int
    review_text: Optional[str]
    location: Optional[str]
    approved: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReviewListResponse(BaseModel):
    total: int
    reviews: list[ReviewOut]
 
 
# ── Routes ─────────────────────────────────────────────────────────────────
 
@router.post("", response_model=ReviewOut, status_code=201)
async def create_review(
    payload: ReviewCreate,
    db: Session = Depends(get_db),
):
    """
    Submit a review. Auth is optional.
    Reviews start as approved=False so admin can moderate.
    """
    review = Review(
        reviewer_name = payload.reviewer_name,
        rating        = payload.rating,
        review_text   = payload.review_text,
        location      = payload.location,
        approved      = False,
    )
    db.add(review)
    db.commit()
    db.refresh(review)
    logger.info("Review created id=%s rating=%s", review.id, review.rating)
    return review
 
 
@router.get("", response_model=dict)
async def list_reviews(
    limit  : int  = Query(default=50, ge=1, le=200),
    offset : int  = Query(default=0,  ge=0),
    db     : Session = Depends(get_db),
):
    """Public: returns only approved reviews, newest first."""
    reviews = (
        db.query(Review)
          .filter(Review.approved == True)
          .order_by(Review.created_at.desc())
          .offset(offset)
          .limit(limit)
          .all()
    )
    total = db.query(Review).filter(Review.approved == True).count()
    return {
        "total": total,
        "reviews": [
            ReviewOut.model_validate(review)
            for review in reviews
        ]
    }
 
 
@router.get("/all", response_model=dict)
async def list_all_reviews(
    limit     : int  = Query(default=50, ge=1, le=500),
    offset    : int  = Query(default=0,  ge=0),
    admin_key : str  = Query(default=""),
    db        : Session = Depends(get_db),
):
    """Admin only: returns all reviews regardless of approval status."""
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    reviews = (
        db.query(Review)
          .order_by(Review.created_at.desc())
          .offset(offset)
          .limit(limit)
          .all()
    )
    total = db.query(Review).count()

    return {
        "total": total,
        "reviews": [
            ReviewOut.model_validate(review)
            for review in reviews
        ]
    }
 
 
@router.patch("/{review_id}/approve", response_model=ReviewOut)
async def approve_review(
    review_id : int,
    admin_key : str = Query(default=""),
    db        : Session = Depends(get_db),
):
    """Admin only: approve a review so it appears publicly."""
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    review.approved = True
    db.commit()
    db.refresh(review)
    return review


@router.patch("/{review_id}/unapprove", response_model=ReviewOut)
async def unapprove_review(
    review_id : int,
    admin_key : str = Query(default=""),
    db        : Session = Depends(get_db),
):
    """Admin only: unapprove a review so it no longer appears publicly."""
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    review.approved = False
    db.commit()
    db.refresh(review)
    return review
 
 
@router.delete("/{review_id}", status_code=204)
async def delete_review(
    review_id : int,
    admin_key : str = Query(default=""),
    db        : Session = Depends(get_db),
):
    """Admin only: hard-delete a review."""
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    db.delete(review)
    db.commit()
