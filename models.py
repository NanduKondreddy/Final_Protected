# backend/models.py
from pydantic import BaseModel, Field, EmailStr
from typing import Literal, Optional, List
from datetime import datetime
 
 
# ── Existing Scan Models (unchanged) ────────────────────────────────────────
 
class ScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000)
 
class ScanResult(BaseModel):
    risk_score: int
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    summary: str
    reasons: list[str]
    action: Literal["TRUST", "CAUTION", "BLOCK"]
    what_to_do: str
    pass1_blocked: bool = False
    priority_used: bool = False
 
 
# ── Auth Models ──────────────────────────────────────────────────────────────
 
class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
 
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
 
class UserOut(BaseModel):
    id: int
    full_name: str
    email: str
    plan: str
    created_at: datetime
    pending_plan: Optional[str] = None
    subscription_ends_at: Optional[datetime] = None
 
    class Config:
        from_attributes = True
 
class AuthResponse(BaseModel):
    token: str
    user: UserOut
 
 
# ── Scan History Models ──────────────────────────────────────────────────────
 
class ScanHistoryItem(BaseModel):
    id: int
    user_id: Optional[int]
    message: str
    risk_score: int
    risk_level: str
    summary: str
    reasons: List[str]
    action: str
    what_to_do: str
    pass1_blocked: bool
    scanned_at: datetime
 
    class Config:
        from_attributes = True
 
class ScanHistoryResponse(BaseModel):
    total: int
    page: int
    page_size: int
    scans: List[ScanHistoryItem]