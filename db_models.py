# backend/db_models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base


class User(Base):
    __tablename__ = "users"

    id                         = Column(Integer, primary_key=True, index=True)
    full_name                  = Column(String, nullable=False, default="User")
    email                      = Column(String, unique=True, index=True, nullable=False)
    password_hash              = Column(String, nullable=False)
    plan                       = Column(String, nullable=False, default="free")  # free | pro | plus
    created_at                 = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Paystack billing ────────────────────────────────────────────────
    paystack_customer_code     = Column(String, nullable=True)
    paystack_subscription_code = Column(String, nullable=True)
    subscription_status        = Column(String, nullable=True)   # active | canceled | past_due
    subscription_ends_at       = Column(DateTime, nullable=True)
    pending_plan               = Column(String, nullable=True)   # pro | free

    scans = relationship("Scan", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=True)
    message       = Column(String, nullable=False)
    risk_score    = Column(Integer, nullable=False)
    risk_level    = Column(String, nullable=False)
    summary       = Column(String, nullable=False)
    reasons       = Column(JSON, nullable=False)
    action        = Column(String, nullable=False)
    what_to_do    = Column(String, nullable=False)
    pass1_blocked = Column(Boolean, default=False)
    scanned_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="scans")


class SupportTicket(Base):
    __tablename__ = "support_tickets"

    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String, nullable=False)
    email      = Column(String, nullable=False)
    subject    = Column(String, nullable=False)
    message    = Column(String, nullable=False)
    status     = Column(String, default="Open")  # Open | Resolved
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditRecord(Base):
    __tablename__ = "audit_records"

    id                = Column(Integer, primary_key=True, index=True)
    request_id        = Column(String, index=True, nullable=False)
    timestamp         = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    risk_score        = Column(Integer, nullable=False)
    risk_band         = Column(String, nullable=False)
    detected_language = Column(String, default="en")
    provider_used     = Column(String, default="gemini")
    latency_ms        = Column(Integer, default=0)
    source            = Column(String, default="web_app")
    was_overridden    = Column(Boolean, default=False)
    fraud_type        = Column(String, nullable=True)
    api_key_id        = Column(String, nullable=True)
    org_id            = Column(String, nullable=True)


class UserActivity(Base):
    __tablename__ = "user_activities"

    id        = Column(Integer, primary_key=True, index=True)
    user_id   = Column(Integer, nullable=True)
    email     = Column(String, nullable=False)
    action    = Column(String, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    details   = Column(JSON, nullable=True)


class PlatformMetric(Base):
    __tablename__ = "platform_metrics"

    id          = Column(Integer, primary_key=True, index=True)
    endpoint    = Column(String, nullable=False)
    method      = Column(String, nullable=False)
    status_code = Column(Integer, nullable=False)
    latency_ms  = Column(Integer, nullable=False)
    client_ip   = Column(String, nullable=False)
    timestamp   = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PatternRecord(Base):
    __tablename__ = "pattern_records"

    id                = Column(Integer, primary_key=True, index=True)
    request_id        = Column(String, index=True, nullable=False)
    timestamp         = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    risk_band         = Column(String, nullable=False)
    patterns          = Column(JSON, nullable=False)
    fraud_type        = Column(String, nullable=True)
    detected_language = Column(String, default="en")
    source            = Column(String, default="web_app")
    api_key_id        = Column(String, nullable=True)