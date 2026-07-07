# backend/db_models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Text
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

    scans = relationship("Scan", back_populates="user")
    payment_transactions = relationship("PaymentTransaction", back_populates="user", lazy="dynamic")


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

class Review(Base):
    __tablename__ = "reviews"
 
    id            = Column(Integer, primary_key=True, index=True)
    reviewer_name = Column(String(80),  nullable=False)
    rating        = Column(Integer,     nullable=False)          # 1-5
    review_text   = Column(Text,        nullable=True)           # optional
    location      = Column(String(80),  nullable=True)           # optional
    approved      = Column(Boolean,     default=False, nullable=False)
    created_at    = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
 

class PaymentTransaction(Base):
    """
    Stores every payment attempt — pending, successful, and failed.
    Written from routers/billings.py at checkout, verify, and webhook events.
    """
    __tablename__ = "payment_transactions"
 
    id               = Column(Integer, primary_key=True, index=True)
    user_id          = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    reference        = Column(String, unique=True, index=True, nullable=False)
    plan             = Column(String, nullable=False)           # "pro" | "plus"
    amount           = Column(Integer, nullable=False)          # smallest unit (kobo/cents)
    currency         = Column(String(10), nullable=False)       # "NGN" | "USD" etc.
    status           = Column(String(20), nullable=False)       # "pending"|"success"|"failed"
    paystack_event   = Column(String(50), nullable=True)        # originating event name
    gateway_response = Column(String(255), nullable=True)       # Paystack gateway_response text
    email_sent       = Column(Boolean, default=False, nullable=False)  # receipt sent? (avoid double-send)
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
 
    user = relationship("User", back_populates="payment_transactions")
 
    def __repr__(self):
        return f"<PaymentTransaction ref={self.reference!r} plan={self.plan!r} status={self.status!r}>"
