# backend/db_models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base
 
 
class User(Base):
    __tablename__ = "users"
 
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False, default="User")
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
 
    scans = relationship("Scan", back_populates="user")
 
 
class Scan(Base):
    __tablename__ = "scans"
 
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # nullable = anonymous scans allowed
    message = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    summary = Column(String, nullable=False)
    reasons = Column(JSON, nullable=False)           # stores list of strings
    action = Column(String, nullable=False)
    what_to_do = Column(String, nullable=False)
    pass1_blocked = Column(Boolean, default=False)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
 
    user = relationship("User", back_populates="scans")
    