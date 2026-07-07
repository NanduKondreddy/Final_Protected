# backend/auth.py
import os
import bcrypt
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db
import db_models
 
load_dotenv_done = False
try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv_done = True
except Exception:
    pass
 
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7
 
# AC6 — reset tokens are short-lived and single-purpose
RESET_TOKEN_EXPIRE_MINUTES = 30
 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
 
 
# ── Password Hashing ────────────────────────────────────────────────────────
 
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
 
 
def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
 
 
# ── JWT — access tokens ───────────────────────────────────────────────────
 
def create_access_token(user_id: int, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    payload = {"sub": str(user_id), "email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
 
 
def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
 
 
# ── JWT — password reset tokens ─────────────────────────────────────────────
#
# Reset tokens are deliberately a *different* token type from access tokens:
#   - they carry "purpose": "password_reset" so a reset link can never be
#     replayed as a login token (and vice versa)
#   - they carry the user's current password_hash so that once the password
#     is changed, the OLD token automatically stops working (the hash won't
#     match anymore) — even before its 30-minute expiry. This gives "single use"
#     behaviour without needing a separate DB table to track used tokens.
#   - they expire in RESET_TOKEN_EXPIRE_MINUTES (AC6)
 
def create_reset_token(user: db_models.User) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "purpose": "password_reset",
        # Bind the token to the current hash so it's invalidated the moment
        # the password actually changes, regardless of expiry.
        "pwd_fingerprint": user.password_hash[-12:],
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
 
 
def decode_reset_token(token: str, db: Session) -> db_models.User:
    """
    Validates a password reset token end-to-end:
      - signature + expiry (raises 400 if invalid/expired — AC6)
      - correct purpose claim (can't reuse a login token here)
      - user still exists
      - token's password fingerprint still matches the user's CURRENT hash
        (so a token can't be reused after a successful reset, or after a
        second reset request has superseded it)
    Returns the User on success, raises HTTPException otherwise.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link is invalid or has expired. Please request a new one.",
        )
 
    if payload.get("purpose") != "password_reset":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token.",
        )
 
    user = db.query(db_models.User).filter(
        db_models.User.id == int(payload["sub"])
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    if payload.get("pwd_fingerprint") != user.password_hash[-12:]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link has already been used. Please request a new one.",
        )
 
    return user
 
 
# ── Dependencies ─────────────────────────────────────────────────────────────
 
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> db_models.User:
    """Require a valid JWT. Use this on protected routes."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    payload = decode_token(token)
    user = db.query(db_models.User).filter(db_models.User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
 
 
def get_optional_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> db_models.User | None:
    """Optionally extract user from JWT — returns None if no token provided."""
    if not token:
        return None
    try:
        payload = decode_token(token)
        return db.query(db_models.User).filter(db_models.User.id == int(payload["sub"])).first()
    except Exception:
        return None
