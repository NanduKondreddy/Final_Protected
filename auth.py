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
 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
 
 
# ── Password Hashing ────────────────────────────────────────────────────────
 
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
 
 
def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
 
 
# ── JWT ─────────────────────────────────────────────────────────────────────
 
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
 