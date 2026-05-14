# backend/routers/auth_router.py
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
import db_models
from auth import hash_password, verify_password, create_access_token, get_current_user
from models import RegisterRequest, LoginRequest, AuthResponse, UserOut
 
router = APIRouter(prefix="/auth", tags=["Auth"])
 
 
@router.post("/register", response_model=AuthResponse)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    # Check if email already exists
    existing = db.query(db_models.User).filter(db_models.User.email == body.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
 
    user = db_models.User(
        full_name=body.full_name,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
 
    token = create_access_token(user.id, user.email)
    return AuthResponse(
        token=token,
        user=UserOut(id=user.id, full_name=user.full_name, email=user.email, created_at=user.created_at),
    )
 
 
@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(db_models.User).filter(db_models.User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
 
    token = create_access_token(user.id, user.email)
    return AuthResponse(
        token=token,
        user=UserOut(id=user.id, full_name=user.full_name, email=user.email, created_at=user.created_at),
    )
 
 
@router.post("/logout")
def logout(current_user: db_models.User = Depends(get_current_user)):
    # JWT is stateless — client should delete the token on their end
    return {"message": "Logged out successfully"}
 
 
@router.get("/me", response_model=UserOut)
def me(current_user: db_models.User = Depends(get_current_user)):
    return UserOut(
        id=current_user.id,
        full_name=current_user.full_name,
        email=current_user.email,
        created_at=current_user.created_at,
    )
 