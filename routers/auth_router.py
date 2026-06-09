# backend/routers/auth_router.py
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
import db_models
from auth import hash_password, verify_password, create_access_token, get_current_user
from models import RegisterRequest, LoginRequest, AuthResponse, UserOut
from enterprise.audit_store import write_user_activity
 
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
    write_user_activity(user.id, user.email, "register", {"name": user.full_name})
    return AuthResponse(
        token=token,
        user=UserOut(id=user.id, full_name=user.full_name, email=user.email, plan=user.plan, created_at=user.created_at),
    )
 
 
@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(db_models.User).filter(db_models.User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
 
    token = create_access_token(user.id, user.email)
    write_user_activity(user.id, user.email, "login")
    return AuthResponse(
        token=token,
        user=UserOut(id=user.id, full_name=user.full_name, email=user.email, plan=user.plan, created_at=user.created_at),
    )
 
 
@router.post("/logout")
def logout(current_user: db_models.User = Depends(get_current_user)):
    # JWT is stateless — client should delete the token on their end
    write_user_activity(current_user.id, current_user.email, "logout")
    return {"message": "Logged out successfully"}
 
 
@router.get("/me", response_model=UserOut)
def me(current_user: db_models.User = Depends(get_current_user)):
    return UserOut(
        id=current_user.id,
        full_name=current_user.full_name,
        email=current_user.email,
        plan=current_user.plan,
        created_at=current_user.created_at,
        pending_plan=current_user.pending_plan,
        subscription_ends_at=current_user.subscription_ends_at,
    )


@router.post("/upgrade", response_model=UserOut)
def upgrade(plan: str, db: Session = Depends(get_db), current_user: db_models.User = Depends(get_current_user)):
    if plan not in ["free", "pro", "plus", "enterprise"]:
        raise HTTPException(status_code=400, detail="Invalid subscription plan")
    current_user.plan = plan
    db.commit()
    db.refresh(current_user)
    write_user_activity(current_user.id, current_user.email, "upgrade_plan", {"plan": plan})
    return UserOut(
        id=current_user.id,
        full_name=current_user.full_name,
        email=current_user.email,
        plan=current_user.plan,
        created_at=current_user.created_at,
        pending_plan=current_user.pending_plan,
        subscription_ends_at=current_user.subscription_ends_at,
    )


@router.get("/download/extension")
def download_extension(
    current_user: db_models.User = Depends(get_current_user),
):
    """Bundles the 'extension' directory on the server into a ZIP file and sends it.
    Only users with 'plus' or 'enterprise' plans can download it.
    """
    import io
    import os
    import zipfile
    from fastapi.responses import StreamingResponse

    if current_user.plan not in ["plus", "enterprise"]:
        raise HTTPException(
            status_code=403,
            detail="The Chrome Extension is only available for Shield Plus or Enterprise plans."
        )

    # Path to extension is backend_root/extension
    # Since this file is in backend_root/routers/auth_router.py, go up one level
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    extension_path = os.path.join(base_dir, "extension")

    if not os.path.exists(extension_path) or not os.path.isdir(extension_path):
        raise HTTPException(
            status_code=500,
            detail="Extension source directory not found on the server."
        )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(extension_path):
            for file in files:
                file_full_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_full_path, extension_path)
                zip_file.write(file_full_path, rel_path)

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=shieldiq-extension.zip"}
    )
 