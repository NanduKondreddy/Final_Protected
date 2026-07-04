# backend/routers/auth_router.py
from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from sqlalchemy.orm import Session
from database import get_db
import db_models
from auth import hash_password, verify_password, create_access_token, get_current_user, create_reset_token, decode_reset_token
from models import RegisterRequest, LoginRequest, AuthResponse, UserOut, ForgotPasswordRequest, ResetPasswordRequest
from enterprise.audit_store import write_user_activity, resolve_and_write_user_activity

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging

logger = logging.getLogger("auth_router")

def send_reset_email(email: str, reset_link: str):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        smtp_port = 587
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    if not smtp_user or not smtp_password:
        logger.warning(f"SMTP credentials not configured. Reset link for {email}: {reset_link}")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = email
        msg['Subject'] = "Reset Your ShieldIQ Password"

        body = f"""Hello,

You requested a password reset for your ShieldIQ account.
Click the link below to reset your password:

{reset_link}

If you did not request this, please ignore this email.

Best regards,
The ShieldIQ Team"""

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_from, email, msg.as_string())
        server.quit()
        logger.info(f"Password reset email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send reset email to {email}: {e}")
        return False


router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Check if email exists in DB
    user = db.query(db_models.User).filter(db_models.User.email == body.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email is not registered")

    # Generate reset token
    token = create_reset_token(body.email)

    # Determine base URL dynamically
    base_url = str(request.base_url).rstrip('/')
    reset_link = f"{base_url}/reset-password?token={token}"

    # Send reset email in background
    background_tasks.add_task(send_reset_email, body.email, reset_link)

    # Log user activity
    xff = request.headers.get("x-forwarded-for")
    ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "127.0.0.1")
    background_tasks.add_task(resolve_and_write_user_activity, user.id, user.email, "forgot_password_request", ip)

    return {"message": "Password reset link has been sent to your email."}


@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    # Decode token to verify it
    email = decode_reset_token(body.token)

    # Fetch user
    user = db.query(db_models.User).filter(db_models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update password hash
    user.password_hash = hash_password(body.password)
    db.commit()

    return {"message": "Password has been reset successfully."}


@router.post("/register", response_model=AuthResponse)
def register(body: RegisterRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
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
    
    # Extract client IP (handle proxies/Render headers)
    xff = request.headers.get("x-forwarded-for")
    ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "127.0.0.1")
    background_tasks.add_task(resolve_and_write_user_activity, user.id, user.email, "register", ip, {"name": user.full_name})
    
    return AuthResponse(
        token=token,
        user=UserOut(id=user.id, full_name=user.full_name, email=user.email, plan=user.plan, created_at=user.created_at),
    )
 
 
@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(db_models.User).filter(db_models.User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
 
    token = create_access_token(user.id, user.email)
    
    # Extract client IP
    xff = request.headers.get("x-forwarded-for")
    ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "127.0.0.1")
    background_tasks.add_task(resolve_and_write_user_activity, user.id, user.email, "login", ip)
    
    return AuthResponse(
        token=token,
        user=UserOut(id=user.id, full_name=user.full_name, email=user.email, plan=user.plan, created_at=user.created_at),
    )
 
 
@router.post("/logout")
def logout(request: Request, background_tasks: BackgroundTasks, current_user: db_models.User = Depends(get_current_user)):
    # JWT is stateless — client should delete the token on their end
    xff = request.headers.get("x-forwarded-for")
    ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "127.0.0.1")
    background_tasks.add_task(resolve_and_write_user_activity, current_user.id, current_user.email, "logout", ip)
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
def upgrade(plan: str, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db), current_user: db_models.User = Depends(get_current_user)):
    if plan not in ["free", "pro", "plus", "enterprise"]:
        raise HTTPException(status_code=400, detail="Invalid subscription plan")
    current_user.plan = plan
    db.commit()
    db.refresh(current_user)
    
    xff = request.headers.get("x-forwarded-for")
    ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "127.0.0.1")
    background_tasks.add_task(resolve_and_write_user_activity, current_user.id, current_user.email, "upgrade_plan", ip, {"plan": plan})
    
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
 