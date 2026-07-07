# backend/main.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import time
from dotenv import load_dotenv
from enterprise.audit_store import write_platform_metric

load_dotenv()

from database import engine
import db_models
from routers import auth_router, scan_router, billings
from routers import audit_router, webhook_router, community_router, background_protection
from routers.reviews import router as reviews_router
from prompts import DEMO_SCENARIOS
from enterprise.api_key_manager import validate_key

# Create all DB tables on startup if they don't exist
db_models.Base.metadata.create_all(bind=engine)

# Migrate flat-file JSONL data to database if the tables are empty
try:
    from enterprise.db_migrator import migrate_all
    migrate_all()
except Exception as e:
    import logging
    logging.getLogger(__name__).error("One-off db migrator failed: %s", str(e))


from sqlalchemy import text

def _safe_alter(sql: str):
    """Run a single ALTER TABLE in its own connection so PostgreSQL tx aborts don't cascade."""
    with engine.connect() as _c:
        try:
            _c.execute(text(sql))
            _c.commit()
        except Exception:
            pass

# Users table columns
_safe_alter("ALTER TABLE users ADD COLUMN plan VARCHAR DEFAULT 'free'")
for col in ["paystack_customer_code", "paystack_subscription_code", "subscription_status"]:
    _safe_alter(f"ALTER TABLE users ADD COLUMN {col} VARCHAR")
_safe_alter("ALTER TABLE users ADD COLUMN subscription_ends_at TIMESTAMP")
_safe_alter("ALTER TABLE users ADD COLUMN pending_plan VARCHAR")

# audit_records: client_ip column (added v3.1) — MUST be isolated from users migrations
_safe_alter("ALTER TABLE audit_records ADD COLUMN client_ip VARCHAR")
_safe_alter("ALTER TABLE users ADD COLUMN retention_days INTEGER DEFAULT 0")
_safe_alter("ALTER TABLE scans ADD COLUMN expires_at TIMESTAMP")
_safe_alter("ALTER TABLE scans ADD COLUMN api_key_id VARCHAR")
_safe_alter("ALTER TABLE scans ADD COLUMN pass1_blocked BOOLEAN DEFAULT FALSE")
_safe_alter("ALTER TABLE scans ADD COLUMN channel VARCHAR DEFAULT 'web_app'")
_safe_alter("ALTER TABLE alerts ADD COLUMN scan_id INTEGER")


app = FastAPI(
    title="ShieldIQ API",
    version="3.0.0",
    description="Enterprise-grade AI fraud detection platform",
)

import traceback
import logging
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    logging.getLogger("main").error(f"Global exception handler: {exc}\n{tb}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal Server Error: {str(exc)}", "traceback": tb}
    )


# B2B Partner API Key Authentication Middleware
@app.middleware("http")
async def api_key_auth_middleware(request: Request, call_next):
    auth_header = request.headers.get("Authorization", "")
    api_key = None
    if auth_header.startswith("Bearer "):
        api_key = auth_header[7:]
    elif "x-api-key" in request.headers:
        api_key = request.headers["x-api-key"]

    # Initialize empty request state attributes to avoid hasattr/getattr errors
    request.state.api_key_id = None
    request.state.partner_name = None
    request.state.tier = None
    request.state.org_id = None
    request.state.retention_days = 0

    if api_key:
        partner_meta = validate_key(api_key)
        if partner_meta:
            request.state.api_key_id = partner_meta["key_id"]
            request.state.partner_name = partner_meta["partner_name"]
            request.state.tier = partner_meta["tier"]
            request.state.org_id = partner_meta.get("org_id")
            request.state.retention_days = partner_meta.get("retention_days", 0)

    response = await call_next(request)
    return response

@app.middleware("http")
async def platform_metrics_middleware(request: Request, call_next):
    # Exclude static files and asset routes to keep logs clean
    path = request.url.path
    if (
        path.startswith(("/css", "/assets", "/favicon.ico")) 
        or path.endswith((".html", ".css", ".js", ".png", ".jpg", ".webp"))
    ):
        return await call_next(request)

    start_time = time.time()
    try:
        response = await call_next(request)
        status_code = response.status_code
    except Exception as e:
        status_code = 500
        raise e
    finally:
        latency_ms = int((time.time() - start_time) * 1000)
        xff = request.headers.get("x-forwarded-for")
        client_ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "unknown")
        write_platform_metric(
            endpoint=path,
            method=request.method,
            status_code=status_code,
            latency_ms=latency_ms,
            client_ip=client_ip
        )
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(auth_router.router)
app.include_router(scan_router.router)
app.include_router(billings.router)

# Enterprise routers
app.include_router(audit_router.router)
app.include_router(webhook_router.router)
app.include_router(community_router.router)
app.include_router(reviews_router)
app.include_router(background_protection.router)


# ── Existing Endpoints (unchanged) ───────────────────────────────────────────
@app.get("/demo/{scenario_id}")
async def get_demo(scenario_id: str):
    msg = DEMO_SCENARIOS.get(scenario_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Demo not found")
    return {"message": msg}

@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0.0", "enterprise": True}

@app.get("/version")
async def version():
    return {
        "version": "3.0.0",
        "platform": "ShieldIQ Enterprise",
        "features": [
            "two_pass_analysis", "nigerian_context_injection",
            "multi_language_support", "multi_model_fallback",
            "output_validation", "audit_trail", "pattern_intelligence",
            "api_key_management", "webhook_system", "community_submissions",
            "intelligence_reports"
        ],
        "supported_languages": ["en", "pidgin", "yoruba", "hausa", "igbo"],
        "providers": ["gemini", "anthropic", "openai"],
    }


# ── Serve Frontend Static Files ──────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")

# Serve CSS, JS, and other static assets
if os.path.isdir(os.path.join(FRONTEND_DIR, "css")):
    app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")

if os.path.isdir(os.path.join(FRONTEND_DIR, "js")):
    app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")

if os.path.isdir(os.path.join(FRONTEND_DIR, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")


# ── HTML Page Routes ─────────────────────────────────────────────────────────
class NoCacheFileResponse(FileResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        self.headers["Pragma"] = "no-cache"
        self.headers["Expires"] = "0"

@app.get("/")
async def serve_home():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/login")
async def serve_login():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/reset-password")
@app.get("/reset-password.html")
async def serve_reset_password():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "reset-password.html"))

@app.get("/scan")
async def serve_scan_page():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "scan.html"))

@app.get("/dashboard")
async def serve_dashboard():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))

@app.get("/plans")
async def serve_plans():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "plans.html"))

@app.get("/checkout")
async def serve_checkout():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "checkout.html"))

@app.get("/ai")
async def serve_ai():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "ai.html"))

@app.get("/privacy")
async def serve_privacy():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "privacy.html"))

@app.get("/security")
async def serve_security():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "security.html"))

@app.get("/terms")
async def serve_terms():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "terms.html"))

@app.get("/about")
async def serve_about():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "about.html"))

@app.get("/contact")
@app.get("/contact.html")
async def serve_contact():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "contact.html"))

# ── Enterprise Pages ─────────────────────────────────────────────────────────
@app.get("/admin")
@app.get("/admin.html")
async def serve_admin():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "admin.html"))

@app.get("/super-admin")
@app.get("/super-admin.html")
@app.get("/super admin")
@app.get("/super%20admin")
async def serve_super_admin():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "super-admin.html"))