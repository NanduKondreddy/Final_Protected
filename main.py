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
from routers import audit_router, webhook_router, community_router
from prompts import DEMO_SCENARIOS
from enterprise.api_key_manager import validate_key

# Create all DB tables on startup if they don't exist
db_models.Base.metadata.create_all(bind=engine)

from sqlalchemy import text
with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN plan VARCHAR DEFAULT 'free'"))
        conn.commit()
    except Exception:
        pass

    # Ensure Paystack columns exist
    for col in ["paystack_customer_code", "paystack_subscription_code", "subscription_status"]:
        try:
            conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} VARCHAR"))
            conn.commit()
        except Exception:
            pass
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN subscription_ends_at DATETIME"))
        conn.commit()
    except Exception:
        pass
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN pending_plan VARCHAR"))
        conn.commit()
    except Exception:
        pass


app = FastAPI(
    title="ShieldIQ API",
    version="3.0.0",
    description="Enterprise-grade AI fraud detection platform",
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

    if api_key:
        partner_meta = validate_key(api_key)
        if partner_meta:
            request.state.api_key_id = partner_meta["key_id"]
            request.state.partner_name = partner_meta["partner_name"]
            request.state.tier = partner_meta["tier"]
            request.state.org_id = partner_meta.get("org_id")

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
        client_ip = request.client.host if request.client else "unknown"
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