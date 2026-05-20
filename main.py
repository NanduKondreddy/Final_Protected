# backend/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
import os

load_dotenv()

from database import engine
import db_models
from routers import auth_router, scan_router
from prompts import DEMO_SCENARIOS

# Create all DB tables on startup if they don't exist
db_models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SHIELD IQ API", version="2.0.0")

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


# ── Existing Endpoints (unchanged) ───────────────────────────────────────────
@app.get("/demo/{scenario_id}")
async def get_demo(scenario_id: str):
    msg = DEMO_SCENARIOS.get(scenario_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Demo not found")
    return {"message": msg}

@app.get("/health")
async def health():
    return {"status": "ok"}


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

@app.get("/checkout")
async def serve_checkout():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "checkout.html"))

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
async def serve_contact():
    return NoCacheFileResponse(os.path.join(FRONTEND_DIR, "contact.html"))