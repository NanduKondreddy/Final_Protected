# test_us01_us02_us03_core_scanner.py
import os
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
import db_models
from main import app
from models import ScanResult as ModelScanResult
import database

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_core_scanner.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

database.SessionLocal = TestingSessionLocal

@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=engine)
    db_session = TestingSessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        if os.path.exists("./test_core_scanner.db"):
            try:
                os.remove("./test_core_scanner.db")
            except Exception:
                pass

@pytest.fixture(scope="module")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()

# Mock AI call helper
@pytest.fixture
def mock_ai_call():
    mock_scan_res = ModelScanResult(
        risk_score=92,
        risk_level="HIGH",
        summary="Urgency language, suspicious link, and bank impersonation indicators.",
        reasons=["suspicious link", "impersonation", "urgency"],
        action="BLOCK",
        what_to_do="Do not click links. Contact your bank directly through official channels.",
        pass1_blocked=False,
        detected_language="en",
        fraud_type="bank_phishing",
        priority_used=False
    )
    async def mock_analyze(*args, **kwargs):
        return mock_scan_res
    return mock_analyze

@pytest.mark.anyio
async def test_us01_scan_message_verdict(client, db, mock_ai_call):
    # Test US-01 AC1 & AC4: message scan completes and returns risk band, score, verdict (action), reasons, and recommendation
    with patch("routers.scan_router.analyze_message", mock_ai_call):
        resp = client.post("/scan", data={"message": "Clean message", "ui_lang": "en"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_score"] == 92
        assert data["risk_level"] == "HIGH"
        assert data["action"] == "BLOCK"
        assert "bank impersonation" in data["summary"]
        assert len(data["reasons"]) >= 1
        assert "Do not click links" in data["what_to_do"]

@pytest.mark.anyio
async def test_us01_ac2_empty_message(client):
    # Test US-01 AC2: empty message validation
    resp = client.post("/scan", data={"message": "", "ui_lang": "en"})
    assert resp.status_code == 400
    assert "provide a message or upload a file" in resp.json()["detail"]

@pytest.mark.anyio
async def test_us01_ac5_ac6_guest_limit_and_zero_persistence(client, db, mock_ai_call):
    # Clear scan table first
    db.query(db_models.Scan).delete()
    db.commit()

    with patch("routers.scan_router.analyze_message", mock_ai_call):
        # Scan 1: Guest Scan
        resp = client.post("/scan", data={"message": "Suspicious link", "ui_lang": "en"})
        assert resp.status_code == 200
        
        # Check that original message content is NOT permanently stored (AC5 / AC6)
        scans = db.query(db_models.Scan).all()
        assert len(scans) == 1
        assert scans[0].message == "[Message content not stored]"
        assert scans[0].user_id is None
        
        # Scan 2: Guest scan quota check (limit is 1 for guests)
        resp = client.post("/scan", data={"message": "Another message", "ui_lang": "en"})
        assert resp.status_code == 402
        assert resp.json()["detail"]["error"] == "quota_exceeded"
        assert resp.json()["detail"]["tier"] == "guest"

@pytest.mark.anyio
async def test_us02_ac4_fallback_assessment(client, db):
    # Test US-02 AC4: If the AI service is unavailable or exceeds timeout, the system
    # automatically performs rules-based analysis and informs the user that a fallback assessment was used.
    async def mock_failed_deep_analysis(*args, **kwargs):
        raise Exception("AI Service Timeout")

    message_text = "URGENT: Your account has been compromised. Log in at http://fake-login-shieldiq.com to verify."
    with patch("analyzer._run_deep_analysis", mock_failed_deep_analysis):
        # Clear scan table so limit doesn't hit
        db.query(db_models.Scan).delete()
        db.commit()

        resp = client.post("/scan", data={"message": message_text, "ui_lang": "en"})
        assert resp.status_code == 200
        data = resp.json()
        
        # Verify that fallback warning is present in results
        assert "[Fallback]" in data["summary"]
        assert any("Fallback assessment was used" in r for r in data["reasons"])
