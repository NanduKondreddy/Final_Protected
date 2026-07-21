# test_enterprise_webhook.py
import os
import json
import pytest
import hmac
import hashlib
import asyncio
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
from db_models import User, Scan, AuditRecord
from main import app
from auth import create_access_token
from models import ScanResult as ModelScanResult

# Setup a clean test database
# Use a distinct test database to avoid locks
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_webhook.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

import database
import enterprise.audit_store
import enterprise.pattern_store
import routers.webhook_router

database.SessionLocal = TestingSessionLocal
enterprise.audit_store.SessionLocal = TestingSessionLocal
enterprise.pattern_store.SessionLocal = TestingSessionLocal
routers.webhook_router.SessionLocal = TestingSessionLocal


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
        if os.path.exists("./test_webhook.db"):
            try:
                os.remove("./test_webhook.db")
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


@pytest.fixture
def anyio_backend():
    return "asyncio"


# Autouse fixture to mock external AI and HTTP calls
@pytest.fixture(autouse=True)
def mock_external_calls():
    # 1. Mock analyze_message to avoid Gemini API quota issues
    mock_scan_res = ModelScanResult(
        risk_score=95,
        risk_level="HIGH",
        summary="Mocked phishing threat detected.",
        reasons=["suspicious link", "impersonation"],
        action="BLOCK",
        what_to_do="Do not click links.",
        pass1_blocked=True,
        detected_language="en",
        fraud_type="phishing",
        priority_used=True
    )
    
    async def mock_analyze(*args, **kwargs):
        return mock_scan_res
        
    patcher_analyze = patch("analyzer.analyze_message", mock_analyze)
    patcher_analyze.start()
    
    # 2. Mock httpx.AsyncClient.post globally so that background tasks are always intercepted
    mock_post = AsyncMock()
    mock_post.return_value.status_code = 200
    
    patcher_post = patch("httpx.AsyncClient.post", mock_post)
    patcher_post.start()
    
    yield mock_post
    
    patcher_analyze.stop()
    patcher_post.stop()


@pytest.mark.anyio
async def test_webhook_alerts_and_audit_trail(client, db, mock_external_calls):
    # Set testing environment so retries are fast
    os.environ["TESTING"] = "1"

    # Clean existing data to ensure independent runs
    db.query(AuditRecord).delete()
    db.query(Scan).delete()
    db.query(User).delete()
    db.commit()

    # 1. Create an Enterprise User
    ent_user = User(
        email="webhook_ent@shieldiq.com",
        full_name="Webhook Enterprise Org",
        password_hash="hashed_pw",
        plan="enterprise",
        retention_days=0
    )
    db.add(ent_user)
    db.commit()
    db.refresh(ent_user)

    ent_token = create_access_token(user_id=ent_user.id, email=ent_user.email)
    headers_ent = {"Authorization": f"Bearer {ent_token}"}

    # 2. Generate API Key
    resp = client.post(
        "/api/enterprise/keys/generate",
        json={"partner_name": "Webhook Partner", "daily_limit": 1000},
        headers=headers_ent
    )
    assert resp.status_code == 200
    key_data = resp.json()
    api_key = key_data["raw_key"]
    key_id = key_data["key_id"]

    # 3. Register Webhook
    webhook_headers = {"Authorization": f"Bearer {api_key}"}
    reg_payload = {
        "callback_url": "http://mock-enterprise-url.com/webhook",
        "secret": "super_secret_webhook_signing_key",
        "events": ["HIGH_RISK_DETECTED", "CAUTION_DETECTED"]
    }
    resp = client.post("/webhook/register", json=reg_payload, headers=webhook_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "registered"

    # 4. Trigger high-risk scan
    scan_msg = "URGENT: Your account has been compromised. Log in at http://fake-login-shieldiq.com to verify."
    
    resp = client.post(
        "/api/enterprise/scan",
        json={"message": scan_msg},
        headers={"x-api-key": api_key}
    )
    assert resp.status_code == 200
    scan_res = resp.json()
    assert scan_res["verdict"] == "HIGH"

    # Give FastAPI background tasks time to yield and complete execution
    await asyncio.sleep(0.1)

    # Verify that mock_post was called
    assert mock_external_calls.called
    call_args = mock_external_calls.call_args
    target_url = call_args[0][0]
    call_kwargs = call_args[1]

    assert target_url == "http://mock-enterprise-url.com/webhook"
    
    # Verify signed headers
    headers = call_kwargs["headers"]
    assert "X-Dovtek-Signature" in headers
    assert "X-Dovtek-Timestamp" in headers

    # Verify payload format
    sent_payload = json.loads(call_kwargs["content"].decode())
    assert sent_payload["eventType"] == "fraud.risk_detected"
    assert sent_payload["riskBand"] == "HIGH"
    assert sent_payload["riskScore"] == scan_res["score"]
    assert sent_payload["channel"] == "API"
    assert sent_payload["recommendedAction"] == "BLOCK"
    assert "scanId" in sent_payload

    # Verify signature validity
    timestamp = headers["X-Dovtek-Timestamp"]
    raw_body = call_kwargs["content"].decode()
    expected_sig_payload = f"{timestamp}.{raw_body}"
    expected_sig = hmac.new(
        reg_payload["secret"].encode(),
        expected_sig_payload.encode(),
        hashlib.sha256
    ).hexdigest()
    assert headers["X-Dovtek-Signature"] == expected_sig

    # AC2: Check successful delivery status stored in audit trail
    audit_record = db.query(AuditRecord).filter(AuditRecord.api_key_id == key_id).first()
    assert audit_record is not None
    assert audit_record.webhook_status == "success"
    assert audit_record.recommended_action == "BLOCK"

    # AC4 & AC5: Check zero-persistence constraints
    # Scans table must not contain message content
    scan_db = db.query(Scan).filter(Scan.api_key_id == key_id).first()
    assert scan_db is not None
    assert scan_db.message == "[Message content not stored]"

    # Audit trail must not contain message content (no content columns exist)
    # Check that only metadata is returned via API
    resp = client.get("/api/enterprise/metrics", headers=headers_ent)
    assert resp.status_code == 200
    metrics = resp.json()
    assert len(metrics["logs"]) >= 1
    log = metrics["logs"][0]
    assert log["webhook_status"] == "success"
    assert log["recommended_action"] == "BLOCK"
    assert "message" not in log

    # AC6: Compliance Export Check
    resp = client.get("/audit/export?format=json", headers=headers_ent)
    assert resp.status_code == 200
    export_json = resp.json()
    assert len(export_json) >= 1
    assert export_json[0]["recommendedAction"] == "BLOCK"
    assert export_json[0]["webhookStatus"] == "success"
    assert "message" not in export_json[0]

    resp = client.get("/audit/export?format=csv", headers=headers_ent)
    assert resp.status_code == 200
    csv_content = resp.text
    assert "Scan ID,Timestamp,Risk Score,Risk Band,Channel,Client ID,Webhook Delivery Status,Recommended Action,Fraud Type" in csv_content
    # Ensure message content is absolutely not in CSV
    assert "fake-login-shieldiq.com" not in csv_content


@pytest.mark.anyio
async def test_webhook_delivery_failure_and_retries(client, db, mock_external_calls):
    # Set testing environment so retries are fast
    os.environ["TESTING"] = "1"

    # Clean existing data to ensure independent runs
    db.query(AuditRecord).delete()
    db.query(Scan).delete()
    db.commit()

    # 1. Register a new key and webhook
    ent_user = db.query(User).filter(User.email == "webhook_ent@shieldiq.com").first()
    ent_token = create_access_token(user_id=ent_user.id, email=ent_user.email)
    headers_ent = {"Authorization": f"Bearer {ent_token}"}

    resp = client.post(
        "/api/enterprise/keys/generate",
        json={"partner_name": "Failure Partner", "daily_limit": 1000},
        headers=headers_ent
    )
    key_data = resp.json()
    api_key = key_data["raw_key"]
    key_id = key_data["key_id"]

    reg_payload = {
        "callback_url": "http://broken-endpoint.com/webhook",
        "secret": "failure_secret",
        "events": ["HIGH_RISK_DETECTED"]
    }
    client.post("/webhook/register", json=reg_payload, headers={"Authorization": f"Bearer {api_key}"})

    # Set mock post to raise connection exception
    mock_external_calls.side_effect = Exception("Unreachable server")

    # Trigger scan
    client.post(
        "/api/enterprise/scan",
        json={"message": "URGENT: Blocked account http://fake.com"},
        headers={"x-api-key": api_key}
    )

    # Wait for all retries to execute (they yield and wait 0.01-0.04s)
    await asyncio.sleep(0.3)

    # Verify that mock_post was called 5 times (1 initial + 4 retries)
    assert mock_external_calls.call_count == 5

    # AC3: Verify webhook_status in AuditRecord is marked as "failed"
    audit_record = db.query(AuditRecord).filter(AuditRecord.api_key_id == key_id).first()
    assert audit_record is not None
    assert audit_record.webhook_status == "failed"
