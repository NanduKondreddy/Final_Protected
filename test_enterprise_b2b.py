# test_enterprise_b2b.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
from db_models import User, Scan, AuditRecord, PatternRecord
from main import app
from auth import create_access_token
from enterprise.api_key_manager import generate_key, revoke_key, list_keys

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_enterprise.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

import database
import enterprise.audit_store
import enterprise.pattern_store
database.SessionLocal = TestingSessionLocal
enterprise.audit_store.SessionLocal = TestingSessionLocal
enterprise.pattern_store.SessionLocal = TestingSessionLocal


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
        import os
        if os.path.exists("./test_enterprise.db"):
            os.remove("./test_enterprise.db")


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


def test_enterprise_b2b_management_and_scan(client, db):
    # 1. Create Enterprise User and Free User
    ent_user = User(
        email="enterprise@shieldiq.com",
        full_name="Enterprise User",
        password_hash="hashed_pw",
        plan="enterprise",
        retention_days=14
    )
    free_user = User(
        email="free@shieldiq.com",
        full_name="Free User",
        password_hash="hashed_pw",
        plan="free"
    )
    db.add(ent_user)
    db.add(free_user)
    db.commit()
    db.refresh(ent_user)
    db.refresh(free_user)

    ent_token = create_access_token(user_id=ent_user.id, email=ent_user.email)
    free_token = create_access_token(user_id=free_user.id, email=free_user.email)

    headers_ent = {"Authorization": f"Bearer {ent_token}"}
    headers_free = {"Authorization": f"Bearer {free_token}"}

    # 2. Verify Free User cannot list/generate keys (AC1 Restricts Access)
    resp = client.get("/api/enterprise/keys", headers=headers_free)
    assert resp.status_code == 403

    resp = client.post("/api/enterprise/keys/generate", json={"partner_name": "Free Partner"}, headers=headers_free)
    assert resp.status_code == 403

    # 3. Generate key for Enterprise User (AC1 / AC3)
    resp = client.post(
        "/api/enterprise/keys/generate",
        json={"partner_name": "Test SDK Partner", "daily_limit": 5000},
        headers=headers_ent
    )
    assert resp.status_code == 200
    key_data = resp.json()
    assert "key_id" in key_data
    assert "raw_key" in key_data
    assert key_data["partner_name"] == "Test SDK Partner"
    assert key_data["daily_limit"] == 5000

    api_key = key_data["raw_key"]
    key_id = key_data["key_id"]

    # 4. List keys (AC1 / AC3)
    resp = client.get("/api/enterprise/keys", headers=headers_ent)
    assert resp.status_code == 200
    keys_list = resp.json()
    assert len(keys_list) >= 1
    assert any(k["key_id"] == key_id for k in keys_list)

    # 5. Scan a message using the generated API Key (AC2 / AC5 / AC6)
    # AC2: Send valid scan request with header
    headers_sdk = {"x-api-key": api_key}
    scan_msg = "URGENT: Your account has been compromised. Log in at http://fake-login-shieldiq.com to verify."
    resp = client.post(
        "/api/enterprise/scan",
        json={"message": scan_msg},
        headers=headers_sdk
    )
    assert resp.status_code == 200
    scan_res = resp.json()
    assert "verdict" in scan_res
    assert "score" in scan_res
    assert "action" in scan_res
    assert "threatType" in scan_res
    assert "timestamp" in scan_res

    # AC6: Check that message is NOT stored in the scans table
    scan_db = db.query(Scan).filter(Scan.api_key_id == key_id).first()
    assert scan_db is not None
    assert scan_db.message == "[Message content not stored]"

    # Verify audit log exists
    audit_db = db.query(AuditRecord).filter(AuditRecord.api_key_id == key_id).first()
    assert audit_db is not None
    assert audit_db.risk_band == scan_res["verdict"]

    # 6. Check metrics endpoint (AC5)
    resp = client.get("/api/enterprise/metrics", headers=headers_ent)
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["total_requests"] >= 1
    assert metrics["requests_today"] >= 1
    assert metrics["keys_count"] >= 1
    assert len(metrics["logs"]) >= 1

    # 7. Revoke Key (AC3)
    resp = client.post(
        "/api/enterprise/keys/revoke",
        json={"key_id": key_id},
        headers=headers_ent
    )
    assert resp.status_code == 200

    # Verify that future scans using this key are rejected
    resp = client.post(
        "/api/enterprise/scan",
        json={"message": "Clean message"},
        headers=headers_sdk
    )
    assert resp.status_code == 401
