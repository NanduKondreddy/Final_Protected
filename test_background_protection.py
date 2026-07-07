import base64
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
from db_models import User, ConnectedAccount, Scan, Alert
from main import app
from auth import create_access_token

# Setup test SQLite database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_background.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


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
        if os.path.exists("./test_background.db"):
            os.remove("./test_background.db")


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


def test_background_protection_lifecycle(client, db):
    # 1. Create a Shield Plus user and a Free user
    plus_user = User(
        email="plus@shieldiq.com",
        full_name="Plus User",
        password_hash="hashed_pw",
        plan="plus"
    )
    free_user = User(
        email="free@shieldiq.com",
        full_name="Free User",
        password_hash="hashed_pw",
        plan="free"
    )
    db.add(plus_user)
    db.add(free_user)
    db.commit()
    db.refresh(plus_user)
    db.refresh(free_user)

    plus_token = create_access_token(user_id=plus_user.id, email=plus_user.email)
    free_token = create_access_token(user_id=free_user.id, email=free_user.email)

    headers_plus = {"Authorization": f"Bearer {plus_token}"}
    headers_free = {"Authorization": f"Bearer {free_token}"}

    # 2. Verify Free User is rejected from connecting background protection
    resp = client.post(
        "/api/background/gmail/connect",
        json={"auth_code": "mock_code_123", "email": "plus@gmail.com"},
        headers=headers_free
    )
    assert resp.status_code == 403
    assert "Shield Plus subscribers" in resp.json()["detail"]

    # 3. Connect Gmail for Shield Plus subscriber (AC1)
    resp = client.post(
        "/api/background/gmail/connect",
        json={"auth_code": "mock_code_123", "email": "plus@gmail.com"},
        headers=headers_plus
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "connected"
    assert resp.json()["email"] == "plus@gmail.com"

    # Verify token storage in DB
    account = db.query(ConnectedAccount).filter(
        ConnectedAccount.user_id == plus_user.id,
        ConnectedAccount.provider == "gmail"
    ).first()
    assert account is not None
    assert account.email == "plus@gmail.com"
    assert account.access_token.startswith("mock_access_")
    assert account.refresh_token == "mock_refresh_mock_code_123"
    assert account.is_active is True

    # 4. Trigger new email watch notification via webhook (AC2, AC4, AC5)
    # The message is high-risk
    payload = {
        "message": {
            "data": base64.b64encode(json.dumps({"emailAddress": "plus@gmail.com", "historyId": 123}).encode()).decode(),
            "messageId": "msg_987"
        },
        "test_message_body": "URGENT: Your bank account is locked. Click here immediately to verify your identity: http://moniepoint-verify.xyz"
    }
    
    resp = client.post("/api/background/gmail/webhook", json=payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "scanned"
    assert res_data["risk_level"] == "HIGH"
    assert res_data["alert_triggered"] is True

    # Verify that ONLY metadata is stored in Scan database table (AC4)
    scans = db.query(Scan).filter(Scan.user_id == plus_user.id, Scan.channel == "gmail").all()
    assert len(scans) == 1
    assert scans[0].risk_level == "HIGH"
    assert scans[0].risk_score > 80
    assert scans[0].message == "[Authorized background scanning - message body not stored]"

    # Verify alert is created in database (AC5)
    alerts = db.query(Alert).filter(Alert.user_id == plus_user.id, Alert.channel == "gmail").all()
    assert len(alerts) == 1
    assert "inbox" in alerts[0].message
    assert alerts[0].is_read is False
    assert alerts[0].scan_id == scans[0].id

    # Test GET single scan detail
    resp = client.get(f"/scans/{scans[0].id}", headers=headers_plus)
    assert resp.status_code == 200
    assert resp.json()["id"] == scans[0].id

    # Get active alerts endpoint
    resp = client.get("/api/background/alerts", headers=headers_plus)
    assert resp.status_code == 200
    assert len(resp.json()["alerts"]) == 1
    alert_id = resp.json()["alerts"][0]["id"]

    # Mark alerts as read
    resp = client.post("/api/background/alerts/read", json={"alert_ids": [alert_id]}, headers=headers_plus)
    assert resp.status_code == 200
    assert resp.json()["marked_count"] == 1
    assert db.query(Alert).filter(Alert.id == alert_id).first().is_read is True

    # Test getting active alerts after marking read (should be 0)
    resp = client.get("/api/background/alerts", headers=headers_plus)
    assert len(resp.json()["alerts"]) == 0

    # Test getting all alerts including read ones
    resp = client.get("/api/background/alerts?all=true", headers=headers_plus)
    assert len(resp.json()["alerts"]) == 1

    # 5. Connect WhatsApp Business webhook protection (AC3)
    resp = client.post(
        "/api/background/whatsapp/connect",
        json={"phone_number": "123456789"},
        headers=headers_plus
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "connected"
    assert resp.json()["phone_number"] == "123456789"

    # Verify verification GET endpoint challenge
    resp = client.get("/api/background/whatsapp/webhook?hub.mode=subscribe&hub.verify_token=shieldiq_verify_token&hub.challenge=test_challenge")
    assert resp.status_code == 200
    assert resp.text == "test_challenge"

    # POST WhatsApp message to webhook (AC3, AC4, AC5)
    whatsapp_payload = {
        "object": "whatsapp_business_account",
        "entry": [
          {
            "id": "123456",
            "changes": [
              {
                "value": {
                  "messaging_product": "whatsapp",
                  "metadata": {
                    "display_phone_number": "123456789",
                    "phone_number_id": "123456789"
                  },
                  "messages": [
                    {
                      "from": "16505551111",
                      "id": "wamid.123",
                      "timestamp": "1625000000",
                      "text": {
                        "body": "Congratulations! You won 1 million USD. Send processing fee now to claim: http://win-now.com"
                      },
                      "type": "text"
                    }
                  ]
                },
                "field": "messages"
              }
            ]
          }
        ]
    }
    resp = client.post("/api/background/whatsapp/webhook", json=whatsapp_payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "scanned"
    assert resp.json()["risk_level"] == "HIGH"

    # Verify Scan database (AC4)
    wa_scans = db.query(Scan).filter(Scan.user_id == plus_user.id, Scan.channel == "whatsapp").all()
    assert len(wa_scans) == 1
    assert wa_scans[0].message == "[Authorized background scanning - message body not stored]"

    # Verify WhatsApp Alert (AC5)
    wa_alerts = db.query(Alert).filter(Alert.user_id == plus_user.id, Alert.channel == "whatsapp").all()
    assert len(wa_alerts) == 1
    assert "WhatsApp" in wa_alerts[0].message
    assert wa_alerts[0].scan_id == wa_scans[0].id

    # 6. Disconnect/Revoke background protections (AC6)
    # Gmail Disconnect
    resp = client.post("/api/background/gmail/disconnect", headers=headers_plus)
    assert resp.status_code == 200
    assert resp.json()["status"] == "disconnected"

    # Verify Gmail watch notification is ignored/stops scanning immediately
    resp = client.post("/api/background/gmail/webhook", json=payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"

    # WhatsApp Disconnect
    resp = client.post("/api/background/whatsapp/disconnect", headers=headers_plus)
    assert resp.status_code == 200
    assert resp.json()["status"] == "disconnected"

    # Verify WhatsApp message webhook is ignored/stops scanning immediately
    resp = client.post("/api/background/whatsapp/webhook", json=whatsapp_payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
