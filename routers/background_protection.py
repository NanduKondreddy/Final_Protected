# backend/routers/background_protection.py
import base64
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import db_models
from auth import get_current_user
from database import get_db
from analyzer import analyze_message

logger = logging.getLogger("background_protection")
router = APIRouter(prefix="/api/background", tags=["Background Protection"])


class GmailConnectRequest(BaseModel):
    auth_code: str
    email: str


class WhatsAppConnectRequest(BaseModel):
    phone_number: str


class AlertReadRequest(BaseModel):
    alert_ids: list[int]


# Helper to refresh Google OAuth token
async def get_valid_access_token(account: db_models.ConnectedAccount, db: Session) -> str:
    if not account.refresh_token:
        raise ValueError("No refresh token available")
    
    # Check if access token is still valid (using a 5-minute buffer)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if account.access_token and account.expires_at and account.expires_at > now + timedelta(minutes=5):
        return account.access_token

    # Token expired, perform refresh
    if account.refresh_token.startswith("mock_"):
        # For mock/testing, return mock access token
        account.access_token = f"mock_access_{datetime.now(timezone.utc).timestamp()}"
        account.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        db.commit()
        return account.access_token

    # Real Google OAuth Token Refresh
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        logger.warning("Google credentials not configured. Returning existing token.")
        return account.access_token or ""

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "refresh_token": account.refresh_token,
                    "grant_type": "refresh_token",
                },
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                account.access_token = data["access_token"]
                expires_in = data.get("expires_in", 3600)
                account.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=expires_in)
                db.commit()
                return account.access_token
            else:
                logger.error("Failed to refresh Gmail token: %s", resp.text)
    except Exception as e:
        logger.error("Exception during token refresh: %s", str(e))
    
    return account.access_token or ""


@router.get("/status", summary="Get background protection status")
async def get_status(current_user: db_models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.plan != "plus":
        return {
            "eligible": False,
            "gmail": {"connected": False, "is_active": False},
            "whatsapp": {"connected": False, "is_active": False}
        }

    accounts = db.query(db_models.ConnectedAccount).filter(db_models.ConnectedAccount.user_id == current_user.id).all()
    gmail_acc = next((a for a in accounts if a.provider == "gmail"), None)
    whatsapp_acc = next((a for a in accounts if a.provider == "whatsapp"), None)

    return {
        "eligible": True,
        "gmail": {
            "connected": gmail_acc is not None,
            "is_active": gmail_acc.is_active if gmail_acc else False,
            "email": gmail_acc.email if gmail_acc else None,
            "created_at": gmail_acc.created_at.isoformat() if gmail_acc else None
        },
        "whatsapp": {
            "connected": whatsapp_acc is not None,
            "is_active": whatsapp_acc.is_active if whatsapp_acc else False,
            "phone_number": whatsapp_acc.phone_number if whatsapp_acc else None,
            "created_at": whatsapp_acc.created_at.isoformat() if whatsapp_acc else None
        }
    }


@router.post("/gmail/connect", summary="Connect Gmail account")
async def connect_gmail(
    body: GmailConnectRequest,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.plan != "plus":
        raise HTTPException(
            status_code=403,
            detail="authorized background scanning is only available for Shield Plus subscribers."
        )

    # Check if already connected
    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.user_id == current_user.id,
        db_models.ConnectedAccount.provider == "gmail"
    ).first()

    # Mocks or real OAuth flow
    access_token = f"mock_access_{body.auth_code}"
    refresh_token = f"mock_refresh_{body.auth_code}"
    expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)

    if not body.auth_code.startswith("mock_"):
        # Real Google OAuth code exchange
        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
        if client_id and client_secret and redirect_uri:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        "https://oauth2.googleapis.com/token",
                        data={
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "code": body.auth_code,
                            "redirect_uri": redirect_uri,
                            "grant_type": "authorization_code",
                        },
                        timeout=10
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        access_token = data.get("access_token")
                        refresh_token = data.get("refresh_token", refresh_token)
                        expires_in = data.get("expires_in", 3600)
                        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=expires_in)
                    else:
                        logger.error("Google OAuth token exchange failed: %s", resp.text)
            except Exception as e:
                logger.error("Google OAuth exception: %s", str(e))

    if not account:
        account = db_models.ConnectedAccount(
            user_id=current_user.id,
            provider="gmail",
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            email=body.email,
            is_active=True
        )
        db.add(account)
    else:
        account.access_token = access_token
        account.refresh_token = refresh_token
        account.expires_at = expires_at
        account.email = body.email
        account.is_active = True

    db.commit()
    logger.info("Gmail connected for user %s (%s)", current_user.id, body.email)
    
    # Try setting up Gmail Watch
    try:
        await setup_gmail_watch_internal(account, db)
    except Exception as ex:
        logger.warning("Could not set up live Gmail Watch (expected in mock/dev): %s", str(ex))

    return {"status": "connected", "email": body.email}


@router.post("/gmail/watch", summary="Trigger or verify Gmail Watch setup")
async def trigger_gmail_watch(
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.plan != "plus":
        raise HTTPException(status_code=403, detail="Shield Plus required")

    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.user_id == current_user.id,
        db_models.ConnectedAccount.provider == "gmail",
        db_models.ConnectedAccount.is_active == True
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Active connected Gmail account not found")

    watch_res = await setup_gmail_watch_internal(account, db)
    return {"status": "success", "watch_details": watch_res}


async def setup_gmail_watch_internal(account: db_models.ConnectedAccount, db: Session):
    token = await get_valid_access_token(account, db)
    if not token or token.startswith("mock_"):
        return {"mock": True, "topicName": "projects/mock/topics/gmail-watch"}

    topic_name = os.getenv("GCP_PUBSUB_TOPIC", "projects/shieldiq-production/topics/gmail-notifications")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://gmail.googleapis.com/gmail/v1/users/me/watch",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={
                    "topicName": topic_name,
                    "labelIds": ["INBOX"]
                },
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                logger.info("Gmail watch set up successfully for %s", account.email)
                return data
            else:
                logger.error("Gmail Watch API returned error: %s", resp.text)
                raise ValueError(f"Gmail watch API failed: {resp.text}")
    except Exception as e:
        logger.error("Gmail watch setup error: %s", str(e))
        raise e


@router.post("/gmail/disconnect", summary="Disconnect Gmail account and stop scanning")
async def disconnect_gmail(
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.user_id == current_user.id,
        db_models.ConnectedAccount.provider == "gmail"
    ).first()

    if account:
        # Revoke watch in background if possible
        try:
            token = await get_valid_access_token(account, db)
            if token and not token.startswith("mock_"):
                async with httpx.AsyncClient() as client:
                    await client.post(
                        "https://gmail.googleapis.com/gmail/v1/users/me/stop",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=5
                    )
        except Exception:
            pass

        db.delete(account)
        db.commit()

    logger.info("Gmail disconnected for user %s", current_user.id)
    return {"status": "disconnected"}


# Webhook receiver for Google Cloud Pub/Sub
@router.post("/gmail/webhook", summary="Receive Gmail Pub/Sub push notifications")
async def gmail_pubsub_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    message_data = body.get("message", {})
    b64_data = message_data.get("data")
    if not b64_data:
        # If testing with raw payload direct from test-suite
        test_email = body.get("test_email")
        test_body = body.get("test_message_body")
        if test_email and test_body:
            return await process_gmail_incoming(test_email, test_body, db)
        raise HTTPException(status_code=400, detail="No pubsub message data")

    try:
        decoded_bytes = base64.b64decode(b64_data)
        decoded_json = json.loads(decoded_bytes.decode("utf-8"))
    except Exception as e:
        logger.error("Failed to decode PubSub message data: %s", str(e))
        raise HTTPException(status_code=400, detail="Failed to decode data")

    email_address = decoded_json.get("emailAddress")
    if not email_address:
        raise HTTPException(status_code=400, detail="emailAddress missing in PubSub payload")

    # Fetch latest Gmail message
    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.provider == "gmail",
        db_models.ConnectedAccount.email == email_address,
        db_models.ConnectedAccount.is_active == True
    ).first()

    if not account:
        logger.info("Received watch notification for inactive/unregistered email: %s", email_address)
        return {"status": "ignored", "reason": "account inactive or not registered"}

    # Fetch the actual message body
    message_body = ""
    # Look for manual test payload injection
    if body.get("test_message_body"):
        message_body = body["test_message_body"]
    else:
        message_body = await fetch_latest_gmail_message_content(account, db)

    if not message_body:
        return {"status": "ignored", "reason": "no new message body found"}

    return await process_gmail_incoming(email_address, message_body, db)


async def fetch_latest_gmail_message_content(account: db_models.ConnectedAccount, db: Session) -> str:
    token = await get_valid_access_token(account, db)
    if not token or token.startswith("mock_"):
        # For mock verification, return a default simulation body
        return "Urgent: Click to verify http://moniepoint-verify.com"

    try:
        async with httpx.AsyncClient() as client:
            # 1. List messages
            list_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1"
            list_resp = await client.get(list_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if list_resp.status_code != 200:
                logger.error("Gmail list messages failed: %s", list_resp.text)
                return ""
            
            messages = list_resp.json().get("messages", [])
            if not messages:
                return ""
            
            msg_id = messages[0]["id"]
            
            # 2. Get message details
            msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
            msg_resp = await client.get(msg_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if msg_resp.status_code != 200:
                return ""
            
            msg_data = msg_resp.json()
            snippet = msg_data.get("snippet", "")
            return snippet
    except Exception as e:
        logger.error("Failed fetching gmail content: %s", str(e))
        return ""


async def process_gmail_incoming(email: str, content: str, db: Session):
    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.provider == "gmail",
        db_models.ConnectedAccount.email == email,
        db_models.ConnectedAccount.is_active == True
    ).first()

    if not account:
        return {"status": "ignored", "reason": "recipient disconnected background protection"}

    user = account.user
    if user.plan != "plus":
        return {"status": "ignored", "reason": "Shield Plus plan required"}

    # Run analysis
    scan_res = await analyze_message(message=content, user_plan=user.plan, ui_lang="en")

    # Store ONLY metadata (AC4)
    db_scan = db_models.Scan(
        user_id=user.id,
        message="[Authorized background scanning - message body not stored]",
        risk_score=scan_res.risk_score,
        risk_level=scan_res.risk_level,
        summary=scan_res.summary,
        reasons=scan_res.reasons,
        action=scan_res.action,
        what_to_do=scan_res.what_to_do,
        pass1_blocked=scan_res.pass1_blocked,
        channel="gmail"
    )
    db.add(db_scan)
    db.flush()

    # Issue alert if high-risk is detected (AC5)
    if scan_res.risk_level == "HIGH":
        alert = db_models.Alert(
            user_id=user.id,
            scan_id=db_scan.id,
            title="Gmail Security Alert",
            message=f"High-risk message detected in your inbox. AI Verdict: {scan_res.summary}",
            channel="gmail",
            risk_score=scan_res.risk_score,
            is_read=False
        )
        db.add(alert)
        logger.warning("HIGH RISK GMAIL SCAN: User %s alerted on %s", user.id, scan_res.summary)

    db.commit()
    return {
        "status": "scanned",
        "risk_level": scan_res.risk_level,
        "risk_score": scan_res.risk_score,
        "alert_triggered": scan_res.risk_level == "HIGH"
    }


# WhatsApp Business Integration Routes
@router.post("/whatsapp/connect", summary="Connect WhatsApp Business webhook protection")
async def connect_whatsapp(
    body: WhatsAppConnectRequest,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.plan != "plus":
        raise HTTPException(
            status_code=403,
            detail="authorized background scanning is only available for Shield Plus subscribers."
        )

    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.user_id == current_user.id,
        db_models.ConnectedAccount.provider == "whatsapp"
    ).first()

    if not account:
        account = db_models.ConnectedAccount(
            user_id=current_user.id,
            provider="whatsapp",
            phone_number=body.phone_number,
            is_active=True
        )
        db.add(account)
    else:
        account.phone_number = body.phone_number
        account.is_active = True

    db.commit()
    logger.info("WhatsApp connected for user %s (%s)", current_user.id, body.phone_number)
    return {"status": "connected", "phone_number": body.phone_number}


@router.post("/whatsapp/disconnect", summary="Disconnect WhatsApp Business account and stop scanning")
async def disconnect_whatsapp(
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.user_id == current_user.id,
        db_models.ConnectedAccount.provider == "whatsapp"
    ).first()

    if account:
        db.delete(account)
        db.commit()

    logger.info("WhatsApp disconnected for user %s", current_user.id)
    return {"status": "disconnected"}


# WhatsApp Business API Webhook verification (GET challenge)
@router.get("/whatsapp/webhook", summary="Verify WhatsApp webhook subscription")
async def verify_whatsapp_webhook(request: Request):
    params = request.query_params
    mode = params.get("hub.mode")
    token = params.get("hub.verify_token")
    challenge = params.get("hub.challenge")

    verify_token = os.getenv("WHATSAPP_VERIFY_TOKEN", "shieldiq_verify_token")

    if mode == "subscribe" and token == verify_token:
        logger.info("WhatsApp webhook verified successfully.")
        return PlainTextResponse(challenge)
    
    logger.warning("WhatsApp webhook verification failed. Token mismatch.")
    raise HTTPException(status_code=403, detail="Verification token mismatch")


# WhatsApp Business webhook event listener
@router.post("/whatsapp/webhook", summary="Receive WhatsApp Business messages")
async def whatsapp_webhook_listener(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Parse message details from WhatsApp Cloud API structure
    entries = body.get("entry", [])
    if not entries:
        raise HTTPException(status_code=400, detail="Invalid WhatsApp payload: no entry")

    changes = entries[0].get("changes", [])
    if not changes:
        raise HTTPException(status_code=400, detail="Invalid WhatsApp payload: no changes")

    value = changes[0].get("value", {})
    messages = value.get("messages", [])
    if not messages:
        # Webhook receives statuses, read-receipts, etc. Return 200 OK.
        return {"status": "received", "details": "no new messages"}

    msg = messages[0]
    sender_phone = msg.get("from")
    msg_type = msg.get("type")
    
    if msg_type != "text":
        return {"status": "ignored", "reason": "unsupported message type"}

    text_body = msg.get("text", {}).get("body", "")
    if not text_body:
        return {"status": "ignored", "reason": "empty message body"}

    metadata = value.get("metadata", {})
    phone_number_id = metadata.get("phone_number_id")

    # Match webhook to an active connection using the recipient's phone number ID
    account = db.query(db_models.ConnectedAccount).filter(
        db_models.ConnectedAccount.provider == "whatsapp",
        db_models.ConnectedAccount.phone_number == phone_number_id,
        db_models.ConnectedAccount.is_active == True
    ).first()

    if not account:
        # Fallback search matching WaID / Sender if phone number ID is not registered directly
        account = db.query(db_models.ConnectedAccount).filter(
            db_models.ConnectedAccount.provider == "whatsapp",
            db_models.ConnectedAccount.is_active == True
        ).first()

    if not account:
        logger.info("Received WhatsApp message but no active background scanning is connected.")
        return {"status": "ignored", "reason": "recipient disconnected background protection"}

    user = account.user
    if user.plan != "plus":
        return {"status": "ignored", "reason": "Shield Plus plan required"}

    # Run analysis
    scan_res = await analyze_message(message=text_body, user_plan=user.plan, ui_lang="en")

    # Store ONLY metadata (AC4)
    db_scan = db_models.Scan(
        user_id=user.id,
        message="[Authorized background scanning - message body not stored]",
        risk_score=scan_res.risk_score,
        risk_level=scan_res.risk_level,
        summary=scan_res.summary,
        reasons=scan_res.reasons,
        action=scan_res.action,
        what_to_do=scan_res.what_to_do,
        pass1_blocked=scan_res.pass1_blocked,
        channel="whatsapp"
    )
    db.add(db_scan)
    db.flush()

    # Issue alert if high-risk detected (AC5)
    if scan_res.risk_level == "HIGH":
        alert = db_models.Alert(
            user_id=user.id,
            scan_id=db_scan.id,
            title="WhatsApp Security Alert",
            message=f"High-risk message detected on WhatsApp Business. AI Verdict: {scan_res.summary}",
            channel="whatsapp",
            risk_score=scan_res.risk_score,
            is_read=False
        )
        db.add(alert)
        logger.warning("HIGH RISK WHATSAPP SCAN: User %s alerted on %s", user.id, scan_res.summary)

    db.commit()
    return {
        "status": "scanned",
        "risk_level": scan_res.risk_level,
        "risk_score": scan_res.risk_score,
        "alert_triggered": scan_res.risk_level == "HIGH"
    }


# Alerts retrieving endpoints for UI
@router.get("/alerts", summary="Get background protection active alerts")
async def get_alerts(
    all: bool = False,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(db_models.Alert).filter(db_models.Alert.user_id == current_user.id)
    if not all:
        query = query.filter(db_models.Alert.is_read == False)
    alerts = query.order_by(db_models.Alert.created_at.desc()).all()

    return {
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "message": a.message,
                "channel": a.channel,
                "risk_score": a.risk_score,
                "is_read": a.is_read,
                "scan_id": a.scan_id,
                "created_at": a.created_at.isoformat()
            }
            for a in alerts
        ]
    }


@router.post("/alerts/read", summary="Mark background alerts as read")
async def mark_alerts_read(
    body: AlertReadRequest,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    alerts = db.query(db_models.Alert).filter(
        db_models.Alert.user_id == current_user.id,
        db_models.Alert.id.in_(body.alert_ids)
    ).all()

    for a in alerts:
        a.is_read = True

    db.commit()
    return {"status": "success", "marked_count": len(alerts)}
