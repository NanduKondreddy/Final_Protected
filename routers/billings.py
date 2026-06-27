# backend/billing.py
import os
import hmac
import hashlib
import logging
import httpx
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

import db_models
from database import get_db
from auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/billing", tags=["billing"])

# ── Config ────────────────────────────────────────────────────────────────
PAYSTACK_SECRET_KEY  = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY  = os.environ.get("PAYSTACK_PUBLIC_KEY", "")
APP_URL              = os.environ.get("APP_URL", "http://localhost:8000")
PAYSTACK_PLAN_PRO    = os.environ.get("PAYSTACK_PLAN_PRO",  "PLN_REPLACE_PRO")
PAYSTACK_PLAN_PLUS   = os.environ.get("PAYSTACK_PLAN_PLUS", "PLN_REPLACE_PLUS")

DUMMY_MODE = (
    not PAYSTACK_SECRET_KEY
    or PAYSTACK_SECRET_KEY.startswith("sk_test_REPLACE")
)
print(f"DEBUG BILLING: DUMMY_MODE={DUMMY_MODE}, KEY={PAYSTACK_SECRET_KEY[:20] if PAYSTACK_SECRET_KEY else 'NOT SET'}")

# Currency amounts in smallest unit (kobo, cents, etc.)
CURRENCY_CONFIG = {
    "NG": {"currency": "NGN", "pro": 590800,  "plus": 1398600},
    "GH": {"currency": "GHS", "pro": 5586,    "plus": 13965},
    "KE": {"currency": "KES", "pro": 51870,   "plus": 129675},
    "ZA": {"currency": "ZAR", "pro": 7382,    "plus": 18455},
}
PAYSTACK_DEFAULT_CURRENCY = os.environ.get("PAYSTACK_DEFAULT_CURRENCY", "NGN").upper()
if PAYSTACK_DEFAULT_CURRENCY == "USD":
    DEFAULT_CURRENCY = {"currency": "USD", "pro": 399, "plus": 999}
else:
    DEFAULT_CURRENCY = {"currency": "NGN", "pro": 590800, "plus": 1398600}

PAYSTACK_API = "https://api.paystack.co"

PLAN_RANK = {"free": 0, "pro": 1, "plus": 2}

# ── Schemas ───────────────────────────────────────────────────────────────
class CheckoutRequest(BaseModel):
    plan: str          # "pro" | "plus"
    country_code: str  # from frontend geo detection


class ActivateRequest(BaseModel):
    plan: str


class VerifyRequest(BaseModel):
    reference: str
    plan: str


class ChangeSubscriptionRequest(BaseModel):
    target_plan: str


# ── Helpers ───────────────────────────────────────────────────────────────
def _normalise_plan(plan: str) -> str:
    """Normalise shield_plus → plus to match db column values."""
    return "plus" if plan in ("shield_plus", "plus") else "pro"


def _get_amount(plan: str, country_code: str) -> dict:
    cfg = CURRENCY_CONFIG.get(country_code.upper(), DEFAULT_CURRENCY)
    amount = cfg["pro"] if plan == "pro" else cfg["plus"]
    return {"amount": amount, "currency": cfg["currency"]}


def _get_billing_details(plan: str, country_code: str) -> dict:
    country = (country_code or "").upper()
    env_key = f"PAYSTACK_PLAN_{plan.upper()}_{country}"
    specific_plan = os.environ.get(env_key)
    
    if specific_plan:
        cfg = CURRENCY_CONFIG.get(country, DEFAULT_CURRENCY)
        amount = cfg["pro"] if plan == "pro" else cfg["plus"]
        return {
            "plan_code": specific_plan,
            "amount": amount,
            "currency": cfg["currency"]
        }
    else:
        plan_code = PAYSTACK_PLAN_PRO if plan == "pro" else PAYSTACK_PLAN_PLUS
        amount = DEFAULT_CURRENCY["pro"] if plan == "pro" else DEFAULT_CURRENCY["plus"]
        return {
            "plan_code": plan_code,
            "amount": amount,
            "currency": DEFAULT_CURRENCY["currency"]
        }


def _paystack_headers() -> dict:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def _write_plan(
    db: Session,
    user: db_models.User,
    plan: str,
    customer_code: str = None,
    subscription_code: str = None,
    status: str = "active",
    ends_at: datetime = None,
):
    """Only place plan is written to DB."""
    user.plan = plan
    if customer_code:
        user.paystack_customer_code = customer_code
    if subscription_code:
        user.paystack_subscription_code = subscription_code
    user.subscription_status  = status
    user.subscription_ends_at = ends_at
    db.commit()
    db.refresh(user)
    logger.info("Plan updated: user=%s plan=%s status=%s", user.id, plan, status)


def _verify_paystack_signature(payload: bytes, signature: str) -> bool:
    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        payload,
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Routes ────────────────────────────────────────────────────────────────

@router.post("/create-checkout")
async def create_checkout(
    body: CheckoutRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    plan = _normalise_plan(body.plan)

    # Block repurchase or downgrade
    if PLAN_RANK.get(current_user.plan, 0) >= PLAN_RANK.get(plan, 0) \
            and current_user.plan != "free":
        raise HTTPException(400, detail={
            "error": "already_subscribed",
            "message": f"You already have {current_user.plan}. "
                       f"You can only upgrade to a higher plan.",
        })

    # ── DUMMY MODE ────────────────────────────────────────────────────────
    if DUMMY_MODE:
        return {
            "mode": "dummy",
            "plan": plan,
            "reference": f"dummy_{current_user.id}_{plan}_{int(datetime.now().timestamp())}",
        }

    # ── LIVE PAYSTACK ─────────────────────────────────────────────────────
    billing_details = _get_billing_details(plan, body.country_code)
    reference = f"shieldiq_{current_user.id}_{plan}_{int(datetime.now().timestamp())}"

    # Use the current frontend origin or referrer for the callback to prevent origin-mismatched logout
    origin = request.headers.get("origin")
    if not origin:
        referer = request.headers.get("referer")
        if referer:
            from urllib.parse import urlparse
            parsed = urlparse(referer)
            origin = f"{parsed.scheme}://{parsed.netloc}"
        else:
            origin = APP_URL.rstrip('/')

    payload = {
        "email":        current_user.email,
        "amount":       billing_details["amount"],
        "currency":     billing_details["currency"],
        "reference":    reference,
        "plan":         billing_details["plan_code"],
        "callback_url": f"{origin}/dashboard?upgraded=true&plan={plan}",
        "metadata": {
            "user_id": current_user.id,
            "plan":    plan,
        },
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PAYSTACK_API}/transaction/initialize",
            json=payload,
            headers=_paystack_headers(),
            timeout=10,
        )

    data = resp.json()

    print("PAYSTACK RESPONSE:", data)
    print("STATUS CODE:", resp.status_code)


    if not data.get("status"):
        raise HTTPException(502, detail="Payment provider error — please try again")

    return {
        "mode":              "live",
        "authorization_url": data["data"]["authorization_url"],
        "reference":         data["data"]["reference"],
        "plan":              plan,
    }


@router.post("/verify")
async def verify_payment(
    body: VerifyRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """Called by frontend after Paystack redirects back — verifies before writing plan."""
    if DUMMY_MODE:
        raise HTTPException(403, detail="Use /activate-dummy in dummy mode")

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{PAYSTACK_API}/transaction/verify/{body.reference}",
            headers=_paystack_headers(),
            timeout=10,
        )

    data = resp.json()
    if not data.get("status") or data["data"]["status"] != "success":
        raise HTTPException(402, detail={
            "error": "payment_not_verified",
            "message": "Payment could not be verified — no charge was made.",
        })

    plan         = _normalise_plan(body.plan)
    customer     = data["data"].get("customer", {})
    subscription = data["data"].get("plan_object", {})

    _write_plan(
        db, current_user,
        plan=plan,
        customer_code=customer.get("customer_code"),
        subscription_code=subscription.get("plan_code"),
        status="active",
        ends_at=datetime.now(timezone.utc) + timedelta(days=30),
    )

    return {"ok": True, "plan": plan, "mode": "live"}


@router.post("/activate-dummy")
async def activate_dummy(
    body: ActivateRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """Dummy mode only — writes plan to DB after mock payment animation."""
    if not DUMMY_MODE:
        raise HTTPException(403, detail="Dummy activation disabled in live mode")

    plan = _normalise_plan(body.plan)
    if plan not in ("pro", "plus"):
        raise HTTPException(400, detail="Invalid plan")

    _write_plan(
        db, current_user,
        plan=plan,
        status="active",
        ends_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    return {"ok": True, "plan": plan, "mode": "dummy"}


@router.post("/webhook")
async def paystack_webhook(request: Request, db: Session = Depends(get_db)):
    """Paystack POSTs here for every subscription event."""
    if DUMMY_MODE:
        return {"status": "ignored — dummy mode"}

    payload   = await request.body()
    signature = request.headers.get("x-paystack-signature", "")

    if not _verify_paystack_signature(payload, signature):
        raise HTTPException(400, detail="Invalid Paystack signature")

    import json
    event      = json.loads(payload)
    event_type = event.get("event")
    data       = event.get("data", {})

    logger.info("Paystack webhook: %s", event_type)

    if event_type == "charge.success":
        user_id = data.get("metadata", {}).get("user_id")
        plan    = data.get("metadata", {}).get("plan")
        if user_id and plan:
            user = db.query(db_models.User).filter_by(id=int(user_id)).first()
            if user:
                _write_plan(
                    db, user,
                    plan=_normalise_plan(plan),
                    customer_code=data.get("customer", {}).get("customer_code"),
                    subscription_code=data.get("plan_object", {}).get("plan_code"),
                    status="active",
                    ends_at=datetime.now(timezone.utc) + timedelta(days=30),
                )

    elif event_type in ("subscription.disable", "subscription.not_renew"):
        sub_code = data.get("subscription_code")
        if sub_code:
            user = db.query(db_models.User).filter_by(
                paystack_subscription_code=sub_code).first()
            if user:
                _write_plan(db, user, plan="free", status="canceled")

    elif event_type == "invoice.payment_failed":
        sub_code = data.get("subscription", {}).get("subscription_code")
        if sub_code:
            user = db.query(db_models.User).filter_by(
                paystack_subscription_code=sub_code).first()
            if user:
                user.subscription_status = "past_due"
                db.commit()

    return {"status": "ok"}


@router.post("/cancel")
async def cancel_subscription(
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    if current_user.plan == "free":
        raise HTTPException(400, detail="You do not have an active subscription to cancel.")

    if not current_user.subscription_ends_at:
        current_user.subscription_ends_at = datetime.now(timezone.utc) + timedelta(days=30)

    current_user.pending_plan = "free"
    current_user.subscription_status = "canceled"

    # In live Paystack mode, disable auto-renew on Paystack's end
    if not DUMMY_MODE and current_user.paystack_subscription_code:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{PAYSTACK_API}/subscription/disable",
                    json={
                        "code":  current_user.paystack_subscription_code,
                        "token": current_user.paystack_customer_code,
                    },
                    headers=_paystack_headers(),
                    timeout=10,
                )
        except Exception as e:
            logger.warning("Could not disable Paystack auto-renewal: %s", str(e))

    db.commit()
    db.refresh(current_user)
    readable_date = current_user.subscription_ends_at.strftime("%Y-%m-%d")
    return {
        "ok": True,
        "message": f"Your subscription cancellation has been scheduled. Your current plan remains active until {readable_date}."
    }


@router.post("/change-subscription")
async def change_subscription(
    body: ChangeSubscriptionRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    if current_user.plan == "free":
        raise HTTPException(400, detail="You do not have an active subscription to change.")
    
    target = body.target_plan.lower()
    if target not in ("pro", "free"):
        raise HTTPException(400, detail="Invalid target plan.")
        
    if PLAN_RANK.get(current_user.plan, 0) <= PLAN_RANK.get(target, 0):
        raise HTTPException(400, detail="You can only downgrade or cancel your plan. Use checkout to upgrade.")

    # Calculate end date if not set
    if not current_user.subscription_ends_at:
        current_user.subscription_ends_at = datetime.now(timezone.utc) + timedelta(days=30)

    current_user.pending_plan = target
    current_user.subscription_status = "canceled" if target == "free" else "pending_downgrade"
    
    # Disable Paystack auto-renew if canceling completely
    if not DUMMY_MODE and target == "free" and current_user.paystack_subscription_code:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{PAYSTACK_API}/subscription/disable",
                    json={
                        "code":  current_user.paystack_subscription_code,
                        "token": current_user.paystack_customer_code,
                    },
                    headers=_paystack_headers(),
                    timeout=10,
                )
        except Exception as e:
            logger.warning("Could not disable Paystack auto-renewal: %s", str(e))

    db.commit()
    db.refresh(current_user)
    
    readable_date = current_user.subscription_ends_at.strftime("%Y-%m-%d")
    return {
        "ok": True,
        "message": f"Your plan change to {target} has been scheduled. Your current plan remains active until {readable_date}.",
        "user": {
            "plan": current_user.plan,
            "pending_plan": current_user.pending_plan,
            "subscription_ends_at": current_user.subscription_ends_at.isoformat()
        }
    }


@router.post("/resume-subscription")
async def resume_subscription(
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    if not current_user.pending_plan:
        raise HTTPException(400, detail="No pending plan changes found.")

    current_user.pending_plan = None
    current_user.subscription_status = "active"
    current_user.subscription_ends_at = None

    db.commit()
    db.refresh(current_user)
    return {
        "ok": True,
        "message": "Your subscription has been resumed successfully.",
        "user": {
            "plan": current_user.plan,
            "pending_plan": current_user.pending_plan
        }
    }
