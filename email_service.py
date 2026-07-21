# backend/email_service.py
"""
Resend-powered transactional email service for ShieldIQ.
 
Handles AC4 & AC5:
  AC4 — sends receipt email after every successful payment
  AC5 — receipt includes customer name, plan, amount, date,
         transaction ID, and support contact
 
Configuration (add to your .env):
  RESEND_API_KEY=re_xxxxxxxxxxxx
  EMAIL_FROM=ShieldIQ <receipts@yourdomain.com>
  SUPPORT_EMAIL=support@yourdomain.com
"""
 
import os
import logging
from datetime import datetime, timezone
 
import httpx
 
logger = logging.getLogger(__name__)
 
# ── Config ────────────────────────────────────────────────────────────────
RESEND_API_KEY  = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM      = os.environ.get("EMAIL_FROM", "ShieldIQ <receipts@shieldiq.app>")
SUPPORT_EMAIL   = os.environ.get("SUPPORT_EMAIL", "support@shieldiq.app")
RESEND_API_URL  = "https://api.resend.com/emails"
 
# Currency symbol map for display
CURRENCY_SYMBOLS = {
    "NGN": "₦", "GHS": "GH₵", "KES": "KSh", "ZAR": "R",
    "USD": "$",  "GBP": "£",   "EUR": "€",
}
 
PLAN_LABELS = {
    "pro":  "ShieldIQ Pro",
    "plus": "Shield Plus",
}
 
 
# ── Helpers ───────────────────────────────────────────────────────────────
 
def _format_amount(amount: int, currency: str) -> str:
    """Convert smallest-unit integer + ISO currency to a display string."""
    symbol  = CURRENCY_SYMBOLS.get(currency.upper(), currency + " ")
    divisor = 100  # all supported currencies use 2 decimal places
    return f"{symbol}{amount / divisor:,.2f}"
 
 
def _format_date(dt: datetime) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%B %d, %Y at %H:%M UTC")
 
 
# ── HTML receipt template ─────────────────────────────────────────────────
 
def _build_receipt_html(
    customer_name: str,
    plan: str,
    amount: int,
    currency: str,
    reference: str,
    paid_at: datetime,
) -> str:
    plan_label    = PLAN_LABELS.get(plan, plan.title())
    amount_str    = _format_amount(amount, currency)
    date_str      = _format_date(paid_at)
    plan_color    = "#00d4a0" if plan == "plus" else "#ffffff"
    plan_bg       = "rgba(0,212,160,0.12)" if plan == "plus" else "rgba(255,255,255,0.08)"
 
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Payment Receipt — ShieldIQ</title>
</head>
<body style="margin:0;padding:0;background:#060810;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#060810;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0"
               style="background:#0d1117;border-radius:16px;border:1px solid rgba(255,255,255,0.08);overflow:hidden;max-width:560px;width:100%;">
 
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0d9488,#0f766e);padding:32px 40px;text-align:center;">
              <div style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-0.02em;">
                SHIELD <span style="color:#060810;">IQ</span>
              </div>
              <div style="font-size:13px;color:rgba(255,255,255,0.75);margin-top:6px;letter-spacing:0.05em;">
                AI FRAUD DETECTION
              </div>
            </td>
          </tr>
 
          <!-- Success badge -->
          <tr>
            <td style="padding:32px 40px 0;text-align:center;">
              <div style="display:inline-block;background:rgba(0,212,160,0.12);
                          border:1px solid rgba(0,212,160,0.3);border-radius:24px;
                          padding:8px 20px;font-size:13px;font-weight:700;
                          color:#00d4a0;letter-spacing:0.05em;">
                ✓ &nbsp;PAYMENT SUCCESSFUL
              </div>
              <h1 style="color:#fff;font-size:22px;font-weight:800;margin:20px 0 6px;">
                Your receipt from ShieldIQ
              </h1>
              <p style="color:#94a3b8;font-size:14px;margin:0;">
                Hi {customer_name}, thanks for subscribing. Here's your payment summary.
              </p>
            </td>
          </tr>
 
          <!-- Receipt details -->
          <tr>
            <td style="padding:28px 40px;">
              <table width="100%" cellpadding="0" cellspacing="0"
                     style="background:#161b22;border-radius:12px;border:1px solid rgba(255,255,255,0.06);">
 
                <!-- Plan -->
                <tr>
                  <td style="padding:18px 24px;border-bottom:1px solid rgba(255,255,255,0.06);">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Subscription Plan
                        </td>
                        <td align="right">
                          <span style="background:{plan_bg};color:{plan_color};
                                       font-size:11px;font-weight:800;padding:4px 12px;
                                       border-radius:10px;letter-spacing:0.06em;text-transform:uppercase;">
                            {plan_label}
                          </span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
 
                <!-- Amount -->
                <tr>
                  <td style="padding:18px 24px;border-bottom:1px solid rgba(255,255,255,0.06);">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Amount Paid
                        </td>
                        <td align="right"
                            style="font-size:20px;font-weight:900;color:#fff;font-family:monospace;">
                          {amount_str}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
 
                <!-- Date -->
                <tr>
                  <td style="padding:18px 24px;border-bottom:1px solid rgba(255,255,255,0.06);">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Date
                        </td>
                        <td align="right" style="font-size:13px;color:#e2e8f0;">
                          {date_str}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
 
                <!-- Transaction ID -->
                <tr>
                  <td style="padding:18px 24px;border-bottom:1px solid rgba(255,255,255,0.06);">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Transaction ID
                        </td>
                        <td align="right"
                            style="font-size:11px;color:#94a3b8;font-family:monospace;word-break:break-all;">
                          {reference}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
 
                <!-- Status -->
                <tr>
                  <td style="padding:18px 24px;">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Payment Status
                        </td>
                        <td align="right">
                          <span style="background:rgba(0,212,160,0.12);color:#00d4a0;
                                       font-size:11px;font-weight:700;padding:3px 10px;
                                       border-radius:8px;text-transform:uppercase;letter-spacing:0.05em;">
                            Successful
                          </span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
 
              </table>
            </td>
          </tr>
 
          <!-- What's included -->
          <tr>
            <td style="padding:0 40px 28px;">
              <p style="font-size:13px;font-weight:700;color:#fff;margin:0 0 12px;">
                What's included in your plan:
              </p>
              {"".join([
                  '<p style="font-size:13px;color:#94a3b8;margin:0 0 8px;padding-left:4px;">✓ &nbsp;' + f + '</p>'
                  for f in (
                      ["Unlimited manual scans", "Advanced PDF & Document scanning",
                       "Full Scan History & Export", "Chrome Extension access"]
                      if plan == "pro" else
                      ["Everything in Pro", "Auto-Scans WhatsApp, SMS, Email & DMs",
                       "Silent when Safe — never interrupts normal use",
                       "Full-screen fraud alerts before you click",
                       "Unlimited AI Document Scanning"]
                  )
              ])}
            </td>
          </tr>
 
          <!-- CTA -->
          <tr>
            <td style="padding:0 40px 32px;text-align:center;">
              <a href="https://shieldiq.app/dashboard"
                 style="display:inline-block;background:linear-gradient(135deg,#0d9488,#0f766e);
                        color:#fff;font-weight:700;font-size:14px;padding:14px 32px;
                        border-radius:8px;text-decoration:none;letter-spacing:0.02em;">
                Go to Dashboard →
              </a>
            </td>
          </tr>
 
          <!-- Support footer -->
          <tr>
            <td style="background:#080c14;border-top:1px solid rgba(255,255,255,0.06);
                       padding:24px 40px;text-align:center;">
              <p style="font-size:12px;color:#475569;margin:0 0 6px;">
                Questions about your subscription?
              </p>
              <p style="font-size:13px;color:#00d4a0;margin:0 0 16px;">
                <a href="mailto:{SUPPORT_EMAIL}"
                   style="color:#00d4a0;text-decoration:none;font-weight:600;">
                  {SUPPORT_EMAIL}
                </a>
              </p>
              <p style="font-size:11px;color:#334155;margin:0;">
                © 2026 ShieldIQ Technologies · Privacy-first AI Fraud Detection
              </p>
              <p style="font-size:11px;color:#334155;margin:6px 0 0;">
                You're receiving this because you made a purchase on ShieldIQ.
              </p>
            </td>
          </tr>
 
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
 
 
# ── Plain-text fallback ───────────────────────────────────────────────────
 
def _build_receipt_text(
    customer_name: str,
    plan: str,
    amount: int,
    currency: str,
    reference: str,
    paid_at: datetime,
) -> str:
    plan_label = PLAN_LABELS.get(plan, plan.title())
    return f"""ShieldIQ — Payment Receipt
==========================
 
Hi {customer_name},
 
Your payment was successful. Here's your receipt.
 
Subscription Plan : {plan_label}
Amount Paid       : {_format_amount(amount, currency)}
Date              : {_format_date(paid_at)}
Transaction ID    : {reference}
Payment Status    : Successful
 
Need help? Contact us at {SUPPORT_EMAIL}
 
© 2026 ShieldIQ Technologies
"""
 
 
# ── Public send function ──────────────────────────────────────────────────
 
async def send_payment_receipt(
    to_email: str,
    customer_name: str,
    plan: str,
    amount: int,
    currency: str,
    reference: str,
    paid_at: datetime = None,
) -> bool:
    """
    Send a payment receipt email via Resend.
 
    Returns True on success, False on failure (non-fatal — never raises,
    so a send failure never blocks plan activation).
    """
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set — skipping receipt email for %s", to_email)
        return False
 
    if paid_at is None:
        paid_at = datetime.now(timezone.utc)
 
    plan_label = PLAN_LABELS.get(plan, plan.title())
 
    payload = {
        "from":    EMAIL_FROM,
        "to":      [to_email],
        "subject": f"Your ShieldIQ receipt — {plan_label}",
        "html":    _build_receipt_html(customer_name, plan, amount, currency, reference, paid_at),
        "text":    _build_receipt_text(customer_name, plan, amount, currency, reference, paid_at),
    }
 
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RESEND_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type":  "application/json",
                },
                timeout=10,
            )
 
        if resp.status_code in (200, 201):
            data = resp.json()
            logger.info(
                "Receipt sent: to=%s plan=%s resend_id=%s",
                to_email, plan, data.get("id"),
            )
            return True
        else:
            logger.error(
                "Resend error %s for %s: %s",
                resp.status_code, to_email, resp.text,
            )
            return False
 
    except Exception as exc:
        logger.error("Failed to send receipt to %s: %s", to_email, exc)
        return False
 
 
# ── Password reset email ────────────────────────────────────────────────────
 
def _build_reset_html(customer_name: str, reset_url: str, expire_minutes: int) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset your ShieldIQ password</title>
</head>
<body style="margin:0;padding:0;background:#060810;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#060810;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="480" cellpadding="0" cellspacing="0"
               style="background:#0d1117;border-radius:16px;border:1px solid rgba(255,255,255,0.08);overflow:hidden;max-width:480px;width:100%;">
 
          <tr>
            <td style="background:linear-gradient(135deg,#0d9488,#0f766e);padding:28px 40px;text-align:center;">
              <div style="font-size:24px;font-weight:900;color:#fff;letter-spacing:-0.02em;">
                SHIELD <span style="color:#060810;">IQ</span>
              </div>
            </td>
          </tr>
 
          <tr>
            <td style="padding:36px 40px 8px;text-align:center;">
              <div style="font-size:40px;margin-bottom:8px;">🔑</div>
              <h1 style="color:#fff;font-size:20px;font-weight:800;margin:0 0 10px;">
                Reset your password
              </h1>
              <p style="color:#94a3b8;font-size:14px;line-height:1.6;margin:0 0 28px;">
                Hi {customer_name}, we received a request to reset your ShieldIQ password.
                Click the button below to choose a new one.
              </p>
            </td>
          </tr>
 
          <tr>
            <td style="padding:0 40px 28px;text-align:center;">
              <a href="{reset_url}"
                 style="display:inline-block;background:linear-gradient(135deg,#0d9488,#0f766e);
                        color:#fff;font-weight:700;font-size:14px;padding:14px 36px;
                        border-radius:8px;text-decoration:none;letter-spacing:0.02em;">
                Reset Password →
              </a>
              <p style="color:#475569;font-size:11px;margin:20px 0 0;line-height:1.6;">
                This link expires in {expire_minutes} minutes and can only be used once.<br>
                If you didn't request this, you can safely ignore this email —
                your password will not be changed.
              </p>
            </td>
          </tr>
 
          <tr>
            <td style="padding:0 40px 28px;text-align:center;">
              <p style="font-size:11px;color:#334155;margin:0 0 6px;">
                Or copy and paste this link into your browser:
              </p>
              <p style="font-size:11px;color:#00d4a0;word-break:break-all;margin:0;">
                {reset_url}
              </p>
            </td>
          </tr>
 
          <tr>
            <td style="background:#080c14;border-top:1px solid rgba(255,255,255,0.06);
                       padding:20px 40px;text-align:center;">
              <p style="font-size:12px;color:#475569;margin:0 0 6px;">
                Need help? Contact us at
              </p>
              <p style="font-size:13px;color:#00d4a0;margin:0;">
                <a href="mailto:{SUPPORT_EMAIL}" style="color:#00d4a0;text-decoration:none;font-weight:600;">
                  {SUPPORT_EMAIL}
                </a>
              </p>
              <p style="font-size:11px;color:#334155;margin:16px 0 0;">
                © 2026 ShieldIQ Technologies
              </p>
            </td>
          </tr>
 
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
 
 
def _build_reset_text(customer_name: str, reset_url: str, expire_minutes: int) -> str:
    return f"""ShieldIQ — Reset Your Password
================================
 
Hi {customer_name},
 
We received a request to reset your ShieldIQ password.
Click the link below to choose a new one:
 
{reset_url}
 
This link expires in {expire_minutes} minutes and can only be used once.
If you didn't request this, you can safely ignore this email.
 
Need help? Contact us at {SUPPORT_EMAIL}
 
© 2026 ShieldIQ Technologies
"""
 
 
async def send_password_reset_email(
    to_email: str,
    customer_name: str,
    reset_url: str,
    expire_minutes: int = 30,
) -> bool:
    """
    Sends a password reset email via Resend.
    Returns True on success, False on failure (non-fatal — never raises).
 
    Note: the caller (auth router) should ALWAYS return a generic
    "if that email exists, a reset link has been sent" response regardless
    of this function's return value or whether the email was registered —
    this avoids leaking which emails are registered users (account enumeration).
    """
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set — skipping reset email for %s", to_email)
        return False
 
    payload = {
        "from":    EMAIL_FROM,
        "to":      [to_email],
        "subject": "Reset your ShieldIQ password",
        "html":    _build_reset_html(customer_name, reset_url, expire_minutes),
        "text":    _build_reset_text(customer_name, reset_url, expire_minutes),
    }
 
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RESEND_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type":  "application/json",
                },
                timeout=10,
            )
 
        if resp.status_code in (200, 201):
            data = resp.json()
            logger.info("Reset email sent: to=%s resend_id=%s", to_email, data.get("id"))
            return True
        else:
            logger.error("Resend error %s for %s: %s", resp.status_code, to_email, resp.text)
            return False
 
    except Exception as exc:
        logger.error("Failed to send reset email to %s: %s", to_email, exc)
        return False


# ── Security Vulnerability Disclosure Emails ───────────────────────────────

def _build_security_acknowledgment_html(
    researcher_name: str,
    ref_id: str,
    severity: str,
    vuln_type: str,
) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report Acknowledgment — ShieldIQ</title>
</head>
<body style="margin:0;padding:0;background:#060810;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#060810;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0"
               style="background:#0d1117;border-radius:16px;border:1px solid rgba(255,255,255,0.08);overflow:hidden;max-width:560px;width:100%;">
          
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0d9488,#0f766e);padding:32px 40px;text-align:center;">
              <div style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-0.02em;">
                SHIELD <span style="color:#060810;">IQ</span>
              </div>
              <div style="font-size:13px;color:rgba(255,255,255,0.75);margin-top:6px;letter-spacing:0.05em;">
                SECURITY & DISCLOSURE
              </div>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding:32px 40px 0;text-align:center;">
              <div style="display:inline-block;background:rgba(0,212,160,0.12);
                          border:1px solid rgba(0,212,160,0.3);border-radius:24px;
                          padding:8px 20px;font-size:13px;font-weight:700;
                          color:#00d4a0;letter-spacing:0.05em;">
                🔐 REPORT RECEIVED
              </div>
              <h1 style="color:#fff;font-size:22px;font-weight:800;margin:20px 0 6px;">
                Thank you for your security report
              </h1>
              <p style="color:#94a3b8;font-size:14px;margin:0;line-height:1.6;">
                Hi {researcher_name}, thank you for helping keep ShieldIQ secure. We have received your vulnerability report and our security team is currently reviewing it.
              </p>
            </td>
          </tr>

          <!-- Details Table -->
          <tr>
            <td style="padding:28px 40px;">
              <table width="100%" cellpadding="0" cellspacing="0"
                     style="background:#161b22;border-radius:12px;border:1px solid rgba(255,255,255,0.06);">
                <tr>
                  <td style="padding:18px 24px;border-bottom:1px solid rgba(255,255,255,0.06);">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Reference ID
                        </td>
                        <td align="right" style="font-size:14px;color:#00d4a0;font-weight:700;font-family:monospace;">
                          {ref_id}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="padding:18px 24px;border-bottom:1px solid rgba(255,255,255,0.06);">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Vulnerability Type
                        </td>
                        <td align="right" style="font-size:13px;color:#fff;font-weight:600;">
                          {vuln_type}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="padding:18px 24px;">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
                          Assessed Severity
                        </td>
                        <td align="right">
                          <span style="background:rgba(255,255,255,0.08);color:#fff;
                                       font-size:11px;font-weight:800;padding:4px 12px;
                                       border-radius:10px;letter-spacing:0.06em;text-transform:uppercase;">
                            {severity}
                          </span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer/Next Steps -->
          <tr>
            <td style="padding:0 40px 32px;text-align:left;color:#94a3b8;font-size:13px;line-height:1.6;">
              <strong style="color:#fff;">What happens next?</strong>
              <ul style="margin:8px 0 0 20px;padding:0;">
                <li>We will conduct an initial review within 5 business days.</li>
                <li>We will keep you updated every 14 days until resolution.</li>
                <li>If the vulnerability is validated, we will coordinate resolution and remediation timelines based on severity.</li>
              </ul>
              <p style="margin-top:20px;font-size:12px;color:#475569;">
                Please do not disclose this issue publicly or to any third party until we have resolved it. Doing so helps us protect our customers.
              </p>
            </td>
          </tr>

          <!-- Support Footer -->
          <tr>
            <td style="background:#080c14;border-top:1px solid rgba(255,255,255,0.06);
                       padding:20px 40px;text-align:center;">
              <p style="font-size:11px;color:#334155;margin:0;">
                © 2026 ShieldIQ Technologies · Privacy-First Fraud Prevention
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _build_security_acknowledgment_text(
    researcher_name: str,
    ref_id: str,
    severity: str,
    vuln_type: str,
) -> str:
    return f"""ShieldIQ — Security Report Acknowledgment
=========================================

Hi {researcher_name},

Thank you for reporting a security issue. Your report has been received and is under review.

Reference ID: {ref_id}
Vulnerability Type: {vuln_type}
Assessed Severity: {severity}

What happens next?
- Our security team will conduct an initial review within 5 business days.
- We will update you every 14 days until resolution.
- Please do not disclose this issue publicly until it is resolved.

Thank you for helping keep ShieldIQ secure.

© 2026 ShieldIQ Technologies
"""


def _build_security_status_update_html(
    researcher_name: str,
    ref_id: str,
    new_status: str,
    message: str,
) -> str:
    status_colors = {
        "received": "#94a3b8",
        "investigating": "#f59e0b",
        "resolved": "#00d4a0",
        "wont_fix": "#ef4444"
    }
    status_color = status_colors.get(new_status, "#00d4a0")
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report Update — ShieldIQ</title>
</head>
<body style="margin:0;padding:0;background:#060810;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#060810;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0"
               style="background:#0d1117;border-radius:16px;border:1px solid rgba(255,255,255,0.08);overflow:hidden;max-width:560px;width:100%;">
          
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0d9488,#0f766e);padding:32px 40px;text-align:center;">
              <div style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-0.02em;">
                SHIELD <span style="color:#060810;">IQ</span>
              </div>
              <div style="font-size:13px;color:rgba(255,255,255,0.75);margin-top:6px;letter-spacing:0.05em;">
                SECURITY STATUS UPDATE
              </div>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding:32px 40px 0;text-align:center;">
              <div style="display:inline-block;background:rgba(255,255,255,0.08);
                          border:1px solid {status_color};border-radius:24px;
                          padding:8px 20px;font-size:13px;font-weight:700;
                          color:{status_color};letter-spacing:0.05em;text-transform:uppercase;">
                • {new_status}
              </div>
              <h1 style="color:#fff;font-size:22px;font-weight:800;margin:20px 0 6px;">
                Status Update: {ref_id}
              </h1>
              <p style="color:#94a3b8;font-size:14px;margin:0;line-height:1.6;">
                Hi {researcher_name}, we have an update on your security report.
              </p>
            </td>
          </tr>

          <!-- Message Box -->
          <tr>
            <td style="padding:28px 40px;">
              <div style="background:#161b22;border-radius:12px;border:1px solid rgba(255,255,255,0.06);padding:24px;color:#fff;font-size:14px;line-height:1.7;">
                <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:12px;">
                  Message from Security Team
                </div>
                {message}
              </div>
            </td>
          </tr>

          <!-- Support Footer -->
          <tr>
            <td style="background:#080c14;border-top:1px solid rgba(255,255,255,0.06);
                       padding:20px 40px;text-align:center;">
              <p style="font-size:11px;color:#334155;margin:0;">
                © 2026 ShieldIQ Technologies · Privacy-First Fraud Prevention
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _build_security_status_update_text(
    researcher_name: str,
    ref_id: str,
    new_status: str,
    message: str,
) -> str:
    return f"""ShieldIQ — Security Report Update
==================================

Hi {researcher_name},

We have an update regarding your security report {ref_id}.

New Status: {new_status}

Message from the Security Team:
----------------------------------
{message}
----------------------------------

Thank you for your help in keeping ShieldIQ secure.

© 2026 ShieldIQ Technologies
"""


async def send_security_acknowledgment(
    to_email: str,
    researcher_name: str,
    ref_id: str,
    severity: str,
    vuln_type: str,
) -> bool:
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set — skipping security ack email for %s", to_email)
        return False

    payload = {
        "from":    EMAIL_FROM,
        "to":      [to_email],
        "subject": f"Security Report Received: {ref_id}",
        "html":    _build_security_acknowledgment_html(researcher_name, ref_id, severity, vuln_type),
        "text":    _build_security_acknowledgment_text(researcher_name, ref_id, severity, vuln_type),
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RESEND_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type":  "application/json",
                },
                timeout=10,
            )

        if resp.status_code in (200, 201):
            data = resp.json()
            logger.info("Security ack email sent: to=%s resend_id=%s", to_email, data.get("id"))
            return True
        else:
            logger.error("Resend error %s for security ack to %s: %s", resp.status_code, to_email, resp.text)
            return False

    except Exception as exc:
        logger.error("Failed to send security ack email to %s: %s", to_email, exc)
        return False


async def send_security_status_update(
    to_email: str,
    researcher_name: str,
    ref_id: str,
    new_status: str,
    message: str,
) -> bool:
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set — skipping security status update email for %s", to_email)
        return False

    payload = {
        "from":    EMAIL_FROM,
        "to":      [to_email],
        "subject": f"Security Report Status Update: {ref_id}",
        "html":    _build_security_status_update_html(researcher_name, ref_id, new_status, message),
        "text":    _build_security_status_update_text(researcher_name, ref_id, new_status, message),
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RESEND_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type":  "application/json",
                },
                timeout=10,
            )

        if resp.status_code in (200, 201):
            data = resp.json()
            logger.info("Security status update email sent: to=%s resend_id=%s", to_email, data.get("id"))
            return True
        else:
            logger.error("Resend error %s for security status update to %s: %s", resp.status_code, to_email, resp.text)
            return False

    except Exception as exc:
        logger.error("Failed to send security status update email to %s: %s", to_email, exc)
        return False