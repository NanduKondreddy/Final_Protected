"""
ShieldIQ Enterprise — API Key Manager
───────────────────────────────────────
Manage API keys for enterprise partners and SDK integrations.
"""

import os, json, uuid, hashlib, logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)
KEY_DIR = os.environ.get("SHIELDIQ_DATA_DIR") or os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "keys")
os.makedirs(KEY_DIR, exist_ok=True)
KEY_FILE = os.path.join(KEY_DIR, "api_keys.json")


def _load_keys() -> dict:
    if not os.path.exists(KEY_FILE):
        return {}
    try:
        with open(KEY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_keys(keys: dict) -> None:
    try:
        with open(KEY_FILE, "w", encoding="utf-8") as f:
            json.dump(keys, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error("API key save failed: %s", str(e))


def generate_key(partner_name: str, tier: str = "enterprise", daily_limit: int = 10000, org_id: Optional[str] = None) -> dict:
    key_id = f"shieldiq_{partner_name.lower().replace(' ', '_')}_{uuid.uuid4().hex[:8]}"
    raw_key = f"sk_live_{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    keys = _load_keys()
    keys[key_id] = {
        "key_hash": key_hash, "partner_name": partner_name, "tier": tier,
        "daily_limit": daily_limit, "org_id": org_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_active": True, "total_scans": 0, "last_used_at": None,
    }
    _save_keys(keys)
    logger.info("API key generated: id=%s partner=%s", key_id, partner_name)

    return {"key_id": key_id, "raw_key": raw_key, "partner_name": partner_name,
            "tier": tier, "daily_limit": daily_limit,
            "message": "Store this key securely. It will not be shown again."}


def validate_key(raw_key: str) -> Optional[dict]:
    if not raw_key:
        return None
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    keys = _load_keys()
    for key_id, meta in keys.items():
        if meta["key_hash"] == key_hash and meta.get("is_active", True):
            meta["total_scans"] = meta.get("total_scans", 0) + 1
            meta["last_used_at"] = datetime.now(timezone.utc).isoformat()
            _save_keys(keys)
            return {"key_id": key_id, "partner_name": meta["partner_name"],
                    "tier": meta["tier"], "daily_limit": meta["daily_limit"],
                    "org_id": meta.get("org_id")}
    return None


def revoke_key(key_id: str) -> bool:
    keys = _load_keys()
    if key_id in keys:
        keys[key_id]["is_active"] = False
        keys[key_id]["revoked_at"] = datetime.now(timezone.utc).isoformat()
        _save_keys(keys)
        return True
    return False


def list_keys(org_id: Optional[str] = None) -> list:
    keys = _load_keys()
    result = []
    for key_id, meta in keys.items():
        if org_id and meta.get("org_id") != org_id:
            continue
        result.append({"key_id": key_id, "partner_name": meta["partner_name"],
                        "tier": meta["tier"], "is_active": meta.get("is_active", True),
                        "created_at": meta["created_at"],
                        "total_scans": meta.get("total_scans", 0),
                        "last_used_at": meta.get("last_used_at")})
    return result
