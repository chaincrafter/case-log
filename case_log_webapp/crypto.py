import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta
from http.cookies import SimpleCookie

from case_log import create_hmac_key, encode_payload, get_hmac_key

from .config import (
    LOGIN_ATTEMPTS,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW_SECONDS,
    PASSWORD_ITERATIONS,
    PIN_LENGTH,
    SESSION_COOKIE,
    SESSION_TTL_HOURS,
)


def hash_secret(secret, salt_hex=""):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return salt.hex(), digest.hex()


def verify_secret(secret, salt, secret_hash):
    _salt, candidate = hash_secret(secret, salt)

    return hmac.compare_digest(candidate, secret_hash)


def is_valid_pin(pin):
    return len(pin) == PIN_LENGTH and pin.isdigit()


def sign_payload(payload):
    hmac_key = get_hmac_key() or create_hmac_key()

    return hmac.new(hmac_key.encode("utf-8"), encode_payload(payload), hashlib.sha256).hexdigest()


def sign_hash(previous_hash, item_hash):
    return sign_payload({"hash": item_hash, "previous_hash": previous_hash})


def session_signature(payload, hmac_key):
    return hmac.new(hmac_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session(user):
    hmac_key = get_hmac_key() or create_hmac_key()
    payload = json.dumps(
        {
            "user_id": user["id"],
            "username": user["username"],
            "system_role": user["system_role"],
            "exp": int((datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)).timestamp()),
            "csrf": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(16),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")
    signature = session_signature(encoded, hmac_key)

    return f"{encoded}.{signature}"


def read_session(cookie_header):
    if not cookie_header:
        return None

    cookies = SimpleCookie(cookie_header)
    morsel = cookies.get(SESSION_COOKIE)

    if not morsel or "." not in morsel.value:
        return None

    encoded, signature = morsel.value.rsplit(".", 1)
    hmac_key = get_hmac_key()

    if not hmac_key or not hmac.compare_digest(session_signature(encoded, hmac_key), signature):
        return None

    try:
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None

    if payload.get("exp", 0) < int(datetime.utcnow().timestamp()):
        return None

    return payload


def login_allowed(identifier, attempts):
    now = time.monotonic()
    recent = [
        attempt for attempt in attempts.get(identifier, [])
        if now - attempt < LOGIN_WINDOW_SECONDS
    ]
    attempts[identifier] = recent

    return len(recent) < LOGIN_MAX_ATTEMPTS


def record_login_failure(identifier, attempts):
    attempts.setdefault(identifier, []).append(time.monotonic())


def clear_login_failures(identifier, attempts):
    attempts.pop(identifier, None)
