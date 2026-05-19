#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from case_log import (
    DATA_DIR,
    HMAC_KEY_FILE,
    HMAC_KEY_ENV,
    SCHEMA_VERSION,
    calculate_case_root,
    calculate_event_signature,
    create_hmac_key,
    encode_payload,
    get_hmac_key,
    timestamp_pair,
)

DB_FILE = DATA_DIR / "case-log.sqlite3"
SESSION_COOKIE = "case_log_session"
SESSION_TTL_HOURS = 8
PASSWORD_ITERATIONS = 240_000
MAX_FORM_BYTES = 32_768
MAX_FIELD_LENGTH = 10_000
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 8
LOGIN_ATTEMPTS = {}
ALLOWED_LATEST_LOOKUPS = {
    ("events", "sequence"),
    ("audit_log", "hash"),
    ("audit_log", "sequence"),
}
WEB_HASH_FIELDS = (
    "case_id",
    "schema_version",
    "sequence",
    "timestamp",
    "timestamp_unix",
    "recorded_at",
    "recorded_at_unix",
    "title",
    "category",
    "people",
    "note",
    "recorded_by",
)
CASE_HASH_FIELDS = (
    "title",
    "description",
    "created_by",
    "created_at",
    "created_at_unix",
)
AUDIT_HASH_FIELDS = (
    "sequence",
    "recorded_at",
    "recorded_at_unix",
    "actor",
    "action",
    "object_type",
    "object_hash",
    "details",
)


def connect_db():
    DATA_DIR.mkdir(exist_ok=True)
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def init_schema(connection):
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS case_members (
            case_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            added_at TEXT NOT NULL,
            added_at_unix INTEGER NOT NULL,
            added_by TEXT NOT NULL,
            PRIMARY KEY (case_id, user_id),
            FOREIGN KEY (case_id) REFERENCES cases(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL DEFAULT 1,
            schema_version INTEGER NOT NULL,
            sequence INTEGER NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            timestamp_unix INTEGER NOT NULL,
            recorded_at TEXT NOT NULL,
            recorded_at_unix INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            people TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL,
            recorded_by TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sequence INTEGER NOT NULL UNIQUE,
            recorded_at TEXT NOT NULL,
            recorded_at_unix INTEGER NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_hash TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL
        );
        """
    )
    migrate_schema(connection)
    connection.commit()


def table_columns(connection, table):
    return {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def migrate_schema(connection):
    event_columns = table_columns(connection, "events")
    added_case_id = "case_id" not in event_columns

    if added_case_id:
        connection.execute("ALTER TABLE events ADD COLUMN case_id INTEGER NOT NULL DEFAULT 1")

    ensure_default_case(connection)

    if added_case_id:
        for case_row in connection.execute("SELECT id FROM cases"):
            rebuild_event_chain(connection, case_row["id"])


def canonical_case(case_record):
    return {field: case_record.get(field, "") for field in CASE_HASH_FIELDS}


def calculate_case_record_hash(case_record):
    return hashlib.sha256(encode_payload({"case": canonical_case(case_record)})).hexdigest()


def calculate_case_signature(case_hash, hmac_key):
    return hmac.new(
        hmac_key.encode("utf-8"),
        encode_payload({"case_hash": case_hash}),
        hashlib.sha256,
    ).hexdigest()


def ensure_default_case(connection):
    case_count = connection.execute("SELECT COUNT(*) AS count FROM cases").fetchone()["count"]

    if case_count:
        return

    user = connection.execute("SELECT * FROM users ORDER BY id LIMIT 1").fetchone()
    created_by = user["username"] if user else "system"
    case_id = create_case(connection, "Default Case", "Migrated default case.", created_by)

    if user:
        grant_case_access(connection, case_id, user["id"], "owner", created_by)

    connection.execute("UPDATE events SET case_id = ? WHERE case_id IS NULL OR case_id = 1", (case_id,))


def hash_password(password, salt_hex=""):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return salt.hex(), digest.hex()


def create_user(connection, username, password, role="user"):
    if not is_valid_username(username):
        raise ValueError("Username must use 3-64 letters, numbers, dots, dashes or underscores.")

    if not is_strong_password(password):
        raise ValueError("Password must be at least 12 characters long.")

    created_at, created_at_unix = timestamp_pair()
    salt, password_hash = hash_password(password)
    connection.execute(
        """
        INSERT INTO users (username, password_hash, salt, role, created_at, created_at_unix)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (username, password_hash, salt, role, created_at, created_at_unix),
    )
    connection.commit()


def verify_password(password, salt, password_hash):
    _salt, candidate = hash_password(password, salt)

    return hmac.compare_digest(candidate, password_hash)


def is_valid_username(username):
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

    return 3 <= len(username) <= 64 and all(character in allowed for character in username)


def is_strong_password(password):
    return len(password) >= 12


def clean_field(value, limit=MAX_FIELD_LENGTH):
    return value.replace("\x00", "").strip()[:limit]


def create_case(connection, title, description, created_by):
    hmac_key = get_hmac_key() or create_hmac_key()
    created_at, created_at_unix = timestamp_pair()
    case_record = {
        "title": clean_field(title, 240) or "Untitled Case",
        "description": clean_field(description, 2_000),
        "created_by": created_by,
        "created_at": created_at,
        "created_at_unix": created_at_unix,
    }
    case_hash = calculate_case_record_hash(case_record)
    signature = calculate_case_signature(case_hash, hmac_key)
    cursor = connection.execute(
        """
        INSERT INTO cases (title, description, created_by, created_at, created_at_unix, hash, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_record["title"],
            case_record["description"],
            case_record["created_by"],
            case_record["created_at"],
            case_record["created_at_unix"],
            case_hash,
            signature,
        ),
    )

    return cursor.lastrowid


def grant_case_access(connection, case_id, user_id, role, added_by):
    added_at, added_at_unix = timestamp_pair()
    connection.execute(
        """
        INSERT OR IGNORE INTO case_members (case_id, user_id, role, added_at, added_at_unix, added_by)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (case_id, user_id, role, added_at, added_at_unix, added_by),
    )


def user_can_access_case(connection, user, case_id):
    if user.get("role") == "admin":
        return True

    row = connection.execute(
        "SELECT 1 FROM case_members WHERE case_id = ? AND user_id = ?",
        (case_id, user.get("user_id")),
    ).fetchone()

    return bool(row)


def list_accessible_cases(connection, user):
    if user.get("role") == "admin":
        return connection.execute("SELECT * FROM cases ORDER BY created_at_unix DESC, id DESC").fetchall()

    return connection.execute(
        """
        SELECT cases.*
        FROM cases
        JOIN case_members ON case_members.case_id = cases.id
        WHERE case_members.user_id = ?
        ORDER BY cases.created_at_unix DESC, cases.id DESC
        """,
        (user.get("user_id"),),
    ).fetchall()


def get_accessible_case(connection, user, case_id):
    if case_id:
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()

        if row and user_can_access_case(connection, user, row["id"]):
            return row

    cases = list_accessible_cases(connection, user)

    if cases:
        return cases[0]

    return None


def canonical_event(event):
    return {field: event.get(field, "") for field in WEB_HASH_FIELDS}


def calculate_web_event_hash(event, previous_hash):
    return hashlib.sha256(
        encode_payload({"event": canonical_event(event), "previous_hash": previous_hash})
    ).hexdigest()


def canonical_audit(entry):
    return {field: entry.get(field, "") for field in AUDIT_HASH_FIELDS}


def calculate_audit_hash(entry, previous_hash):
    return hashlib.sha256(
        encode_payload({"audit": canonical_audit(entry), "previous_hash": previous_hash})
    ).hexdigest()


def sign_hash(previous_hash, item_hash, hmac_key):
    return hmac.new(
        hmac_key.encode("utf-8"),
        encode_payload({"hash": item_hash, "previous_hash": previous_hash}),
        hashlib.sha256,
    ).hexdigest()


def latest_value(connection, table, column, default):
    if (table, column) not in ALLOWED_LATEST_LOOKUPS:
        raise ValueError("Unsupported lookup")

    row = connection.execute(
        f"SELECT {column} FROM {table} ORDER BY sequence DESC LIMIT 1"
    ).fetchone()

    if not row:
        return default

    return row[column]


def latest_event_value(connection, case_id, column, default):
    if column not in {"hash", "sequence"}:
        raise ValueError("Unsupported event lookup")

    row = connection.execute(
        f"SELECT {column} FROM events WHERE case_id = ? ORDER BY sequence DESC LIMIT 1",
        (case_id,),
    ).fetchone()

    if not row:
        return default

    return row[column]


def append_audit(connection, actor, action, object_type, object_hash, details):
    hmac_key = get_hmac_key() or create_hmac_key()
    previous_hash = latest_value(connection, "audit_log", "hash", "")
    sequence = latest_value(connection, "audit_log", "sequence", 0) + 1
    recorded_at, recorded_at_unix = timestamp_pair()
    entry = {
        "sequence": sequence,
        "recorded_at": recorded_at,
        "recorded_at_unix": recorded_at_unix,
        "actor": actor,
        "action": action,
        "object_type": object_type,
        "object_hash": object_hash,
        "details": details,
    }
    entry_hash = calculate_audit_hash(entry, previous_hash)
    signature = sign_hash(previous_hash, entry_hash, hmac_key)

    connection.execute(
        """
        INSERT INTO audit_log (
            sequence, recorded_at, recorded_at_unix, actor, action, object_type,
            object_hash, details, previous_hash, hash, signature
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sequence,
            recorded_at,
            recorded_at_unix,
            actor,
            action,
            object_type,
            object_hash,
            details,
            previous_hash,
            entry_hash,
            signature,
        ),
    )


def add_event(connection, form, user, case_id):
    if not user_can_access_case(connection, user, case_id):
        raise PermissionError("No access to case")

    hmac_key = get_hmac_key() or create_hmac_key()
    previous_hash = latest_event_value(connection, case_id, "hash", "")
    sequence = latest_value(connection, "events", "sequence", 0) + 1
    timestamp, timestamp_unix = timestamp_pair(form.get("timestamp", ""))
    recorded_at, recorded_at_unix = timestamp_pair()
    event = {
        "case_id": case_id,
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "timestamp": timestamp,
        "timestamp_unix": timestamp_unix,
        "recorded_at": recorded_at,
        "recorded_at_unix": recorded_at_unix,
        "title": clean_field(form.get("title", ""), 240),
        "category": clean_field(form.get("category", "general"), 80) or "general",
        "people": clean_field(form.get("people", ""), 500),
        "note": clean_field(form.get("note", ""), 10_000),
        "recorded_by": user["username"],
    }
    event_hash = calculate_web_event_hash(event, previous_hash)
    signature = calculate_event_signature(
        {"hash": event_hash, "previous_hash": previous_hash},
        hmac_key,
    )

    connection.execute(
        """
        INSERT INTO events (
            case_id, schema_version, sequence, timestamp, timestamp_unix, recorded_at,
            recorded_at_unix, title, category, people, note, recorded_by,
            previous_hash, hash, signature
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["case_id"],
            event["schema_version"],
            event["sequence"],
            event["timestamp"],
            event["timestamp_unix"],
            event["recorded_at"],
            event["recorded_at_unix"],
            event["title"],
            event["category"],
            event["people"],
            event["note"],
            event["recorded_by"],
            previous_hash,
            event_hash,
            signature,
        ),
    )
    append_audit(
        connection,
        user["username"],
        "event.add",
        "event",
        event_hash,
        f"case_id={case_id}; title={event['title']}",
    )
    connection.commit()


def rebuild_event_chain(connection, case_id):
    hmac_key = get_hmac_key() or create_hmac_key()
    previous_hash = ""

    for row in connection.execute(
        "SELECT * FROM events WHERE case_id = ? ORDER BY sequence, id",
        (case_id,),
    ):
        event = dict(row)
        event["case_id"] = case_id
        event_hash = calculate_web_event_hash(event, previous_hash)
        signature = calculate_event_signature(
            {"hash": event_hash, "previous_hash": previous_hash},
            hmac_key,
        )
        connection.execute(
            """
            UPDATE events
            SET previous_hash = ?, hash = ?, signature = ?
            WHERE id = ?
            """,
            (previous_hash, event_hash, signature, event["id"]),
        )
        previous_hash = event_hash


def verify_database(connection):
    errors = []
    hmac_key = get_hmac_key()

    for row in connection.execute("SELECT * FROM cases ORDER BY id"):
        case_record = dict(row)
        expected_hash = calculate_case_record_hash(case_record)

        if case_record["hash"] != expected_hash:
            errors.append(f"Case #{case_record['id']}: hash mismatch")

        if not hmac_key:
            errors.append(f"Case #{case_record['id']}: missing HMAC key")
        else:
            expected_signature = calculate_case_signature(expected_hash, hmac_key)

            if not hmac.compare_digest(case_record["signature"], expected_signature):
                errors.append(f"Case #{case_record['id']}: signature mismatch")

    for case_row in connection.execute("SELECT id, title FROM cases ORDER BY id"):
        previous_hash = ""

        for row in connection.execute(
            "SELECT * FROM events WHERE case_id = ? ORDER BY sequence",
            (case_row["id"],),
        ):
            event = dict(row)
            expected_hash = calculate_web_event_hash(event, previous_hash)

            if event["previous_hash"] != previous_hash:
                errors.append(
                    f"Case #{case_row['id']} event #{event['sequence']}: previous_hash mismatch"
                )

            if event["hash"] != expected_hash:
                errors.append(f"Case #{case_row['id']} event #{event['sequence']}: hash mismatch")

            if not hmac_key:
                errors.append(f"Case #{case_row['id']} event #{event['sequence']}: missing HMAC key")
            else:
                expected_signature = calculate_event_signature(
                    {"hash": expected_hash, "previous_hash": previous_hash},
                    hmac_key,
                )

                if not hmac.compare_digest(event["signature"], expected_signature):
                    errors.append(f"Case #{case_row['id']} event #{event['sequence']}: signature mismatch")

            previous_hash = event["hash"]

    previous_hash = ""

    for row in connection.execute("SELECT * FROM audit_log ORDER BY sequence"):
        entry = dict(row)
        expected_hash = calculate_audit_hash(entry, previous_hash)

        if entry["previous_hash"] != previous_hash:
            errors.append(f"Audit #{entry['sequence']}: previous_hash mismatch")

        if entry["hash"] != expected_hash:
            errors.append(f"Audit #{entry['sequence']}: hash mismatch")

        if not hmac_key:
            errors.append(f"Audit #{entry['sequence']}: missing HMAC key")
        else:
            expected_signature = sign_hash(previous_hash, expected_hash, hmac_key)

            if not hmac.compare_digest(entry["signature"], expected_signature):
                errors.append(f"Audit #{entry['sequence']}: signature mismatch")

        previous_hash = entry["hash"]

    return errors


def session_signature(payload, hmac_key):
    return hmac.new(hmac_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session(user):
    hmac_key = get_hmac_key() or create_hmac_key()
    payload = json.dumps(
        {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
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


def login_allowed(identifier):
    now = time.monotonic()
    attempts = [
        attempt for attempt in LOGIN_ATTEMPTS.get(identifier, [])
        if now - attempt < LOGIN_WINDOW_SECONDS
    ]
    LOGIN_ATTEMPTS[identifier] = attempts

    return len(attempts) < LOGIN_MAX_ATTEMPTS


def record_login_failure(identifier):
    attempts = LOGIN_ATTEMPTS.setdefault(identifier, [])
    attempts.append(time.monotonic())


def clear_login_failures(identifier):
    LOGIN_ATTEMPTS.pop(identifier, None)


def csrf_input(user):
    if not user:
        return ""

    return f"<input type='hidden' name='csrf_token' value='{html.escape(user.get('csrf', ''))}'>"


def case_link(path, case_id):
    return f"{path}?case_id={case_id}" if case_id else path


def page(title, body, user=None):
    user_nav = ""

    if user:
        user_nav = (
            f"<span>{html.escape(user['username'])}</span>"
            "<a href='/logout'>Logout</a>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} - case-log</title>
  <style>
    :root {{ color-scheme: dark; --ink: #d9fff3; --muted: #7da99c; --line: #183d36; --accent: #00ff9c; --accent2: #00b8ff; --ok: #00ff9c; --bad: #ff4d6d; --bg: #030706; --panel: #07110f; --panel2: #0b1714; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Consolas, 'Courier New', monospace; color: var(--ink); background: radial-gradient(circle at top left, #0c221d 0, #030706 34rem); }}
    body::before {{ content: ""; position: fixed; inset: 0; pointer-events: none; background: repeating-linear-gradient(0deg, rgba(255,255,255,0.025), rgba(255,255,255,0.025) 1px, transparent 1px, transparent 4px); opacity: .42; }}
    header {{ position: sticky; top: 0; z-index: 2; display: flex; align-items: center; justify-content: space-between; padding: 14px 22px; border-bottom: 1px solid var(--line); background: rgba(3, 7, 6, .92); backdrop-filter: blur(10px); box-shadow: 0 0 24px rgba(0,255,156,.12); }}
    header strong {{ font-size: 18px; color: var(--accent); text-transform: uppercase; letter-spacing: 0; text-shadow: 0 0 12px rgba(0,255,156,.72); }}
    nav {{ display: flex; gap: 14px; align-items: center; font-size: 14px; }}
    a {{ color: var(--accent); text-decoration: none; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    h1 {{ font-size: 24px; margin: 0 0 18px; color: #ffffff; text-shadow: 0 0 18px rgba(0,184,255,.34); }}
    h1::before {{ content: "> "; color: var(--accent); }}
    h2 {{ font-size: 16px; margin: 24px 0 10px; color: var(--accent2); }}
    form {{ display: grid; gap: 12px; max-width: 760px; }}
    label {{ display: grid; gap: 5px; font-size: 13px; color: var(--muted); }}
    input, textarea {{ width: 100%; padding: 10px 11px; border: 1px solid var(--line); border-radius: 6px; font: inherit; color: var(--ink); background: #020504; outline: none; }}
    input:focus, textarea:focus {{ border-color: var(--accent); box-shadow: 0 0 0 2px rgba(0,255,156,.12), 0 0 18px rgba(0,255,156,.16); }}
    textarea {{ min-height: 120px; resize: vertical; }}
    button {{ width: fit-content; padding: 9px 14px; border: 1px solid rgba(0,255,156,.55); border-radius: 6px; background: linear-gradient(180deg, #00ff9c, #00b875); color: #001b12; font-weight: 700; cursor: pointer; box-shadow: 0 0 20px rgba(0,255,156,.18); }}
    table {{ width: 100%; border-collapse: collapse; background: rgba(7,17,15,.92); border: 1px solid var(--line); box-shadow: 0 0 26px rgba(0,184,255,.08); }}
    th, td {{ padding: 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 14px; }}
    th {{ background: #0d221d; color: var(--accent); }}
    tr:hover td {{ background: rgba(0,255,156,.035); }}
    code {{ font-family: Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; color: #9effd8; }}
    .split {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; align-items: start; }}
    .panel {{ background: linear-gradient(180deg, rgba(11,23,20,.94), rgba(4,10,9,.94)); border: 1px solid var(--line); border-radius: 8px; padding: 18px; box-shadow: 0 0 28px rgba(0,255,156,.08); }}
    .ok {{ color: var(--ok); font-weight: 700; }}
    .bad {{ color: var(--bad); font-weight: 700; }}
    .muted {{ color: var(--muted); }}
    @media (max-width: 800px) {{ .split {{ grid-template-columns: 1fr; }} main {{ padding: 16px; }} table {{ display: block; overflow-x: auto; }} }}
  </style>
</head>
<body>
  <header><strong>case-log</strong><nav><a href="/cases">Cases</a><a href="/">Events</a><a href="/verify">Verify</a><a href="/audit">Audit</a>{user_nav}</nav></header>
  <main>{body}</main>
</body>
</html>"""


class CaseLogHandler(BaseHTTPRequestHandler):
    server_version = "case-log/0.2"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def current_user(self):
        user = read_session(self.headers.get("Cookie"))

        if not user:
            return None

        with connect_db() as connection:
            row = connection.execute(
                "SELECT role, active FROM users WHERE id = ? AND username = ?",
                (user.get("user_id"), user.get("username")),
            ).fetchone()

        if not row or row["active"] != 1:
            return None

        user["role"] = row["role"]

        return user

    def security_headers(self):
        return {
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }

    def send_html(self, status, body, headers=None):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))

        response_headers = self.security_headers()
        response_headers.update(headers or {})

        for key, value in response_headers.items():
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(encoded)

    def send_error(self, code, message=None, explain=None):
        status = HTTPStatus(code)
        body = page(
            status.phrase,
            f"<div class='panel'><h1>{status.phrase}</h1><p class='bad'>{html.escape(message or status.description)}</p></div>",
        )
        self.send_html(status, body)

    def redirect(self, location, headers=None):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)

        response_headers = self.security_headers()
        response_headers.update(headers or {})

        for key, value in response_headers.items():
            self.send_header(key, value)

        self.end_headers()

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0"))

        if length > MAX_FORM_BYTES:
            raise ValueError("Form body too large")

        body = self.rfile.read(length).decode("utf-8")

        return {key: values[0] for key, values in parse_qs(body).items()}

    def verify_csrf(self, user, form):
        token = form.get("csrf_token", "")

        return bool(token) and hmac.compare_digest(token, user.get("csrf", ""))

    def query_case_id(self):
        query = parse_qs(urlparse(self.path).query)
        value = query.get("case_id", [""])[0]

        try:
            return int(value) if value else 0
        except ValueError:
            return 0

    def require_user(self):
        user = self.current_user()

        if not user:
            self.redirect("/login")
            return None

        return user

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/login":
            self.login_page()
            return

        if path == "/logout":
            self.redirect(
                "/login",
                {"Set-Cookie": f"{SESSION_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"},
            )
            return

        user = self.require_user()

        if not user:
            return

        if path == "/":
            self.events_page(user)
        elif path == "/cases":
            self.cases_page(user)
        elif path == "/verify":
            self.verify_page(user)
        elif path == "/audit":
            self.audit_page(user)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/login":
            self.login_post()
            return

        user = self.require_user()

        if not user:
            return

        if path == "/cases":
            try:
                form = self.read_form()
            except ValueError:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return

            if not self.verify_csrf(user, form):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

            if not form.get("title"):
                self.redirect("/cases")
                return

            with connect_db() as connection:
                case_id = create_case(
                    connection,
                    form.get("title", ""),
                    form.get("description", ""),
                    user["username"],
                )
                grant_case_access(connection, case_id, user["user_id"], "owner", user["username"])
                append_audit(
                    connection,
                    user["username"],
                    "case.create",
                    "case",
                    str(case_id),
                    clean_field(form.get("title", ""), 240),
                )
                connection.commit()

            self.redirect(case_link("/", case_id))
            return

        if path == "/events":
            try:
                form = self.read_form()
            except ValueError:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return

            if not self.verify_csrf(user, form):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

            if not form.get("title") or not form.get("note"):
                self.redirect("/")
                return

            try:
                case_id = int(form.get("case_id", "0"))
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return

            with connect_db() as connection:
                try:
                    add_event(connection, form, user, case_id)
                except PermissionError:
                    self.send_error(HTTPStatus.FORBIDDEN)
                    return
                except ValueError:
                    self.send_error(HTTPStatus.BAD_REQUEST)
                    return

            self.redirect(case_link("/", case_id))
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def login_page(self):
        body = """
        <div class="panel">
          <h1>Login</h1>
          <form method="post" action="/login">
            <label>Username<input name="username" autocomplete="username" required></label>
            <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
            <button type="submit">Login</button>
          </form>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Login", body))

    def login_post(self):
        try:
            form = self.read_form()
        except ValueError:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        username = clean_field(form.get("username", ""), 64)
        identifier = f"{self.client_address[0]}:{username}"

        if not login_allowed(identifier):
            self.send_html(
                HTTPStatus.TOO_MANY_REQUESTS,
                page("Login delayed", "<p class='bad'>Too many login attempts. Try again later.</p>"),
            )
            return

        with connect_db() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE username = ? AND active = 1",
                (username,),
            ).fetchone()

            if not user or not verify_password(form.get("password", ""), user["salt"], user["password_hash"]):
                record_login_failure(identifier)
                self.send_html(
                    HTTPStatus.UNAUTHORIZED,
                    page("Login failed", "<p class='bad'>Invalid login.</p>"),
                )
                return

            clear_login_failures(identifier)
            append_audit(connection, user["username"], "user.login", "user", user["username"], "")
            connection.commit()

        cookie = make_session(user)
        self.redirect(
            "/",
            {
                "Set-Cookie": (
                    f"{SESSION_COOKIE}={cookie}; HttpOnly; SameSite=Strict; Path=/; "
                    f"Max-Age={SESSION_TTL_HOURS * 3600}"
                )
            },
        )

    def cases_page(self, user):
        with connect_db() as connection:
            cases = list_accessible_cases(connection, user)
            counts = {
                row["case_id"]: row["count"]
                for row in connection.execute(
                    "SELECT case_id, COUNT(*) AS count FROM events GROUP BY case_id"
                )
            }

        table_rows = "".join(
            "<tr>"
            f"<td><a href='/?case_id={case_row['id']}'>{html.escape(case_row['title'])}</a></td>"
            f"<td>{counts.get(case_row['id'], 0)}</td>"
            f"<td>{html.escape(case_row['created_by'])}</td>"
            f"<td>{html.escape(case_row['created_at'])}</td>"
            f"<td><code>{html.escape(case_row['hash'])}</code></td>"
            "</tr>"
            for case_row in cases
        )
        body = f"""
        <h1>Cases</h1>
        <div class="split">
          <section>
            <table>
              <thead><tr><th>Case</th><th>Entries</th><th>Created by</th><th>Created</th><th>Hash</th></tr></thead>
              <tbody>{table_rows or "<tr><td colspan='5'>No cases available.</td></tr>"}</tbody>
            </table>
          </section>
          <section class="panel">
            <h2>Create Case</h2>
            <form method="post" action="/cases">
              {csrf_input(user)}
              <label>Title<input name="title" required></label>
              <label>Description<textarea name="description"></textarea></label>
              <button type="submit">Create case</button>
            </form>
          </section>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Cases", body, user))

    def events_page(self, user):
        requested_case_id = self.query_case_id()

        with connect_db() as connection:
            active_case = get_accessible_case(connection, user, requested_case_id)

            if not active_case:
                self.redirect("/cases")
                return

            cases = list_accessible_cases(connection, user)
            rows = connection.execute(
                "SELECT * FROM events WHERE case_id = ? ORDER BY sequence",
                (active_case["id"],),
            ).fetchall()

        table_rows = "".join(
            "<tr>"
            f"<td>#{row['sequence']}</td>"
            f"<td>{html.escape(row['timestamp'])}<br><span class='muted'>{row['timestamp_unix']}</span></td>"
            f"<td>{html.escape(row['category'])}</td>"
            f"<td>{html.escape(row['title'])}<br><span class='muted'>{html.escape(row['people'])}</span></td>"
            f"<td>{html.escape(row['recorded_by'])}<br><span class='muted'>{html.escape(row['recorded_at'])}</span></td>"
            f"<td><code>{html.escape(row['hash'])}</code></td>"
            "</tr>"
            for row in rows
        )
        case_options = "".join(
            f"<a href='/?case_id={case_row['id']}'>{html.escape(case_row['title'])}</a>"
            for case_row in cases
        )
        body = f"""
        <h1>{html.escape(active_case['title'])}</h1>
        <p class="muted">{html.escape(active_case['description'])}</p>
        <p class="muted">Cases: {case_options}</p>
        <div class="split">
          <section>
            <table>
              <thead><tr><th>Seq</th><th>Event time</th><th>Category</th><th>Event</th><th>Recorded</th><th>Hash</th></tr></thead>
              <tbody>{table_rows or "<tr><td colspan='6'>No events yet.</td></tr>"}</tbody>
            </table>
          </section>
          <section class="panel">
            <h2>Add Event</h2>
            <form method="post" action="/events">
              {csrf_input(user)}
              <input type="hidden" name="case_id" value="{active_case['id']}">
              <label>Title<input name="title" required></label>
              <label>Category<input name="category" value="general"></label>
              <label>Event time<input name="timestamp" placeholder="2026-05-19T20:30:00+02:00"></label>
              <label>People<input name="people"></label>
              <label>Note<textarea name="note" required></textarea></label>
              <button type="submit">Add event</button>
            </form>
          </section>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Events", body, user))

    def verify_page(self, user):
        requested_case_id = self.query_case_id()

        with connect_db() as connection:
            errors = verify_database(connection)
            active_case = get_accessible_case(connection, user, requested_case_id)

            if not active_case:
                self.redirect("/cases")
                return

            cases = list_accessible_cases(connection, user)
            events = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM events WHERE case_id = ? ORDER BY sequence",
                    (active_case["id"],),
                )
            ]

        root = calculate_case_root(events)
        case_options = " ".join(
            f"<a href='/verify?case_id={case_row['id']}'>{html.escape(case_row['title'])}</a>"
            for case_row in cases
        )
        status = "<p class='ok'>Database integrity and signatures verified.</p>"

        if errors:
            status = "<p class='bad'>Verification failed.</p><ul>" + "".join(
                f"<li>{html.escape(error)}</li>" for error in errors
            ) + "</ul>"

        body = f"""
        <h1>Verify {html.escape(active_case['title'])}</h1>
        <div class="panel">
          {status}
          <p class="muted">Cases: {case_options}</p>
          <p>Event count: {len(events)}</p>
          <p>Case root hash:<br><code>{html.escape(root)}</code></p>
          <p class="muted">For court-facing use, export or record this root hash and submit it to a qualified external timestamp process outside this local app.</p>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Verify", body, user))

    def audit_page(self, user):
        with connect_db() as connection:
            if user.get("role") == "admin":
                rows = connection.execute(
                    "SELECT * FROM audit_log ORDER BY sequence DESC LIMIT 200"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE actor = ? ORDER BY sequence DESC LIMIT 200",
                    (user["username"],),
                ).fetchall()

        table_rows = "".join(
            "<tr>"
            f"<td>#{row['sequence']}</td>"
            f"<td>{html.escape(row['recorded_at'])}</td>"
            f"<td>{html.escape(row['actor'])}</td>"
            f"<td>{html.escape(row['action'])}</td>"
            f"<td>{html.escape(row['object_type'])}</td>"
            f"<td><code>{html.escape(row['hash'])}</code></td>"
            "</tr>"
            for row in rows
        )
        body = f"""
        <h1>Audit Log</h1>
        <table>
          <thead><tr><th>Seq</th><th>Recorded</th><th>Actor</th><th>Action</th><th>Object</th><th>Hash</th></tr></thead>
          <tbody>{table_rows or "<tr><td colspan='6'>No audit entries yet.</td></tr>"}</tbody>
        </table>
        """
        self.send_html(HTTPStatus.OK, page("Audit", body, user))


def command_init_db(args):
    with connect_db() as connection:
        init_schema(connection)
        create_hmac_key()
        user_count = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]

        if user_count == 0:
            if not args.admin_password:
                raise SystemExit("Provide --admin-password for the first admin user.")

            create_user(connection, args.admin_user, args.admin_password, "admin")
            admin = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (args.admin_user,),
            ).fetchone()
            for case_row in connection.execute("SELECT id FROM cases"):
                grant_case_access(connection, case_row["id"], admin["id"], "owner", args.admin_user)
            append_audit(connection, args.admin_user, "user.create", "user", args.admin_user, "admin")
            connection.commit()
            print(f"Created admin user: {args.admin_user}")

        for admin in connection.execute("SELECT * FROM users WHERE role = 'admin' AND active = 1"):
            for case_row in connection.execute("SELECT id FROM cases"):
                grant_case_access(connection, case_row["id"], admin["id"], "owner", "system")
        connection.commit()

    print(f"Database ready: {DB_FILE}")
    print(f"HMAC key: {HMAC_KEY_FILE} or {HMAC_KEY_ENV}")


def command_create_user(args):
    if not args.password:
        raise SystemExit("Provide --password for the new user.")

    with connect_db() as connection:
        init_schema(connection)
        create_user(connection, args.username, args.password, args.role)
        append_audit(
            connection,
            args.created_by,
            "user.create",
            "user",
            args.username,
            args.role,
        )
        connection.commit()

    print(f"Created user: {args.username}")


def command_grant_user(args):
    with connect_db() as connection:
        init_schema(connection)
        user = connection.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (args.username,),
        ).fetchone()
        case_row = connection.execute("SELECT * FROM cases WHERE id = ?", (args.case_id,)).fetchone()

        if not user:
            raise SystemExit(f"Unknown active user: {args.username}")

        if not case_row:
            raise SystemExit(f"Unknown case id: {args.case_id}")

        grant_case_access(connection, args.case_id, user["id"], args.role, args.granted_by)
        append_audit(
            connection,
            args.granted_by,
            "case.grant",
            "case",
            str(args.case_id),
            f"user={args.username}; role={args.role}",
        )
        connection.commit()

    print(f"Granted {args.username} access to case #{args.case_id}")


def command_serve(args):
    with connect_db() as connection:
        init_schema(connection)

    server = ThreadingHTTPServer((args.host, args.port), CaseLogHandler)
    print(f"Serving case-log on http://{args.host}:{args.port}")
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="case-log web interface")
    subparsers = parser.add_subparsers(required=True)

    init_parser = subparsers.add_parser("init-db", help="Initialize the SQLite database")
    init_parser.add_argument("--admin-user", default="admin")
    init_parser.add_argument("--admin-password", default="")
    init_parser.set_defaults(func=command_init_db)

    user_parser = subparsers.add_parser("create-user", help="Create another web user")
    user_parser.add_argument("--username", required=True)
    user_parser.add_argument("--password", required=True)
    user_parser.add_argument("--role", default="user", choices=("admin", "user"))
    user_parser.add_argument("--created-by", default="admin")
    user_parser.set_defaults(func=command_create_user)

    grant_parser = subparsers.add_parser("grant-user", help="Grant a user access to a case")
    grant_parser.add_argument("--case-id", required=True, type=int)
    grant_parser.add_argument("--username", required=True)
    grant_parser.add_argument("--role", default="member", choices=("owner", "member", "viewer"))
    grant_parser.add_argument("--granted-by", default="admin")
    grant_parser.set_defaults(func=command_grant_user)

    serve_parser = subparsers.add_parser("serve", help="Run the local web server")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.set_defaults(func=command_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
