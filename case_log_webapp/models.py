import hashlib
import hmac

from case_log import (
    SCHEMA_VERSION,
    calculate_case_root,
    calculate_event_signature,
    encode_payload,
    get_hmac_key,
    timestamp_pair,
)

from .config import (
    AUDIT_HASH_FIELDS,
    CASE_HASH_FIELDS,
    CASE_ROLES,
    MAX_FIELD_LENGTH,
    ORG_PERMISSIONS,
    ORG_ROLES,
    ORGANIZATION_HASH_FIELDS,
    SYSTEM_ROLES,
    WEB_HASH_FIELDS,
)
from .crypto import hash_secret, is_valid_pin, sign_hash, sign_payload, verify_secret


def clean_field(value, limit=MAX_FIELD_LENGTH):
    return value.replace("\x00", "").strip()[:limit]


def is_valid_username(username):
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

    return 3 <= len(username) <= 64 and all(character in allowed for character in username)


def has_users(connection):
    return connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"] > 0


def ensure_migrated_defaults(connection):
    if not has_users(connection):
        return

    org_count = connection.execute("SELECT COUNT(*) AS count FROM organizations").fetchone()["count"]

    if org_count == 0:
        first_user = connection.execute("SELECT * FROM users ORDER BY id LIMIT 1").fetchone()
        created_by = first_user["username"] if first_user else "system"
        org_id = create_organization(connection, "Default Organization", "Migrated organization.", created_by)
    else:
        org_id = connection.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()["id"]

    connection.execute("UPDATE cases SET organization_id = ? WHERE organization_id IS NULL OR organization_id = 1", (org_id,))
    connection.execute("UPDATE events SET organization_id = ? WHERE organization_id IS NULL OR organization_id = 1", (org_id,))

    for admin in connection.execute("SELECT * FROM users WHERE system_role = 'system_admin' AND active = 1"):
        grant_organization_access(connection, org_id, admin["id"], "owner", "system")

    for case_row in connection.execute("SELECT id FROM cases WHERE organization_id = ?", (org_id,)):
        for admin in connection.execute("SELECT * FROM users WHERE system_role = 'system_admin' AND active = 1"):
            grant_case_access(connection, case_row["id"], admin["id"], "owner", "system")

    rebuild_all_case_hashes(connection)
    rebuild_all_event_chains(connection)
    connection.commit()


def create_user(connection, username, pin, system_role="user", display_name=""):
    if not is_valid_username(username):
        raise ValueError("Username must use 3-64 letters, numbers, dots, dashes or underscores.")

    if not is_valid_pin(pin):
        raise ValueError("PIN must be exactly 4 digits.")

    if system_role not in SYSTEM_ROLES:
        raise ValueError("Unsupported system role.")

    created_at, created_at_unix = timestamp_pair()
    salt, pin_hash = hash_secret(pin)
    cursor = connection.execute(
        """
        INSERT INTO users (
            username, password_hash, salt, role, system_role, active, created_at, created_at_unix
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (username, pin_hash, salt, "admin" if system_role == "system_admin" else "user", system_role, created_at, created_at_unix),
    )
    user_id = cursor.lastrowid
    connection.execute(
        "INSERT INTO profiles (user_id, display_name) VALUES (?, ?)",
        (user_id, clean_field(display_name, 120) or username),
    )

    return user_id


def set_user_pin(connection, username, pin):
    if not is_valid_pin(pin):
        raise ValueError("PIN must be exactly 4 digits.")

    salt, pin_hash = hash_secret(pin)
    cursor = connection.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE username = ? AND active = 1",
        (pin_hash, salt, username),
    )

    if cursor.rowcount == 0:
        raise ValueError("Unknown active user.")


def verify_login(connection, username, pin):
    user = connection.execute(
        "SELECT * FROM users WHERE username = ? AND active = 1",
        (username,),
    ).fetchone()

    if not user or not verify_secret(pin, user["salt"], user["password_hash"]):
        return None

    last_login_at, last_login_at_unix = timestamp_pair()
    connection.execute(
        "UPDATE users SET last_login_at = ?, last_login_at_unix = ? WHERE id = ?",
        (last_login_at, last_login_at_unix, user["id"]),
    )

    return connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()


def update_profile(connection, user_id, form):
    connection.execute(
        """
        UPDATE profiles
        SET display_name = ?, avatar_url = ?, title = ?, bio = ?
        WHERE user_id = ?
        """,
        (
            clean_field(form.get("display_name", ""), 120),
            clean_field(form.get("avatar_url", ""), 500),
            clean_field(form.get("title", ""), 120),
            clean_field(form.get("bio", ""), 1_000),
            user_id,
        ),
    )


def canonical_record(record, fields):
    return {field: record.get(field, "") for field in fields}


def calculate_organization_hash(organization):
    return hashlib.sha256(
        encode_payload({"organization": canonical_record(organization, ORGANIZATION_HASH_FIELDS)})
    ).hexdigest()


def calculate_case_hash(case_record):
    return hashlib.sha256(
        encode_payload({"case": canonical_record(case_record, CASE_HASH_FIELDS)})
    ).hexdigest()


def calculate_web_event_hash(event, previous_hash):
    return hashlib.sha256(
        encode_payload({"event": canonical_record(event, WEB_HASH_FIELDS), "previous_hash": previous_hash})
    ).hexdigest()


def calculate_audit_hash(entry, previous_hash):
    return hashlib.sha256(
        encode_payload({"audit": canonical_record(entry, AUDIT_HASH_FIELDS), "previous_hash": previous_hash})
    ).hexdigest()


def create_organization(connection, name, description, created_by):
    created_at, created_at_unix = timestamp_pair()
    organization = {
        "name": clean_field(name, 200) or "Untitled Organization",
        "description": clean_field(description, 2_000),
        "created_by": created_by,
        "created_at": created_at,
        "created_at_unix": created_at_unix,
    }
    org_hash = calculate_organization_hash(organization)
    signature = sign_payload({"organization_hash": org_hash})
    cursor = connection.execute(
        """
        INSERT INTO organizations (name, description, created_by, created_at, created_at_unix, hash, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            organization["name"],
            organization["description"],
            organization["created_by"],
            organization["created_at"],
            organization["created_at_unix"],
            org_hash,
            signature,
        ),
    )

    return cursor.lastrowid


def grant_organization_access(connection, organization_id, user_id, role, added_by):
    if role not in ORG_ROLES:
        raise ValueError("Unsupported organization role.")

    added_at, added_at_unix = timestamp_pair()
    connection.execute(
        """
        INSERT INTO organization_members (
            organization_id, user_id, role, added_at, added_at_unix, added_by
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(organization_id, user_id) DO UPDATE SET role = excluded.role
        """,
        (organization_id, user_id, role, added_at, added_at_unix, added_by),
    )


def get_org_role(connection, user, organization_id):
    if user.get("system_role") == "system_admin":
        return "owner"

    row = connection.execute(
        "SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?",
        (organization_id, user.get("user_id")),
    ).fetchone()

    return row["role"] if row else ""


def has_org_permission(connection, user, organization_id, permission):
    role = get_org_role(connection, user, organization_id)

    return permission in ORG_PERMISSIONS.get(role, set())


def list_accessible_organizations(connection, user):
    if user.get("system_role") == "system_admin":
        return connection.execute("SELECT * FROM organizations ORDER BY created_at_unix DESC, id DESC").fetchall()

    return connection.execute(
        """
        SELECT organizations.*
        FROM organizations
        JOIN organization_members ON organization_members.organization_id = organizations.id
        WHERE organization_members.user_id = ?
        ORDER BY organizations.created_at_unix DESC, organizations.id DESC
        """,
        (user.get("user_id"),),
    ).fetchall()


def get_accessible_organization(connection, user, organization_id):
    if organization_id:
        row = connection.execute("SELECT * FROM organizations WHERE id = ?", (organization_id,)).fetchone()

        if row and get_org_role(connection, user, row["id"]):
            return row

    organizations = list_accessible_organizations(connection, user)

    return organizations[0] if organizations else None


def create_case(connection, organization_id, title, description, created_by):
    created_at, created_at_unix = timestamp_pair()
    case_record = {
        "organization_id": organization_id,
        "title": clean_field(title, 240) or "Untitled Case",
        "description": clean_field(description, 2_000),
        "created_by": created_by,
        "created_at": created_at,
        "created_at_unix": created_at_unix,
    }
    case_hash = calculate_case_hash(case_record)
    signature = sign_payload({"case_hash": case_hash})
    cursor = connection.execute(
        """
        INSERT INTO cases (
            organization_id, title, description, created_by, created_at, created_at_unix, hash, signature
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_record["organization_id"],
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
    if role not in CASE_ROLES:
        raise ValueError("Unsupported case role.")

    added_at, added_at_unix = timestamp_pair()
    connection.execute(
        """
        INSERT INTO case_members (case_id, user_id, role, added_at, added_at_unix, added_by)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(case_id, user_id) DO UPDATE SET role = excluded.role
        """,
        (case_id, user_id, role, added_at, added_at_unix, added_by),
    )


def user_can_access_case(connection, user, case_id, permission="cases.read"):
    case_row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()

    if not case_row:
        return False

    if has_org_permission(connection, user, case_row["organization_id"], permission):
        return True

    if permission != "cases.read":
        return False

    row = connection.execute(
        "SELECT 1 FROM case_members WHERE case_id = ? AND user_id = ?",
        (case_id, user.get("user_id")),
    ).fetchone()

    return bool(row)


def list_accessible_cases(connection, user, organization_id):
    if has_org_permission(connection, user, organization_id, "cases.read"):
        return connection.execute(
            "SELECT * FROM cases WHERE organization_id = ? ORDER BY created_at_unix DESC, id DESC",
            (organization_id,),
        ).fetchall()

    return connection.execute(
        """
        SELECT cases.*
        FROM cases
        JOIN case_members ON case_members.case_id = cases.id
        WHERE cases.organization_id = ? AND case_members.user_id = ?
        ORDER BY cases.created_at_unix DESC, cases.id DESC
        """,
        (organization_id, user.get("user_id")),
    ).fetchall()


def get_accessible_case(connection, user, organization_id, case_id):
    if case_id:
        row = connection.execute(
            "SELECT * FROM cases WHERE id = ? AND organization_id = ?",
            (case_id, organization_id),
        ).fetchone()

        if row and user_can_access_case(connection, user, row["id"]):
            return row

    cases = list_accessible_cases(connection, user, organization_id)

    return cases[0] if cases else None


def latest_value(connection, table, column, default):
    if (table, column) not in {("events", "sequence"), ("audit_log", "hash"), ("audit_log", "sequence")}:
        raise ValueError("Unsupported lookup")

    row = connection.execute(
        f"SELECT {column} FROM {table} ORDER BY sequence DESC LIMIT 1"
    ).fetchone()

    return row[column] if row else default


def latest_case_event_hash(connection, case_id):
    row = connection.execute(
        "SELECT hash FROM events WHERE case_id = ? ORDER BY sequence DESC LIMIT 1",
        (case_id,),
    ).fetchone()

    return row["hash"] if row else ""


def append_audit(connection, actor, action, object_type, object_hash, details):
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
    signature = sign_hash(previous_hash, entry_hash)
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


def add_event(connection, form, user, organization_id, case_id):
    if not user_can_access_case(connection, user, case_id, "cases.write"):
        raise PermissionError("No write access to case")

    previous_hash = latest_case_event_hash(connection, case_id)
    sequence = latest_value(connection, "events", "sequence", 0) + 1
    timestamp, timestamp_unix = timestamp_pair(form.get("timestamp", ""))
    recorded_at, recorded_at_unix = timestamp_pair()
    event = {
        "organization_id": organization_id,
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
        get_hmac_key(),
    )
    connection.execute(
        """
        INSERT INTO events (
            organization_id, case_id, schema_version, sequence, timestamp, timestamp_unix,
            recorded_at, recorded_at_unix, title, category, people, note, recorded_by,
            previous_hash, hash, signature
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["organization_id"],
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
    append_audit(connection, user["username"], "event.add", "event", event_hash, event["title"])


def rebuild_all_case_hashes(connection):
    for row in connection.execute("SELECT * FROM cases ORDER BY id"):
        case_record = dict(row)
        case_hash = calculate_case_hash(case_record)
        signature = sign_payload({"case_hash": case_hash})
        connection.execute(
            "UPDATE cases SET hash = ?, signature = ? WHERE id = ?",
            (case_hash, signature, case_record["id"]),
        )


def rebuild_all_event_chains(connection):
    for case_row in connection.execute("SELECT id FROM cases ORDER BY id"):
        previous_hash = ""

        for row in connection.execute(
            "SELECT * FROM events WHERE case_id = ? ORDER BY sequence, id",
            (case_row["id"],),
        ):
            event = dict(row)
            event_hash = calculate_web_event_hash(event, previous_hash)
            signature = calculate_event_signature(
                {"hash": event_hash, "previous_hash": previous_hash},
                get_hmac_key(),
            )
            connection.execute(
                "UPDATE events SET previous_hash = ?, hash = ?, signature = ? WHERE id = ?",
                (previous_hash, event_hash, signature, event["id"]),
            )
            previous_hash = event_hash


def award_badge(connection, user_id, code, awarded_by):
    badge = connection.execute("SELECT * FROM badges WHERE code = ?", (code,)).fetchone()

    if not badge:
        return

    awarded_at, awarded_at_unix = timestamp_pair()
    connection.execute(
        """
        INSERT OR IGNORE INTO user_badges (user_id, badge_id, awarded_at, awarded_at_unix, awarded_by)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, badge["id"], awarded_at, awarded_at_unix, awarded_by),
    )


def verify_database(connection):
    errors = []
    hmac_key = get_hmac_key()

    for row in connection.execute("SELECT * FROM organizations ORDER BY id"):
        organization = dict(row)
        expected_hash = calculate_organization_hash(organization)
        expected_signature = sign_payload({"organization_hash": expected_hash}) if hmac_key else ""

        if organization["hash"] != expected_hash:
            errors.append(f"Organization #{organization['id']}: hash mismatch")

        if hmac_key and not hmac.compare_digest(organization["signature"], expected_signature):
            errors.append(f"Organization #{organization['id']}: signature mismatch")

    for row in connection.execute("SELECT * FROM cases ORDER BY id"):
        case_record = dict(row)
        expected_hash = calculate_case_hash(case_record)
        expected_signature = sign_payload({"case_hash": expected_hash}) if hmac_key else ""

        if case_record["hash"] != expected_hash:
            errors.append(f"Case #{case_record['id']}: hash mismatch")

        if hmac_key and not hmac.compare_digest(case_record["signature"], expected_signature):
            errors.append(f"Case #{case_record['id']}: signature mismatch")

    for case_row in connection.execute("SELECT id FROM cases ORDER BY id"):
        previous_hash = ""

        for row in connection.execute(
            "SELECT * FROM events WHERE case_id = ? ORDER BY sequence",
            (case_row["id"],),
        ):
            event = dict(row)
            expected_hash = calculate_web_event_hash(event, previous_hash)

            if event["previous_hash"] != previous_hash:
                errors.append(f"Case #{case_row['id']} event #{event['sequence']}: previous_hash mismatch")

            if event["hash"] != expected_hash:
                errors.append(f"Case #{case_row['id']} event #{event['sequence']}: hash mismatch")

            if hmac_key:
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

        previous_hash = entry["hash"]

    return errors


def case_root_for(connection, case_id):
    events = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM events WHERE case_id = ? ORDER BY sequence",
            (case_id,),
        )
    ]

    return calculate_case_root(events), events
