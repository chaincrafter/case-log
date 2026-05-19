from case_log import DATA_DIR

DB_FILE = DATA_DIR / "case-log.sqlite3"
SESSION_COOKIE = "case_log_session"
SESSION_TTL_HOURS = 8
PASSWORD_ITERATIONS = 240_000
PIN_LENGTH = 4
MAX_FORM_BYTES = 32_768
MAX_FIELD_LENGTH = 10_000
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 8
LOGIN_ATTEMPTS = {}

SYSTEM_ROLES = ("system_admin", "user")
ORG_ROLES = ("owner", "admin", "case_manager", "analyst", "viewer")
CASE_ROLES = ("owner", "member", "viewer")

ORG_PERMISSIONS = {
    "owner": {"org.manage", "users.manage", "cases.manage", "cases.write", "cases.read"},
    "admin": {"users.manage", "cases.manage", "cases.write", "cases.read"},
    "case_manager": {"cases.manage", "cases.write", "cases.read"},
    "analyst": {"cases.write", "cases.read"},
    "viewer": {"cases.read"},
}

WEB_HASH_FIELDS = (
    "organization_id",
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
    "organization_id",
    "title",
    "description",
    "created_by",
    "created_at",
    "created_at_unix",
)

ORGANIZATION_HASH_FIELDS = (
    "name",
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
