import sqlite3

from case_log import DATA_DIR

from .config import DB_FILE


def connect_db():
    DATA_DIR.mkdir(exist_ok=True)
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def table_columns(connection, table):
    return {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def add_column(connection, table, definition):
    column = definition.split()[0]

    if column not in table_columns(connection, table):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


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

        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            display_name TEXT NOT NULL DEFAULT '',
            avatar_url TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            bio TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domain TEXT NOT NULL DEFAULT 'foster_care',
            description TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS organization_members (
            organization_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            added_at TEXT NOT NULL,
            added_at_unix INTEGER NOT NULL,
            added_by TEXT NOT NULL,
            PRIMARY KEY (organization_id, user_id),
            FOREIGN KEY (organization_id) REFERENCES organizations(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS user_badges (
            user_id INTEGER NOT NULL,
            badge_id INTEGER NOT NULL,
            awarded_at TEXT NOT NULL,
            awarded_at_unix INTEGER NOT NULL,
            awarded_by TEXT NOT NULL,
            PRIMARY KEY (user_id, badge_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (badge_id) REFERENCES badges(id)
        );

        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL DEFAULT 1,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            subject_name TEXT NOT NULL DEFAULT '',
            subject_identifier TEXT NOT NULL DEFAULT '',
            subject_birthdate TEXT NOT NULL DEFAULT '',
            agency TEXT NOT NULL DEFAULT '',
            case_worker TEXT NOT NULL DEFAULT '',
            guardian TEXT NOT NULL DEFAULT '',
            court_reference TEXT NOT NULL DEFAULT '',
            school_or_daycare TEXT NOT NULL DEFAULT '',
            medical_contacts TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
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
            organization_id INTEGER NOT NULL DEFAULT 1,
            case_id INTEGER NOT NULL DEFAULT 1,
            event_type TEXT NOT NULL DEFAULT 'general',
            priority TEXT NOT NULL DEFAULT 'normal',
            schema_version INTEGER NOT NULL,
            sequence INTEGER NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            timestamp_unix INTEGER NOT NULL,
            recorded_at TEXT NOT NULL,
            recorded_at_unix INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            people TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',
            quote TEXT NOT NULL DEFAULT '',
            observation TEXT NOT NULL DEFAULT '',
            assessment TEXT NOT NULL DEFAULT '',
            action_taken TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL,
            recorded_by TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id),
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
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

        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            added_at TEXT NOT NULL,
            added_at_unix INTEGER NOT NULL,
            added_by TEXT NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events(id)
        );

        CREATE TABLE IF NOT EXISTS event_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            prompt TEXT NOT NULL DEFAULT ''
        );
        """
    )
    migrate_schema(connection)
    connection.commit()


def migrate_schema(connection):
    add_column(connection, "users", "system_role TEXT NOT NULL DEFAULT 'user'")
    add_column(connection, "users", "last_login_at TEXT NOT NULL DEFAULT ''")
    add_column(connection, "users", "last_login_at_unix INTEGER NOT NULL DEFAULT 0")
    add_column(connection, "organizations", "domain TEXT NOT NULL DEFAULT 'foster_care'")
    add_column(connection, "cases", "organization_id INTEGER NOT NULL DEFAULT 1")
    add_column(connection, "cases", "subject_name TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "subject_identifier TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "subject_birthdate TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "agency TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "case_worker TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "guardian TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "court_reference TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "school_or_daycare TEXT NOT NULL DEFAULT ''")
    add_column(connection, "cases", "medical_contacts TEXT NOT NULL DEFAULT ''")
    add_column(connection, "events", "organization_id INTEGER NOT NULL DEFAULT 1")
    add_column(connection, "events", "case_id INTEGER NOT NULL DEFAULT 1")
    add_column(connection, "events", "event_type TEXT NOT NULL DEFAULT 'general'")
    add_column(connection, "events", "priority TEXT NOT NULL DEFAULT 'normal'")
    add_column(connection, "events", "location TEXT NOT NULL DEFAULT ''")
    add_column(connection, "events", "quote TEXT NOT NULL DEFAULT ''")
    add_column(connection, "events", "observation TEXT NOT NULL DEFAULT ''")
    add_column(connection, "events", "assessment TEXT NOT NULL DEFAULT ''")
    add_column(connection, "events", "action_taken TEXT NOT NULL DEFAULT ''")

    connection.execute("UPDATE users SET system_role = 'system_admin' WHERE role = 'admin'")
    connection.execute("UPDATE users SET system_role = 'user' WHERE system_role = ''")

    for user in connection.execute("SELECT id, username FROM users"):
        connection.execute(
            "INSERT OR IGNORE INTO profiles (user_id, display_name) VALUES (?, ?)",
            (user["id"], user["username"]),
        )

    seed_badges(connection)
    seed_templates(connection)


def seed_badges(connection):
    badges = (
        ("first_case", "First Case", "Created the first case in an organization."),
        ("chain_keeper", "Chain Keeper", "Verified an integrity chain."),
        ("case_scribe", "Case Scribe", "Added structured case entries."),
        ("org_admin", "Organization Admin", "Manages users and cases for an organization."),
    )

    for code, label, description in badges:
        connection.execute(
            "INSERT OR IGNORE INTO badges (code, label, description) VALUES (?, ?, ?)",
            (code, label, description),
        )


def seed_templates(connection):
    templates = (
        ("foster_care", "contact", "Umgangskontakt dokumentieren", "Wer war beteiligt? Beginn/Ende? Übergabe? Verhalten davor und danach?"),
        ("foster_care", "medical", "Medizinischer Termin", "Anlass, Diagnose/Empfehlung, Unterlagen, nächste Schritte."),
        ("foster_care", "crisis", "Krise oder Schutzereignis", "Auslöser, Verlauf, Maßnahmen, Zeugen, Information an Stellen."),
        ("foster_care", "youth_office", "Jugendamt / Hilfeplanung", "Teilnehmende, Zusagen, Fristen, offene Punkte."),
        ("foster_care", "behavior", "Beobachtung", "Fakt, Beobachtung, Einschätzung und Maßnahme getrennt notieren."),
    )

    for domain, event_type, title, prompt in templates:
        connection.execute(
            """
            INSERT OR IGNORE INTO event_templates (domain, event_type, title, prompt)
            VALUES (?, ?, ?, ?)
            """,
            (domain, event_type, title, prompt),
        )
