import argparse

from case_log import HMAC_KEY_ENV, HMAC_KEY_FILE, create_hmac_key

from .bootstrap import complete_first_run, first_run_required
from .db import DB_FILE, connect_db, init_schema
from .models import (
    append_audit,
    create_user,
    ensure_migrated_defaults,
    grant_case_access,
    grant_organization_access,
    set_user_pin,
    verify_database,
)
from .server import serve


def command_init_db(args):
    with connect_db() as connection:
        init_schema(connection)
        create_hmac_key()

        if first_run_required(connection):
            if not args.admin_pin:
                print("Database ready. Open /setup in the browser or pass --admin-pin.")
            else:
                complete_first_run(
                    connection,
                    args.organization,
                    args.admin_user,
                    args.admin_pin,
                )
                print(f"Created first admin user: {args.admin_user}")
        else:
            ensure_migrated_defaults(connection)

    print(f"Database ready: {DB_FILE}")
    print(f"HMAC key: {HMAC_KEY_FILE} or {HMAC_KEY_ENV}")


def command_create_user(args):
    with connect_db() as connection:
        init_schema(connection)
        ensure_migrated_defaults(connection)
        user_id = create_user(connection, args.username, args.pin, args.system_role, args.display_name)

        if args.organization_id:
            grant_organization_access(
                connection,
                args.organization_id,
                user_id,
                args.org_role,
                args.created_by,
            )

        append_audit(connection, args.created_by, "user.create", "user", args.username, args.org_role)
        connection.commit()

    print(f"Created user: {args.username}")


def command_grant_org(args):
    with connect_db() as connection:
        init_schema(connection)
        ensure_migrated_defaults(connection)
        user = connection.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (args.username,),
        ).fetchone()

        if not user:
            raise SystemExit(f"Unknown active user: {args.username}")

        grant_organization_access(connection, args.organization_id, user["id"], args.role, args.granted_by)
        append_audit(
            connection,
            args.granted_by,
            "organization.grant",
            "organization",
            str(args.organization_id),
            f"user={args.username}; role={args.role}",
        )
        connection.commit()

    print(f"Granted {args.username} access to organization #{args.organization_id}")


def command_grant_case(args):
    with connect_db() as connection:
        init_schema(connection)
        ensure_migrated_defaults(connection)
        user = connection.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (args.username,),
        ).fetchone()

        if not user:
            raise SystemExit(f"Unknown active user: {args.username}")

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


def command_set_pin(args):
    with connect_db() as connection:
        init_schema(connection)
        ensure_migrated_defaults(connection)
        set_user_pin(connection, args.username, args.pin)
        append_audit(connection, args.changed_by, "user.pin.set", "user", args.username, "")
        connection.commit()

    print(f"Updated PIN for user: {args.username}")


def command_verify_db(_args):
    with connect_db() as connection:
        init_schema(connection)
        ensure_migrated_defaults(connection)
        errors = verify_database(connection)

    if errors:
        print("Database verification failed.")

        for error in errors:
            print(f"- {error}")

        raise SystemExit(1)

    print("Database verification passed.")


def command_serve(args):
    serve(args.host, args.port)


def main():
    parser = argparse.ArgumentParser(description="case-log web interface")
    subparsers = parser.add_subparsers(required=True)

    init_parser = subparsers.add_parser("init-db", help="Initialize the SQLite database")
    init_parser.add_argument("--organization", default="Default Organization")
    init_parser.add_argument("--admin-user", default="admin")
    init_parser.add_argument("--admin-pin", default="")
    init_parser.set_defaults(func=command_init_db)

    user_parser = subparsers.add_parser("create-user", help="Create another web user")
    user_parser.add_argument("--username", required=True)
    user_parser.add_argument("--pin", required=True)
    user_parser.add_argument("--display-name", default="")
    user_parser.add_argument("--system-role", default="user", choices=("system_admin", "user"))
    user_parser.add_argument("--organization-id", type=int, default=0)
    user_parser.add_argument("--org-role", default="viewer", choices=("owner", "admin", "case_manager", "analyst", "viewer"))
    user_parser.add_argument("--created-by", default="admin")
    user_parser.set_defaults(func=command_create_user)

    org_parser = subparsers.add_parser("grant-org", help="Grant organization access")
    org_parser.add_argument("--organization-id", required=True, type=int)
    org_parser.add_argument("--username", required=True)
    org_parser.add_argument("--role", default="viewer", choices=("owner", "admin", "case_manager", "analyst", "viewer"))
    org_parser.add_argument("--granted-by", default="admin")
    org_parser.set_defaults(func=command_grant_org)

    case_parser = subparsers.add_parser("grant-case", help="Grant case access")
    case_parser.add_argument("--case-id", required=True, type=int)
    case_parser.add_argument("--username", required=True)
    case_parser.add_argument("--role", default="member", choices=("owner", "member", "viewer"))
    case_parser.add_argument("--granted-by", default="admin")
    case_parser.set_defaults(func=command_grant_case)

    pin_parser = subparsers.add_parser("set-pin", help="Set a user's 4-digit PIN")
    pin_parser.add_argument("--username", required=True)
    pin_parser.add_argument("--pin", required=True)
    pin_parser.add_argument("--changed-by", default="admin")
    pin_parser.set_defaults(func=command_set_pin)

    verify_parser = subparsers.add_parser("verify-db", help="Verify SQLite integrity chains")
    verify_parser.set_defaults(func=command_verify_db)

    serve_parser = subparsers.add_parser("serve", help="Run the local web server")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.set_defaults(func=command_serve)

    args = parser.parse_args()
    args.func(args)
