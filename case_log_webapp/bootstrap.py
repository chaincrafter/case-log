from case_log import create_hmac_key

from .models import (
    append_audit,
    award_badge,
    create_organization,
    create_user,
    grant_organization_access,
    has_users,
)


def first_run_required(connection):
    return not has_users(connection)


def complete_first_run(connection, organization_name, admin_username, admin_pin):
    create_hmac_key()
    user_id = create_user(connection, admin_username, admin_pin, "system_admin", admin_username)
    org_id = create_organization(
        connection,
        organization_name,
        "Initial organization.",
        admin_username,
        "foster_care",
    )
    grant_organization_access(connection, org_id, user_id, "owner", admin_username)
    award_badge(connection, user_id, "org_admin", admin_username)
    append_audit(connection, admin_username, "setup.complete", "organization", str(org_id), organization_name)
    connection.commit()

    return org_id, user_id
