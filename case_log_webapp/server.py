from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .bootstrap import complete_first_run, first_run_required
from .config import LOGIN_ATTEMPTS, MAX_FORM_BYTES, SESSION_COOKIE
from .crypto import (
    clear_login_failures,
    login_allowed,
    make_session,
    read_session,
    record_login_failure,
)
from .db import connect_db, init_schema
from .models import (
    add_event,
    append_audit,
    award_badge,
    case_root_for,
    clean_field,
    create_case,
    create_organization,
    create_user,
    get_accessible_case,
    get_accessible_organization,
    grant_case_access,
    grant_organization_access,
    has_org_permission,
    ensure_migrated_defaults,
    list_accessible_cases,
    list_accessible_organizations,
    update_profile,
    verify_database,
    verify_login,
)
from .views import (
    case_role_options,
    csrf_input,
    esc,
    login_page,
    org_role_options,
    page,
    setup_page,
)


class CaseLogHandler(BaseHTTPRequestHandler):
    server_version = "case-log/0.3"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def security_headers(self):
        return {
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data: https:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
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
        self.send_html(
            status,
            page(status.phrase, f"<div class='panel'><h1>{status.phrase}</h1><p class='bad'>{esc(message or status.description)}</p></div>"),
        )

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

    def query_int(self, name):
        value = parse_qs(urlparse(self.path).query).get(name, [""])[0]

        try:
            return int(value) if value else 0
        except ValueError:
            return 0

    def current_user(self):
        user = read_session(self.headers.get("Cookie"))

        if not user:
            return None

        with connect_db() as connection:
            row = connection.execute(
                """
                SELECT users.*, profiles.display_name, profiles.avatar_url, profiles.title
                FROM users
                LEFT JOIN profiles ON profiles.user_id = users.id
                WHERE users.id = ? AND users.username = ? AND users.active = 1
                """,
                (user.get("user_id"), user.get("username")),
            ).fetchone()

        if not row:
            return None

        user["system_role"] = row["system_role"]
        user["display_name"] = row["display_name"] or row["username"]
        user["avatar_url"] = row["avatar_url"]
        user["title"] = row["title"]

        return user

    def require_user(self):
        with connect_db() as connection:
            init_schema(connection)

            if first_run_required(connection):
                self.redirect("/setup")
                return None

        user = self.current_user()

        if not user:
            self.redirect("/login")
            return None

        return user

    def verify_csrf(self, user, form):
        return bool(form.get("csrf_token")) and form.get("csrf_token") == user.get("csrf")

    def do_GET(self):
        with connect_db() as connection:
            init_schema(connection)
            ensure_migrated_defaults(connection)
            needs_setup = first_run_required(connection)

        path = urlparse(self.path).path

        if needs_setup:
            if path == "/setup":
                self.send_html(HTTPStatus.OK, setup_page())
                return

            self.redirect("/setup")
            return

        if path == "/login":
            self.send_html(HTTPStatus.OK, login_page())
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

        routes = {
            "/": self.events_page,
            "/organizations": self.organizations_page,
            "/cases": self.cases_page,
            "/admin/users": self.users_page,
            "/profile": self.profile_page,
            "/verify": self.verify_page,
            "/audit": self.audit_page,
        }
        handler = routes.get(path)

        if not handler:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        handler(user)

    def do_POST(self):
        path = urlparse(self.path).path

        try:
            form = self.read_form()
        except ValueError:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        if path == "/setup":
            with connect_db() as connection:
                init_schema(connection)

                if not first_run_required(connection):
                    self.redirect("/login")
                    return

                try:
                    complete_first_run(
                        connection,
                        form.get("organization_name", ""),
                        form.get("username", ""),
                        form.get("pin", ""),
                    )
                except ValueError as error:
                    self.send_html(HTTPStatus.BAD_REQUEST, setup_page(str(error)))
                    return

            self.redirect("/login")
            return

        if path == "/login":
            self.login_post(form)
            return

        user = self.require_user()

        if not user:
            return

        if not self.verify_csrf(user, form):
            self.send_error(HTTPStatus.FORBIDDEN)
            return

        handlers = {
            "/organizations": self.organization_post,
            "/cases": self.case_post,
            "/events": self.event_post,
            "/admin/users": self.user_post,
            "/admin/grant-org": self.grant_org_post,
            "/admin/grant-case": self.grant_case_post,
            "/profile": self.profile_post,
        }
        handler = handlers.get(path)

        if not handler:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        handler(user, form)

    def login_post(self, form):
        username = clean_field(form.get("username", ""), 64)
        identifier = f"{self.client_address[0]}:{username}"

        if not login_allowed(identifier, LOGIN_ATTEMPTS):
            self.send_html(HTTPStatus.TOO_MANY_REQUESTS, login_page("Too many login attempts. Try again later."))
            return

        with connect_db() as connection:
            init_schema(connection)
            ensure_migrated_defaults(connection)
            user = verify_login(connection, username, form.get("pin", ""))

            if not user:
                record_login_failure(identifier, LOGIN_ATTEMPTS)
                self.send_html(HTTPStatus.UNAUTHORIZED, login_page("Invalid login."))
                return

            clear_login_failures(identifier, LOGIN_ATTEMPTS)
            append_audit(connection, user["username"], "user.login", "user", user["username"], "")
            connection.commit()

        self.redirect(
            "/organizations",
            {"Set-Cookie": f"{SESSION_COOKIE}={make_session(user)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"},
        )

    def selected_org(self, connection, user):
        return get_accessible_organization(connection, user, self.query_int("org_id"))

    def selected_case(self, connection, user, organization_id):
        return get_accessible_case(connection, user, organization_id, self.query_int("case_id"))

    def organizations_page(self, user):
        with connect_db() as connection:
            orgs = list_accessible_organizations(connection, user)

        rows = "".join(
            f"<tr><td><a href='/cases?org_id={org['id']}'>{esc(org['name'])}</a></td><td>{esc(org['description'])}</td><td>{esc(org['created_by'])}</td><td><code>{esc(org['hash'])}</code></td></tr>"
            for org in orgs
        )
        create_form = ""

        if user.get("system_role") == "system_admin":
            create_form = f"""
            <section class="panel">
              <h2>Create Organization</h2>
              <form method="post" action="/organizations">
                {csrf_input(user)}
                <label>Name<input name="name" required></label>
                <label>Description<textarea name="description"></textarea></label>
                <button type="submit">Create organization</button>
              </form>
            </section>
            """

        body = f"""
        <h1>Organizations</h1>
        <div class="split">
          <section><table><thead><tr><th>Name</th><th>Description</th><th>Created by</th><th>Hash</th></tr></thead><tbody>{rows or "<tr><td colspan='4'>No organizations.</td></tr>"}</tbody></table></section>
          {create_form}
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Organizations", body, user))

    def organization_post(self, user, form):
        if user.get("system_role") != "system_admin":
            self.send_error(HTTPStatus.FORBIDDEN)
            return

        with connect_db() as connection:
            org_id = create_organization(connection, form.get("name", ""), form.get("description", ""), user["username"])
            grant_organization_access(connection, org_id, user["user_id"], "owner", user["username"])
            append_audit(connection, user["username"], "organization.create", "organization", str(org_id), form.get("name", ""))
            connection.commit()

        self.redirect(f"/cases?org_id={org_id}")

    def cases_page(self, user):
        with connect_db() as connection:
            org = self.selected_org(connection, user)

            if not org:
                self.redirect("/organizations")
                return

            cases = list_accessible_cases(connection, user, org["id"])
            can_manage = has_org_permission(connection, user, org["id"], "cases.manage")

        rows = "".join(
            f"<tr><td><a href='/?org_id={org['id']}&case_id={case['id']}'>{esc(case['title'])}</a></td><td>{esc(case['description'])}</td><td>{esc(case['created_by'])}</td><td><code>{esc(case['hash'])}</code></td></tr>"
            for case in cases
        )
        form_html = ""

        if can_manage:
            form_html = f"""
            <section class="panel">
              <h2>Create Case</h2>
              <form method="post" action="/cases">
                {csrf_input(user)}
                <input type="hidden" name="organization_id" value="{org['id']}">
                <label>Title<input name="title" required></label>
                <label>Description<textarea name="description"></textarea></label>
                <button type="submit">Create case</button>
              </form>
            </section>
            """

        body = f"""
        <h1>{esc(org['name'])} Cases</h1>
        <div class="split">
          <section><table><thead><tr><th>Case</th><th>Description</th><th>Created by</th><th>Hash</th></tr></thead><tbody>{rows or "<tr><td colspan='4'>No cases.</td></tr>"}</tbody></table></section>
          {form_html}
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Cases", body, user))

    def case_post(self, user, form):
        organization_id = int(form.get("organization_id", "0"))

        with connect_db() as connection:
            if not has_org_permission(connection, user, organization_id, "cases.manage"):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

            case_id = create_case(connection, organization_id, form.get("title", ""), form.get("description", ""), user["username"])
            grant_case_access(connection, case_id, user["user_id"], "owner", user["username"])
            award_badge(connection, user["user_id"], "first_case", user["username"])
            append_audit(connection, user["username"], "case.create", "case", str(case_id), form.get("title", ""))
            connection.commit()

        self.redirect(f"/?org_id={organization_id}&case_id={case_id}")

    def events_page(self, user):
        with connect_db() as connection:
            org = self.selected_org(connection, user)

            if not org:
                self.redirect("/organizations")
                return

            case = self.selected_case(connection, user, org["id"])

            if not case:
                self.redirect(f"/cases?org_id={org['id']}")
                return

            events = connection.execute(
                "SELECT * FROM events WHERE case_id = ? ORDER BY sequence",
                (case["id"],),
            ).fetchall()
            can_write = has_org_permission(connection, user, org["id"], "cases.write")

        rows = "".join(
            f"<tr><td>#{event['sequence']}</td><td>{esc(event['timestamp'])}<br><span class='muted'>{event['timestamp_unix']}</span></td><td>{esc(event['category'])}</td><td>{esc(event['title'])}<br><span class='muted'>{esc(event['people'])}</span></td><td>{esc(event['recorded_by'])}</td><td><code>{esc(event['hash'])}</code></td></tr>"
            for event in events
        )
        form_html = ""

        if can_write:
            form_html = f"""
            <section class="panel">
              <h2>Add Entry</h2>
              <form method="post" action="/events">
                {csrf_input(user)}
                <input type="hidden" name="organization_id" value="{org['id']}">
                <input type="hidden" name="case_id" value="{case['id']}">
                <label>Title<input name="title" required></label>
                <label>Category<input name="category" value="general"></label>
                <label>Event time<input name="timestamp" placeholder="2026-05-19T20:30:00+02:00"></label>
                <label>People<input name="people"></label>
                <label>Note<textarea name="note" required></textarea></label>
                <button type="submit">Add entry</button>
              </form>
            </section>
            """

        body = f"""
        <h1>{esc(case['title'])}</h1>
        <p class="muted">{esc(org['name'])} / {esc(case['description'])}</p>
        <div class="split">
          <section><table><thead><tr><th>Seq</th><th>Time</th><th>Category</th><th>Entry</th><th>User</th><th>Hash</th></tr></thead><tbody>{rows or "<tr><td colspan='6'>No entries.</td></tr>"}</tbody></table></section>
          {form_html}
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Entries", body, user))

    def event_post(self, user, form):
        organization_id = int(form.get("organization_id", "0"))
        case_id = int(form.get("case_id", "0"))

        with connect_db() as connection:
            try:
                add_event(connection, form, user, organization_id, case_id)
                award_badge(connection, user["user_id"], "case_scribe", user["username"])
                connection.commit()
            except PermissionError:
                self.send_error(HTTPStatus.FORBIDDEN)
                return

        self.redirect(f"/?org_id={organization_id}&case_id={case_id}")

    def users_page(self, user):
        with connect_db() as connection:
            org = self.selected_org(connection, user)

            if not org:
                self.redirect("/organizations")
                return

            if not has_org_permission(connection, user, org["id"], "users.manage"):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

            users = connection.execute(
                """
                SELECT users.*, profiles.display_name, profiles.avatar_url, organization_members.role AS org_role
                FROM users
                LEFT JOIN profiles ON profiles.user_id = users.id
                LEFT JOIN organization_members ON organization_members.user_id = users.id
                    AND organization_members.organization_id = ?
                ORDER BY users.username
                """,
                (org["id"],),
            ).fetchall()
            cases = list_accessible_cases(connection, user, org["id"])

        user_rows = ""

        for row in users:
            avatar = f"<img class='avatar' src='{esc(row['avatar_url'])}'>" if row["avatar_url"] else ""
            user_rows += (
                f"<tr><td>{avatar}</td><td>{esc(row['username'])}<br>"
                f"<span class='muted'>{esc(row['display_name'])}</span></td>"
                f"<td>{esc(row['system_role'])}</td><td>{esc(row['org_role'] or '-')}</td>"
                f"<td>{esc(row['active'])}</td></tr>"
            )
        case_options = "".join(f"<option value='{case['id']}'>{esc(case['title'])}</option>" for case in cases)
        body = f"""
        <h1>User Management / {esc(org['name'])}</h1>
        <div class="split">
          <section><table><thead><tr><th></th><th>User</th><th>System</th><th>Org role</th><th>Active</th></tr></thead><tbody>{user_rows}</tbody></table></section>
          <section class="panel">
            <h2>Create User</h2>
            <form method="post" action="/admin/users">
              {csrf_input(user)}
              <input type="hidden" name="organization_id" value="{org['id']}">
              <label>Username<input name="username" required></label>
              <label>Display name<input name="display_name"></label>
              <label>4-digit PIN<input name="pin" inputmode="numeric" maxlength="4" required></label>
              <label>Organization role<select name="org_role">{org_role_options('viewer')}</select></label>
              <button type="submit">Create user</button>
            </form>
            <h2>Grant Case Access</h2>
            <form method="post" action="/admin/grant-case">
              {csrf_input(user)}
              <input type="hidden" name="organization_id" value="{org['id']}">
              <label>Username<input name="username" required></label>
              <label>Case<select name="case_id">{case_options}</select></label>
              <label>Case role<select name="case_role">{case_role_options('member')}</select></label>
              <button type="submit">Grant case</button>
            </form>
          </section>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Users", body, user))

    def user_post(self, user, form):
        organization_id = int(form.get("organization_id", "0"))

        with connect_db() as connection:
            if not has_org_permission(connection, user, organization_id, "users.manage"):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

            try:
                user_id = create_user(connection, form.get("username", ""), form.get("pin", ""), "user", form.get("display_name", ""))
                grant_organization_access(connection, organization_id, user_id, form.get("org_role", "viewer"), user["username"])
                append_audit(connection, user["username"], "user.create", "user", form.get("username", ""), f"org={organization_id}")
                connection.commit()
            except ValueError as error:
                self.send_error(HTTPStatus.BAD_REQUEST, str(error))
                return

        self.redirect(f"/admin/users?org_id={organization_id}")

    def grant_case_post(self, user, form):
        organization_id = int(form.get("organization_id", "0"))

        with connect_db() as connection:
            if not has_org_permission(connection, user, organization_id, "users.manage"):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

            target = connection.execute("SELECT * FROM users WHERE username = ?", (form.get("username", ""),)).fetchone()

            if not target:
                self.send_error(HTTPStatus.BAD_REQUEST, "Unknown user")
                return

            grant_case_access(connection, int(form.get("case_id", "0")), target["id"], form.get("case_role", "member"), user["username"])
            append_audit(connection, user["username"], "case.grant", "case", form.get("case_id", ""), form.get("username", ""))
            connection.commit()

        self.redirect(f"/admin/users?org_id={organization_id}")

    def grant_org_post(self, user, form):
        self.user_post(user, form)

    def profile_page(self, user):
        with connect_db() as connection:
            profile = connection.execute("SELECT * FROM profiles WHERE user_id = ?", (user["user_id"],)).fetchone()
            badges = connection.execute(
                """
                SELECT badges.*
                FROM badges
                JOIN user_badges ON user_badges.badge_id = badges.id
                WHERE user_badges.user_id = ?
                ORDER BY badges.label
                """,
                (user["user_id"],),
            ).fetchall()

        badge_html = "".join(f"<span class='badge'>{esc(badge['label'])}</span>" for badge in badges)
        body = f"""
        <h1>Profile</h1>
        <div class="split">
          <section class="panel">
            <p>{'<img class="avatar" src="' + esc(profile['avatar_url']) + '">' if profile and profile['avatar_url'] else ''}</p>
            <p>{badge_html or "<span class='muted'>No badges yet.</span>"}</p>
            <form method="post" action="/profile">
              {csrf_input(user)}
              <label>Display name<input name="display_name" value="{esc(profile['display_name'] if profile else '')}"></label>
              <label>Avatar URL<input name="avatar_url" value="{esc(profile['avatar_url'] if profile else '')}"></label>
              <label>Title<input name="title" value="{esc(profile['title'] if profile else '')}"></label>
              <label>Bio<textarea name="bio">{esc(profile['bio'] if profile else '')}</textarea></label>
              <button type="submit">Update profile</button>
            </form>
          </section>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Profile", body, user))

    def profile_post(self, user, form):
        with connect_db() as connection:
            update_profile(connection, user["user_id"], form)
            append_audit(connection, user["username"], "profile.update", "user", user["username"], "")
            connection.commit()

        self.redirect("/profile")

    def verify_page(self, user):
        with connect_db() as connection:
            errors = verify_database(connection)
            org = self.selected_org(connection, user)

            if not org:
                self.redirect("/organizations")
                return

            case = self.selected_case(connection, user, org["id"])

            if not case:
                self.redirect(f"/cases?org_id={org['id']}")
                return

            root, events = case_root_for(connection, case["id"])
            award_badge(connection, user["user_id"], "chain_keeper", user["username"])
            connection.commit()

        status = "<p class='ok'>Database integrity and signatures verified.</p>"

        if errors:
            status = "<p class='bad'>Verification failed.</p><ul>" + "".join(
                f"<li>{esc(error)}</li>" for error in errors
            ) + "</ul>"

        body = f"""
        <h1>Verify {esc(case['title'])}</h1>
        <div class="panel">
          {status}
          <p>Event count: {len(events)}</p>
          <p>Case root hash:<br><code>{esc(root)}</code></p>
          <p class="muted">For court-facing use, export or record this root hash and submit it to a qualified external timestamp process outside this local app.</p>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Verify", body, user))

    def audit_page(self, user):
        with connect_db() as connection:
            rows = connection.execute("SELECT * FROM audit_log ORDER BY sequence DESC LIMIT 200").fetchall()

        table_rows = "".join(
            f"<tr><td>#{row['sequence']}</td><td>{esc(row['recorded_at'])}</td><td>{esc(row['actor'])}</td><td>{esc(row['action'])}</td><td>{esc(row['object_type'])}</td><td><code>{esc(row['hash'])}</code></td></tr>"
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


def serve(host, port):
    with connect_db() as connection:
        init_schema(connection)
        ensure_migrated_defaults(connection)

    server = ThreadingHTTPServer((host, port), CaseLogHandler)
    print(f"Serving case-log on http://{host}:{port}")
    server.serve_forever()
