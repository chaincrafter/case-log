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
    domain_options,
    esc,
    event_type_options,
    login_page,
    org_role_options,
    page,
    priority_options,
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

    def current_theme(self):
        return "dark" if "theme=dark" in (self.headers.get("Cookie") or "") else "light"

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
            page(
                status.phrase,
                f"<div class='panel'><h1>{status.phrase}</h1><p class='bad'>{esc(message or status.description)}</p></div>",
                theme=self.current_theme(),
            ),
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

        if path == "/theme":
            theme = "dark" if self.query_int("dark") else "light"
            self.redirect(
                self.headers.get("Referer") or "/",
                {"Set-Cookie": f"theme={theme}; SameSite=Strict; Path=/; Max-Age=31536000"},
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
            f"<tr><td><a href='/cases?org_id={org['id']}'>{esc(org['name'])}</a></td><td>{esc(org['domain'])}</td><td>{esc(org['description'])}</td><td>{esc(org['created_by'])}</td><td><code>{esc(org['hash'])}</code></td></tr>"
            for org in orgs
        )
        create_form = ""

        if user.get("system_role") == "system_admin":
            create_form = f"""
            <section class="panel">
              <h2>Organisation anlegen</h2>
              <p class="helper">Eine Organisation bündelt Fälle, Teamzugriff und Prüfnachweise.</p>
              <form id="create-organization" method="post" action="/organizations">
                {csrf_input(user)}
                <div class="form-grid">
                  <label>Name<input name="name" required></label>
                  <label>Bereich<select name="domain">{domain_options('foster_care')}</select></label>
                  <label class="wide">Kurzbeschreibung<textarea name="description"></textarea></label>
                </div>
                <button type="submit">Organisation speichern</button>
              </form>
            </section>
            """

        body = f"""
        <div class="page-heading">
          <div>
            <p class="eyebrow">Workspace</p>
            <h1>Organizations</h1>
            <p class="muted">Choose the working area for cases, users and evidence chains.</p>
          </div>
          <div class="quick-actions"><a class="button" href="#create-organization">Organisation anlegen</a></div>
        </div>
        <div class="summary-strip">
          <div class="summary-item"><strong>{len(orgs)}</strong><span>Organisationen</span></div>
          <div class="summary-item"><strong>{'Admin' if user.get('system_role') == 'system_admin' else 'Team'}</strong><span>Aktuelle Rolle</span></div>
          <div class="summary-item"><strong>HMAC</strong><span>Signierte Nachweise</span></div>
        </div>
        <div class="split">
          <section class="table-panel">
            <div class="table-panel-header"><div><h2>Organisationen</h2><p>{len(orgs)} Arbeitsbereich(e)</p></div></div>
            <div class="table-wrap"><table><thead><tr><th>Name</th><th>Bereich</th><th>Description</th><th>Created by</th><th>Hash</th></tr></thead><tbody>{rows or "<tr><td colspan='5'><div class='empty-state'>No organizations.</div></td></tr>"}</tbody></table></div>
          </section>
          {create_form}
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Organizations", body, user, self.current_theme()))

    def organization_post(self, user, form):
        if user.get("system_role") != "system_admin":
            self.send_error(HTTPStatus.FORBIDDEN)
            return

        with connect_db() as connection:
            org_id = create_organization(
                connection,
                form.get("name", ""),
                form.get("description", ""),
                user["username"],
                form.get("domain", "foster_care"),
            )
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
            f"<tr><td><a href='/?org_id={org['id']}&case_id={case['id']}'>{esc(case['title'])}</a><br><span class='muted'>{esc(case['subject_name'])}</span></td><td>{esc(case['description'])}</td><td>{esc(case['agency'])}<br><span class='muted'>{esc(case['case_worker'])}</span></td><td>{esc(case['created_by'])}</td><td><code>{esc(case['hash'])}</code></td></tr>"
            for case in cases
        )
        form_html = ""

        if can_manage:
            form_html = f"""
            <section class="panel primary-task">
              <h2>Kind / Fall anlegen</h2>
              <p class="helper">Nur Name oder Kürzel reicht für den Start. Alles Weitere kann später ergänzt werden.</p>
              <form id="create-case" method="post" action="/cases">
                {csrf_input(user)}
                <input type="hidden" name="organization_id" value="{org['id']}">
                <div class="form-grid">
                  <label>Name / Kürzel des Kindes<input name="subject_name" required></label>
                  <label>Fallname<input name="title" placeholder="optional, sonst wie Name / Kürzel"></label>
                </div>
                <details class="form-section">
                  <summary>Optionale Details</summary>
                  <div class="form-section-body form-grid">
                    <label>Geburtsdatum<input name="subject_birthdate" placeholder="YYYY-MM-DD"></label>
                    <label class="wide">Kurzbeschreibung<textarea name="description"></textarea></label>
                    <label>Aktenzeichen / Fallnummer<input name="subject_identifier"></label>
                    <label>Jugendamt<input name="agency"></label>
                    <label>Sachbearbeitung<input name="case_worker"></label>
                    <label>Vormund / Ergänzungspflege<input name="guardian"></label>
                    <label>Gericht / Aktenzeichen<input name="court_reference"></label>
                    <label>Schule / Kita<input name="school_or_daycare"></label>
                  </div>
                </details>
                <details class="form-section">
                  <summary>Medizin & Therapie</summary>
                  <div class="form-section-body">
                    <label>Ärzte / Therapie<textarea name="medical_contacts"></textarea></label>
                  </div>
                </details>
                <button type="submit">Jetzt starten</button>
              </form>
            </section>
            """

        body = f"""
        <div class="page-heading">
          <div>
            <p class="eyebrow">Cases</p>
            <h1>{esc(org['name'])}</h1>
            <p class="muted">Manage case files and open the chronology for documentation.</p>
          </div>
          <div class="quick-actions"><a class="button" href="#create-case">Fall anlegen</a></div>
        </div>
        <div class="summary-strip">
          <div class="summary-item"><strong>{len(cases)}</strong><span>Fälle</span></div>
          <div class="summary-item"><strong>{esc(org['domain'])}</strong><span>Bereich</span></div>
          <div class="summary-item"><strong>{'Ja' if can_manage else 'Nein'}</strong><span>Fallverwaltung</span></div>
        </div>
        <div class="split action-first">
          {form_html}
          <section class="table-panel">
            <div class="table-panel-header"><div><h2>Fallakten</h2><p>{len(cases)} Fall/Fälle in dieser Organisation</p></div></div>
            <div class="table-wrap"><table><thead><tr><th>Case</th><th>Description</th><th>Jugendamt</th><th>Created by</th><th>Hash</th></tr></thead><tbody>{rows or "<tr><td colspan='5'><div class='empty-state'>No cases yet.</div></td></tr>"}</tbody></table></div>
          </section>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Cases", body, user, self.current_theme()))

    def case_post(self, user, form):
        organization_id = int(form.get("organization_id", "0"))
        if not form.get("title", "").strip():
            form["title"] = form.get("subject_name", "").strip() or "Neuer Fall"

        with connect_db() as connection:
            if not has_org_permission(connection, user, organization_id, "cases.manage"):
                self.send_error(HTTPStatus.FORBIDDEN)
                return

            case_id = create_case(connection, organization_id, form, user["username"])
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
            attachment_counts = {
                row["event_id"]: row["count"]
                for row in connection.execute(
                    """
                    SELECT event_id, COUNT(*) AS count
                    FROM attachments
                    GROUP BY event_id
                    """
                )
            }
            can_write = has_org_permission(connection, user, org["id"], "cases.write")

        rows = "".join(
            f"<tr><td>#{event['sequence']}</td><td>{esc(event['timestamp'])}<br><span class='muted'>{event['timestamp_unix']}</span></td><td>{esc(event['event_type'])}<br><span class='muted'>{esc(event['priority'])}</span></td><td>{esc(event['title'])}<br><span class='muted'>{esc(event['people'])}</span><br><span class='muted'>Anhänge: {attachment_counts.get(event['id'], 0)}</span></td><td>{esc(event['recorded_by'])}</td><td><code>{esc(event['hash'])}</code></td></tr>"
            for event in events
        )
        event_cards = "".join(
            f"<article class='event-card'><div><strong>{esc(event['title'])}</strong><span>{esc(event['timestamp'])}</span></div><p>{esc(event['note'])}</p><small>{esc(event['event_type'])} · {esc(event['recorded_by'])}</small></article>"
            for event in reversed(events[-6:])
        )
        form_html = ""
        quick_html = ""

        if can_write:
            quick_html = f"""
            <section class="quick-log panel">
              <div>
                <p class="eyebrow">Schnell dokumentieren</p>
                <h2>Medikament gegeben</h2>
                <p class="helper">Für Situationen wie "Nureflex 4 ml": vier Felder, speichern, fertig.</p>
              </div>
              <form method="post" action="/events">
                {csrf_input(user)}
                <input type="hidden" name="quick_type" value="medication">
                <input type="hidden" name="organization_id" value="{org['id']}">
                <input type="hidden" name="case_id" value="{case['id']}">
                <div class="quick-form">
                  <label>Medikament<input name="medication_name" placeholder="Nureflex" required></label>
                  <label>Dosis<input name="medication_dose" placeholder="4 ml" required></label>
                  <label>Zeit<input name="timestamp" placeholder="jetzt"></label>
                  <label>Grund / Notiz<input name="quick_note" placeholder="Fieber, Schmerzen, nach Plan ..."></label>
                </div>
                <button type="submit">Medikament speichern</button>
              </form>
            </section>
            """
            form_html = f"""
            <section class="panel secondary-task">
              <details class="form-section">
                <summary>Ausführlichen Eintrag erfassen</summary>
                <div class="form-section-body">
              <p class="helper">Für längere Dokumentation mit Beobachtung, Einschätzung, Maßnahmen und Anhängen.</p>
              <form id="add-entry" method="post" action="/events">
                {csrf_input(user)}
                <input type="hidden" name="organization_id" value="{org['id']}">
                <input type="hidden" name="case_id" value="{case['id']}">
                <details class="form-section" open>
                  <summary>1. Was ist passiert?</summary>
                  <div class="form-section-body form-grid">
                <label class="wide">Titel<input name="title" required></label>
                <label>Ereignistyp<select name="event_type">{event_type_options('general')}</select></label>
                <label>Priorität<select name="priority">{priority_options('normal')}</select></label>
                <label>Zeitpunkt<input name="timestamp" placeholder="2026-05-19T20:30:00+02:00"></label>
                <label class="wide">Beteiligte Personen<input name="people"></label>
                <label>Ort<input name="location"></label>
                <label>Zitat des Kindes / wörtliche Aussage<textarea name="quote"></textarea></label>
                <label>Faktische Beobachtung<textarea name="observation"></textarea></label>
                <label>Einschätzung<textarea name="assessment"></textarea></label>
                <label>Maßnahme / nächster Schritt<textarea name="action_taken"></textarea></label>
                <label class="wide">Notiz<textarea name="note" required></textarea></label>
                  </div>
                </details>
                <details class="form-section">
                  <summary>4. Anhang mit Hash</summary>
                  <div class="form-section-body form-grid">
                <label>Dateiname<input name="attachment_name"></label>
                <label>SHA-256<input name="attachment_sha256" maxlength="64"></label>
                <label>Größe in Bytes<input name="attachment_size" inputmode="numeric"></label>
                <label class="wide">Beschreibung<textarea name="attachment_description"></textarea></label>
                  </div>
                </details>
                <button type="submit">Eintrag speichern</button>
              </form>
                </div>
              </details>
            </section>
            """

        body = f"""
        <div class="page-heading">
          <div>
            <p class="eyebrow">{esc(org['name'])}</p>
            <h1>{esc(case['title'])}</h1>
            <p class="muted">{esc(case['description'])}</p>
          </div>
          <div class="quick-actions"><a class="button" href="#add-entry">Eintrag erfassen</a><a class="button secondary" href="/verify?org_id={org['id']}&case_id={case['id']}">Integrität prüfen</a></div>
        </div>
        <div class="summary-strip">
          <div class="summary-item"><strong>{len(events)}</strong><span>Einträge</span></div>
          <div class="summary-item"><strong>{esc(case['subject_name'] or '-')}</strong><span>Kind / Kürzel</span></div>
          <div class="summary-item"><strong>{'Ja' if can_write else 'Nein'}</strong><span>Schreibzugriff</span></div>
        </div>
        {quick_html}
        <section class="event-list">{event_cards or "<div class='empty-state'>Noch keine Einträge. Nutze oben die Schnell-Doku.</div>"}</section>
        <div class="split">
          <section class="table-panel chronology-table">
            <div class="table-panel-header"><div><h2>Chronologie</h2><p>{len(events)} dokumentierte(s) Ereignis(se)</p></div></div>
            <div class="table-wrap"><table><thead><tr><th>Seq</th><th>Time</th><th>Type</th><th>Entry</th><th>User</th><th>Hash</th></tr></thead><tbody>{rows or "<tr><td colspan='6'><div class='empty-state'>No entries yet.</div></td></tr>"}</tbody></table></div>
          </section>
          {form_html}
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Entries", body, user, self.current_theme()))

    def event_post(self, user, form):
        organization_id = int(form.get("organization_id", "0"))
        case_id = int(form.get("case_id", "0"))

        if form.get("quick_type") == "medication":
            medication = clean_field(form.get("medication_name", ""), 120)
            dose = clean_field(form.get("medication_dose", ""), 80)
            quick_note = clean_field(form.get("quick_note", ""), 500)
            note_parts = [f"Medikament: {medication}", f"Dosis: {dose}"]

            if quick_note:
                note_parts.append(f"Notiz: {quick_note}")

            form["title"] = f"{medication} {dose}".strip()
            form["event_type"] = "medical"
            form["priority"] = "normal"
            form["category"] = "medical"
            form["note"] = "\n".join(note_parts)
            form["observation"] = form["note"]

        with connect_db() as connection:
            try:
                add_event(connection, form, user, organization_id, case_id)
                award_badge(connection, user["user_id"], "case_scribe", user["username"])
                connection.commit()
            except PermissionError:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            except ValueError as error:
                self.send_error(HTTPStatus.BAD_REQUEST, str(error))
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
        <div class="page-heading">
          <div>
            <p class="eyebrow">Access control</p>
            <h1>User Management</h1>
            <p class="muted">{esc(org['name'])}</p>
          </div>
        </div>
        <div class="split">
          <section class="table-panel">
            <div class="table-panel-header"><div><h2>People</h2><p>{len(users)} user(s)</p></div></div>
            <div class="table-wrap"><table><thead><tr><th></th><th>User</th><th>System</th><th>Org role</th><th>Active</th></tr></thead><tbody>{user_rows}</tbody></table></div>
          </section>
          <section class="panel">
            <h2>Create User</h2>
            <form method="post" action="/admin/users">
              {csrf_input(user)}
              <input type="hidden" name="organization_id" value="{org['id']}">
              <div class="form-grid">
              <label>Username<input name="username" required></label>
              <label>Display name<input name="display_name"></label>
              <label>4-digit PIN<input name="pin" inputmode="numeric" maxlength="4" required></label>
              <label>Organization role<select name="org_role">{org_role_options('viewer')}</select></label>
              </div>
              <button type="submit">Create user</button>
            </form>
            <h2>Grant Case Access</h2>
            <form method="post" action="/admin/grant-case">
              {csrf_input(user)}
              <input type="hidden" name="organization_id" value="{org['id']}">
              <div class="form-grid">
              <label>Username<input name="username" required></label>
              <label>Case<select name="case_id">{case_options}</select></label>
              <label>Case role<select name="case_role">{case_role_options('member')}</select></label>
              </div>
              <button type="submit">Grant case</button>
            </form>
          </section>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Users", body, user, self.current_theme()))

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
        <div class="page-heading">
          <div>
            <p class="eyebrow">Account</p>
            <h1>Profile</h1>
            <p class="muted">Update how your account appears in the case log.</p>
          </div>
        </div>
        <div class="split">
          <section class="panel">
            <p>{'<img class="avatar" src="' + esc(profile['avatar_url']) + '">' if profile and profile['avatar_url'] else ''}</p>
            <p>{badge_html or "<span class='muted'>No badges yet.</span>"}</p>
            <form method="post" action="/profile">
              {csrf_input(user)}
              <div class="form-grid">
              <label>Display name<input name="display_name" value="{esc(profile['display_name'] if profile else '')}"></label>
              <label>Avatar URL<input name="avatar_url" value="{esc(profile['avatar_url'] if profile else '')}"></label>
              <label class="wide">Title<input name="title" value="{esc(profile['title'] if profile else '')}"></label>
              <label class="wide">Bio<textarea name="bio">{esc(profile['bio'] if profile else '')}</textarea></label>
              </div>
              <button type="submit">Update profile</button>
            </form>
          </section>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Profile", body, user, self.current_theme()))

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
        <div class="page-heading">
          <div>
            <p class="eyebrow">Integrity</p>
            <h1>Verify {esc(case['title'])}</h1>
            <p class="muted">{esc(org['name'])}</p>
          </div>
        </div>
        <div class="panel">
          {status}
          <p>Event count: {len(events)}</p>
          <p>Case root hash:<br><code>{esc(root)}</code></p>
          <p class="muted">For court-facing use, export or record this root hash and submit it to a qualified external timestamp process outside this local app.</p>
        </div>
        """
        self.send_html(HTTPStatus.OK, page("Verify", body, user, self.current_theme()))

    def audit_page(self, user):
        with connect_db() as connection:
            rows = connection.execute("SELECT * FROM audit_log ORDER BY sequence DESC LIMIT 200").fetchall()

        table_rows = "".join(
            f"<tr><td>#{row['sequence']}</td><td>{esc(row['recorded_at'])}</td><td>{esc(row['actor'])}</td><td>{esc(row['action'])}</td><td>{esc(row['object_type'])}</td><td><code>{esc(row['hash'])}</code></td></tr>"
            for row in rows
        )
        body = f"""
        <div class="page-heading">
          <div>
            <p class="eyebrow">System record</p>
            <h1>Audit Log</h1>
            <p class="muted">Latest signed administrative and user actions.</p>
          </div>
        </div>
        <section class="table-panel">
          <div class="table-panel-header"><div><h2>Recent actions</h2><p>Showing up to 200 entries</p></div></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Seq</th><th>Recorded</th><th>Actor</th><th>Action</th><th>Object</th><th>Hash</th></tr></thead>
            <tbody>{table_rows or "<tr><td colspan='6'><div class='empty-state'>No audit entries yet.</div></td></tr>"}</tbody>
          </table></div>
        </section>
        """
        self.send_html(HTTPStatus.OK, page("Audit", body, user, self.current_theme()))


def serve(host, port):
    with connect_db() as connection:
        init_schema(connection)
        ensure_migrated_defaults(connection)

    server = ThreadingHTTPServer((host, port), CaseLogHandler)
    print(f"Serving case-log on http://{host}:{port}")
    server.serve_forever()
