import html

from .config import CASE_ROLES, ORG_ROLES


def esc(value):
    return html.escape(str(value or ""))


def csrf_input(user):
    if not user:
        return ""

    return f"<input type='hidden' name='csrf_token' value='{esc(user.get('csrf', ''))}'>"


def page(title, body, user=None):
    user_nav = ""

    if user:
        user_nav = (
            f"<span>{esc(user['username'])}</span>"
            "<a href='/profile'>Profile</a>"
            "<a href='/logout'>Logout</a>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - case-log</title>
  <style>
    :root {{ color-scheme: dark; --ink: #d9fff3; --muted: #7da99c; --line: #183d36; --accent: #00ff9c; --accent2: #00b8ff; --ok: #00ff9c; --bad: #ff4d6d; --bg: #030706; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Consolas, 'Courier New', monospace; color: var(--ink); background: radial-gradient(circle at top left, #0c221d 0, #030706 34rem); }}
    body::before {{ content: ""; position: fixed; inset: 0; pointer-events: none; background: repeating-linear-gradient(0deg, rgba(255,255,255,0.025), rgba(255,255,255,0.025) 1px, transparent 1px, transparent 4px); opacity: .42; }}
    header {{ position: sticky; top: 0; z-index: 2; display: flex; align-items: center; justify-content: space-between; padding: 14px 22px; border-bottom: 1px solid var(--line); background: rgba(3, 7, 6, .92); backdrop-filter: blur(10px); }}
    header strong {{ color: var(--accent); text-transform: uppercase; text-shadow: 0 0 12px rgba(0,255,156,.72); }}
    nav {{ display: flex; gap: 14px; align-items: center; flex-wrap: wrap; font-size: 14px; }}
    a {{ color: var(--accent); text-decoration: none; }}
    main {{ max-width: 1220px; margin: 0 auto; padding: 24px; }}
    h1 {{ font-size: 24px; margin: 0 0 18px; color: #fff; }}
    h1::before {{ content: "> "; color: var(--accent); }}
    h2 {{ font-size: 16px; color: var(--accent2); }}
    form {{ display: grid; gap: 12px; max-width: 760px; }}
    label {{ display: grid; gap: 5px; font-size: 13px; color: var(--muted); }}
    input, textarea, select {{ width: 100%; padding: 10px 11px; border: 1px solid var(--line); border-radius: 6px; font: inherit; color: var(--ink); background: #020504; outline: none; }}
    input:focus, textarea:focus, select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 2px rgba(0,255,156,.12); }}
    textarea {{ min-height: 120px; resize: vertical; }}
    button {{ width: fit-content; padding: 9px 14px; border: 1px solid rgba(0,255,156,.55); border-radius: 6px; background: linear-gradient(180deg, #00ff9c, #00b875); color: #001b12; font-weight: 700; cursor: pointer; }}
    table {{ width: 100%; border-collapse: collapse; background: rgba(7,17,15,.92); border: 1px solid var(--line); }}
    th, td {{ padding: 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 14px; }}
    th {{ background: #0d221d; color: var(--accent); }}
    code {{ font-family: Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; color: #9effd8; }}
    .split {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; align-items: start; }}
    .panel {{ background: linear-gradient(180deg, rgba(11,23,20,.94), rgba(4,10,9,.94)); border: 1px solid var(--line); border-radius: 8px; padding: 18px; }}
    .badge {{ display: inline-block; margin: 2px 5px 2px 0; padding: 4px 8px; border: 1px solid var(--accent); border-radius: 999px; color: var(--accent); font-size: 12px; }}
    .avatar {{ width: 42px; height: 42px; border-radius: 50%; object-fit: cover; border: 1px solid var(--accent); }}
    .ok {{ color: var(--ok); font-weight: 700; }}
    .bad {{ color: var(--bad); font-weight: 700; }}
    .muted {{ color: var(--muted); }}
    @media (max-width: 800px) {{ .split {{ grid-template-columns: 1fr; }} main {{ padding: 16px; }} table {{ display: block; overflow-x: auto; }} }}
  </style>
</head>
<body>
  <header><strong>case-log</strong><nav><a href="/organizations">Organizations</a><a href="/cases">Cases</a><a href="/">Events</a><a href="/admin/users">Users</a><a href="/verify">Verify</a><a href="/audit">Audit</a>{user_nav}</nav></header>
  <main>{body}</main>
</body>
</html>"""


def setup_page(error=""):
    body = f"""
    <div class="panel">
      <h1>First Run Setup</h1>
      <p class="muted">Create the first organization and system admin.</p>
      {"<p class='bad'>" + esc(error) + "</p>" if error else ""}
      <form method="post" action="/setup">
        <label>Organization<input name="organization_name" required></label>
        <label>Admin username<input name="username" required></label>
        <label>4-digit PIN<input name="pin" inputmode="numeric" pattern="[0-9]{{4}}" maxlength="4" required></label>
        <button type="submit">Initialize</button>
      </form>
    </div>
    """
    return page("Setup", body)


def login_page(error=""):
    body = f"""
    <div class="panel">
      <h1>Login</h1>
      {"<p class='bad'>" + esc(error) + "</p>" if error else ""}
      <form method="post" action="/login">
        <label>Username<input name="username" autocomplete="username" required></label>
        <label>PIN<input name="pin" type="password" inputmode="numeric" maxlength="4" autocomplete="current-password" required></label>
        <button type="submit">Login</button>
      </form>
    </div>
    """
    return page("Login", body)


def role_options(roles, selected=""):
    return "".join(
        f"<option value='{esc(role)}' {'selected' if role == selected else ''}>{esc(role)}</option>"
        for role in roles
    )


def org_role_options(selected="viewer"):
    return role_options(ORG_ROLES, selected)


def case_role_options(selected="member"):
    return role_options(CASE_ROLES, selected)
