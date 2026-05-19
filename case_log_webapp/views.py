import html

from .config import CASE_ROLES, FOSTER_EVENT_TYPES, ORG_DOMAINS, ORG_ROLES, PRIORITIES


def esc(value):
    return html.escape(str(value or ""))


def csrf_input(user):
    if not user:
        return ""

    return f"<input type='hidden' name='csrf_token' value='{esc(user.get('csrf', ''))}'>"


def page(title, body, user=None, theme="light"):
    user_nav = ""

    if user:
        display_name = user.get("display_name") or user.get("username")
        initials = "".join(part[:1] for part in str(display_name).split()[:2]).upper() or "U"
        user_nav = (
            "<div class='user-card'>"
            f"<span class='avatar-fallback'>{esc(initials)}</span>"
            "<span class='user-copy'>"
            f"<strong>{esc(display_name)}</strong>"
            f"<small>{esc(user['username'])}</small>"
            "</span>"
            "</div>"
            "<div class='utility-nav'>"
            "<a href='/profile'>Profile</a>"
            "<a href='/theme'>Light</a>"
            "<a href='/theme?dark=1'>Dark</a>"
            "<a href='/logout'>Logout</a>"
            "</div>"
        )

    theme_class = "theme-dark" if theme == "dark" else "theme-light"
    shell = (
        f"""
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark">CL</span><span class="brand-copy"><strong>case-log</strong><small>Forensic chronology</small></span></div>
      <nav class="primary-nav"><a href="/organizations">Organizations</a><a href="/cases">Cases</a><a href="/">Events</a><a href="/admin/users">Users</a><a href="/verify">Verify</a><a href="/audit">Audit</a></nav>
      <div class="sidebar-footer">{user_nav}</div>
    </aside>
    <div class="content"><main>{body}</main></div>
  </div>"""
        if user
        else f"<main>{body}</main>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - case-log</title>
  <style>
    :root {{ color-scheme: light; --ink: #18211f; --muted: #65736f; --line: #d9e1dd; --line-strong: #becbc5; --accent: #17614a; --accent-strong: #0d4a37; --accent-soft: #e4f3ed; --accent2: #285c86; --ok: #147448; --bad: #b4233c; --warn: #9a5b00; --bg: #f6f8f7; --panel: #ffffff; --panel-soft: #edf2ef; --shadow: 0 18px 44px rgba(24,33,31,.08); --radius: 8px; }}
    body.theme-dark {{ color-scheme: dark; --ink: #e8f0ed; --muted: #9eaaa6; --line: #273530; --line-strong: #384842; --accent: #53d69d; --accent-strong: #7ce7b7; --accent-soft: #142821; --accent2: #8fc7ff; --ok: #63d897; --bad: #ff8094; --warn: #ffd28a; --bg: #101513; --panel: #171d1a; --panel-soft: #1d2521; --shadow: 0 18px 44px rgba(0,0,0,.26); }}
    * {{ box-sizing: border-box; }}
    html {{ min-height: 100%; }}
    body {{ margin: 0; min-height: 100%; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg); letter-spacing: 0; }}
    body.theme-dark {{ background: #101513; }}
    a {{ color: var(--accent); text-decoration: none; font-weight: 650; }}
    a:hover {{ color: var(--accent-strong); text-decoration: underline; text-underline-offset: 3px; }}
    .app-shell {{ min-height: 100vh; display: grid; grid-template-columns: 260px minmax(0, 1fr); }}
    .sidebar {{ position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column; gap: 22px; padding: 22px 16px; border-right: 1px solid var(--line); background: color-mix(in srgb, var(--panel) 92%, var(--bg)); }}
    .brand {{ display: flex; align-items: center; gap: 10px; padding: 0 8px 12px; border-bottom: 1px solid var(--line); }}
    .brand-mark {{ display: grid; place-items: center; width: 34px; height: 34px; border-radius: 8px; background: var(--accent); color: #fff; font-weight: 800; }}
    .brand-copy strong {{ display: block; color: var(--ink); text-transform: lowercase; letter-spacing: 0; font-size: 17px; }}
    .brand-copy small {{ color: var(--muted); font-size: 12px; }}
    nav.primary-nav {{ display: grid; gap: 5px; }}
    nav.primary-nav a {{ display: flex; align-items: center; min-height: 38px; padding: 9px 11px; border-radius: 8px; color: var(--ink); font-size: 14px; font-weight: 700; }}
    nav.primary-nav a:hover {{ background: var(--panel-soft); color: var(--accent-strong); text-decoration: none; }}
    .sidebar-footer {{ margin-top: auto; display: grid; gap: 12px; }}
    .user-card {{ display: flex; align-items: center; gap: 10px; padding: 10px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); }}
    .avatar-fallback {{ flex: 0 0 auto; display: grid; place-items: center; width: 36px; height: 36px; border-radius: 50%; background: var(--accent-soft); color: var(--accent-strong); font-weight: 800; }}
    .user-copy {{ min-width: 0; display: grid; gap: 1px; }}
    .user-copy strong, .user-copy small {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .user-copy small {{ color: var(--muted); }}
    .utility-nav {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .utility-nav a {{ padding: 6px 8px; border-radius: 6px; color: var(--muted); font-size: 12px; font-weight: 750; }}
    .utility-nav a:hover {{ background: var(--panel-soft); color: var(--accent-strong); text-decoration: none; }}
    .content {{ min-width: 0; padding: 34px clamp(18px, 4vw, 48px) 54px; }}
    main {{ max-width: 1280px; margin: 0 auto; }}
    .page-heading {{ display: flex; align-items: end; justify-content: space-between; gap: 20px; margin-bottom: 22px; }}
    .eyebrow {{ margin: 0 0 6px; color: var(--accent); font-size: 12px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }}
    h1 {{ margin: 0; color: var(--ink); font-size: clamp(28px, 4vw, 42px); line-height: 1.05; font-weight: 800; letter-spacing: 0; }}
    h2 {{ margin: 0 0 14px; color: var(--ink); font-size: 18px; line-height: 1.2; }}
    h3 {{ margin: 20px 0 10px; color: var(--ink); font-size: 15px; }}
    p {{ line-height: 1.55; }}
    form {{ display: grid; gap: 14px; max-width: 860px; }}
    label {{ display: grid; gap: 6px; font-size: 13px; font-weight: 750; color: var(--muted); }}
    input, textarea, select {{ width: 100%; padding: 11px 12px; border: 1px solid var(--line); border-radius: 7px; font: inherit; color: var(--ink); background: var(--panel); outline: none; transition: border-color .16s ease, box-shadow .16s ease, background .16s ease; }}
    input:focus, textarea:focus, select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent); }}
    textarea {{ min-height: 120px; resize: vertical; }}
    button {{ width: fit-content; min-height: 40px; padding: 10px 15px; border: 1px solid var(--accent); border-radius: 7px; background: var(--accent); color: #fff; font-weight: 800; cursor: pointer; box-shadow: 0 8px 18px color-mix(in srgb, var(--accent) 20%, transparent); }}
    button:hover {{ background: var(--accent-strong); border-color: var(--accent-strong); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); }}
    th, td {{ padding: 14px 16px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 14px; }}
    th {{ position: sticky; top: 0; z-index: 1; background: var(--panel-soft); color: var(--muted); font-size: 12px; letter-spacing: .04em; text-transform: uppercase; }}
    tr:hover td {{ background: color-mix(in srgb, var(--accent-soft) 42%, transparent); }}
    code {{ display: inline-block; max-width: 260px; padding: 4px 6px; border-radius: 6px; background: var(--panel-soft); color: var(--accent2); font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }}
    .split {{ display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(340px, .85fr); gap: 22px; align-items: start; }}
    .panel, .table-panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); }}
    .panel {{ padding: 22px; }}
    .table-panel {{ overflow: hidden; }}
    .table-panel-header {{ display: flex; justify-content: space-between; gap: 14px; padding: 18px 20px; border-bottom: 1px solid var(--line); background: var(--panel); }}
    .table-panel-header p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}
    .table-wrap {{ width: 100%; overflow: auto; }}
    .form-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
    .form-grid .wide {{ grid-column: 1 / -1; }}
    .badge {{ display: inline-block; margin: 2px 5px 2px 0; padding: 5px 9px; border: 1px solid var(--line-strong); border-radius: 999px; background: var(--accent-soft); color: var(--accent-strong); font-size: 12px; font-weight: 800; }}
    .avatar {{ width: 42px; height: 42px; border-radius: 50%; object-fit: cover; border: 1px solid var(--line-strong); }}
    .empty-state {{ padding: 34px 20px; color: var(--muted); text-align: center; }}
    .status-card {{ display: flex; gap: 12px; align-items: flex-start; padding: 14px; border-radius: 8px; background: var(--panel-soft); }}
    .ok {{ color: var(--ok); font-weight: 700; }}
    .bad {{ color: var(--bad); font-weight: 700; }}
    .muted {{ color: var(--muted); }}
    .auth-shell {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    .auth-panel {{ width: min(460px, 100%); }}
    @media (max-width: 980px) {{ .app-shell {{ grid-template-columns: 1fr; }} .sidebar {{ position: static; height: auto; }} nav.primary-nav {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }} .content {{ padding-top: 24px; }} .split {{ grid-template-columns: 1fr; }} }}
    @media (max-width: 640px) {{ nav.primary-nav {{ grid-template-columns: 1fr 1fr; }} .page-heading {{ display: block; }} .form-grid {{ grid-template-columns: 1fr; }} th, td {{ padding: 12px; }} }}
  </style>
</head>
<body class="{theme_class}">
{shell}
</body>
</html>"""


def setup_page(error=""):
    body = f"""
    <div class="auth-shell"><section class="panel auth-panel">
      <p class="eyebrow">First run</p>
      <h1>Set up case-log</h1>
      <p class="muted">Create the first organization and system admin.</p>
      {"<p class='bad'>" + esc(error) + "</p>" if error else ""}
      <form method="post" action="/setup">
        <label>Organization<input name="organization_name" required></label>
        <label>Admin username<input name="username" required></label>
        <label>4-digit PIN<input name="pin" inputmode="numeric" pattern="[0-9]{{4}}" maxlength="4" required></label>
        <button type="submit">Initialize</button>
      </form>
    </section></div>
    """
    return page("Setup", body)


def login_page(error=""):
    body = f"""
    <div class="auth-shell"><section class="panel auth-panel">
      <p class="eyebrow">Secure access</p>
      <h1>Login</h1>
      {"<p class='bad'>" + esc(error) + "</p>" if error else ""}
      <form method="post" action="/login">
        <label>Username<input name="username" autocomplete="username" required></label>
        <label>PIN<input name="pin" type="password" inputmode="numeric" maxlength="4" autocomplete="current-password" required></label>
        <button type="submit">Login</button>
      </form>
    </section></div>
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


def domain_options(selected="foster_care"):
    return "".join(
        f"<option value='{esc(value)}' {'selected' if value == selected else ''}>{esc(label)}</option>"
        for value, label in ORG_DOMAINS.items()
    )


def event_type_options(selected="general"):
    return "".join(
        f"<option value='{esc(value)}' {'selected' if value == selected else ''}>{esc(label)}</option>"
        for value, label in FOSTER_EVENT_TYPES.items()
    )


def priority_options(selected="normal"):
    return role_options(PRIORITIES, selected)
