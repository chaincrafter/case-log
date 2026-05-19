# case-log

`case-log` is a small, dependency-free forensic case logging tool.

It supports append-only chronological event documentation, local integrity
verification, HMAC signatures, evidence reports and a local multi-user SQLite web
interface with organizations, domains, roles, user profiles, badges and a
government-friendly light/dark design.

## Scope

`case-log` is designed to support chain-of-custody documentation and local
tamper detection. It does not create a qualified electronic timestamp,
qualified electronic signature or qualified seal by itself. For court-facing
workflows, preserve exports and submit the case root hash or evidence report to
a qualified external timestamp/signature process.

## Features

- Add structured event entries from the CLI
- Store events as JSON
- Store timezone-aware ISO timestamps and Unix timestamps
- Record both event time and recorded-at time
- Assign schema versions and sequence numbers
- Protect event lists with a SHA-256 hash chain
- Sign hashes with HMAC-SHA-256
- Verify hash and signature integrity
- Generate evidence reports with a case root hash
- Export Markdown chronologies
- Run a local multi-user SQLite web interface
- First-run web setup for the first organization and admin PIN
- Manage multiple organizations
- Assign each organization to a domain such as foster care, general chronology or vehicle chronology
- Create multiple cases with separate entries
- Create foster-care case profiles with child/case metadata
- Record structured foster-care event fields
- Track attachment metadata with SHA-256 hashes
- Grant users organization and case roles
- Maintain user profiles with avatar URLs, titles and badges
- Track web actions in an HMAC-signed audit log

## Requirements

- Python 3.11+
- No third-party Python packages required

## Project Structure

```text
case-log/
  README.md
  CHANGELOG.md
  SECURITY.md
  case_log.py
  case_log_web.py
  case_log_webapp/
    bootstrap.py
    cli.py
    config.py
    crypto.py
    db.py
    models.py
    server.py
    views.py
  data/
    events.json
  examples/
    example_chronology.md
  .gitignore
```

## CLI Usage

Add an event:

```bash
python case_log.py add --title "Medical appointment" --category "medical" --people "Doctor, client" --note "Current condition was documented."
```

Add an event with an explicit event time:

```bash
python case_log.py add --title "Call" --note "Incoming call documented." --timestamp "2026-05-19T20:30:00+02:00"
```

List events:

```bash
python case_log.py list
```

Verify integrity:

```bash
python case_log.py verify --require-signatures
```

Sign existing events and create a local HMAC key when needed:

```bash
python case_log.py sign --init-key
```

Write an evidence report:

```bash
python case_log.py evidence --output evidence.json
```

Export a Markdown chronology:

```bash
python case_log.py export-md --output chronology.md
```

## Web Interface

The local web interface uses Python's standard library and SQLite. It is split
into modules under `case_log_webapp/` so the server, models, database, crypto
and views can be edited separately.

Events are organized by organization and case. System admins can manage
organizations. Organization owners/admins can manage users and cases inside
their organization. Regular users only see organizations and cases they are
assigned to.

Start the server and complete first-run setup in the browser:

```bash
python case_log_web.py serve --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/setup
```

The setup page creates the first organization and a system admin with a
4-digit PIN.

Initialize from the CLI instead:

```bash
python case_log_web.py init-db --organization "Acme Investigations" --admin-user admin --admin-pin 1234
```

Create another user:

```bash
python case_log_web.py create-user --username analyst --pin 2345 --display-name "Case Analyst" --organization-id 1 --org-role analyst
```

Set or reset a user's PIN:

```bash
python case_log_web.py set-pin --username analyst --pin 3456
```

Grant organization access:

```bash
python case_log_web.py grant-org --organization-id 1 --username analyst --role analyst
```

Grant case access:

```bash
python case_log_web.py grant-case --case-id 1 --username analyst --role member
```

## Data Format

Events in `data/events.json` contain:

- `schema_version`
- `sequence`
- `timestamp`
- `timestamp_unix`
- `recorded_at`
- `recorded_at_unix`
- `title`
- `category`
- `people`
- `note`
- `previous_hash`
- `hash`
- `signature`

The `hash` value is calculated from the event fields and the previous event
hash. Changing, removing or reordering entries breaks the chain.

The `signature` value is an HMAC-SHA-256 signature over the stored hash-chain
values. The signing key is read from `CASE_LOG_HMAC_KEY` or from
`data/.case-log-hmac-key`.

## Foster Care Domain

Organizations can be created with a domain. The first implemented domain is
`foster_care`. It adds:

- child or case subject metadata
- youth office, case worker, guardian and court reference fields
- school/daycare and medical contact fields
- foster-care event types such as contact, youth office, medical, school,
  behavior, crisis, development, handover and court
- priority values: `normal`, `important`, `critical`, `reportable`
- separated fields for quote, factual observation, assessment and action taken
- attachment metadata with filename, description, size and SHA-256 hash

The domain structure is intentionally generic enough to add other domains later,
for example `vehicle`.

## Evidence Workflow

1. Add events append-only.
2. Run `python case_log.py verify --require-signatures`.
3. Run `python case_log.py evidence --output evidence.json`.
4. Preserve `events.json`, `evidence.json`, exports and the reported case root
   hash.
5. Keep `data/.case-log-hmac-key` private and backed up securely.
6. For court-facing use, submit the evidence report or case root hash to an
   appropriate qualified external timestamp/signature process.

## Web Security

The web interface includes:

- Per-case access control through case memberships
- Per-organization access control through organization memberships
- PBKDF2-HMAC-SHA-256 password hashing
- HMAC-signed session cookies
- CSRF tokens for event creation
- Login rate limiting per username and client address
- Security headers for content type, framing, referrer handling and caching
- Request body size limits and form field length limits
- Append-only event records and append-only audit records

## Web Roles

System roles:

- `system_admin`: can create and manage organizations
- `user`: can work inside assigned organizations

Organization roles:

- `owner`: full organization control
- `admin`: user and case management
- `case_manager`: case management and entries
- `analyst`: create entries in accessible cases
- `viewer`: read-only organization access

Case roles:

- `owner`
- `member`
- `viewer`

For sensitive use, bind the server to `127.0.0.1`, use a strong HMAC key, keep
`data/.case-log-hmac-key` private, restrict filesystem access to `data/`, and
place the app behind a properly configured HTTPS reverse proxy before exposing it
to any network.

## Ignored Local Files

These files are intentionally not committed:

- `data/.case-log-hmac-key`
- `data/*.sqlite3`
- `data/*.log`
- `evidence.json`
- `chronology.md`

## Example Output

See:

```text
examples/example_chronology.md
```

## Roadmap

- Attachments with file hashes
- Case metadata
- Export bundles
- PDF export
- Optional integration with qualified timestamp/signature providers

## License

MIT

## Status

Early public version. The tool is intentionally small and dependency-free.
