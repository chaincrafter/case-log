# Security

`case-log` is built for local forensic documentation and tamper detection. It
can support chain-of-custody workflows, but it does not replace qualified
electronic timestamps, qualified electronic signatures, qualified seals or legal
review.

## Local Secrets

Keep this file private and backed up securely:

```text
data/.case-log-hmac-key
```

Anyone with write access to the event data and the HMAC key can recalculate
valid signatures. Restrict filesystem access to the project directory,
especially `data/`.

You can also provide the key through:

```text
CASE_LOG_HMAC_KEY
```

## Web Deployment

For sensitive use:

- Bind the app to `127.0.0.1` unless it is behind a hardened reverse proxy
- Use HTTPS before exposing the app to any network
- Treat the current 4-digit PIN mode as local-only convenience, not public-facing authentication
- Use organization roles conservatively and grant only the minimum required rights
- Grant regular users access only to the cases they need
- Keep the SQLite database and HMAC key out of Git
- Back up `data/events.json`, `data/*.sqlite3`, exports and the HMAC key
- Preserve generated evidence reports and case root hashes
- Store attachment files in a controlled location and enter their SHA-256 hashes
  in the attachment metadata
- Verify regularly with `python case_log.py verify --require-signatures`

## Built-In Protections

- SHA-256 event hash chain
- HMAC-SHA-256 signatures
- PBKDF2-HMAC-SHA-256 password hashing for web users
- HMAC-signed session cookies
- Organization-level role management
- Per-case access control through case memberships
- Attachment metadata with SHA-256 hashes
- CSRF token checks for event creation
- Login rate limiting
- Append-only event and audit records
- Security headers for the web interface
- Request body and form field limits

## Known Limits

- Local system time can be wrong or manipulated
- Local HMAC signatures do not prove an external trusted time
- SQLite file permissions depend on the host operating system
- The web server is intentionally minimal and should not be exposed directly to
  the public internet
- Four-digit PINs are intentionally easy to use but weak against online guessing
  without strict deployment controls
- Court acceptance depends on jurisdiction, procedure, chain of custody and
  external validation

For court-facing workflows, submit the case root hash or evidence report to an
appropriate qualified timestamp/signature process outside this local tool.
