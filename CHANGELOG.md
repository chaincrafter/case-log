# Changelog

All notable changes to this project are documented here.

## Unreleased

### Added

- SHA-256 hash chain for event integrity checks
- HMAC-SHA-256 signatures for signed event lists
- `verify` command for integrity and signature verification
- `sign` command for signing existing events
- `evidence` command with a case root hash report
- Timezone-aware ISO timestamps, Unix timestamps and recorded-at fields
- Sequence numbers and schema versioning for event records
- Local SQLite web interface with multi-user login
- `create-user` command for additional web users
- Multiple database-backed cases with separate event views
- Case membership access control for regular users
- `grant-user` command for assigning users to cases
- PBKDF2-HMAC-SHA-256 password hashing for web users
- HMAC-signed web session cookies
- HMAC-signed web event chain and audit log
- Dark terminal-style web interface
- CSRF tokens for event creation
- Login rate limiting per username and client address
- Security headers and form size limits
- `SECURITY.md` with operational security guidance
- Updated example chronology for the forensic export format

### Changed

- Existing sample events were migrated to schema version 2
- Markdown export now includes sequence numbers, Unix time, recorded-at time and event hashes
- README was reorganized around CLI usage, web usage, evidence workflow and security

## v0.1.0 - 2026-05-19

### Added

- Initial CLI version
- Add event command
- Chronological event listing
- Markdown export
- JSON-based local storage
- Example chronology
- Basic README
