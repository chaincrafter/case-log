# case-log

A small CLI tool for structured event documentation.

`case-log` helps create clean chronological event logs for procedures, appointments, meetings and case preparation.

## Useful for

- case chronologies
- meeting notes
- medical appointment logs
- administrative procedures
- legal preparation timelines

## Features

- Add structured event entries
- Store events as JSON
- List events chronologically
- Export a clean Markdown chronology
- Protect the event list with a SHA-256 hash chain
- Verify that stored events were not changed afterwards
- Sign the hash chain with HMAC-SHA-256

## Requirements

- Python 3.11+

## Project structure

```text
case-log/
  README.md
  case_log.py
  data/
    events.json
  examples/
    example_chronology.md
  .gitignore
```

## Usage

Add an event:

```bash
python case_log.py add --title "Medical appointment" --category "medical" --people "Doctor, client" --note "Current condition was documented."
```

List all events:

```bash
python case_log.py list
```

Verify the event list:

```bash
python case_log.py verify
```

Require HMAC signatures during verification:

```bash
python case_log.py verify --require-signatures
```

Sign existing events and create a local HMAC key when needed:

```bash
python case_log.py sign --init-key
```

Export a Markdown chronology:

```bash
python case_log.py export-md --output chronology.md
```

## Data format

Events are stored in `data/events.json`.

Each event contains:

- `timestamp`
- `title`
- `category`
- `people`
- `note`
- `previous_hash`
- `hash`
- `signature`

The `hash` value is calculated from the event fields and the previous event hash.
Changing, removing or reordering entries breaks the chain and is reported by:

```bash
python case_log.py verify
```

The optional `signature` value is an HMAC-SHA-256 signature over the stored hash
chain values. The signing key is read from `CASE_LOG_HMAC_KEY` or from the local
file `data/.case-log-hmac-key`. The local key file is ignored by Git and must be
kept private. Run this once to sign existing data:

```bash
python case_log.py sign --init-key
```

After a key exists, newly added events are signed automatically.

## Example output

See:

```text
examples/example_chronology.md
```

## Roadmap

- Tags
- Deadlines
- Attachments
- YAML configuration
- PDF export

## License

MIT

## Status

Early public version. The tool is intentionally small and dependency-free.
