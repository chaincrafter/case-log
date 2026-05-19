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