#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
DATA_FILE = DATA_DIR / "events.json"


def load_events():
    if not DATA_FILE.exists():
        return []

    with DATA_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_events(events):
    DATA_DIR.mkdir(exist_ok=True)

    with DATA_FILE.open("w", encoding="utf-8") as file:
        json.dump(events, file, ensure_ascii=False, indent=2)


def add_event(args):
    events = load_events()

    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "title": args.title,
        "category": args.category,
        "people": args.people,
        "note": args.note,
    }

    events.append(event)
    save_events(events)

    print(f"Added event: {args.title}")


def list_events(_args):
    events = load_events()
    events.sort(key=lambda item: item["timestamp"])

    if not events:
        print("No events found.")
        return

    for event in events:
        print(f"{event['timestamp']} | {event['category']} | {event['title']}")

        if event.get("people"):
            print(f"  People: {event['people']}")

        if event.get("note"):
            print(f"  Note: {event['note']}")

        print()


def export_markdown(args):
    events = load_events()
    events.sort(key=lambda item: item["timestamp"])

    lines = ["# Event Chronology", ""]

    for event in events:
        lines.append(f"## {event['timestamp']} – {event['title']}")
        lines.append("")
        lines.append(f"**Category:** {event.get('category', '')}")
        lines.append("")

        if event.get("people"):
            lines.append(f"**People:** {event['people']}")
            lines.append("")

        if event.get("note"):
            lines.append(event["note"])
            lines.append("")

    output_path = Path(args.output)
    output_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Exported chronology to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Structured event documentation CLI")
    subparsers = parser.add_subparsers(required=True)

    add_parser = subparsers.add_parser("add", help="Add a new event")
    add_parser.add_argument("--title", required=True)
    add_parser.add_argument("--category", default="general")
    add_parser.add_argument("--people", default="")
    add_parser.add_argument("--note", required=True)
    add_parser.set_defaults(func=add_event)

    list_parser = subparsers.add_parser("list", help="List all events")
    list_parser.set_defaults(func=list_events)

    export_parser = subparsers.add_parser("export-md", help="Export events to Markdown")
    export_parser.add_argument("--output", default="chronology.md")
    export_parser.set_defaults(func=export_markdown)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()