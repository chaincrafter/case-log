#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime
from pathlib import Path

DATA_DIR = Path("data")
DATA_FILE = DATA_DIR / "events.json"
HMAC_KEY_FILE = DATA_DIR / ".case-log-hmac-key"
SCHEMA_VERSION = 2
HASH_FIELDS = (
    "schema_version",
    "sequence",
    "timestamp",
    "timestamp_unix",
    "recorded_at",
    "recorded_at_unix",
    "title",
    "category",
    "people",
    "note",
)
EMPTY_HASH = ""
HMAC_KEY_ENV = "CASE_LOG_HMAC_KEY"


def load_events():
    if not DATA_FILE.exists():
        return []

    with DATA_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_events(events):
    DATA_DIR.mkdir(exist_ok=True)

    with DATA_FILE.open("w", encoding="utf-8") as file:
        json.dump(events, file, ensure_ascii=False, indent=2)
        file.write("\n")


def now_local():
    return datetime.now().astimezone()


def parse_local_datetime(value):
    if not value:
        return now_local()

    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        return parsed.astimezone()

    return parsed.astimezone()


def timestamp_pair(value=""):
    parsed = parse_local_datetime(value)

    return parsed.isoformat(timespec="seconds"), int(parsed.timestamp())


def canonical_event(event):
    return {field: event.get(field, "") for field in HASH_FIELDS}


def encode_payload(payload):
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def calculate_event_hash(event, previous_hash):
    payload = {
        "event": canonical_event(event),
        "previous_hash": previous_hash,
    }

    return hashlib.sha256(encode_payload(payload)).hexdigest()


def get_hmac_key():
    key = os.environ.get(HMAC_KEY_ENV)

    if key:
        return key

    if HMAC_KEY_FILE.exists():
        return HMAC_KEY_FILE.read_text(encoding="utf-8").strip()

    return ""


def create_hmac_key():
    DATA_DIR.mkdir(exist_ok=True)

    if HMAC_KEY_FILE.exists():
        return get_hmac_key()

    key = secrets.token_urlsafe(48)
    HMAC_KEY_FILE.write_text(f"{key}\n", encoding="utf-8")

    return key


def calculate_event_signature(event, hmac_key):
    payload = {
        "hash": event.get("hash", ""),
        "previous_hash": event.get("previous_hash", ""),
    }

    return hmac.new(
        hmac_key.encode("utf-8"),
        encode_payload(payload),
        hashlib.sha256,
    ).hexdigest()


def calculate_case_root(events):
    payload = {
        "event_count": len(events),
        "events": [
            {
                "sequence": event.get("sequence", ""),
                "hash": event.get("hash", ""),
                "signature": event.get("signature", ""),
            }
            for event in events
        ],
        "schema_version": SCHEMA_VERSION,
    }

    return hashlib.sha256(encode_payload(payload)).hexdigest()


def normalize_event(event, sequence):
    normalized = dict(event)
    event_time, event_time_unix = timestamp_pair(
        normalized.get("timestamp") or normalized.get("event_time", "")
    )
    recorded_at, recorded_at_unix = timestamp_pair(normalized.get("recorded_at", event_time))

    normalized["schema_version"] = SCHEMA_VERSION
    normalized["sequence"] = sequence
    normalized["timestamp"] = event_time
    normalized["timestamp_unix"] = event_time_unix
    normalized["recorded_at"] = recorded_at
    normalized["recorded_at_unix"] = recorded_at_unix
    normalized.setdefault("title", "")
    normalized.setdefault("category", "general")
    normalized.setdefault("people", "")
    normalized.setdefault("note", "")

    return normalized


def normalize_events(events):
    return [normalize_event(event, index) for index, event in enumerate(events, start=1)]


def apply_hash_chain(events, hmac_key=""):
    previous_hash = EMPTY_HASH

    for index, event in enumerate(events, start=1):
        event["sequence"] = index
        event["previous_hash"] = previous_hash
        event["hash"] = calculate_event_hash(event, previous_hash)

        if hmac_key:
            event["signature"] = calculate_event_signature(event, hmac_key)

        previous_hash = event["hash"]


def verify_events(events, hmac_key="", require_signatures=False):
    errors = []
    previous_hash = EMPTY_HASH
    has_signatures = any(event.get("signature") for event in events)
    check_signatures = require_signatures or has_signatures

    for index, event in enumerate(events, start=1):
        expected_previous_hash = previous_hash
        expected_hash = calculate_event_hash(event, expected_previous_hash)

        if event.get("schema_version") != SCHEMA_VERSION:
            errors.append(
                f"Event {index} ({event.get('title', 'untitled')}): schema_version mismatch"
            )

        if event.get("sequence") != index:
            errors.append(f"Event {index} ({event.get('title', 'untitled')}): sequence mismatch")

        if event.get("previous_hash") != expected_previous_hash:
            errors.append(
                f"Event {index} ({event.get('title', 'untitled')}): previous_hash mismatch"
            )

        if event.get("hash") != expected_hash:
            errors.append(f"Event {index} ({event.get('title', 'untitled')}): hash mismatch")

        if check_signatures:
            if not hmac_key:
                errors.append(
                    f"Event {index} ({event.get('title', 'untitled')}): "
                    f"signature cannot be verified without {HMAC_KEY_ENV} or {HMAC_KEY_FILE}"
                )
            elif not event.get("signature"):
                errors.append(
                    f"Event {index} ({event.get('title', 'untitled')}): signature missing"
                )
            else:
                expected_signature = calculate_event_signature(
                    {
                        "hash": expected_hash,
                        "previous_hash": expected_previous_hash,
                    },
                    hmac_key,
                )

                if not hmac.compare_digest(event["signature"], expected_signature):
                    errors.append(
                        f"Event {index} ({event.get('title', 'untitled')}): "
                        "signature mismatch"
                    )

        previous_hash = event.get("hash", "")

    return errors


def require_valid_events(events):
    errors = verify_events(events, get_hmac_key())

    if errors:
        print("Integrity check failed. The event list may have been changed.")

        for error in errors:
            print(f"- {error}")

        raise SystemExit(1)


def add_event(args):
    events = normalize_events(load_events())
    require_valid_events(events)
    hmac_key = get_hmac_key() or create_hmac_key()
    event_time, event_time_unix = timestamp_pair(args.timestamp)
    recorded_at, recorded_at_unix = timestamp_pair()

    event = {
        "schema_version": SCHEMA_VERSION,
        "sequence": len(events) + 1,
        "timestamp": event_time,
        "timestamp_unix": event_time_unix,
        "recorded_at": recorded_at,
        "recorded_at_unix": recorded_at_unix,
        "title": args.title,
        "category": args.category,
        "people": args.people,
        "note": args.note,
    }

    events.append(event)
    apply_hash_chain(events, hmac_key)
    save_events(events)

    print(f"Added event: {args.title}")


def list_events(_args):
    events = normalize_events(load_events())
    require_valid_events(events)
    events.sort(key=lambda item: item["sequence"])

    if not events:
        print("No events found.")
        return

    for event in events:
        print(
            f"#{event['sequence']} | {event['timestamp']} | "
            f"{event['category']} | {event['title']}"
        )

        if event.get("people"):
            print(f"  People: {event['people']}")

        if event.get("note"):
            print(f"  Note: {event['note']}")

        print(f"  Hash: {event.get('hash', '')}")
        print()


def export_markdown(args):
    events = normalize_events(load_events())
    require_valid_events(events)
    events.sort(key=lambda item: item["sequence"])

    lines = ["# Event Chronology", ""]

    for event in events:
        lines.append(f"## #{event['sequence']} {event['timestamp']} - {event['title']}")
        lines.append("")
        lines.append(f"**Category:** {event.get('category', '')}")
        lines.append("")
        lines.append(f"**Unix time:** {event.get('timestamp_unix', '')}")
        lines.append("")
        lines.append(f"**Recorded at:** {event.get('recorded_at', '')}")
        lines.append("")

        if event.get("people"):
            lines.append(f"**People:** {event['people']}")
            lines.append("")

        if event.get("note"):
            lines.append(event["note"])
            lines.append("")

        lines.append(f"**Hash:** `{event.get('hash', '')}`")
        lines.append("")

    output_path = Path(args.output)
    output_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Exported chronology to {output_path}")


def build_evidence():
    events = normalize_events(load_events())
    require_valid_events(events)
    verified_at, verified_at_unix = timestamp_pair()

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": verified_at,
        "generated_at_unix": verified_at_unix,
        "event_count": len(events),
        "first_event_timestamp": events[0]["timestamp"] if events else "",
        "last_event_timestamp": events[-1]["timestamp"] if events else "",
        "case_root_hash": calculate_case_root(events),
        "last_event_hash": events[-1]["hash"] if events else "",
        "all_events_signed": all(event.get("signature") for event in events),
        "events": [
            {
                "sequence": event["sequence"],
                "timestamp": event["timestamp"],
                "timestamp_unix": event["timestamp_unix"],
                "hash": event["hash"],
                "signature": event.get("signature", ""),
            }
            for event in events
        ],
    }


def write_evidence(args):
    evidence = build_evidence()
    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Wrote evidence report to {output_path}")
    print(f"Case root hash: {evidence['case_root_hash']}")


def verify_hashes(_args):
    events = normalize_events(load_events())
    hmac_key = get_hmac_key()
    errors = verify_events(events, hmac_key, _args.require_signatures)

    if errors:
        print("Integrity check failed. The event list may have been changed.")

        for error in errors:
            print(f"- {error}")

        raise SystemExit(1)

    print(f"Case root hash: {calculate_case_root(events)}")

    if any(event.get("signature") for event in events):
        print(f"Integrity and signature check passed for {len(events)} event(s).")
    else:
        print(f"Integrity check passed for {len(events)} event(s). No signatures found.")


def sign_events(args):
    events = normalize_events(load_events())
    hmac_key = get_hmac_key()

    if not hmac_key and args.init_key:
        hmac_key = create_hmac_key()

    if not hmac_key:
        print(f"No HMAC key found. Set {HMAC_KEY_ENV} or run: python case_log.py sign --init-key")
        raise SystemExit(1)

    apply_hash_chain(events, hmac_key)
    save_events(events)

    print(f"Signed {len(events)} event(s) with HMAC.")
    print(f"Case root hash: {calculate_case_root(events)}")


def main():
    parser = argparse.ArgumentParser(description="Structured event documentation CLI")
    subparsers = parser.add_subparsers(required=True)

    add_parser = subparsers.add_parser("add", help="Add a new event")
    add_parser.add_argument("--title", required=True)
    add_parser.add_argument("--category", default="general")
    add_parser.add_argument("--people", default="")
    add_parser.add_argument("--note", required=True)
    add_parser.add_argument(
        "--timestamp",
        default="",
        help="Event time as ISO 8601. Defaults to current local time.",
    )
    add_parser.set_defaults(func=add_event)

    list_parser = subparsers.add_parser("list", help="List all events")
    list_parser.set_defaults(func=list_events)

    verify_parser = subparsers.add_parser("verify", help="Verify event hash chain")
    verify_parser.add_argument(
        "--require-signatures",
        action="store_true",
        help="Fail when events are not HMAC-signed",
    )
    verify_parser.set_defaults(func=verify_hashes)

    sign_parser = subparsers.add_parser("sign", help="Sign all events with HMAC")
    sign_parser.add_argument(
        "--init-key",
        action="store_true",
        help=f"Create {HMAC_KEY_FILE} when no HMAC key exists",
    )
    sign_parser.set_defaults(func=sign_events)

    evidence_parser = subparsers.add_parser("evidence", help="Write an evidence report")
    evidence_parser.add_argument("--output", default="evidence.json")
    evidence_parser.set_defaults(func=write_evidence)

    export_parser = subparsers.add_parser("export-md", help="Export events to Markdown")
    export_parser.add_argument("--output", default="chronology.md")
    export_parser.set_defaults(func=export_markdown)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
