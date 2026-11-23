#!/usr/bin/env python3
"""Offline explorer for the VGK research notebook.

The tool parses research-notes.txt directly so the catalog always remains tied
to the complete, untouched source record. It performs no driver interaction.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NOTES = ROOT / "research-notes.txt"
MANIFEST = ROOT / "research-manifest.json"
EVENT_RE = re.compile(
    r"^(0x(?:b000|1000|e000)[0-9a-f]{4}(?:\s*(?:/|,|\.\.)\s*0x(?:b000|1000|e000)[0-9a-f]{4})*)\s+—\s+(.+)$",
    re.I,
)
IOCTL_RE = re.compile(
    r"^(0x22c[0-9a-f]{3})(?:\s+\.\.\s+(0x22c[0-9a-f]{3}))?(?:\s+\([^)]*\))?\s+—\s+(.+)$",
    re.I,
)


def read_lines() -> list[str]:
    return NOTES.read_text(encoding="utf-8").splitlines()


def events() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    in_catalog = False
    for line in read_lines():
        if line.startswith("9.1 "):
            in_catalog = True
            continue
        if line.startswith("9.2 "):
            break
        if not in_catalog:
            continue
        match = EVENT_RE.match(line)
        if match:
            out.append({"code": match.group(1), "description": match.group(2)})
    return out


def ioctls() -> list[dict[str, str | None]]:
    out: list[dict[str, str | None]] = []
    in_catalog = False
    for line in read_lines():
        if line.startswith("9.2 "):
            in_catalog = True
            continue
        if not in_catalog:
            continue
        match = IOCTL_RE.match(line)
        if match:
            out.append({"start": match.group(1), "end": match.group(2), "description": match.group(3)})
    return out


def print_records(records: list[dict[str, object]]) -> None:
    for record in records:
        key = record.get("code") or record.get("start")
        end = record.get("end")
        label = f"{key}..{end}" if end else str(key)
        print(f"{label:24} {record['description']}")


def command_summary(_: argparse.Namespace) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\nparsed event catalog rows: {len(events())}")
    print(f"parsed IOCTL catalog rows: {len(ioctls())}")


def command_events(args: argparse.Namespace) -> None:
    records = events()
    if args.family:
        needle = args.family.lower()
        records = [item for item in records if item["code"].lower().startswith(needle)]
    if args.query:
        needle = args.query.lower()
        records = [item for item in records if needle in (item["code"] + " " + item["description"]).lower()]
    print_records(records)


def command_ioctls(args: argparse.Namespace) -> None:
    records = ioctls()
    if args.query:
        needle = args.query.lower()
        records = [item for item in records if needle in " ".join(str(value) for value in item.values()).lower()]
    print_records(records)


def command_search(args: argparse.Namespace) -> None:
    needle = args.query.lower()
    for number, line in enumerate(read_lines(), 1):
        if needle in line.lower():
            print(f"{number:04d}: {line}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Explore the VGK research notebook offline")
    sub = parser.add_subparsers(dest="command", required=True)

    summary = sub.add_parser("summary", help="show build identity and headline measurements")
    summary.set_defaults(func=command_summary)

    event_cmd = sub.add_parser("events", help="list or filter documented telemetry events")
    event_cmd.add_argument("--family", help="prefix such as 0xb000, 0x1000, or 0xe000")
    event_cmd.add_argument("--query", help="case-insensitive code or description filter")
    event_cmd.set_defaults(func=command_events)

    ioctl_cmd = sub.add_parser("ioctls", help="list or filter documented IOCTL rows")
    ioctl_cmd.add_argument("--query", help="case-insensitive code or description filter")
    ioctl_cmd.set_defaults(func=command_ioctls)

    search = sub.add_parser("search", help="search every source-note line")
    search.add_argument("query")
    search.set_defaults(func=command_search)
    return parser


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

