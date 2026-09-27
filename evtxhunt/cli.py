from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .correlate import correlate
from .parser import load_events
from .rules import load_rules, scan_events

_BUNDLED_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evtxhunt",
        description="Sigma-style detection and IR triage for Windows Event Log exports (XML/JSONL).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan event log export(s) against a rule pack")
    scan.add_argument("logs", nargs="+", help="Windows Event XML or JSONL export file(s)")
    scan.add_argument(
        "--rules-dir",
        default=None,
        help=f"directory of JSON detection rules (default: bundled pack at {_BUNDLED_RULES_DIR})",
    )
    scan.add_argument(
        "--window-minutes",
        type=int,
        default=15,
        help="correlation time window in minutes (default: 15)",
    )
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--out", default=None, help="write report to this file instead of stdout")
    scan.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="only report incidents at or above this score (default: 0, i.e. all)",
    )
    return parser


def _incidents_to_json(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for inc in incidents:
        out.append(
            {
                "host": inc["host"],
                "score": inc["score"],
                "hit_count": inc["hit_count"],
                "distinct_rules": inc["distinct_rules"],
                "attack_tags": inc["attack_tags"],
                "hits": [
                    {
                        "rule_id": h["rule"].id,
                        "title": h["rule"].title,
                        "level": h["rule"].level,
                        "time": h["event"].get("TimeCreated"),
                        "event_id": h["event"].get("EventID"),
                    }
                    for h in inc["hits"]
                ],
            }
        )
    return out


def _render_text(incidents: list[dict[str, Any]], event_count: int, rule_count: int) -> str:
    lines = [f"evtxhunt: scanned {event_count} events against {rule_count} rules", ""]
    if not incidents:
        lines.append("No correlated incidents above threshold.")
        return "\n".join(lines)
    for inc in incidents:
        lines.append(
            f"[score {inc['score']:>3}] host={inc['host']} "
            f"hits={inc['hit_count']} distinct_rules={len(inc['distinct_rules'])}"
        )
        if inc["attack_tags"]:
            lines.append(f"    tags: {', '.join(inc['attack_tags'])}")
        for h in inc["hits"]:
            lines.append(
                f"    - {h['event'].get('TimeCreated', '?')}  [{h['rule'].level}] "
                f"{h['rule'].title} (EventID {h['event'].get('EventID')})"
            )
        lines.append("")
    return "\n".join(lines)


def run_scan(args: argparse.Namespace) -> int:
    rules_dir = args.rules_dir or _BUNDLED_RULES_DIR
    rules = load_rules(rules_dir)
    if not rules:
        print(f"evtxhunt: no rules loaded from {rules_dir}", file=sys.stderr)
        return 2

    events = []
    for log_path in args.logs:
        events.extend(load_events(log_path))

    hits = scan_events(events, rules)
    incidents = [i for i in correlate(hits, window_minutes=args.window_minutes) if i["score"] >= args.min_score]

    if args.format == "json":
        output = json.dumps(_incidents_to_json(incidents), indent=2)
    else:
        output = _render_text(incidents, len(events), len(rules))

    if args.out:
        Path(args.out).write_text(output + "\n")
    else:
        print(output)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
