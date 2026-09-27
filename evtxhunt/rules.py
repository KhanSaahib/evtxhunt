"""A Sigma-inspired detection rule engine, expressed in JSON instead of YAML
so evtxhunt stays dependency-free (the Python standard library has no YAML
parser). This mirrors the same trade-off blue-forge's sigmajson tool made
for CloudTrail-style JSON logs; evtxhunt applies the same idea to normalized
Windows Event Log fields (EventID, Provider, Channel, EventData.*).

Rule shape::

    {
      "id": "win-encoded-powershell",
      "title": "PowerShell execution with an encoded command",
      "level": "high",
      "tags": ["attack.execution", "attack.t1059.001"],
      "logsource": {"channel": "Microsoft-Windows-PowerShell/Operational"},
      "detection": {
        "selection": {
          "EventID": 4104,
          "EventData.ScriptBlockText|contains": ["-EncodedCommand", "-enc "]
        },
        "condition": "selection"
      }
    }

Supported condition subset: a single selection name, "and"/"or" chains of
selection names (left-to-right, "and" binds tighter than "or"), an optional
single "and not <name>" tail, and "1 of <glob>" / "all of <glob>". No
parentheses - this is a documented subset, not full Sigma.

Field matching: EventID/Provider/Channel/Computer/RecordID read the
top-level normalized fields; anything else (bare or "EventData.X") reads
event["EventData"]. Values may be a single scalar or a list (list = OR).
A field key may carry one modifier: "|contains", "|startswith", "|endswith";
with no modifier, matching is case-insensitive with "*"/"?" wildcards.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

_TOP_LEVEL_FIELDS = {"EventID", "Provider", "Channel", "Computer", "RecordID", "TimeCreated"}


class RuleError(ValueError):
    pass


class Rule:
    def __init__(self, data: dict[str, Any], source_path: str | None = None):
        self.title = data.get("title", "untitled rule")
        self.id = data.get("id") or self.title
        self.description = data.get("description", "")
        self.level = data.get("level", "medium")
        self.tags = list(data.get("tags", []))
        self.logsource = data.get("logsource", {}) or {}
        self.detection = data.get("detection", {}) or {}
        self.source_path = source_path

        self.condition = self.detection.get("condition")
        if not self.condition:
            raise RuleError(f"rule {self.id!r} is missing detection.condition")
        self.selections = {k: v for k, v in self.detection.items() if k != "condition"}
        if not self.selections:
            raise RuleError(f"rule {self.id!r} has no selection blocks")

    def matches_logsource(self, event: dict[str, Any]) -> bool:
        channel = self.logsource.get("channel")
        if channel and event.get("Channel") != channel:
            return False
        provider = self.logsource.get("provider")
        if provider and event.get("Provider") != provider:
            return False
        return True

    def evaluate(self, event: dict[str, Any]) -> bool:
        if not self.matches_logsource(event):
            return False
        matched = {name: _selection_matches(event, sel) for name, sel in self.selections.items()}
        return _eval_condition(self.condition, matched)


def _get_field_value(event: dict[str, Any], field: str) -> Any:
    if field in _TOP_LEVEL_FIELDS:
        return event.get(field)
    if field.startswith("EventData."):
        field = field[len("EventData."):]
    return (event.get("EventData") or {}).get(field)


def _values_match(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False
    actual_str = str(actual).lower()
    expected_list = expected if isinstance(expected, list) else [expected]
    for exp in expected_list:
        exp_str = str(exp).lower()
        if modifier == "contains":
            if exp_str in actual_str:
                return True
        elif modifier == "startswith":
            if actual_str.startswith(exp_str):
                return True
        elif modifier == "endswith":
            if actual_str.endswith(exp_str):
                return True
        elif modifier is None:
            if fnmatch.fnmatch(actual_str, exp_str):
                return True
        else:
            raise RuleError(f"unsupported field modifier {modifier!r}")
    return False


def _selection_matches(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    if not selection:
        return False
    for field_key, expected in selection.items():
        field, _, modifier = field_key.partition("|")
        if not _values_match(_get_field_value(event, field), expected, modifier or None):
            return False
    return True


def _eval_condition(condition: str, matched: dict[str, bool]) -> bool:
    condition = condition.strip()

    lowered = condition.lower()
    if lowered.startswith("all of ") or lowered.startswith("1 of "):
        quantifier, _, pattern = condition.partition(" of ")
        names = [n for n in matched if fnmatch.fnmatch(n, pattern.strip())]
        if not names:
            return False
        if quantifier.strip().lower() == "all":
            return all(matched[n] for n in names)
        return any(matched[n] for n in names)

    def value_of(name: str) -> bool:
        name = name.strip()
        if name not in matched:
            raise RuleError(f"condition references unknown selection {name!r}")
        return matched[name]

    for or_term in condition.split(" or "):
        and_terms = or_term.strip().split(" and ")
        result = True
        for term in and_terms:
            term = term.strip()
            if term.lower().startswith("not "):
                result = result and (not value_of(term[4:]))
            else:
                result = result and value_of(term)
        if result:
            return True
    return False


def load_rules(rules_dir: str | Path) -> list[Rule]:
    rules = []
    for path in sorted(Path(rules_dir).glob("*.json")):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        rules.append(Rule(data, source_path=str(path)))
    return rules


def scan_events(events: list[dict[str, Any]], rules: list[Rule]) -> list[dict[str, Any]]:
    hits = []
    for event in events:
        for rule in rules:
            if rule.evaluate(event):
                hits.append({"rule": rule, "event": event})
    return hits
