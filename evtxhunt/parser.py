"""Normalize Windows Event Log exports (XML or JSONL) into a common event dict.

Supported inputs:
  * Windows Event XML - the schema produced by ``wevtutil epl <log> out.xml /f:xml``
    or PowerShell's ``Get-WinEvent | ForEach-Object { $_.ToXml() }``. Multiple
    ``<Event>`` fragments concatenated in one file (with or without a wrapping
    ``<Events>`` root, with or without repeated XML declarations) are all
    accepted.
  * JSON Lines - one normalized-ish JSON object per line, for logs already
    converted by another tool (e.g. python-evtx's evtx_dump --format jsonl).

Raw binary .evtx files are intentionally out of scope: decoding the EVTX
binary-XML container is a large undertaking on its own, and every common IR
workflow already has a trivial way to get XML or JSON out of an .evtx file
(wevtutil, Get-WinEvent, evtx_dump). evtxhunt starts from there.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

_XML_DECL_RE = re.compile(r"<\?xml[^>]*\?>")

_NORMALIZED_KEYS = ("EventID", "Provider", "Channel", "Computer", "TimeCreated", "RecordID")


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _to_int(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def _empty_event() -> dict[str, Any]:
    return {
        "EventID": None,
        "Provider": None,
        "Channel": None,
        "Computer": None,
        "TimeCreated": None,
        "RecordID": None,
        "EventData": {},
    }


def _normalize_event_element(event_el: ET.Element) -> dict[str, Any]:
    normalized = _empty_event()
    system_el = None
    data_el = None
    for child in event_el:
        tag = _strip_ns(child.tag)
        if tag == "System":
            system_el = child
        elif tag in ("EventData", "UserData"):
            data_el = child

    if system_el is not None:
        for child in system_el:
            tag = _strip_ns(child.tag)
            if tag == "EventID":
                normalized["EventID"] = _to_int(child.text)
            elif tag == "Provider":
                normalized["Provider"] = child.attrib.get("Name")
            elif tag == "Channel":
                normalized["Channel"] = child.text
            elif tag == "Computer":
                normalized["Computer"] = child.text
            elif tag == "TimeCreated":
                normalized["TimeCreated"] = child.attrib.get("SystemTime")
            elif tag == "EventRecordID":
                normalized["RecordID"] = _to_int(child.text)

    if data_el is not None:
        for item in data_el:
            tag = _strip_ns(item.tag)
            if tag == "Data":
                name = item.attrib.get("Name")
                if name:
                    normalized["EventData"][name] = item.text
                else:
                    normalized["EventData"].setdefault("_", []).append(item.text)
            elif len(item):
                for sub in item.iter():
                    sub_tag = _strip_ns(sub.tag)
                    if sub_tag != tag and sub.text and sub.text.strip():
                        normalized["EventData"][sub_tag] = sub.text
            elif item.text and item.text.strip():
                normalized["EventData"][tag] = item.text

    return normalized


def parse_xml_events(text: str) -> list[dict[str, Any]]:
    text = _XML_DECL_RE.sub("", text).strip()
    if not text:
        return []
    try:
        root = ET.fromstring(f"<EvtxHuntRoot>{text}</EvtxHuntRoot>")
    except ET.ParseError as exc:
        raise ValueError(f"failed to parse Windows Event XML: {exc}") from exc

    events = []
    for el in root.iter():
        if _strip_ns(el.tag) == "Event":
            events.append(_normalize_event_element(el))
    return events


def _normalize_json_event(obj: dict[str, Any]) -> dict[str, Any]:
    normalized = _empty_event()
    for key in _NORMALIZED_KEYS:
        if key in obj:
            normalized[key] = obj[key]
    normalized["EventData"] = obj.get("EventData") or {}
    return normalized


def parse_jsonl_events(text: str) -> list[dict[str, Any]]:
    events = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on line {line_num}: {exc}") from exc
        events.append(_normalize_json_event(obj))
    return events


def load_events(path: str | Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("<"):
        return parse_xml_events(text)
    return parse_jsonl_events(text)
