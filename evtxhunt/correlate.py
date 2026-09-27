"""Group flat rule hits into scored, per-host incidents.

Chainsaw, Hayabusa and Zircolite (the trending open-source EVTX hunters this
tool draws inspiration from) all emit a flat list of rule hits and leave the
analyst to work out which ones belong to the same incident. evtxhunt's one
opinionated addition is this module: hits on the same host within a rolling
time window are grouped, and a group that trips *multiple distinct rules*
(more of an attack chain than a single noisy signature) is scored higher -
that ordering is the thing an IR analyst actually wants to triage first.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

LEVEL_SCORES = {"informational": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}
_DISTINCT_RULE_BONUS = 2


def _parse_time(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _build_incident(host: str, group: list[dict[str, Any]]) -> dict[str, Any]:
    rule_ids = sorted({h["rule"].id for h in group})
    tags = sorted({t for h in group for t in h["rule"].tags})
    score = sum(LEVEL_SCORES.get(h["rule"].level, 1) for h in group)
    if len(rule_ids) > 1:
        score += _DISTINCT_RULE_BONUS * (len(rule_ids) - 1)
    return {
        "host": host,
        "hit_count": len(group),
        "distinct_rules": rule_ids,
        "attack_tags": tags,
        "score": score,
        "hits": group,
    }


def correlate(hits: list[dict[str, Any]], window_minutes: int = 15) -> list[dict[str, Any]]:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for hit in hits:
        host = hit["event"].get("Computer") or "unknown"
        by_host.setdefault(host, []).append(hit)

    window = timedelta(minutes=window_minutes)
    incidents = []
    for host, host_hits in by_host.items():
        timed = sorted(
            ((_parse_time(h["event"].get("TimeCreated")), h) for h in host_hits),
            key=lambda pair: (pair[0] is None, pair[0]),
        )

        group: list[dict[str, Any]] = []
        anchor: datetime | None = None
        for t, h in timed:
            if not group:
                group, anchor = [h], t
                continue
            if t is None or anchor is None or t - anchor <= window:
                group.append(h)
            else:
                incidents.append(_build_incident(host, group))
                group, anchor = [h], t
        if group:
            incidents.append(_build_incident(host, group))

    incidents.sort(key=lambda inc: inc["score"], reverse=True)
    return incidents
