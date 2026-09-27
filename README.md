# evtxhunt

A dependency-free Sigma-style detection engine and IR triage tool for
**Windows Event Log exports** (XML or JSONL) — pure Python standard library,
no installs required.

## Why this exists

The trending open-source EVTX hunters — [Chainsaw](https://github.com/WithSecureLabs/chainsaw),
[Hayabusa](https://github.com/Yamato-Security/hayabusa), and
[Zircolite](https://github.com/wagga40/zircolite) — are all excellent at
running Sigma-style rules against Windows Event Logs. But they all do the
same thing at the end: emit a flat list of rule hits and leave the analyst to
figure out which ones belong to the same incident.

evtxhunt does two things differently:

1. **No YAML dependency.** Detection rules are plain JSON, not Sigma's YAML.
   The Python standard library has no YAML parser, so this keeps the tool at
   zero third-party dependencies — the same trade-off this author's
   [`sigmajson`](https://github.com/KhanSaahib/blue-forge/tree/main/sigmajson)
   tool made for CloudTrail-style JSON logs. `sigmajson` explicitly scoped
   *out* Windows Event Logs in favor of cloud audit JSON, citing Chainsaw/
   Hayabusa/Zircolite as "the EVTX tools" — evtxhunt is the sibling that
   covers that gap for actual Windows Event Logs.
2. **Correlation, not just matching.** A single failed logon or a single
   RunAs event is noise. evtxhunt groups all rule hits on the same host
   within a rolling time window into one **incident**, and scores a host
   that trips *several distinct rules* (an attack chain) higher than a host
   that trips the same low-severity rule many times (background noise). That
   ordering — "review this host first" — is the thing an IR analyst actually
   needs, and none of the tools above provide it out of the box.

## What it does not do

evtxhunt does not parse raw binary `.evtx` files. Decoding EVTX's binary-XML
container is a significant undertaking on its own, and every real IR
workflow already has a one-line way to get XML or JSON out of an `.evtx`
file:

```powershell
# Windows Event XML (the schema evtxhunt expects)
wevtutil epl Security security.xml /f:xml -w:utf8n
# or, for a live query:
wevtutil qe Security /f:xml /c:1000 > security.xml
```

```bash
# or JSON Lines, e.g. via python-evtx's evtx_dump
evtx_dump --format jsonl Security.evtx > security.jsonl
```

evtxhunt picks up from there.

## Install

No install needed beyond a Python 3.10+ interpreter — everything is standard
library.

```bash
git clone https://github.com/KhanSaahib/evtxhunt.git
cd evtxhunt
python3 -m evtxhunt scan --help
```

## Usage

```bash
python3 -m evtxhunt scan security.xml system.xml \
    --window-minutes 15 \
    --format text
```

```
evtxhunt: scanned 4 events against 12 rules

[score  21] host=WORKSTATION01.corp.local hits=3 distinct_rules=3
    tags: attack.credential-access, attack.defense-evasion, attack.t1070.001, attack.t1110, attack.t1218
    - 2026-01-01T10:00:00.000000Z  [high] Living-off-the-land binary used for download/execute or encoded payloads (EventID 4688)
    - 2026-01-01T10:02:00.000000Z  [low] Failed logon attempt (EventID 4625)
    - 2026-01-01T10:05:00.000000Z  [critical] Windows Security or System event log was cleared (EventID 1102)
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--rules-dir PATH` | bundled `rules/` | directory of JSON detection rules to load |
| `--window-minutes N` | `15` | correlation window per host |
| `--format text\|json` | `text` | output format |
| `--out FILE` | stdout | write report to a file |
| `--min-score N` | `0` | drop incidents scoring below N |

Machine-readable output (`--format json`) is a list of incidents, each with
`host`, `score`, `hit_count`, `distinct_rules`, `attack_tags`, and the
individual `hits`.

## Writing detection rules

Rules live as `*.json` files in a rules directory (the bundled pack is in
[`rules/`](rules/)). Shape:

```json
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
```

- **Fields**: `EventID`, `Provider`, `Channel`, `Computer`, `RecordID` read
  the normalized top-level event; anything else (bare, or prefixed
  `EventData.`) reads that key out of the event's `EventData` map.
- **Values**: a scalar or a list (list = OR). No modifier means
  case-insensitive match with `*`/`?` wildcards; `|contains`, `|startswith`,
  `|endswith` do substring-style matching.
- **Selections**: any top-level key in `detection` other than `condition` is
  a named selection block; all fields inside one block are ANDed together.
- **Condition**: a documented *subset* of Sigma's condition language —
  a single name, `and`/`or` chains (left-to-right, `and` binds tighter than
  `or`), one optional trailing `and not <name>`, or `1 of <glob>` /
  `all of <glob>`. No parentheses.

This is intentionally a subset, not a full Sigma implementation — see
[NOTICE.md](NOTICE.md) for what it draws on and doesn't.

## Testing

```bash
python3 -m unittest discover -v
```

28 unit tests cover XML/JSONL normalization, rule matching (equality,
wildcards, modifiers, conditions, quantifiers), and the correlation/scoring
logic, using small inline fixtures under `tests/fixtures/`.
