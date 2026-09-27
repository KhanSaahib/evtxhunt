# Notice / Attributions

evtxhunt is original code written for this repository. No third-party source
code was copied into this project. The following prior art informed its
design; each is credited for the *idea*, not for any reused code or text.

## Design inspiration (ideas only, no code or rule text copied)

- **[Chainsaw](https://github.com/WithSecureLabs/chainsaw)** (WithSecure Labs,
  GPL-3.0) — established the idea of running Sigma-style detections directly
  against Windows Event Logs for fast IR triage. evtxhunt's scope (detect
  over EVTX-derived events) follows this pattern; no Chainsaw source or rule
  content was copied.
- **[Hayabusa](https://github.com/Yamato-Security/hayabusa)** (Yamato
  Security, GPL-3.0 / AGPL-3.0 for bundled rules) — informed the idea of
  scoring/leveling hits by severity. No source or rules copied.
- **[Zircolite](https://github.com/wagga40/zircolite)** (wagga40, GPL-3.0) —
  informed the general "Sigma rules over EVTX-as-structured-data" approach.
  No source or rules copied.
- **[SigmaHQ](https://github.com/SigmaHQ/sigma)** (Detection Rule License
  1.1) — the well-known public detection *concepts* bundled in `rules/`
  (e.g. flagging `-EncodedCommand` PowerShell, RC4 Kerberos tickets as a
  Kerberoasting indicator, service installs with shell binaries, audit log
  clearing) reflect widely documented, generic Windows detection engineering
  knowledge. No SigmaHQ rule YAML, text, or other source was copied,
  translated, or derived from field-by-field; each JSON rule in this repo
  was written from scratch against evtxhunt's own schema.
- **[`sigmajson`](https://github.com/KhanSaahib/blue-forge/tree/main/sigmajson)**
  (same author, part of the `blue-forge` repo) — evtxhunt reuses the
  "JSON instead of YAML, to stay dependency-free" design decision from this
  sibling project. No code shared between the two repos; each has its own
  independent implementation for its own log format.

## Why no code was copied

Chainsaw, Hayabusa, and Zircolite are GPL-3.0/AGPL-3.0 licensed, and SigmaHQ's
rule corpus carries the Detection Rule License (DRL) 1.1, which restricts
commercial resale of the rules themselves. To avoid any licensing
entanglement, evtxhunt's parser, rule engine, correlation logic, and bundled
rule pack are all original implementations written for this repository, not
copies, translations, or line-by-line derivations of any of the above.

## Third-party runtime dependencies

None. evtxhunt uses only the Python 3 standard library (`argparse`, `json`,
`fnmatch`, `pathlib`, `xml.etree.ElementTree`, `datetime`).
