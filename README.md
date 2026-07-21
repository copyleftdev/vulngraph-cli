# vulngraph

**Observe the exploitation evidence behind a CVE or package version — offline, in your terminal.**

[![Tip my tokens](https://tokentip.to/badge/copyleftdev.svg?logo=1)](https://tokentip.to/@copyleftdev)
[![CI](https://github.com/copyleftdev/vulngraph-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/copyleftdev/vulngraph-cli/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![data](https://img.shields.io/badge/data-vulngraph--data_releases-0969da)](https://github.com/copyleftdev/vulngraph-data/releases)
[![offline](https://img.shields.io/badge/checks-offline-2ea44f)](#guarantees)

`vulngraph` compiles current vulnerability observations into an auditable
local snapshot, then answers checks with zero network access. It does not
score reputation or call an API per lookup — it reports the **typed evidence**
behind a verdict: CISA KEV listing, public exploits, EPSS probability, CVSS
severity, ATT&CK mappings, and OSV version ranges.

```console
$ vulngraph CVE-2024-4577
  CVE-2024-4577
  verdict: ACTIVELY EXPLOITED  (confidence 0.99)
  action:  patch now
  reasons: CRITICAL_SEVERITY, KNOWN_EXPLOITED, MULTISOURCE_CORROBORATION, PUBLIC_EXPLOIT, …
  cvss:    9.8
  epss:    100.0%
  kev:     listed
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/copyleftdev/vulngraph-cli/main/scripts/install.sh | sh
vulngraph update      # download + verify the latest data release (~54 MB)
```

Prebuilt binaries: `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`. Or
`cargo install --git https://github.com/copyleftdev/vulngraph-cli`.

## The five commands

| Command | What it does |
|---|---|
| `vulngraph check <target>…` | Verdict + evidence for each target. `<target>` is `CVE-YYYY-NNNN` or `ecosystem:name@version` (e.g. `npm:lodash@4.17.20`). |
| `vulngraph status` | Installed snapshot, integrity, freshness. |
| `vulngraph update` | Download, verify, compile, and atomically activate a data release. `--offline-dir DIR` installs from local assets. |
| `vulngraph capabilities` | Commands, output schemas, guarantees, exit codes. |
| `vulngraph schema <name>` | Print a stable JSON Schema (`command`, `observation`, `status`). |

Global: `--json` (stable machine envelope), `--offline` (assert no network).
`vulngraph CVE-2024-4577` is shorthand for `vulngraph check …`.

## Verdicts

Severity-ordered, and **`unknown` is never rendered as clean** — absence of
evidence is reported as absence, not safety.

| Disposition | Meaning | Action |
|---|---|---|
| `actively-exploited` | CISA KEV listed | patch now |
| `weaponized` | public exploit + EPSS ≥ 0.9 | patch now |
| `proof-of-concept` | ≥1 public exploit | prioritize |
| `scored` | CVSS/EPSS present, no exploit | prioritize / monitor |
| `recorded` | in the graph, no risk signals | monitor |
| `not-affected` | package known, version outside every affected range | no action |
| `unknown` | not present in the snapshot | investigate |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success (including `unknown` / `not-affected` — the tool observes, it doesn't gate) |
| 1 | operational or integrity error (no snapshot, corrupt data) |
| 2 | invalid invocation (bad target) |
| 4 | dataset too stale (> 14 days) — `check` refuses to answer |

## Guarantees

- **Offline checks.** Only `update` touches the network. Everything else
  reads the local snapshot.
- **Verified data.** Every install verifies asset checksums, per-file
  hashes, and a recomputed snapshot identity against the release manifest,
  then sanity-opens the graph before activating. A failed update never
  replaces the last verified snapshot.
- **Deterministic.** Same snapshot + same target → same verdict. No clock,
  no randomness in the policy.
- **Stable JSON.** `--json` emits `vulngraph.command.v1` wrapping
  `vulngraph.observation.v1`; the shapes are versioned and validated in CI.

## Data provenance

Data is published by
[**vulngraph-data**](https://github.com/copyleftdev/vulngraph-data) as
immutable `data-YYYYMMDD` GitHub Releases aggregating CVE List V5, EPSS,
CISA KEV, ExploitDB / PoC-in-GitHub / Nuclei, MITRE ATT&CK, and OSV/GHSA.
This CLI installs those artifacts; it does not build the graph.

MIT licensed.
