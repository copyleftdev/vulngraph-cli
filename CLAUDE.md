# CLAUDE.md

Guidance for Claude Code working in this repository.

## What This Is

`vulngraph` is a focused, public CLI for vulnerability intelligence, built on
the KiloCheck pattern. It consumes published data releases and answers checks
offline. It is the read/query/policy/render layer only — it never produces
graph data and never depends on the private `vulngraph` engine repo.

Three crates, linear dependency stack:
- `vulngraph-core` — serde-only stable contracts (envelope, target grammar,
  verdict policy, release manifest). Leaf; `#![forbid(unsafe_code)]`.
- `vulngraph-dataset` — update/verify/install + the vendored engine read path
  + query engine. `#![deny(unsafe_code)]` with one scoped `#[allow]`.
- `vulngraph-cli` — clap surface, rendering, exit codes. Binary `vulngraph`;
  `#![forbid(unsafe_code)]`.

## The Five-Command Discipline (Non-Negotiable)

The command surface is exactly: `check`, `status`, `update`, `capabilities`,
`schema`. Do not add commands (no `scan`, no config file, no server mode).
Focus is the product. New evidence sources extend `check` output; they do not
add verbs.

## Three External SYNC Points

This CLI vendors code from two other repos. Each vendored file carries a
`SYNC:` header. Changing the upstream requires propagating here, and any
on-disk-format change gates a `format_version` bump in the release manifest
(which `update` checks before installing).

1. **Engine read path** — `crates/vulngraph-dataset/src/engine/{types,storage,index,graph}.rs`
   mirror the private `vulngraph` repo's `engine/src/`. Only the read halves
   are vendored (no writers, builder, or ingest). The binary ABI is fixed:
   `NodeHeader`=48, `EdgeRecord`=32, `IndexSlot`=16, `DescSlot`=8; FNV-1a
   basis `0xcbf29ce484222325`, hash-0→1; `NodeType` 0–7, `EdgeType` 0–10.
2. **Version comparator** — `src/semver.rs` mirrors the private repo's
   `mcp/src/tools/batch.rs` (`version_in_ranges`/`parse_semver`/`semver_cmp`).
3. **Snapshot identity** — `src/snapshot_id.rs` mirrors vulngraph-data's
   `crates/vulngraph-data/src/manifest.rs` (`SEMANTIC_FILES` + hash walk). The
   file list is shared via `vulngraph_core::manifest::SEMANTIC_FILES`.

## Unsafe Policy

Workspace `unsafe_code = "deny"`. `core` and `cli` add crate-level
`#![forbid(unsafe_code)]`. The **only** `#[allow(unsafe_code)]` is
`engine/storage.rs`, confined to immutable mmap of Pod data with alignment and
size-multiple checks at open time and a bounds-checked public API. Keep it
there — the vendored `index.rs` deliberately uses checked `get`, not
`get_unchecked`, so unsafe stays in one file.

## Determinism

The verdict policy and the VRB compiler must be deterministic: no clock, no
`Math.random`, no HashMap iteration in any output path (use `BTreeMap`/sort).
Two compiles of the same `version_ranges.json` against the same graph produce
byte-identical VRB files (tested). `unknown` is never rendered as clean.

## Working Rules

- Every untrusted-input parser (target, manifest, VRB reader) has a fuzz
  target and must never panic; add one before shipping a new parser.
- Prefer property tests over example lists for the verdict policy and version
  semantics.
- Hand-written error enums with `Display` + `source()`; no anyhow/thiserror.
- `just`-free; use `cargo build/test/clippy`. CI gates fmt, clippy
  `-D warnings`, and workspace tests on Linux + macOS.
- Real-data smoke tests live in `crates/vulngraph-dataset/tests/real_data.rs`,
  `#[ignore]` by default (set `VULNGRAPH_REAL_DB`).

## Commit Convention

`feat:`/`fix:`/`refactor:`/`test:`/`docs:`/`chore:`, scoped like
`feat(dataset):`. Commits touching a vendored file must state whether the
upstream changed and whether a `format_version` bump is implied.
