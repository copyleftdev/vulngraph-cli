# Contributing to vulngraph

Thanks for helping. A few rules keep this CLI focused and trustworthy.

## Scope

The command surface is exactly five: `check`, `status`, `update`,
`capabilities`, `schema`. Proposals that add commands, a config file, or a
server mode will be declined — focus is the product. New evidence sources
extend `check` output; they do not add verbs.

## The evidence contract

- Tests are part of the public evidence contract. Every change ships with the
  tests that prove it.
- `unknown` is never "clean." Absence of evidence is reported as absence.
- Verdict policy and the version-range compiler are deterministic: no clock,
  no randomness, no HashMap iteration into on-disk or rendered output.
- Every parser of untrusted input (target, manifest, VRB reader) has a fuzz
  target and must never panic. Add one before landing a new parser.

## Before you push

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
sh -n scripts/install.sh
```

Optionally, against a real snapshot:

```sh
VULNGRAPH_REAL_DB=~/Project/vulngraph-data/builds/vulngraph.db \
  cargo test -p vulngraph-dataset --test real_data -- --ignored
```

## Vendored code

`crates/vulngraph-dataset/src/engine/*`, `src/semver.rs`, and
`src/snapshot_id.rs` mirror upstream repos (see the `SYNC:` headers and
CLAUDE.md). Keep them diffable against upstream — prefer a per-file `#[allow]`
over rewriting to satisfy a lint. A change to the on-disk format is a
cross-repo event that gates a `format_version` bump.

## License

By contributing you agree your work is licensed under the MIT License.
