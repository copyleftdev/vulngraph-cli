//! Vendored read path of the VulnGraph binary graph engine.
//!
//! SYNC: keep in sync with the private vulngraph repo, `engine/src/` — same
//! precedent as its WASM mirror. Vendored: `types.rs`, the read halves of
//! `storage.rs` (`MappedArray`, `MappedBytes`) and `index.rs` (`IndexSlot`,
//! `HashIndex`), and `graph.rs`. Deliberately NOT vendored: all writer
//! primitives, `GraphBuilder`, and every ingest module — this CLI can only
//! read published snapshots, never produce them.
//!
//! Any upstream change to struct layout, discriminants, or the FNV-1a
//! contract gates a `format_version` bump in the release manifest, which
//! this CLI checks before installing data.

pub mod error;
pub mod graph;
pub mod index;
pub mod storage;
#[cfg(test)]
pub mod testutil;
pub mod types;
