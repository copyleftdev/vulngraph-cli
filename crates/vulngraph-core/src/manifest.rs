//! Release-manifest schema published by vulngraph-data.
//!
//! SYNC: field shapes mirror vulngraph-data `crates/vulngraph-data/src/manifest.rs`
//! (`Manifest` / `FileEntry`). Changing either side is a cross-repo contract
//! change gated by `manifest_version` / `format_version`.

use crate::SUPPORTED_FORMAT_VERSION;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The 12 files whose bytes define the snapshot identity, in the fixed
/// sorted order the `snapshot_id` hash walks them.
pub const SEMANTIC_FILES: &[&str] = &[
    "desc_index.bin",
    "desc_strings.bin",
    "edges_fwd.bin",
    "edges_rev.bin",
    "idx_extid.bin",
    "nodes.bin",
    "props_cvss.bin",
    "props_epss.bin",
    "props_epss_pct.bin",
    "props_published.bin",
    "strings.bin",
    "version_ranges.json",
];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReleaseManifest {
    pub manifest_version: u32,
    pub snapshot_id: String,
    pub format_version: u64,
    pub engine_rev: String,
    pub created_at: String,
    pub node_count: u64,
    pub edge_count: u64,
    pub files: BTreeMap<String, FileEntry>,
    #[serde(default)]
    pub sources: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demo_blob: Option<serde_json::Value>,
}

#[derive(Debug)]
pub enum ManifestError {
    Json(serde_json::Error),
    Invalid(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "manifest is not valid JSON: {e}"),
            Self::Invalid(msg) => write!(f, "manifest invalid: {msg}"),
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl From<serde_json::Error> for ManifestError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl ReleaseManifest {
    /// Parse and structurally validate untrusted manifest bytes.
    /// This is the fuzz entry point — must never panic.
    ///
    /// # Errors
    /// Returns `ManifestError::Json` on malformed JSON and
    /// `ManifestError::Invalid` when any schema rule fails.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// # Errors
    /// Returns `ManifestError::Invalid` naming the first violated rule:
    /// version support, snapshot-id shape, per-file hashes, or a missing
    /// semantic file.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let invalid = |msg: String| Err(ManifestError::Invalid(msg));
        if self.manifest_version != 1 {
            return invalid(format!(
                "unsupported manifest_version {}",
                self.manifest_version
            ));
        }
        if self.format_version != SUPPORTED_FORMAT_VERSION {
            return invalid(format!(
                "format_version {} unsupported (CLI supports {SUPPORTED_FORMAT_VERSION})",
                self.format_version
            ));
        }
        let Some(hash) = self.snapshot_id.strip_prefix("sha256:") else {
            return invalid("snapshot_id must start with 'sha256:'".to_string());
        };
        if !is_sha256_hex(hash) {
            return invalid("snapshot_id hash must be 64 lowercase hex chars".to_string());
        }
        if self.created_at.is_empty() {
            return invalid("created_at empty".to_string());
        }
        if self.node_count == 0 || self.edge_count == 0 {
            return invalid("node/edge counts must be positive".to_string());
        }
        if self.engine_rev.is_empty() {
            return invalid("engine_rev empty".to_string());
        }
        for (name, entry) in &self.files {
            if !is_sha256_hex(&entry.sha256) {
                return invalid(format!("file {name} has malformed sha256"));
            }
            if entry.bytes == 0 {
                return invalid(format!("file {name} has zero size"));
            }
        }
        for name in SEMANTIC_FILES {
            if !self.files.contains_key(*name) {
                return invalid(format!("semantic file {name} missing from manifest"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest_json() -> serde_json::Value {
        let sha = "a".repeat(64);
        let files: BTreeMap<String, serde_json::Value> = SEMANTIC_FILES
            .iter()
            .map(|n| {
                (
                    (*n).to_string(),
                    serde_json::json!({"bytes": 10, "sha256": sha}),
                )
            })
            .collect();
        serde_json::json!({
            "manifest_version": 1,
            "snapshot_id": format!("sha256:{sha}"),
            "format_version": 1,
            "engine_rev": "engine-v0.1.0",
            "created_at": "2026-07-21T02:00:00Z",
            "node_count": 541_550,
            "edge_count": 751_324,
            "files": files,
            "sources": {}
        })
    }

    #[test]
    fn valid_manifest_parses() {
        let bytes = serde_json::to_vec(&valid_manifest_json()).unwrap();
        let m = ReleaseManifest::parse_json(&bytes).unwrap();
        assert_eq!(m.node_count, 541_550);
    }

    #[test]
    fn rejects_bad_fields() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("manifest_version", serde_json::json!(2)),
            ("format_version", serde_json::json!(99)),
            ("snapshot_id", serde_json::json!("41ee5fbb")),
            (
                "snapshot_id",
                serde_json::json!(format!("sha256:{}", "Z".repeat(64))),
            ),
            ("created_at", serde_json::json!("")),
            ("node_count", serde_json::json!(0)),
            ("engine_rev", serde_json::json!("")),
        ];
        for (field, value) in cases {
            let mut m = valid_manifest_json();
            m[field] = value;
            let bytes = serde_json::to_vec(&m).unwrap();
            assert!(
                ReleaseManifest::parse_json(&bytes).is_err(),
                "{field} should fail"
            );
        }
    }

    #[test]
    fn rejects_missing_semantic_file() {
        let mut m = valid_manifest_json();
        m["files"].as_object_mut().unwrap().remove("nodes.bin");
        let bytes = serde_json::to_vec(&m).unwrap();
        assert!(ReleaseManifest::parse_json(&bytes).is_err());
    }

    #[test]
    fn never_panics_on_garbage() {
        for garbage in [&b"{}"[..], b"null", b"[1,2]", b"\xff\xfe", b""] {
            let _ = ReleaseManifest::parse_json(garbage);
        }
    }
}
