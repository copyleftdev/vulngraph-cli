//! Snapshot content identity.
//!
//! SYNC: keep in sync with vulngraph-data
//! `crates/vulngraph-data/src/manifest.rs` (`SEMANTIC_FILES` order and the
//! `snapshot_id` hash walk). The semantic file list itself is shared via
//! `vulngraph_core::manifest::SEMANTIC_FILES`.

use sha2::{Digest, Sha256};
use std::path::Path;
use vulngraph_core::manifest::SEMANTIC_FILES;

/// Compute the snapshot identity of a db directory: sha256 over
/// `filename \0 sha256(file) \n` for each `SEMANTIC_FILES` entry that
/// exists, in the fixed (sorted) order. A missing semantic file changes the
/// identity because its line is absent.
///
/// # Errors
/// Propagates I/O failures reading any present semantic file.
pub fn snapshot_id(db_dir: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    for name in SEMANTIC_FILES {
        let path = db_dir.join(name);
        if !path.exists() {
            continue;
        }
        let (hash, _) = sha256_file(&path)?;
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Stream-hash a file, returning (lowercase hex sha256, byte length).
///
/// # Errors
/// Propagates I/O failures.
pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let bytes = std::io::copy(&mut file, &mut hasher)?;
    Ok((hex::encode(hasher.finalize()), bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sidecar_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.bin"), b"abc").unwrap();
        std::fs::write(dir.path().join("strings.bin"), b"def").unwrap();
        std::fs::write(dir.path().join("meta.json"), b"{\"ts\":1}").unwrap();

        let a = snapshot_id(dir.path()).unwrap();
        assert_eq!(a, snapshot_id(dir.path()).unwrap());

        // Sidecars are not semantic
        std::fs::write(dir.path().join("meta.json"), b"{\"ts\":2}").unwrap();
        assert_eq!(a, snapshot_id(dir.path()).unwrap());

        // Semantic content changes identity
        std::fs::write(dir.path().join("nodes.bin"), b"abd").unwrap();
        assert_ne!(a, snapshot_id(dir.path()).unwrap());
    }
}
