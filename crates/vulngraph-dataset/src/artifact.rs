//! Release acquisition, verification, and atomic installation.
//!
//! Mirrors the KiloCheck update discipline: every byte is verified before
//! activation (asset checksum, per-file hashes, recomputed snapshot
//! identity, engine sanity-open), snapshots are content-addressed and
//! immutable, and activation is an append-only pointer written with
//! `persist_noclobber` — a failed update can never replace the last
//! verified snapshot.

use crate::engine::graph::Graph;
use crate::snapshot_id::{sha256_file, snapshot_id};
use crate::vrb;
use crate::{ACTIVE_SCHEMA, DB_ARCHIVE, DatasetError, MANIFEST_ASSET, RELEASE_BASE_URL, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use vulngraph_core::SUPPORTED_FORMAT_VERSION;
use vulngraph_core::manifest::ReleaseManifest;

pub const INSTALLED_SCHEMA: &str = "vulngraph.installed.v1";

/// Freshness policy (matches the release contract).
pub const MAX_AGE_DAYS: i64 = 14;
pub const FUTURE_SKEW_MINUTES: i64 = 15;

/// Archive safety limits (kilo pattern).
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledManifest {
    pub schema: String,
    pub snapshot_id: String,
    pub created_at: String,
    pub format_version: u64,
    pub engine_rev: String,
    pub node_count: u64,
    pub edge_count: u64,
    /// sha256 of the update-time-compiled `compiled/version_ranges.bin`.
    pub vrb_sha256: String,
    pub installed_at: String,
}

impl InstalledManifest {
    /// # Errors
    /// Returns `DatasetError::Invalid` naming the violated field.
    pub fn validate(&self) -> Result<()> {
        let invalid = |msg: String| Err(DatasetError::Invalid(msg));
        if self.schema != INSTALLED_SCHEMA {
            return invalid(format!(
                "installed manifest schema '{}' unsupported",
                self.schema
            ));
        }
        let Some(hash) = self.snapshot_id.strip_prefix("sha256:") else {
            return invalid("installed snapshot_id missing sha256: prefix".to_string());
        };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return invalid("installed snapshot_id hash malformed".to_string());
        }
        if self.format_version != SUPPORTED_FORMAT_VERSION {
            return invalid(format!(
                "installed format_version {} unsupported",
                self.format_version
            ));
        }
        if self.node_count == 0 || self.edge_count == 0 {
            return invalid("installed manifest has zero counts".to_string());
        }
        if self.vrb_sha256.len() != 64 || !self.vrb_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return invalid("installed vrb_sha256 malformed".to_string());
        }
        Ok(())
    }

    /// Enforce the freshness policy against the current clock.
    ///
    /// # Errors
    /// `DatasetError::Stale` when older than `MAX_AGE_DAYS`;
    /// `DatasetError::Invalid` on unparseable or future-dated timestamps.
    pub fn ensure_fresh(&self) -> Result<()> {
        ensure_created_at_fresh(&self.created_at)
    }

    #[must_use]
    pub fn snapshot_hex(&self) -> &str {
        self.snapshot_id
            .strip_prefix("sha256:")
            .unwrap_or(&self.snapshot_id)
    }
}

fn ensure_created_at_fresh(created_at: &str) -> Result<()> {
    let created = chrono::DateTime::parse_from_rfc3339(created_at)
        .map_err(|e| DatasetError::Invalid(format!("created_at '{created_at}' unparseable: {e}")))?
        .with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();
    if created > now + chrono::Duration::minutes(FUTURE_SKEW_MINUTES) {
        return Err(DatasetError::Invalid(format!(
            "manifest is future-dated ({created_at})"
        )));
    }
    let age = now - created;
    if age > chrono::Duration::days(MAX_AGE_DAYS) {
        return Err(DatasetError::Stale(format!(
            "snapshot created {created_at} is older than {MAX_AGE_DAYS} days"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct UpdateOptions {
    /// Install from a local directory holding the three assets instead of
    /// downloading (air-gapped / testing).
    pub offline_dir: Option<PathBuf>,
    /// Override the release download base URL (mirrors and testing).
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateReport {
    pub snapshot_id: String,
    pub created_at: String,
    pub node_count: u64,
    pub edge_count: u64,
    pub engine_rev: String,
    pub vrb_packages: usize,
    pub vrb_ranges: usize,
    pub dropped_range_cves: usize,
    /// True when the release was already installed and active.
    pub noop: bool,
}

/// Download, verify, compile, and atomically activate the latest release.
///
/// # Errors
/// Any verification failure aborts with the staging directory removed and
/// the previously active snapshot untouched.
pub fn update(home: &Path, options: &UpdateOptions) -> Result<UpdateReport> {
    let staging_root = home.join("staging");
    std::fs::create_dir_all(&staging_root)?;
    let staging = tempfile::Builder::new()
        .prefix("update-")
        .tempdir_in(&staging_root)?;

    // ── Acquire assets ────────────────────────────
    let archive_path = staging.path().join(DB_ARCHIVE);
    let sha_path = staging.path().join(format!("{DB_ARCHIVE}.sha256"));
    let manifest_path = staging.path().join(MANIFEST_ASSET);

    if let Some(offline_dir) = &options.offline_dir {
        for (name, dest) in [
            (DB_ARCHIVE.to_string(), &archive_path),
            (format!("{DB_ARCHIVE}.sha256"), &sha_path),
            (MANIFEST_ASSET.to_string(), &manifest_path),
        ] {
            let src = offline_dir.join(&name);
            if !src.is_file() {
                return Err(DatasetError::Invalid(format!(
                    "offline dir is missing {name} ({})",
                    src.display()
                )));
            }
            std::fs::copy(&src, dest)?;
        }
    } else {
        let base = options.base_url.as_deref().unwrap_or(RELEASE_BASE_URL);
        download(&format!("{base}/{MANIFEST_ASSET}"), &manifest_path)?;
        download(&format!("{base}/{DB_ARCHIVE}.sha256"), &sha_path)?;
        download(&format!("{base}/{DB_ARCHIVE}"), &archive_path)?;
    }

    // ── Verify archive checksum ───────────────────
    verify_archive_checksum(&archive_path, &sha_path, DB_ARCHIVE)?;

    // ── Parse + validate manifest, enforce freshness ──
    let manifest = ReleaseManifest::parse_json(&std::fs::read(&manifest_path)?)
        .map_err(|e| DatasetError::Invalid(e.to_string()))?;
    ensure_created_at_fresh(&manifest.created_at)?;

    // ── No-op fast path ───────────────────────────
    if let Some(installed) = crate::installed_manifest(home)?
        && installed.snapshot_id == manifest.snapshot_id
    {
        return Ok(UpdateReport {
            snapshot_id: installed.snapshot_id,
            created_at: installed.created_at,
            node_count: installed.node_count,
            edge_count: installed.edge_count,
            engine_rev: installed.engine_rev,
            vrb_packages: 0,
            vrb_ranges: 0,
            dropped_range_cves: 0,
            noop: true,
        });
    }

    // ── Unpack with safety limits ─────────────────
    let db_dir = staging.path().join("db");
    std::fs::create_dir_all(&db_dir)?;
    unpack(&archive_path, &db_dir)?;

    // ── Per-file verification against the manifest ──
    for (name, entry) in &manifest.files {
        let path = db_dir.join(name);
        if !path.is_file() {
            return Err(DatasetError::Invalid(format!(
                "{name} listed in manifest but absent from archive"
            )));
        }
        let (sha, bytes) = sha256_file(&path)?;
        if sha != entry.sha256 || bytes != entry.bytes {
            return Err(DatasetError::Invalid(format!("{name} hash/size mismatch")));
        }
    }

    // ── Recompute snapshot identity ───────────────
    let computed = snapshot_id(&db_dir)?;
    if computed != manifest.snapshot_id {
        return Err(DatasetError::Invalid(format!(
            "snapshot_id mismatch (manifest {}, computed {computed})",
            manifest.snapshot_id
        )));
    }

    // ── Engine sanity-open + count cross-check ────
    let graph = Graph::open(&db_dir)?;
    if graph.node_count() as u64 != manifest.node_count
        || graph.edge_count() as u64 != manifest.edge_count
    {
        return Err(DatasetError::Invalid(format!(
            "graph counts ({} / {}) disagree with manifest ({} / {})",
            graph.node_count(),
            graph.edge_count(),
            manifest.node_count,
            manifest.edge_count
        )));
    }

    // ── Compile version ranges, self-check, hash ──
    let vrb_path = staging.path().join("compiled/version_ranges.bin");
    let stats = vrb::compile(&db_dir.join("version_ranges.json"), &graph, &vrb_path)?;
    vrb::VrbReader::open(&vrb_path)?;
    let (vrb_sha, _) = sha256_file(&vrb_path)?;
    drop(graph); // release mmaps before the directory rename

    // ── Installed manifest ────────────────────────
    let installed = InstalledManifest {
        schema: INSTALLED_SCHEMA.to_string(),
        snapshot_id: manifest.snapshot_id.clone(),
        created_at: manifest.created_at.clone(),
        format_version: manifest.format_version,
        engine_rev: manifest.engine_rev.clone(),
        node_count: manifest.node_count,
        edge_count: manifest.edge_count,
        vrb_sha256: vrb_sha,
        installed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    installed.validate()?;
    std::fs::write(
        staging.path().join("installed-manifest.json"),
        serde_json::to_vec_pretty(&installed)?,
    )?;
    // The downloaded assets are not part of the installed snapshot.
    std::fs::remove_file(&archive_path)?;
    std::fs::remove_file(&sha_path)?;
    std::fs::remove_file(&manifest_path)?;

    // ── Content-addressed install + activation ────
    let snapshots = home.join("snapshots");
    std::fs::create_dir_all(&snapshots)?;
    let final_dir = snapshots.join(installed.snapshot_hex());
    if final_dir.exists() {
        // Same content already installed (e.g. prior activation rolled
        // back) — reuse it, drop the staging copy.
    } else {
        let staged = staging.keep();
        std::fs::rename(&staged, &final_dir)?;
    }
    activate(home, installed.snapshot_hex())?;
    gc(home)?;

    Ok(UpdateReport {
        snapshot_id: installed.snapshot_id,
        created_at: installed.created_at,
        node_count: installed.node_count,
        edge_count: installed.edge_count,
        engine_rev: installed.engine_rev,
        vrb_packages: stats.packages,
        vrb_ranges: stats.ranges,
        dropped_range_cves: stats.dropped_range_cves,
        noop: false,
    })
}

fn download(url: &str, dest: &Path) -> Result<()> {
    let response = ureq::get(url)
        .set(
            "User-Agent",
            concat!("vulngraph/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|e| DatasetError::Http(format!("{url}: {e}")))?;
    if let Some(len) = response
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok())
        && len > MAX_ARCHIVE_BYTES
    {
        return Err(DatasetError::Http(format!(
            "{url}: declared size {len} exceeds the {MAX_ARCHIVE_BYTES}-byte cap"
        )));
    }
    let mut reader = response.into_reader().take(MAX_ARCHIVE_BYTES + 1);
    let mut file = std::fs::File::create(dest)?;
    let copied = std::io::copy(&mut reader, &mut file)?;
    if copied > MAX_ARCHIVE_BYTES {
        return Err(DatasetError::Http(format!(
            "{url}: stream exceeded the {MAX_ARCHIVE_BYTES}-byte cap"
        )));
    }
    Ok(())
}

/// Strict `.sha256` parse: exactly `<64-hex>  <asset-name>`, nothing else.
fn verify_archive_checksum(archive: &Path, sha_file: &Path, asset_name: &str) -> Result<()> {
    let content = std::fs::read_to_string(sha_file)?;
    let mut fields = content.split_whitespace();
    let (Some(expected), Some(named), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err(DatasetError::Invalid(format!(
            "{} is not a two-field sha256 file",
            sha_file.display()
        )));
    };
    if named != asset_name {
        return Err(DatasetError::Invalid(format!(
            "checksum file names '{named}', expected '{asset_name}'"
        )));
    }
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DatasetError::Invalid("malformed sha256 digest".to_string()));
    }
    let (actual, _) = sha256_file(archive)?;
    if actual != expected.to_ascii_lowercase() {
        return Err(DatasetError::Invalid(format!(
            "{asset_name} checksum mismatch"
        )));
    }
    Ok(())
}

/// Untar with the kilo safety rules: bounded entry count and unpacked
/// bytes; only plain files and directories with `Normal` path components.
fn unpack(archive: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(archive)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut entries = 0usize;
    let mut unpacked: u64 = 0;
    for entry in tar.entries()? {
        let mut entry = entry?;
        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            return Err(DatasetError::Invalid(format!(
                "archive exceeds {MAX_ARCHIVE_ENTRIES} entries"
            )));
        }
        let entry_type = entry.header().entry_type();
        if !matches!(
            entry_type,
            tar::EntryType::Regular | tar::EntryType::Directory
        ) {
            return Err(DatasetError::Invalid(format!(
                "archive contains forbidden entry type {entry_type:?}"
            )));
        }
        let path = entry
            .path()
            .map_err(|e| DatasetError::Invalid(format!("bad path: {e}")))?;
        for component in path.components() {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err(DatasetError::Invalid(format!(
                    "archive path '{}' escapes the extraction root",
                    path.display()
                )));
            }
        }
        unpacked = unpacked.saturating_add(entry.header().size().unwrap_or(0));
        if unpacked > MAX_UNPACKED_BYTES {
            return Err(DatasetError::Invalid(format!(
                "archive unpacks beyond the {MAX_UNPACKED_BYTES}-byte cap"
            )));
        }
        if !entry.unpack_in(dest)? {
            return Err(DatasetError::Invalid(
                "archive entry escaped the extraction root".to_string(),
            ));
        }
    }
    Ok(())
}

/// Append-only activation pointer: `activations/<seq>.json`, written via
/// `persist_noclobber` in a retry loop so concurrent updaters can never
/// clobber each other.
fn activate(home: &Path, snapshot_hex: &str) -> Result<()> {
    let directory = home.join("activations");
    std::fs::create_dir_all(&directory)?;
    let pointer = serde_json::json!({
        "schema": ACTIVE_SCHEMA,
        "snapshot_id": snapshot_hex,
    });
    let bytes = serde_json::to_vec_pretty(&pointer)?;
    for _ in 0..1024 {
        let next = next_activation_sequence(&directory)?;
        let temp = tempfile::NamedTempFile::new_in(&directory)?;
        std::io::Write::write_all(&mut temp.as_file(), &bytes)?;
        temp.as_file().sync_all()?;
        match temp.persist_noclobber(directory.join(format!("{next}.json"))) {
            Ok(_) => return Ok(()),
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(DatasetError::Io(e.error)),
        }
    }
    Err(DatasetError::Invalid(
        "could not claim an activation sequence number".to_string(),
    ))
}

fn next_activation_sequence(directory: &Path) -> Result<u64> {
    let mut max = 0u64;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if let Some(seq) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.parse::<u64>().ok())
        {
            max = max.max(seq);
        }
    }
    Ok(max + 1)
}

/// Remove snapshots not referenced by the two newest activation pointers.
fn gc(home: &Path) -> Result<()> {
    let directory = home.join("activations");
    if !directory.is_dir() {
        return Ok(());
    }
    let mut activations: Vec<(u64, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&directory)? {
        let entry = entry?;
        if let Some(seq) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.parse::<u64>().ok())
        {
            activations.push((seq, entry.path()));
        }
    }
    activations.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));
    let mut keep: Vec<String> = Vec::new();
    for (_, path) in activations.iter().take(2) {
        if let Ok(pointer) = serde_json::from_slice::<crate::ActivePointer>(&std::fs::read(path)?) {
            keep.push(pointer.snapshot_id);
        }
    }
    let snapshots = home.join("snapshots");
    if !snapshots.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&snapshots)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !keep.iter().any(|k| k == name) {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::testutil::FixtureDb;
    use crate::engine::types::NodeType;
    use vulngraph_core::manifest::SEMANTIC_FILES;

    /// Build a complete synthetic dist dir (archive + sha + manifest) from
    /// a fixture db, returning (dist_dir, snapshot_id).
    fn build_dist(root: &Path) -> (PathBuf, String) {
        let db_src = root.join("dbsrc");
        let mut fx = FixtureDb::new();
        let cve = fx.add_node("CVE-2020-8203", NodeType::CVE);
        let pkg = fx.add_node("npm:lodash", NodeType::PACKAGE);
        fx.add_edge(cve, pkg, crate::engine::types::EdgeType::AFFECTS);
        fx.set_cvss(cve, 7.4);
        // Every shipped file must be non-empty (manifest validation).
        fx.set_description(cve, "Prototype pollution in lodash.");
        fx.set_published(cve, 1_588_000_000);
        fx.set_epss(cve, 0.02, 0.5);
        fx.write(&db_src).unwrap();
        let vr = serde_json::json!({"npm:lodash": {"CVE-2020-8203": [["3.7.0", "4.17.19"]]}});
        std::fs::write(
            db_src.join("version_ranges.json"),
            serde_json::to_vec(&vr).unwrap(),
        )
        .unwrap();
        std::fs::write(db_src.join("freshness.json"), b"{\"sources\":{}}").unwrap();

        let dist = root.join("dist");
        std::fs::create_dir_all(&dist).unwrap();

        // Tar the db files at archive root.
        let archive_path = dist.join(DB_ARCHIVE);
        let file = std::fs::File::create(&archive_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(enc);
        let mut files = std::collections::BTreeMap::new();
        for entry in std::fs::read_dir(&db_src).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_str().unwrap().to_string();
            tar.append_path_with_name(entry.path(), &name).unwrap();
            let (sha, bytes) = sha256_file(&entry.path()).unwrap();
            files.insert(name, serde_json::json!({"bytes": bytes, "sha256": sha}));
        }
        tar.into_inner().unwrap().finish().unwrap();

        let (archive_sha, _) = sha256_file(&archive_path).unwrap();
        std::fs::write(
            dist.join(format!("{DB_ARCHIVE}.sha256")),
            format!("{archive_sha}  {DB_ARCHIVE}\n"),
        )
        .unwrap();

        for name in SEMANTIC_FILES {
            assert!(files.contains_key(*name), "fixture must ship {name}");
        }
        let sid = snapshot_id(&db_src).unwrap();
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "snapshot_id": sid,
            "format_version": 1,
            "engine_rev": "engine-v0.1.0",
            "created_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "node_count": 2,
            "edge_count": 1,
            "files": files,
            "sources": {},
        });
        std::fs::write(
            dist.join(MANIFEST_ASSET),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        (dist, sid)
    }

    fn offline_options(dist: &Path) -> UpdateOptions {
        UpdateOptions {
            offline_dir: Some(dist.to_path_buf()),
            base_url: None,
        }
    }

    #[test]
    fn full_offline_install_and_noop() {
        let root = tempfile::tempdir().unwrap();
        let (dist, sid) = build_dist(root.path());
        let home = root.path().join("home");

        let report = update(&home, &offline_options(&dist)).unwrap();
        assert_eq!(report.snapshot_id, sid);
        assert!(!report.noop);
        assert_eq!(report.vrb_packages, 1);

        // Snapshot opens and answers.
        let snap = crate::open_active(&home).unwrap();
        assert_eq!(snap.manifest.snapshot_id, sid);

        // Second install of the same release is a no-op.
        let report = update(&home, &offline_options(&dist)).unwrap();
        assert!(report.noop);
    }

    #[test]
    fn tampered_archive_is_rejected_and_leaves_no_activation() {
        let root = tempfile::tempdir().unwrap();
        let (dist, _) = build_dist(root.path());
        let home = root.path().join("home");

        let archive = dist.join(DB_ARCHIVE);
        let mut bytes = std::fs::read(&archive).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&archive, &bytes).unwrap();

        assert!(update(&home, &offline_options(&dist)).is_err());
        assert!(crate::active_snapshot_dir(&home).unwrap().is_none());
    }

    #[test]
    fn wrong_snapshot_id_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (dist, _) = build_dist(root.path());
        let home = root.path().join("home");

        let manifest_path = dist.join(MANIFEST_ASSET);
        let mut m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        m["snapshot_id"] = serde_json::json!(format!("sha256:{}", "b".repeat(64)));
        std::fs::write(&manifest_path, serde_json::to_vec(&m).unwrap()).unwrap();

        let err = update(&home, &offline_options(&dist)).unwrap_err();
        assert!(err.to_string().contains("snapshot_id mismatch"), "{err}");
        assert!(crate::active_snapshot_dir(&home).unwrap().is_none());
    }

    #[test]
    fn stale_manifest_is_rejected_with_stale_error() {
        let root = tempfile::tempdir().unwrap();
        let (dist, _) = build_dist(root.path());
        let home = root.path().join("home");

        let manifest_path = dist.join(MANIFEST_ASSET);
        let mut m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        m["created_at"] = serde_json::json!("2020-01-01T00:00:00Z");
        std::fs::write(&manifest_path, serde_json::to_vec(&m).unwrap()).unwrap();

        match update(&home, &offline_options(&dist)) {
            Err(DatasetError::Stale(_)) => {}
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn future_dated_manifest_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (dist, _) = build_dist(root.path());
        let home = root.path().join("home");

        let manifest_path = dist.join(MANIFEST_ASSET);
        let mut m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let future = chrono::Utc::now() + chrono::Duration::hours(2);
        m["created_at"] =
            serde_json::json!(future.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        std::fs::write(&manifest_path, serde_json::to_vec(&m).unwrap()).unwrap();

        assert!(update(&home, &offline_options(&dist)).is_err());
    }

    #[test]
    fn symlink_archive_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (dist, _) = build_dist(root.path());
        let home = root.path().join("home");

        // Rebuild the archive with a symlink entry (the tar Builder refuses
        // to author `..` paths, so entry-type rejection is the testable
        // half of the safety rules; unpack_in covers traversal).
        let archive_path = dist.join(DB_ARCHIVE);
        let file = std::fs::File::create(&archive_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        tar.append_link(&mut header, "meta.json", "/etc/passwd")
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        let (sha, _) = sha256_file(&archive_path).unwrap();
        std::fs::write(
            dist.join(format!("{DB_ARCHIVE}.sha256")),
            format!("{sha}  {DB_ARCHIVE}\n"),
        )
        .unwrap();

        let err = update(&home, &offline_options(&dist)).unwrap_err();
        assert!(err.to_string().contains("forbidden entry type"), "{err}");
        assert!(crate::active_snapshot_dir(&home).unwrap().is_none());
    }

    #[test]
    fn concurrent_activations_never_clobber() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().to_path_buf();
        std::fs::create_dir_all(home.join("activations")).unwrap();
        let mut handles = Vec::new();
        for i in 0..8 {
            let home = home.clone();
            handles.push(std::thread::spawn(move || {
                activate(&home, &format!("{:064}", i)).unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let count = std::fs::read_dir(home.join("activations")).unwrap().count();
        assert_eq!(
            count, 8,
            "every activation must land under its own sequence"
        );
    }
}
