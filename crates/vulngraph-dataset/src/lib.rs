//! Verified VulnGraph data installation and deterministic local queries.

#![deny(unsafe_code)]
// This crate vendors the engine read path near-verbatim to keep it
// diffable against the private repo (see `engine/`), so several pedantic
// lints that would force stylistic divergence are relaxed crate-wide.
#![allow(
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::uninlined_format_args,
    clippy::unreadable_literal,
    clippy::missing_fields_in_debug,
    clippy::pub_underscore_fields,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::type_complexity
)]

pub mod artifact;
pub mod engine;
pub mod query;
pub mod semver;
pub mod snapshot_id;
pub mod vrb;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub use artifact::{InstalledManifest, UpdateOptions, UpdateReport, update};
pub use query::Snapshot;

pub const DB_ARCHIVE: &str = "vulngraph-db.tar.gz";
pub const MANIFEST_ASSET: &str = "manifest.json";
pub const RELEASE_BASE_URL: &str =
    "https://github.com/copyleftdev/vulngraph-data/releases/latest/download";

pub const ACTIVE_SCHEMA: &str = "vulngraph.active.v1";

#[derive(Debug)]
pub enum DatasetError {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(String),
    Http(String),
    Engine(String),
    Stale(String),
}

impl fmt::Display for DatasetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
            Self::Http(message) => write!(formatter, "download failed: {message}"),
            Self::Engine(message) => write!(formatter, "graph engine error: {message}"),
            Self::Stale(message) => write!(formatter, "stale dataset: {message}"),
        }
    }
}

impl std::error::Error for DatasetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Invalid(_) | Self::Http(_) | Self::Engine(_) | Self::Stale(_) => None,
        }
    }
}

impl From<io::Error> for DatasetError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for DatasetError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<engine::error::EngineError> for DatasetError {
    fn from(value: engine::error::EngineError) -> Self {
        Self::Engine(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DatasetError>;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ActivePointer {
    schema: String,
    snapshot_id: String,
}

/// Resolve the active snapshot directory without opening its contents.
///
/// # Errors
/// Returns an error when the active pointer cannot be read or is malformed.
pub fn active_snapshot_dir(home: &Path) -> Result<Option<PathBuf>> {
    let Some(pointer_path) = latest_activation(home)? else {
        return Ok(None);
    };
    if !pointer_path.is_file() {
        return Ok(None);
    }
    let pointer: ActivePointer = serde_json::from_slice(&std::fs::read(&pointer_path)?)?;
    if pointer.schema != ACTIVE_SCHEMA
        || pointer.snapshot_id.len() != 64
        || !pointer
            .snapshot_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DatasetError::Invalid(format!(
            "invalid active snapshot pointer at {}",
            pointer_path.display()
        )));
    }
    Ok(Some(home.join("snapshots").join(pointer.snapshot_id)))
}

fn latest_activation(home: &Path) -> Result<Option<PathBuf>> {
    let directory = home.join("activations");
    if !directory.is_dir() {
        return Ok(None);
    }
    let mut latest = None;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(sequence) = name
            .strip_suffix(".json")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        if latest
            .as_ref()
            .is_none_or(|(current, _)| sequence > *current)
        {
            latest = Some((sequence, entry.path()));
        }
    }
    Ok(latest.map(|(_, path)| path))
}

/// Read and validate the active installed manifest, if one exists.
///
/// # Errors
/// Returns an error when the active pointer or manifest is unreadable or invalid.
pub fn installed_manifest(home: &Path) -> Result<Option<InstalledManifest>> {
    let Some(directory) = active_snapshot_dir(home)? else {
        return Ok(None);
    };
    let path = directory.join("installed-manifest.json");
    let manifest: InstalledManifest = serde_json::from_slice(&std::fs::read(&path)?)?;
    manifest.validate()?;
    Ok(Some(manifest))
}

/// Open and integrity-check the active local snapshot.
///
/// # Errors
/// Returns an error when no snapshot is active or its files fail validation.
pub fn open_active(home: &Path) -> Result<Snapshot> {
    let directory = active_snapshot_dir(home)?.ok_or_else(|| {
        DatasetError::Invalid(format!(
            "no active VulnGraph snapshot is installed in {}",
            home.display()
        ))
    })?;
    Snapshot::open(&directory)
}
