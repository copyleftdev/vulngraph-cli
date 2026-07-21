//! Minimal engine error type.
//!
//! SYNC: keep in sync with the private vulngraph repo, `engine/src/error.rs`
//! (write-side variants Duplicate/Ingest are intentionally not vendored).
//! Hand-written Display/Error impls — this workspace avoids thiserror.

use std::fmt;

#[derive(Debug)]
pub enum EngineError {
    Io(String),
    Storage(String),
    Index(String),
    InvalidData(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::Index(msg) => write!(f, "index error: {msg}"),
            Self::InvalidData(msg) => write!(f, "invalid data: {msg}"),
        }
    }
}

impl std::error::Error for EngineError {}

pub type Result<T> = std::result::Result<T, EngineError>;
