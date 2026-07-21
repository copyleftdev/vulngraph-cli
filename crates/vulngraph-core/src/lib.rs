//! Stable domain contracts for the vulngraph CLI.
//!
//! Everything in this crate is part of the product interface: the JSON
//! envelope, target grammar, verdict policy, and release-manifest schema.
//! It is a leaf crate — serde only, no I/O.

#![forbid(unsafe_code)]

pub mod lockfile;
pub mod manifest;
pub mod status;
pub mod target;
pub mod verdict;

use serde::{Deserialize, Serialize};

pub const COMMAND_SCHEMA: &str = "vulngraph.command.v1";
pub const OBSERVATION_SCHEMA: &str = "vulngraph.observation.v1";
pub const STATUS_SCHEMA: &str = "vulngraph.status.v1";
pub const CAPABILITIES_SCHEMA: &str = "vulngraph.capabilities.v1";

/// The binary graph format version this CLI understands. Mirrors the
/// `format_version` field of vulngraph-data release manifests.
pub const SUPPORTED_FORMAT_VERSION: u64 = 1;

/// Machine-readable diagnostic attached to envelope warnings/errors.
/// Output-only (codes are &'static str), hence Serialize without Deserialize.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
}

impl Diagnostic {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub mod codes {
    pub const INVALID_TARGET: &str = "INVALID_TARGET";
    pub const DATASET_MISSING: &str = "DATASET_MISSING";
    pub const DATASET_INVALID: &str = "DATASET_INVALID";
    pub const DATASET_STALE: &str = "DATASET_STALE";
    pub const UPDATE_FAILED: &str = "UPDATE_FAILED";
    pub const OFFLINE_INPUT_REQUIRED: &str = "OFFLINE_INPUT_REQUIRED";
    pub const SERIALIZATION_FAILED: &str = "SERIALIZATION_FAILED";
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Metrics {
    pub elapsed_us: u64,
}

/// The stable machine-output wrapper for every command.
#[derive(Serialize, Debug, Clone)]
pub struct CommandEnvelope<T> {
    pub schema: String,
    pub command: String,
    pub ok: bool,
    pub partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    pub warnings: Vec<Diagnostic>,
    pub errors: Vec<Diagnostic>,
    pub metrics: Metrics,
}

impl<T> CommandEnvelope<T> {
    #[must_use]
    pub fn success(command: &str, data: T, elapsed_us: u64) -> Self {
        Self {
            schema: COMMAND_SCHEMA.to_string(),
            command: command.to_string(),
            ok: true,
            partial: false,
            snapshot_id: None,
            data: Some(data),
            warnings: Vec::new(),
            errors: Vec::new(),
            metrics: Metrics { elapsed_us },
        }
    }

    #[must_use]
    pub fn success_with_snapshot(
        command: &str,
        snapshot_id: String,
        data: T,
        elapsed_us: u64,
    ) -> Self {
        let mut env = Self::success(command, data, elapsed_us);
        env.snapshot_id = Some(snapshot_id);
        env
    }

    #[must_use]
    pub fn failure(command: &str, error: Diagnostic, elapsed_us: u64) -> Self {
        Self {
            schema: COMMAND_SCHEMA.to_string(),
            command: command.to_string(),
            ok: false,
            partial: false,
            snapshot_id: None,
            data: None,
            warnings: Vec::new(),
            errors: vec![error],
            metrics: Metrics { elapsed_us },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_success_shape() {
        let env = CommandEnvelope::success("status", 7u32, 42);
        assert!(env.ok);
        assert!(!env.partial);
        assert_eq!(env.schema, COMMAND_SCHEMA);
        assert_eq!(env.data, Some(7));
        assert!(env.errors.is_empty());
        let json = serde_json::to_value(&env).unwrap();
        assert!(
            json.get("snapshot_id").is_none(),
            "absent snapshot_id must be omitted"
        );
    }

    #[test]
    fn envelope_failure_shape() {
        let env: CommandEnvelope<()> =
            CommandEnvelope::failure("check", Diagnostic::new(codes::INVALID_TARGET, "bad"), 1);
        assert!(!env.ok);
        assert_eq!(env.errors[0].code, codes::INVALID_TARGET);
        assert!(env.data.is_none());
    }
}
