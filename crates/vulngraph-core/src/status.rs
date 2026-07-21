//! `status` and `capabilities` data shapes.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSummary {
    pub id: String,
    pub created_at: String,
    pub node_count: u64,
    pub edge_count: u64,
    pub engine_rev: String,
    pub format_version: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DatasetStatus {
    pub schema: String,
    pub installed: bool,
    pub home: String,
    /// "verified" | "invalid" | "unavailable"
    pub integrity: String,
    /// "fresh" | "stale" | "unavailable"
    pub freshness: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotSummary>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExitCode {
    pub code: u8,
    pub meaning: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub schema: String,
    pub commands: Vec<String>,
    pub output_schemas: Vec<String>,
    pub exit_codes: Vec<ExitCode>,
    pub offline_checks: bool,
    pub deterministic: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        let s = String::from;
        Self {
            schema: crate::CAPABILITIES_SCHEMA.to_string(),
            commands: vec![
                s("check"),
                s("status"),
                s("update"),
                s("capabilities"),
                s("schema"),
            ],
            output_schemas: vec![
                crate::COMMAND_SCHEMA.to_string(),
                crate::OBSERVATION_SCHEMA.to_string(),
                crate::STATUS_SCHEMA.to_string(),
            ],
            exit_codes: vec![
                ExitCode {
                    code: 0,
                    meaning: s("success"),
                },
                ExitCode {
                    code: 1,
                    meaning: s("operational or integrity error"),
                },
                ExitCode {
                    code: 2,
                    meaning: s("invalid invocation"),
                },
                ExitCode {
                    code: 4,
                    meaning: s("dataset too stale"),
                },
            ],
            offline_checks: true,
            deterministic: true,
        }
    }
}
