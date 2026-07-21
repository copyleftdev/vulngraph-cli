//! `vulngraph` — focused, offline-first vulnerability intelligence.
//!
//! Five commands, one stable JSON envelope, deterministic verdicts derived
//! from an installed data snapshot. Data comes only from published
//! vulngraph-data releases; this binary never talks to any private service.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use std::collections::BTreeMap;

use clap::{Parser, Subcommand, ValueEnum};
use vulngraph_core::lockfile::{self, LockFormat};
use vulngraph_core::status::{Capabilities, DatasetStatus, SnapshotSummary};
use vulngraph_core::target::Target;
use vulngraph_core::verdict::{CheckResult, Disposition};
use vulngraph_core::{CommandEnvelope, Diagnostic, STATUS_SCHEMA, codes};
use vulngraph_dataset::{
    DatasetError, Snapshot, UpdateOptions, active_snapshot_dir, installed_manifest, open_active,
    update,
};

const COMMAND_SCHEMA_JSON: &str = include_str!("../../../schemas/vulngraph.command.v1.json");
const OBSERVATION_SCHEMA_JSON: &str =
    include_str!("../../../schemas/vulngraph.observation.v1.json");
const STATUS_SCHEMA_JSON: &str = include_str!("../../../schemas/vulngraph.status.v1.json");

// Exit codes (stable contract).
const EXIT_OK: u8 = 0;
const EXIT_OPERATIONAL: u8 = 1;
const EXIT_INVALID_INVOCATION: u8 = 2;
const EXIT_STALE: u8 = 4;

#[derive(Debug, Parser)]
#[command(
    name = "vulngraph",
    version,
    about = "Observe the exploitation evidence behind a CVE or package version"
)]
struct Cli {
    /// Emit the stable machine-readable command envelope.
    #[arg(long, global = true)]
    json: bool,

    /// Guarantee that the command performs no network access.
    #[arg(long, global = true)]
    offline: bool,

    /// Disable terminal color (currently the default).
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check targets, or a lockfile of them.
    ///
    /// Each argument is a CVE (CVE-YYYY-NNNN), a package
    /// (ecosystem:name@version), or a path to a lockfile / manifest
    /// (package-lock.json, Cargo.lock, requirements.txt, go.sum, pom.xml, …)
    /// whose dependencies are each checked.
    Check {
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Report local dataset installation and integrity state.
    Status,
    /// Download, verify, compile, and atomically activate a data release.
    Update {
        /// Read release assets from a local directory instead of the network.
        #[arg(long)]
        offline_dir: Option<PathBuf>,

        /// Override the release download base URL (mirrors and testing).
        #[arg(long, hide = true)]
        base_url: Option<String>,
    },
    /// Describe commands, schemas, guarantees, and exit codes.
    Capabilities,
    /// Print a stable JSON Schema.
    Schema {
        #[arg(value_enum)]
        name: SchemaName,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SchemaName {
    Command,
    Observation,
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_shorthand(env::args_os()));
    let _ = cli.no_color;

    let code = match cli.command {
        Command::Check { targets } => check(&targets, cli.json),
        Command::Status => status(cli.json),
        Command::Update {
            offline_dir,
            base_url,
        } => update_command(cli.json, cli.offline, offline_dir, base_url),
        Command::Capabilities => capabilities(cli.json),
        Command::Schema { name } => schema(name),
    };
    ExitCode::from(code)
}

/// Insert `check` when the first positional argument is a bare CVE id, so
/// `vulngraph CVE-2024-4577` works.
fn normalize_shorthand(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let args: Vec<OsString> = args.into_iter().collect();
    let commands = [
        "check",
        "status",
        "update",
        "capabilities",
        "schema",
        "help",
    ];
    let first_positional = args
        .iter()
        .skip(1)
        .find(|arg| arg.to_str().is_some_and(|value| !value.starts_with('-')));
    if let Some(first) = first_positional
        && let Some(value) = first.to_str()
    {
        let is_command = commands.contains(&value);
        let looks_like_cve =
            value.len() >= 4 && value.as_bytes()[..4].eq_ignore_ascii_case(b"cve-");
        if !is_command && looks_like_cve {
            let mut rewritten = vec![args[0].clone(), OsString::from("check")];
            rewritten.extend(args.into_iter().skip(1));
            return rewritten;
        }
    }
    args
}

fn home_dir() -> PathBuf {
    if let Some(explicit) = env::var_os("VULNGRAPH_HOME") {
        return PathBuf::from(explicit);
    }
    if let Some(xdg) = env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("vulngraph");
    }
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share/vulngraph");
    }
    PathBuf::from(".vulngraph")
}

// ─── check ────────────────────────────────────────

fn check(targets: &[String], json: bool) -> u8 {
    let start = Instant::now();

    // Each argument is a single target or a lockfile that expands to many.
    // A single bad argument fails the whole invocation.
    let mut parsed: Vec<Target> = Vec::with_capacity(targets.len());
    let mut scanned_files = 0usize;
    let mut seen = std::collections::HashSet::new();
    for raw in targets {
        match expand_argument(raw) {
            Ok(expanded) => {
                if expanded.from_file {
                    scanned_files += 1;
                }
                for target in expanded.targets {
                    if seen.insert(target.value().to_string()) {
                        parsed.push(target);
                    }
                }
            }
            Err(diagnostic) => {
                return emit_failure(
                    "check",
                    json,
                    diagnostic,
                    EXIT_INVALID_INVOCATION,
                    elapsed(start),
                );
            }
        }
    }

    let home = home_dir();
    let snapshot = match verified_fresh_snapshot(&home) {
        Ok(snapshot) => snapshot,
        Err((diagnostic, code)) => {
            return emit_failure("check", json, diagnostic, code, elapsed(start));
        }
    };

    let results: Vec<CheckResult> = parsed.iter().map(|target| snapshot.check(target)).collect();
    let envelope = CommandEnvelope::success_with_snapshot(
        "check",
        snapshot.manifest.snapshot_id.clone(),
        results,
        elapsed(start),
    );

    if json {
        print_json(&envelope);
    } else if scanned_files > 0 {
        render_scan(
            envelope.data.as_deref().unwrap_or(&[]),
            &snapshot.manifest.snapshot_id,
        );
    } else {
        render_check(
            envelope.data.as_deref().unwrap_or(&[]),
            &snapshot.manifest.snapshot_id,
        );
    }
    EXIT_OK
}

struct Expanded {
    targets: Vec<Target>,
    from_file: bool,
}

/// Turn one CLI argument into targets: a lockfile path expands to its
/// dependencies; anything else parses as a single CVE/package target.
fn expand_argument(raw: &str) -> Result<Expanded, Diagnostic> {
    let path = std::path::Path::new(raw);
    if path.is_file() {
        let format = LockFormat::detect(path).ok_or_else(|| {
            Diagnostic::new(
                codes::INVALID_TARGET,
                lockfile::LockfileError::UnknownFormat(
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(raw)
                        .to_string(),
                )
                .to_string(),
            )
        })?;
        let content = std::fs::read_to_string(path).map_err(|e| {
            Diagnostic::new(codes::INVALID_TARGET, format!("cannot read {raw}: {e}"))
        })?;
        let targets = lockfile::parse(format, &content)
            .map_err(|e| Diagnostic::new(codes::INVALID_TARGET, e.to_string()))?;
        Ok(Expanded {
            targets,
            from_file: true,
        })
    } else {
        let target = raw
            .parse::<Target>()
            .map_err(|e| Diagnostic::new(codes::INVALID_TARGET, e.to_string()))?;
        Ok(Expanded {
            targets: vec![target],
            from_file: false,
        })
    }
}

/// Open the active snapshot, mapping the distinct failure states to their
/// diagnostic codes and exit codes.
fn verified_fresh_snapshot(home: &std::path::Path) -> Result<Snapshot, (Diagnostic, u8)> {
    match active_snapshot_dir(home) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err((
                Diagnostic::new(
                    codes::DATASET_MISSING,
                    "no data snapshot installed — run `vulngraph update`",
                ),
                EXIT_OPERATIONAL,
            ));
        }
        Err(e) => {
            return Err((
                Diagnostic::new(codes::DATASET_INVALID, e.to_string()),
                EXIT_OPERATIONAL,
            ));
        }
    }

    match installed_manifest(home) {
        Ok(Some(manifest)) => {
            if let Err(e) = manifest.ensure_fresh() {
                let (diag_code, code) = match e {
                    DatasetError::Stale(_) => (codes::DATASET_STALE, EXIT_STALE),
                    _ => (codes::DATASET_INVALID, EXIT_OPERATIONAL),
                };
                return Err((Diagnostic::new(diag_code, e.to_string()), code));
            }
        }
        Ok(None) => {
            return Err((
                Diagnostic::new(codes::DATASET_MISSING, "no data snapshot installed"),
                EXIT_OPERATIONAL,
            ));
        }
        Err(e) => {
            return Err((
                Diagnostic::new(codes::DATASET_INVALID, e.to_string()),
                EXIT_OPERATIONAL,
            ));
        }
    }

    open_active(home).map_err(|e| {
        (
            Diagnostic::new(codes::DATASET_INVALID, e.to_string()),
            EXIT_OPERATIONAL,
        )
    })
}

// ─── status ───────────────────────────────────────

fn status(json: bool) -> u8 {
    let start = Instant::now();
    let home = home_dir();
    let mut integrity = "unavailable";
    let mut freshness = "unavailable";
    let mut snapshot = None;
    let mut installed = false;
    let mut stale = false;

    match installed_manifest(&home) {
        Ok(Some(manifest)) => {
            installed = true;
            integrity = "verified";
            snapshot = Some(SnapshotSummary {
                id: manifest.snapshot_id.clone(),
                created_at: manifest.created_at.clone(),
                node_count: manifest.node_count,
                edge_count: manifest.edge_count,
                engine_rev: manifest.engine_rev.clone(),
                format_version: manifest.format_version,
            });
            match manifest.ensure_fresh() {
                Ok(()) => freshness = "fresh",
                Err(DatasetError::Stale(_)) => {
                    freshness = "stale";
                    stale = true;
                }
                Err(_) => freshness = "unavailable",
            }
        }
        Ok(None) => {}
        Err(_) => integrity = "invalid",
    }

    let status = DatasetStatus {
        schema: STATUS_SCHEMA.to_string(),
        installed,
        home: home.display().to_string(),
        integrity: integrity.to_string(),
        freshness: freshness.to_string(),
        snapshot,
    };

    if json {
        print_json(&CommandEnvelope::success("status", status, elapsed(start)));
    } else {
        render_status(&status);
    }
    if stale { EXIT_STALE } else { EXIT_OK }
}

// ─── update ───────────────────────────────────────

fn update_command(
    json: bool,
    offline: bool,
    offline_dir: Option<PathBuf>,
    base_url: Option<String>,
) -> u8 {
    let start = Instant::now();
    if offline && offline_dir.is_none() {
        return emit_failure(
            "update",
            json,
            Diagnostic::new(
                codes::OFFLINE_INPUT_REQUIRED,
                "--offline requires --offline-dir pointing at release assets",
            ),
            EXIT_INVALID_INVOCATION,
            elapsed(start),
        );
    }

    let home = home_dir();
    let options = UpdateOptions {
        offline_dir,
        base_url,
    };
    match update(&home, &options) {
        Ok(report) => {
            if json {
                print_json(&CommandEnvelope::success_with_snapshot(
                    "update",
                    report.snapshot_id.clone(),
                    report,
                    elapsed(start),
                ));
            } else {
                render_update(&report);
            }
            EXIT_OK
        }
        Err(e) => {
            let (code, exit) = match e {
                DatasetError::Stale(_) => (codes::DATASET_STALE, EXIT_STALE),
                _ => (codes::UPDATE_FAILED, EXIT_OPERATIONAL),
            };
            emit_failure(
                "update",
                json,
                Diagnostic::new(code, e.to_string()),
                exit,
                elapsed(start),
            )
        }
    }
}

// ─── capabilities / schema ────────────────────────

fn capabilities(json: bool) -> u8 {
    let start = Instant::now();
    let capabilities = Capabilities::default();
    if json {
        print_json(&CommandEnvelope::success(
            "capabilities",
            capabilities,
            elapsed(start),
        ));
    } else {
        println!("vulngraph {}", env!("CARGO_PKG_VERSION"));
        println!("commands:       {}", capabilities.commands.join(", "));
        println!("output schemas: {}", capabilities.output_schemas.join(", "));
        println!("offline checks: {}", capabilities.offline_checks);
        println!("deterministic:  {}", capabilities.deterministic);
        println!("exit codes:");
        for ec in &capabilities.exit_codes {
            println!("  {} — {}", ec.code, ec.meaning);
        }
    }
    EXIT_OK
}

fn schema(name: SchemaName) -> u8 {
    let body = match name {
        SchemaName::Command => COMMAND_SCHEMA_JSON,
        SchemaName::Observation => OBSERVATION_SCHEMA_JSON,
        SchemaName::Status => STATUS_SCHEMA_JSON,
    };
    println!("{body}");
    EXIT_OK
}

// ─── rendering helpers ────────────────────────────

#[allow(clippy::cast_possible_truncation)]
fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

fn print_json<T: serde::Serialize>(envelope: &CommandEnvelope<T>) {
    match serde_json::to_string_pretty(envelope) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("error[{}]: {e}", codes::SERIALIZATION_FAILED),
    }
}

fn emit_failure(
    command: &str,
    json: bool,
    diagnostic: Diagnostic,
    code: u8,
    elapsed_us: u64,
) -> u8 {
    if json {
        let envelope: CommandEnvelope<()> =
            CommandEnvelope::failure(command, diagnostic, elapsed_us);
        print_json(&envelope);
    } else {
        eprintln!("error[{}]: {}", diagnostic.code, diagnostic.message);
    }
    code
}

fn disposition_label(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::ActivelyExploited => "ACTIVELY EXPLOITED",
        Disposition::Weaponized => "WEAPONIZED",
        Disposition::ProofOfConcept => "PROOF OF CONCEPT",
        Disposition::Scored => "SCORED",
        Disposition::Recorded => "RECORDED",
        Disposition::NotAffected => "NOT AFFECTED",
        Disposition::Unknown => "UNKNOWN",
    }
}

fn action_label(verdict: &vulngraph_core::verdict::Verdict) -> &'static str {
    use vulngraph_core::verdict::RecommendedAction as A;
    match verdict.action {
        A::PatchNow => "patch now",
        A::Prioritize => "prioritize",
        A::Monitor => "monitor",
        A::Investigate => "investigate",
        A::NoActionRequired => "no action required",
    }
}

fn render_check(results: &[CheckResult], snapshot_id: &str) {
    for result in results {
        println!();
        println!("  {}", result.target.value());
        let verdict = &result.verdict;
        println!(
            "  verdict: {}  (confidence {:.2})",
            disposition_label(verdict.disposition),
            verdict.confidence
        );
        println!("  action:  {}", action_label(verdict));
        if !verdict.reason_codes.is_empty() {
            println!("  reasons: {}", verdict.reason_codes.join(", "));
        }
        if let Some(meta) = &result.metadata {
            render_metadata(meta);
        }
        if !result.observations.is_empty() {
            println!("  observations:");
            for obs in &result.observations {
                println!(
                    "    - {} [{}] {}",
                    obs.classification, obs.source_id, obs.assertion
                );
            }
        }
        if let Some(findings) = &result.findings {
            for finding in findings {
                println!(
                    "    · {} — {} ({})",
                    finding.cve_id,
                    disposition_label(finding.verdict.disposition),
                    if finding.no_fix_available {
                        "no fix available"
                    } else {
                        "fix available"
                    }
                );
            }
        }
    }
    println!();
    println!("  snapshot: {snapshot_id}");
    println!();
}

/// Render a lockfile scan: a disposition histogram plus detail only for the
/// packages that are actually affected (noise from hundreds of clean deps
/// would bury the signal).
fn render_scan(results: &[CheckResult], snapshot_id: &str) {
    let mut counts: BTreeMap<Disposition, usize> = BTreeMap::new();
    let mut affected: Vec<&CheckResult> = Vec::new();
    for result in results {
        *counts.entry(result.verdict.disposition).or_insert(0) += 1;
        // "Affected" = a version range matched (recorded and above), i.e.
        // everything except not-affected and unknown.
        if result.verdict.disposition > Disposition::NotAffected {
            affected.push(result);
        }
    }
    affected.sort_by_key(|r| std::cmp::Reverse(r.verdict.disposition));

    println!();
    println!("  Scanned {} package(s)", results.len());
    // Highest severity first.
    for disposition in [
        Disposition::ActivelyExploited,
        Disposition::Weaponized,
        Disposition::ProofOfConcept,
        Disposition::Scored,
        Disposition::Recorded,
        Disposition::NotAffected,
        Disposition::Unknown,
    ] {
        if let Some(n) = counts.get(&disposition) {
            println!("    {:>4}  {}", n, disposition_label(disposition));
        }
    }

    if !affected.is_empty() {
        println!();
        println!("  Affected:");
        for result in affected {
            let count = result
                .metadata
                .as_ref()
                .and_then(|m| m.get("cves_affecting_version"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            println!(
                "    {}  {}  ({} CVE{})",
                disposition_label(result.verdict.disposition),
                result.target.value(),
                count,
                if count == 1 { "" } else { "s" }
            );
        }
    }
    println!();
    println!("  snapshot: {snapshot_id}");
    println!();
}

fn render_metadata(meta: &serde_json::Value) {
    if let Some(cvss) = meta.get("cvss").and_then(serde_json::Value::as_f64) {
        println!("  cvss:    {cvss:.1}");
    }
    if let Some(epss) = meta.get("epss").and_then(serde_json::Value::as_f64) {
        println!("  epss:    {:.1}%", epss * 100.0);
    }
    if meta.get("kev_listed").and_then(serde_json::Value::as_bool) == Some(true) {
        println!("  kev:     listed");
    }
    if let Some(pkg) = meta.get("package").and_then(serde_json::Value::as_str) {
        let count = meta
            .get("cves_affecting_version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        println!("  package: {pkg} — {count} CVE(s) affect this version");
    }
    if let Some(published) = meta.get("published").and_then(serde_json::Value::as_str) {
        println!("  published: {published}");
    }
}

fn render_status(status: &DatasetStatus) {
    println!("Installed:  {}", status.installed);
    println!("Home:       {}", status.home);
    println!("Integrity:  {}", status.integrity);
    println!("Freshness:  {}", status.freshness);
    if let Some(snapshot) = &status.snapshot {
        println!("Snapshot:   {}", snapshot.id);
        println!("Created:    {}", snapshot.created_at);
        println!(
            "Graph:      {} nodes / {} edges",
            snapshot.node_count, snapshot.edge_count
        );
        println!(
            "Engine:     {} (format v{})",
            snapshot.engine_rev, snapshot.format_version
        );
    }
}

fn render_update(report: &vulngraph_dataset::UpdateReport) {
    if report.noop {
        println!("Already up to date ({}).", report.snapshot_id);
        return;
    }
    println!("Installed {} ({})", report.snapshot_id, report.created_at);
    println!(
        "Graph:    {} nodes / {} edges",
        report.node_count, report.edge_count
    );
    println!("Engine:   {}", report.engine_rev);
    println!(
        "Ranges:   {} packages / {} version ranges ({} dropped)",
        report.vrb_packages, report.vrb_ranges, report.dropped_range_cves
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorthand_inserts_check_for_bare_cve() {
        let args = ["vulngraph", "CVE-2024-4577"].map(OsString::from);
        let out = normalize_shorthand(args);
        assert_eq!(out[1], OsString::from("check"));
        assert_eq!(out[2], OsString::from("CVE-2024-4577"));
    }

    #[test]
    fn shorthand_leaves_commands_untouched() {
        let args = ["vulngraph", "status"].map(OsString::from);
        assert_eq!(normalize_shorthand(args.clone()), args.to_vec());

        let args = ["vulngraph", "check", "CVE-2024-4577"].map(OsString::from);
        assert_eq!(normalize_shorthand(args.clone()), args.to_vec());
    }

    #[test]
    fn shorthand_ignores_packages_and_flags() {
        // Package shorthand is intentionally not auto-inserted.
        let args = ["vulngraph", "npm:lodash@1.0.0"].map(OsString::from);
        assert_eq!(normalize_shorthand(args.clone()), args.to_vec());

        let args = ["vulngraph", "--json", "status"].map(OsString::from);
        assert_eq!(normalize_shorthand(args.clone()), args.to_vec());
    }

    #[test]
    fn embedded_schemas_are_valid_json() {
        for body in [
            COMMAND_SCHEMA_JSON,
            OBSERVATION_SCHEMA_JSON,
            STATUS_SCHEMA_JSON,
        ] {
            let _: serde_json::Value = serde_json::from_str(body).unwrap();
        }
    }
}
