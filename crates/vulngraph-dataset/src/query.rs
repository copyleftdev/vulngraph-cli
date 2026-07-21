//! Deterministic local queries over an installed snapshot.
//!
//! Maps graph facts to typed `Observation`s; verdict derivation itself
//! lives in `vulngraph-core` and is pure.

use crate::artifact::InstalledManifest;
use crate::engine::graph::Graph;
use crate::engine::types::{EdgeType, NodeId};
use crate::semver::version_in_ranges;
use crate::snapshot_id::sha256_file;
use crate::vrb::VrbReader;
use crate::{DatasetError, Result};
use std::collections::BTreeSet;
use std::path::Path;
use vulngraph_core::OBSERVATION_SCHEMA;
use vulngraph_core::target::Target;
use vulngraph_core::verdict::{
    CheckResult, CveFinding, Observation, cvss_bucket, derive_package_verdict, derive_verdict,
};

/// Cap on per-classification observation fan-out so a CVE with hundreds of
/// PoCs stays readable; the full count is always in the metadata block.
const MAX_OBS_PER_KIND: usize = 10;
const MAX_DESCRIPTION_CHARS: usize = 500;

pub struct Snapshot {
    pub graph: Graph,
    pub vrb: VrbReader,
    pub manifest: InstalledManifest,
}

impl Snapshot {
    /// Open an installed snapshot directory and re-verify its integrity
    /// anchors (installed manifest, compiled VRB hash, graph open).
    ///
    /// # Errors
    /// Fails when any component is missing, corrupt, or inconsistent with
    /// the installed manifest.
    pub fn open(dir: &Path) -> Result<Self> {
        let manifest_path = dir.join("installed-manifest.json");
        let manifest: InstalledManifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
        manifest.validate()?;

        let graph = Graph::open(&dir.join("db"))?;
        if graph.node_count() as u64 != manifest.node_count
            || graph.edge_count() as u64 != manifest.edge_count
        {
            return Err(DatasetError::Invalid(format!(
                "graph counts ({} nodes / {} edges) disagree with installed manifest ({} / {})",
                graph.node_count(),
                graph.edge_count(),
                manifest.node_count,
                manifest.edge_count
            )));
        }

        let vrb_path = dir.join("compiled/version_ranges.bin");
        let (vrb_sha, _) = sha256_file(&vrb_path)?;
        if vrb_sha != manifest.vrb_sha256 {
            return Err(DatasetError::Invalid(
                "compiled version_ranges.bin hash disagrees with installed manifest".to_string(),
            ));
        }
        let vrb = VrbReader::open(&vrb_path)?;

        Ok(Self {
            graph,
            vrb,
            manifest,
        })
    }

    /// Check a single parsed target.
    #[must_use]
    pub fn check(&self, target: &Target) -> CheckResult {
        match target {
            Target::Cve { value } => self.check_cve(target, value),
            Target::Package {
                ecosystem,
                name,
                version,
                ..
            } => self.check_package(target, ecosystem, name, version),
        }
    }

    fn check_cve(&self, target: &Target, cve_id: &str) -> CheckResult {
        let Some((node_id, _)) = self.graph.node_by_id(cve_id) else {
            return CheckResult {
                schema: OBSERVATION_SCHEMA.to_string(),
                target: target.clone(),
                verdict: derive_verdict(&[]),
                observations: Vec::new(),
                findings: None,
                metadata: None,
            };
        };
        let (observations, metadata) = self.cve_observations(node_id);
        CheckResult {
            schema: OBSERVATION_SCHEMA.to_string(),
            target: target.clone(),
            verdict: derive_verdict(&observations),
            observations,
            findings: None,
            metadata: Some(metadata),
        }
    }

    fn check_package(
        &self,
        target: &Target,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> CheckResult {
        let key = format!("{ecosystem}:{name}");
        let in_graph = self.graph.node_by_id(&key).is_some();
        let ranges = self.vrb.lookup(&key);
        let package_known = in_graph || ranges.is_some();

        let mut findings: Vec<CveFinding> = Vec::new();
        if let Some(ranges) = ranges {
            // Group ranges by CVE node, preserving compile order (sorted by
            // CVE external id, so output order is deterministic).
            let mut order: Vec<u32> = Vec::new();
            let mut grouped: std::collections::HashMap<u32, Vec<(String, Option<String>)>> =
                std::collections::HashMap::new();
            for range in ranges {
                let entry = grouped.entry(range.cve_node).or_default();
                if entry.is_empty() {
                    order.push(range.cve_node);
                }
                entry.push(self.vrb.range_versions(range));
            }
            for cve_node in order {
                let cve_ranges = &grouped[&cve_node];
                if !version_in_ranges(version, cve_ranges) {
                    continue;
                }
                let node_id = NodeId(cve_node);
                let cve_id = self
                    .graph
                    .node(node_id)
                    .and_then(|h| self.graph.external_id(h))
                    .unwrap_or("?")
                    .to_string();
                let (mut observations, _) = self.cve_observations(node_id);
                let matched: Vec<&(String, Option<String>)> = cve_ranges
                    .iter()
                    .filter(|r| version_in_ranges(version, std::slice::from_ref(*r)))
                    .collect();
                let no_fix_available = matched.iter().any(|(_, fixed)| fixed.is_none());
                if let Some((introduced, fixed)) = matched.first() {
                    observations.push(Observation {
                        classification: "affected-version-range".to_string(),
                        source_id: "osv".to_string(),
                        independence_group: "osv".to_string(),
                        assertion: format!(
                            "introduced={introduced} fixed={}",
                            fixed.as_deref().unwrap_or("none")
                        ),
                        confidence: 0.90,
                    });
                }
                findings.push(CveFinding {
                    cve_id,
                    verdict: derive_verdict(&observations),
                    observations,
                    no_fix_available,
                });
            }
        }

        let verdict = derive_package_verdict(package_known, &findings);
        let metadata = serde_json::json!({
            "package": key,
            "version": version,
            "package_in_graph": in_graph,
            "cves_evaluated": ranges.map_or(0, <[_]>::len),
            "cves_affecting_version": findings.len(),
        });
        CheckResult {
            schema: OBSERVATION_SCHEMA.to_string(),
            target: target.clone(),
            verdict,
            observations: Vec::new(),
            findings: Some(findings),
            metadata: Some(metadata),
        }
    }

    /// Build the typed observations + metadata block for a CVE node.
    fn cve_observations(&self, node_id: NodeId) -> (Vec<Observation>, serde_json::Value) {
        let mut observations: Vec<Observation> = Vec::new();

        // KEV listing
        let kev = !self
            .graph
            .edges_from_typed(node_id, EdgeType::EXPLOITED_IN_WILD)
            .is_empty();
        if kev {
            observations.push(Observation {
                classification: "exploited-in-wild".to_string(),
                source_id: "cisa-kev".to_string(),
                independence_group: "cisa".to_string(),
                assertion: "listed-in-kev-catalog".to_string(),
                confidence: 0.99,
            });
        }

        // Public exploits (classified by external-id prefix)
        let poc_edges = self.graph.edges_from_typed(node_id, EdgeType::HAS_POC);
        let exploit_count = poc_edges.len();
        let mut seen_exploits: BTreeSet<String> = BTreeSet::new();
        for edge in poc_edges {
            if seen_exploits.len() >= MAX_OBS_PER_KIND {
                break;
            }
            let Some(ext_id) = self
                .graph
                .node(NodeId(edge.target))
                .and_then(|h| self.graph.external_id(h))
            else {
                continue;
            };
            if !seen_exploits.insert(ext_id.to_string()) {
                continue;
            }
            let source_id = if ext_id.starts_with("EDB:") {
                "exploitdb"
            } else if ext_id.starts_with("Nuclei:") {
                "nuclei"
            } else {
                "github-poc"
            };
            observations.push(Observation {
                classification: "public-exploit".to_string(),
                source_id: source_id.to_string(),
                independence_group: source_id.to_string(),
                assertion: ext_id.to_string(),
                confidence: 0.90,
            });
        }

        // EPSS
        let epss = self.graph.epss_score(node_id).filter(|s| *s > 0.0);
        let epss_pct = self.graph.epss_percentile(node_id).filter(|p| *p > 0.0);
        if let Some(score) = epss
            && score >= 0.5
        {
            observations.push(Observation {
                classification: "exploit-predicted".to_string(),
                source_id: "first-epss".to_string(),
                independence_group: "first".to_string(),
                assertion: format!("epss={score:.4} pct={:.4}", epss_pct.unwrap_or(0.0)),
                confidence: 0.80,
            });
        }

        // CVSS
        let cvss = self.graph.cvss_score(node_id).filter(|s| *s > 0.0);
        if let Some(score) = cvss {
            observations.push(Observation {
                classification: cvss_bucket(f64::from(score)).to_string(),
                source_id: "nvd-cvss".to_string(),
                independence_group: "nvd".to_string(),
                assertion: format!("cvss={score:.1}"),
                confidence: 0.85,
            });
        }

        // Weaknesses (CWE) and ATT&CK techniques reachable through them
        // and through exploit nodes.
        let mut cwes: BTreeSet<String> = BTreeSet::new();
        let mut techniques: BTreeSet<String> = BTreeSet::new();
        for edge in self
            .graph
            .edges_from_typed(node_id, EdgeType::CLASSIFIED_AS)
        {
            let cwe_node = NodeId(edge.target);
            if let Some(ext) = self
                .graph
                .node(cwe_node)
                .and_then(|h| self.graph.external_id(h))
            {
                cwes.insert(ext.to_string());
            }
            for tech_edge in self
                .graph
                .edges_from_typed(cwe_node, EdgeType::USES_TECHNIQUE)
            {
                if let Some(ext) = self
                    .graph
                    .node(NodeId(tech_edge.target))
                    .and_then(|h| self.graph.external_id(h))
                {
                    techniques.insert(ext.to_string());
                }
            }
        }
        for cwe in cwes.iter().take(MAX_OBS_PER_KIND) {
            observations.push(Observation {
                classification: "weakness".to_string(),
                source_id: "cwe".to_string(),
                independence_group: "mitre".to_string(),
                assertion: cwe.clone(),
                confidence: 0.70,
            });
        }
        for technique in techniques.iter().take(MAX_OBS_PER_KIND) {
            observations.push(Observation {
                classification: "attack-technique".to_string(),
                source_id: "mitre-attack".to_string(),
                independence_group: "mitre".to_string(),
                assertion: technique.clone(),
                confidence: 0.70,
            });
        }

        let description = self.graph.description(node_id).map(|d| {
            if d.chars().count() > MAX_DESCRIPTION_CHARS {
                let truncated: String = d.chars().take(MAX_DESCRIPTION_CHARS).collect();
                format!("{truncated}…")
            } else {
                d.to_string()
            }
        });
        let published = self.graph.published_at(node_id).and_then(|secs| {
            let ts = i64::try_from(secs).ok()?;
            let dt = chrono::DateTime::from_timestamp(ts, 0)?;
            Some(dt.format("%Y-%m-%d").to_string())
        });

        let metadata = serde_json::json!({
            "cvss": cvss,
            "epss": epss,
            "epss_percentile": epss_pct,
            "kev_listed": kev,
            "public_exploits": exploit_count,
            "published": published,
            "description": description,
        });
        (observations, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::testutil::FixtureDb;
    use crate::engine::types::NodeType;
    use vulngraph_core::verdict::Disposition;

    fn build_snapshot(dir: &Path) -> Snapshot {
        let mut fx = FixtureDb::new();
        let cve = fx.add_node("CVE-2024-4577", NodeType::CVE);
        let kev = fx.add_node("KEV:CVE-2024-4577", NodeType::EXPLOIT);
        let edb = fx.add_node("EDB:52331", NodeType::EXPLOIT);
        let pkg = fx.add_node("npm:lodash", NodeType::PACKAGE);
        let quiet = fx.add_node("CVE-2020-8203", NodeType::CVE);
        let cwe = fx.add_node("CWE-78", NodeType::WEAKNESS);
        fx.add_edge(cve, kev, EdgeType::EXPLOITED_IN_WILD);
        fx.add_edge(cve, edb, EdgeType::HAS_POC);
        fx.add_edge(cve, cwe, EdgeType::CLASSIFIED_AS);
        fx.add_edge(quiet, pkg, EdgeType::AFFECTS);
        fx.set_cvss(cve, 9.8);
        fx.set_epss(cve, 0.94, 0.999);
        fx.set_cvss(quiet, 7.4);
        fx.set_description(cve, "PHP CGI argument injection.");
        fx.set_published(cve, 1_717_900_000);

        let db_dir = dir.join("db");
        fx.write(&db_dir).unwrap();
        let graph = Graph::open(&db_dir).unwrap();

        let vr = serde_json::json!({
            "npm:lodash": { "CVE-2020-8203": [["3.7.0", "4.17.19"]] }
        });
        let json_path = dir.join("version_ranges.json");
        std::fs::write(&json_path, serde_json::to_vec(&vr).unwrap()).unwrap();
        let vrb_path = dir.join("compiled/version_ranges.bin");
        crate::vrb::compile(&json_path, &graph, &vrb_path).unwrap();
        let (vrb_sha, _) = sha256_file(&vrb_path).unwrap();

        let manifest = InstalledManifest {
            schema: crate::artifact::INSTALLED_SCHEMA.to_string(),
            snapshot_id: format!("sha256:{}", "a".repeat(64)),
            created_at: "2026-07-21T02:00:00Z".to_string(),
            format_version: 1,
            engine_rev: "engine-v0.1.0".to_string(),
            node_count: graph.node_count() as u64,
            edge_count: graph.edge_count() as u64,
            vrb_sha256: vrb_sha,
            installed_at: "2026-07-21T03:00:00Z".to_string(),
        };
        std::fs::write(
            dir.join("installed-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        Snapshot::open(dir).unwrap()
    }

    #[test]
    fn kev_cve_is_actively_exploited() {
        let dir = tempfile::tempdir().unwrap();
        let snap = build_snapshot(dir.path());
        let target: Target = "CVE-2024-4577".parse().unwrap();
        let result = snap.check(&target);
        assert_eq!(result.verdict.disposition, Disposition::ActivelyExploited);
        assert!(
            result
                .observations
                .iter()
                .any(|o| o.source_id == "exploitdb")
        );
        let meta = result.metadata.unwrap();
        assert_eq!(meta["kev_listed"], true);
        assert_eq!(meta["published"], "2024-06-09");
    }

    #[test]
    fn unknown_cve_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let snap = build_snapshot(dir.path());
        let target: Target = "CVE-1999-9999".parse().unwrap();
        let result = snap.check(&target);
        assert_eq!(result.verdict.disposition, Disposition::Unknown);
        assert!(result.observations.is_empty());
    }

    #[test]
    fn package_version_inside_and_outside_range() {
        let dir = tempfile::tempdir().unwrap();
        let snap = build_snapshot(dir.path());

        let vulnerable: Target = "npm:lodash@4.17.15".parse().unwrap();
        let result = snap.check(&vulnerable);
        assert!(result.verdict.disposition > Disposition::NotAffected);
        let findings = result.findings.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cve_id, "CVE-2020-8203");

        let fixed: Target = "npm:lodash@4.17.19".parse().unwrap();
        let result = snap.check(&fixed);
        assert_eq!(result.verdict.disposition, Disposition::NotAffected);

        let unknown: Target = "npm:no-such-package@1.0.0".parse().unwrap();
        let result = snap.check(&unknown);
        assert_eq!(result.verdict.disposition, Disposition::Unknown);
    }

    #[test]
    fn snapshot_open_rejects_tampered_vrb() {
        let dir = tempfile::tempdir().unwrap();
        let _ = build_snapshot(dir.path());
        // Flip one byte in the compiled VRB — open must refuse.
        let vrb_path = dir.path().join("compiled/version_ranges.bin");
        let mut bytes = std::fs::read(&vrb_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&vrb_path, &bytes).unwrap();
        assert!(Snapshot::open(dir.path()).is_err());
    }
}
