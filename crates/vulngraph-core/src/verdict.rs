//! Verdict policy: typed observations in, deterministic verdict out.
//!
//! The policy is pure — no clock, no I/O, no float comparisons other than
//! fixed thresholds — so it is property-testable and its outputs are part
//! of the product contract.

use crate::target::Target;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Severity-ordered dispositions. `unknown` is never rendered as clean:
/// absence of evidence is reported as absence, not safety.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    Unknown,
    NotAffected,
    Recorded,
    Scored,
    ProofOfConcept,
    Weaponized,
    ActivelyExploited,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendedAction {
    PatchNow,
    Prioritize,
    Monitor,
    Investigate,
    NoActionRequired,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Verdict {
    pub disposition: Disposition,
    pub confidence: f64,
    pub action: RecommendedAction,
    pub reason_codes: Vec<String>,
}

/// A single typed piece of evidence read from the graph snapshot.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Observation {
    /// e.g. `exploited-in-wild`, `public-exploit`, `severity-critical`.
    pub classification: String,
    /// e.g. `cisa-kev`, `exploitdb`, `nvd-cvss`.
    pub source_id: String,
    /// Sources sharing an upstream share a group; corroboration counts
    /// distinct groups, not records.
    pub independence_group: String,
    /// Human-legible core claim, e.g. `epss=0.94 pct=0.999` or `EDB-52331`.
    pub assertion: String,
    pub confidence: f64,
}

/// One CVE finding inside a package check.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CveFinding {
    pub cve_id: String,
    pub verdict: Verdict,
    pub observations: Vec<Observation>,
    /// True when some matched range has no fixed version.
    pub no_fix_available: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CheckResult {
    pub schema: String,
    pub target: Target,
    pub verdict: Verdict,
    pub observations: Vec<Observation>,
    /// Present for package targets: per-CVE findings behind the verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<Vec<CveFinding>>,
    /// Free-form metadata block (scores, description, published date).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[must_use]
pub fn cvss_bucket(score: f64) -> &'static str {
    if score >= 9.0 {
        "severity-critical"
    } else if score >= 7.0 {
        "severity-high"
    } else if score >= 4.0 {
        "severity-medium"
    } else {
        "severity-low"
    }
}

fn severity_of(classification: &str) -> (u8, &'static str) {
    match classification {
        "exploited-in-wild" => (5, "KNOWN_EXPLOITED"),
        "public-exploit" => (3, "PUBLIC_EXPLOIT"),
        "exploit-predicted" => (2, "HIGH_EXPLOIT_PROBABILITY"),
        "severity-critical" => (2, "CRITICAL_SEVERITY"),
        "severity-high" => (2, "HIGH_SEVERITY"),
        "severity-medium" | "severity-low" => (1, "SEVERITY_SCORED"),
        "attack-technique" => (1, "ATTACK_MAPPED"),
        "weakness" => (1, "WEAKNESS_CLASSIFIED"),
        "affected-version-range" => (1, "VERSION_IN_AFFECTED_RANGE"),
        _ => (1, "THREAT_OBSERVATION"),
    }
}

fn epss_score(assertion: &str) -> Option<f64> {
    // assertion form: "epss=<score> pct=<percentile>"
    assertion
        .strip_prefix("epss=")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Derive a verdict for a CVE target from its observations.
#[must_use]
pub fn derive_verdict(observations: &[Observation]) -> Verdict {
    if observations.is_empty() {
        return Verdict {
            disposition: Disposition::Unknown,
            confidence: 0.0,
            action: RecommendedAction::Investigate,
            reason_codes: vec!["NOT_OBSERVED".to_string()],
        };
    }

    let mut severity: u8 = 0;
    let mut reasons: BTreeSet<&'static str> = BTreeSet::new();
    let mut groups: BTreeSet<&str> = BTreeSet::new();
    let mut max_confidence: f64 = 0.0;
    let mut has_public_exploit = false;
    let mut predicted_ge_90 = false;

    for obs in observations {
        let (sev, reason) = severity_of(&obs.classification);
        if sev >= severity {
            severity = sev;
        }
        reasons.insert(reason);
        groups.insert(&obs.independence_group);
        if obs.confidence > max_confidence {
            max_confidence = obs.confidence;
        }
        match obs.classification.as_str() {
            "public-exploit" => has_public_exploit = true,
            "exploit-predicted" if epss_score(&obs.assertion).is_some_and(|s| s >= 0.9) => {
                predicted_ge_90 = true;
            }
            _ => {}
        }
    }

    // SYNC: mirrors exploit_maturity in the private vulngraph MCP server —
    // public exploit + EPSS >= 0.9 without KEV is treated as weaponized.
    if severity < 4 && has_public_exploit && predicted_ge_90 {
        severity = 4;
        reasons.insert("WEAPONIZED_COMBINATION");
    }

    let (disposition, action) = match severity {
        5 => (Disposition::ActivelyExploited, RecommendedAction::PatchNow),
        4 => (Disposition::Weaponized, RecommendedAction::PatchNow),
        3 => (Disposition::ProofOfConcept, RecommendedAction::Prioritize),
        2 => {
            let hot = reasons.contains("CRITICAL_SEVERITY")
                || reasons.contains("HIGH_EXPLOIT_PROBABILITY");
            (
                Disposition::Scored,
                if hot {
                    RecommendedAction::Prioritize
                } else {
                    RecommendedAction::Monitor
                },
            )
        }
        _ => (Disposition::Recorded, RecommendedAction::Monitor),
    };

    let extra_groups = groups.len().saturating_sub(1);
    #[allow(clippy::cast_precision_loss)]
    let mut confidence = max_confidence + 0.02 * extra_groups as f64;
    if confidence > 0.99 {
        confidence = 0.99;
    }
    let mut reason_codes: Vec<String> = reasons.into_iter().map(str::to_string).collect();
    if extra_groups > 0 {
        reason_codes.push("MULTISOURCE_CORROBORATION".to_string());
        reason_codes.sort();
    }

    Verdict {
        disposition,
        confidence,
        action,
        reason_codes,
    }
}

/// Derive a package-target verdict from per-CVE findings.
#[must_use]
pub fn derive_package_verdict(package_known: bool, findings: &[CveFinding]) -> Verdict {
    if !package_known {
        return Verdict {
            disposition: Disposition::Unknown,
            confidence: 0.0,
            action: RecommendedAction::Investigate,
            reason_codes: vec!["NOT_OBSERVED".to_string()],
        };
    }
    let worst = findings.iter().max_by(|a, b| {
        a.verdict
            .disposition
            .cmp(&b.verdict.disposition)
            .then(a.verdict.confidence.total_cmp(&b.verdict.confidence))
    });
    let Some(worst) = worst else {
        // Affirmative: package known, every affected range evaluated,
        // this version outside all of them. Distinct from unknown.
        return Verdict {
            disposition: Disposition::NotAffected,
            confidence: 0.90,
            action: RecommendedAction::NoActionRequired,
            reason_codes: vec!["VERSION_NOT_AFFECTED".to_string()],
        };
    };

    let mut reasons: BTreeSet<String> = findings
        .iter()
        .flat_map(|f| f.verdict.reason_codes.iter().cloned())
        .collect();
    if findings.iter().any(|f| f.no_fix_available) {
        reasons.insert("NO_FIX_AVAILABLE".to_string());
    }

    Verdict {
        disposition: worst.verdict.disposition,
        confidence: worst.verdict.confidence,
        action: worst.verdict.action,
        reason_codes: reasons.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::Strategy;

    fn obs(class: &str, source: &str, group: &str, assertion: &str, conf: f64) -> Observation {
        Observation {
            classification: class.to_string(),
            source_id: source.to_string(),
            independence_group: group.to_string(),
            assertion: assertion.to_string(),
            confidence: conf,
        }
    }

    #[test]
    fn empty_is_unknown_never_clean() {
        let v = derive_verdict(&[]);
        assert_eq!(v.disposition, Disposition::Unknown);
        assert_eq!(v.reason_codes, vec!["NOT_OBSERVED"]);
        assert_eq!(v.action, RecommendedAction::Investigate);
    }

    #[test]
    fn kev_dominates() {
        let v = derive_verdict(&[
            obs(
                "exploited-in-wild",
                "cisa-kev",
                "cisa",
                "listed-in-kev-catalog",
                0.99,
            ),
            obs("severity-low", "nvd-cvss", "nvd", "cvss=2.0", 0.85),
        ]);
        assert_eq!(v.disposition, Disposition::ActivelyExploited);
        assert_eq!(v.action, RecommendedAction::PatchNow);
        assert!(v.reason_codes.contains(&"KNOWN_EXPLOITED".to_string()));
    }

    #[test]
    fn weaponized_combination() {
        let v = derive_verdict(&[
            obs(
                "public-exploit",
                "exploitdb",
                "exploitdb",
                "EDB-52331",
                0.90,
            ),
            obs(
                "exploit-predicted",
                "first-epss",
                "first",
                "epss=0.94 pct=0.999",
                0.80,
            ),
        ]);
        assert_eq!(v.disposition, Disposition::Weaponized);
        assert!(
            v.reason_codes
                .contains(&"WEAPONIZED_COMBINATION".to_string())
        );
    }

    #[test]
    fn poc_without_high_epss_stays_poc() {
        let v = derive_verdict(&[
            obs(
                "public-exploit",
                "github-poc",
                "github",
                "GitHub-PoC:CVE-X:0",
                0.90,
            ),
            obs(
                "exploit-predicted",
                "first-epss",
                "first",
                "epss=0.55 pct=0.9",
                0.80,
            ),
        ]);
        assert_eq!(v.disposition, Disposition::ProofOfConcept);
    }

    #[test]
    fn corroboration_bumps_confidence() {
        let single = derive_verdict(&[obs("severity-high", "nvd-cvss", "nvd", "cvss=8.1", 0.85)]);
        let multi = derive_verdict(&[
            obs("severity-high", "nvd-cvss", "nvd", "cvss=8.1", 0.85),
            obs("weakness", "cwe", "mitre", "CWE-79", 0.70),
        ]);
        assert!(multi.confidence > single.confidence);
        assert!(
            multi
                .reason_codes
                .contains(&"MULTISOURCE_CORROBORATION".to_string())
        );
    }

    #[test]
    fn package_unknown_vs_not_affected() {
        assert_eq!(
            derive_package_verdict(false, &[]).disposition,
            Disposition::Unknown
        );
        let clean = derive_package_verdict(true, &[]);
        assert_eq!(clean.disposition, Disposition::NotAffected);
        assert_eq!(clean.action, RecommendedAction::NoActionRequired);
    }

    #[test]
    fn package_takes_worst_finding_and_flags_no_fix() {
        let finding = |disp: Disposition, no_fix: bool| CveFinding {
            cve_id: "CVE-2020-8203".to_string(),
            verdict: Verdict {
                disposition: disp,
                confidence: 0.9,
                action: RecommendedAction::Prioritize,
                reason_codes: vec!["PUBLIC_EXPLOIT".to_string()],
            },
            observations: vec![],
            no_fix_available: no_fix,
        };
        let v = derive_package_verdict(
            true,
            &[
                finding(Disposition::Scored, false),
                finding(Disposition::ProofOfConcept, true),
            ],
        );
        assert_eq!(v.disposition, Disposition::ProofOfConcept);
        assert!(v.reason_codes.contains(&"NO_FIX_AVAILABLE".to_string()));
    }

    proptest::proptest! {
        #[test]
        fn confidence_bounded(observations in proptest::collection::vec(
            (proptest::sample::select(vec![
                "exploited-in-wild", "public-exploit", "exploit-predicted",
                "severity-critical", "severity-high", "severity-medium",
                "attack-technique", "weakness", "affected-version-range", "other",
            ]), "[a-z]{1,8}", 0.0f64..1.0)
                .prop_map(|(c, g, conf)| super::Observation {
                    classification: c.to_string(),
                    source_id: g.clone(),
                    independence_group: g,
                    assertion: "epss=0.95 pct=0.99".to_string(),
                    confidence: conf,
                }), 0..12)) {
            use proptest::prelude::prop_assert;
            let v = derive_verdict(&observations);
            prop_assert!((0.0..=0.99).contains(&v.confidence));
            prop_assert!(!v.reason_codes.is_empty());
            let mut sorted = v.reason_codes.clone();
            sorted.sort();
            sorted.dedup();
            prop_assert!(sorted == v.reason_codes, "reason codes sorted+deduped");
            if observations.is_empty() {
                prop_assert!(v.disposition == Disposition::Unknown);
            } else {
                prop_assert!(v.disposition != Disposition::Unknown);
            }
        }

        #[test]
        fn adding_kev_never_lowers(disposition_obs in proptest::collection::vec(
            proptest::sample::select(vec!["public-exploit", "severity-high", "weakness"]),
            0..6)) {
            use proptest::prelude::prop_assert;
            let base: Vec<_> = disposition_obs.iter().map(|c| super::Observation {
                classification: (*c).to_string(),
                source_id: "s".to_string(),
                independence_group: "g".to_string(),
                assertion: String::new(),
                confidence: 0.5,
            }).collect();
            let without = derive_verdict(&base);
            let mut with = base;
            with.push(super::Observation {
                classification: "exploited-in-wild".to_string(),
                source_id: "cisa-kev".to_string(),
                independence_group: "cisa".to_string(),
                assertion: "listed-in-kev-catalog".to_string(),
                confidence: 0.99,
            });
            let v = derive_verdict(&with);
            prop_assert!(v.disposition >= without.disposition);
            prop_assert!(v.disposition == Disposition::ActivelyExploited);
        }
    }
}
