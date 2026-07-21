//! Smoke tests against a real vulngraph database. Ignored by default —
//! run explicitly on a machine with a built snapshot:
//!
//! ```sh
//! VULNGRAPH_REAL_DB=~/Project/vulngraph-data/builds/vulngraph.db \
//!     cargo test -p vulngraph-dataset --test real_data -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use vulngraph_dataset::engine::graph::Graph;
use vulngraph_dataset::semver::version_in_ranges;
use vulngraph_dataset::vrb;

fn real_db() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var("VULNGRAPH_REAL_DB").ok()?);
    path.is_dir().then_some(path)
}

#[test]
#[ignore = "requires a real database (set VULNGRAPH_REAL_DB)"]
fn opens_real_db_and_answers_known_lookups() {
    let db = real_db().expect("VULNGRAPH_REAL_DB not set or not a directory");
    let graph = Graph::open(&db).expect("vendored reader must open the real db");
    assert!(graph.node_count() > 500_000, "expected the full graph");

    let (node, _) = graph
        .node_by_id("CVE-2024-4577")
        .expect("known KEV CVE present");
    assert!(graph.cvss_score(node).is_some_and(|s| s > 9.0));
    assert!(graph.epss_score(node).is_some_and(|s| s > 0.5));
    assert!(
        !graph
            .edges_from_typed(
                node,
                vulngraph_dataset::engine::types::EdgeType::EXPLOITED_IN_WILD
            )
            .is_empty(),
        "CVE-2024-4577 is KEV-listed"
    );
    assert!(graph.description(node).is_some());

    let cves = graph.cves_for_package("npm:lodash");
    assert!(!cves.is_empty(), "lodash has known CVEs");
}

#[test]
#[ignore = "requires a real database (set VULNGRAPH_REAL_DB)"]
fn snapshot_id_matches_pipeline_implementation() {
    let db = real_db().expect("VULNGRAPH_REAL_DB not set");
    let computed = vulngraph_dataset::snapshot_id::snapshot_id(&db).unwrap();
    println!("computed snapshot_id: {computed}");
    if let Ok(expected) = std::env::var("VULNGRAPH_EXPECT_SNAPSHOT") {
        assert_eq!(computed, expected);
    }
}

#[test]
#[ignore = "requires a real database (set VULNGRAPH_REAL_DB)"]
fn vrb_compile_of_real_ranges_matches_json_reference() {
    let db = real_db().expect("VULNGRAPH_REAL_DB not set");
    let graph = Graph::open(&db).unwrap();
    let out = tempfile::tempdir().unwrap();
    let vrb_path = out.path().join("version_ranges.bin");

    let started = std::time::Instant::now();
    let stats = vrb::compile(&db.join("version_ranges.json"), &graph, &vrb_path).unwrap();
    println!(
        "compiled {} packages / {} ranges ({} dropped) in {:.1}s -> {} bytes",
        stats.packages,
        stats.ranges,
        stats.dropped_range_cves,
        started.elapsed().as_secs_f64(),
        std::fs::metadata(&vrb_path).unwrap().len()
    );
    assert!(
        stats.packages > 50_000,
        "real data has tens of thousands of packages"
    );

    let reader = vrb::VrbReader::open(&vrb_path).unwrap();

    // JSON reference for a sample of packages: verdict for a fixed probe
    // version must be identical through both paths.
    let raw = std::fs::read(db.join("version_ranges.json")).unwrap();
    let parsed: vrb::VersionRangesJson = serde_json::from_slice(&raw).unwrap();
    let mut checked = 0usize;
    for (pkg, cves) in parsed.iter().take(500) {
        let compiled = reader.lookup(pkg);
        for (cve_id, ranges) in cves {
            let Some((node_id, _)) = graph.node_by_id(cve_id) else {
                continue;
            };
            let compiled_ranges: Vec<(String, Option<String>)> = compiled
                .into_iter()
                .flatten()
                .filter(|r| r.cve_node == node_id.0)
                .map(|r| reader.range_versions(r))
                .collect();
            // A CVE with a non-empty range set must survive compile; an
            // empty set legitimately compiles to nothing (both paths agree
            // that every probe is unaffected).
            if !ranges.is_empty() {
                assert!(
                    !compiled_ranges.is_empty(),
                    "{pkg}/{cve_id} lost in compile"
                );
            }
            for probe in ["0.0.1", "1.2.3", "4.17.20", "99.0.0"] {
                assert_eq!(
                    version_in_ranges(probe, ranges),
                    version_in_ranges(probe, &compiled_ranges),
                    "{pkg}/{cve_id} probe {probe} diverged"
                );
            }
            checked += 1;
        }
    }
    println!("verified {checked} package/CVE range sets against the JSON reference");
    assert!(checked > 100);
}
