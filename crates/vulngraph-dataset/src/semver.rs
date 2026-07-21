//! Version-range semantics for package checks.
//!
//! SYNC: keep in sync with the private vulngraph repo,
//! `mcp/src/tools/batch.rs` (`version_in_ranges` / `parse_semver` /
//! `semver_cmp`). The shipped range strings already encode OSV
//! `last_affected` as an exclusive `fixed` bound (bumped at ingest), so
//! comparing them verbatim reproduces the server's semantics exactly.
//! Deviation from upstream: `semver_cmp` returns `Ordering` instead of a
//! signed integer — only the sign is ever consumed.

use std::cmp::Ordering;

/// Check if a version falls within any of the affected ranges.
/// Each range is (introduced, fixed). Version is affected if:
///   introduced <= version < fixed  (when fixed is Some)
///   introduced <= version           (when fixed is None — no fix available)
#[must_use]
pub fn version_in_ranges(version: &str, ranges: &[(String, Option<String>)]) -> bool {
    let ver = parse_semver(version);
    for (introduced, fixed) in ranges {
        let intro = parse_semver(introduced);
        if semver_cmp(&ver, &intro) == Ordering::Less {
            continue; // version is before introduced
        }
        match fixed {
            Some(fix) => {
                let fix_ver = parse_semver(fix);
                if semver_cmp(&ver, &fix_ver) == Ordering::Less {
                    return true; // introduced <= version < fixed → affected
                }
                // version >= fixed → not affected by this range, check next
            }
            None => return true, // no fix → still vulnerable
        }
    }
    false
}

/// Parse a version string into numeric components for comparison.
/// Handles: "1.2.3", "0.8.6", "1.0.0-rc1", "3.20.2"
/// Non-numeric suffixes (pre-release) are stripped for comparison.
#[must_use]
pub fn parse_semver(s: &str) -> Vec<u64> {
    let clean = s.trim_start_matches('v');
    clean
        .split('.')
        .map(|part| {
            // Take only leading digits (handles "1-beta", "2rc3", etc.)
            let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

/// Compare two semver tuples, treating missing components as 0.
#[must_use]
pub fn semver_cmp(a: &[u64], b: &[u64]) -> Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(intro: &str, fixed: Option<&str>) -> (String, Option<String>) {
        (intro.to_string(), fixed.map(str::to_string))
    }

    #[test]
    fn boundary_semantics() {
        let ranges = [r("4.0.0", Some("4.17.21"))];
        assert!(!version_in_ranges("3.9.9", &ranges), "before introduced");
        assert!(
            version_in_ranges("4.0.0", &ranges),
            "introduced is inclusive"
        );
        assert!(version_in_ranges("4.17.20", &ranges), "inside range");
        assert!(!version_in_ranges("4.17.21", &ranges), "fixed is exclusive");
        assert!(!version_in_ranges("5.0.0", &ranges), "after fixed");
    }

    #[test]
    fn no_fix_means_always_affected_from_introduced() {
        let ranges = [r("0", None)];
        assert!(version_in_ranges("0.0.1", &ranges));
        assert!(version_in_ranges("99.99.99", &ranges));
    }

    #[test]
    fn v_prefix_and_prerelease_suffixes() {
        assert_eq!(parse_semver("v1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_semver("1.0.0-rc1"), vec![1, 0, 0]);
        assert_eq!(parse_semver("2rc3.1"), vec![2, 1]);
        assert_eq!(parse_semver("abc"), vec![0]);
    }

    #[test]
    fn shorter_versions_pad_with_zero() {
        assert_eq!(
            semver_cmp(&parse_semver("1.2"), &parse_semver("1.2.0")),
            Ordering::Equal
        );
        assert_eq!(
            semver_cmp(&parse_semver("1.2"), &parse_semver("1.2.1")),
            Ordering::Less
        );
    }

    proptest::proptest! {
        #[test]
        fn cmp_is_total_order(a in proptest::collection::vec(0u64..1000, 0..5),
                              b in proptest::collection::vec(0u64..1000, 0..5),
                              c in proptest::collection::vec(0u64..1000, 0..5)) {
            use proptest::prelude::prop_assert;
            prop_assert!(semver_cmp(&a, &a) == Ordering::Equal);
            prop_assert!(semver_cmp(&a, &b) == semver_cmp(&b, &a).reverse());
            if semver_cmp(&a, &b) != Ordering::Greater
                && semver_cmp(&b, &c) != Ordering::Greater {
                prop_assert!(semver_cmp(&a, &c) != Ordering::Greater, "transitive");
            }
        }

        #[test]
        fn parse_never_panics(s in ".{0,64}") {
            let _ = parse_semver(&s);
        }
    }
}
