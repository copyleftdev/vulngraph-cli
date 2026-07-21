//! Check-target grammar: `CVE-YYYY-NNNN…` or `ecosystem:name@version`.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Canonical OSV ecosystem casings as stored in the graph, keyed by
/// lowercase alias.
const ECOSYSTEM_ALIASES: &[(&str, &str)] = &[
    ("npm", "npm"),
    ("pypi", "PyPI"),
    ("crates.io", "crates.io"),
    ("crates", "crates.io"),
    ("cargo", "crates.io"),
    ("go", "Go"),
    ("golang", "Go"),
    ("maven", "Maven"),
    ("rubygems", "RubyGems"),
    ("gem", "RubyGems"),
    ("packagist", "Packagist"),
    ("composer", "Packagist"),
    ("nuget", "NuGet"),
    ("hex", "Hex"),
    ("pub", "Pub"),
    ("debian", "Debian"),
    ("alpine", "Alpine"),
];

const MAX_ECOSYSTEM_LEN: usize = 64;
const MAX_NAME_LEN: usize = 512;
const MAX_VERSION_LEN: usize = 128;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Target {
    Cve {
        /// Canonical uppercase form, e.g. `CVE-2024-4577`.
        value: String,
    },
    Package {
        /// Canonical `ecosystem:name@version` form.
        value: String,
        ecosystem: String,
        name: String,
        version: String,
    },
}

impl Target {
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::Cve { value } | Self::Package { value, .. } => value,
        }
    }

    /// Graph external-id key for package targets (`ecosystem:name`).
    #[must_use]
    pub fn package_key(&self) -> Option<String> {
        match self {
            Self::Package {
                ecosystem, name, ..
            } => Some(format!("{ecosystem}:{name}")),
            Self::Cve { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetError {
    pub input: String,
    pub reason: String,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid target '{}': {} (expected CVE-YYYY-NNNN or ecosystem:name@version)",
            self.input, self.reason
        )
    }
}

impl std::error::Error for TargetError {}

fn err(input: &str, reason: &str) -> TargetError {
    TargetError {
        input: input.to_string(),
        reason: reason.to_string(),
    }
}

fn parse_cve(input: &str) -> Result<Target, TargetError> {
    let upper = input.to_ascii_uppercase();
    let mut parts = upper.split('-');
    let (Some(prefix), Some(year), Some(num), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(err(input, "malformed CVE id"));
    };
    if prefix != "CVE" {
        return Err(err(input, "malformed CVE id"));
    }
    if year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(input, "CVE year must be 4 digits"));
    }
    if num.len() < 4 || num.len() > 19 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(input, "CVE sequence must be 4-19 digits"));
    }
    Ok(Target::Cve { value: upper })
}

fn canonical_ecosystem(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    for (alias, canonical) in ECOSYSTEM_ALIASES {
        if lower == *alias {
            return (*canonical).to_string();
        }
    }
    // Unrecognized ecosystems pass through verbatim; a graph miss yields
    // an `unknown` verdict, not a parse error.
    raw.to_string()
}

fn parse_package(input: &str) -> Result<Target, TargetError> {
    let (eco_raw, rest) = input
        .split_once(':')
        .ok_or_else(|| err(input, "missing ':'"))?;
    if eco_raw.is_empty() || eco_raw.len() > MAX_ECOSYSTEM_LEN {
        return Err(err(input, "bad ecosystem"));
    }
    if eco_raw
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(err(input, "bad ecosystem"));
    }
    // Split at the LAST '@' so scoped npm names parse: npm:@scope/pkg@1.2.3
    let (name, version) = rest
        .rsplit_once('@')
        .ok_or_else(|| err(input, "missing '@version'"))?;
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(err(input, "bad package name"));
    }
    if name
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(err(input, "bad package name"));
    }
    if version.is_empty() || version.len() > MAX_VERSION_LEN {
        return Err(err(input, "bad version"));
    }
    if version
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(err(input, "bad version"));
    }
    let ecosystem = canonical_ecosystem(eco_raw);
    Ok(Target::Package {
        value: format!("{ecosystem}:{name}@{version}"),
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
    })
}

impl FromStr for Target {
    type Err = TargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > MAX_NAME_LEN + MAX_ECOSYSTEM_LEN + MAX_VERSION_LEN + 2 {
            return Err(err(s, "empty or oversized target"));
        }
        if s.len() >= 4 && s.as_bytes()[..4].eq_ignore_ascii_case(b"cve-") {
            parse_cve(s)
        } else if s.contains(':') {
            parse_package(s)
        } else {
            Err(err(s, "unrecognized target form"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_parses_and_canonicalizes() {
        let t: Target = "cve-2024-4577".parse().unwrap();
        assert_eq!(t.value(), "CVE-2024-4577");
        assert!("CVE-2024-45771234".parse::<Target>().is_ok());
    }

    #[test]
    fn cve_rejects_malformed() {
        for bad in [
            "CVE-24-4577",
            "CVE-2024-1",
            "CVE-2024-",
            "CVE-2024-abc",
            "CVE--2024-4577",
        ] {
            assert!(bad.parse::<Target>().is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn package_parses_with_alias_and_scope() {
        let t: Target = "PYPI:requests@2.31.0".parse().unwrap();
        assert_eq!(t.value(), "PyPI:requests@2.31.0");
        assert_eq!(t.package_key().unwrap(), "PyPI:requests");

        let t: Target = "npm:@babel/core@7.0.0".parse().unwrap();
        match &t {
            Target::Package { name, version, .. } => {
                assert_eq!(name, "@babel/core");
                assert_eq!(version, "7.0.0");
            }
            Target::Cve { .. } => panic!("expected package"),
        }
    }

    #[test]
    fn unknown_ecosystem_passes_through() {
        let t: Target = "conda:numpy@1.0".parse().unwrap();
        assert_eq!(t.package_key().unwrap(), "conda:numpy");
    }

    #[test]
    fn package_rejects_malformed() {
        for bad in [
            "npm:lodash",
            ":lodash@1",
            "npm:@1.0",
            "npm:lodash@",
            "lodash",
            "npm: a@1",
        ] {
            assert!(bad.parse::<Target>().is_err(), "{bad} should fail");
        }
    }

    proptest::proptest! {
        #[test]
        fn parser_never_panics(s in ".{0,300}") {
            let _ = s.parse::<Target>();
        }

        #[test]
        fn canonical_forms_round_trip(year in 1999u32..2100, num in 1000u32..999_999) {
            let s = format!("CVE-{year}-{num}");
            let t: Target = s.parse().unwrap();
            proptest::prop_assert_eq!(t.value(), s.as_str());
            let again: Target = t.value().parse().unwrap();
            proptest::prop_assert_eq!(again, t);
        }
    }
}
