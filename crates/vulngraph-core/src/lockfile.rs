//! Lockfile / manifest parsing → package targets.
//!
//! SYNC: parser bodies mirror the private vulngraph repo,
//! `mcp/src/tools/batch.rs` (the `parse_*` lockfile functions). They emit
//! canonical OSV ecosystem casings, so the resulting `Target::Package`
//! keys match graph external ids directly. Deps without a concrete version
//! are dropped (nothing to check a range against).

use crate::target::Target;
use serde_json::Value;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockFormat {
    PackageLockJson,
    YarnLock,
    PnpmLock,
    CargoLock,
    GemfileLock,
    PoetryLock,
    RequirementsTxt,
    GoSum,
    ComposerLock,
    PomXml,
    GradleLockfile,
    PipfileLock,
}

impl LockFormat {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::PackageLockJson => "package-lock.json",
            Self::YarnLock => "yarn.lock",
            Self::PnpmLock => "pnpm-lock.yaml",
            Self::CargoLock => "Cargo.lock",
            Self::GemfileLock => "Gemfile.lock",
            Self::PoetryLock => "poetry.lock",
            Self::RequirementsTxt => "requirements.txt",
            Self::GoSum => "go.sum",
            Self::ComposerLock => "composer.lock",
            Self::PomXml => "pom.xml",
            Self::GradleLockfile => "gradle.lockfile",
            Self::PipfileLock => "Pipfile.lock",
        }
    }

    /// Detect a format from a path's file name.
    #[must_use]
    pub fn detect(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        let lower = name.to_ascii_lowercase();
        Some(match lower.as_str() {
            "package-lock.json" | "npm-shrinkwrap.json" => Self::PackageLockJson,
            "yarn.lock" => Self::YarnLock,
            "pnpm-lock.yaml" => Self::PnpmLock,
            "cargo.lock" => Self::CargoLock,
            "gemfile.lock" => Self::GemfileLock,
            "poetry.lock" => Self::PoetryLock,
            "requirements.txt" => Self::RequirementsTxt,
            "go.sum" => Self::GoSum,
            "composer.lock" => Self::ComposerLock,
            "pom.xml" => Self::PomXml,
            "gradle.lockfile" => Self::GradleLockfile,
            "pipfile.lock" => Self::PipfileLock,
            _ => {
                // requirements-dev.txt, dev-requirements.txt, etc.
                if lower.ends_with("requirements.txt") || lower.starts_with("requirements") {
                    Self::RequirementsTxt
                } else {
                    return None;
                }
            }
        })
    }
}

#[derive(Debug)]
pub enum LockfileError {
    UnknownFormat(String),
    Parse(String),
}

impl fmt::Display for LockfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormat(name) => write!(
                f,
                "unrecognized lockfile '{name}' — supported: package-lock.json, yarn.lock, \
                 pnpm-lock.yaml, Cargo.lock, Gemfile.lock, poetry.lock, requirements.txt, \
                 go.sum, composer.lock, pom.xml, gradle.lockfile, Pipfile.lock"
            ),
            Self::Parse(msg) => write!(f, "lockfile parse error: {msg}"),
        }
    }
}

impl std::error::Error for LockfileError {}

/// A parsed dependency before conversion to a `Target`.
struct Dep {
    ecosystem: &'static str,
    name: String,
    version: String,
}

fn to_targets(deps: Vec<Dep>) -> Vec<Target> {
    let mut targets = Vec::with_capacity(deps.len());
    for dep in deps {
        if dep.name.is_empty() || dep.version.is_empty() {
            continue; // cannot range-check without a concrete version
        }
        targets.push(Target::Package {
            value: format!("{}:{}@{}", dep.ecosystem, dep.name, dep.version),
            ecosystem: dep.ecosystem.to_string(),
            name: dep.name,
            version: dep.version,
        });
    }
    targets
}

/// Parse lockfile content of a known format into package targets.
///
/// # Errors
/// Returns `Parse` on malformed content.
pub fn parse(format: LockFormat, content: &str) -> Result<Vec<Target>, LockfileError> {
    let deps = match format {
        LockFormat::PackageLockJson => parse_package_lock_json(content)?,
        LockFormat::YarnLock => parse_yarn_lock(content),
        LockFormat::PnpmLock => parse_pnpm_lock(content),
        LockFormat::CargoLock => parse_cargo_lock(content),
        LockFormat::GemfileLock => parse_gemfile_lock(content),
        LockFormat::PoetryLock => parse_poetry_lock(content),
        LockFormat::RequirementsTxt => parse_requirements_txt(content),
        LockFormat::GoSum => parse_go_sum(content),
        LockFormat::ComposerLock => parse_composer_lock(content)?,
        LockFormat::PomXml => parse_pom_xml(content),
        LockFormat::GradleLockfile => parse_gradle_lockfile(content),
        LockFormat::PipfileLock => parse_pipfile_lock(content)?,
    };
    Ok(to_targets(deps))
}

fn json(content: &str) -> Result<Value, LockfileError> {
    serde_json::from_str(content).map_err(|e| LockfileError::Parse(format!("invalid JSON: {e}")))
}

fn parse_package_lock_json(content: &str) -> Result<Vec<Dep>, LockfileError> {
    let doc = json(content)?;
    let mut out = Vec::new();
    if let Some(pkgs) = doc.get("packages").and_then(Value::as_object) {
        for (key, val) in pkgs {
            if key.is_empty() {
                continue; // root
            }
            let name = key.rsplit("node_modules/").next().unwrap_or(key);
            let version = val.get("version").and_then(Value::as_str).unwrap_or("");
            if !name.is_empty() && !version.is_empty() {
                out.push(Dep {
                    ecosystem: "npm",
                    name: name.to_string(),
                    version: version.to_string(),
                });
            }
        }
    } else if let Some(deps) = doc.get("dependencies").and_then(Value::as_object) {
        collect_npm_deps(deps, &mut out);
    }
    Ok(out)
}

fn collect_npm_deps(deps: &serde_json::Map<String, Value>, out: &mut Vec<Dep>) {
    for (name, val) in deps {
        let version = val.get("version").and_then(Value::as_str).unwrap_or("");
        if !version.is_empty() {
            out.push(Dep {
                ecosystem: "npm",
                name: name.clone(),
                version: version.to_string(),
            });
        }
        if let Some(nested) = val.get("dependencies").and_then(Value::as_object) {
            collect_npm_deps(nested, out);
        }
    }
}

fn parse_yarn_lock(content: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            let header = trimmed.trim_end_matches(':').trim_matches('"');
            let first = header.split(',').next().unwrap_or(header).trim();
            if let Some(at_pos) = first.rfind('@')
                && at_pos > 0
            {
                current_name = Some(first[..at_pos].to_string());
            }
        } else if trimmed.starts_with("version ")
            && let Some(name) = current_name.take()
        {
            let ver = trimmed
                .strip_prefix("version ")
                .unwrap_or("")
                .trim_matches('"');
            if !ver.is_empty() {
                out.push(Dep {
                    ecosystem: "npm",
                    name,
                    version: ver.to_string(),
                });
            }
        }
    }
    out
}

fn parse_pnpm_lock(content: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let mut in_packages = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }
        if in_packages && !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
            in_packages = false;
        }
        if !in_packages {
            continue;
        }
        let entry = trimmed.trim_start_matches('/').trim_end_matches(':');
        if let Some(at_pos) = entry.rfind('@')
            && at_pos > 0
        {
            let name = &entry[..at_pos];
            let version = &entry[at_pos + 1..];
            let clean_ver = version.split('(').next().unwrap_or(version).trim();
            if !clean_ver.is_empty() {
                out.push(Dep {
                    ecosystem: "npm",
                    name: name.to_string(),
                    version: clean_ver.to_string(),
                });
            }
        }
    }
    out
}

fn parse_toml_packages(content: &str, ecosystem: &'static str) -> Vec<Dep> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                out.push(Dep {
                    ecosystem,
                    name: n,
                    version: v,
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            version = Some(rest.trim_matches('"').to_string());
        }
    }
    if let (Some(n), Some(v)) = (name, version) {
        out.push(Dep {
            ecosystem,
            name: n,
            version: v,
        });
    }
    out
}

fn parse_cargo_lock(content: &str) -> Vec<Dep> {
    parse_toml_packages(content, "crates.io")
}

fn parse_poetry_lock(content: &str) -> Vec<Dep> {
    parse_toml_packages(content, "PyPI")
}

fn parse_gemfile_lock(content: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let mut in_specs = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        if in_specs && !line.starts_with(' ') {
            in_specs = false;
        }
        if !in_specs {
            continue;
        }
        if line.starts_with("    ") && !line.starts_with("      ") {
            let parts = trimmed.splitn(2, ' ').collect::<Vec<_>>();
            if parts.len() == 2 {
                let ver = parts[1].trim_start_matches('(').trim_end_matches(')');
                out.push(Dep {
                    ecosystem: "RubyGems",
                    name: parts[0].to_string(),
                    version: ver.to_string(),
                });
            }
        }
    }
    out
}

fn parse_requirements_txt(content: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        let (name, version) = if let Some(pos) = trimmed.find("==") {
            (&trimmed[..pos], trimmed[pos + 2..].trim())
        } else if let Some(pos) = trimmed.find(">=") {
            (
                &trimmed[..pos],
                trimmed[pos + 2..].split(',').next().unwrap_or("").trim(),
            )
        } else if let Some(pos) = trimmed.find("~=") {
            (
                &trimmed[..pos],
                trimmed[pos + 2..].split(',').next().unwrap_or("").trim(),
            )
        } else {
            (trimmed.split('[').next().unwrap_or(trimmed), "")
        };
        let clean_name = name.split('[').next().unwrap_or(name).trim();
        if !clean_name.is_empty() {
            out.push(Dep {
                ecosystem: "PyPI",
                name: clean_name.to_string(),
                version: version.to_string(),
            });
        }
    }
    out
}

fn parse_go_sum(content: &str) -> Vec<Dep> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let module = parts[0];
        let version = parts[1]
            .trim_start_matches('v')
            .split('/')
            .next()
            .unwrap_or("");
        let key = format!("{module}@{version}");
        if !seen.insert(key) {
            continue;
        }
        out.push(Dep {
            ecosystem: "Go",
            name: module.to_string(),
            version: version.to_string(),
        });
    }
    out
}

fn parse_composer_lock(content: &str) -> Result<Vec<Dep>, LockfileError> {
    let doc = json(content)?;
    let mut out = Vec::new();
    for key in ["packages", "packages-dev"] {
        if let Some(pkgs) = doc.get(key).and_then(Value::as_array) {
            for pkg in pkgs {
                let name = pkg.get("name").and_then(Value::as_str).unwrap_or("");
                let version = pkg.get("version").and_then(Value::as_str).unwrap_or("");
                let clean_ver = version.trim_start_matches('v');
                if !name.is_empty() {
                    out.push(Dep {
                        ecosystem: "Packagist",
                        name: name.to_string(),
                        version: clean_ver.to_string(),
                    });
                }
            }
        }
    }
    Ok(out)
}

fn parse_pom_xml(content: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let mut in_dep = false;
    let (mut group, mut artifact, mut version) = (String::new(), String::new(), String::new());
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<dependency>") {
            in_dep = true;
            group.clear();
            artifact.clear();
            version.clear();
        } else if trimmed.contains("</dependency>") {
            if in_dep && !group.is_empty() && !artifact.is_empty() {
                out.push(Dep {
                    ecosystem: "Maven",
                    name: format!("{group}:{artifact}"),
                    version: version.clone(),
                });
            }
            in_dep = false;
        } else if in_dep {
            if let Some(val) = extract_xml_value(trimmed, "groupId") {
                group = val;
            } else if let Some(val) = extract_xml_value(trimmed, "artifactId") {
                artifact = val;
            } else if let Some(val) = extract_xml_value(trimmed, "version") {
                version = val;
            }
        }
    }
    out
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = line.find(&open)?;
    let end = line.find(&close)?;
    let val_start = start + open.len();
    (val_start < end).then(|| line[val_start..end].trim().to_string())
}

fn parse_gradle_lockfile(content: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let entry = trimmed.split('=').next().unwrap_or(trimmed);
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() >= 3 {
            out.push(Dep {
                ecosystem: "Maven",
                name: format!("{}:{}", parts[0], parts[1]),
                version: parts[2].to_string(),
            });
        }
    }
    out
}

fn parse_pipfile_lock(content: &str) -> Result<Vec<Dep>, LockfileError> {
    let doc = json(content)?;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        if let Some(deps) = doc.get(section).and_then(Value::as_object) {
            for (name, info) in deps {
                let version = info.get("version").and_then(Value::as_str).unwrap_or("");
                let clean = version.trim_start_matches("==");
                out.push(Dep {
                    ecosystem: "PyPI",
                    name: name.clone(),
                    version: clean.to_string(),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(targets: &[Target]) -> Vec<String> {
        targets.iter().map(|t| t.value().to_string()).collect()
    }

    #[test]
    fn detect_by_filename() {
        assert_eq!(
            LockFormat::detect(Path::new("a/Cargo.lock")),
            Some(LockFormat::CargoLock)
        );
        assert_eq!(
            LockFormat::detect(Path::new("package-lock.json")),
            Some(LockFormat::PackageLockJson)
        );
        assert_eq!(
            LockFormat::detect(Path::new("dev-requirements.txt")),
            Some(LockFormat::RequirementsTxt)
        );
        assert_eq!(LockFormat::detect(Path::new("mystery.bin")), None);
    }

    #[test]
    fn cargo_lock_parses() {
        let content = "\
[[package]]
name = \"lodash-rs\"
version = \"1.2.3\"

[[package]]
name = \"serde\"
version = \"1.0.200\"
";
        let targets = parse(LockFormat::CargoLock, content).unwrap();
        assert_eq!(
            keys(&targets),
            ["crates.io:lodash-rs@1.2.3", "crates.io:serde@1.0.200"]
        );
    }

    #[test]
    fn package_lock_v3_and_requirements() {
        let npm = serde_json::json!({
            "packages": {
                "": {"name": "root"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/@babel/core": {"version": "7.0.0"}
            }
        })
        .to_string();
        let mut got = keys(&parse(LockFormat::PackageLockJson, &npm).unwrap());
        got.sort();
        assert_eq!(got, ["npm:@babel/core@7.0.0", "npm:lodash@4.17.15"]);

        let reqs = "flask==2.0.1\n# comment\nrequests>=2.31.0\nunpinned\n";
        let py = keys(&parse(LockFormat::RequirementsTxt, reqs).unwrap());
        // unpinned (no version) is dropped
        assert_eq!(py, ["PyPI:flask@2.0.1", "PyPI:requests@2.31.0"]);
    }

    #[test]
    fn empty_versions_are_dropped() {
        let targets = parse(LockFormat::RequirementsTxt, "django\nflask==3.0\n").unwrap();
        assert_eq!(keys(&targets), ["PyPI:flask@3.0"]);
    }
}
