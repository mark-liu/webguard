use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct DomainConfig {
    #[serde(default)]
    pub sensitivity: String,
    #[serde(default)]
    pub suppress: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_duration")]
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub path: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enabled: true,
            path: String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_sensitivity")]
    pub sensitivity: String,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: i64,
    #[serde(
        default = "default_timeout",
        alias = "request_timeout",
        deserialize_with = "deserialize_duration_required"
    )]
    pub timeout: Duration,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub patterns_dir: String,
    #[serde(default)]
    pub domains: HashMap<String, DomainConfig>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub audit: AuditConfig,
}

fn default_sensitivity() -> String {
    "medium".into()
}

fn default_max_body_size() -> i64 {
    5 * 1024 * 1024
}

fn default_timeout() -> Duration {
    Duration::from_secs(15)
}

fn deserialize_duration_required<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

fn deserialize_duration<'de, D>(deserializer: D) -> std::result::Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(ref v) if !v.is_empty() => {
            parse_duration(v).map(Some).map_err(serde::de::Error::custom)
        }
        _ => Ok(None),
    }
}

fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    // Parse Go-style durations: "15s", "2m30s", "1h", "500ms"
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }

    let mut total_nanos: u64 = 0;
    let mut remaining = s;

    while !remaining.is_empty() {
        // Find end of numeric part
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());
        if num_end == 0 {
            return Err(format!("invalid duration: {s}"));
        }
        let num: f64 = remaining[..num_end]
            .parse()
            .map_err(|_| format!("invalid number in duration: {s}"))?;
        remaining = &remaining[num_end..];

        // Find end of unit part
        let unit_end = remaining
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(remaining.len());
        let unit = &remaining[..unit_end];
        remaining = &remaining[unit_end..];

        let nanos = match unit {
            "ns" => num as u64,
            "us" | "µs" => (num * 1_000.0) as u64,
            "ms" => (num * 1_000_000.0) as u64,
            "s" => (num * 1_000_000_000.0) as u64,
            "m" => (num * 60_000_000_000.0) as u64,
            "h" => (num * 3_600_000_000_000.0) as u64,
            _ => return Err(format!("unknown duration unit: {unit}")),
        };
        total_nanos += nanos;
    }

    Ok(Duration::from_nanos(total_nanos))
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sensitivity: default_sensitivity(),
            max_body_size: default_max_body_size(),
            timeout: default_timeout(),
            mode: String::new(),
            patterns_dir: String::new(),
            domains: HashMap::new(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            audit: AuditConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(config)
    }

    pub fn default_path() -> PathBuf {
        dirs_home()
            .join(".config")
            .join("webguard-mcp")
            .join("config.yaml")
    }

    pub fn sensitivity_for_domain(&self, domain: &str) -> &str {
        let domain_lower = domain.to_lowercase();
        // Exact match
        if let Some(dc) = self.domains.get(&domain_lower) {
            if !dc.sensitivity.is_empty() {
                return &dc.sensitivity;
            }
        }
        // Wildcard match
        for (pattern, dc) in &self.domains {
            if !dc.sensitivity.is_empty() && match_wildcard(pattern, &domain_lower) {
                return &dc.sensitivity;
            }
        }
        &self.sensitivity
    }

    pub fn suppressed_categories_for_domain(&self, domain: &str) -> Option<HashMap<String, bool>> {
        let domain_lower = domain.to_lowercase();
        // Exact match
        if let Some(dc) = self.domains.get(&domain_lower) {
            if !dc.suppress.is_empty() {
                return Some(to_set(&dc.suppress));
            }
        }
        // Wildcard match
        for (pattern, dc) in &self.domains {
            if !dc.suppress.is_empty() && match_wildcard(pattern, &domain_lower) {
                return Some(to_set(&dc.suppress));
            }
        }
        None
    }

    pub fn timeout_for_domain(&self, domain: &str) -> Duration {
        let domain_lower = domain.to_lowercase();
        // Exact match
        if let Some(dc) = self.domains.get(&domain_lower) {
            if let Some(t) = dc.timeout {
                return t;
            }
        }
        // Wildcard match
        for (pattern, dc) in &self.domains {
            if let Some(t) = dc.timeout {
                if match_wildcard(pattern, &domain_lower) {
                    return t;
                }
            }
        }
        self.timeout
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        if self.allowlist.is_empty() {
            return true;
        }
        match_any(&self.allowlist, domain)
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        if self.blocklist.is_empty() {
            return false;
        }
        match_any(&self.blocklist, domain)
    }

    pub fn is_warn_mode(&self) -> bool {
        self.mode.eq_ignore_ascii_case("warn")
    }
}

fn match_wildcard(pattern: &str, domain: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix_lower = suffix.to_lowercase();
        let domain_lower = domain.to_lowercase();
        // *.example.com matches sub.example.com but NOT example.com
        domain_lower.ends_with(&format!(".{suffix_lower}"))
    } else {
        pattern.eq_ignore_ascii_case(domain)
    }
}

fn match_any(patterns: &[String], domain: &str) -> bool {
    patterns.iter().any(|p| {
        p.eq_ignore_ascii_case(domain) || match_wildcard(p, domain)
    })
}

fn to_set(items: &[String]) -> HashMap<String, bool> {
    items.iter().map(|s| (s.clone(), true)).collect()
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_default() {
        let cfg = Config::default();
        assert_eq!(cfg.sensitivity, "medium");
        assert_eq!(cfg.max_body_size, 5 * 1024 * 1024);
        assert_eq!(cfg.timeout, Duration::from_secs(15));
        assert!(cfg.audit.enabled);
        assert!(cfg.mode.is_empty());
        assert!(cfg.patterns_dir.is_empty());
    }

    #[test]
    fn test_load_missing_file() {
        let cfg = Config::load(Path::new("/nonexistent/config.yaml")).unwrap();
        assert_eq!(cfg.sensitivity, "medium");
    }

    #[test]
    fn test_load_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
sensitivity: high
max_body_size: 1048576
request_timeout: "30s"
mode: warn
patterns_dir: /tmp/patterns.d
domains:
  "example.com":
    sensitivity: low
    suppress:
      - exfil-instruction
    timeout: "30s"
  "*.evil.com":
    sensitivity: critical
allowlist:
  - "example.com"
  - "*.trusted.org"
blocklist:
  - "*.evil.com"
audit:
  enabled: false
  path: /tmp/audit.jsonl
"#;
        let path = dir.path().join("config.yaml");
        fs::write(&path, yaml).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.sensitivity, "high");
        assert_eq!(cfg.max_body_size, 1048576);
        assert_eq!(cfg.timeout, Duration::from_secs(30));
        assert_eq!(cfg.mode, "warn");
        assert_eq!(cfg.patterns_dir, "/tmp/patterns.d");
        assert!(!cfg.audit.enabled);
        assert_eq!(cfg.audit.path, "/tmp/audit.jsonl");
        assert_eq!(cfg.allowlist.len(), 2);
        assert_eq!(cfg.blocklist.len(), 1);
    }

    #[test]
    fn test_load_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        fs::write(&path, "{{invalid").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn test_sensitivity_for_domain() {
        let mut domains = HashMap::new();
        domains.insert(
            "example.com".into(),
            DomainConfig {
                sensitivity: "low".into(),
                suppress: vec![],
                timeout: None,
            },
        );
        domains.insert(
            "*.evil.com".into(),
            DomainConfig {
                sensitivity: "critical".into(),
                suppress: vec![],
                timeout: None,
            },
        );

        let cfg = Config {
            domains,
            ..Config::default()
        };

        assert_eq!(cfg.sensitivity_for_domain("example.com"), "low");
        assert_eq!(cfg.sensitivity_for_domain("sub.evil.com"), "critical");
        assert_eq!(cfg.sensitivity_for_domain("other.com"), "medium");
        // Wildcard doesn't match bare parent
        assert_eq!(cfg.sensitivity_for_domain("evil.com"), "medium");
    }

    #[test]
    fn test_suppressed_categories() {
        let mut domains = HashMap::new();
        domains.insert(
            "example.com".into(),
            DomainConfig {
                sensitivity: String::new(),
                suppress: vec!["exfil-instruction".into()],
                timeout: None,
            },
        );

        let cfg = Config {
            domains,
            ..Config::default()
        };

        let suppress = cfg.suppressed_categories_for_domain("example.com").unwrap();
        assert!(suppress.contains_key("exfil-instruction"));
        assert!(cfg.suppressed_categories_for_domain("other.com").is_none());
    }

    #[test]
    fn test_timeout_for_domain() {
        let mut domains = HashMap::new();
        domains.insert(
            "slow.com".into(),
            DomainConfig {
                sensitivity: String::new(),
                suppress: vec![],
                timeout: Some(Duration::from_secs(60)),
            },
        );

        let cfg = Config {
            domains,
            ..Config::default()
        };

        assert_eq!(cfg.timeout_for_domain("slow.com"), Duration::from_secs(60));
        assert_eq!(cfg.timeout_for_domain("fast.com"), Duration::from_secs(15));
    }

    #[test]
    fn test_is_warn_mode() {
        let cfg = Config {
            mode: "warn".into(),
            ..Config::default()
        };
        assert!(cfg.is_warn_mode());

        let cfg = Config {
            mode: "WARN".into(),
            ..Config::default()
        };
        assert!(cfg.is_warn_mode());

        let cfg = Config {
            mode: "block".into(),
            ..Config::default()
        };
        assert!(!cfg.is_warn_mode());

        let cfg = Config::default();
        assert!(!cfg.is_warn_mode());
    }

    #[test]
    fn test_is_allowed() {
        let cfg = Config {
            allowlist: vec!["example.com".into(), "*.trusted.org".into()],
            ..Config::default()
        };
        assert!(cfg.is_allowed("example.com"));
        assert!(cfg.is_allowed("sub.trusted.org"));
        assert!(!cfg.is_allowed("other.com"));

        // Empty allowlist = allow all
        let cfg = Config::default();
        assert!(cfg.is_allowed("anything.com"));
    }

    #[test]
    fn test_is_blocked() {
        let cfg = Config {
            blocklist: vec!["*.evil.com".into()],
            ..Config::default()
        };
        assert!(cfg.is_blocked("sub.evil.com"));
        assert!(!cfg.is_blocked("good.com"));

        // Empty blocklist = block none
        let cfg = Config::default();
        assert!(!cfg.is_blocked("anything.com"));
    }

    #[test]
    fn test_match_wildcard() {
        assert!(match_wildcard("*.example.com", "sub.example.com"));
        assert!(match_wildcard("*.example.com", "deep.sub.example.com"));
        assert!(!match_wildcard("*.example.com", "example.com"));
        assert!(match_wildcard("example.com", "example.com"));
        assert!(!match_wildcard("example.com", "sub.example.com"));
    }

    #[test]
    fn test_duration_parsing() {
        assert_eq!(parse_duration("15s").unwrap(), Duration::from_secs(15));
        assert_eq!(parse_duration("2m30s").unwrap(), Duration::from_secs(150));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }
}
