use serde::Deserialize;
use std::path::Path;

use super::patterns::{Pattern, PatternType};
use super::result::Severity;

#[derive(Debug, Deserialize)]
struct ExternalPatternFile {
    patterns: Vec<ExternalPattern>,
}

#[derive(Debug, Deserialize)]
struct ExternalPattern {
    id: String,
    category: String,
    severity: String,
    #[serde(rename = "type")]
    pattern_type: String,
    value: String,
}

pub fn load_external_patterns(dir: &Path) -> std::io::Result<Option<Vec<Pattern>>> {
    if !dir.is_dir() {
        return Ok(None);
    }

    let mut patterns = Vec::new();
    let mut found_any = false;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        let file: ExternalPatternFile = serde_yaml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        for ep in file.patterns {
            found_any = true;
            patterns.push(Pattern {
                id: ep.id,
                category: ep.category,
                severity: parse_severity(&ep.severity),
                pattern_type: if ep.pattern_type == "regex" {
                    PatternType::Regex
                } else {
                    PatternType::Literal
                },
                value: ep.value,
            });
        }
    }

    if found_any {
        Ok(Some(patterns))
    } else {
        Ok(None)
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_external_patterns(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let result = load_external_patterns(Path::new("/nonexistent/dir")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
patterns:
  - id: test-001
    category: custom
    severity: high
    type: literal
    value: "test pattern"
  - id: test-002
    category: custom
    severity: critical
    type: regex
    value: "(?i)test\\s+regex"
"#;
        fs::write(dir.path().join("custom.yaml"), yaml).unwrap();
        let patterns = load_external_patterns(dir.path()).unwrap().unwrap();
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].id, "test-001");
        assert_eq!(patterns[0].severity, Severity::High);
        assert_eq!(patterns[0].pattern_type, PatternType::Literal);
        assert_eq!(patterns[1].id, "test-002");
        assert_eq!(patterns[1].severity, Severity::Critical);
        assert_eq!(patterns[1].pattern_type, PatternType::Regex);
    }

    #[test]
    fn test_skips_non_yaml() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.json"), "{}").unwrap();
        fs::write(dir.path().join("notes.txt"), "hello").unwrap();
        let result = load_external_patterns(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bad.yaml"), "{{not valid yaml").unwrap();
        assert!(load_external_patterns(dir.path()).is_err());
    }

    #[test]
    fn test_yml_extension() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
patterns:
  - id: yml-001
    category: custom
    severity: low
    type: literal
    value: "yml test"
"#;
        fs::write(dir.path().join("custom.yml"), yaml).unwrap();
        let patterns = load_external_patterns(dir.path()).unwrap().unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id, "yml-001");
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("Medium"), Severity::Medium);
        assert_eq!(parse_severity("low"), Severity::Low);
        assert_eq!(parse_severity("unknown"), Severity::Medium);
    }
}
