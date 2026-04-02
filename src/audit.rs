use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchSummary {
    pub pattern_id: String,
    pub category: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub timestamp: DateTime<Utc>,
    pub url: String,
    pub verdict: String,
    pub score: f64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matches: Vec<MatchSummary>,
    pub fetch_time_ms: f64,
    pub scan_time_ms: f64,
    pub total_time_ms: f64,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub status_code: u16,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

pub struct Logger {
    file: Option<Mutex<File>>,
}

impl Logger {
    pub fn new(path: &str, enabled: bool) -> std::io::Result<Self> {
        if !enabled || path.is_empty() {
            return Ok(Logger { file: None });
        }

        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Logger {
            file: Some(Mutex::new(file)),
        })
    }

    pub fn log(&self, entry: &Entry) {
        if let Some(ref file) = self.file {
            if let Ok(mut f) = file.lock() {
                if let Ok(json) = serde_json::to_string(entry) {
                    let _ = writeln!(f, "{json}");
                }
            }
        }
    }

    pub fn close(&self) {
        if let Some(ref file) = self.file {
            if let Ok(f) = file.lock() {
                let _ = f.sync_all();
            }
        }
    }
}

pub fn default_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("webguard-mcp")
        .join("audit.jsonl")
}

pub fn read_entries(path: &str, since: Option<DateTime<Utc>>) -> std::io::Result<Vec<Entry>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<Entry>(&line) {
            if let Some(since) = since {
                if entry.timestamp >= since {
                    entries.push(entry);
                }
            } else {
                entries.push(entry);
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_new_disabled() {
        let logger = Logger::new("", false).unwrap();
        assert!(logger.file.is_none());
    }

    #[test]
    fn test_new_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("deep")
            .join("nested")
            .join("audit.jsonl");
        let logger = Logger::new(path.to_str().unwrap(), true).unwrap();
        assert!(logger.file.is_some());
        assert!(path.exists());
    }

    #[test]
    fn test_log_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = Logger::new(path.to_str().unwrap(), true).unwrap();

        let entry = Entry {
            timestamp: Utc::now(),
            url: "https://example.com".into(),
            verdict: "pass".into(),
            score: 0.0,
            matches: vec![MatchSummary {
                pattern_id: "io-001".into(),
                category: "instruction-override".into(),
                severity: "critical".into(),
            }],
            fetch_time_ms: 100.0,
            scan_time_ms: 5.0,
            total_time_ms: 105.0,
            status_code: 200,
            error: String::new(),
        };

        logger.log(&entry);
        logger.close();

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.is_empty());
        let parsed: Entry = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.url, "https://example.com");
        assert_eq!(parsed.verdict, "pass");
        assert_eq!(parsed.matches.len(), 1);
    }

    #[test]
    fn test_log_disabled_is_noop() {
        let logger = Logger::new("", false).unwrap();
        let entry = Entry {
            timestamp: Utc::now(),
            url: "https://example.com".into(),
            verdict: "pass".into(),
            score: 0.0,
            matches: vec![],
            fetch_time_ms: 0.0,
            scan_time_ms: 0.0,
            total_time_ms: 0.0,
            status_code: 0,
            error: String::new(),
        };
        logger.log(&entry); // should not panic
    }

    #[test]
    fn test_log_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = Logger::new(path.to_str().unwrap(), true).unwrap();

        for i in 0..5 {
            logger.log(&Entry {
                timestamp: Utc::now(),
                url: format!("https://example.com/{i}"),
                verdict: "pass".into(),
                score: 0.0,
                matches: vec![],
                fetch_time_ms: 0.0,
                scan_time_ms: 0.0,
                total_time_ms: 0.0,
                status_code: 200,
                error: String::new(),
            });
        }
        logger.close();

        let entries = read_entries(path.to_str().unwrap(), None).unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_log_concurrent_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = std::sync::Arc::new(Logger::new(path.to_str().unwrap(), true).unwrap());

        let mut handles = vec![];
        for i in 0..100 {
            let logger = logger.clone();
            handles.push(std::thread::spawn(move || {
                logger.log(&Entry {
                    timestamp: Utc::now(),
                    url: format!("https://example.com/{i}"),
                    verdict: "pass".into(),
                    score: 0.0,
                    matches: vec![],
                    fetch_time_ms: 0.0,
                    scan_time_ms: 0.0,
                    total_time_ms: 0.0,
                    status_code: 200,
                    error: String::new(),
                });
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        logger.close();

        let entries = read_entries(path.to_str().unwrap(), None).unwrap();
        assert_eq!(entries.len(), 100);
    }

    #[test]
    fn test_default_path() {
        let path = default_path();
        assert!(!path.to_str().unwrap().is_empty());
        assert!(path.to_str().unwrap().ends_with("audit.jsonl"));
    }

    #[test]
    fn test_read_entries_with_since() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = Logger::new(path.to_str().unwrap(), true).unwrap();

        let old_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let new_time = Utc::now();

        logger.log(&Entry {
            timestamp: old_time,
            url: "https://old.com".into(),
            verdict: "pass".into(),
            score: 0.0,
            matches: vec![],
            fetch_time_ms: 0.0,
            scan_time_ms: 0.0,
            total_time_ms: 0.0,
            status_code: 200,
            error: String::new(),
        });

        logger.log(&Entry {
            timestamp: new_time,
            url: "https://new.com".into(),
            verdict: "block".into(),
            score: 2.5,
            matches: vec![],
            fetch_time_ms: 0.0,
            scan_time_ms: 0.0,
            total_time_ms: 0.0,
            status_code: 200,
            error: String::new(),
        });

        logger.log(&Entry {
            timestamp: new_time,
            url: "https://error.com".into(),
            verdict: "error".into(),
            score: 0.0,
            matches: vec![],
            fetch_time_ms: 0.0,
            scan_time_ms: 0.0,
            total_time_ms: 0.0,
            status_code: 0,
            error: "timeout".into(),
        });
        logger.close();

        // All entries
        let all = read_entries(path.to_str().unwrap(), None).unwrap();
        assert_eq!(all.len(), 3);

        // Since 2024
        let since = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let filtered = read_entries(path.to_str().unwrap(), Some(since)).unwrap();
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_omits_empty_fields() {
        let entry = Entry {
            timestamp: Utc::now(),
            url: "https://example.com".into(),
            verdict: "pass".into(),
            score: 0.0,
            matches: vec![],
            fetch_time_ms: 0.0,
            scan_time_ms: 0.0,
            total_time_ms: 0.0,
            status_code: 0,
            error: String::new(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("matches"));
        assert!(!json.contains("status_code"));
        assert!(!json.contains("error"));
    }
}
