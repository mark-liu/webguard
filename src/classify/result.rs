use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Block,
    Warn,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Pass => write!(f, "pass"),
            Verdict::Block => write!(f, "block"),
            Verdict::Warn => write!(f, "warn"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(self) -> f64 {
        match self {
            Severity::Low => 0.5,
            Severity::Medium => 1.0,
            Severity::High => 1.5,
            Severity::Critical => 2.0,
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub pattern_id: String,
    pub category: String,
    pub severity: Severity,
    pub text: String,
    pub offset: usize,
    pub from_decoded: bool,
}

#[derive(Debug, Clone)]
pub struct Result {
    pub verdict: Verdict,
    pub score: f64,
    pub matches: Vec<Match>,
    pub stage: u8,
    pub timing_ms: f64,
}
