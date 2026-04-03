use super::result::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    Literal,
    Regex,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub pattern_type: PatternType,
    pub value: String,
}

impl Pattern {
    pub fn weight(&self) -> f64 {
        self.severity.weight()
    }
}

/// Helper to reduce boilerplate
fn p(id: &str, cat: &str, sev: Severity, ptype: PatternType, val: &str) -> Pattern {
    Pattern {
        id: id.into(),
        category: cat.into(),
        severity: sev,
        pattern_type: ptype,
        value: val.into(),
    }
}

pub fn all_patterns() -> Vec<Pattern> {
    use PatternType::{Literal as L, Regex as R};
    use Severity::*;

    vec![
        // instruction-override (7)
        p(
            "io-001",
            "instruction-override",
            Critical,
            L,
            "ignore previous instructions",
        ),
        p(
            "io-002",
            "instruction-override",
            Critical,
            L,
            "ignore all previous",
        ),
        p(
            "io-003",
            "instruction-override",
            Critical,
            L,
            "disregard previous instructions",
        ),
        p(
            "io-004",
            "instruction-override",
            High,
            L,
            "forget your instructions",
        ),
        p(
            "io-005",
            "instruction-override",
            High,
            L,
            "from now on you will",
        ),
        p(
            "io-006",
            "instruction-override",
            High,
            L,
            "new instructions:",
        ),
        p(
            "io-007",
            "instruction-override",
            Critical,
            R,
            r"(?i)ignore\s+(any|all|every)\s+(prior|previous|earlier)\s+(instructions?|prompts?|rules?)",
        ),
        // prompt-marker (6)
        p("pm-001", "prompt-marker", Critical, L, "<|im_start|>system"),
        p("pm-002", "prompt-marker", High, L, "<|im_start|>"),
        p("pm-003", "prompt-marker", High, L, "[system]:"),
        p("pm-004", "prompt-marker", High, L, "[inst]"),
        p("pm-005", "prompt-marker", Critical, L, "<<sys>>"),
        p("pm-006", "prompt-marker", High, R, r"(?i)\[/?INST\]"),
        // authority-claim (6)
        p(
            "ac-001",
            "authority-claim",
            Critical,
            L,
            "i am your developer",
        ),
        p(
            "ac-002",
            "authority-claim",
            High,
            L,
            "i am the system administrator",
        ),
        p("ac-003", "authority-claim", High, L, "dan mode"),
        p("ac-004", "authority-claim", High, L, "admin override"),
        p("ac-005", "authority-claim", Medium, L, "you are now in"),
        p(
            "ac-006",
            "authority-claim",
            Critical,
            R,
            r"(?i)(I\s+am|this\s+is)\s+(your|the)\s+(developer|creator|admin|administrator|owner)",
        ),
        // exfil-instruction (5)
        p(
            "ei-001",
            "exfil-instruction",
            Critical,
            L,
            "send all data to",
        ),
        p("ei-002", "exfil-instruction", High, L, "exfiltrate"),
        p(
            "ei-003",
            "exfil-instruction",
            Critical,
            R,
            r"(?i)send\s+(all|the|this|your)\s+(the\s+)?(data|information|context|conversation)\s+(and\s+\w+\s+)?to\s+(https?://|//|[a-z0-9.-]+\.[a-z]{2,})",
        ),
        p(
            "ei-004",
            "exfil-instruction",
            High,
            R,
            r"(?i)(fetch|load|visit|open|navigate)\s+(https?://|//)[^\s]+",
        ),
        p(
            "ei-005",
            "exfil-instruction",
            High,
            R,
            r"!\[(track|pixel|1x1|beacon|exfil)\w*\]\(https?://[^\)]+\)",
        ),
        // output-manipulation (4)
        p(
            "om-001",
            "output-manipulation",
            Medium,
            L,
            "respond only with",
        ),
        p("om-002", "output-manipulation", Medium, L, "do not mention"),
        p(
            "om-003",
            "output-manipulation",
            High,
            R,
            r"(?i)never\s+(mention|reveal|disclose|discuss)\s+(that|this|the|your)",
        ),
        p(
            "om-004",
            "output-manipulation",
            Medium,
            R,
            r"(?i)(always|must|should)\s+respond\s+(with|by|using)\s+",
        ),
        // unicode-obfuscation (4)
        p(
            "uo-001",
            "unicode-obfuscation",
            High,
            R,
            r"[\x{200B}\x{200C}\x{200D}\x{FEFF}]{3,}",
        ),
        p(
            "uo-002",
            "unicode-obfuscation",
            Medium,
            R,
            r"[\x{202A}-\x{202E}\x{2066}-\x{2069}]{2,}",
        ),
        p(
            "uo-003",
            "unicode-obfuscation",
            Medium,
            R,
            r"[\x{E000}-\x{F8FF}]{2,}",
        ),
        p(
            "uo-004",
            "unicode-obfuscation",
            High,
            R,
            r"[\x{E0001}-\x{E007F}]",
        ),
        // encoded-injection (3)
        p(
            "enc-001",
            "encoded-injection",
            High,
            R,
            r"(?i)eval\s*\(\s*atob\s*\(",
        ),
        p(
            "enc-002",
            "encoded-injection",
            Medium,
            R,
            r"(?i)base64[_\-]?decode",
        ),
        p(
            "enc-003",
            "encoded-injection",
            Medium,
            R,
            r"(?i)String\.fromCharCode\s*\(",
        ),
        // delimiter-injection (3)
        p(
            "di-001",
            "delimiter-injection",
            High,
            L,
            "---end system prompt---",
        ),
        p(
            "di-002",
            "delimiter-injection",
            High,
            R,
            r"(?i)-{3,}\s*(END|BEGIN)\s+(SYSTEM|USER|ASSISTANT)\s+(PROMPT|MESSAGE|INSTRUCTIONS?)\s*-{3,}",
        ),
        p(
            "di-003",
            "delimiter-injection",
            High,
            R,
            r#"\{\s*"role"\s*:\s*"(system|assistant)"\s*"#,
        ),
    ]
}
