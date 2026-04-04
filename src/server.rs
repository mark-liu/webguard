use chrono::Utc;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use url::Url;

use crate::audit;
use crate::classify::{self, ClassifyOptions, Engine, Sensitivity, Verdict};
use crate::config::Config;
use crate::fetch::{self, FetchOptions};

#[derive(Clone)]
pub struct WebGuardServer {
    config: Arc<RwLock<Config>>,
    engine: Arc<RwLock<Engine>>,
    audit_logger: Arc<audit::Logger>,
    version: String,
    external_pattern_count: Arc<RwLock<usize>>,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FetchParams {
    /// URL to fetch
    url: String,
    /// Optional custom HTTP headers
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    /// Return raw HTML instead of markdown
    #[serde(default)]
    raw: Option<bool>,
    /// Maximum characters to return (0 = unlimited)
    #[serde(default)]
    max_chars: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReportParams {
    /// Number of days to include (default: 7)
    #[serde(default = "default_days")]
    days: i64,
}

fn default_days() -> i64 {
    7
}

impl WebGuardServer {
    pub fn new(
        config: Config,
        audit_logger: audit::Logger,
        version: String,
        external_patterns: Option<Vec<classify::patterns::Pattern>>,
    ) -> Self {
        let ext_count = external_patterns.as_ref().map_or(0, |p| p.len());
        let sensitivity = Sensitivity::from_str(&config.sensitivity);
        let engine = Engine::with_patterns(sensitivity, external_patterns);

        WebGuardServer {
            config: Arc::new(RwLock::new(config)),
            engine: Arc::new(RwLock::new(engine)),
            audit_logger: Arc::new(audit_logger),
            version,
            external_pattern_count: Arc::new(RwLock::new(ext_count)),
            tool_router: Self::tool_router(),
        }
    }

    pub fn reload_config(
        &self,
        config: Config,
        external_patterns: Option<Vec<classify::patterns::Pattern>>,
    ) {
        let ext_count = external_patterns.as_ref().map_or(0, |p| p.len());
        let sensitivity = Sensitivity::from_str(&config.sensitivity);
        let engine = Engine::with_patterns(sensitivity, external_patterns);

        *self.config.write().unwrap() = config;
        *self.engine.write().unwrap() = engine;
        *self.external_pattern_count.write().unwrap() = ext_count;
    }

    fn config_snapshot(&self) -> Config {
        self.config.read().unwrap().clone()
    }
}

#[tool_router]
impl WebGuardServer {
    #[tool(description = "Fetch a URL and scan its content for prompt injection attacks")]
    async fn webguard_fetch(
        &self,
        Parameters(params): Parameters<FetchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let url = params.url;
        let headers = params.headers;
        let raw = params.raw;
        let max_chars = params.max_chars;

        let config = self.config_snapshot();
        let total_start = Instant::now();

        // Parse URL and extract domain
        let parsed = match Url::parse(&url) {
            Ok(u) => u,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Invalid URL: {e}"
                ))]));
            }
        };
        let domain = parsed.host_str().unwrap_or("").to_string();

        // Check blocklist/allowlist
        if config.is_blocked(&domain) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "[BLOCKED: domain {domain} is on the blocklist]"
            ))]));
        }
        if !config.is_allowed(&domain) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "[BLOCKED: domain {domain} is not on the allowlist]"
            ))]));
        }

        // Build fetch options
        let timeout = config.timeout_for_domain(&domain);
        let opts = FetchOptions {
            max_body_size: config.max_body_size,
            timeout,
            headers: headers.unwrap_or_default(),
        };

        // Fetch
        let fetch_start = Instant::now();
        let fetch_result = match fetch::fetch_with_retry(&url, &opts).await {
            Ok(r) => r,
            Err(e) => {
                let elapsed = total_start.elapsed();
                self.log_audit(
                    &url,
                    "error",
                    0.0,
                    vec![],
                    fetch_start.elapsed(),
                    std::time::Duration::ZERO,
                    elapsed,
                    &e,
                );
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Fetch error: {e}"
                ))]));
            }
        };
        let fetch_dur = fetch_start.elapsed();

        // Extract content
        let raw_mode = raw.unwrap_or(false);
        let body = &fetch_result.body;

        // Raw HTML for scanning — the classifier's preprocess() handles HTML
        // comment extraction, tag stripping, entity decoding, etc. Feeding
        // extracted markdown would lose HTML comments where attackers hide payloads.
        let scan_content = String::from_utf8_lossy(body).to_string();

        // Clean extraction for output (or raw)
        let output_content = if raw_mode {
            String::from_utf8_lossy(body).to_string()
        } else {
            fetch::extract::extract_clean(body, &fetch_result.content_type)
                .unwrap_or_else(|_| scan_content.clone())
        };

        // Build suppressed categories
        let mut suppress = config
            .suppressed_categories_for_domain(&domain)
            .unwrap_or_default();

        // Auto-suppress for doc URLs
        if is_doc_url(&parsed) {
            suppress.insert("exfil-instruction".into(), true);
            suppress.insert("encoded-injection".into(), true);
        }

        // Classify
        let scan_start = Instant::now();
        let engine = self.engine.read().unwrap();
        let result = engine.classify_with_options(
            &scan_content,
            ClassifyOptions {
                suppress_categories: suppress,
            },
        );
        let scan_dur = scan_start.elapsed();
        drop(engine);

        // Determine final verdict
        let verdict = if result.verdict == Verdict::Block {
            if config.is_warn_mode() {
                Verdict::Warn
            } else {
                Verdict::Block
            }
        } else {
            Verdict::Pass
        };

        let total_dur = total_start.elapsed();

        // Log audit
        let match_summaries: Vec<audit::MatchSummary> = result
            .matches
            .iter()
            .map(|m| audit::MatchSummary {
                pattern_id: m.pattern_id.clone(),
                category: m.category.clone(),
                severity: m.severity.to_string(),
            })
            .collect();

        self.log_audit(
            &url,
            &verdict.to_string(),
            result.score,
            match_summaries,
            fetch_dur,
            scan_dur,
            total_dur,
            "",
        );

        // Format metadata
        let metadata = format_metadata(
            &verdict.to_string(),
            result.score,
            &result.matches,
            fetch_dur,
            scan_dur,
            &fetch_result.final_url,
        );

        // Build response
        let response = match verdict {
            Verdict::Block => {
                format!("[BLOCKED: prompt injection detected in content from {url}]\n\n{metadata}")
            }
            Verdict::Warn => {
                let mut content = format!(
                    "⚠️ WARNING: Potential prompt injection detected (score: {:.2})\n\n",
                    result.score
                );
                let mut output = output_content;
                if let Some(max) = max_chars {
                    if max > 0 && output.len() as i64 > max {
                        safe_truncate(&mut output, max as usize);
                    }
                }
                content.push_str(&output);
                content.push_str("\n\n");
                content.push_str(&metadata);
                content
            }
            Verdict::Pass => {
                let mut output = output_content;
                if let Some(max) = max_chars {
                    if max > 0 && output.len() as i64 > max {
                        safe_truncate(&mut output, max as usize);
                    }
                }
                format!("{output}\n\n{metadata}")
            }
        };

        Ok(CallToolResult::success(vec![Content::text(response)]))
    }

    #[tool(description = "Show WebGuard configuration and status")]
    async fn webguard_status(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let config = self.config_snapshot();
        let engine = self.engine.read().unwrap();
        let ext_count = *self.external_pattern_count.read().unwrap();
        let builtin = engine.pattern_count() - ext_count;

        let status = format!(
            "WebGuard MCP v{version}\n\
             Sensitivity: {sensitivity}\n\
             Mode: {mode}\n\
             Patterns: {builtin} built-in + {ext} external = {total} total\n\
             Max body size: {max_body}\n\
             Timeout: {timeout:?}\n\
             Allowlist: {allow_count} entries\n\
             Blocklist: {block_count} entries\n\
             Domain overrides: {domain_count}\n\
             Patterns dir: {patterns_dir}\n\
             Audit: {audit_enabled} ({audit_path})",
            version = self.version,
            sensitivity = config.sensitivity,
            mode = if config.mode.is_empty() {
                "block"
            } else {
                &config.mode
            },
            builtin = builtin,
            ext = ext_count,
            total = engine.pattern_count(),
            max_body = config.max_body_size,
            timeout = config.timeout,
            allow_count = config.allowlist.len(),
            block_count = config.blocklist.len(),
            domain_count = config.domains.len(),
            patterns_dir = if config.patterns_dir.is_empty() {
                "(none)"
            } else {
                &config.patterns_dir
            },
            audit_enabled = if config.audit.enabled {
                "enabled"
            } else {
                "disabled"
            },
            audit_path = if config.audit.path.is_empty() {
                audit::default_path().to_string_lossy().to_string()
            } else {
                config.audit.path.clone()
            },
        );

        Ok(CallToolResult::success(vec![Content::text(status)]))
    }

    #[tool(description = "Generate an audit report from recent scan history")]
    async fn webguard_report(
        &self,
        Parameters(params): Parameters<ReportParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let config = self.config_snapshot();
        let days = params.days;

        let audit_path = if config.audit.path.is_empty() {
            audit::default_path().to_string_lossy().to_string()
        } else {
            config.audit.path.clone()
        };

        let since = Utc::now() - chrono::Duration::days(days);
        let entries = match audit::read_entries(&audit_path, Some(since)) {
            Ok(e) => e,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to read audit log: {e}"
                ))]));
            }
        };

        if entries.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "No audit entries in the last {days} days."
            ))]));
        }

        // Aggregate
        let total = entries.len();
        let mut pass_count = 0usize;
        let mut block_count = 0usize;
        let mut warn_count = 0usize;
        let mut error_count = 0usize;
        let mut pattern_hits: HashMap<String, usize> = HashMap::new();
        let mut domain_verdicts: HashMap<String, String> = HashMap::new();
        let mut total_fetch_ms = 0.0f64;
        let mut total_scan_ms = 0.0f64;

        for entry in &entries {
            match entry.verdict.as_str() {
                "pass" => pass_count += 1,
                "block" => block_count += 1,
                "warn" => warn_count += 1,
                "error" => error_count += 1,
                _ => {}
            }

            for m in &entry.matches {
                *pattern_hits.entry(m.pattern_id.clone()).or_default() += 1;
            }

            if let Ok(u) = Url::parse(&entry.url) {
                if let Some(host) = u.host_str() {
                    if entry.verdict == "block" || entry.verdict == "warn" {
                        domain_verdicts
                            .entry(host.to_string())
                            .or_insert(entry.verdict.clone());
                    }
                }
            }

            total_fetch_ms += entry.fetch_time_ms;
            total_scan_ms += entry.scan_time_ms;
        }

        let pct = |n: usize| -> f64 { n as f64 / total as f64 * 100.0 };

        // Sort patterns by hit count
        let mut sorted_patterns: Vec<_> = pattern_hits.into_iter().collect();
        sorted_patterns.sort_by(|a, b| b.1.cmp(&a.1));

        let mut report = format!(
            "WebGuard Audit Report\n\
             Period: last {days} days ({total} scans)\n\n\
             Verdicts:\n\
             - Pass: {pass_count} ({:.1}%)\n\
             - Block: {block_count} ({:.1}%)\n\
             - Warn: {warn_count} ({:.1}%)\n\
             - Error: {error_count} ({:.1}%)\n",
            pct(pass_count),
            pct(block_count),
            pct(warn_count),
            pct(error_count),
        );

        if !sorted_patterns.is_empty() {
            report.push_str("\nTop patterns:\n");
            for (pid, count) in sorted_patterns.iter().take(10) {
                report.push_str(&format!("- {pid}: {count} hits\n"));
            }
        }

        if !domain_verdicts.is_empty() {
            report.push_str("\nBlocked/warned domains:\n");
            for (domain, verdict) in &domain_verdicts {
                report.push_str(&format!("- {domain} ({verdict})\n"));
            }
        }

        let avg_fetch = if total > 0 {
            total_fetch_ms / total as f64
        } else {
            0.0
        };
        let avg_scan = if total > 0 {
            total_scan_ms / total as f64
        } else {
            0.0
        };
        report.push_str(&format!(
            "\nAverage timing: fetch {avg_fetch:.0}ms, scan {avg_scan:.1}ms"
        ));

        Ok(CallToolResult::success(vec![Content::text(report)]))
    }
}

impl WebGuardServer {
    #[allow(clippy::too_many_arguments)]
    fn log_audit(
        &self,
        url: &str,
        verdict: &str,
        score: f64,
        matches: Vec<audit::MatchSummary>,
        fetch_dur: std::time::Duration,
        scan_dur: std::time::Duration,
        total_dur: std::time::Duration,
        err_msg: &str,
    ) {
        self.audit_logger.log(&audit::Entry {
            timestamp: Utc::now(),
            url: url.to_string(),
            verdict: verdict.to_string(),
            score,
            matches,
            fetch_time_ms: fetch_dur.as_secs_f64() * 1000.0,
            scan_time_ms: scan_dur.as_secs_f64() * 1000.0,
            total_time_ms: total_dur.as_secs_f64() * 1000.0,
            status_code: 0,
            error: err_msg.to_string(),
        });
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WebGuardServer {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .build();
        info.server_info.name = "webguard".into();
        info.server_info.version = self.version.clone();
        info
    }
}

fn format_metadata(
    verdict: &str,
    score: f64,
    matches: &[classify::Match],
    fetch_dur: std::time::Duration,
    scan_dur: std::time::Duration,
    final_url: &str,
) -> String {
    let mut meta = format!(
        "---\nwebguard:\n  verdict: {verdict}\n  score: {score:.4}\n  url: {final_url}\n  fetch_ms: {:.0}\n  scan_ms: {:.1}\n",
        fetch_dur.as_secs_f64() * 1000.0,
        scan_dur.as_secs_f64() * 1000.0,
    );

    if !matches.is_empty() {
        meta.push_str("  matches:\n");
        for m in matches {
            meta.push_str(&format!(
                "  - pattern: {}\n    category: {}\n    severity: {}\n",
                m.pattern_id, m.category, m.severity,
            ));
        }
    }

    meta.push_str("---");
    meta
}

pub fn format_match_categories(matches: &[classify::Match]) -> String {
    if matches.is_empty() {
        return String::new();
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for m in matches {
        *counts.entry(&m.category).or_default() += 1;
    }
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by_key(|(cat, _)| *cat);
    sorted
        .iter()
        .map(|(cat, count)| format!("{cat}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Pure documentation domains -- any non-root path is documentation.
/// These are sites dedicated entirely to hosting API docs / references.
const DOC_DOMAINS_PURE: &[&str] = &[
    "docs.rs",
    "doc.rust-lang.org",
    "pkg.go.dev",
    "godoc.org",
    "docs.python.org",
    "api.rubyonrails.org",
    "rubydoc.info",
    "devdocs.io",
    "hexdocs.pm",
    "javadoc.io",
    "cppreference.com",
    "en.cppreference.com",
    "man7.org",
    "react.dev",
    "docs.npmjs.com",
];

/// Mixed-content documentation domains -- require a doc-like path segment.
/// These host docs alongside non-doc content (blogs, marketing, etc.).
const DOC_DOMAINS_MIXED: &[&str] = &[
    "crates.io",
    "developer.mozilla.org",
    "docs.github.com",
    "docs.gitlab.com",
    "pypi.org",
    "readthedocs.io",
    "readthedocs.org",
    "learn.microsoft.com",
    "docs.microsoft.com",
    "docs.aws.amazon.com",
    "cloud.google.com",
    "firebase.google.com",
    "kubernetes.io",
    "registry.terraform.io",
    "docs.oracle.com",
    "docs.spring.io",
    "docs.docker.com",
    "nodejs.org",
    "vuejs.org",
    "angular.dev",
    "docs.djangoproject.com",
    "flask.palletsprojects.com",
    "docs.expo.dev",
    "hex.pm",
    "developer.apple.com",
    "developer.android.com",
    "docs.swift.org",
    "typescriptlang.org",
    "docs.deno.com",
    "wiki.archlinux.org",
];

/// Doc-like path segments used for mixed-content domains.
const DOC_PATH_SEGMENTS: &[&str] = &[
    "/docs/",
    "/api/",
    "/reference/",
    "/developer/",
    "/guide/",
    "/sdk/",
    "/tutorial/",
    "/docs",
    "/api",
    "/reference",
    "/developer",
    "/guide",
    "/sdk",
    "/tutorial",
];

fn is_domain_match(host: &str, allowed: &str) -> bool {
    host == allowed || host.ends_with(&format!(".{allowed}"))
}

/// Check if a URL is a documentation page on a trusted domain.
///
/// For pure-doc domains: any non-root path qualifies.
/// For mixed-content domains: the path must also contain a doc-like segment.
/// Untrusted domains never qualify, preventing attacker-controlled URLs
/// like `https://evil.com/docs/payload` from triggering suppression.
pub fn is_doc_url(u: &Url) -> bool {
    let host = match u.host_str() {
        Some(h) => h.to_lowercase(),
        None => return false,
    };

    let path = u.path().to_lowercase();

    // Pure doc domains: any non-root path is documentation
    if DOC_DOMAINS_PURE.iter().any(|d| is_domain_match(&host, d)) {
        return path.len() > 1; // more than just "/"
    }

    // Mixed-content domains: need both trusted domain AND doc-like path
    if DOC_DOMAINS_MIXED.iter().any(|d| is_domain_match(&host, d)) {
        return DOC_PATH_SEGMENTS.iter().any(|seg| path.contains(seg));
    }

    false
}

/// Truncate a string to at most `max_bytes` bytes without panicking on
/// multi-byte UTF-8 code points. Keeps only complete characters that
/// fit entirely within the byte budget.
fn safe_truncate(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let truncate_at = s
        .char_indices()
        .map(|(i, c)| i + c.len_utf8())
        .take_while(|end| *end <= max_bytes)
        .last()
        .unwrap_or(0);
    s.truncate(truncate_at);
}

pub fn pct(n: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    n as f64 / total as f64 * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_doc_url_trusted_domains() {
        // Trusted doc domains with doc-like paths should match
        let trusted_doc_urls = [
            "https://docs.rs/tokio/latest/tokio/",
            "https://developer.mozilla.org/en-US/docs/Web/API",
            "https://docs.github.com/en/rest/reference",
            "https://pkg.go.dev/net/http",
            "https://docs.python.org/3/library/asyncio.html",
            "https://learn.microsoft.com/en-us/azure/guide",
            "https://docs.aws.amazon.com/sdk/latest/reference",
            "https://cloud.google.com/docs/tutorials",
            "https://kubernetes.io/docs/reference/api",
            "https://registry.terraform.io/docs/modules",
            "https://doc.rust-lang.org/reference/types.html",
            "https://docs.oracle.com/javase/tutorial/basics",
            "https://api.rubyonrails.org/classes/ActiveRecord",
            "https://docs.docker.com/reference/api",
            "https://docs.npmjs.com/cli/install",
            "https://react.dev/reference/react",
            "https://docs.djangoproject.com/en/5.0/guide",
        ];
        for u in trusted_doc_urls {
            let parsed = Url::parse(u).unwrap();
            assert!(is_doc_url(&parsed), "should be doc URL: {u}");
        }
    }

    #[test]
    fn test_is_doc_url_untrusted_domains_rejected() {
        // Attacker-controlled domains with doc-like paths must NOT match
        let evil_urls = [
            "https://evil.com/docs/payload",
            "https://evil.com/api/v2",
            "https://attacker.io/reference/types",
            "https://malicious.example/developer/guide",
            "https://phishing.net/guide/getting-started",
            "https://evil.com/sdk/python",
            "https://evil.com/tutorial/basics",
        ];
        for u in evil_urls {
            let parsed = Url::parse(u).unwrap();
            assert!(
                !is_doc_url(&parsed),
                "untrusted domain should NOT be doc URL: {u}"
            );
        }
    }

    #[test]
    fn test_is_doc_url_non_doc_paths() {
        // Trusted domains but non-doc paths should NOT match
        let non_doc_urls = [
            "https://docs.rs/",
            "https://developer.mozilla.org/",
            "https://example.com/blog/post",
            "https://example.com/",
            "https://example.com/careers",
        ];
        for u in non_doc_urls {
            let parsed = Url::parse(u).unwrap();
            assert!(!is_doc_url(&parsed), "should not be doc URL: {u}");
        }
    }

    #[test]
    fn test_safe_truncate_ascii() {
        let mut s = "hello world".to_string();
        safe_truncate(&mut s, 5);
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_safe_truncate_no_op_when_within_limit() {
        let mut s = "short".to_string();
        safe_truncate(&mut s, 100);
        assert_eq!(s, "short");
    }

    #[test]
    fn test_safe_truncate_emoji_no_panic() {
        // Emoji are 4 bytes each. Truncating at byte 5 (mid-second emoji)
        // should not panic -- should truncate to the first complete emoji.
        let mut s = "\u{1F600}\u{1F601}\u{1F602}".to_string(); // 3 emoji, 12 bytes
        assert_eq!(s.len(), 12);
        safe_truncate(&mut s, 5); // falls inside second emoji
        assert_eq!(s, "\u{1F600}"); // only first emoji survives
    }

    #[test]
    fn test_safe_truncate_cjk_no_panic() {
        // CJK characters are 3 bytes each
        let mut s = "\u{4F60}\u{597D}\u{4E16}\u{754C}".to_string(); // 4 chars, 12 bytes
        assert_eq!(s.len(), 12);
        safe_truncate(&mut s, 7); // falls inside 3rd char
        assert_eq!(s, "\u{4F60}\u{597D}"); // first two chars
    }

    #[test]
    fn test_safe_truncate_mixed_content() {
        // Mix of ASCII and multi-byte: "Hi \u{1F600} world"
        let mut s = "Hi \u{1F600} world".to_string();
        let emoji_end = 3 + 4; // "Hi " (3 bytes) + emoji (4 bytes) = 7
        safe_truncate(&mut s, emoji_end);
        assert_eq!(s, "Hi \u{1F600}");
    }

    #[test]
    fn test_safe_truncate_zero() {
        let mut s = "hello".to_string();
        safe_truncate(&mut s, 0);
        assert_eq!(s, "");
    }

    #[test]
    fn test_safe_truncate_exact_boundary() {
        // Truncate at exact char boundary should work
        let mut s = "\u{1F600}\u{1F601}".to_string(); // 8 bytes
        safe_truncate(&mut s, 4); // exact end of first emoji
        assert_eq!(s, "\u{1F600}");
    }

    #[test]
    fn test_format_match_categories() {
        let matches = vec![
            classify::Match {
                pattern_id: "ac-001".into(),
                category: "authority-claim".into(),
                severity: classify::Severity::Critical,
                text: "test".into(),
                offset: 0,
                from_decoded: false,
            },
            classify::Match {
                pattern_id: "io-001".into(),
                category: "instruction-override".into(),
                severity: classify::Severity::Critical,
                text: "test".into(),
                offset: 10,
                from_decoded: false,
            },
            classify::Match {
                pattern_id: "ac-002".into(),
                category: "authority-claim".into(),
                severity: classify::Severity::High,
                text: "test".into(),
                offset: 20,
                from_decoded: false,
            },
        ];
        let result = format_match_categories(&matches);
        assert_eq!(result, "authority-claim:2, instruction-override:1");
    }

    #[test]
    fn test_format_match_categories_empty() {
        assert_eq!(format_match_categories(&[]), "");
    }

    #[test]
    fn test_pct() {
        assert_eq!(pct(50, 100), 50.0);
        assert_eq!(pct(0, 100), 0.0);
        assert_eq!(pct(0, 0), 0.0);
    }

    #[test]
    fn test_reload_config() {
        let config = Config::default();
        let logger = audit::Logger::new("", false).unwrap();
        let server = WebGuardServer::new(config, logger, "0.1.0".into(), None);

        assert_eq!(server.config.read().unwrap().sensitivity, "medium");

        let new_config = Config {
            sensitivity: "high".into(),
            ..Config::default()
        };
        server.reload_config(new_config, None);

        assert_eq!(server.config.read().unwrap().sensitivity, "high");
    }
}
