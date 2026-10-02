use regex::Regex;
use scraper::{Html, Selector};
use std::sync::LazyLock;

static EXCESSIVE_NEWLINES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{3,}").unwrap());

const FORBIDDEN_TAGS: &[&str] = &["script", "style", "svg", "noscript", "iframe"];
const BOILERPLATE_TAGS: &[&str] = &["nav", "header", "footer", "aside"];

/// True for bodies that are not HTML and must not go through htmd, which
/// collapses newlines, escapes `[x]` and drops `<email>` as a tag.
pub fn is_verbatim_type(content_type: &str) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if mime == "application/xhtml+xml" {
        return false;
    }
    if let Some(sub) = mime.strip_prefix("text/") {
        return sub != "html";
    }
    let Some(sub) = mime.strip_prefix("application/") else {
        return false;
    };
    sub.ends_with("+json")
        || sub.ends_with("+xml")
        || matches!(
            sub,
            "json"
                | "toml"
                | "x-toml"
                | "yaml"
                | "x-yaml"
                | "xml"
                | "javascript"
                | "x-javascript"
                | "ecmascript"
                | "typescript"
                | "x-sh"
                | "x-httpd-php"
        )
}

/// Extract content for security scanning (full content, no boilerplate removal).
pub fn extract(html_content: &[u8], content_type: &str) -> std::result::Result<String, String> {
    if is_verbatim_type(content_type) {
        return Ok(String::from_utf8_lossy(html_content).into_owned());
    }
    let html_str = String::from_utf8_lossy(html_content);

    // Strip forbidden tags from HTML before conversion
    let cleaned = strip_tags(&html_str, FORBIDDEN_TAGS);

    // Convert to markdown
    let md = htmd::convert(&cleaned).map_err(|e| format!("markdown conversion error: {e}"))?;

    // Collapse excessive newlines
    let md = EXCESSIVE_NEWLINES
        .replace_all(&md, "\n\n")
        .trim()
        .to_string();

    Ok(md)
}

/// Extract clean content for output (boilerplate removed).
pub fn extract_clean(
    html_content: &[u8],
    content_type: &str,
) -> std::result::Result<String, String> {
    if is_verbatim_type(content_type) {
        return Ok(String::from_utf8_lossy(html_content).into_owned());
    }
    let html_str = String::from_utf8_lossy(html_content);

    // Strip forbidden + boilerplate tags
    let all_tags: Vec<&str> = FORBIDDEN_TAGS
        .iter()
        .chain(BOILERPLATE_TAGS.iter())
        .copied()
        .collect();
    let cleaned = strip_tags(&html_str, &all_tags);

    let md = htmd::convert(&cleaned).map_err(|e| format!("markdown conversion error: {e}"))?;
    let md = EXCESSIVE_NEWLINES
        .replace_all(&md, "\n\n")
        .trim()
        .to_string();

    Ok(md)
}

fn strip_tags(html: &str, tags: &[&str]) -> String {
    let doc = Html::parse_document(html);
    let mut html_out = html.to_string();

    for tag in tags {
        if let Ok(selector) = Selector::parse(tag) {
            for element in doc.select(&selector) {
                let outer_html = element.html();
                html_out = html_out.replace(&outer_html, "");
            }
        }
    }

    html_out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract() {
        // Simple HTML
        let html = b"<h1>Title</h1><p>Hello <a href='#'>world</a></p><ul><li>item</li></ul>";
        let result = extract(html, "text/html").unwrap();
        assert!(result.contains("Title"));
        assert!(result.contains("world"));
        assert!(result.contains("item"));

        // Script tags stripped
        let html = b"<p>safe</p><script>alert('xss')</script><p>content</p>";
        let result = extract(html, "text/html").unwrap();
        assert!(result.contains("safe"));
        assert!(result.contains("content"));
        assert!(!result.contains("alert"));

        // Style tags stripped
        let html = b"<style>.red { color: red; }</style><p>visible</p>";
        let result = extract(html, "text/html").unwrap();
        assert!(result.contains("visible"));
        assert!(!result.contains("color: red"));

        // Iframe stripped
        let html = b"<p>before</p><iframe src='evil.com'></iframe><p>after</p>";
        let result = extract(html, "text/html").unwrap();
        assert!(!result.contains("evil.com"));

        // Empty
        let result = extract(b"", "text/html").unwrap();
        assert!(result.is_empty());

        // Excessive newlines collapsed
        let html = b"<p>one</p>\n\n\n\n\n<p>two</p>";
        let result = extract(html, "text/html").unwrap();
        assert!(!result.contains("\n\n\n"));
    }

    #[test]
    fn test_extract_clean() {
        let html = b"<nav>navigation</nav><main><p>content</p></main><footer>foot</footer><aside>side</aside><header>head</header>";
        let full = extract(html, "text/html").unwrap();
        let clean = extract_clean(html, "text/html").unwrap();

        // Full includes boilerplate
        assert!(full.contains("navigation") || full.contains("foot"));

        // Clean excludes boilerplate but keeps main content
        assert!(clean.contains("content"));
    }

    #[test]
    fn test_is_verbatim_type() {
        for ct in [
            "text/plain",
            "text/plain; charset=utf-8",
            "TEXT/Markdown",
            "text/x-go",
            "application/json",
            "application/vnd.api+json; charset=utf-8",
            "application/toml",
            "application/x-yaml",
            "application/javascript",
        ] {
            assert!(is_verbatim_type(ct), "{ct}");
        }
        for ct in [
            "",
            "text/html",
            "text/html; charset=utf-8",
            "application/xhtml+xml",
            "application/octet-stream",
            "application/pdf",
        ] {
            assert!(!is_verbatim_type(ct), "{ct}");
        }
    }

    #[test]
    fn test_verbatim_toml_is_byte_identical() {
        let toml = b"[package]\nname = \"aho-corasick\"\nauthors = [\"Andrew Gallant <jamslam@gmail.com>\"]\n\n\n[dependencies]\n";
        let out = extract_clean(toml, "text/plain; charset=utf-8").unwrap();
        assert_eq!(out.as_bytes(), toml);
        assert_eq!(extract(toml, "text/plain").unwrap().as_bytes(), toml);
        // Same bytes labelled HTML still get mangled, proving the gate matters.
        let mangled = extract_clean(toml, "text/html").unwrap();
        assert_ne!(mangled.as_bytes(), toml);
    }

    #[test]
    fn test_verbatim_json_and_markdown_untouched() {
        let json = b"{\n  \"a\": [1, 2],\n  \"b\": \"<x>\"\n}\n";
        assert_eq!(
            extract_clean(json, "application/json").unwrap().as_bytes(),
            json
        );
        let md = b"# Title\n\n[link](http://x)\n";
        assert_eq!(extract_clean(md, "text/markdown").unwrap().as_bytes(), md);
    }
}
