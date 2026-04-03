use regex::Regex;
use scraper::{Html, Selector};
use std::sync::LazyLock;

static EXCESSIVE_NEWLINES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{3,}").unwrap());

const FORBIDDEN_TAGS: &[&str] = &["script", "style", "svg", "noscript", "iframe"];
const BOILERPLATE_TAGS: &[&str] = &["nav", "header", "footer", "aside"];

/// Extract content for security scanning (full content, no boilerplate removal).
pub fn extract(html_content: &[u8], _content_type: &str) -> std::result::Result<String, String> {
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
    _content_type: &str,
) -> std::result::Result<String, String> {
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
}
