use regex::Regex;
use scraper::{Html, Node};
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

/// Raw HTML minus script/style/noscript/svg/iframe elements and comments:
/// keeps tags and layout markup (which htmd rewrites) but drops the inline-JS
/// text behind the fromCharCode false positives. Same parse as delivery, so
/// nothing the model reads can fall out of this view.
pub fn strip_non_prose(html: &str) -> String {
    prune(html, FORBIDDEN_TAGS)
}

/// Extract content for security scanning (full content, no boilerplate removal).
pub fn extract(html_content: &[u8], content_type: &str) -> std::result::Result<String, String> {
    if is_verbatim_type(content_type) {
        return Ok(String::from_utf8_lossy(html_content).into_owned());
    }
    let html_str = String::from_utf8_lossy(html_content);

    // Strip forbidden tags from HTML before conversion
    let cleaned = prune(&html_str, FORBIDDEN_TAGS);

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
    let cleaned = prune(&html_str, &all_tags);

    let md = htmd::convert(&cleaned).map_err(|e| format!("markdown conversion error: {e}"))?;
    let md = EXCESSIVE_NEWLINES
        .replace_all(&md, "\n\n")
        .trim()
        .to_string();

    Ok(md)
}

/// Detach every `tags` element and every comment from one html5ever parse and
/// re-serialise. A regex or string replace disagrees with the tokenizer on
/// attribute-quoted markers, odd end tags and foreign-content breakout.
fn prune(html: &str, tags: &[&str]) -> String {
    let mut doc = Html::parse_document(html);
    let doomed: Vec<_> = doc
        .tree
        .nodes()
        .filter(|n| match n.value() {
            Node::Comment(_) => true,
            Node::Element(el) => tags.contains(&el.name()),
            _ => false,
        })
        .map(|n| n.id())
        .collect();
    for id in doomed {
        if let Some(mut node) = doc.tree.get_mut(id) {
            node.detach();
        }
    }
    flatten_deep(&mut doc);
    doc.html()
}

/// Chromium's parser depth cap. htmd recurses per element and aborts the whole
/// process (stack overflow, uncatchable) near 5000 levels on a 2 MiB thread.
const MAX_DEPTH: usize = 512;

/// Unwrap every element nested deeper than MAX_DEPTH: its children move up in
/// place, so all text survives for scanning and only the excess tags go.
fn flatten_deep(doc: &mut Html) {
    let mut deep = Vec::new();
    let mut stack = vec![(doc.tree.root(), 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_DEPTH && node.value().is_element() {
            deep.push(node.id());
        }
        // Reversed so the pop order stays pre-order: parents unwrap before children.
        let kids: Vec<_> = node.children().collect();
        stack.extend(kids.into_iter().rev().map(|c| (c, depth + 1)));
    }
    for id in deep {
        let kids: Vec<_> = doc.tree.get(id).unwrap().children().map(|c| c.id()).collect();
        let mut node = doc.tree.get_mut(id).unwrap();
        for kid in kids {
            node.insert_id_before(kid);
        }
        node.detach();
    }
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
    fn test_deep_nesting_flattened() {
        // 2 MiB matches a tokio worker; 5000 levels aborted the process before the cap.
        let run = |tag: &'static str| {
            std::thread::Builder::new()
                .stack_size(2 << 20)
                .spawn(move || {
                    let html = format!(
                        "{}deep text{}",
                        format!("<{tag}>").repeat(20_000),
                        format!("</{tag}>").repeat(20_000)
                    );
                    let full = extract(html.as_bytes(), "text/html").unwrap();
                    let clean = extract_clean(html.as_bytes(), "text/html").unwrap();
                    let stripped = strip_non_prose(&html);
                    (full, clean, stripped)
                })
                .unwrap()
                .join()
                .unwrap()
        };
        for tag in ["div", "span", "blockquote"] {
            let (full, clean, stripped) = run(tag);
            assert!(full.contains("deep text"), "{tag}");
            assert!(clean.contains("deep text"), "{tag}");
            assert!(stripped.contains("deep text"), "{tag}");
            let opens = stripped.matches(&format!("<{tag}>")).count();
            assert!(opens <= MAX_DEPTH, "{tag}: {opens} levels kept");
        }
    }

    #[test]
    fn test_shallow_markup_untouched_by_depth_cap() {
        let html = "<div><p>keep <b>bold</b> and <a href='https://x.test'>link</a></p></div>";
        assert_eq!(strip_non_prose(html), Html::parse_document(html).html());
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

