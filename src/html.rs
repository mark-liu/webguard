//! Time-bounded HTML parsing. html5ever's tree builder is quadratic in nesting
//! depth (scope checks walk the open-element stack): 100k nested `<div>` cost
//! 14 s, and a 5 MiB body runs for many minutes, so input is fed in chunks
//! against a deadline and the parse is dropped once it runs over.

use html5ever::tendril::{StrTendril, TendrilSink, fmt::UTF8};
use html5ever::{QualName, driver, local_name, namespace_url, ns};
use scraper::{Html, HtmlTreeSink};
use std::time::{Duration, Instant};

/// A normal 5 MiB page parses in well under this; a page that does not is hostile.
pub const PARSE_BUDGET: Duration = Duration::from_secs(2);

/// Small enough that one chunk past the deadline costs well under a second.
const CHUNK: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExceeded;

/// Same tree as `Html::parse_document`, or `BudgetExceeded`.
pub fn parse_document(html: &str, budget: Duration) -> Result<Html, BudgetExceeded> {
    let parser =
        driver::parse_document(HtmlTreeSink::new(Html::new_document()), Default::default());
    feed(parser, html, budget)
}

/// Same tree as `Html::parse_fragment`, or `BudgetExceeded`.
pub fn parse_fragment(html: &str, budget: Duration) -> Result<Html, BudgetExceeded> {
    let parser = driver::parse_fragment(
        HtmlTreeSink::new(Html::new_fragment()),
        Default::default(),
        QualName::new(None, ns!(html), local_name!("body")),
        Vec::new(),
    );
    feed(parser, html, budget)
}

/// Test fixture: `inner` wrapped in `n` levels of `tag`.
#[cfg(test)]
pub fn nested(tag: &str, n: usize, inner: &str) -> String {
    format!(
        "{}{inner}{}",
        format!("<{tag}>").repeat(n),
        format!("</{tag}>").repeat(n)
    )
}

fn feed<P: TendrilSink<UTF8>>(
    mut parser: P,
    s: &str,
    budget: Duration,
) -> Result<P::Output, BudgetExceeded> {
    let deadline = Instant::now() + budget;
    let mut rest = s;
    while !rest.is_empty() {
        let mut end = rest.len().min(CHUNK);
        while !rest.is_char_boundary(end) {
            end += 1;
        }
        let (chunk, tail) = rest.split_at(end);
        parser.process(StrTendril::from_slice(chunk));
        rest = tail;
        if Instant::now() > deadline {
            return Err(BudgetExceeded);
        }
    }
    Ok(parser.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_parse_matches_one_shot() {
        // Multi-byte text and tags straddle the 16 KiB chunk boundaries.
        let html = "<p>héllo <b>wörld</b> 日本語 <a href='x'>l</a></p>\n".repeat(2000);
        assert!(html.len() > 4 * CHUNK);
        assert_eq!(
            parse_document(&html, PARSE_BUDGET).unwrap().html(),
            Html::parse_document(&html).html()
        );
        assert_eq!(
            parse_fragment(&html, PARSE_BUDGET).unwrap().html(),
            Html::parse_fragment(&html).html()
        );
    }

    #[test]
    fn deep_nesting_trips_budget() {
        let html = nested("div", 100_000, "x");
        let start = Instant::now();
        assert_eq!(
            parse_document(&html, Duration::from_millis(50)).err(),
            Some(BudgetExceeded)
        );
        assert_eq!(
            parse_fragment(&html, Duration::from_millis(50)).err(),
            Some(BudgetExceeded)
        );
        // Unbounded, this page parses for about 14 s per call.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn large_shallow_page_fits_default_budget() {
        let html = "<div><p>plain paragraph of text with <b>bold</b></p></div>\n".repeat(80_000);
        assert!(html.len() > 4 << 20);
        assert!(parse_document(&html, PARSE_BUDGET).is_ok());
    }
}
