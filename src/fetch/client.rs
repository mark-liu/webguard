use rquest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION,
    UPGRADE_INSECURE_REQUESTS, USER_AGENT,
};
use rquest_util::Emulation;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use super::ssrf::{resolve_and_validate, validate_url};

const DEFAULT_MAX_BODY_SIZE: i64 = 5 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REDIRECTS: usize = 5;

// Mirror Chrome 136 across the whole stack: TLS ClientHello + HTTP/2 SETTINGS
// (via `rquest_util::Emulation::Chrome136`), header order, and this UA string.
// The version pinned here MUST match `EMULATION_PROFILE` below — divergent
// header/UA vs. wire fingerprint is itself a bot signal.
// `concat!` avoids string-literal continuation, which would embed leading
// whitespace from the next line into the value and trip UA fingerprinting.
const UA: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) ",
    "Chrome/136.0.0.0 Safari/537.36",
);

const EMULATION_PROFILE: Emulation = Emulation::Chrome136;

const ACCEPT_DEFAULT: &str = concat!(
    "text/html,application/xhtml+xml,application/xml;q=0.9,",
    "image/avif,image/webp,image/apng,*/*;q=0.8,",
    "application/signed-exchange;v=b3;q=0.7",
);

/// Browser-shaped default headers. Caller-supplied headers may override
/// only the names in `OVERRIDABLE_HEADERS`.
///
/// `Sec-Fetch-Site` is intentionally not set: real browsers vary it by
/// navigation context (`none`/`same-origin`/`cross-site`), and a constant
/// value is itself a fingerprint. The remaining `Sec-Fetch-*` are constant
/// for the top-level GETs we issue.
static DEFAULT_HEADERS: LazyLock<HeaderMap> = LazyLock::new(|| {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(UA));
    headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_DEFAULT));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    headers
});

/// Caller (LLM) overrides are restricted to a small allowlist.
/// Anything else — `Host`, `Connection`, `Range`, `Accept-Encoding`,
/// `Cookie`, `Authorization`, hop-by-hop headers, etc — is silently
/// dropped to prevent request smuggling, decompression bypass, the
/// caller defeating its own anti-bot profile, and credential leakage.
const OVERRIDABLE_HEADERS: &[&str] = &["accept", "accept-language", "user-agent"];

fn apply_header_overrides(headers: &mut HeaderMap, overrides: &HashMap<String, String>) {
    for (k, v) in overrides {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            if OVERRIDABLE_HEADERS.contains(&name.as_str()) {
                headers.insert(name, val);
            }
        }
    }
}

pub struct FetchOptions {
    pub max_body_size: i64,
    pub timeout: Duration,
    pub headers: HashMap<String, String>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        FetchOptions {
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            timeout: DEFAULT_TIMEOUT,
            headers: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct FetchResult {
    pub status_code: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub final_url: String,
    pub redirect_count: usize,
    /// True if `max_body_size` was hit and the body was cut short.
    /// Callers (especially the prompt-injection scanner) should treat
    /// truncated content as lower-trust — payload may sit past the cut.
    pub truncated: bool,
}

/// Build an rquest client that pins `host` to `resolved_ip`, preventing
/// DNS rebinding between validation and the actual connection.
///
/// `Emulation::Chrome136` drives the TLS ClientHello (JA3/JA4) and HTTP/2
/// SETTINGS frame to match real Chrome — the actual mechanism that defeats
/// Cloudflare/Akamai bot management. Header tweaks alone don't cross that
/// gate; the wire fingerprint does.
///
/// `cookie_store(true)` gives this client an empty in-memory jar. Cookies
/// (e.g. `cf_clearance` issued after a JS challenge) only persist while
/// the same client is used. The redirect loop in `fetch()` reuses this
/// client for same-host hops, so jar survives a CF challenge → 302 →
/// origin chain. Cross-host redirects deliberately rebuild and reset the
/// jar — that's correct cookie-origin behaviour, no cross-site leak.
fn build_pinned_client(
    host: &str,
    resolved_ip: IpAddr,
    port: u16,
    timeout: Duration,
    headers: HeaderMap,
) -> std::result::Result<rquest::Client, String> {
    let socket_addr = SocketAddr::new(resolved_ip, port);
    // Auto-decompress gzip/brotli/deflate. rquest sets `Accept-Encoding`
    // automatically — never set it in `headers` or decompression silently
    // turns into raw passthrough.
    rquest::Client::builder()
        .emulation(EMULATION_PROFILE)
        .timeout(timeout)
        .redirect(rquest::redirect::Policy::none())
        .default_headers(headers)
        .resolve(host, socket_addr)
        .cookie_store(true)
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .build()
        .map_err(|e| format!("client build error: {e}"))
}

pub async fn fetch(raw_url: &str, opts: &FetchOptions) -> std::result::Result<FetchResult, String> {
    // Validate URL
    let url = validate_url(raw_url)?;
    let mut current_host = url.host_str().ok_or("no host")?.to_string();
    let mut current_port = url.port_or_known_default().unwrap_or(443);

    // Resolve DNS and validate all IPs against SSRF rules (async)
    let mut current_ip = resolve_and_validate(&current_host).await?;

    let mut headers = DEFAULT_HEADERS.clone();
    apply_header_overrides(&mut headers, &opts.headers);

    // Build client pinned to the validated IP — prevents DNS rebinding TOCTOU
    let mut client = build_pinned_client(
        &current_host,
        current_ip,
        current_port,
        opts.timeout,
        headers.clone(),
    )?;

    // Follow redirects manually with SSRF re-validation per hop
    let mut current_url = url.to_string();
    let mut redirect_count = 0usize;

    let response = loop {
        let resp = client
            .get(&current_url)
            .send()
            .await
            .map_err(|e| format!("fetch error: {e}"))?;

        if resp.status().is_redirection() {
            if redirect_count >= MAX_REDIRECTS {
                return Err(format!("too many redirects ({MAX_REDIRECTS})"));
            }
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("redirect with no location header")?;

            // Resolve relative redirects against current URL
            let next_url = url::Url::parse(location)
                .or_else(|_| url::Url::parse(&current_url).and_then(|base| base.join(location)))
                .map_err(|e| format!("invalid redirect URL: {e}"))?;

            // Re-validate redirect target against SSRF rules — must run on
            // every hop, even same-host, to catch DNS-flip attacks.
            let _ = validate_url(next_url.as_str())?;
            let redirect_host = next_url
                .host_str()
                .ok_or("no host in redirect")?
                .to_string();
            let redirect_ip = resolve_and_validate(&redirect_host).await?;
            let redirect_port = next_url.port_or_known_default().unwrap_or(443);

            // Same-endpoint fast path: reuse the existing client. This
            // preserves the cookie jar (so `cf_clearance` set during a CF
            // challenge → 302 → origin chain reaches the origin) and
            // avoids a fresh BoringSSL handshake. Cross-endpoint redirects
            // rebuild — fresh jar prevents cross-origin cookie leaks.
            let same_endpoint = redirect_host == current_host
                && redirect_port == current_port
                && redirect_ip == current_ip;
            if !same_endpoint {
                client = build_pinned_client(
                    &redirect_host,
                    redirect_ip,
                    redirect_port,
                    opts.timeout,
                    headers.clone(),
                )?;
                current_host = redirect_host;
                current_port = redirect_port;
                current_ip = redirect_ip;
            }

            current_url = next_url.to_string();
            redirect_count += 1;
            continue;
        }

        break resp;
    };

    let status_code = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let final_url = current_url;

    // Stream body with size limit — don't buffer beyond max_body_size
    let limit = if opts.max_body_size > 0 {
        opts.max_body_size as usize
    } else {
        DEFAULT_MAX_BODY_SIZE as usize
    };

    let mut body = Vec::with_capacity(limit.min(1024 * 64)); // pre-alloc max 64KB
    let mut response = response;
    let mut truncated = false;

    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = limit.saturating_sub(body.len());
                if remaining == 0 {
                    // More bytes pending but limit hit — record so callers
                    // can mark partial scans as lower-trust.
                    truncated = true;
                    break;
                }
                if chunk.len() > remaining {
                    truncated = true;
                }
                let to_take = chunk.len().min(remaining);
                body.extend_from_slice(&chunk[..to_take]);
            }
            Ok(None) => break,
            Err(e) => return Err(format!("body read error: {e}")),
        }
    }

    Ok(FetchResult {
        status_code,
        content_type,
        body,
        final_url,
        redirect_count,
        truncated,
    })
}

pub async fn fetch_with_retry(
    raw_url: &str,
    opts: &FetchOptions,
) -> std::result::Result<FetchResult, String> {
    match fetch(raw_url, opts).await {
        Ok(result) => Ok(result),
        Err(e) if is_timeout_error(&e) => {
            // Retry once with doubled timeout
            let retry_opts = FetchOptions {
                max_body_size: opts.max_body_size,
                timeout: opts.timeout * 2,
                headers: opts.headers.clone(),
            };
            fetch(raw_url, &retry_opts).await
        }
        Err(e) => Err(e),
    }
}

fn is_timeout_error(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("context deadline exceeded")
        || lower.contains("tls handshake timeout")
        || lower.contains("i/o timeout")
        || lower.contains("operation timed out")
        || lower.contains("timed out")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rquest::header::ACCEPT_ENCODING;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_pinned_client_succeeds() {
        // Verify the pinned client builder produces a valid client
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com
        let headers = HeaderMap::new();
        let client = build_pinned_client("example.com", ip, 443, Duration::from_secs(10), headers);
        assert!(client.is_ok(), "pinned client should build successfully");
    }

    #[test]
    fn test_build_pinned_client_ipv6() {
        let ip: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        let headers = HeaderMap::new();
        let client = build_pinned_client("example.com", ip, 443, Duration::from_secs(10), headers);
        assert!(client.is_ok(), "pinned client should work with IPv6");
    }

    #[test]
    fn test_build_pinned_client_custom_port() {
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let headers = HeaderMap::new();
        let client = build_pinned_client("example.com", ip, 8443, Duration::from_secs(5), headers);
        assert!(client.is_ok(), "pinned client should work with custom port");
    }

    #[test]
    fn test_default_headers_look_like_chrome() {
        let ua = DEFAULT_HEADERS
            .get(USER_AGENT)
            .expect("UA missing")
            .to_str()
            .unwrap();
        assert!(
            ua.starts_with("Mozilla/5.0"),
            "UA must start with Mozilla/5.0"
        );
        assert!(ua.contains("Chrome/"), "UA must contain Chrome/");
        // No embedded whitespace — guards against `\` continuation regression.
        assert!(!ua.contains("  "), "UA contains run of spaces: {ua:?}");
        assert!(DEFAULT_HEADERS.contains_key(ACCEPT));
        assert!(DEFAULT_HEADERS.contains_key(ACCEPT_LANGUAGE));
        assert_eq!(
            DEFAULT_HEADERS
                .get("sec-fetch-mode")
                .and_then(|v| v.to_str().ok()),
            Some("navigate"),
        );
        assert!(DEFAULT_HEADERS.get(ACCEPT_ENCODING).is_none());
    }

    #[test]
    fn test_allowlisted_overrides_win() {
        let mut headers = DEFAULT_HEADERS.clone();
        let mut overrides = HashMap::new();
        overrides.insert("user-agent".to_string(), "MyBot/1.0".to_string());
        overrides.insert("accept-language".to_string(), "fr-FR".to_string());
        apply_header_overrides(&mut headers, &overrides);

        assert_eq!(
            headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            Some("MyBot/1.0"),
        );
        assert_eq!(
            headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
            Some("fr-FR"),
        );
    }

    #[test]
    fn test_non_allowlisted_overrides_dropped() {
        let mut headers = DEFAULT_HEADERS.clone();
        let mut overrides = HashMap::new();
        // Routing / smuggling vectors that must never reach the wire.
        overrides.insert("host".to_string(), "evil.example.com".to_string());
        overrides.insert("connection".to_string(), "close".to_string());
        overrides.insert("range".to_string(), "bytes=0-1".to_string());
        overrides.insert("accept-encoding".to_string(), "identity".to_string());
        overrides.insert("authorization".to_string(), "Bearer SECRET".to_string());
        overrides.insert("cookie".to_string(), "session=evil".to_string());
        overrides.insert("x-custom".to_string(), "yes".to_string());
        apply_header_overrides(&mut headers, &overrides);

        for blocked in [
            "host",
            "connection",
            "range",
            "authorization",
            "cookie",
            "x-custom",
        ] {
            assert!(
                headers.get(blocked).is_none(),
                "{blocked} must be dropped, found: {:?}",
                headers.get(blocked),
            );
        }
        // Accept-Encoding must remain unset so reqwest's auto-decompression
        // engages — caller can't override it back to identity.
        assert!(headers.get(ACCEPT_ENCODING).is_none());
    }

    #[test]
    fn test_is_timeout_error() {
        assert!(is_timeout_error("fetch error: operation timed out"));
        assert!(is_timeout_error("tls handshake timeout"));
        assert!(is_timeout_error("context deadline exceeded"));
        assert!(!is_timeout_error("connection refused"));
        assert!(!is_timeout_error("DNS resolution failed"));
    }
}
