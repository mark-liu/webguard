use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use std::collections::HashMap;
use std::time::Duration;

use super::ssrf::{resolve_and_validate, validate_url};

const DEFAULT_MAX_BODY_SIZE: i64 = 5 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REDIRECTS: usize = 5;
const UA: &str = "webguard-mcp/0.1.0";

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
}

pub async fn fetch(
    raw_url: &str,
    opts: &FetchOptions,
) -> std::result::Result<FetchResult, String> {
    // Validate URL
    let url = validate_url(raw_url)?;
    let host = url.host_str().ok_or("no host")?.to_string();

    // Validate resolved IP (DNS pinning)
    let _resolved_ip = resolve_and_validate(&host)?;

    // Build headers
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(UA));
    for (k, v) in &opts.headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }

    // Disable automatic redirects — we follow manually to re-validate each hop
    let client = reqwest::Client::builder()
        .timeout(opts.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .build()
        .map_err(|e| format!("client build error: {e}"))?;

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
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or("redirect with no location header")?;

            // Resolve relative redirects against current URL
            let next_url = url::Url::parse(location)
                .or_else(|_| url::Url::parse(&current_url).and_then(|base| base.join(location)))
                .map_err(|e| format!("invalid redirect URL: {e}"))?;

            // Re-validate redirect target against SSRF rules
            let _ = validate_url(next_url.as_str())?;
            let redirect_host = next_url.host_str().ok_or("no host in redirect")?.to_string();
            let _ = resolve_and_validate(&redirect_host)?;

            current_url = next_url.to_string();
            redirect_count += 1;
            continue;
        }

        break resp;
    };

    let status_code = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
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
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("body read error: {e}"))?;
        let remaining = limit.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        let to_take = chunk.len().min(remaining);
        body.extend_from_slice(&chunk[..to_take]);
    }

    Ok(FetchResult {
        status_code,
        content_type,
        body,
        final_url,
        redirect_count,
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
