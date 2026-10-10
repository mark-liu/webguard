use ipnetwork::IpNetwork;
#[cfg(test)]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;
use url::Url;

static BLOCKED_NETS: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
    vec![
        // IPv4
        "127.0.0.0/8".parse().unwrap(),    // loopback
        "10.0.0.0/8".parse().unwrap(),     // RFC 1918
        "172.16.0.0/12".parse().unwrap(),  // RFC 1918
        "192.168.0.0/16".parse().unwrap(), // RFC 1918
        "169.254.0.0/16".parse().unwrap(), // link-local
        // IPv6
        "::1/128".parse().unwrap(),   // loopback
        "fe80::/10".parse().unwrap(), // link-local
        "fc00::/7".parse().unwrap(),  // unique local
    ]
});

/// Carrier-grade NAT. Blocked unless the host matches a configured suffix.
static CGNAT_NET: LazyLock<IpNetwork> = LazyLock::new(|| "100.64.0.0/10".parse().unwrap());

static CLOUD_METADATA_IPS: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    vec![
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), // AWS/GCP/Azure
        IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2)),   // AWS ECS
        IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)), // Alibaba
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 250)), // Oracle
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 251)), // Oracle
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 252)), // Oracle
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253)), // Oracle
        "fd00:ec2::254".parse().unwrap(),              // AWS IPv6
    ]
});

static CLOUD_METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.goog"];

pub fn validate_url(raw: &str) -> std::result::Result<Url, String> {
    let mut url = Url::parse(raw).map_err(|e| e.to_string())?;

    // Scheme check + HTTP upgrade
    match url.scheme() {
        "http" => {
            url.set_scheme("https")
                .map_err(|_| "scheme upgrade failed")?;
        }
        "https" => {}
        other => return Err(format!("unsupported scheme: {other}")),
    }

    // No userinfo
    if !url.username().is_empty() || url.password().is_some() {
        return Err("userinfo not allowed".into());
    }

    // Authority ends where the url crate ends it; backslash counts for https.
    let raw_authority = raw.find("://").map(|i| {
        let rest = &raw[i + 3..];
        &rest[..rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len())]
    });

    // No @ in raw authority (an @ in the path, e.g. medium.com/@user, is fine)
    if raw_authority.is_some_and(|a| a.contains('@')) {
        return Err("@ in authority".into());
    }

    // No URL-encoded hostname (check raw input since url crate auto-decodes %XX)
    let host = url.host_str().unwrap_or("");
    if host.contains('%') {
        return Err("URL-encoded hostname".into());
    }
    // Also check the raw URL — url crate normalizes percent-encoding before we see host_str
    let raw_host = raw_authority.map(|a| &a[..a.find(':').unwrap_or(a.len())]);
    if raw_host.is_some_and(|h| h.contains('%')) {
        return Err("URL-encoded hostname".into());
    }

    // Cloud metadata hostname check
    let host_lower = host.to_lowercase();
    for meta in CLOUD_METADATA_HOSTS {
        if host_lower == *meta {
            return Err("cloud metadata hostname".into());
        }
    }

    // Octal IP notation check (also check raw host since url crate may not parse as IP)
    if is_octal_ip(host) {
        return Err("octal IP notation".into());
    }
    if raw_host.is_some_and(is_octal_ip) {
        return Err("octal IP notation".into());
    }

    Ok(url)
}

/// Dot-boundary suffix match. Entries are lowercased and stripped of a leading
/// `*.`/`.` and trailing `.`; empty entries match nothing. `ts.net` matches
/// `a.ts.net` and `ts.net`, never `evil-ts.net`. IP literals never match.
pub fn host_matches_suffix(host: &str, suffixes: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
        return false;
    }
    suffixes.iter().any(|raw| {
        let s = raw.trim().to_ascii_lowercase();
        let s = s.strip_prefix("*.").unwrap_or(&s);
        let s = s.trim_start_matches('.').trim_end_matches('.');
        !s.is_empty()
            && host
                .strip_suffix(s)
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
    })
}

pub fn validate_ip(ip: IpAddr) -> std::result::Result<(), String> {
    validate_ip_with(ip, false)
}

/// `allow_cgnat` lifts only 100.64.0.0/10; every other blocked range and the
/// metadata IPs (including 100.100.100.200, which sits inside it) stay blocked.
pub fn validate_ip_with(ip: IpAddr, allow_cgnat: bool) -> std::result::Result<(), String> {
    // Extract IPv4 from IPv4-mapped IPv6
    let check_ip = match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                ip
            }
        }
        _ => ip,
    };

    for net in BLOCKED_NETS.iter() {
        if net.contains(check_ip) {
            return Err(format!("IP {ip} in blocked range {net}"));
        }
    }
    if !allow_cgnat && CGNAT_NET.contains(check_ip) {
        return Err(format!("IP {ip} in blocked range {}", *CGNAT_NET));
    }

    for meta_ip in CLOUD_METADATA_IPS.iter() {
        if check_ip == *meta_ip {
            return Err(format!("IP {ip} is cloud metadata endpoint"));
        }
    }

    Ok(())
}

/// Resolve `host` and validate every address. Hosts matching `cgnat_suffixes`
/// may resolve into 100.64.0.0/10; IP literals never get that allowance.
pub async fn resolve_and_validate(
    host: &str,
    cgnat_suffixes: &[String],
) -> std::result::Result<IpAddr, String> {
    // If host is already an IP
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_ip(ip)?;
        return Ok(ip);
    }
    let allow_cgnat = host_matches_suffix(host, cgnat_suffixes);

    // Async DNS resolve -- avoids blocking the tokio runtime
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{host}:0"))
        .await
        .map_err(|e| format!("DNS resolution failed: {e}"))?
        .map(|sa| sa.ip())
        .collect();

    if addrs.is_empty() {
        return Err("no IPs resolved".into());
    }

    // Validate ALL resolved IPs
    for ip in &addrs {
        validate_ip_with(*ip, allow_cgnat)?;
    }

    // Prefer IPv4
    addrs
        .iter()
        .find(|ip| ip.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| "no valid IPs".into())
}

fn is_octal_ip(host: &str) -> bool {
    // Detect octal notation like 0177.0.0.1
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .any(|p| p.len() > 1 && p.starts_with('0') && p.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url() {
        // Valid HTTPS
        assert!(validate_url("https://example.com").is_ok());

        // HTTP upgraded to HTTPS
        let url = validate_url("http://example.com").unwrap();
        assert_eq!(url.scheme(), "https");

        // @ in authority
        assert!(validate_url("https://evil.com@169.254.169.254").is_err());

        // Userinfo
        assert!(validate_url("https://user:pass@example.com").is_err());
        assert!(validate_url("https://:pass@example.com").is_err());

        // @ outside the authority is a path character, not userinfo
        assert!(validate_url("https://medium.com/@user/post").is_ok());
        assert!(validate_url("https://example.com/a?u=x@y.com").is_ok());
        assert!(validate_url("https://example.com#@evil.com").is_ok());
        assert!(validate_url("https://evil.com@169.254.169.254/@x").is_err());
        assert!(validate_url("https://exam%70le.com/@x").is_err());
        assert!(validate_url("https://0177.0.0.1/@x").is_err());

        // URL-encoded hostname
        assert!(validate_url("https://exam%70le.com").is_err());

        // Octal IP
        assert!(validate_url("https://0177.0.0.1").is_err());

        // FTP scheme
        assert!(validate_url("ftp://example.com").is_err());

        // No scheme
        assert!(validate_url("example.com").is_err());

        // Empty
        assert!(validate_url("").is_err());
    }

    #[test]
    fn test_validate_ip() {
        // Public IPv4 OK
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_ok());

        // Loopback blocked
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).is_err());

        // Private ranges blocked
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_err());
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))).is_err());
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_err());

        // Link-local blocked
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))).is_err());

        // AWS metadata blocked
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))).is_err());

        // Carrier-grade NAT blocked
        assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))).is_err());

        // IPv6 loopback blocked
        assert!(validate_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_err());

        // IPv4-mapped IPv6 loopback blocked
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(validate_ip(mapped).is_err());

        // Public IPv6 OK
        let public_v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(validate_ip(public_v6).is_ok());
    }

    #[tokio::test]
    async fn test_resolve_and_validate_ip_passthrough() {
        // Direct IP should pass through without DNS lookup
        let result = resolve_and_validate("8.8.8.8", &[]).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[tokio::test]
    async fn test_resolve_and_validate_blocks_private_ip() {
        let result = resolve_and_validate("127.0.0.1", &[]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked range"));
    }

    #[tokio::test]
    async fn test_resolve_and_validate_blocks_metadata_ip() {
        let result = resolve_and_validate("169.254.169.254", &[]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_and_validate_resolves_hostname() {
        // This test requires network access but validates async DNS works
        let result = resolve_and_validate("example.com", &[]).await;
        assert!(result.is_ok(), "should resolve example.com: {:?}", result);
        let ip = result.unwrap();
        // example.com resolves to a public IP
        assert!(!ip.is_loopback());
    }

    fn sfx(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_host_matches_suffix_dot_boundary() {
        let s = sfx(&["example-tailnet.ts.net"]);
        assert!(host_matches_suffix("box.example-tailnet.ts.net", &s));
        assert!(host_matches_suffix("a.b.example-tailnet.ts.net", &s));
        assert!(host_matches_suffix("BOX.Example-Tailnet.ts.net.", &s));
        assert!(host_matches_suffix("example-tailnet.ts.net", &s));
        assert!(!host_matches_suffix("evil-example-tailnet.ts.net", &s));
        assert!(!host_matches_suffix("example-tailnet.ts.net.evil.com", &s));
        let s = sfx(&["ts.net"]);
        assert!(!host_matches_suffix("evil-ts.net", &s));
        assert!(host_matches_suffix("x.ts.net", &s));
    }

    #[test]
    fn test_host_matches_suffix_entry_forms_and_empties() {
        for entry in ["*.ts.net", ".ts.net", "TS.NET.", " ts.net "] {
            assert!(host_matches_suffix("x.ts.net", &sfx(&[entry])), "{entry}");
        }
        for entry in ["", ".", "*.", " "] {
            assert!(
                !host_matches_suffix("x.ts.net", &sfx(&[entry])),
                "{entry:?}"
            );
            assert!(
                !host_matches_suffix("example.com", &sfx(&[entry])),
                "{entry:?}"
            );
        }
        assert!(!host_matches_suffix("x.ts.net", &[]));
    }

    #[test]
    fn test_host_matches_suffix_never_ip_literals() {
        let s = sfx(&["4", "0.1", "1", "::1", "100.64.0.1"]);
        assert!(!host_matches_suffix("100.64.0.1", &s));
        assert!(!host_matches_suffix("100.64.0.4", &s));
        assert!(!host_matches_suffix("::1", &s));
        assert!(!host_matches_suffix("[::1]", &s));
    }

    #[test]
    fn test_validate_ip_with_cgnat_allowance_is_cgnat_only() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        // CGNAT: blocked by default, allowed when lifted (edges of the /10 too)
        for ip in [v4(100, 64, 0, 1), v4(100, 127, 255, 254)] {
            assert!(validate_ip(ip).is_err());
            assert!(validate_ip_with(ip, true).is_ok(), "{ip}");
        }
        // Neighbours outside the /10 stay public
        assert!(validate_ip_with(v4(100, 63, 255, 255), true).is_ok());
        assert!(validate_ip_with(v4(100, 128, 0, 1), true).is_ok());
        // Everything else stays blocked even with the allowance
        for ip in [
            v4(127, 0, 0, 1),
            v4(10, 0, 0, 1),
            v4(172, 16, 0, 1),
            v4(192, 168, 1, 1),
            v4(169, 254, 1, 1),
            v4(169, 254, 169, 254),
            v4(100, 100, 100, 200), // metadata IP inside the CGNAT range
            "::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "fd7a:115c:a1e0::1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
            "fd00:ec2::254".parse().unwrap(),
        ] {
            assert!(validate_ip_with(ip, true).is_err(), "{ip}");
        }
        // IPv4-mapped CGNAT follows the same rule
        let mapped: IpAddr = "::ffff:100.64.0.1".parse().unwrap();
        assert!(validate_ip(mapped).is_err());
        assert!(validate_ip_with(mapped, true).is_ok());
    }

    #[tokio::test]
    async fn test_resolve_and_validate_ip_literal_ignores_suffixes() {
        let s = sfx(&["100.64.0.1", "1", "0.1"]);
        assert!(resolve_and_validate("100.64.0.1", &s).await.is_err());
        assert!(resolve_and_validate("127.0.0.1", &s).await.is_err());
    }

    #[tokio::test]
    async fn test_resolve_and_validate_localhost_not_unlocked() {
        // Suffix match lifts CGNAT only; a matching name resolving to loopback stays blocked.
        let s = sfx(&["localhost"]);
        assert!(resolve_and_validate("localhost", &s).await.is_err());
    }
}
