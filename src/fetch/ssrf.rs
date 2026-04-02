use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
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
        "100.64.0.0/10".parse().unwrap(),  // carrier-grade NAT
        // IPv6
        "::1/128".parse().unwrap(),        // loopback
        "fe80::/10".parse().unwrap(),      // link-local
        "fc00::/7".parse().unwrap(),       // unique local
    ]
});

static CLOUD_METADATA_IPS: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    vec![
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), // AWS/GCP/Azure
        IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2)),   // AWS ECS
        IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)), // Alibaba
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 250)), // Oracle
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 251)), // Oracle
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 252)), // Oracle
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253)), // Oracle
        "fd00:ec2::254".parse().unwrap(),                // AWS IPv6
    ]
});

static CLOUD_METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.goog"];

pub fn validate_url(raw: &str) -> std::result::Result<Url, String> {
    let mut url = Url::parse(raw).map_err(|e| e.to_string())?;

    // Scheme check + HTTP upgrade
    match url.scheme() {
        "http" => {
            url.set_scheme("https").map_err(|_| "scheme upgrade failed")?;
        }
        "https" => {}
        other => return Err(format!("unsupported scheme: {other}")),
    }

    // No userinfo
    if !url.username().is_empty() {
        return Err("userinfo not allowed".into());
    }

    // No @ in raw authority
    if raw.contains('@') {
        return Err("@ in authority".into());
    }

    // No URL-encoded hostname (check raw input since url crate auto-decodes %XX)
    let host = url.host_str().unwrap_or("");
    if host.contains('%') {
        return Err("URL-encoded hostname".into());
    }
    // Also check the raw URL — url crate normalizes percent-encoding before we see host_str
    if let Some(auth_start) = raw.find("://") {
        let after_scheme = &raw[auth_start + 3..];
        // Strip optional userinfo@
        let host_part = after_scheme.split('@').last().unwrap_or(after_scheme);
        let host_end = host_part
            .find(|c: char| c == '/' || c == ':' || c == '?')
            .unwrap_or(host_part.len());
        let raw_host = &host_part[..host_end];
        if raw_host.contains('%') {
            return Err("URL-encoded hostname".into());
        }
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
    if let Some(auth_start) = raw.find("://") {
        let after_scheme = &raw[auth_start + 3..];
        let host_part = after_scheme.split('@').last().unwrap_or(after_scheme);
        let host_end = host_part
            .find(|c: char| c == '/' || c == ':' || c == '?')
            .unwrap_or(host_part.len());
        if is_octal_ip(&host_part[..host_end]) {
            return Err("octal IP notation".into());
        }
    }

    Ok(url)
}

pub fn validate_ip(ip: IpAddr) -> std::result::Result<(), String> {
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

    for meta_ip in CLOUD_METADATA_IPS.iter() {
        if check_ip == *meta_ip {
            return Err(format!("IP {ip} is cloud metadata endpoint"));
        }
    }

    Ok(())
}

pub fn resolve_and_validate(host: &str) -> std::result::Result<IpAddr, String> {
    // If host is already an IP
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_ip(ip)?;
        return Ok(ip);
    }

    // DNS resolve
    let addrs: Vec<IpAddr> = format!("{host}:0")
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {e}"))?
        .map(|sa| sa.ip())
        .collect();

    if addrs.is_empty() {
        return Err("no IPs resolved".into());
    }

    // Validate ALL resolved IPs
    for ip in &addrs {
        validate_ip(*ip)?;
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
    parts.iter().any(|p| {
        p.len() > 1 && p.starts_with('0') && p.chars().all(|c| c.is_ascii_digit())
    })
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
}
