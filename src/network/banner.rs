//! Banner grabbing and service identification module.
//!
//! Connects to open ports and reads service banners to identify
//! the running software, version, and potential OS fingerprints.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::ScanError;
use crate::network::tls::TlsInfo;

/// Result of a banner grab operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BannerResult {
    /// Target IP address
    pub ip: String,
    /// Target port number
    pub port: u16,
    /// Raw banner string received from the service
    pub banner: String,
    /// Identified service name (e.g., "OpenSSH", "nginx")
    pub service: Option<String>,
    /// OS fingerprint if detectable (e.g., "Ubuntu", "Windows")
    pub os_fingerprint: Option<String>,
    /// Unix timestamp when the banner was grabbed
    pub timestamp: i64,
    /// TLS certificate information (only for TLS-capable ports)
    pub tls_info: Option<TlsInfo>,
}

/// Well-known ports to attempt banner grabbing on.
pub const BANNER_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443,
];

/// Banner grabber that connects to open ports and reads service information.
pub struct BannerGrabber {
    /// Timeout for each connection and read operation
    timeout: Duration,
}

impl BannerGrabber {
    /// Create a new banner grabber with the given timeout.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Grab a banner from a specific IP and port.
    ///
    /// Connects via TCP, sends an appropriate probe based on the port,
    /// and reads the response to identify the service.
    pub async fn grab_banner(&self, ip: &str, port: u16) -> Result<BannerResult, ScanError> {
        let addr = format!("{}:{}", ip, port);

        let connect_result = tokio::time::timeout(self.timeout, TcpStream::connect(&addr)).await;

        let mut stream = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(ScanError::NetworkError(format!(
                    "Failed to connect to {} for banner grab: {}",
                    addr, e
                )));
            }
            Err(_) => {
                return Err(ScanError::Timeout);
            }
        };

        // Send appropriate probe based on port
        let probe = get_probe_for_port(port, ip);
        if !probe.is_empty() {
            let write_result =
                tokio::time::timeout(self.timeout, stream.write_all(probe.as_bytes())).await;

            match write_result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(ScanError::NetworkError(format!(
                        "Failed to send probe to {}: {}",
                        addr, e
                    )));
                }
                Err(_) => {
                    return Err(ScanError::Timeout);
                }
            }
        }

        // Read response
        let mut buf = vec![0u8; 4096];
        let read_result = tokio::time::timeout(self.timeout, stream.read(&mut buf)).await;

        let bytes_read = match read_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                return Err(ScanError::NetworkError(format!(
                    "Failed to read banner from {}: {}",
                    addr, e
                )));
            }
            Err(_) => {
                return Err(ScanError::Timeout);
            }
        };

        if bytes_read == 0 {
            return Err(ScanError::NetworkError(format!(
                "No data received from {}",
                addr
            )));
        }

        // Convert to string, replacing non-UTF8 bytes
        let banner = String::from_utf8_lossy(&buf[..bytes_read])
            .trim()
            .to_string();

        // Parse service info from banner
        let (service, os_fingerprint) = parse_service_info(&banner, port);

        Ok(BannerResult {
            ip: ip.to_string(),
            port,
            banner,
            service,
            os_fingerprint,
            timestamp: chrono::Utc::now().timestamp(),
            tls_info: None,
        })
    }

    /// Grab banners from multiple ports on a host.
    ///
    /// Only attempts ports that are in the `BANNER_PORTS` list.
    /// Returns successful grabs only; failures are silently skipped.
    pub async fn grab_banners(&self, ip: &str, open_ports: &[u16]) -> Vec<BannerResult> {
        use futures::stream::{self, StreamExt};

        let ports_to_grab: Vec<u16> = open_ports
            .iter()
            .filter(|p| BANNER_PORTS.contains(p))
            .copied()
            .collect();

        stream::iter(ports_to_grab)
            .filter_map(|port| async move { self.grab_banner(ip, port).await.ok() })
            .collect()
            .await
    }
}

/// Get the appropriate probe string for a given port.
fn get_probe_for_port(port: u16, ip: &str) -> String {
    match port {
        // HTTP ports: send a HEAD request
        80 | 8080 | 8443 => format!(
            "HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: NetSentinel/1.0\r\nConnection: close\r\n\r\n",
            ip
        ),
        // SSH: just read the greeting (no probe needed)
        22 => String::new(),
        // SMTP: read the 220 greeting
        25 | 587 => String::new(),
        // FTP: read the 220 greeting
        21 => String::new(),
        // Telnet: read the greeting
        23 => String::new(),
        // POP3: read the greeting
        110 => String::new(),
        // IMAP: read the greeting
        143 => String::new(),
        // For other ports: send empty bytes and read response
        _ => String::new(),
    }
}

/// Parse service name and OS fingerprint from a banner string.
///
/// Uses pattern matching against known service signatures to identify
/// the software and potentially the operating system.
pub fn parse_service_info(banner: &str, port: u16) -> (Option<String>, Option<String>) {
    let banner_lower = banner.to_lowercase();

    let service = if banner_lower.contains("openssh") {
        extract_version_string(&banner_lower, "openssh")
            .map(|v| format!("OpenSSH {}", v))
            .or_else(|| Some("OpenSSH".to_string()))
    } else if banner_lower.contains("ssh-") {
        Some(extract_ssh_banner_info(banner))
    } else if banner_lower.contains("nginx") {
        extract_version_string(&banner_lower, "nginx")
            .map(|v| format!("nginx {}", v))
            .or_else(|| Some("nginx".to_string()))
    } else if banner_lower.contains("apache") {
        extract_version_string(&banner_lower, "apache")
            .map(|v| format!("Apache httpd {}", v))
            .or_else(|| Some("Apache httpd".to_string()))
    } else if banner_lower.contains("microsoft-iis") {
        extract_version_string(&banner_lower, "microsoft-iis")
            .map(|v| format!("Microsoft IIS {}", v))
            .or_else(|| Some("Microsoft IIS".to_string()))
    } else if banner_lower.contains("vsftpd") {
        extract_version_string(&banner_lower, "vsftpd")
            .map(|v| format!("vsftpd {}", v))
            .or_else(|| Some("vsftpd".to_string()))
    } else if banner_lower.contains("proftpd") {
        extract_version_string(&banner_lower, "proftpd")
            .map(|v| format!("ProFTPD {}", v))
            .or_else(|| Some("ProFTPD".to_string()))
    } else if banner_lower.contains("mysql") {
        extract_version_string(&banner_lower, "mysql")
            .map(|v| format!("MySQL {}", v))
            .or_else(|| Some("MySQL".to_string()))
    } else if banner_lower.contains("mariadb") {
        extract_version_string(&banner_lower, "mariadb")
            .map(|v| format!("MariaDB {}", v))
            .or_else(|| Some("MariaDB".to_string()))
    } else if banner_lower.contains("postgres") {
        extract_version_string(&banner_lower, "postgres")
            .map(|v| format!("PostgreSQL {}", v))
            .or_else(|| Some("PostgreSQL".to_string()))
    } else if banner_lower.contains("openssl") {
        extract_version_string(&banner_lower, "openssl")
            .map(|v| format!("OpenSSL {}", v))
            .or_else(|| Some("OpenSSL".to_string()))
    } else if banner_lower.contains("samba") || banner_lower.contains("smb") {
        Some("Samba".to_string())
    } else if banner_lower.contains("rdp") || port == 3389 {
        Some("RDP".to_string())
    } else if banner_lower.contains("smtp") || port == 25 || port == 587 {
        Some("SMTP".to_string())
    } else if banner_lower.contains("ftp") || port == 21 {
        Some("FTP".to_string())
    } else if banner_lower.contains("http") || port == 80 || port == 8080 {
        Some("HTTP".to_string())
    } else if port == 443 || port == 8443 {
        Some("HTTPS".to_string())
    } else {
        crate::types::get_service_name(port)
    };

    // OS fingerprint detection
    let os_fingerprint = if banner_lower.contains("ubuntu") {
        Some("Ubuntu".to_string())
    } else if banner_lower.contains("debian") {
        Some("Debian".to_string())
    } else if banner_lower.contains("centos") || banner_lower.contains("rhel") {
        Some("CentOS/RHEL".to_string())
    } else if banner_lower.contains("fedora") {
        Some("Fedora".to_string())
    } else if banner_lower.contains("windows") || banner_lower.contains("microsoft") {
        Some("Windows".to_string())
    } else if banner_lower.contains("freebsd") {
        Some("FreeBSD".to_string())
    } else if banner_lower.contains("alpine") {
        Some("Alpine Linux".to_string())
    } else if banner_lower.contains("raspbian") {
        Some("Raspbian".to_string())
    } else {
        None
    };

    (service, os_fingerprint)
}

/// Extract a version string following a keyword in the banner.
fn extract_version_string(banner_lower: &str, keyword: &str) -> Option<String> {
    let idx = banner_lower.find(keyword)?;
    let after = &banner_lower[idx + keyword.len()..];

    // Skip separators (space, slash, dash, underscore)
    let after = after.trim_start_matches(|c: char| c == ' ' || c == '/' || c == '-' || c == '_');

    // Extract version-like token (digits, dots, letters, hyphens)
    let version: String = after
        .chars()
        .take_while(|c| {
            c.is_ascii_digit() || *c == '.' || c.is_ascii_alphabetic() || *c == '-' || *c == '_'
        })
        .take(30) // Limit version string length
        .collect();

    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Extract information from an SSH banner.
///
/// SSH banners follow the format: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1`
fn extract_ssh_banner_info(banner: &str) -> String {
    // SSH-2.0-SoftwareVersion comments
    let parts: Vec<&str> = banner.splitn(3, '-').collect();
    if parts.len() >= 3 {
        let software = parts[2].trim();
        // Take the first meaningful token
        let first_token = software.split_whitespace().next().unwrap_or(software);
        first_token.to_string()
    } else {
        "SSH".to_string()
    }
}

/// Extract a version number from a banner string.
///
/// Looks for patterns like `X.Y.Z` or `X.Y` in the banner.
pub fn extract_version(banner: &str) -> Option<String> {
    // Look for version patterns: X.Y.Z, X.Y, X.YpZ
    let mut chars = banner.chars().peekable();
    let mut version_start = None;

    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let start_pos = banner.len() - chars.clone().count();
            version_start = Some(start_pos);

            let mut version = String::new();
            let mut has_dot = false;

            while let Some(&ch) = chars.peek() {
                if ch.is_ascii_digit() || ch == '.' || ch == 'p' || ch == '_' {
                    if ch == '.' {
                        has_dot = true;
                    }
                    version.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }

            if has_dot && version.len() >= 3 {
                return Some(version);
            }
        }
        chars.next();
    }

    // Fallback: try to find version after common keywords
    let banner_lower = banner.to_lowercase();
    for keyword in &["version", "ver", "v"] {
        if let Some(idx) = banner_lower.find(keyword) {
            let after = &banner[idx + keyword.len()..];
            let after = after.trim_start_matches(|c: char| !c.is_ascii_digit());
            let version: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == 'p' || *c == '_')
                .take(20)
                .collect();
            if !version.is_empty() && version.contains('.') {
                return Some(version);
            }
        }
    }

    let _ = version_start; // suppress unused warning
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_service_info_openssh() {
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
        let (service, os) = parse_service_info(banner, 22);
        assert!(service.unwrap().contains("OpenSSH"));
        assert_eq!(os, Some("Ubuntu".to_string()));
    }

    #[test]
    fn test_parse_service_info_nginx() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n";
        let (service, _) = parse_service_info(banner, 80);
        assert!(service.unwrap().contains("nginx"));
    }

    #[test]
    fn test_parse_service_info_apache() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\n";
        let (service, os) = parse_service_info(banner, 80);
        assert!(service.unwrap().contains("Apache"));
        assert_eq!(os, Some("Ubuntu".to_string()));
    }

    #[test]
    fn test_parse_service_info_iis() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n";
        let (service, os) = parse_service_info(banner, 80);
        assert!(service.unwrap().contains("IIS"));
        assert_eq!(os, Some("Windows".to_string()));
    }

    #[test]
    fn test_parse_service_info_mysql() {
        let banner = "5.7.42-log\0some binary data";
        let (service, _) = parse_service_info(banner, 3306);
        assert!(service.unwrap().contains("MySQL"));
    }

    #[test]
    fn test_parse_service_info_vsftpd() {
        let banner = "220 (vsFTPd 3.0.5)";
        let (service, _) = parse_service_info(banner, 21);
        assert!(service.unwrap().contains("vsftpd"));
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("OpenSSH_8.9p1"), Some("8.9p1".to_string()));
        assert_eq!(extract_version("nginx/1.24.0"), Some("1.24.0".to_string()));
        assert_eq!(extract_version("Apache/2.4.57"), Some("2.4.57".to_string()));
    }

    #[test]
    fn test_extract_version_string() {
        assert_eq!(
            extract_version_string("openssh_8.9p1 ubuntu", "openssh"),
            Some("8.9p1".to_string())
        );
        assert_eq!(
            extract_version_string("nginx/1.24.0", "nginx"),
            Some("1.24.0".to_string())
        );
    }

    #[test]
    fn test_get_probe_for_port() {
        let http_probe = get_probe_for_port(80, "192.168.1.1");
        assert!(http_probe.contains("HEAD / HTTP/1.0"));
        assert!(http_probe.contains("Host: 192.168.1.1"));

        let ssh_probe = get_probe_for_port(22, "192.168.1.1");
        assert!(ssh_probe.is_empty()); // SSH just reads
    }

    #[test]
    fn test_banner_result_serialization() {
        let result = BannerResult {
            ip: "192.168.1.1".to_string(),
            port: 22,
            banner: "SSH-2.0-OpenSSH_8.9p1".to_string(),
            service: Some("OpenSSH 8.9p1".to_string()),
            os_fingerprint: Some("Ubuntu".to_string()),
            timestamp: 1700000000,
            tls_info: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"ip\""));
        assert!(json.contains("\"osFingerprint\""));
    }

    #[test]
    fn test_banner_result_with_tls_info_none() {
        let result = BannerResult {
            ip: "192.168.1.1".to_string(),
            port: 80,
            banner: "HTTP/1.1 200 OK".to_string(),
            service: Some("HTTP".to_string()),
            os_fingerprint: None,
            timestamp: 1700000000,
            tls_info: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"tlsInfo\":null"));
    }

    #[test]
    fn test_banner_result_with_tls_info_some() {
        let tls_info = TlsInfo {
            version: "TLSv1.3".to_string(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
            issuer: "Let's Encrypt Authority X3".to_string(),
            subject: "example.com".to_string(),
            not_before: 1_700_000_000,
            not_after: 1_710_000_000,
            self_signed: false,
            san_domains: vec!["example.com".to_string()],
            expired: false,
            days_until_expiry: 115,
        };

        let result = BannerResult {
            ip: "192.168.1.1".to_string(),
            port: 443,
            banner: "HTTP/1.1 200 OK".to_string(),
            service: Some("HTTPS".to_string()),
            os_fingerprint: None,
            timestamp: 1700000000,
            tls_info: Some(tls_info),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"tlsInfo\":{"));
        assert!(json.contains("\"cipherSuite\""));
        assert!(json.contains("TLS_AES_256_GCM_SHA384"));
        assert!(json.contains("\"selfSigned\":false"));
    }

    #[test]
    fn test_parse_service_info_unknown() {
        let banner = "some random data";
        let (service, os) = parse_service_info(banner, 9999);
        assert!(service.is_none());
        assert!(os.is_none());
    }

    #[test]
    fn test_os_fingerprint_detection() {
        let (_, os) = parse_service_info("Debian GNU/Linux", 80);
        assert_eq!(os, Some("Debian".to_string()));

        let (_, os) = parse_service_info("CentOS Linux release 7.9", 80);
        assert_eq!(os, Some("CentOS/RHEL".to_string()));

        let (_, os) = parse_service_info("FreeBSD 13.2", 80);
        assert_eq!(os, Some("FreeBSD".to_string()));
    }
}
