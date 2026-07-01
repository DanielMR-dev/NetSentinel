use serde::{Deserialize, Serialize};

use crate::network::banner::BannerResult;
use crate::network::cve::{CveMatch, CveSeverity};
use crate::network::tls::TlsInfo;
use crate::reporting::compliance::ComplianceIssue;

/// Source subsystem that produced a finding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    Cve,
    ActiveCheck,
    WebAudit,
}

/// Logical category for a finding, used for grouping and reporting.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    #[default]
    Cve,
    Web,
    ActiveCheck,
    Tls,
    Compliance,
    Traffic,
    Exposure,
}

/// Normalized finding severity used across CVE, active check, and web audit results.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Confidence level for a normalized finding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    Confirmed,
    High,
    Medium,
    Low,
}

/// CVE-specific details attached to normalized findings.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CveFindingDetails {
    pub cve_id: String,
    pub affected_software: String,
    pub affected_versions: Vec<String>,
    pub cvss_score: f64,
}

/// Unified security finding attached to a device.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    #[serde(default)]
    pub scan_id: String,
    pub source: FindingSource,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub title: String,
    pub description: String,
    pub ip: String,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub evidence: Option<String>,
    pub cve: Option<CveFindingDetails>,
    pub timestamp: i64,
    #[serde(default)]
    pub category: FindingCategory,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub epss_probability: Option<f64>,
    #[serde(default)]
    pub remediation: Option<String>,
}

impl Finding {
    pub fn from_cve(cve: &CveMatch) -> Self {
        Self {
            id: stable_finding_id(&[
                "cve",
                &cve.ip,
                &cve.port.to_string(),
                &cve.cve_id.to_lowercase(),
            ]),
            scan_id: String::new(),
            source: FindingSource::Cve,
            severity: FindingSeverity::from(&cve.severity),
            confidence: FindingConfidence::Medium,
            title: cve.cve_id.clone(),
            description: cve.description.clone(),
            ip: cve.ip.clone(),
            port: Some(cve.port),
            service: Some(cve.affected_software.clone()),
            evidence: Some(format!("CVSS {:.1}", cve.cvss_score)),
            cve: Some(CveFindingDetails {
                cve_id: cve.cve_id.clone(),
                affected_software: cve.affected_software.clone(),
                affected_versions: cve.affected_versions.clone(),
                cvss_score: cve.cvss_score,
            }),
            timestamp: chrono::Utc::now().timestamp(),
            category: FindingCategory::Cve,
            cvss_score: Some(cve.cvss_score),
            epss_probability: None,
            remediation: Some("Update affected software to a patched version.".to_string()),
        }
    }

    pub fn from_active_check(
        ip: &str,
        check: &crate::network::active_checks::ActiveCheckResult,
    ) -> Option<Self> {
        if !check.is_vulnerable {
            return None;
        }

        Some(Self {
            id: stable_finding_id(&["active", ip, &check.vulnerability_name.to_lowercase()]),
            scan_id: String::new(),
            source: FindingSource::ActiveCheck,
            severity: FindingSeverity::High,
            confidence: FindingConfidence::Confirmed,
            title: check.vulnerability_name.clone(),
            description: check
                .details
                .clone()
                .unwrap_or_else(|| "Active check confirmed vulnerable behavior".to_string()),
            ip: ip.to_string(),
            port: None,
            service: None,
            evidence: check.details.clone(),
            cve: None,
            timestamp: chrono::Utc::now().timestamp(),
            category: FindingCategory::ActiveCheck,
            cvss_score: None,
            epss_probability: None,
            remediation: Some("Remediate per active check guidance.".to_string()),
        })
    }

    pub fn from_web_audit(audit: &crate::network::web_audit::WebAuditResult) -> Vec<Self> {
        let (ip, port) = parse_web_audit_target(&audit.url);
        let mut findings = Vec::new();

        if !audit.exposed_directories.is_empty() {
            findings.push(Self {
                id: stable_finding_id(&[
                    "web",
                    &ip,
                    &port.map(|p| p.to_string()).unwrap_or_default(),
                    "exposed-directories",
                    &audit.exposed_directories.join("|").to_lowercase(),
                ]),
                scan_id: String::new(),
                source: FindingSource::WebAudit,
                severity: FindingSeverity::Medium,
                confidence: FindingConfidence::High,
                title: "Exposed web paths".to_string(),
                description: "Sensitive web paths responded successfully during audit".to_string(),
                ip: ip.clone(),
                port,
                service: Some("http".to_string()),
                evidence: Some(audit.exposed_directories.join(", ")),
                cve: None,
                timestamp: chrono::Utc::now().timestamp(),
                category: FindingCategory::Web,
                cvss_score: None,
                epss_probability: None,
                remediation: Some(
                    "Restrict exposed paths / remove identifying headers.".to_string(),
                ),
            });
        }

        if let Some(powered_by) = audit.powered_by_header.as_ref() {
            findings.push(Self {
                id: stable_finding_id(&[
                    "web",
                    &ip,
                    &port.map(|p| p.to_string()).unwrap_or_default(),
                    "x-powered-by",
                    &powered_by.to_lowercase(),
                ]),
                scan_id: String::new(),
                source: FindingSource::WebAudit,
                severity: FindingSeverity::Low,
                confidence: FindingConfidence::High,
                title: "Technology disclosure".to_string(),
                description: "Web service exposes an X-Powered-By header".to_string(),
                ip,
                port,
                service: Some("http".to_string()),
                evidence: Some(powered_by.clone()),
                cve: None,
                timestamp: chrono::Utc::now().timestamp(),
                category: FindingCategory::Web,
                cvss_score: None,
                epss_probability: None,
                remediation: Some(
                    "Restrict exposed paths / remove identifying headers.".to_string(),
                ),
            });
        }

        findings
    }

    pub fn from_tls(ip: &str, port: u16, tls: &TlsInfo) -> Vec<Self> {
        let mut findings = Vec::new();
        let not_after_text = chrono::DateTime::from_timestamp(tls.not_after, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| tls.not_after.to_string());

        if tls.expired {
            let title = "Expired TLS certificate".to_string();
            findings.push(Self {
                id: stable_finding_id(&["tls", ip, &port.to_string(), &title.to_lowercase()]),
                scan_id: String::new(),
                source: FindingSource::WebAudit,
                severity: FindingSeverity::Critical,
                confidence: FindingConfidence::Confirmed,
                title,
                description: "The TLS certificate has expired.".to_string(),
                ip: ip.to_string(),
                port: Some(port),
                service: Some("tls".to_string()),
                evidence: Some(format!(
                    "Issuer: {}; Subject: {}; Not After: {}; Version: {}",
                    tls.issuer, tls.subject, not_after_text, tls.version
                )),
                cve: None,
                timestamp: chrono::Utc::now().timestamp(),
                category: FindingCategory::Tls,
                cvss_score: None,
                epss_probability: None,
                remediation: Some(
                    "Renew or remove the expired certificate immediately.".to_string(),
                ),
            });
        }

        if tls.self_signed && !tls.expired {
            let title = "Self-signed TLS certificate".to_string();
            findings.push(Self {
                id: stable_finding_id(&["tls", ip, &port.to_string(), &title.to_lowercase()]),
                scan_id: String::new(),
                source: FindingSource::WebAudit,
                severity: FindingSeverity::High,
                confidence: FindingConfidence::Confirmed,
                title,
                description: "The TLS certificate is self-signed.".to_string(),
                ip: ip.to_string(),
                port: Some(port),
                service: Some("tls".to_string()),
                evidence: Some(format!(
                    "Issuer: {}; Subject: {}; Not After: {}; Version: {}",
                    tls.issuer, tls.subject, not_after_text, tls.version
                )),
                cve: None,
                timestamp: chrono::Utc::now().timestamp(),
                category: FindingCategory::Tls,
                cvss_score: None,
                epss_probability: None,
                remediation: Some(
                    "Replace self-signed certificate with one issued by a trusted CA.".to_string(),
                ),
            });
        }

        if tls.version != "Unknown"
            && (tls.version.contains("TLSv1.0") || tls.version.contains("TLSv1.1"))
        {
            let title = "Weak TLS protocol version".to_string();
            findings.push(Self {
                id: stable_finding_id(&["tls", ip, &port.to_string(), &title.to_lowercase()]),
                scan_id: String::new(),
                source: FindingSource::WebAudit,
                severity: FindingSeverity::Medium,
                confidence: FindingConfidence::Confirmed,
                title,
                description: "The service negotiates a deprecated TLS version.".to_string(),
                ip: ip.to_string(),
                port: Some(port),
                service: Some("tls".to_string()),
                evidence: Some(format!(
                    "Issuer: {}; Subject: {}; Not After: {}; Version: {}",
                    tls.issuer, tls.subject, not_after_text, tls.version
                )),
                cve: None,
                timestamp: chrono::Utc::now().timestamp(),
                category: FindingCategory::Tls,
                cvss_score: None,
                epss_probability: None,
                remediation: Some("Disable TLSv1.0/1.1 and enforce TLSv1.2+.".to_string()),
            });
        }

        if !tls.expired && tls.days_until_expiry > 0 && tls.days_until_expiry < 30 {
            let title = "TLS certificate expiring soon".to_string();
            findings.push(Self {
                id: stable_finding_id(&["tls", ip, &port.to_string(), &title.to_lowercase()]),
                scan_id: String::new(),
                source: FindingSource::WebAudit,
                severity: FindingSeverity::Low,
                confidence: FindingConfidence::Confirmed,
                title,
                description: format!(
                    "The TLS certificate expires in {} days.",
                    tls.days_until_expiry
                ),
                ip: ip.to_string(),
                port: Some(port),
                service: Some("tls".to_string()),
                evidence: Some(format!(
                    "Issuer: {}; Subject: {}; Not After: {}; Version: {}",
                    tls.issuer, tls.subject, not_after_text, tls.version
                )),
                cve: None,
                timestamp: chrono::Utc::now().timestamp(),
                category: FindingCategory::Tls,
                cvss_score: None,
                epss_probability: None,
                remediation: Some("Renew the certificate before it expires.".to_string()),
            });
        }

        findings
    }

    pub fn from_compliance(ip: &str, issue: &ComplianceIssue) -> Self {
        let severity =
            crate::reporting::compliance::compliance_severity_to_finding(&issue.severity);
        Self {
            id: stable_finding_id(&[
                "compliance",
                ip,
                &issue.framework.to_lowercase(),
                &issue.rule.to_lowercase(),
            ]),
            scan_id: String::new(),
            source: FindingSource::ActiveCheck,
            severity,
            confidence: FindingConfidence::High,
            title: format!("{}: {}", issue.framework, issue.rule),
            description: issue.description.clone(),
            ip: ip.to_string(),
            port: issue.port,
            service: None,
            evidence: None,
            cve: None,
            timestamp: chrono::Utc::now().timestamp(),
            category: FindingCategory::Compliance,
            cvss_score: None,
            epss_probability: None,
            remediation: Some(format!("{} — review and remediate.", issue.rule)),
        }
    }

    pub fn with_scan_id(mut self, scan_id: impl Into<String>) -> Self {
        self.scan_id = scan_id.into();
        self
    }
}

impl From<&CveSeverity> for FindingSeverity {
    fn from(value: &CveSeverity) -> Self {
        match value {
            CveSeverity::Critical => FindingSeverity::Critical,
            CveSeverity::High => FindingSeverity::High,
            CveSeverity::Medium => FindingSeverity::Medium,
            CveSeverity::Low => FindingSeverity::Low,
        }
    }
}

pub(crate) fn stable_finding_id(parts: &[&str]) -> String {
    let joined = parts
        .iter()
        .map(|part| {
            part.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .trim_matches('-')
                .to_string()
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(":");

    if joined.is_empty() {
        "finding:unknown".to_string()
    } else {
        joined
    }
}

fn parse_web_audit_target(url: &str) -> (String, Option<u16>) {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);

    if let Some((host, port)) = authority.rsplit_once(':') {
        return (host.to_string(), port.parse::<u16>().ok());
    }

    (authority.to_string(), None)
}

/// Scan type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    /// Standard TCP Connect scan (no special privileges needed)
    Connect,
    /// Stealth SYN scan (requires raw socket privileges)
    Syn,
    /// TCP FIN scan
    Fin,
    /// TCP XMAS scan
    Xmas,
    /// TCP NULL scan
    Null,
    /// UDP port scan (no special privileges needed for basic, raw socket for full)
    Udp,
    /// SCTP INIT scan
    Sctp,
}

impl Default for ScanType {
    fn default() -> Self {
        ScanType::Connect
    }
}

impl ScanType {
    /// Return all scan types available in the UI.
    pub fn all_types() -> &'static [ScanType] {
        &[
            ScanType::Connect,
            ScanType::Syn,
            ScanType::Fin,
            ScanType::Xmas,
            ScanType::Null,
            ScanType::Udp,
            ScanType::Sctp,
        ]
    }
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Connect => write!(f, "Connect"),
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Fin => write!(f, "FIN"),
            ScanType::Xmas => write!(f, "XMAS"),
            ScanType::Null => write!(f, "NULL"),
            ScanType::Udp => write!(f, "UDP"),
            ScanType::Sctp => write!(f, "SCTP"),
        }
    }
}

/// Log level enumeration for scan logging
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

/// Event emitted for frontend scan logging
#[derive(Serialize, Clone)]
pub struct ScanLogEvent {
    pub level: String,
    pub message: String,
    pub target: Option<String>,
    pub timestamp: i64,
}

/// Event emitted when scan starts
#[derive(Serialize, Clone)]
pub struct ScanStartedEvent {
    pub scan_id: String,
    pub target_cidr: String,
    pub total_hosts: u32,
    pub timestamp: i64,
}

/// Discovery method used to find a device
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DiscoveryMethod {
    ArpTable,
    TcpProbe,
    Unknown,
}

/// Device status enumeration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DeviceStatus {
    Online,
    Offline,
    Unknown,
}

/// Port state enumeration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Network port representation
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub state: PortState,
}

/// Discovered network device
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<String>,
    pub status: DeviceStatus,
    pub ports: Vec<Port>,
    pub last_seen: i64,
    /// Banner grab results for this device
    pub banner_results: Vec<BannerResult>,
    /// Active critical vulnerability checks for this device
    pub active_checks: Vec<crate::network::active_checks::ActiveCheckResult>,
    /// Web auditing results for HTTP/HTTPS services found on this device
    pub web_audits: Vec<crate::network::web_audit::WebAuditResult>,
    /// Unified security findings for this device
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl Device {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            mac: String::new(),
            hostname: None,
            vendor: None,
            os: None,
            status: DeviceStatus::Unknown,
            ports: Vec::new(),
            last_seen: chrono::Utc::now().timestamp(),
            banner_results: Vec::new(),
            active_checks: Vec::new(),
            web_audits: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn with_mac(mut self, mac: String) -> Self {
        self.mac = mac;
        self
    }

    pub fn with_hostname(mut self, hostname: Option<String>) -> Self {
        self.hostname = hostname;
        self
    }

    pub fn with_vendor(mut self, vendor: Option<String>) -> Self {
        self.vendor = vendor;
        self
    }

    pub fn with_os(mut self, os: Option<String>) -> Self {
        self.os = os;
        self
    }

    pub fn with_status(mut self, status: DeviceStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_ports(mut self, ports: Vec<Port>) -> Self {
        self.ports = ports;
        self
    }
}

#[cfg(test)]
mod finding_tests {
    use super::*;

    #[test]
    fn cve_constructor_uses_deterministic_id_and_severity() {
        let cve = CveMatch {
            cve_id: "CVE-2026-0001".to_string(),
            severity: CveSeverity::Critical,
            description: "Example issue".to_string(),
            affected_software: "OpenSSH".to_string(),
            affected_versions: vec!["< 9.0".to_string()],
            cvss_score: 9.8,
            ip: "192.0.2.10".to_string(),
            port: 22,
        };

        let finding = Finding::from_cve(&cve);

        assert_eq!(finding.id, "cve:192-0-2-10:22:cve-2026-0001");
        assert_eq!(finding.severity, FindingSeverity::Critical);
        assert_eq!(
            finding.cve.as_ref().map(|d| d.cve_id.as_str()),
            Some("CVE-2026-0001")
        );
    }

    #[test]
    fn device_json_without_findings_defaults_to_empty_vec() {
        let json = r#"{
            "ip":"192.0.2.20",
            "mac":"",
            "hostname":null,
            "vendor":null,
            "os":null,
            "status":"Unknown",
            "ports":[],
            "last_seen":0,
            "banner_results":[],
            "active_checks":[],
            "web_audits":[]
        }"#;

        let device_result: Result<Device, _> = serde_json::from_str(json);
        assert!(device_result.is_ok());
        let device = match device_result {
            Ok(device) => device,
            Err(_) => return,
        };

        assert!(device.findings.is_empty());
    }
}

/// Classification of a topology node for rendering and analysis.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum NodeKind {
    Unknown,
    LocalHost,
    Gateway,
    Router,
    Server,
    Endpoint,
    Peripheral,
    Virtual,
}

impl Default for NodeKind {
    fn default() -> Self {
        NodeKind::Unknown
    }
}

/// Classification of a topology edge for rendering and analysis.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum EdgeKind {
    Unknown,
    GatewayLink,
    DirectLink,
    Inferred,
}

impl Default for EdgeKind {
    fn default() -> Self {
        EdgeKind::Unknown
    }
}

/// Source of topology information.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum TopologySource {
    Discovery,
    ArpTable,
    NetworkInfo,
    FlowObserved,
    Inferred,
}

impl Default for TopologySource {
    fn default() -> Self {
        TopologySource::Inferred
    }
}

/// A single node in the topology graph.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TopologyNode {
    /// Stable node identifier (typically the device IP).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Classified node kind.
    pub kind: NodeKind,
    /// Source subsystem that produced this node.
    pub source: TopologySource,
    /// Underlying device data, if available.
    pub device: Option<Device>,
    /// Optional grouping/hierarchy identifier.
    pub group: Option<String>,
}

/// A single edge in the topology graph.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TopologyEdge {
    /// Source node identifier.
    pub source: String,
    /// Target node identifier.
    pub target: String,
    /// Classified edge kind.
    pub kind: EdgeKind,
}

/// A graph representation of the discovered network topology.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct TopologyGraph {
    /// Nodes in the topology.
    pub nodes: Vec<TopologyNode>,
    /// Edges connecting nodes.
    pub edges: Vec<TopologyEdge>,
    /// Timestamp when the graph was generated.
    pub generated_at: i64,
}

impl TopologyGraph {
    /// Create an empty topology graph.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            generated_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Add a node to the graph if it does not already exist.
    pub fn add_node(&mut self, node: TopologyNode) {
        if !self.nodes.iter().any(|n| n.id == node.id) {
            self.nodes.push(node);
        }
    }

    /// Add an edge to the graph if it does not already exist.
    pub fn add_edge(&mut self, edge: TopologyEdge) {
        if !self
            .edges
            .iter()
            .any(|e| e.source == edge.source && e.target == edge.target && e.kind == edge.kind)
        {
            self.edges.push(edge);
        }
    }
}

/// Scan response when starting a scan
#[derive(Serialize, Deserialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub status: String,
    /// The scan type being used
    pub scan_type: ScanType,
}

/// Scan results containing discovered devices
#[derive(Serialize, Deserialize)]
pub struct ScanResultsResponse {
    pub devices: Vec<Device>,
    pub scanned_count: u32,
    pub total_hosts: u32,
}

/// Event emitted when a device is found
#[derive(Serialize, Clone)]
pub struct DeviceFoundEvent {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<String>,
    pub timestamp: i64,
    pub ports: Vec<Port>,
    pub discovery_method: String,
    /// Banner grab results for this device
    pub banner_results: Vec<BannerResult>,
}

/// Estimate operating system based on received packet's TTL value.
///
/// Typical ranges:
/// - ~64 (0-64) -> Linux/Android
/// - ~128 (65-128) -> Windows
/// - ~255 (129-255) -> Network Equipment/Others
pub fn estimate_os_by_ttl(ttl: u8) -> Option<String> {
    match ttl {
        0..=64 => Some("Linux/Android".to_string()),
        65..=128 => Some("Windows".to_string()),
        129..=255 => Some("Network Device".to_string()),
    }
}

/// Event emitted during scan progress
#[derive(Serialize, Clone)]
pub struct ScanProgressEvent {
    pub scanned: u32,
    pub total: u32,
    pub current_target: String,
    pub devices_found: u32,
}

/// Event emitted when scan completes
#[derive(Serialize, Clone)]
pub struct ScanCompleteEvent {
    pub scan_id: String,
    pub device_count: u32,
    pub duration_ms: u64,
    pub status: String,
}

/// Map port number to known service name
pub fn get_service_name(port: u16) -> Option<String> {
    match port {
        // TCP services
        20 => Some("FTP-DATA".to_string()),
        21 => Some("FTP".to_string()),
        22 => Some("SSH".to_string()),
        23 => Some("TELNET".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        80 => Some("HTTP".to_string()),
        110 => Some("POP3".to_string()),
        143 => Some("IMAP".to_string()),
        443 => Some("HTTPS".to_string()),
        445 => Some("SMB".to_string()),
        993 => Some("IMAPS".to_string()),
        995 => Some("POP3S".to_string()),
        3306 => Some("MySQL".to_string()),
        3389 => Some("RDP".to_string()),
        5432 => Some("PostgreSQL".to_string()),
        5900 => Some("VNC".to_string()),
        6379 => Some("Redis".to_string()),
        8080 => Some("HTTP-ALT".to_string()),
        8443 => Some("HTTPS-ALT".to_string()),
        // UDP-specific services
        67 => Some("DHCP".to_string()),
        68 => Some("DHCP".to_string()),
        69 => Some("TFTP".to_string()),
        123 => Some("NTP".to_string()),
        161 => Some("SNMP".to_string()),
        162 => Some("SNMP-TRAP".to_string()),
        500 => Some("IKE".to_string()),
        514 => Some("Syslog".to_string()),
        1900 => Some("SSDP".to_string()),
        5353 => Some("mDNS".to_string()),
        5355 => Some("LLMNR".to_string()),
        4789 => Some("VXLAN".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_os_by_ttl() {
        assert_eq!(estimate_os_by_ttl(64), Some("Linux/Android".to_string()));
        assert_eq!(estimate_os_by_ttl(45), Some("Linux/Android".to_string()));
        assert_eq!(estimate_os_by_ttl(128), Some("Windows".to_string()));
        assert_eq!(estimate_os_by_ttl(100), Some("Windows".to_string()));
        assert_eq!(estimate_os_by_ttl(255), Some("Network Device".to_string()));
        assert_eq!(estimate_os_by_ttl(150), Some("Network Device".to_string()));
    }

    #[test]
    fn test_scan_type_udp_serialization() {
        let scan_type = ScanType::Udp;
        let json = serde_json::to_string(&scan_type).unwrap();
        assert_eq!(json, "\"udp\"");

        let deserialized: ScanType = serde_json::from_str("\"udp\"").unwrap();
        assert_eq!(deserialized, ScanType::Udp);
    }

    #[test]
    fn test_scan_type_all_variants_serialization() {
        // Connect
        let json = serde_json::to_string(&ScanType::Connect).unwrap();
        assert_eq!(json, "\"connect\"");

        // Syn
        let json = serde_json::to_string(&ScanType::Syn).unwrap();
        assert_eq!(json, "\"syn\"");

        // Fin
        let json = serde_json::to_string(&ScanType::Fin).unwrap();
        assert_eq!(json, "\"fin\"");

        // Xmas
        let json = serde_json::to_string(&ScanType::Xmas).unwrap();
        assert_eq!(json, "\"xmas\"");

        // Null
        let json = serde_json::to_string(&ScanType::Null).unwrap();
        assert_eq!(json, "\"null\"");

        // Udp
        let json = serde_json::to_string(&ScanType::Udp).unwrap();
        assert_eq!(json, "\"udp\"");

        // Sctp
        let json = serde_json::to_string(&ScanType::Sctp).unwrap();
        assert_eq!(json, "\"sctp\"");
    }

    #[test]
    fn test_scan_type_default_is_connect() {
        assert_eq!(ScanType::default(), ScanType::Connect);
    }

    #[test]
    fn test_get_service_name_tcp_services() {
        assert_eq!(get_service_name(22), Some("SSH".to_string()));
        assert_eq!(get_service_name(80), Some("HTTP".to_string()));
        assert_eq!(get_service_name(443), Some("HTTPS".to_string()));
        assert_eq!(get_service_name(3389), Some("RDP".to_string()));
    }

    #[test]
    fn test_get_service_name_udp_services() {
        assert_eq!(get_service_name(53), Some("DNS".to_string()));
        assert_eq!(get_service_name(67), Some("DHCP".to_string()));
        assert_eq!(get_service_name(68), Some("DHCP".to_string()));
        assert_eq!(get_service_name(69), Some("TFTP".to_string()));
        assert_eq!(get_service_name(123), Some("NTP".to_string()));
        assert_eq!(get_service_name(161), Some("SNMP".to_string()));
        assert_eq!(get_service_name(162), Some("SNMP-TRAP".to_string()));
        assert_eq!(get_service_name(500), Some("IKE".to_string()));
        assert_eq!(get_service_name(514), Some("Syslog".to_string()));
        assert_eq!(get_service_name(1900), Some("SSDP".to_string()));
        assert_eq!(get_service_name(5353), Some("mDNS".to_string()));
        assert_eq!(get_service_name(5355), Some("LLMNR".to_string()));
        assert_eq!(get_service_name(4789), Some("VXLAN".to_string()));
    }

    #[test]
    fn test_get_service_name_unknown_port() {
        assert_eq!(get_service_name(9999), None);
        assert_eq!(get_service_name(31337), None);
    }
}
