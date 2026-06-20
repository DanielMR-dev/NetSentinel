use serde::{Deserialize, Serialize};

use crate::network::banner::BannerResult;

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