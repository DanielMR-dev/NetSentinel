use serde::{Deserialize, Serialize};

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
    pub status: DeviceStatus,
    pub ports: Vec<Port>,
    pub last_seen: i64,
}

impl Device {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            mac: String::new(),
            hostname: None,
            status: DeviceStatus::Unknown,
            ports: Vec::new(),
            last_seen: chrono::Utc::now().timestamp(),
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
    pub timestamp: i64,
    pub ports: Vec<Port>,
    pub discovery_method: String,
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
        _ => None,
    }
}