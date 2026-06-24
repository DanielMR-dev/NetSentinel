use serde::Serialize;
use thiserror::Error;

/// Project-wide error type for NetSentinel.
///
/// All fallible operations in the backend return `Result<T, ScanError>`.
/// The enum is intentionally `Clone` and `PartialEq` so it can be stored in
/// UI state, compared in tests, and propagated across async boundaries.
#[derive(Error, Debug, Serialize, Clone, PartialEq)]
pub enum ScanError {
    // ── Input / validation errors ───────────────────────────────────────────
    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid port range: {0}")]
    InvalidPort(String),

    #[error("Invalid identifier: {0}")]
    InvalidId(String),

    #[error("Invalid timeout: {0}")]
    InvalidTimeout(String),

    // ── Network errors ──────────────────────────────────────────────────────
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Socket bind failed: {0}")]
    SocketBind(String),

    #[error("Raw socket error: {0}")]
    RawSocketError(String),

    #[error("Packet construction error: {0}")]
    PacketError(String),

    #[error("Datalink channel error: {0}")]
    DatalinkError(String),

    #[error("No network interface found for IP: {0}")]
    NoInterfaceForIp(String),

    #[error("Failed to resolve gateway MAC address: {0}")]
    GatewayMacResolution(String),

    #[error("Connection timeout: {0}")]
    ConnectionTimeout(String),

    #[error("Timeout")]
    Timeout,

    // ── Permission / privilege errors ───────────────────────────────────────
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Elevated privileges required: {0}")]
    ElevatedPrivilegesRequired(String),

    // ── Scan lifecycle errors ───────────────────────────────────────────────
    #[error("Scan cancelled")]
    Cancelled,

    #[error("Scan not running")]
    NotRunning,

    #[error("Scan already running")]
    AlreadyRunning,

    #[error("Invalid scan state: {0}")]
    InvalidScanState(String),

    // ── Storage / persistence errors ────────────────────────────────────────
    #[error("Settings error: {0}")]
    SettingsError(String),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("History error: {0}")]
    HistoryError(String),

    #[error("Baseline error: {0}")]
    BaselineError(String),

    #[error("Baseline not found: {0}")]
    BaselineNotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    // ── CVE / event errors ──────────────────────────────────────────────────
    #[error("CVE error: {0}")]
    CveError(String),

    #[error("Event error: {0}")]
    EventError(String),

    // ── Catch-all internal error ────────────────────────────────────────────
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::PermissionDenied => ScanError::PermissionDenied(err.to_string()),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                ScanError::ConnectionTimeout(err.to_string())
            }
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable => {
                ScanError::SocketBind(err.to_string())
            }
            _ => ScanError::NetworkError(err.to_string()),
        }
    }
}

impl From<serde_json::Error> for ScanError {
    fn from(err: serde_json::Error) -> Self {
        if err.is_data() || err.is_eof() || err.is_syntax() {
            ScanError::DeserializationError(err.to_string())
        } else {
            ScanError::SerializationError(err.to_string())
        }
    }
}

impl From<rusqlite::Error> for ScanError {
    fn from(err: rusqlite::Error) -> Self {
        ScanError::BaselineError(err.to_string())
    }
}

impl From<bincode::Error> for ScanError {
    fn from(err: bincode::Error) -> Self {
        ScanError::DeserializationError(err.to_string())
    }
}
