use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug, Serialize)]
pub enum ScanError {
    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Scan cancelled")]
    Cancelled,

    #[error("Scan not running")]
    NotRunning,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid port range: {0}")]
    InvalidPort(String),

    #[error("Settings error: {0}")]
    SettingsError(String),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("History error: {0}")]
    HistoryError(String),

    #[error("Timeout")]
    Timeout,

    #[error("Baseline error: {0}")]
    BaselineError(String),

    #[error("CVE error: {0}")]
    CveError(String),

    #[error("Event error: {0}")]
    EventError(String),
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::NetworkError(err.to_string())
    }
}