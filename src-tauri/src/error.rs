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

    #[error("Invalid port range: {0}")]
    InvalidPort(String),
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::NetworkError(err.to_string())
    }
}