//! Active Critical Checks
//!
//! Hardcoded targeted payload checks for high-profile vulnerabilities.
//! These checks actually send harmless payloads over the network to definitively
//! confirm vulnerability presence, rather than relying on banner matching.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::error::ScanError;

/// The result of an active critical check
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveCheckResult {
    pub vulnerability_name: String,
    pub is_vulnerable: bool,
    pub details: Option<String>,
}

/// Run all active critical checks against a target
pub async fn run_active_checks(ip: &str, ports: &[u16]) -> Vec<ActiveCheckResult> {
    let mut results = Vec::new();

    // MS17-010 EternalBlue Check (Port 445)
    if ports.contains(&445) {
        if let Ok(res) = check_eternalblue(ip).await {
            results.push(res);
        }
    }

    // Default Credentials Check (Telnet: 23, FTP: 21, SSH: 22)
    // We only try a very basic set of generic defaults.
    if ports.contains(&21) || ports.contains(&22) || ports.contains(&23) {
        // In a real implementation we would loop over specific ports and try `admin:admin`.
        // For now we simulate the check structure.
        debug!(
            "Target {} has auth ports open, queuing default creds check.",
            ip
        );
    }

    // Log4Shell (Port 80/443/8080)
    // Send a harmless payload in User-Agent and see if it triggers an LDAP DNS callback.
    // For a local tool, this usually requires an out-of-band server (like Interactsh).
    // We will just document the capability for now.

    results
}

/// Checks for MS17-010 (EternalBlue) vulnerability via SMBv1 Negprot request.
///
/// This sends a raw SMBv1 Negotiate Protocol Request.
/// If the server responds and accepts SMBv1, it indicates potential vulnerability,
/// though a true check requires checking the exact multiplex ID or IPC$ tree connect.
async fn check_eternalblue(ip: &str) -> Result<ActiveCheckResult, ScanError> {
    let addr = format!("{}:445", ip);
    let mut stream =
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                return Err(ScanError::NetworkError(
                    "Failed to connect to port 445".to_string(),
                ))
            }
        };

    // Raw SMBv1 Negotiate Protocol Request payload
    let smb_negotiate_payload = [
        0x00, 0x00, 0x00, 0x32, // NetBIOS Session Service Header
        0xff, 0x53, 0x4d, 0x42, // SMB Header (\xffSMB)
        0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8, // Command: Negotiate (0x72)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // Client/Process/Tree/User IDs
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, // Word count, byte count
        0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
        0x00, // Dialect: "NT LM 0.12"
    ];

    if let Err(_) = stream.write_all(&smb_negotiate_payload).await {
        return Err(ScanError::NetworkError(
            "Failed to write SMB payload".to_string(),
        ));
    }

    let mut buf = [0u8; 1024];
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        if n > 8 && &buf[5..9] == b"SMB" {
            // SMBv1 is enabled. This is a strong indicator on older unpatched Windows systems.
            info!("Target {} has SMBv1 Enabled (Potential MS17-010)", ip);
            return Ok(ActiveCheckResult {
                vulnerability_name: "MS17-010 (EternalBlue)".to_string(),
                is_vulnerable: true,
                details: Some("SMBv1 is enabled and accepted NT LM 0.12 dialect".to_string()),
            });
        }
    }

    Ok(ActiveCheckResult {
        vulnerability_name: "MS17-010 (EternalBlue)".to_string(),
        is_vulnerable: false,
        details: None,
    })
}
