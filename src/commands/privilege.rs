//! Privilege status Tauri command.
//!
//! Provides an IPC endpoint for checking the current process's
//! privilege status and available scanning capabilities.

use crate::error::ScanError;
use crate::network::privileges::{self, PrivilegeStatus};

/// Check the current process's privilege status.
///
/// Returns a comprehensive report of available capabilities including
/// raw socket access, CAP_NET_RAW, SYN scan availability, and ICMP
/// availability.
#[tauri::command]
pub async fn check_privilege_status() -> Result<PrivilegeStatus, ScanError> {
    // Privilege checks involve file I/O and process spawning,
    // so we use spawn_blocking to avoid blocking the async runtime.
    let status = tokio::task::spawn_blocking(privileges::check_system_privileges)
        .await
        .map_err(|e| {
            ScanError::NetworkError(format!("Privilege check task failed: {}", e))
        })?;

    Ok(status)
}
