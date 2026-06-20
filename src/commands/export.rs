//! Export commands for audit reports.
//!
//! Provides `export_audit_report` for exporting scan results in CSV or JSON
//! format using a native file dialog.

use std::path::PathBuf;
use crate::error::ScanError;
use crate::types::Device;

/// Helper function to convert Vec<Device> to a CSV string.
fn devices_to_csv(devices: &[Device]) -> String {
    let mut csv = String::new();
    // Header
    csv.push_str("IP,MAC,Hostname,Vendor,OS,Status,Open Ports,Vulnerabilities\n");
    for dev in devices {
        // Escape helper for CSV values to ensure commas don't break columns
        let escape = |s: &str| -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };

        let ip = escape(&dev.ip);
        let mac = escape(&dev.mac);
        let hostname = escape(dev.hostname.as_deref().unwrap_or(""));
        let vendor = escape(dev.vendor.as_deref().unwrap_or(""));
        let os = escape(dev.os.as_deref().unwrap_or(""));
        let status = format!("{:?}", dev.status);

        // Format open ports, e.g. "80/tcp(http); 443/tcp(https)"
        let mut port_strings = Vec::new();
        for port in &dev.ports {
            if port.state == crate::types::PortState::Open {
                let service = port.service.as_deref().unwrap_or("unknown");
                port_strings.push(format!("{}/{}({})", port.number, port.protocol, service));
            }
        }
        let ports_str = escape(&port_strings.join("; "));

        // Format vulnerabilities
        let mut cve_ids = Vec::new();
        for banner in &dev.banner_results {
            let cves = crate::network::cve::lookup_cves(banner);
            for cve in cves {
                cve_ids.push(format!("{} ({:?})", cve.cve_id, cve.severity));
            }
        }
        let cves_str = escape(&cve_ids.join("; "));

        csv.push_str(&format!("{},{},{},{},{},{},{},{}\n", ip, mac, hostname, vendor, os, status, ports_str, cves_str));
    }
    csv
}

/// Export scan report in CSV or JSON format.
///
/// Proposes a native save file dialog to select target file.
pub async fn export_audit_report(format: String, devices: Vec<Device>) -> Result<bool, ScanError> {
    let fmt = format.to_lowercase();
    if fmt != "csv" && fmt != "json" {
        return Err(ScanError::InvalidInput("Format must be 'csv' or 'json'".to_string()));
    }

    let fmt_clone = fmt.clone();
    // Propose native save file dialog
    let file_path = tokio::task::spawn_blocking(move || {
        let default_name = format!("netsentinel-report.{}", fmt_clone);
        rfd::FileDialog::new()
            .set_title("Export Audit Report")
            .set_file_name(&default_name)
            .set_directory(
                dirs::download_dir()
                    .or_else(dirs::document_dir)
                    .unwrap_or_else(|| PathBuf::from(".")),
            )
            .add_filter(
                if fmt_clone == "csv" { "CSV File (*.csv)" } else { "JSON File (*.json)" },
                &[&fmt_clone],
            )
            .save_file()
    })
    .await
    .map_err(|e| ScanError::NetworkError(format!("Dialog thread panic: {}", e)))?;

    if let Some(path) = file_path {
        let content = if fmt == "csv" {
            devices_to_csv(&devices)
        } else {
            serde_json::to_string_pretty(&devices)
                .map_err(|e| ScanError::NetworkError(format!("JSON serialization failed: {}", e)))?
        };

        tokio::fs::write(&path, content).await
            .map_err(|e| ScanError::NetworkError(format!("Failed to write report file: {}", e)))?;
        Ok(true)
    } else {
        Ok(false) // user cancelled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Device, DeviceStatus, Port, PortState};

    #[test]
    fn test_devices_to_csv_formatting() {
        let mut dev1 = Device::new("192.168.1.5".to_string());
        dev1.mac = "AA:BB:CC:DD:EE:FF".to_string();
        dev1.hostname = Some("TestHost,Inc.".to_string()); // contains a comma to test escaping
        dev1.vendor = Some("Apple".to_string());
        dev1.os = Some("Linux/Android".to_string());
        dev1.status = DeviceStatus::Online;
        dev1.ports = vec![
            Port {
                number: 80,
                protocol: "tcp".to_string(),
                service: Some("http".to_string()),
                state: PortState::Open,
            }
        ];

        let csv = devices_to_csv(&[dev1]);
        println!("{}", csv);

        // Assert header is present
        assert!(csv.contains("IP,MAC,Hostname,Vendor,OS,Status,Open Ports,Vulnerabilities"));
        // Assert escaped hostname is quoted
        assert!(csv.contains("\"TestHost,Inc.\""));
        // Assert IP and MAC are correct
        assert!(csv.contains("192.168.1.5"));
        assert!(csv.contains("AA:BB:CC:DD:EE:FF"));
        // Assert port is formatted correctly
        assert!(csv.contains("80/tcp(http)"));
    }
}
