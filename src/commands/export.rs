//! Export commands for audit reports.
//!
//! Provides `export_audit_report` for exporting scan results in CSV or JSON
//! format using a native file dialog.

use crate::error::ScanError;
use crate::types::{Device, FindingSeverity};
use std::path::PathBuf;

/// Helper function to convert Vec<Device> to a CSV string.
fn devices_to_csv(devices: &[Device]) -> String {
    let mut csv = String::new();
    // Header
    csv.push_str("IP,MAC,Hostname,Vendor,OS,Status,Open Ports,Findings,Critical Findings,High Findings,Medium Findings,Low Findings,Info Findings,Finding Titles\n");
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

        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut info = 0usize;
        let mut finding_titles = Vec::new();

        for finding in &dev.findings {
            match &finding.severity {
                FindingSeverity::Critical => critical += 1,
                FindingSeverity::High => high += 1,
                FindingSeverity::Medium => medium += 1,
                FindingSeverity::Low => low += 1,
                FindingSeverity::Info => info += 1,
            }
            finding_titles.push(format!("{} ({:?})", finding.title, finding.severity));
        }
        let findings_str = escape(&finding_titles.join("; "));

        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            ip,
            mac,
            hostname,
            vendor,
            os,
            status,
            ports_str,
            dev.findings.len(),
            critical,
            high,
            medium,
            low,
            info,
            findings_str
        ));
    }
    csv
}

/// Export scan report in CSV or JSON format.
///
/// Proposes a native save file dialog to select target file.
pub async fn export_audit_report(format: String, devices: Vec<Device>) -> Result<bool, ScanError> {
    let fmt = format.to_lowercase();
    if fmt != "csv" && fmt != "json" {
        return Err(ScanError::InvalidInput(
            "Format must be 'csv' or 'json'".to_string(),
        ));
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
                if fmt_clone == "csv" {
                    "CSV File (*.csv)"
                } else {
                    "JSON File (*.json)"
                },
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

        tokio::fs::write(&path, content)
            .await
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
        dev1.ports = vec![Port {
            number: 80,
            protocol: "tcp".to_string(),
            service: Some("http".to_string()),
            state: PortState::Open,
        }];

        let csv = devices_to_csv(&[dev1]);
        println!("{}", csv);

        // Assert header is present
        assert!(csv.contains("IP,MAC,Hostname,Vendor,OS,Status,Open Ports,Findings"));
        // Assert escaped hostname is quoted
        assert!(csv.contains("\"TestHost,Inc.\""));
        // Assert IP and MAC are correct
        assert!(csv.contains("192.168.1.5"));
        assert!(csv.contains("AA:BB:CC:DD:EE:FF"));
        // Assert port is formatted correctly
        assert!(csv.contains("80/tcp(http)"));
    }

    #[test]
    fn test_devices_to_csv_includes_finding_counts() {
        let mut dev = Device::new("192.168.1.7".to_string());
        dev.findings.push(crate::types::Finding {
            id: "finding-1".to_string(),
            source: crate::types::FindingSource::WebAudit,
            severity: FindingSeverity::High,
            confidence: crate::types::FindingConfidence::High,
            title: "Exposed path".to_string(),
            description: "A sensitive path was exposed".to_string(),
            ip: dev.ip.clone(),
            port: Some(80),
            service: Some("http".to_string()),
            evidence: Some("/.env".to_string()),
            cve: None,
            timestamp: 0,
            category: crate::types::FindingCategory::Web,
            cvss_score: None,
            epss_probability: None,
            remediation: None,
        });

        let csv = devices_to_csv(&[dev]);

        assert!(csv.contains(",1,0,1,0,0,0,"));
        assert!(csv.contains("Exposed path (High)"));
    }
}
