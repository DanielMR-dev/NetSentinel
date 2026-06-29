//! Compliance Auditing (CIS, HIPAA, PCI DSS)
//!
//! Provides basic heuristic checks against discovered devices to
//! identify potential compliance violations.

use crate::types::{Device, Finding, FindingSeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceIssue {
    pub framework: String,
    pub rule: String,
    pub description: String,
    pub severity: String,
    #[serde(default)]
    pub port: Option<u16>,
}

pub struct ComplianceEngine;

impl ComplianceEngine {
    pub fn audit_device(device: &Device) -> Vec<ComplianceIssue> {
        let mut issues = Vec::new();

        // Check ports
        for port in &device.ports {
            if port.state != crate::types::PortState::Open {
                continue;
            }

            // PCI DSS Checks
            if port.number == 23 || port.number == 21 {
                issues.push(ComplianceIssue {
                    framework: "PCI DSS".to_string(),
                    rule: "Requirement 4.1 - Secure Protocols".to_string(),
                    description: format!("Insecure cleartext protocol found on port {}. Telnet/FTP are strictly prohibited in cardholder data environments.", port.number),
                    severity: "High".to_string(),
                    port: Some(port.number),
                });
            }

            // HIPAA Checks
            if port.number == 80 {
                issues.push(ComplianceIssue {
                    framework: "HIPAA".to_string(),
                    rule: "Technical Safeguards - Transmission Security (164.312(e)(1))".to_string(),
                    description: "Unencrypted HTTP discovered on port 80. If ePHI is transmitted, it must be encrypted (e.g., via HTTPS).".to_string(),
                    severity: "Medium".to_string(),
                    port: Some(port.number),
                });
            }

            // CIS Checks
            if port.number == 22 {
                // If SSH is found, we'd normally check version. For heuristic, flag if it's very old,
                // but since we only have the banner string here, we do a simple check.
                if let Some(banner) = port.service.as_ref() {
                    if banner.contains("SSH-1.") {
                        issues.push(ComplianceIssue {
                            framework: "CIS".to_string(),
                            rule: "Disable SSH v1".to_string(),
                            description: "SSH protocol version 1 is outdated and vulnerable."
                                .to_string(),
                            severity: "High".to_string(),
                            port: Some(port.number),
                        });
                    }
                }
            }
        }

        // Active checks (Default Credentials) for CIS
        for check in &device.active_checks {
            if check.vulnerability_name == "Default Credentials" {
                issues.push(ComplianceIssue {
                    framework: "CIS".to_string(),
                    rule: "Ensure default passwords are changed".to_string(),
                    description: format!("Default credentials found on {}.", device.ip),
                    severity: "Critical".to_string(),
                    port: None,
                });
            }
        }

        issues
    }

    pub fn audit_device_findings(device: &Device) -> Vec<Finding> {
        Self::audit_device(device)
            .into_iter()
            .map(|issue| Finding::from_compliance(&device.ip, &issue))
            .collect()
    }
}

pub(crate) fn compliance_severity_to_finding(s: &str) -> FindingSeverity {
    match s.to_lowercase().as_str() {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        _ => FindingSeverity::Info,
    }
}
