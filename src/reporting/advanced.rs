//! Advanced reporting scaffolding.
//!
//! Provides the data model for compliance-aware, multi-format report
//! generation. The concrete generators (HTML, PDF, JSON, CSV) delegate to
//! existing reporting modules; this file defines the unified configuration
//! interface and a compile-safe report generator skeleton.

use serde::{Deserialize, Serialize};

use crate::error::ScanError;
use crate::types::Device;

/// Supported compliance frameworks for report templates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum ComplianceFramework {
    /// CIS Critical Security Controls.
    Cis,
    /// HIPAA Security Rule.
    Hipaa,
    /// PCI DSS.
    PciDss,
    /// NIST Cybersecurity Framework.
    Nist,
    /// ISO/IEC 27001.
    Iso27001,
}

/// Output format for generated reports.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// HTML document.
    Html,
    /// PDF document.
    Pdf,
    /// JSON machine-readable report.
    Json,
    /// CSV spreadsheet.
    Csv,
}

/// Configuration for an advanced report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportConfig {
    /// Report title.
    pub title: String,
    /// Report output format.
    pub format: ReportFormat,
    /// Optional compliance framework to include in the report.
    pub compliance_framework: Option<ComplianceFramework>,
    /// Whether to include CVE findings.
    pub include_cves: bool,
    /// Whether to include active check findings.
    pub include_active_checks: bool,
    /// Whether to include web audit findings.
    pub include_web_audits: bool,
    /// Whether to include a topology graph section.
    pub include_topology: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            title: "NetSentinel Audit Report".to_string(),
            format: ReportFormat::Html,
            compliance_framework: None,
            include_cves: true,
            include_active_checks: true,
            include_web_audits: true,
            include_topology: false,
        }
    }
}

/// Report generator placeholder.
///
/// Holds a report configuration and provides async generation hooks. The
/// current implementation validates the configuration and routes to existing
/// export functions where available; unsupported formats return a clear error.
#[derive(Debug, Clone)]
pub struct ReportGenerator {
    config: ReportConfig,
}

impl ReportGenerator {
    /// Create a new report generator from a configuration.
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    /// Generate a report for the given devices at the specified output path.
    ///
    /// This is a placeholder that currently routes HTML/PDF to the existing
    /// reporting module and returns `ScanError::Internal` for not-yet-supported
    /// advanced features.
    pub async fn generate(
        &self,
        devices: &[Device],
        output_path: &std::path::Path,
    ) -> Result<(), ScanError> {
        match self.config.format {
            ReportFormat::Html => {
                crate::reporting::export::generate_html_report(devices, output_path).map_err(|e| {
                    ScanError::Internal(format!("HTML report generation failed: {}", e))
                })
            }
            ReportFormat::Pdf => {
                crate::reporting::export::generate_pdf_report(devices, output_path).map_err(|e| {
                    ScanError::Internal(format!("PDF report generation failed: {}", e))
                })
            }
            ReportFormat::Json => Err(ScanError::Internal(
                "JSON advanced report format is not yet implemented".to_string(),
            )),
            ReportFormat::Csv => Err(ScanError::Internal(
                "CSV advanced report format is not yet implemented".to_string(),
            )),
        }
    }

    /// Return the report configuration.
    pub fn config(&self) -> &ReportConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_config_default() {
        let config = ReportConfig::default();
        assert_eq!(config.format, ReportFormat::Html);
        assert!(config.include_cves);
    }

    #[test]
    fn test_compliance_framework_serialization() {
        let fw = ComplianceFramework::PciDss;
        let json = serde_json::to_string(&fw).expect("serialize");
        assert_eq!(json, "\"PCIDSS\"");
    }
}
