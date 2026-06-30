//! Risk scoring helpers for findings and devices.
//!
//! Provides a deterministic numeric risk score (0-100) derived from severity,
//! CVSS, and EPSS probability.

use crate::types::{Device, Finding, FindingSeverity};

/// Compute a normalized risk score for a single finding.
///
/// The score is a weighted combination of:
/// - Severity weight (50%)
/// - CVSS score normalized to 0-1 (30%)
/// - EPSS probability (20%)
pub fn finding_risk_score(finding: &Finding) -> f64 {
    let severity_weight = match finding.severity {
        FindingSeverity::Critical => 1.0,
        FindingSeverity::High => 0.75,
        FindingSeverity::Medium => 0.5,
        FindingSeverity::Low => 0.25,
        FindingSeverity::Info => 0.1,
    };
    let cvss_norm = finding.cvss_score.unwrap_or(severity_weight * 10.0) / 10.0;
    let epss_norm = finding.epss_probability.unwrap_or(0.0);
    let raw = severity_weight * 0.5 + cvss_norm * 0.3 + epss_norm * 0.2;
    (raw * 100.0).clamp(0.0, 100.0)
}

/// Compute the maximum finding risk score for a device.
pub fn device_risk_score(device: &Device) -> f64 {
    device
        .findings
        .iter()
        .map(finding_risk_score)
        .fold(0.0, f64::max)
}

/// Return the top `n` devices ordered by descending risk score.
pub fn top_hosts_by_risk(devices: &[Device], n: usize) -> Vec<(&Device, f64)> {
    let mut scored: Vec<_> = devices.iter().map(|d| (d, device_risk_score(d))).collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.into_iter().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Finding, FindingCategory, FindingConfidence, FindingSeverity, FindingSource,
    };

    fn sample_finding(severity: FindingSeverity, cvss: Option<f64>, epss: Option<f64>) -> Finding {
        Finding {
            id: "finding-1".to_string(),
            scan_id: String::new(),
            source: FindingSource::Cve,
            severity,
            confidence: FindingConfidence::Medium,
            title: "Test".to_string(),
            description: "Test finding".to_string(),
            ip: "192.0.2.1".to_string(),
            port: Some(80),
            service: Some("http".to_string()),
            evidence: None,
            cve: None,
            timestamp: 0,
            category: FindingCategory::Cve,
            cvss_score: cvss,
            epss_probability: epss,
            remediation: None,
        }
    }

    #[test]
    fn finding_risk_score_ranges_between_0_and_100() {
        let finding = sample_finding(FindingSeverity::Critical, Some(10.0), Some(1.0));
        let score = finding_risk_score(&finding);
        assert!(
            score >= 0.0 && score <= 100.0,
            "score {} out of range",
            score
        );

        let finding = sample_finding(FindingSeverity::Info, None, None);
        let score = finding_risk_score(&finding);
        assert!(
            score >= 0.0 && score <= 100.0,
            "score {} out of range",
            score
        );
    }

    #[test]
    fn critical_with_max_cvss_and_epss_is_high_score() {
        let finding = sample_finding(FindingSeverity::Critical, Some(10.0), Some(1.0));
        let score = finding_risk_score(&finding);
        assert!(score > 90.0, "expected high score, got {}", score);
    }

    #[test]
    fn device_risk_score_returns_max_finding_score() {
        let mut device = Device::new("192.0.2.1".to_string());
        device
            .findings
            .push(sample_finding(FindingSeverity::Low, None, None));
        device
            .findings
            .push(sample_finding(FindingSeverity::High, Some(8.0), None));
        let score = device_risk_score(&device);
        let high_score = finding_risk_score(&device.findings[1]);
        assert!((score - high_score).abs() < f64::EPSILON);
    }

    #[test]
    fn top_hosts_by_risk_orders_descending() {
        let mut low_risk = Device::new("192.0.2.1".to_string());
        low_risk
            .findings
            .push(sample_finding(FindingSeverity::Low, None, None));

        let mut high_risk = Device::new("192.0.2.2".to_string());
        high_risk.findings.push(sample_finding(
            FindingSeverity::Critical,
            Some(10.0),
            Some(1.0),
        ));

        let devices = [low_risk, high_risk];
        let top = top_hosts_by_risk(&devices, 2);
        assert_eq!(top.len(), 2);
        assert!(top[0].1 >= top[1].1);
        assert_eq!(top[0].0.ip, "192.0.2.2");
    }
}
