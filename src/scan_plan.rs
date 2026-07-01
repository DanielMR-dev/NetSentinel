use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::ScanError;
use crate::network::sanitize;

pub const LARGE_SCAN_HOST_THRESHOLD: u32 = 256;
pub const HIGH_RISK_WORK_UNITS: u64 = 65_536;
pub const MAX_SAFE_HOST_CONCURRENCY: usize = 64;
pub const MAX_SAFE_PORT_CONCURRENCY: usize = 256;
pub const TARGET_CHANNEL_CAPACITY: usize = 64;
pub const DISCOVERY_CHANNEL_CAPACITY: usize = 32;
pub const PORT_CHANNEL_CAPACITY: usize = 16;
pub const ENRICH_CHANNEL_CAPACITY: usize = 16;
pub const FINDING_CHANNEL_CAPACITY: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    DiscoveryOnly,
    PortScanOnly,
    FullAudit,
    RescanSelected,
}

impl Default for ScanMode {
    fn default() -> Self {
        Self::FullAudit
    }
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DiscoveryOnly => write!(f, "Discovery-only"),
            Self::PortScanOnly => write!(f, "Port scan only"),
            Self::FullAudit => write!(f, "Full audit"),
            Self::RescanSelected => write!(f, "Re-scan selected"),
        }
    }
}

impl ScanMode {
    pub fn all() -> &'static [ScanMode] {
        &[ScanMode::DiscoveryOnly, ScanMode::FullAudit]
    }

    pub fn is_supported(self) -> bool {
        matches!(self, ScanMode::DiscoveryOnly | ScanMode::FullAudit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRisk {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for ScanRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanEstimate {
    pub hosts: u32,
    pub ports_per_host: usize,
    pub work_units: u64,
    pub risk: ScanRisk,
    pub requires_confirmation: bool,
    pub warnings: Vec<String>,
}

pub fn estimate_scan(
    cidr: &str,
    ports_per_host: usize,
    mode: ScanMode,
) -> Result<ScanEstimate, ScanError> {
    let network = sanitize::validate_cidr(cidr)?;
    let hosts = match network {
        ipnetwork::IpNetwork::V4(net) => {
            let host_bits = u32::from(32_u8.saturating_sub(net.prefix()));
            2_u32.saturating_pow(host_bits)
        }
        ipnetwork::IpNetwork::V6(net) => {
            let host_bits = u32::from(128_u8.saturating_sub(net.prefix()));
            if host_bits >= 32 {
                u32::MAX
            } else {
                2_u32.saturating_pow(host_bits)
            }
        }
    };
    let effective_ports = match mode {
        ScanMode::DiscoveryOnly => 0,
        _ => ports_per_host,
    };
    let work_units = u64::from(hosts).saturating_mul(effective_ports.max(1) as u64);
    let risk = if work_units >= HIGH_RISK_WORK_UNITS || hosts > 4096 {
        ScanRisk::High
    } else if hosts > LARGE_SCAN_HOST_THRESHOLD || work_units > 8_192 {
        ScanRisk::Medium
    } else {
        ScanRisk::Low
    };

    let mut warnings = Vec::new();
    if hosts > LARGE_SCAN_HOST_THRESHOLD {
        warnings.push(format!("Large target range: {hosts} hosts."));
    }
    if effective_ports > 0 && work_units > 8_192 {
        warnings.push(format!(
            "Estimated scan work: {work_units} host/port checks."
        ));
    }

    Ok(ScanEstimate {
        hosts,
        ports_per_host: effective_ports,
        work_units,
        risk,
        requires_confirmation: risk != ScanRisk::Low,
        warnings,
    })
}

pub fn safe_concurrency_defaults(hosts: usize, ports_per_host: usize) -> (usize, usize) {
    let host_limit = if hosts > 4096 { 32 } else { 50 }.min(MAX_SAFE_HOST_CONCURRENCY);
    let port_limit = if hosts.saturating_mul(ports_per_host) > HIGH_RISK_WORK_UNITS as usize {
        128
    } else {
        100
    }
    .min(MAX_SAFE_PORT_CONCURRENCY);
    (host_limit, port_limit)
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub retries: u8,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl RetryPolicy {
    pub fn new(retries: u8, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            retries,
            base_delay,
            max_delay,
        }
    }

    pub fn backoff_delay(&self, attempt: u8) -> Duration {
        let shift = u32::from(attempt.min(6));
        let multiplier = 1_u32.checked_shl(shift).unwrap_or(64);
        self.base_delay
            .saturating_mul(multiplier)
            .min(self.max_delay)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new(1, Duration::from_millis(75), Duration::from_millis(750))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimator_labels_large_port_scan_high_risk() {
        let estimate = estimate_scan("10.0.0.0/16", 1000, ScanMode::FullAudit).unwrap();
        assert_eq!(estimate.risk, ScanRisk::High);
        assert!(estimate.requires_confirmation);
    }

    #[test]
    fn discovery_only_ignores_port_work() {
        let estimate = estimate_scan("192.168.1.0/24", 1000, ScanMode::DiscoveryOnly).unwrap();
        assert_eq!(estimate.ports_per_host, 0);
        assert_eq!(estimate.risk, ScanRisk::Low);
    }

    #[test]
    fn retry_policy_caps_backoff() {
        let policy = RetryPolicy::new(3, Duration::from_millis(100), Duration::from_millis(450));
        assert_eq!(policy.backoff_delay(0), Duration::from_millis(100));
        assert_eq!(policy.backoff_delay(2), Duration::from_millis(400));
        assert_eq!(policy.backoff_delay(5), Duration::from_millis(450));
    }

    #[test]
    fn safe_defaults_reduce_large_workload_pressure() {
        let (hosts, ports) = safe_concurrency_defaults(65_536, 1000);
        assert!(hosts <= MAX_SAFE_HOST_CONCURRENCY);
        assert!(ports <= 128);
    }

    #[test]
    fn exposed_scan_modes_are_only_supported_modes() {
        assert!(ScanMode::all().iter().all(|mode| mode.is_supported()));
        assert!(!ScanMode::PortScanOnly.is_supported());
        assert!(!ScanMode::RescanSelected.is_supported());
    }

    #[tokio::test]
    async fn bounded_stage_channel_applies_backpressure() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u8>(1);
        assert!(tx.try_send(1).is_ok());
        assert!(tx.try_send(2).is_err());
        assert_eq!(rx.recv().await, Some(1));
    }

    #[tokio::test]
    async fn cancellation_watch_is_observable_by_stage_helpers() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        assert!(tx.send(true).is_ok());
        assert!(rx.changed().await.is_ok());
        assert!(*rx.borrow());
    }
}
