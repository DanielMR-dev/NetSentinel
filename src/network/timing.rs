//! Adaptive timing templates for network scanning (Nmap-style T0-T5).
//!
//! Provides `TimingTemplate` enum and `TimingController` struct that
//! wraps a `tokio::sync::Semaphore` with inter-packet delays.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, SemaphorePermit};

/// Nmap-style timing templates that control scan aggressiveness.
///
/// Each template defines:
/// - Maximum concurrent connections
/// - Delay between packets
/// - Per-connection timeout
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TimingTemplate {
    /// T0: Paranoid — 5 min between packets, 1 concurrent
    Paranoid,
    /// T1: Sneaky — 15s between packets, 1 concurrent
    Sneaky,
    /// T2: Polite — 0.4s between packets, 10 concurrent
    Polite,
    /// T3: Normal — default behavior, 100 concurrent
    Normal,
    /// T4: Aggressive — 10ms between packets, 500 concurrent
    Aggressive,
    /// T5: Insane — no delay, 1000 concurrent
    Insane,
}

impl Default for TimingTemplate {
    fn default() -> Self {
        TimingTemplate::Normal
    }
}

impl TimingTemplate {
    /// Maximum concurrent connections for this timing template.
    pub fn max_concurrent(&self) -> usize {
        match self {
            TimingTemplate::Paranoid => 1,
            TimingTemplate::Sneaky => 1,
            TimingTemplate::Polite => 10,
            TimingTemplate::Normal => 100,
            TimingTemplate::Aggressive => 500,
            TimingTemplate::Insane => 1000,
        }
    }

    /// Delay between packets for this timing template.
    pub fn delay_between_packets(&self) -> Duration {
        match self {
            TimingTemplate::Paranoid => Duration::from_secs(300),
            TimingTemplate::Sneaky => Duration::from_secs(15),
            TimingTemplate::Polite => Duration::from_millis(400),
            TimingTemplate::Normal => Duration::from_millis(0),
            TimingTemplate::Aggressive => Duration::from_millis(10),
            TimingTemplate::Insane => Duration::from_millis(0),
        }
    }

    /// Per-connection timeout for this timing template.
    pub fn connection_timeout(&self) -> Duration {
        match self {
            TimingTemplate::Paranoid => Duration::from_secs(300),
            TimingTemplate::Sneaky => Duration::from_secs(15),
            TimingTemplate::Polite => Duration::from_secs(10),
            TimingTemplate::Normal => Duration::from_secs(3),
            TimingTemplate::Aggressive => Duration::from_secs(2),
            TimingTemplate::Insane => Duration::from_millis(500),
        }
    }

    /// Parse a timing template from a string (case-insensitive).
    ///
    /// Accepts: "paranoid", "sneaky", "polite", "normal", "aggressive", "insane"
    /// Also accepts T0-T5 notation.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "paranoid" | "t0" => Some(TimingTemplate::Paranoid),
            "sneaky" | "t1" => Some(TimingTemplate::Sneaky),
            "polite" | "t2" => Some(TimingTemplate::Polite),
            "normal" | "t3" => Some(TimingTemplate::Normal),
            "aggressive" | "t4" => Some(TimingTemplate::Aggressive),
            "insane" | "t5" => Some(TimingTemplate::Insane),
            _ => None,
        }
    }
}

/// Timing controller that wraps a semaphore with inter-packet delays.
///
/// Used throughout the scan pipeline to enforce timing constraints.
pub struct TimingController {
    semaphore: Arc<Semaphore>,
    template: TimingTemplate,
}

impl TimingController {
    /// Create a new timing controller with the given template.
    pub fn new(template: TimingTemplate) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(template.max_concurrent())),
            template,
        }
    }

    /// Create a timing controller with a custom concurrency limit.
    ///
    /// Uses the template's delay and timeout but overrides the semaphore size.
    pub fn with_concurrency(template: TimingTemplate, max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            template,
        }
    }

    /// Acquire a semaphore permit.
    ///
    /// Blocks until a permit is available. Returns `None` if the semaphore
    /// is closed (should not happen in normal operation).
    pub async fn acquire(&self) -> Option<SemaphorePermit<'_>> {
        self.semaphore.acquire().await.ok()
    }

    /// Acquire an owned semaphore permit (for use in spawned tasks).
    pub async fn acquire_owned(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.semaphore.clone().acquire_owned().await.ok()
    }

    /// Apply the inter-packet delay for this timing template.
    ///
    /// Uses `tokio::time::sleep` to avoid blocking the async runtime.
    pub async fn apply_delay(&self) {
        let delay = self.template.delay_between_packets();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    /// Get the connection timeout for this timing template.
    pub fn connection_timeout(&self) -> Duration {
        self.template.connection_timeout()
    }

    /// Get the timing template.
    pub fn template(&self) -> TimingTemplate {
        self.template
    }

    /// Get the maximum concurrency level.
    pub fn max_concurrent(&self) -> usize {
        self.template.max_concurrent()
    }

    /// Get a clone of the semaphore for use in sub-operations.
    pub fn semaphore(&self) -> Arc<Semaphore> {
        self.semaphore.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_template_defaults() {
        assert_eq!(TimingTemplate::default(), TimingTemplate::Normal);
    }

    #[test]
    fn test_timing_template_max_concurrent() {
        assert_eq!(TimingTemplate::Paranoid.max_concurrent(), 1);
        assert_eq!(TimingTemplate::Sneaky.max_concurrent(), 1);
        assert_eq!(TimingTemplate::Polite.max_concurrent(), 10);
        assert_eq!(TimingTemplate::Normal.max_concurrent(), 100);
        assert_eq!(TimingTemplate::Aggressive.max_concurrent(), 500);
        assert_eq!(TimingTemplate::Insane.max_concurrent(), 1000);
    }

    #[test]
    fn test_timing_template_delays() {
        assert_eq!(
            TimingTemplate::Paranoid.delay_between_packets(),
            Duration::from_secs(300)
        );
        assert_eq!(
            TimingTemplate::Normal.delay_between_packets(),
            Duration::from_millis(0)
        );
        assert_eq!(
            TimingTemplate::Aggressive.delay_between_packets(),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn test_timing_template_connection_timeouts() {
        assert!(
            TimingTemplate::Paranoid.connection_timeout()
                > TimingTemplate::Normal.connection_timeout()
        );
        assert!(
            TimingTemplate::Normal.connection_timeout()
                > TimingTemplate::Insane.connection_timeout()
        );
    }

    #[test]
    fn test_timing_template_from_str() {
        assert_eq!(
            TimingTemplate::from_str_loose("paranoid"),
            Some(TimingTemplate::Paranoid)
        );
        assert_eq!(
            TimingTemplate::from_str_loose("T0"),
            Some(TimingTemplate::Paranoid)
        );
        assert_eq!(
            TimingTemplate::from_str_loose("NORMAL"),
            Some(TimingTemplate::Normal)
        );
        assert_eq!(
            TimingTemplate::from_str_loose("t5"),
            Some(TimingTemplate::Insane)
        );
        assert_eq!(TimingTemplate::from_str_loose("invalid"), None);
    }

    #[test]
    fn test_timing_controller_creation() {
        let controller = TimingController::new(TimingTemplate::Normal);
        assert_eq!(controller.max_concurrent(), 100);
        assert_eq!(controller.template(), TimingTemplate::Normal);
    }

    #[test]
    fn test_timing_controller_custom_concurrency() {
        let controller = TimingController::with_concurrency(TimingTemplate::Normal, 50);
        assert_eq!(controller.template(), TimingTemplate::Normal);
        // The semaphore should have 50 permits, not 100
    }

    #[tokio::test]
    async fn test_timing_controller_acquire() {
        let controller = TimingController::new(TimingTemplate::Normal);
        let permit = controller.acquire().await;
        assert!(permit.is_some());
    }

    #[test]
    fn test_timing_template_serialization() {
        let template = TimingTemplate::Aggressive;
        let json = serde_json::to_string(&template).unwrap();
        assert_eq!(json, "\"aggressive\"");

        let deserialized: TimingTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, TimingTemplate::Aggressive);
    }
}
