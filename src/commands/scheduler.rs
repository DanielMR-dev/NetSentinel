//! Scan scheduler scaffolding.
//!
//! Defines the configuration types and a placeholder async runtime interface
//! for scheduling recurring scans. The actual execution engine will be wired
//! up in a future iteration; this module provides the compile-ready data model
//! and a safe no-op runtime skeleton.

use serde::{Deserialize, Serialize};

/// Day of the week for weekly scan schedules.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum WeekDay {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// How often a scheduled scan should recur.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ScheduleFrequency {
    /// Run once at a specific time.
    Once,
    /// Run every N minutes.
    IntervalMinutes(u32),
    /// Run daily at a specific hour/minute (UTC).
    Daily { hour: u8, minute: u8 },
    /// Run weekly on the given day at the given hour/minute (UTC).
    Weekly { day: WeekDay, hour: u8, minute: u8 },
}

/// A single scheduled scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSchedule {
    /// Unique schedule identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Target CIDR or host expression.
    pub target: String,
    /// Recurrence pattern.
    pub frequency: ScheduleFrequency,
    /// Whether the schedule is currently enabled.
    pub enabled: bool,
    /// Optional scan type override.
    pub scan_type: Option<crate::types::ScanType>,
    /// Creation timestamp.
    pub created_at: i64,
}

/// Placeholder scheduler runtime.
///
/// Maintains a list of schedules and exposes async start/stop hooks. The
/// current implementation logs lifecycle events and returns immediately; the
/// background scheduling loop will be implemented in a future phase.
#[derive(Debug, Default)]
pub struct SchedulerRuntime {
    schedules: Vec<ScanSchedule>,
    running: bool,
}

impl SchedulerRuntime {
    /// Create a new scheduler runtime with the given schedules.
    pub fn new(schedules: Vec<ScanSchedule>) -> Self {
        Self {
            schedules,
            running: false,
        }
    }

    /// Start the scheduler runtime.
    ///
    /// This is a placeholder: it marks the runtime as running and logs the
    /// configured schedules. It does not block the caller.
    pub async fn start(&mut self) {
        self.running = true;
        tracing::info!(
            "Scheduler runtime started with {} schedule(s)",
            self.schedules.len()
        );
        for schedule in &self.schedules {
            tracing::debug!(schedule_id = %schedule.id, name = %schedule.name, "Loaded schedule");
        }
    }

    /// Stop the scheduler runtime.
    pub async fn stop(&mut self) {
        self.running = false;
        tracing::info!("Scheduler runtime stopped");
    }

    /// Returns whether the runtime is currently marked as running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Add or replace a schedule.
    pub fn upsert_schedule(&mut self, schedule: ScanSchedule) {
        if let Some(existing) = self.schedules.iter_mut().find(|s| s.id == schedule.id) {
            *existing = schedule;
        } else {
            self.schedules.push(schedule);
        }
    }

    /// Remove a schedule by ID.
    pub fn remove_schedule(&mut self, id: &str) {
        self.schedules.retain(|s| s.id != id);
    }

    /// Return the currently configured schedules.
    pub fn schedules(&self) -> &[ScanSchedule] {
        &self.schedules
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn make_schedule(id: &str, enabled: bool) -> ScanSchedule {
        ScanSchedule {
            id: id.to_string(),
            name: "Test Schedule".to_string(),
            target: "192.168.1.0/24".to_string(),
            frequency: ScheduleFrequency::Daily { hour: 2, minute: 0 },
            enabled,
            scan_type: Some(crate::types::ScanType::Connect),
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn test_scheduler_lifecycle() {
        let mut runtime = SchedulerRuntime::new(vec![make_schedule("s1", true)]);
        assert!(!runtime.is_running());
        runtime.start().await;
        assert!(runtime.is_running());
        runtime.stop().await;
        assert!(!runtime.is_running());
    }

    #[test]
    fn test_upsert_and_remove_schedule() {
        let mut runtime = SchedulerRuntime::default();
        runtime.upsert_schedule(make_schedule("s1", true));
        assert_eq!(runtime.schedules().len(), 1);

        let mut updated = make_schedule("s1", false);
        updated.name = "Updated".to_string();
        runtime.upsert_schedule(updated);
        assert_eq!(runtime.schedules().len(), 1);
        assert_eq!(runtime.schedules()[0].name, "Updated");

        runtime.remove_schedule("s1");
        assert!(runtime.schedules().is_empty());
    }
}
