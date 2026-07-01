//! NetSentinel UI module — Iced application entry point.
//!
//! Implements the Elm Architecture (Model-View-Update) for the NetSentinel
//! desktop application. This module contains:
//! - `NetSentinelApp`: the application model (all state)
//! - `Message`: all event variants
//! - `Page`: navigation enum
//! - `update()`: state mutation and async command dispatch
//! - `view()`: pure UI rendering
//! - `subscription()`: streaming event bridge from backend
//! - `run()`: application entry point

use std::sync::Arc;

use futures::SinkExt;
use iced::widget::{column, container, row, text, Stack};
use iced::{Element, Length, Subscription, Task};
use tokio::sync::mpsc;

use crate::baseline::{Baseline, BaselineDiff};
use crate::commands::platform::PlatformCapabilities;
use crate::commands::{DeviceInfo, NetworkInfo};
use crate::events::AppEvent;
use crate::history::ScanHistoryEntry;
use crate::network::cve::CveMatch;
use crate::network::privileges::PrivilegeStatus;
use crate::network::timing::TimingTemplate;
use crate::network::web_audit::WebAuditProfile;
use crate::scan_store::StoredDeviceSummary;
use crate::settings::{SettingsDiscoveryMethod, SettingsProfile};
use crate::state::SharedScanState;
use crate::types::{Device, Finding, FindingSeverity, ScanType, TopologyGraph};

pub mod theme;
pub mod views;
pub mod widgets;

// ── Page Navigation ─────────────────────────────────────────────────────

/// Application pages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    Scan,
    Settings,
    History,
    Baseline,
    Topology,
}

impl Page {
    fn label(&self) -> &'static str {
        match self {
            Page::Dashboard => "Dashboard",
            Page::Scan => "Scan",
            Page::Settings => "Settings",
            Page::History => "History",
            Page::Baseline => "Baseline",
            Page::Topology => "Topology",
        }
    }

    fn all() -> &'static [Page] {
        &[
            Page::Dashboard,
            Page::Scan,
            Page::Topology,
            Page::History,
            Page::Baseline,
            Page::Settings,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Ip,
    Mac,
    Vendor,
    Hostname,
    OpenPorts,
    Findings,
    LastSeen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

/// Guided scan profiles for one-click configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuidedScanProfile {
    FastDiscovery,
    StandardAudit,
    DeepAudit,
    WebServicesAudit,
    StealthRawScan,
}

impl GuidedScanProfile {
    /// Human-readable label for the profile.
    pub fn label(&self) -> &'static str {
        match self {
            GuidedScanProfile::FastDiscovery => "Fast discovery",
            GuidedScanProfile::StandardAudit => "Standard audit",
            GuidedScanProfile::DeepAudit => "Deep audit",
            GuidedScanProfile::WebServicesAudit => "Web services audit",
            GuidedScanProfile::StealthRawScan => "Stealth/raw scan",
        }
    }

    /// All guided profiles.
    pub fn all() -> &'static [GuidedScanProfile] {
        &[
            GuidedScanProfile::FastDiscovery,
            GuidedScanProfile::StandardAudit,
            GuidedScanProfile::DeepAudit,
            GuidedScanProfile::WebServicesAudit,
            GuidedScanProfile::StealthRawScan,
        ]
    }
}

impl std::fmt::Display for GuidedScanProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── Message Enum ────────────────────────────────────────────────────────

/// All possible events in the application
#[derive(Debug, Clone)]
pub enum Message {
    // Navigation
    NavigateTo(Page),

    // Initialization results
    DeviceInfoLoaded(Result<DeviceInfo, String>),
    NetworkInfoLoaded(Result<NetworkInfo, String>),
    PrivilegeLoaded(Result<PrivilegeStatus, String>),
    PlatformCapsLoaded(PlatformCapabilities),

    // Scan control
    StartScan,
    StopScan,
    PauseScan,
    ResumeScan,
    ScanCidrChanged(String),
    ScanPortsChanged(String),
    ScanTypeSelected(ScanType),
    ScanModeSelected(crate::scan_plan::ScanMode),
    StartScanRequested,
    StartScanConfirmed,
    StartScanCancelled,
    QuickStartScanCurrentNetwork,
    QuickStartAdvancedScan,
    ApplyGuidedProfile(GuidedScanProfile),

    // Scan events (from subscription)
    DeviceDiscovered(Device),
    DevicesDiscovered(Vec<Device>),
    ScanProgress {
        scanned: u32,
        total: u32,
        target: String,
    },
    ScanCompleted {
        scan_id: String,
        device_count: u32,
        duration_ms: u64,
        devices: Vec<Device>,
        status: String,
    },
    ScanLogReceived {
        level: String,
        message: String,
        target: Option<String>,
        timestamp: i64,
    },
    CveAlertReceived(CveMatch),
    FindingReceived(Finding),
    FindingsReceived(Vec<Finding>),
    ScanStartResult(Result<String, String>),
    ScanStopResult(Result<(), String>),

    // IPC
    IpcServerStopped(Result<(), String>),
    IpcCommandReceived(String),

    // Device selection
    DeviceSelected(Option<usize>),

    // Settings
    SettingsProfilesLoaded(Result<Vec<SettingsProfile>, String>),
    SettingsLoaded(Result<SettingsProfile, String>),
    SettingsSaved(Result<(), String>),
    SaveSettings,
    ProfileSelected(String),
    ProfileCreated,
    ProfileDeleted(String),
    SettingsCidrChanged(String),
    SettingsTimeoutChanged(String),
    SettingsMaxHostsChanged(String),
    SettingsMaxPortsChanged(String),
    SettingsRetryChanged(String),
    SettingsScanPortsToggled(bool),
    SettingsTimingTemplateSelected(TimingTemplate),
    SettingsWebAuditProfileSelected(WebAuditProfile),
    SettingsRunActiveChecksToggled(bool),
    SettingsDiscoveryMethodToggled(String, bool),
    SettingsAutoRefreshToggled(bool),
    SettingsConfirmScanToggled(bool),
    SettingsAdvancedToggled(bool),
    SettingsRefreshRateChanged(String),

    // History
    HistoryLoaded(Result<Vec<ScanHistoryEntry>, String>),
    HistoryEntryDeleted(Result<String, String>),
    DeleteHistoryEntry(String),
    HistoryCleared(Result<(), String>),
    ClearHistory,
    HistoryEntryToggled(String),
    HistoryDevicesLoaded(Result<(String, Vec<StoredDeviceSummary>, u32), String>),
    HistoryDeviceSelected(String),
    HistoryDeviceDetailLoaded(Result<Device, String>),

    // Baseline
    BaselinesLoaded(Result<Vec<Baseline>, String>),
    BaselineSaveResult(Result<String, String>),
    SaveBaseline,
    BaselineDeleted(Result<String, String>),
    DeleteBaseline(String),
    BaselineCompared(Result<BaselineDiff, String>),
    CompareBaseline(String),
    BaselineNameChanged(String),
    BaselineDescriptionChanged(String),

    // Topology
    TopologyRefresh,
    TopologyLoaded(Result<TopologyGraph, String>),

    // Export
    ExportCsv,
    ExportJson,
    ExportHtml,
    ExportPdf,
    ExportCompleted(Result<bool, String>),

    // Search / Filter / Sort / Theme
    SearchQueryChanged(String),
    FilterStatusChanged(String),
    FilterHasOpenPortsToggled(bool),
    FilterHasFindingsToggled(bool),
    SortTableBy(SortField),
    ClearFilters,
    ToggleTheme,

    // UI
    StatusDismissed,
    Tick,
}

// ── Scan Log Entry (UI display) ─────────────────────────────────────────

/// A scan log entry for display in the UI
#[derive(Debug, Clone)]
pub struct ScanLogEntry {
    pub level: String,
    pub message: String,
    pub target: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default)]
pub struct FindingCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

// ── Application Model ───────────────────────────────────────────────────

/// The main application state
pub struct NetSentinelApp {
    // Navigation
    current_page: Page,

    // Backend integration
    scan_state: Arc<SharedScanState>,
    event_rx: Arc<tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<AppEvent>>>>,
    event_tx: Option<mpsc::UnboundedSender<AppEvent>>,
    ipc_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<AppEvent>>>>,

    // System info
    device_info: Option<DeviceInfo>,
    network_info: Option<NetworkInfo>,
    privilege_status: Option<PrivilegeStatus>,
    platform_caps: Option<PlatformCapabilities>,

    // Scan state
    scan_cidr: String,
    scan_ports_str: String,
    scan_type: ScanType,
    scan_mode: crate::scan_plan::ScanMode,
    scan_cidr_error: Option<String>,
    scan_ports_error: Option<String>,
    scan_ports_warning: Option<String>,
    show_scan_confirm: bool,
    scan_confirm_estimated_hosts: u32,
    scan_confirm_port_summary: String,
    scan_confirm_risk_label: String,
    scan_confirm_work_units: u64,
    scan_confirm_warnings: Vec<String>,
    is_scanning: bool,
    is_paused: bool,
    scan_progress: f32,
    scan_scanned: u32,
    scan_total: u32,
    scan_current_target: String,
    discovered_devices: Vec<Device>,
    findings: Vec<Finding>,
    selected_finding: Option<Finding>,
    finding_counts: FindingCounts,
    scan_logs: Vec<ScanLogEntry>,
    selected_device: Option<Device>,

    // Search/filtering/sorting
    pub search_query: String,
    pub filter_status: String,
    pub filter_has_open_ports: bool,
    pub filter_has_findings: bool,
    pub sort_field: SortField,
    pub sort_direction: SortDirection,
    pub filtered_devices: Vec<Device>,
    pub theme_dark: bool,

    // Settings
    settings_profile: SettingsProfile,
    settings_profiles: Vec<SettingsProfile>,

    // History
    history_entries: Vec<ScanHistoryEntry>,
    expanded_history: Option<String>,
    history_devices: Vec<StoredDeviceSummary>,
    history_devices_total: u32,
    history_devices_scan_id: Option<String>,
    history_device_detail: Option<Device>,

    // Baseline
    baselines: Vec<Baseline>,
    baseline_diff: Option<BaselineDiff>,
    baseline_name: String,
    baseline_description: String,

    // Topology
    topology_graph: Option<TopologyGraph>,
    topology_loading: bool,
    topology_error: Option<String>,

    // CVE
    cve_alerts: Vec<CveMatch>,

    // UI state
    status_message: Option<String>,
    loading: bool,
}

impl NetSentinelApp {
    /// Create a new application instance with initial state
    fn new() -> (Self, Task<Message>) {
        let scan_state = Arc::new(SharedScanState::new());
        let event_rx_arc = Arc::new(tokio::sync::Mutex::new(None));

        let (ipc_tx, ipc_rx) = mpsc::channel(1024);
        let ipc_rx_arc = Arc::new(tokio::sync::Mutex::new(Some(ipc_rx)));

        let app = Self {
            current_page: Page::Dashboard,
            scan_state,
            event_rx: event_rx_arc,
            event_tx: None,
            ipc_rx: ipc_rx_arc,
            device_info: None,
            network_info: None,
            privilege_status: None,
            platform_caps: None,
            scan_cidr: "192.168.1.0/24".to_string(),
            scan_ports_str:
                "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
                    .to_string(),
            scan_type: ScanType::Connect,
            scan_mode: crate::scan_plan::ScanMode::FullAudit,
            scan_cidr_error: None,
            scan_ports_error: None,
            scan_ports_warning: None,
            show_scan_confirm: false,
            scan_confirm_estimated_hosts: 0,
            scan_confirm_port_summary: String::new(),
            scan_confirm_risk_label: String::new(),
            scan_confirm_work_units: 0,
            scan_confirm_warnings: Vec::new(),
            is_scanning: false,
            is_paused: false,
            scan_progress: 0.0,
            scan_scanned: 0,
            scan_total: 0,
            scan_current_target: String::new(),
            discovered_devices: Vec::new(),
            findings: Vec::new(),
            selected_finding: None,
            finding_counts: FindingCounts::default(),
            scan_logs: Vec::new(),
            selected_device: None,
            search_query: String::new(),
            filter_status: "all".to_string(),
            filter_has_open_ports: false,
            filter_has_findings: false,
            sort_field: SortField::Ip,
            sort_direction: SortDirection::Asc,
            filtered_devices: Vec::new(),
            theme_dark: true,
            settings_profile: SettingsProfile::default_profile(),
            settings_profiles: Vec::new(),
            history_entries: Vec::new(),
            expanded_history: None,
            history_devices: Vec::new(),
            history_devices_total: 0,
            history_devices_scan_id: None,
            history_device_detail: None,
            baselines: Vec::new(),
            baseline_diff: None,
            baseline_name: String::new(),
            baseline_description: String::new(),
            topology_graph: None,
            topology_loading: false,
            topology_error: None,
            cve_alerts: Vec::new(),
            status_message: None,
            loading: true,
        };

        // Load initial data
        let ipc_task = Task::perform(
            async move {
                let _ = crate::ipc::IpcServer::new("/tmp/nexus_central.sock")
                    .run(ipc_tx)
                    .await;
                Ok(())
            },
            Message::IpcServerStopped,
        );

        let init_task = Task::batch(vec![
            load_device_info(),
            load_network_info(),
            load_privilege_status(),
            load_platform_caps(),
            load_settings(),
            load_settings_profiles(),
            load_history(),
            load_baselines(),
            ipc_task,
        ]);

        (app, init_task)
    }

    /// Dynamic helper to filter and sort discovered devices, caching the result in filtered_devices.
    pub fn update_filtered_devices(&mut self) {
        let mut devices = self.discovered_devices.clone();

        // 1. Filter by Search Query
        if !self.search_query.is_empty() {
            let query = self.search_query.to_lowercase();
            devices.retain(|d| {
                d.ip.to_lowercase().contains(&query)
                    || d.mac.to_lowercase().contains(&query)
                    || d.hostname
                        .as_ref()
                        .map(|h| h.to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || d.vendor
                        .as_ref()
                        .map(|v| v.to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || d.findings.iter().any(|finding| {
                        finding.title.to_lowercase().contains(&query)
                            || finding.description.to_lowercase().contains(&query)
                            || finding
                                .cve
                                .as_ref()
                                .map(|cve| cve.cve_id.to_lowercase().contains(&query))
                                .unwrap_or(false)
                    })
            });
        }

        // 2. Filter by Status
        if self.filter_status != "all" {
            let status = self.filter_status.to_lowercase();
            devices.retain(|d| {
                let status_str = format!("{:?}", d.status).to_lowercase();
                status_str == status
            });
        }

        // 3. Filter by Open Ports
        if self.filter_has_open_ports {
            devices.retain(|d| {
                d.ports
                    .iter()
                    .any(|p| format!("{:?}", p.state).to_lowercase() == "open")
            });
        }

        if self.filter_has_findings {
            devices.retain(|d| !d.findings.is_empty());
        }

        // 4. Sort
        let field = self.sort_field;
        let direction = self.sort_direction;
        devices.sort_by(|a, b| {
            let ordering = match field {
                SortField::Ip => {
                    let a_parts: Vec<u32> =
                        a.ip.split('.').filter_map(|p| p.parse().ok()).collect();
                    let b_parts: Vec<u32> =
                        b.ip.split('.').filter_map(|p| p.parse().ok()).collect();
                    a_parts.cmp(&b_parts)
                }
                SortField::Mac => a.mac.cmp(&b.mac),
                SortField::Vendor => {
                    let a_v = a.vendor.as_deref().unwrap_or("");
                    let b_v = b.vendor.as_deref().unwrap_or("");
                    a_v.cmp(b_v)
                }
                SortField::Hostname => {
                    let a_h = a.hostname.as_deref().unwrap_or("");
                    let b_h = b.hostname.as_deref().unwrap_or("");
                    a_h.cmp(b_h)
                }
                SortField::OpenPorts => {
                    let a_open = a
                        .ports
                        .iter()
                        .filter(|p| format!("{:?}", p.state).to_lowercase() == "open")
                        .count();
                    let b_open = b
                        .ports
                        .iter()
                        .filter(|p| format!("{:?}", p.state).to_lowercase() == "open")
                        .count();
                    a_open.cmp(&b_open)
                }
                SortField::Findings => a.findings.len().cmp(&b.findings.len()),
                SortField::LastSeen => a.last_seen.cmp(&b.last_seen),
            };

            match direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            }
        });

        self.filtered_devices = devices;
    }

    fn attach_cached_findings_to_device(&self, device: &mut Device) {
        for finding in self
            .findings
            .iter()
            .filter(|finding| finding.ip == device.ip)
        {
            if !device
                .findings
                .iter()
                .any(|existing| existing.id == finding.id)
            {
                device.findings.push(finding.clone());
            }
        }
    }

    fn merge_device(&mut self, mut device: Device) {
        self.attach_cached_findings_to_device(&mut device);
        if let Some(existing) = self
            .discovered_devices
            .iter_mut()
            .find(|existing| existing.ip == device.ip)
        {
            *existing = device;
        } else {
            self.discovered_devices.push(device);
        }
        self.rebuild_findings_cache();
        self.update_selected_device_snapshot();
        self.update_filtered_devices();
    }

    fn merge_devices(&mut self, devices: Vec<Device>) {
        for mut device in devices {
            self.attach_cached_findings_to_device(&mut device);
            if let Some(existing) = self
                .discovered_devices
                .iter_mut()
                .find(|existing| existing.ip == device.ip)
            {
                *existing = device;
            } else {
                self.discovered_devices.push(device);
            }
        }
        self.rebuild_findings_cache();
        self.update_selected_device_snapshot();
        self.update_filtered_devices();
    }

    fn merge_finding(&mut self, finding: Finding) {
        if !self
            .findings
            .iter()
            .any(|existing| existing.id == finding.id)
        {
            self.findings.push(finding.clone());
        }

        if let Some(device) = self
            .discovered_devices
            .iter_mut()
            .find(|device| device.ip == finding.ip)
        {
            if !device
                .findings
                .iter()
                .any(|existing| existing.id == finding.id)
            {
                device.findings.push(finding.clone());
            }
        }

        if let Some(device) = self.selected_device.as_mut() {
            if device.ip == finding.ip
                && !device
                    .findings
                    .iter()
                    .any(|existing| existing.id == finding.id)
            {
                device.findings.push(finding);
            }
        }

        self.refresh_finding_counts();
        self.update_filtered_devices();
    }

    fn rebuild_findings_cache(&mut self) {
        let mut findings = Vec::new();
        for device in &self.discovered_devices {
            for finding in &device.findings {
                if !findings
                    .iter()
                    .any(|existing: &Finding| existing.id == finding.id)
                {
                    findings.push(finding.clone());
                }
            }
        }
        self.findings = findings;
        self.refresh_finding_counts();
    }

    fn refresh_finding_counts(&mut self) {
        let severity_rank = |severity: &FindingSeverity| match severity {
            FindingSeverity::Critical => 0,
            FindingSeverity::High => 1,
            FindingSeverity::Medium => 2,
            FindingSeverity::Low => 3,
            FindingSeverity::Info => 4,
        };
        self.findings
            .sort_by_key(|finding| severity_rank(&finding.severity));

        let mut counts = FindingCounts::default();
        for finding in &self.findings {
            match &finding.severity {
                FindingSeverity::Critical => counts.critical += 1,
                FindingSeverity::High => counts.high += 1,
                FindingSeverity::Medium => counts.medium += 1,
                FindingSeverity::Low => counts.low += 1,
                FindingSeverity::Info => counts.info += 1,
            }
        }
        self.finding_counts = counts;
    }

    fn update_selected_device_snapshot(&mut self) {
        let selected_ip = self
            .selected_device
            .as_ref()
            .map(|device| device.ip.clone());
        if let Some(ip) = selected_ip {
            self.selected_device = self
                .discovered_devices
                .iter()
                .find(|device| device.ip == ip)
                .cloned();
        }
    }

    /// Validate the current scan CIDR and port expression, populating UI error
    /// and warning fields. Returns true if the inputs are valid.
    fn validate_scan_inputs(&mut self) -> bool {
        let mut valid = true;

        match crate::network::sanitize::validate_cidr(&self.scan_cidr) {
            Ok(_) => self.scan_cidr_error = None,
            Err(e) => {
                self.scan_cidr_error = Some(e.to_string());
                valid = false;
            }
        }

        if self.settings_profile.scan_config.scan_ports_enabled {
            match crate::network::sanitize::parse_port_expression(&self.scan_ports_str) {
                Ok((_, warning)) => {
                    self.scan_ports_warning = warning;
                    self.scan_ports_error = None;
                }
                Err(e) => {
                    self.scan_ports_error = Some(e.to_string());
                    self.scan_ports_warning = None;
                    valid = false;
                }
            }
        } else {
            self.scan_ports_error = None;
            self.scan_ports_warning = None;
        }

        valid
    }

    fn prepare_scan_confirmation(&mut self) {
        let ports_per_host = if self.settings_profile.scan_config.scan_ports_enabled {
            crate::network::sanitize::parse_port_expression(&self.scan_ports_str)
                .map(|(ports, _)| {
                    if ports.is_empty() {
                        self.settings_profile.scan_config.effective_ports().len()
                    } else {
                        ports.len()
                    }
                })
                .unwrap_or_else(|_| self.settings_profile.scan_config.effective_ports().len())
        } else {
            0
        };

        let estimate =
            crate::scan_plan::estimate_scan(&self.scan_cidr, ports_per_host, self.scan_mode).ok();
        self.scan_confirm_estimated_hosts = estimate.as_ref().map(|value| value.hosts).unwrap_or(0);
        self.scan_confirm_risk_label = estimate
            .as_ref()
            .map(|value| value.risk.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        self.scan_confirm_work_units = estimate.as_ref().map(|value| value.work_units).unwrap_or(0);

        self.scan_confirm_port_summary = if self.settings_profile.scan_config.scan_ports_enabled {
            match crate::network::sanitize::parse_port_expression(&self.scan_ports_str) {
                Ok((ports, _)) if !ports.is_empty() => format!("{} ports", ports.len()),
                _ => "default ports".to_string(),
            }
        } else {
            "host discovery only".to_string()
        };

        let mut warnings = estimate.map(|value| value.warnings).unwrap_or_default();

        let elevated = self
            .platform_caps
            .as_ref()
            .map(|caps| caps.is_elevated)
            .unwrap_or(false);

        if matches!(
            self.scan_type,
            ScanType::Syn | ScanType::Fin | ScanType::Xmas | ScanType::Null | ScanType::Udp
        ) && !elevated
        {
            warnings.push(format!(
                "{} scan requires elevated privileges. The engine will downgrade to TCP Connect if needed.",
                self.scan_type
            ));
        } else if matches!(self.scan_type, ScanType::Sctp) && !elevated {
            warnings.push(
                "SCTP scan requires elevated privileges and will fail without them.".to_string(),
            );
        }

        self.scan_confirm_warnings = warnings;
    }

    /// Apply a guided scan profile to the current scan configuration.
    /// Returns any warnings that should be surfaced to the user.
    fn apply_guided_profile(&mut self, profile: GuidedScanProfile) -> Vec<String> {
        use crate::network::timing::TimingTemplate;
        use crate::network::web_audit::WebAuditProfile;
        use crate::scan_plan::ScanMode;
        use crate::settings::SettingsDiscoveryMethod;
        use crate::types::ScanType;

        let mut warnings = Vec::new();

        let (
            scan_type,
            ports_expr,
            timing,
            run_active_checks,
            web_audit_profile,
            max_hosts,
            max_ports,
            scan_mode,
        ) = match profile {
            GuidedScanProfile::FastDiscovery => (
                ScanType::Connect,
                "top-100",
                TimingTemplate::Aggressive,
                false,
                WebAuditProfile::Safe,
                100,
                100,
                ScanMode::DiscoveryOnly,
            ),
            GuidedScanProfile::StandardAudit => (
                ScanType::Connect,
                "top-1000",
                TimingTemplate::Normal,
                true,
                WebAuditProfile::Safe,
                50,
                100,
                ScanMode::FullAudit,
            ),
            GuidedScanProfile::DeepAudit => (
                ScanType::Connect,
                "top-10000",
                TimingTemplate::Polite,
                true,
                WebAuditProfile::Aggressive,
                50,
                100,
                ScanMode::FullAudit,
            ),
            GuidedScanProfile::WebServicesAudit => (
                ScanType::Connect,
                "80,443,8080,8443",
                TimingTemplate::Normal,
                false,
                WebAuditProfile::Aggressive,
                50,
                100,
                ScanMode::FullAudit,
            ),
            GuidedScanProfile::StealthRawScan => (
                ScanType::Syn,
                "top-1000",
                TimingTemplate::Sneaky,
                false,
                WebAuditProfile::Safe,
                50,
                100,
                ScanMode::FullAudit,
            ),
        };

        self.scan_type = scan_type.clone();
        self.scan_ports_str = ports_expr.to_string();
        self.settings_profile.scan_config.timing_template = timing;
        self.settings_profile.scan_config.run_active_checks = run_active_checks;
        self.settings_profile.scan_config.web_audit_profile = web_audit_profile;
        self.settings_profile.scan_config.max_concurrent_hosts = max_hosts;
        self.settings_profile.scan_config.max_concurrent_ports = max_ports;
        self.scan_mode = scan_mode;
        self.settings_profile.scan_config.scan_mode = scan_mode;
        self.settings_profile.scan_config.scan_ports_enabled =
            !matches!(scan_mode, ScanMode::DiscoveryOnly);
        self.settings_profile.scan_config.discovery_methods = vec![SettingsDiscoveryMethod::All];

        if matches!(
            scan_type,
            ScanType::Syn | ScanType::Fin | ScanType::Xmas | ScanType::Null | ScanType::Udp
        ) {
            let elevated = self
                .platform_caps
                .as_ref()
                .map(|caps| caps.is_elevated)
                .unwrap_or(false);
            if !elevated {
                warnings.push(format!(
                    "{} scan requires elevated privileges. The engine will downgrade to TCP Connect if privileges are unavailable.",
                    scan_type
                ));
            }
        } else if matches!(scan_type, ScanType::Sctp) {
            let elevated = self
                .platform_caps
                .as_ref()
                .map(|caps| caps.is_elevated)
                .unwrap_or(false);
            if !elevated {
                warnings.push(
                    "SCTP scan requires elevated privileges and will fail without them."
                        .to_string(),
                );
            }
        }

        if ports_expr == "top-10000" {
            warnings.push(
                "Deep audit scans up to 10,000 ports per host and may take a long time."
                    .to_string(),
            );
        }

        warnings
    }

    /// Handle state updates and dispatch async commands
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // ── Navigation ──────────────────────────────────────────────
            Message::NavigateTo(page) => {
                self.current_page = page.clone();
                if page == Page::Topology {
                    return load_topology_graph(self.scan_state.clone());
                }
                Task::none()
            }

            // ── Initialization ──────────────────────────────────────────
            Message::DeviceInfoLoaded(result) => {
                match result {
                    Ok(info) => self.device_info = Some(info),
                    Err(e) => {
                        self.status_message = Some(format!("Failed to load device info: {}", e))
                    }
                }
                Task::none()
            }
            Message::NetworkInfoLoaded(result) => {
                match result {
                    Ok(info) => {
                        let cidr = if !info.gateway.is_empty()
                            && info.gateway != "Unknown"
                            && info.gateway != "0.0.0.0"
                        {
                            calculate_cidr(&info.gateway)
                        } else if !info.ip_address.is_empty() && info.ip_address != "Unknown" {
                            calculate_cidr(&info.ip_address)
                        } else {
                            "192.168.1.0/24".to_string()
                        };
                        // Override default CIDR with detected one, unless user settings already customized it
                        if self.scan_cidr == "192.168.1.0/24" {
                            self.scan_cidr = cidr;
                        }
                        self.network_info = Some(info);
                    }
                    Err(e) => {
                        self.status_message = Some(format!("Failed to load network info: {}", e))
                    }
                }
                Task::none()
            }
            Message::PrivilegeLoaded(result) => {
                match result {
                    Ok(status) => self.privilege_status = Some(status),
                    Err(e) => {
                        self.status_message =
                            Some(format!("Failed to load privilege status: {}", e))
                    }
                }
                self.loading = false;
                Task::none()
            }
            Message::PlatformCapsLoaded(caps) => {
                self.platform_caps = Some(caps);
                Task::none()
            }

            // ── Scan Control ────────────────────────────────────────────
            Message::StartScan => {
                // Guard against re-starting while already scanning
                if self.is_scanning {
                    return Task::none();
                }

                // Validate CIDR and ports before mutating state.
                if !self.validate_scan_inputs() {
                    return Task::none();
                }

                let scan_ports_enabled = self.settings_profile.scan_config.scan_ports_enabled;
                let scan_ports_enabled = scan_ports_enabled
                    && !matches!(self.scan_mode, crate::scan_plan::ScanMode::DiscoveryOnly);

                // Resolve ports from the scan page input or from settings.
                let parsed_ports = if scan_ports_enabled {
                    match crate::network::sanitize::parse_port_expression(&self.scan_ports_str) {
                        Ok((ports, warning)) => {
                            self.scan_ports_warning = warning;
                            ports
                        }
                        Err(e) => {
                            self.scan_ports_error = Some(e.to_string());
                            return Task::none();
                        }
                    }
                } else {
                    Vec::new()
                };

                let ports = if parsed_ports.is_empty() {
                    self.settings_profile.scan_config.effective_ports()
                } else {
                    parsed_ports
                };

                self.is_scanning = true;
                self.is_paused = false;
                self.scan_progress = 0.0;
                self.scan_scanned = 0;
                self.discovered_devices.clear();
                self.findings.clear();
                self.selected_finding = None;
                self.finding_counts = FindingCounts::default();
                self.filtered_devices.clear();
                self.scan_logs.clear();
                self.selected_device = None;
                self.cve_alerts.clear();

                // Create event channel
                let (tx, rx) = mpsc::unbounded_channel();
                self.event_tx = Some(tx.clone());

                // Install receiver synchronously to avoid race with subscription.
                // `try_lock` is used because `update()` is not async and must not block.
                if let Ok(mut guard) = self.event_rx.try_lock() {
                    *guard = Some(rx);
                }

                let cidr = self.scan_cidr.clone();
                let scan_type = self.scan_type.clone();
                let state = self.scan_state.clone();
                let timeout = self.settings_profile.scan_config.timeout_ms;
                let max_hosts = self.settings_profile.scan_config.max_concurrent_hosts as u32;
                let max_ports = self.settings_profile.scan_config.max_concurrent_ports as u32;
                let retry = self.settings_profile.scan_config.retry_count as u8;
                let discovery_methods = self
                    .settings_profile
                    .scan_config
                    .effective_discovery_methods();
                let timing_template = self.settings_profile.scan_config.timing_template;
                let web_audit_profile = self.settings_profile.scan_config.web_audit_profile;
                let run_active_checks = self.settings_profile.scan_config.run_active_checks;
                let scan_mode = self.scan_mode;

                Task::perform(
                    async move {
                        crate::commands::start_scan(
                            state,
                            tx,
                            cidr,
                            timeout,
                            scan_ports_enabled,
                            ports,
                            Some(max_hosts),
                            Some(max_ports),
                            Some(discovery_methods),
                            Some(retry),
                            Some(scan_type),
                            Some(timing_template),
                            Some(web_audit_profile),
                            Some(run_active_checks),
                            Some(scan_mode),
                        )
                        .await
                        .map(|r| r.scan_id)
                        .map_err(|e| e.to_string())
                    },
                    Message::ScanStartResult,
                )
            }

            Message::StartScanRequested => {
                if self.is_scanning {
                    return Task::none();
                }

                self.scan_cidr_error = None;
                self.scan_ports_error = None;

                if !self.validate_scan_inputs() {
                    return Task::none();
                }

                let is_first_use = self.history_entries.is_empty();
                self.prepare_scan_confirmation();
                let requires_large_scan_confirmation = crate::scan_plan::estimate_scan(
                    &self.scan_cidr,
                    if self.settings_profile.scan_config.scan_ports_enabled {
                        crate::network::sanitize::parse_port_expression(&self.scan_ports_str)
                            .map(|(ports, _)| {
                                if ports.is_empty() {
                                    self.settings_profile.scan_config.effective_ports().len()
                                } else {
                                    ports.len()
                                }
                            })
                            .unwrap_or(0)
                    } else {
                        0
                    },
                    self.scan_mode,
                )
                .map(|estimate| estimate.requires_confirmation)
                .unwrap_or(false);

                if self.settings_profile.ui_preferences.confirm_before_scan
                    || is_first_use
                    || requires_large_scan_confirmation
                {
                    self.show_scan_confirm = true;
                    Task::none()
                } else {
                    Task::done(Message::StartScan)
                }
            }

            Message::StartScanConfirmed => {
                self.show_scan_confirm = false;
                self.scan_confirm_warnings.clear();
                Task::done(Message::StartScan)
            }

            Message::StartScanCancelled => {
                self.show_scan_confirm = false;
                self.scan_confirm_warnings.clear();
                Task::none()
            }

            Message::QuickStartScanCurrentNetwork => {
                if let Some(ref info) = self.network_info {
                    if !info.ip_address.is_empty() && info.ip_address != "Unknown" {
                        self.scan_cidr = calculate_cidr(&info.ip_address);
                    }
                }
                Task::done(Message::StartScanRequested)
            }

            Message::QuickStartAdvancedScan => {
                self.current_page = Page::Scan;
                Task::none()
            }

            Message::ApplyGuidedProfile(profile) => {
                let warnings = self.apply_guided_profile(profile);
                if !warnings.is_empty() {
                    self.status_message = Some(warnings.join(" "));
                }
                Task::none()
            }

            Message::StopScan => {
                let state = self.scan_state.clone();
                let event_tx = self
                    .event_tx
                    .clone()
                    .unwrap_or_else(|| mpsc::unbounded_channel().0);
                Task::perform(
                    async move {
                        crate::commands::stop_scan(state, event_tx)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::ScanStopResult,
                )
            }

            Message::PauseScan => {
                self.is_paused = true;
                self.scan_state.set_paused(true);
                Task::none()
            }

            Message::ResumeScan => {
                self.is_paused = false;
                self.scan_state.set_paused(false);
                Task::none()
            }

            Message::ScanCidrChanged(cidr) => {
                self.scan_cidr = cidr;
                Task::none()
            }

            Message::ScanPortsChanged(ports) => {
                self.scan_ports_str = ports;
                Task::none()
            }

            Message::ScanTypeSelected(scan_type) => {
                self.scan_type = scan_type;
                Task::none()
            }

            Message::ScanModeSelected(scan_mode) => {
                if scan_mode.is_supported() {
                    self.scan_mode = scan_mode;
                    self.settings_profile.scan_config.scan_mode = scan_mode;
                }
                Task::none()
            }

            // ── Scan Events ─────────────────────────────────────────────
            Message::DeviceDiscovered(device) => {
                self.merge_device(device);
                Task::none()
            }

            Message::DevicesDiscovered(devices) => {
                self.merge_devices(devices);
                Task::none()
            }

            Message::IpcServerStopped(result) => {
                if let Err(e) = result {
                    self.status_message = Some(format!("IPC Server failed: {}", e));
                }
                Task::none()
            }

            Message::IpcCommandReceived(cmd) => {
                self.status_message = Some(format!("Received command: {}", cmd));
                Task::none()
            }

            Message::ScanProgress {
                scanned,
                total,
                target,
            } => {
                self.scan_scanned = scanned;
                self.scan_total = total;
                self.scan_current_target = target;
                if total > 0 {
                    self.scan_progress = scanned as f32 / total as f32;
                }
                Task::none()
            }

            Message::ScanCompleted {
                scan_id,
                device_count,
                duration_ms,
                devices,
                status,
            } => {
                self.is_scanning = false;
                self.is_paused = false;
                self.scan_progress = 1.0;
                self.discovered_devices = devices;
                self.rebuild_findings_cache();
                // Clear the receiver synchronously
                if let Ok(mut guard) = self.event_rx.try_lock() {
                    *guard = None;
                }
                self.update_selected_device_snapshot();
                self.update_filtered_devices();

                // Persist scan to history automatically, then reload history
                let cidr = self.scan_cidr.clone();
                let entry = crate::history::ScanHistoryEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_store_id: Some(scan_id.clone()),
                    scan_id,
                    cidr,
                    device_count,
                    duration_ms,
                    status,
                    timestamp: chrono::Utc::now().timestamp(),
                };

                Task::perform(
                    async move {
                        if let Err(e) = crate::commands::save_scan_history(entry).await {
                            tracing::warn!("Failed to persist scan history: {}", e);
                        }
                        crate::commands::get_scan_history()
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::HistoryLoaded,
                )
            }

            Message::ScanLogReceived {
                level,
                message,
                target,
                timestamp,
            } => {
                self.scan_logs.push(ScanLogEntry {
                    level,
                    message,
                    target,
                    timestamp,
                });
                // Keep only last 200 logs
                if self.scan_logs.len() > 200 {
                    self.scan_logs.remove(0);
                }
                Task::none()
            }

            Message::CveAlertReceived(cve) => {
                self.cve_alerts.push(cve);
                Task::none()
            }

            Message::FindingReceived(finding) => {
                self.merge_finding(finding);
                Task::none()
            }

            Message::FindingsReceived(findings) => {
                for finding in findings {
                    self.merge_finding(finding);
                }
                Task::none()
            }

            Message::ScanStartResult(result) => {
                match result {
                    Ok(scan_id) => {
                        self.scan_logs.push(ScanLogEntry {
                            level: "info".to_string(),
                            message: format!("Scan started: {}", scan_id),
                            target: None,
                            timestamp: chrono::Utc::now().timestamp(),
                        });
                    }
                    Err(e) => {
                        self.is_scanning = false;
                        self.status_message = Some(format!("Scan failed to start: {}", e));
                    }
                }
                Task::none()
            }

            Message::ScanStopResult(result) => {
                self.is_scanning = false;
                self.is_paused = false;
                if let Ok(mut guard) = self.event_rx.try_lock() {
                    *guard = None;
                }
                if let Err(e) = result {
                    self.status_message = Some(format!("Failed to stop scan: {}", e));
                }
                Task::none()
            }

            // ── Device Selection ────────────────────────────────────────
            Message::DeviceSelected(idx) => {
                self.selected_device = idx.and_then(|i| self.filtered_devices.get(i).cloned());
                Task::none()
            }

            // ── Search / Filter / Sort / Theme ─────────────────────────
            Message::SearchQueryChanged(query) => {
                self.search_query = query;
                self.update_filtered_devices();
                Task::none()
            }
            Message::FilterStatusChanged(status) => {
                self.filter_status = status;
                self.update_filtered_devices();
                Task::none()
            }
            Message::FilterHasOpenPortsToggled(val) => {
                self.filter_has_open_ports = val;
                self.update_filtered_devices();
                Task::none()
            }
            Message::FilterHasFindingsToggled(val) => {
                self.filter_has_findings = val;
                self.update_filtered_devices();
                Task::none()
            }
            Message::SortTableBy(field) => {
                if self.sort_field == field {
                    self.sort_direction = match self.sort_direction {
                        SortDirection::Asc => SortDirection::Desc,
                        SortDirection::Desc => SortDirection::Asc,
                    };
                } else {
                    self.sort_field = field;
                    self.sort_direction = SortDirection::Asc;
                }
                self.update_filtered_devices();
                Task::none()
            }
            Message::ClearFilters => {
                self.search_query.clear();
                self.filter_status = "all".to_string();
                self.filter_has_open_ports = false;
                self.filter_has_findings = false;
                self.update_filtered_devices();
                Task::none()
            }
            Message::ToggleTheme => {
                self.theme_dark = !self.theme_dark;
                Task::none()
            }

            // ── Settings ────────────────────────────────────────────────
            Message::SettingsProfilesLoaded(result) => {
                match result {
                    Ok(profiles) => self.settings_profiles = profiles,
                    Err(e) => self.status_message = Some(format!("Failed to load profiles: {}", e)),
                }
                Task::none()
            }

            Message::SettingsLoaded(result) => {
                match result {
                    Ok(profile) => {
                        self.settings_profile = profile.clone();
                        self.scan_mode = if profile.scan_config.scan_mode.is_supported() {
                            profile.scan_config.scan_mode
                        } else {
                            crate::scan_plan::ScanMode::FullAudit
                        };
                        self.settings_profile.scan_config.scan_mode = self.scan_mode;
                        // Sync profile default CIDR if it has been customized
                        if profile.scan_config.default_cidr != "192.168.1.0/24"
                            && !profile.scan_config.default_cidr.is_empty()
                        {
                            self.scan_cidr = profile.scan_config.default_cidr.clone();
                        }
                    }
                    Err(e) => self.status_message = Some(format!("Failed to load settings: {}", e)),
                }
                Task::none()
            }

            Message::SettingsSaved(result) => {
                match result {
                    Ok(()) => self.status_message = Some("Settings saved successfully".to_string()),
                    Err(e) => self.status_message = Some(format!("Failed to save settings: {}", e)),
                }
                Task::none()
            }

            Message::SaveSettings => {
                let profile = self.settings_profile.clone();
                Task::perform(
                    async move {
                        crate::commands::save_profile(profile)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::SettingsSaved,
                )
            }

            Message::ProfileSelected(id) => {
                if let Some(profile) = self.settings_profiles.iter().find(|p| p.id == id).cloned() {
                    self.scan_mode = if profile.scan_config.scan_mode.is_supported() {
                        profile.scan_config.scan_mode
                    } else {
                        crate::scan_plan::ScanMode::FullAudit
                    };
                    self.settings_profile = profile;
                    self.settings_profile.scan_config.scan_mode = self.scan_mode;
                }
                Task::none()
            }

            Message::ProfileCreated => {
                let mut new_profile = SettingsProfile::new("New Profile".to_string());
                new_profile.scan_config = self.settings_profile.scan_config.clone();
                new_profile.ui_preferences = self.settings_profile.ui_preferences.clone();
                self.settings_profile = new_profile.clone();
                self.settings_profiles.push(new_profile.clone());

                Task::perform(
                    async move {
                        crate::commands::save_profile(new_profile)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::SettingsSaved,
                )
            }

            Message::ProfileDeleted(id) => {
                self.settings_profiles.retain(|p| p.id != id);
                Task::perform(
                    async move {
                        crate::commands::delete_profile(id)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    |result| Message::SettingsSaved(result),
                )
            }

            Message::SettingsCidrChanged(val) => {
                self.settings_profile.scan_config.default_cidr = val;
                Task::none()
            }

            Message::SettingsTimeoutChanged(val) => {
                if let Ok(n) = val.parse::<u64>() {
                    self.settings_profile.scan_config.timeout_ms = n;
                }
                Task::none()
            }

            Message::SettingsMaxHostsChanged(val) => {
                if let Ok(n) = val.parse::<usize>() {
                    self.settings_profile.scan_config.max_concurrent_hosts = n;
                }
                Task::none()
            }

            Message::SettingsMaxPortsChanged(val) => {
                if let Ok(n) = val.parse::<usize>() {
                    self.settings_profile.scan_config.max_concurrent_ports = n;
                }
                Task::none()
            }

            Message::SettingsRetryChanged(val) => {
                if let Ok(n) = val.parse::<u32>() {
                    self.settings_profile.scan_config.retry_count = n;
                }
                Task::none()
            }

            Message::SettingsScanPortsToggled(val) => {
                self.settings_profile.scan_config.scan_ports_enabled = val;
                Task::none()
            }

            Message::SettingsTimingTemplateSelected(template) => {
                self.settings_profile.scan_config.timing_template = template;
                Task::none()
            }

            Message::SettingsWebAuditProfileSelected(profile) => {
                self.settings_profile.scan_config.web_audit_profile = profile;
                Task::none()
            }

            Message::SettingsRunActiveChecksToggled(val) => {
                self.settings_profile.scan_config.run_active_checks = val;
                Task::none()
            }

            Message::SettingsDiscoveryMethodToggled(method, enabled) => {
                let methods = &mut self.settings_profile.scan_config.discovery_methods;
                let all = vec![
                    SettingsDiscoveryMethod::ArpTable,
                    SettingsDiscoveryMethod::TcpProbe,
                    SettingsDiscoveryMethod::IcmpPing,
                ];

                if method == "all" {
                    if enabled {
                        *methods = vec![SettingsDiscoveryMethod::All];
                    } else {
                        methods.retain(|m| !matches!(m, SettingsDiscoveryMethod::All));
                    }
                } else {
                    methods.retain(|m| !matches!(m, SettingsDiscoveryMethod::All));
                    let target = match method.as_str() {
                        "arp" => SettingsDiscoveryMethod::ArpTable,
                        "tcp_probe" => SettingsDiscoveryMethod::TcpProbe,
                        "icmp" => SettingsDiscoveryMethod::IcmpPing,
                        _ => SettingsDiscoveryMethod::TcpProbe,
                    };
                    if enabled {
                        if !methods.iter().any(|m| *m == target) {
                            methods.push(target);
                        }
                    } else {
                        methods.retain(|m| *m != target);
                    }
                    if methods.is_empty() {
                        *methods = all;
                    } else if methods.len() == all.len() {
                        *methods = vec![SettingsDiscoveryMethod::All];
                    }
                }
                Task::none()
            }

            Message::SettingsAutoRefreshToggled(val) => {
                self.settings_profile.ui_preferences.auto_refresh = val;
                Task::none()
            }

            Message::SettingsConfirmScanToggled(val) => {
                self.settings_profile.ui_preferences.confirm_before_scan = val;
                Task::none()
            }

            Message::SettingsAdvancedToggled(val) => {
                self.settings_profile.ui_preferences.show_advanced_options = val;
                Task::none()
            }

            Message::SettingsRefreshRateChanged(val) => {
                if let Ok(n) = val.parse::<u64>() {
                    self.settings_profile.ui_preferences.refresh_rate_ms = n;
                }
                Task::none()
            }

            // ── History ─────────────────────────────────────────────────
            Message::HistoryLoaded(result) => {
                match result {
                    Ok(entries) => self.history_entries = entries,
                    Err(e) => self.status_message = Some(format!("Failed to load history: {}", e)),
                }
                Task::none()
            }

            Message::HistoryEntryDeleted(result) => {
                match result {
                    Ok(id) => {
                        self.history_entries.retain(|e| e.id != id);
                    }
                    Err(e) => self.status_message = Some(format!("Failed to delete entry: {}", e)),
                }
                Task::none()
            }

            Message::DeleteHistoryEntry(id) => {
                let id_clone = id.clone();
                Task::perform(
                    async move {
                        crate::commands::delete_scan_history_entry(id)
                            .await
                            .map(|_| id_clone)
                            .map_err(|e| e.to_string())
                    },
                    Message::HistoryEntryDeleted,
                )
            }

            Message::HistoryCleared(result) => {
                match result {
                    Ok(()) => self.history_entries.clear(),
                    Err(e) => self.status_message = Some(format!("Failed to clear history: {}", e)),
                }
                Task::none()
            }

            Message::ClearHistory => Task::perform(
                async {
                    crate::commands::clear_scan_history()
                        .await
                        .map_err(|e| e.to_string())
                },
                Message::HistoryCleared,
            ),

            Message::HistoryEntryToggled(id) => {
                if self.expanded_history.as_deref() == Some(&id) {
                    self.expanded_history = None;
                    self.history_devices.clear();
                    self.history_devices_total = 0;
                    self.history_devices_scan_id = None;
                    self.history_device_detail = None;
                    Task::none()
                } else {
                    self.expanded_history = Some(id.clone());
                    self.history_device_detail = None;

                    if let Some(entry) = self.history_entries.iter().find(|e| e.id == id).cloned() {
                        if let Some(scan_store_id) = entry.scan_store_id {
                            self.history_devices_scan_id = Some(scan_store_id.clone());
                            let scan_id_for_task = scan_store_id.clone();
                            return Task::perform(
                                async move {
                                    crate::commands::get_history_devices_page(
                                        scan_id_for_task.clone(),
                                        50,
                                        0,
                                    )
                                    .await
                                    .map(|page| (scan_id_for_task, page.items, page.total))
                                    .map_err(|e| e.to_string())
                                },
                                Message::HistoryDevicesLoaded,
                            );
                        }
                    }
                    Task::none()
                }
            }

            Message::HistoryDevicesLoaded(result) => {
                match result {
                    Ok((scan_id, devices, total)) => {
                        self.history_devices_scan_id = Some(scan_id);
                        self.history_devices = devices;
                        self.history_devices_total = total;
                    }
                    Err(e) => {
                        self.status_message = Some(format!("Failed to load history devices: {}", e))
                    }
                }
                Task::none()
            }

            Message::HistoryDeviceSelected(ip) => {
                if let Some(scan_id) = self.history_devices_scan_id.clone() {
                    return Task::perform(
                        async move {
                            crate::commands::get_history_device_detail(scan_id, ip)
                                .await
                                .map(|device| {
                                    device.unwrap_or_else(|| Device::new("0.0.0.0".to_string()))
                                })
                                .map_err(|e| e.to_string())
                        },
                        Message::HistoryDeviceDetailLoaded,
                    );
                }
                Task::none()
            }

            Message::HistoryDeviceDetailLoaded(result) => {
                match result {
                    Ok(device) => self.history_device_detail = Some(device),
                    Err(e) => {
                        self.status_message = Some(format!("Failed to load device detail: {}", e))
                    }
                }
                Task::none()
            }

            // ── Baseline ────────────────────────────────────────────────
            Message::BaselinesLoaded(result) => {
                match result {
                    Ok(baselines) => self.baselines = baselines,
                    Err(e) => {
                        self.status_message = Some(format!("Failed to load baselines: {}", e))
                    }
                }
                Task::none()
            }

            Message::BaselineSaveResult(result) => {
                match result {
                    Ok(id) => {
                        self.status_message = Some(format!("Baseline saved: {}", id));
                        self.baseline_name.clear();
                        self.baseline_description.clear();
                    }
                    Err(e) => self.status_message = Some(format!("Failed to save baseline: {}", e)),
                }
                // Reload baselines
                Task::perform(
                    async {
                        crate::commands::get_baselines()
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::BaselinesLoaded,
                )
            }

            Message::SaveBaseline => {
                let baseline = crate::baseline::Baseline {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: self.baseline_name.clone(),
                    description: if self.baseline_description.is_empty() {
                        None
                    } else {
                        Some(self.baseline_description.clone())
                    },
                    devices: self.discovered_devices.clone(),
                    scan_cidr: self.scan_cidr.clone(),
                    created_at: chrono::Utc::now().timestamp(),
                };
                Task::perform(
                    async move {
                        crate::commands::save_baseline(baseline)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::BaselineSaveResult,
                )
            }

            Message::BaselineDeleted(result) => {
                match result {
                    Ok(id) => {
                        self.baselines.retain(|b| b.id != id);
                    }
                    Err(e) => {
                        self.status_message = Some(format!("Failed to delete baseline: {}", e))
                    }
                }
                Task::none()
            }

            Message::DeleteBaseline(id) => {
                let id_clone = id.clone();
                Task::perform(
                    async move {
                        crate::commands::delete_baseline(id)
                            .await
                            .map(|_| id_clone)
                            .map_err(|e| e.to_string())
                    },
                    Message::BaselineDeleted,
                )
            }

            Message::BaselineCompared(result) => {
                match result {
                    Ok(diff) => self.baseline_diff = Some(diff),
                    Err(e) => {
                        self.status_message = Some(format!("Failed to compare baseline: {}", e))
                    }
                }
                Task::none()
            }

            Message::CompareBaseline(id) => {
                let state = self.scan_state.clone();
                Task::perform(
                    async move {
                        crate::commands::compare_baseline(id, state)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::BaselineCompared,
                )
            }

            Message::BaselineNameChanged(name) => {
                self.baseline_name = name;
                Task::none()
            }

            Message::BaselineDescriptionChanged(desc) => {
                self.baseline_description = desc;
                Task::none()
            }

            // ── Topology ────────────────────────────────────────────────
            Message::TopologyRefresh => {
                self.topology_loading = true;
                self.topology_error = None;
                load_topology_graph(self.scan_state.clone())
            }

            Message::TopologyLoaded(result) => {
                self.topology_loading = false;
                match result {
                    Ok(graph) => {
                        self.topology_graph = Some(graph);
                        self.topology_error = None;
                    }
                    Err(e) => {
                        self.topology_error = Some(e);
                    }
                }
                Task::none()
            }

            // ── Export ──────────────────────────────────────────────────
            Message::ExportCsv => {
                let devices = self.discovered_devices.clone();
                Task::perform(
                    async move {
                        crate::commands::export_audit_report("csv".to_string(), devices)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::ExportCompleted,
                )
            }

            Message::ExportJson => {
                let devices = self.discovered_devices.clone();
                Task::perform(
                    async move {
                        crate::commands::export_audit_report("json".to_string(), devices)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::ExportCompleted,
                )
            }

            Message::ExportHtml => {
                let devices = self.discovered_devices.clone();
                Task::perform(
                    async move {
                        if let Some(path) = rfd::AsyncFileDialog::new()
                            .add_filter("HTML Document", &["html"])
                            .set_file_name("netsentinel_report.html")
                            .save_file()
                            .await
                        {
                            let path = path.path().to_path_buf();
                            tokio::task::spawn_blocking(move || {
                                crate::reporting::export::generate_html_report(&devices, &path)
                                    .map_err(|e| e.to_string())
                            })
                            .await
                            .map_err(|e| format!("HTML export task failed: {}", e))??;
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    },
                    Message::ExportCompleted,
                )
            }

            Message::ExportPdf => {
                let devices = self.discovered_devices.clone();
                Task::perform(
                    async move {
                        if let Some(path) = rfd::AsyncFileDialog::new()
                            .add_filter("PDF Document", &["pdf"])
                            .set_file_name("netsentinel_report.pdf")
                            .save_file()
                            .await
                        {
                            let path = path.path().to_path_buf();
                            tokio::task::spawn_blocking(move || {
                                crate::reporting::export::generate_pdf_report(&devices, &path)
                                    .map_err(|e| e.to_string())
                            })
                            .await
                            .map_err(|e| format!("PDF export task failed: {}", e))??;
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    },
                    Message::ExportCompleted,
                )
            }

            Message::ExportCompleted(result) => {
                match result {
                    Ok(true) => {
                        self.status_message = Some("Report exported successfully".to_string())
                    }
                    Ok(false) => self.status_message = Some("Export cancelled".to_string()),
                    Err(e) => self.status_message = Some(format!("Export failed: {}", e)),
                }
                Task::none()
            }

            // ── UI ──────────────────────────────────────────────────────
            Message::StatusDismissed => {
                self.status_message = None;
                Task::none()
            }

            Message::Tick => {
                // No-op, used for triggering re-renders after async state changes
                Task::none()
            }
        }
    }

    /// Render the current view based on the active page
    fn view(&self) -> Element<'_, Message> {
        // Persistent Top Header
        let header = self.view_header();

        // Privilege warning banner if active
        let privilege_banner = self.view_privilege_banner();

        // Main content for active page
        let content: Element<'_, Message> = match self.current_page {
            Page::Dashboard => views::dashboard::view(self),
            Page::Scan => views::scan::view(self),
            Page::Topology => views::topology::view(self),
            Page::Settings => views::settings::view(self),
            Page::History => views::history::view(self),
            Page::Baseline => views::baseline::view(self),
        };

        // Scrollable view content layout containing the tab navigation and active content
        let mut main_column = column![self.view_tab_nav()]
            .spacing(16)
            .width(Length::Fill)
            .height(Length::Fill);

        if let Some(banner) = privilege_banner {
            main_column = main_column.push(banner);
        }

        main_column = main_column.push(content);

        // Put the main content inside a padding container
        let main_content = container(main_column)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill);

        // Global status bar at bottom
        let status_bar = self.view_status();

        let layout = column![header, main_content, status_bar]
            .width(Length::Fill)
            .height(Length::Fill);

        let main_view = container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::app_background);

        if self.show_scan_confirm {
            Stack::new()
                .push(main_view)
                .push(self.view_scan_confirm_modal())
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else {
            main_view.into()
        }
    }

    /// Render the global persistent top header
    fn view_header(&self) -> Element<'_, Message> {
        let logo = iced::widget::image("assets/netSentinel-logo.png")
            .width(Length::Fixed(32.0))
            .height(Length::Fixed(32.0));

        let title = text("NetSentinel").color(theme::PRIMARY).size(20);

        let header_left = row![logo, title]
            .spacing(10)
            .align_y(iced::Alignment::Center);

        let theme_btn = iced::widget::button(
            text(if self.theme_dark { "🌙" } else { "☀️" })
                .size(14)
                .color(theme::TEXT),
        )
        .padding([6, 12])
        .style(theme::secondary_button)
        .on_press(Message::ToggleTheme);

        let header_row = row![
            header_left,
            iced::widget::horizontal_space().width(Length::Fill),
            theme_btn,
        ]
        .padding([12, 20])
        .align_y(iced::Alignment::Center)
        .width(Length::Fill);

        container(header_row)
            .width(Length::Fill)
            .style(theme::header_style)
            .into()
    }

    /// Render the horizontal Tab Navigation bar below the header
    fn view_tab_nav(&self) -> Element<'_, Message> {
        let mut tabs_row = row![].spacing(16).align_y(iced::Alignment::Center);

        for page in Page::all() {
            let is_active = self.current_page == *page;

            // Stack the button and a bottom indicator line in a column
            let tab_element = column![
                iced::widget::button(text(page.label()).size(14))
                    .padding([8, 4])
                    .style(if is_active {
                        theme::active_tab_button
                    } else {
                        theme::tab_button
                    })
                    .on_press(Message::NavigateTo(page.clone())),
                // Active indicator line
                container(iced::widget::horizontal_space().width(Length::Fill))
                    .height(2)
                    .style(move |_theme| {
                        iced::widget::container::Style {
                            background: Some(iced::Background::Color(if is_active {
                                theme::PRIMARY
                            } else {
                                iced::Color::TRANSPARENT
                            })),
                            ..Default::default()
                        }
                    })
            ]
            .width(Length::Shrink)
            .spacing(2);

            tabs_row = tabs_row.push(tab_element);
        }

        // Draw a horizontal divider line under the tabs row
        column![
            tabs_row,
            container(iced::widget::horizontal_space().width(Length::Fill))
                .height(1)
                .style(|_theme| {
                    iced::widget::container::Style {
                        background: Some(iced::Background::Color(theme::BORDER_COLOR)),
                        ..Default::default()
                    }
                })
        ]
        .width(Length::Fill)
        .spacing(4)
        .into()
    }

    /// Render the privilege warning banner globally if active
    fn view_privilege_banner(&self) -> Option<Element<'_, Message>> {
        if let Some(ref caps) = self.platform_caps {
            widgets::privilege_banner(&caps.warnings).map(|c| c.into())
        } else {
            None
        }
    }

    /// Render the status bar at the bottom
    fn view_status(&self) -> Element<'_, Message> {
        let status_text = if let Some(ref msg) = self.status_message {
            text(msg.as_str()).color(theme::TEXT_MUTED).size(12)
        } else if self.is_scanning {
            text(format!(
                "Scanning... {} / {} hosts ({}%)",
                self.scan_scanned,
                self.scan_total,
                (self.scan_progress * 100.0) as u32
            ))
            .color(theme::TEXT_MUTED)
            .size(12)
        } else {
            text("Ready").color(theme::TEXT_MUTED).size(12)
        };

        let mut status_row = row![
            status_text,
            iced::widget::horizontal_space().width(Length::Fill),
        ]
        .padding([8, 20])
        .align_y(iced::Alignment::Center)
        .width(Length::Fill);

        if self.status_message.is_some() {
            status_row = status_row.push(
                iced::widget::button(text("Dismiss").color(theme::TEXT_MUTED).size(11))
                    .padding([2, 8])
                    .style(theme::secondary_button)
                    .on_press(Message::StatusDismissed),
            );
        }

        container(status_row)
            .width(Length::Fill)
            .style(theme::header_style)
            .into()
    }

    /// Render the scan confirmation modal overlay.
    fn view_scan_confirm_modal(&self) -> Element<'_, Message> {
        use iced::widget::{button, column, container, row, text, MouseArea};

        let mut warning_col = column![].spacing(6);
        for warning in &self.scan_confirm_warnings {
            warning_col = warning_col.push(text(warning.clone()).color(theme::WARNING).size(12));
        }

        let content = column![
            text("Confirm Scan").color(theme::TEXT).size(18),
            text(format!("Target: {}", self.scan_cidr))
                .color(theme::TEXT_MUTED)
                .size(13),
            text(format!(
                "Estimated hosts: {}",
                self.scan_confirm_estimated_hosts
            ))
            .color(theme::TEXT_MUTED)
            .size(13),
            text(format!("Scan type: {}", self.scan_type))
                .color(theme::TEXT_MUTED)
                .size(13),
            text(format!("Mode: {}", self.scan_mode))
                .color(theme::TEXT_MUTED)
                .size(13),
            text(format!("Ports: {}", self.scan_confirm_port_summary))
                .color(theme::TEXT_MUTED)
                .size(13),
            text(format!(
                "Estimated work: {} checks — Risk: {}",
                self.scan_confirm_work_units, self.scan_confirm_risk_label
            ))
            .color(theme::TEXT_MUTED)
            .size(13),
            warning_col,
            text("Only scan networks you own or have explicit permission to test.")
                .color(theme::DANGER)
                .size(12),
            row![
                button(text("Cancel").color(theme::TEXT).size(13))
                    .padding([8, 16])
                    .style(theme::secondary_button)
                    .on_press(Message::StartScanCancelled),
                button(text("Start Scan").color(theme::TEXT).size(13))
                    .padding([8, 16])
                    .style(theme::primary_button)
                    .on_press(Message::StartScanConfirmed),
            ]
            .spacing(12)
            .align_y(iced::Alignment::Center),
        ]
        .spacing(12)
        .align_x(iced::Alignment::Center);

        let card = container(content)
            .padding(24)
            .width(Length::Fixed(420.0))
            .style(theme::modal_card_style);

        // Capture events on the card background so they do not propagate to the
        // overlay cancel handler.
        let card_area = MouseArea::new(card).on_press(Message::Tick);

        let overlay = container(
            // Empty space filler that dims the main view.
            iced::widget::horizontal_space().width(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::modal_overlay_style);

        MouseArea::new(
            Stack::new()
                .push(overlay)
                .push(card_area)
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .on_press(Message::StartScanCancelled)
        .into()
    }

    /// Subscribe to backend events when scanning is active and globally for IPC
    fn subscription(&self) -> Subscription<Message> {
        let mut subs = Vec::new();

        // 1. IPC Subscription (Always running)
        let ipc_rx_arc = self.ipc_rx.clone();
        subs.push(Subscription::run_with_id(
            "ipc-events",
            iced::stream::channel(100, move |mut output| async move {
                let mut receiver = ipc_rx_arc.lock().await.take();

                if let Some(ref mut rx) = receiver {
                    let mut buffer = Vec::new();
                    let mut findings_buffer = Vec::new();
                    let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));

                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                if !buffer.is_empty() {
                                    let batch = std::mem::take(&mut buffer);
                                    if output.send(Message::DevicesDiscovered(batch)).await.is_err() {
                                        break;
                                    }
                                }
                                if !findings_buffer.is_empty() {
                                    let batch = std::mem::take(&mut findings_buffer);
                                    if output.send(Message::FindingsReceived(batch)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            event = rx.recv() => {
                                match event {
                                    Some(AppEvent::DeviceFound(device)) => {
                                        buffer.push(device);
                                    }
                                    Some(AppEvent::IpcCommand(cmd)) => {
                                        if output.send(Message::IpcCommandReceived(cmd)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(AppEvent::SecurityAlert { source_tool, severity, title, description, target_artifact, timestamp }) => {
                                        let message = format!("[{}] {}: {} ({})", source_tool, title, description, target_artifact);
                                        if output.send(Message::ScanLogReceived {
                                            level: severity,
                                            message,
                                            target: None,
                                            timestamp,
                                        }).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(AppEvent::FindingFound(finding)) => {
                                        findings_buffer.push(finding);
                                    }
                                    Some(AppEvent::FindingsDiscovered(findings)) => {
                                        findings_buffer.extend(findings);
                                    }
                                    Some(AppEvent::HostLifecycle { host, stage, status, timestamp }) => {
                                        if output.send(Message::ScanLogReceived {
                                            level: "debug".to_string(),
                                            message: format!("Host lifecycle: {} {}", stage, status),
                                            target: Some(host),
                                            timestamp,
                                        }).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(_) => {} // Ignore other events for IPC
                                    None => break, // Channel closed
                                }
                            }
                        }
                    }
                }
            }),
        ));

        // 2. Scanner Subscription
        if self.is_scanning {
            let rx = self.event_rx.clone();
            subs.push(Subscription::run_with_id(
                "scan-events",
                iced::stream::channel(100, move |mut output| async move {
                    let mut receiver = rx.lock().await.take();

                    if let Some(ref mut rx) = receiver {
                        let mut buffer = Vec::new();
                        let mut findings_buffer = Vec::new();
                        let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));

                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                    if !buffer.is_empty() {
                                        let batch = std::mem::take(&mut buffer);
                                        if output.send(Message::DevicesDiscovered(batch)).await.is_err() {
                                            break;
                                        }
                                    }
                                    if !findings_buffer.is_empty() {
                                        let batch = std::mem::take(&mut findings_buffer);
                                        if output.send(Message::FindingsReceived(batch)).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                event = rx.recv() => {
                                    match event {
                                        Some(AppEvent::DeviceFound(device)) => {
                                            buffer.push(device);
                                        }
                                        Some(AppEvent::ScanProgress { scanned, total, current_target }) => {
                                            if output.send(Message::ScanProgress { scanned, total, target: current_target }).await.is_err() { break; }
                                        }
                                        Some(AppEvent::ScanComplete { scan_id, device_count, duration_ms, status, devices }) => {
                                            if !buffer.is_empty() {
                                                let batch = std::mem::take(&mut buffer);
                                                let _ = output.send(Message::DevicesDiscovered(batch)).await;
                                            }
                                            if !findings_buffer.is_empty() {
                                                let batch = std::mem::take(&mut findings_buffer);
                                                let _ = output.send(Message::FindingsReceived(batch)).await;
                                            }
                                            if output.send(Message::ScanCompleted { scan_id, device_count, duration_ms, devices, status }).await.is_err() { break; }
                                        }
                                        Some(AppEvent::ScanLog { level, message, target, timestamp }) => {
                                            if output.send(Message::ScanLogReceived { level, message, target, timestamp }).await.is_err() { break; }
                                        }
                                        Some(AppEvent::CveAlert(cve)) => {
                                            if output.send(Message::CveAlertReceived(cve)).await.is_err() { break; }
                                        }
                                        Some(AppEvent::FindingFound(finding)) => {
                                            findings_buffer.push(finding);
                                        }
                                        Some(AppEvent::FindingsDiscovered(findings)) => {
                                            findings_buffer.extend(findings);
                                        }
                                        Some(AppEvent::HostLifecycle { host, stage, status, timestamp }) => {
                                            if output.send(Message::ScanLogReceived {
                                                level: "debug".to_string(),
                                                message: format!("Host lifecycle: {} {}", stage, status),
                                                target: Some(host),
                                                timestamp,
                                            }).await.is_err() { break; }
                                        }
                                        Some(_) => {}
                                        None => break,
                                    }
                                }
                            }
                        }
                    }
                }),
            ));
        }

        Subscription::batch(subs)
    }
}

// ── Async Helper Functions ──────────────────────────────────────────────

/// Load device information
fn load_device_info() -> Task<Message> {
    Task::perform(
        async {
            crate::commands::get_device_info()
                .await
                .map_err(|e| e.to_string())
        },
        Message::DeviceInfoLoaded,
    )
}

/// Load network information
fn load_network_info() -> Task<Message> {
    Task::perform(
        async {
            crate::commands::get_network_info()
                .await
                .map_err(|e| e.to_string())
        },
        Message::NetworkInfoLoaded,
    )
}

/// Load privilege status
fn load_privilege_status() -> Task<Message> {
    Task::perform(
        async {
            crate::commands::check_privilege_status()
                .await
                .map_err(|e| e.to_string())
        },
        Message::PrivilegeLoaded,
    )
}

/// Load platform capabilities
fn load_platform_caps() -> Task<Message> {
    Task::perform(
        async { crate::commands::get_platform_capabilities() },
        Message::PlatformCapsLoaded,
    )
}

/// Load current settings
fn load_settings() -> Task<Message> {
    Task::perform(
        async {
            crate::commands::load_settings()
                .await
                .map_err(|e| e.to_string())
        },
        Message::SettingsLoaded,
    )
}

/// Load settings profiles
fn load_settings_profiles() -> Task<Message> {
    Task::perform(
        async {
            crate::commands::get_settings_profiles()
                .await
                .map_err(|e| e.to_string())
        },
        Message::SettingsProfilesLoaded,
    )
}

/// Load scan history
fn load_history() -> Task<Message> {
    Task::perform(
        async {
            crate::commands::get_scan_history()
                .await
                .map_err(|e| e.to_string())
        },
        Message::HistoryLoaded,
    )
}

/// Load baselines
fn load_baselines() -> Task<Message> {
    Task::perform(
        async {
            crate::commands::get_baselines()
                .await
                .map_err(|e| e.to_string())
        },
        Message::BaselinesLoaded,
    )
}

/// Load the current topology graph from shared scan state.
fn load_topology_graph(state: Arc<SharedScanState>) -> Task<Message> {
    Task::perform(
        async move {
            crate::commands::build_current_topology(state)
                .await
                .map_err(|e| e.to_string())
        },
        Message::TopologyLoaded,
    )
}

/// Calculate a /24 CIDR from an IP address
pub(crate) fn calculate_cidr(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        "192.168.1.0/24".to_string()
    }
}

// ── Application Entry Point ─────────────────────────────────────────────

/// Launch the NetSentinel Iced application
pub fn run() -> iced::Result {
    iced::application("NetSentinel", NetSentinelApp::update, NetSentinelApp::view)
        .subscription(NetSentinelApp::subscription)
        .run_with(NetSentinelApp::new)
}
