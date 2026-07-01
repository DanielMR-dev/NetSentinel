//! Dashboard view — system overview, network info, CVE summary, device list.

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Length};

use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{GuidedScanProfile, Message, NetSentinelApp};

/// Render the first-use Quick Start card shown on the Dashboard.
fn quick_start_card(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut info_col = column![].spacing(6);

    if let Some(ref net) = app.network_info {
        if !net.network_name.is_empty() && net.network_name != "Unknown" {
            info_col = info_col.push(widgets::info_row("Interface:", net.network_name.clone()));
        }
        if !net.ip_address.is_empty() && net.ip_address != "Unknown" {
            let network = crate::ui::calculate_cidr(&net.ip_address);
            info_col = info_col.push(widgets::info_row("Local IP:", net.ip_address.clone()));
            info_col = info_col.push(widgets::info_row("Local Network:", network));
        }
    }

    if let Some(ref caps) = app.platform_caps {
        let privilege_text = if caps.is_elevated {
            "Elevated (raw sockets available)".to_string()
        } else {
            "Standard user (some scans will be limited)".to_string()
        };
        info_col = info_col.push(widgets::info_row("Permissions:", privilege_text));
    }

    let scan_btn = button(text("Scan current network").color(TEXT).size(13))
        .padding([8, 16])
        .style(theme::primary_button)
        .on_press(Message::QuickStartScanCurrentNetwork);

    let advanced_btn = button(text("Advanced scan").color(TEXT).size(13))
        .padding([8, 16])
        .style(theme::secondary_button)
        .on_press(Message::QuickStartAdvancedScan);

    let mut profile_row = row![text("Guided:").color(TEXT_MUTED).size(12)]
        .spacing(6)
        .align_y(Alignment::Center);
    for profile in GuidedScanProfile::all() {
        profile_row = profile_row.push(
            button(text(profile.label()).size(11).color(TEXT))
                .padding([4, 8])
                .style(theme::secondary_button)
                .on_press(Message::ApplyGuidedProfile(*profile)),
        );
    }

    let content = column![
        text("Welcome to NetSentinel").color(TEXT).size(16),
        text("Start by scanning your local network or choose a guided profile.")
            .color(TEXT_MUTED)
            .size(13),
        info_col,
        row![scan_btn, advanced_btn]
            .spacing(12)
            .align_y(Alignment::Center),
        profile_row,
    ]
    .spacing(12);

    widgets::card(Some("Quick Start"), content).into()
}

/// Render the Dashboard page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).width(Length::Fill);

    // ── CVE Warning Banner (placed at the top if alerts exist) ──────────
    if !app.cve_alerts.is_empty() {
        let unique_hosts: std::collections::HashSet<&str> =
            app.cve_alerts.iter().map(|a| a.ip.as_str()).collect();
        let total = app.cve_alerts.len();
        let host_count = unique_hosts.len();

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for alert in &app.cve_alerts {
            match alert.severity {
                crate::network::cve::CveSeverity::Critical => critical_count += 1,
                crate::network::cve::CveSeverity::High => high_count += 1,
                crate::network::cve::CveSeverity::Medium => medium_count += 1,
                crate::network::cve::CveSeverity::Low => low_count += 1,
            }
        }

        let mut severity_row = row![].spacing(16);
        if critical_count > 0 {
            severity_row = severity_row.push(
                text(format!("{} critical", critical_count))
                    .color(theme::DANGER)
                    .size(12),
            );
        }
        if high_count > 0 {
            severity_row = severity_row.push(
                text(format!("{} high", high_count))
                    .color(theme::WARNING)
                    .size(12),
            );
        }
        if medium_count > 0 {
            severity_row = severity_row.push(
                text(format!("{} medium", medium_count))
                    .color(theme::WARNING)
                    .size(12),
            );
        }
        if low_count > 0 {
            severity_row = severity_row.push(
                text(format!("{} low", low_count))
                    .color(theme::INFO)
                    .size(12),
            );
        }

        let banner_text = format!(
            "{} vulnerabilit{} detected across {} host{}",
            total,
            if total == 1 { "y" } else { "ies" },
            host_count,
            if host_count == 1 { "" } else { "s" }
        );

        let banner_col = column![
            row![
                text("⚠️").size(16),
                text(banner_text).color(theme::TEXT).size(14),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            severity_row
        ]
        .spacing(6)
        .width(Length::Fill);

        let cve_banner = container(banner_col)
            .padding(14)
            .width(Length::Fill)
            .style(theme::cve_banner_style);

        content = content.push(cve_banner);
    }

    // ── System Info Card ────────────────────────────────────────────────
    let device_info_content = if let Some(ref info) = app.device_info {
        column![
            widgets::info_row("Hostname:", info.hostname.clone()),
            widgets::info_row("OS:", format!("{} {}", info.os_name, info.os_version)),
            widgets::info_row("Uptime:", info.uptime.clone()),
        ]
        .spacing(6)
    } else {
        column![widgets::loading_spinner("Loading device info...")]
    };

    let device_card = widgets::card(Some("System Information"), device_info_content);

    // ── Network Info Card ───────────────────────────────────────────────
    let network_info_content = if let Some(ref info) = app.network_info {
        column![
            widgets::info_row("IP Address:", info.ip_address.clone()),
            widgets::info_row("MAC Address:", info.mac_address.clone()),
            widgets::info_row("Gateway:", info.gateway.clone()),
            widgets::info_row("Interface:", info.network_name.clone()),
        ]
        .spacing(6)
    } else {
        column![widgets::loading_spinner("Loading network info...")]
    };

    let network_card = widgets::card(Some("Network Information"), network_info_content);

    // ── Top row: two cards side by side ─────────────────────────────────
    let info_row = row![device_card, network_card]
        .spacing(16)
        .width(Length::Fill);

    content = content.push(info_row);

    // ── Quick Start Card (first use) ────────────────────────────────────
    if app.history_entries.is_empty() && !app.is_scanning {
        content = content.push(quick_start_card(app));
    }

    // ── Discovered Devices Card ─────────────────────────────────────────
    let device_count = app.discovered_devices.len();
    let mut device_list = column![].spacing(4);

    if app.discovered_devices.is_empty() {
        device_list = device_list.push(
            text("No devices discovered yet. Start a scan from the Scan tab.")
                .color(TEXT_MUTED)
                .size(13),
        );
    } else {
        // Header row
        device_list = device_list.push(
            row![
                text("IP Address")
                    .color(TEXT_MUTED)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text("MAC")
                    .color(TEXT_MUTED)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text("Hostname")
                    .color(TEXT_MUTED)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text("Status")
                    .color(TEXT_MUTED)
                    .size(12)
                    .width(Length::FillPortion(1)),
                text("Ports")
                    .color(TEXT_MUTED)
                    .size(12)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(8)
            .padding([4, 8])
            .width(Length::Fill),
        );

        for device in &app.discovered_devices {
            let hostname = device.hostname.as_deref().unwrap_or("-");
            let status_str = format!("{:?}", device.status);
            let port_count = device.ports.len();

            let device_row = row![
                text(&device.ip)
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(&device.mac)
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(hostname)
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(2)),
                widgets::status_badge(&status_str).width(Length::FillPortion(1)),
                text(format!("{}", port_count))
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(8)
            .padding([4, 8])
            .align_y(Alignment::Center)
            .width(Length::Fill);

            device_list = device_list.push(device_row);
        }
    }

    let device_card_title = format!("Discovered Devices ({})", device_count);
    let device_card = widgets::card(
        Some(device_card_title),
        scrollable(device_list).height(Length::Fixed(300.0)),
    );

    content = content.push(device_card);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::app_background)
        .into()
}
