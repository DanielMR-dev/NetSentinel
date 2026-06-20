//! Dashboard view — system overview, network info, CVE summary, device list.

use iced::{Alignment, Length};
use iced::widget::{column, container, row, scrollable, text};

use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

/// Render the Dashboard page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).padding(20).width(Length::Fill);

    // ── Privilege Banner ────────────────────────────────────────────────
    if let Some(ref caps) = app.platform_caps {
        if let Some(banner) = widgets::privilege_banner(&caps.warnings) {
            content = content.push(banner);
        }
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

    // ── CVE Summary Card ────────────────────────────────────────────────
    let cve_count = app.cve_alerts.len();
    let critical_count = app
        .cve_alerts
        .iter()
        .filter(|c| matches!(c.severity, crate::network::cve::CveSeverity::Critical))
        .count();
    let high_count = app
        .cve_alerts
        .iter()
        .filter(|c| matches!(c.severity, crate::network::cve::CveSeverity::High))
        .count();

    let cve_content = if cve_count == 0 {
        column![text("No CVE alerts").color(TEXT_MUTED).size(13)]
    } else {
        column![
            row![
                text(format!("Total: {}", cve_count)).color(TEXT).size(13),
                iced::widget::horizontal_space().width(Length::Fixed(16.0)),
                text(format!("Critical: {}", critical_count))
                    .color(crate::ui::theme::DANGER)
                    .size(13),
                iced::widget::horizontal_space().width(Length::Fixed(16.0)),
                text(format!("High: {}", high_count))
                    .color(crate::ui::theme::WARNING)
                    .size(13),
            ]
            .spacing(0),
        ]
        .spacing(6)
    };

    let cve_card = widgets::card(Some("CVE Summary"), cve_content);
    content = content.push(cve_card);

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
                text("IP Address").color(TEXT_MUTED).size(12).width(Length::FillPortion(2)),
                text("MAC").color(TEXT_MUTED).size(12).width(Length::FillPortion(2)),
                text("Hostname").color(TEXT_MUTED).size(12).width(Length::FillPortion(2)),
                text("Status").color(TEXT_MUTED).size(12).width(Length::FillPortion(1)),
                text("Ports").color(TEXT_MUTED).size(12).width(Length::FillPortion(1)),
            ]
            .spacing(8)
            .padding([4, 8])
            .width(Length::Fill),
        );

        for device in &app.discovered_devices {
            let hostname = device
                .hostname
                .as_deref()
                .unwrap_or("-");
            let status_str = format!("{:?}", device.status);
            let port_count = device.ports.len();

            let device_row = row![
                text(&device.ip).color(TEXT).size(12).width(Length::FillPortion(2)),
                text(&device.mac).color(TEXT).size(12).width(Length::FillPortion(2)),
                text(hostname).color(TEXT).size(12).width(Length::FillPortion(2)),
                widgets::status_badge(&status_str).width(Length::FillPortion(1)),
                text(format!("{}", port_count)).color(TEXT).size(12).width(Length::FillPortion(1)),
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
