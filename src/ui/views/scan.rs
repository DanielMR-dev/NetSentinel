//! Scan view — configuration panel, progress bar, results table,
//! device detail panel, and scan logs.

use iced::{Alignment, Length};
use iced::widget::{
    button, column, container, pick_list, progress_bar, row, scrollable, text, text_input,
};

use crate::types::ScanType;
use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

/// Render the Scan page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).padding(20).width(Length::Fill);

    // ── Configuration Panel ─────────────────────────────────────────────
    let cidr_input = text_input("Target CIDR (e.g. 192.168.1.0/24)", &app.scan_cidr)
        .on_input(Message::ScanCidrChanged)
        .padding(8)
        .size(14);

    let ports_input = text_input("Ports (comma-separated, e.g. 22,80,443)", &app.scan_ports_str)
        .on_input(Message::ScanPortsChanged)
        .padding(8)
        .size(14);

    let scan_type_picker = pick_list(
        &ScanType::all_types()[..],
        Some(app.scan_type.clone()),
        Message::ScanTypeSelected,
    )
    .padding(8)
    .text_size(14);

    let config_row = row![
        column![
            text("Target CIDR").color(TEXT_MUTED).size(12),
            cidr_input,
        ]
        .spacing(4)
        .width(Length::FillPortion(3)),
        column![
            text("Ports").color(TEXT_MUTED).size(12),
            ports_input,
        ]
        .spacing(4)
        .width(Length::FillPortion(2)),
        column![
            text("Scan Type").color(TEXT_MUTED).size(12),
            scan_type_picker,
        ]
        .spacing(4)
        .width(Length::FillPortion(1)),
    ]
    .spacing(12)
    .align_y(Alignment::End);

    // ── Control Buttons ─────────────────────────────────────────────────
    let start_btn = button(text("Start Scan").color(TEXT).size(14))
        .padding([8, 20])
        .style(theme::primary_button)
        .on_press(Message::StartScan);

    let stop_btn = button(text("Stop").color(TEXT).size(14))
        .padding([8, 16])
        .style(theme::danger_button)
        .on_press(Message::StopScan);

    let pause_btn = if app.is_paused {
        button(text("Resume").color(TEXT).size(14))
            .padding([8, 16])
            .style(theme::success_button)
            .on_press(Message::ResumeScan)
    } else {
        button(text("Pause").color(TEXT).size(14))
            .padding([8, 16])
            .style(theme::secondary_button)
            .on_press(Message::PauseScan)
    };

    let mut controls = row![].spacing(8).align_y(Alignment::Center);

    if app.is_scanning {
        controls = controls.push(pause_btn).push(stop_btn);
    } else {
        controls = controls.push(start_btn);
    }

    let config_card = widgets::card(
        Some("Scan Configuration"),
        column![config_row, controls.spacing(8)]
            .spacing(12)
            .width(Length::Fill),
    );

    content = content.push(config_card);

    // ── Progress Section ────────────────────────────────────────────────
    if app.is_scanning {
        let progress_pct = (app.scan_progress * 100.0) as u32;
        let progress_text = text(format!(
            "{}% — {} / {} hosts — Current: {}",
            progress_pct,
            app.scan_scanned,
            app.scan_total,
            if app.scan_current_target.is_empty() {
                "initializing..."
            } else {
                &app.scan_current_target
            }
        ))
        .color(TEXT_MUTED)
        .size(12);

        let progress_bar_widget = progress_bar(0.0..=1.0, app.scan_progress)
            .height(8);

        let progress_card = widgets::card(
            Some("Scan Progress"),
            column![progress_bar_widget, progress_text]
                .spacing(8)
                .width(Length::Fill),
        );

        content = content.push(progress_card);
    }

    // ── Results Table ───────────────────────────────────────────────────
    let device_count = app.discovered_devices.len();
    let mut results_list = column![].spacing(2);

    if app.discovered_devices.is_empty() {
        results_list = results_list.push(
            text(if app.is_scanning {
                "Scanning in progress... devices will appear here."
            } else {
                "No devices discovered. Configure and start a scan."
            })
            .color(TEXT_MUTED)
            .size(13),
        );
    } else {
        // Header
        results_list = results_list.push(
            row![
                text("IP").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("MAC").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("Hostname").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("Vendor").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("OS").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("Status").color(TEXT_MUTED).size(11).width(Length::FillPortion(1)),
                text("Ports").color(TEXT_MUTED).size(11).width(Length::FillPortion(1)),
            ]
            .spacing(4)
            .padding([4, 8])
            .width(Length::Fill),
        );

        for device in &app.discovered_devices {
            let hostname = device.hostname.as_deref().unwrap_or("-");
            let vendor = device.vendor.as_deref().unwrap_or("-");
            let os = device.os.as_deref().unwrap_or("-");
            let status_str = format!("{:?}", device.status);
            let port_count = device.ports.len();

            let device_row = row![
                text(&device.ip).color(TEXT).size(11).width(Length::FillPortion(2)),
                text(&device.mac).color(TEXT).size(11).width(Length::FillPortion(2)),
                text(hostname).color(TEXT).size(11).width(Length::FillPortion(2)),
                text(vendor).color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text(os).color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                widgets::status_badge(&status_str).width(Length::FillPortion(1)),
                text(format!("{}", port_count))
                    .color(TEXT)
                    .size(11)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(4)
            .padding([3, 8])
            .align_y(Alignment::Center)
            .width(Length::Fill);

            results_list = results_list.push(device_row);
        }
    }

    let results_title = format!("Scan Results ({})", device_count);
    let results_card = widgets::card(
        Some(&results_title),
        scrollable(results_list).height(Length::Fixed(250.0)),
    );

    content = content.push(results_card);

    // ── Device Detail Panel ─────────────────────────────────────────────
    if let Some(ref device) = app.selected_device {
        let mut detail_col = column![].spacing(6);

        detail_col = detail_col.push(widgets::info_row("IP:", device.ip.clone()));
        detail_col = detail_col.push(widgets::info_row("MAC:", device.mac.clone()));
        detail_col = detail_col.push(widgets::info_row(
            "Hostname:",
            device.hostname.clone().unwrap_or_else(|| "-".to_string()),
        ));
        detail_col = detail_col.push(widgets::info_row(
            "Vendor:",
            device.vendor.clone().unwrap_or_else(|| "-".to_string()),
        ));
        detail_col = detail_col.push(widgets::info_row(
            "OS:",
            device.os.clone().unwrap_or_else(|| "-".to_string()),
        ));
        detail_col = detail_col.push(widgets::info_row(
            "Status:",
            format!("{:?}", device.status),
        ));

        // Ports list
        if !device.ports.is_empty() {
            detail_col = detail_col.push(text("Ports:").color(TEXT_MUTED).size(12));
            let mut ports_row = row![].spacing(4);
            for port in &device.ports {
                let svc = port.service.as_deref();
                let state_str = format!("{:?}", port.state);
                ports_row = ports_row.push(widgets::port_badge(port.number, &state_str, svc));
            }
            detail_col = detail_col.push(ports_row);
        }

        // Banner results
        if !device.banner_results.is_empty() {
            detail_col = detail_col.push(text("Banners:").color(TEXT_MUTED).size(12));
            for banner in &device.banner_results {
                let banner_text = format!(
                    "  {}/{}: {} ({})",
                    banner.ip,
                    banner.port,
                    banner.service.as_deref().unwrap_or("unknown"),
                    &banner.banner[..banner.banner.len().min(60)]
                );
                detail_col = detail_col.push(text(banner_text).color(TEXT_MUTED).size(11));
            }
        }

        let detail_card = widgets::card(Some("Device Detail"), detail_col);
        content = content.push(detail_card);
    }

    // ── Scan Logs ───────────────────────────────────────────────────────
    let mut logs_list = column![].spacing(2);

    if app.scan_logs.is_empty() {
        logs_list = logs_list.push(
            text("No scan logs yet.")
                .color(TEXT_MUTED)
                .size(12),
        );
    } else {
        // Show last 50 logs
        let start = if app.scan_logs.len() > 50 {
            app.scan_logs.len() - 50
        } else {
            0
        };
        for log in &app.scan_logs[start..] {
            let level_color = match log.level.as_str() {
                "error" => crate::ui::theme::DANGER,
                "warn" => crate::ui::theme::WARNING,
                "info" => crate::ui::theme::INFO,
                _ => TEXT_MUTED,
            };
            let log_text = format!(
                "[{}] [{}] {}",
                log.level.to_uppercase(),
                log.target.as_deref().unwrap_or("-"),
                log.message
            );
            logs_list = logs_list.push(text(log_text).color(level_color).size(11));
        }
    }

    let logs_card = widgets::card(
        Some("Scan Logs"),
        scrollable(logs_list).height(Length::Fixed(150.0)),
    );

    content = content.push(logs_card);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
            .style(theme::app_background)
        .into()
}
