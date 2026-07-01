//! History view — scan history table with expandable entries.
//!
//! Expanded entries load device summaries paginated from the linked
//! `ScanStore` session rather than reading embedded device vectors.

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Length};

use crate::history_adapter::format_port_preview;
use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

const HISTORY_DEVICE_PAGE_SIZE: u32 = 50;

/// Render the History page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).width(Length::Fill);

    // ── Header with controls ────────────────────────────────────────────
    let mut header = row![
        text("Scan History").color(TEXT).size(18),
        iced::widget::horizontal_space().width(Length::Fill),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    if !app.history_entries.is_empty() {
        header = header.push(
            button(text("Clear All").color(TEXT).size(12))
                .padding([4, 12])
                .style(theme::danger_button)
                .on_press(Message::ClearHistory),
        );
    }

    content = content.push(header);

    // ── History Table ───────────────────────────────────────────────────
    let mut history_list = column![].spacing(4);

    if app.history_entries.is_empty() {
        history_list = history_list.push(
            container(
                text("No scan history yet. Completed scans will appear here.")
                    .color(TEXT_MUTED)
                    .size(13),
            )
            .padding(20)
            .width(Length::Fill),
        );
    } else {
        // Table header
        history_list = history_list.push(
            row![
                text("Date")
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(2)),
                text("CIDR")
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(2)),
                text("Devices")
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(1)),
                text("Duration")
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(1)),
                text("Status")
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(1)),
                text("")
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(8)
            .padding([4, 8])
            .width(Length::Fill),
        );

        for entry in &app.history_entries {
            let is_expanded = app.expanded_history.as_deref() == Some(&entry.id);

            // Format timestamp
            let date_str = format_timestamp(entry.timestamp);
            let duration_str = format_duration(entry.duration_ms);
            let status_str = entry.status.clone();

            let expand_btn = button(
                text(if is_expanded { "▼" } else { "▶" })
                    .color(TEXT_MUTED)
                    .size(10),
            )
            .padding([2, 6])
            .style(theme::secondary_button)
            .on_press(Message::HistoryEntryToggled(entry.id.clone()));

            let delete_btn = button(text("✕").color(TEXT_MUTED).size(10))
                .padding([2, 6])
                .style(theme::danger_button)
                .on_press(Message::DeleteHistoryEntry(entry.id.clone()));

            let entry_row = row![
                text(date_str)
                    .color(TEXT)
                    .size(11)
                    .width(Length::FillPortion(2)),
                text(&entry.cidr)
                    .color(TEXT)
                    .size(11)
                    .width(Length::FillPortion(2)),
                text(format!("{}", entry.device_count))
                    .color(TEXT)
                    .size(11)
                    .width(Length::FillPortion(1)),
                text(duration_str)
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(1)),
                widgets::status_badge(&status_str).width(Length::FillPortion(1)),
                row![expand_btn, delete_btn]
                    .spacing(4)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(8)
            .padding([4, 8])
            .align_y(Alignment::Center)
            .width(Length::Fill);

            history_list = history_list.push(entry_row);

            // Expanded detail
            if is_expanded {
                history_list = history_list.push(view_expanded_detail(app, entry));
            }
        }
    }

    let history_card = container(scrollable(history_list).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill);

    content = content.push(history_card);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::app_background)
        .into()
}

fn view_expanded_detail<'a>(
    app: &'a NetSentinelApp,
    entry: &'a crate::history::ScanHistoryEntry,
) -> iced::Element<'a, Message> {
    let mut detail_col = column![].spacing(8);

    detail_col = detail_col.push(
        row![
            text(format!("Scan ID: {}", entry.scan_id))
                .color(TEXT_MUTED)
                .size(11),
            iced::widget::horizontal_space().width(Length::Fill),
        ]
        .width(Length::Fill),
    );

    let devices_for_entry =
        if app.history_devices_scan_id.as_deref() == entry.scan_store_id.as_deref() {
            &app.history_devices[..]
        } else {
            &[]
        };

    if devices_for_entry.is_empty() {
        detail_col = detail_col.push(
            text("No devices loaded for this scan.")
                .color(TEXT_MUTED)
                .size(11),
        );
    } else {
        detail_col = detail_col.push(
            text(format!(
                "Devices {} of {}",
                devices_for_entry.len(),
                app.history_devices_total
            ))
            .color(TEXT_MUTED)
            .size(11),
        );

        for summary in devices_for_entry {
            let hostname = summary.hostname.as_deref().unwrap_or("-");
            let selected = app
                .history_device_detail
                .as_ref()
                .map(|d| d.ip == summary.ip)
                .unwrap_or(false);

            let row_btn = button(
                row![text(format!(
                    "{} ({}) — {} open / {} ports — {} findings",
                    summary.ip,
                    hostname,
                    summary.open_port_count,
                    summary.port_count,
                    summary.finding_count
                ))
                .color(if selected { theme::INFO } else { TEXT })
                .size(11)
                .width(Length::Fill),]
                .width(Length::Fill),
            )
            .padding([4, 8])
            .style(if selected {
                theme::active_tab_button
            } else {
                theme::secondary_button
            })
            .on_press(Message::HistoryDeviceSelected(summary.ip.clone()));

            detail_col = detail_col.push(row_btn);
        }

        if app.history_devices_total > HISTORY_DEVICE_PAGE_SIZE
            && devices_for_entry.len() < app.history_devices_total as usize
        {
            detail_col = detail_col.push(
                text(format!(
                    "Showing first {} of {} devices.",
                    devices_for_entry.len(),
                    app.history_devices_total
                ))
                .color(TEXT_MUTED)
                .size(10),
            );
        }
    }

    if let Some(device) = &app.history_device_detail {
        detail_col = detail_col.push(view_device_detail(device));
    }

    container(detail_col)
        .padding([8, 16])
        .width(Length::Fill)
        .style(theme::card_style)
        .into()
}

fn view_device_detail(device: &crate::types::Device) -> iced::Element<'_, Message> {
    let mut detail_col = column![].spacing(6);

    detail_col = detail_col.push(
        row![
            text("Device Detail").color(TEXT).size(12),
            iced::widget::horizontal_space().width(Length::Fill),
        ]
        .width(Length::Fill),
    );

    detail_col = detail_col.push(
        text(format!(
            "IP: {}    MAC: {}    Status: {:?}",
            device.ip, device.mac, device.status
        ))
        .color(TEXT)
        .size(11),
    );

    if let Some(hostname) = &device.hostname {
        detail_col = detail_col.push(text(format!("Hostname: {}", hostname)).color(TEXT).size(11));
    }
    if let Some(vendor) = &device.vendor {
        detail_col = detail_col.push(text(format!("Vendor: {}", vendor)).color(TEXT).size(11));
    }
    if let Some(os) = &device.os {
        detail_col = detail_col.push(text(format!("OS: {}", os)).color(TEXT).size(11));
    }

    if !device.ports.is_empty() {
        detail_col = detail_col.push(text("Open ports:").color(TEXT_MUTED).size(11));
        for port in device
            .ports
            .iter()
            .filter(|p| p.state == crate::types::PortState::Open)
        {
            detail_col = detail_col.push(
                text(format!("  {}", format_port_preview(port)))
                    .color(TEXT)
                    .size(10),
            );
        }
    }

    if !device.findings.is_empty() {
        detail_col = detail_col.push(
            text(format!("Findings: {}", device.findings.len()))
                .color(TEXT_MUTED)
                .size(11),
        );
    }

    container(detail_col)
        .padding(8)
        .width(Length::Fill)
        .style(theme::table_container_style)
        .into()
}

/// Format a Unix timestamp into a human-readable date string.
fn format_timestamp(ts: i64) -> String {
    let dt = chrono::DateTime::from_timestamp(ts, 0);
    match dt {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "Invalid date".to_string(),
    }
}

/// Format milliseconds into a human-readable duration.
fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{}m {}s", mins, secs)
    }
}
