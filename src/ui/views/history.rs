//! History view — scan history table with expandable entries.

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Length};

use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

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
                let mut detail_col = column![].spacing(4);

                detail_col = detail_col.push(
                    text(format!("Scan ID: {}", entry.scan_id))
                        .color(TEXT_MUTED)
                        .size(11),
                );

                if entry.devices.is_empty() {
                    detail_col = detail_col
                        .push(text("No devices in this scan.").color(TEXT_MUTED).size(11));
                } else {
                    for device in &entry.devices {
                        let hostname = device.hostname.as_deref().unwrap_or("-");
                        let port_count = device.ports.len();
                        detail_col = detail_col.push(
                            text(format!(
                                "  {} ({}) — {} ports — {:?}",
                                device.ip, hostname, port_count, device.status
                            ))
                            .color(TEXT)
                            .size(11),
                        );
                    }
                }

                let detail_container = container(detail_col)
                    .padding([8, 16])
                    .width(Length::Fill)
                    .style(theme::card_style);

                history_list = history_list.push(detail_container);
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
