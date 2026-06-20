//! Baseline view — create form, baseline list, diff view.

use iced::{Alignment, Length};
use iced::widget::{button, column, container, row, scrollable, text, text_input};

use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

/// Render the Baseline page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).padding(20).width(Length::Fill);

    // ── Create Baseline Form ────────────────────────────────────────────
    let name_input = text_input("Baseline name", &app.baseline_name)
        .on_input(Message::BaselineNameChanged)
        .padding(8)
        .size(13);

    let desc_input = text_input("Description (optional)", &app.baseline_description)
        .on_input(Message::BaselineDescriptionChanged)
        .padding(8)
        .size(13);

    let save_btn = button(text("Save Baseline").color(TEXT).size(13))
        .padding([6, 14])
        .style(theme::PrimaryButton)
        .on_press(Message::BaselineSaved);

    let create_card = widgets::card(
        Some("Create Baseline from Current Scan"),
        column![
            row![
                column![
                    text("Name").color(TEXT_MUTED).size(11),
                    name_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(1)),
                column![
                    text("Description").color(TEXT_MUTED).size(11),
                    desc_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(2)),
            ]
            .spacing(12)
            .align_items(Alignment::End),
            save_btn,
        ]
        .spacing(10),
    );

    content = content.push(create_card);

    // ── Baseline List ───────────────────────────────────────────────────
    let mut baseline_list = column![].spacing(4);

    if app.baselines.is_empty() {
        baseline_list = baseline_list.push(
            text("No baselines saved yet. Run a scan and save a baseline above.")
                .color(TEXT_MUTED)
                .size(13),
        );
    } else {
        // Header
        baseline_list = baseline_list.push(
            row![
                text("Name").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("CIDR").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("Devices").color(TEXT_MUTED).size(11).width(Length::FillPortion(1)),
                text("Created").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
                text("Actions").color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
            ]
            .spacing(8)
            .padding([4, 8])
            .width(Length::Fill),
        );

        for baseline in &app.baselines {
            let date_str = format_timestamp(baseline.created_at);
            let device_count = baseline.devices.len();

            let compare_btn = button(text("Compare").color(TEXT).size(11))
                .padding([4, 10])
                .style(theme::SecondaryButton)
                .on_press(Message::BaselineCompared(baseline.id.clone()));

            let delete_btn = button(text("Delete").color(TEXT).size(11))
                .padding([4, 10])
                .style(theme::DangerButton)
                .on_press(Message::BaselineDeleted(baseline.id.clone()));

            let baseline_row = row![
                text(&baseline.name).color(TEXT).size(11).width(Length::FillPortion(2)),
                text(&baseline.scan_cidr).color(TEXT).size(11).width(Length::FillPortion(2)),
                text(format!("{}", device_count))
                    .color(TEXT)
                    .size(11)
                    .width(Length::FillPortion(1)),
                text(date_str)
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(2)),
                row![compare_btn, delete_btn]
                    .spacing(4)
                    .width(Length::FillPortion(2)),
            ]
            .spacing(8)
            .padding([4, 8])
            .align_items(Alignment::Center)
            .width(Length::Fill);

            baseline_list = baseline_list.push(baseline_row);
        }
    }

    let list_card = widgets::card(
        Some("Saved Baselines"),
        scrollable(baseline_list).height(Length::Fixed(200.0)),
    );

    content = content.push(list_card);

    // ── Diff View ───────────────────────────────────────────────────────
    if let Some(ref diff) = app.baseline_diff {
        let mut diff_col = column![].spacing(8);

        // Summary
        diff_col = diff_col.push(
            row![
                text(format!("Baseline: {}", diff.baseline_name))
                    .color(TEXT)
                    .size(13),
                iced::widget::horizontal_space(Length::Fill),
                text(format!(
                    "New: {} | Removed: {} | Changed Ports: {}",
                    diff.new_hosts.len(),
                    diff.removed_hosts.len(),
                    diff.changed_ports.len()
                ))
                .color(TEXT_MUTED)
                .size(12),
            ]
            .align_items(Alignment::Center)
            .width(Length::Fill),
        );

        // New hosts
        if !diff.new_hosts.is_empty() {
            let mut new_hosts_col = column![].spacing(2);
            for device in &diff.new_hosts {
                new_hosts_col = new_hosts_col.push(
                    text(format!("+ {} ({})", device.ip, device.hostname.as_deref().unwrap_or("-")))
                        .color(crate::ui::theme::SUCCESS)
                        .size(12),
                );
            }
            diff_col = diff_col.push(widgets::card(
                Some("New Hosts"),
                scrollable(new_hosts_col).height(Length::Fixed(100.0)),
            ));
        }

        // Removed hosts
        if !diff.removed_hosts.is_empty() {
            let mut removed_col = column![].spacing(2);
            for device in &diff.removed_hosts {
                removed_col = removed_col.push(
                    text(format!("- {} ({})", device.ip, device.hostname.as_deref().unwrap_or("-")))
                        .color(crate::ui::theme::DANGER)
                        .size(12),
                );
            }
            diff_col = diff_col.push(widgets::card(
                Some("Removed Hosts"),
                scrollable(removed_col).height(Length::Fixed(100.0)),
            ));
        }

        // Changed ports
        if !diff.changed_ports.is_empty() {
            let mut changed_col = column![].spacing(2);
            for change in &diff.changed_ports {
                let prev = change
                    .previous_state
                    .as_ref()
                    .map(|s| format!("{:?}", s))
                    .unwrap_or_else(|| "none".to_string());
                let curr = format!("{:?}", change.current_state);
                changed_col = changed_col.push(
                    text(format!(
                        "~ {}:{} — {} → {}",
                        change.ip, change.port.number, prev, curr
                    ))
                    .color(crate::ui::theme::WARNING)
                    .size(12),
                );
            }
            diff_col = diff_col.push(widgets::card(
                Some("Changed Ports"),
                scrollable(changed_col).height(Length::Fixed(100.0)),
            ));
        }

        let diff_card = widgets::card(Some("Baseline Comparison"), diff_col);
        content = content.push(diff_card);
    }

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::AppBackground)
        .into()
}

/// Format a Unix timestamp into a human-readable date string.
fn format_timestamp(ts: i64) -> String {
    let dt = chrono::DateTime::from_timestamp(ts, 0);
    match dt {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => "Invalid date".to_string(),
    }
}
