//! Scan view — configuration panel, progress bar, results table,
//! device detail panel, and scan logs.

use iced::{Alignment, Length};
use iced::widget::{
    button, checkbox, column, container, pick_list, progress_bar, row, scrollable, text, text_input,
};

use crate::types::ScanType;
use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

/// Render the Scan page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).width(Length::Fill).height(Length::Fill);

    // ── Configuration Panel ─────────────────────────────────────────────
    let cidr_input = text_input("Target CIDR (e.g. 192.168.1.0/24)", &app.scan_cidr)
        .on_input(Message::ScanCidrChanged)
        .padding(10)
        .size(14);

    let ports_input = text_input("Ports (comma-separated, e.g. 22,80,443)", &app.scan_ports_str)
        .on_input(Message::ScanPortsChanged)
        .padding(10)
        .size(14);

    let scan_type_picker = pick_list(
        &ScanType::all_types()[..],
        Some(app.scan_type.clone()),
        Message::ScanTypeSelected,
    )
    .padding(10)
    .text_size(14)
    .width(Length::Fill);

    let start_btn = button(
        row![text("Start Scan").color(TEXT).size(15)].align_y(Alignment::Center)
    )
    .padding([10, 24])
    .style(theme::primary_button)
    .on_press(Message::StartScan);

    let stop_btn = button(text("Stop Scan").color(TEXT).size(15))
        .padding([10, 24])
        .style(theme::danger_button)
        .on_press(Message::StopScan);

    let pause_btn = if app.is_paused {
        button(text("Resume").color(TEXT).size(15))
            .padding([10, 20])
            .style(theme::success_button)
            .on_press(Message::ResumeScan)
    } else {
        button(text("Pause").color(TEXT).size(15))
            .padding([10, 20])
            .style(theme::secondary_button)
            .on_press(Message::PauseScan)
    };

    let mut controls = row![].spacing(12).align_y(Alignment::Center);

    if app.is_scanning {
        controls = controls.push(pause_btn).push(stop_btn);
    } else {
        controls = controls.push(start_btn);
    }

    let config_row = row![
        column![
            text("Target Network (CIDR)").color(TEXT_MUTED).size(12),
            cidr_input,
        ]
        .spacing(6)
        .width(Length::FillPortion(3)),
        column![
            text("Target Ports").color(TEXT_MUTED).size(12),
            ports_input,
        ]
        .spacing(6)
        .width(Length::FillPortion(3)),
        column![
            text("Scan Type").color(TEXT_MUTED).size(12),
            scan_type_picker,
        ]
        .spacing(6)
        .width(Length::FillPortion(2)),
        column![
            text("").size(12), // Spacer to align with inputs
            controls,
        ]
        .spacing(6)
        .width(Length::Shrink),
    ]
    .spacing(16)
    .align_y(Alignment::End);

    let config_card = widgets::card(
        Some("Scan Configuration"),
        column![config_row]
            .spacing(16)
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

    // ── Toolbar Header (Title, Exports) ─────────────────────────────────
    let toolbar = row![
        text(format!("Discovered Devices ({})", app.discovered_devices.len())).color(TEXT).size(15),
        iced::widget::horizontal_space().width(Length::Fill),
        button(text("Export CSV").size(12))
            .padding([4, 8])
            .style(theme::secondary_button)
            .on_press(Message::ExportCsv),
        button(text("Export JSON").size(12))
            .padding([4, 8])
            .style(theme::secondary_button)
            .on_press(Message::ExportJson),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .width(Length::Fill);

    // ── Filter and Search Bar ───────────────────────────────────────────
    let search_input = text_input("Search devices...", &app.search_query)
        .on_input(Message::SearchQueryChanged)
        .padding(6)
        .size(12);

    let mut status_row = row![].spacing(4).align_y(Alignment::Center);
    for (val, label) in &[("all", "All"), ("online", "Online"), ("offline", "Offline"), ("unknown", "Unknown")] {
        let is_active = app.filter_status == *val;
        status_row = status_row.push(
            button(text(*label).size(11))
                .padding([4, 8])
                .style(if is_active {
                    theme::primary_button
                } else {
                    theme::secondary_button
                })
                .on_press(Message::FilterStatusChanged(val.to_string()))
        );
    }

    let open_ports_check = checkbox("Has open ports", app.filter_has_open_ports)
        .on_toggle(Message::FilterHasOpenPortsToggled)
        .size(14);

    let mut filter_row = row![
        column![text("Search").color(TEXT_MUTED).size(10), search_input]
            .spacing(2)
            .width(Length::FillPortion(2)),
        column![text("Status").color(TEXT_MUTED).size(10), status_row]
            .spacing(2)
            .width(Length::Shrink),
        column![text("Ports").color(TEXT_MUTED).size(10), open_ports_check]
            .spacing(2)
            .width(Length::Shrink),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    if !app.search_query.is_empty() || app.filter_status != "all" || app.filter_has_open_ports {
        filter_row = filter_row.push(
            button(text("Clear").size(11))
                .padding([4, 8])
                .style(theme::danger_button)
                .on_press(Message::ClearFilters)
        );
    }

    let results_count = text(format!("Showing {} of {} devices", app.filtered_devices.len(), app.discovered_devices.len()))
        .color(TEXT_MUTED)
        .size(11);

    let filter_bar = row![
        filter_row,
        iced::widget::horizontal_space().width(Length::Fill),
        results_count
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .width(Length::Fill);

    // ── Table Header (Sortable) ─────────────────────────────────────────
    let make_header = |label: &'static str, field: crate::ui::SortField, width: Length| {
        let is_active = app.sort_field == field;
        let icon = if is_active {
            match app.sort_direction {
                crate::ui::SortDirection::Asc => " ↑",
                crate::ui::SortDirection::Desc => " ↓",
            }
        } else {
            " ↕"
        };
        button(
            row![
                text(label).color(if is_active { theme::PRIMARY } else { TEXT_MUTED }).size(11),
                text(icon).color(TEXT_MUTED).size(10),
            ].spacing(2)
        )
        .style(theme::tab_button)
        .on_press(Message::SortTableBy(field))
        .width(width)
    };

    let table_header = row![
        make_header("IP Address", crate::ui::SortField::Ip, Length::FillPortion(2)),
        make_header("MAC Address", crate::ui::SortField::Mac, Length::FillPortion(2)),
        make_header("Vendor", crate::ui::SortField::Vendor, Length::FillPortion(2)),
        make_header("Hostname", crate::ui::SortField::Hostname, Length::FillPortion(2)),
        make_header("Open Ports", crate::ui::SortField::OpenPorts, Length::FillPortion(1)),
        make_header("Last Seen", crate::ui::SortField::LastSeen, Length::FillPortion(2)),
    ]
    .spacing(8)
    .padding([6, 12])
    .width(Length::Fill);

    // ── Results Table Content ───────────────────────────────────────────
    let mut results_list = column![].spacing(2);

    if app.filtered_devices.is_empty() {
        let empty_msg = if app.is_scanning {
            "Scanning in progress... devices will appear here."
        } else if app.discovered_devices.is_empty() {
            "No devices discovered yet.\nEnter a target network and start a scan."
        } else {
            "No devices match the current filters."
        };
        
        let empty_state = container(
            column![
                text(empty_msg)
                    .color(TEXT_MUTED)
                    .size(15),
            ]
            .align_x(Alignment::Center)
        )
        .center_x(Length::Fill)
        .center_y(Length::Fixed(200.0))
        .style(theme::empty_state_style);

        results_list = results_list.push(empty_state);
    } else {
        let mut idx = 0;
        for device in &app.filtered_devices {
            let hostname = device.hostname.as_deref().unwrap_or("-");
            let vendor = device.vendor.as_deref().unwrap_or("-");
            let port_count = device.ports.len();

            let is_selected = app.selected_device.as_ref().map(|d| d.ip == device.ip).unwrap_or(false);

            let row_content = row![
                text(&device.ip).color(TEXT).size(12).width(Length::FillPortion(2)),
                text(&device.mac).color(TEXT).size(12).width(Length::FillPortion(2)),
                text(vendor).color(TEXT_MUTED).size(12).width(Length::FillPortion(2)),
                text(hostname).color(TEXT).size(12).width(Length::FillPortion(2)),
                text(format!("{}", port_count)).color(TEXT).size(12).width(Length::FillPortion(1)),
                text(format_timestamp(device.last_seen)).color(TEXT_MUTED).size(11).width(Length::FillPortion(2)),
            ]
            .spacing(8)
            .padding([8, 12])
            .align_y(Alignment::Center)
            .width(Length::Fill);

            // Toggle select on click
            let select_msg = if is_selected {
                Message::DeviceSelected(None)
            } else {
                Message::DeviceSelected(Some(idx))
            };

            let device_row = button(row_content)
                .style(row_button_style(is_selected))
                .on_press(select_msg);

            results_list = results_list.push(device_row);
            idx += 1;
        }
    }

    // Left container (Table + toolbar + filters)
    let left_column = column![
        toolbar,
        filter_bar,
        table_header,
        scrollable(results_list).height(Length::Fill)
    ]
    .spacing(12)
    .width(Length::Fill)
    .height(Length::Fill);

    let left_card = container(left_column)
        .padding(16)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::card_style);

    // ── Device Detail Panel (Split view on right) ────────────────────────
    let results_block: iced::Element<'_, Message> = if let Some(ref device) = app.selected_device {
        let mut detail_col = column![].spacing(16).width(Length::Fill);
        
        detail_col = detail_col.push(
            row![
                text("Device Details").color(TEXT).size(18),
                iced::widget::horizontal_space().width(Length::Fill),
                button(text("✕").size(14).color(TEXT_MUTED))
                    .padding([4, 8])
                    .style(theme::secondary_button)
                    .on_press(Message::DeviceSelected(None))
            ]
            .align_y(Alignment::Center)
        );

        let info_section = column![
            widgets::info_row("IP Address:", device.ip.clone()),
            widgets::info_row("MAC Address:", device.mac.clone()),
            widgets::info_row(
                "Hostname:",
                device.hostname.clone().unwrap_or_else(|| "-".to_string()),
            ),
            widgets::info_row(
                "Vendor:",
                device.vendor.clone().unwrap_or_else(|| "-".to_string()),
            ),
            widgets::info_row(
                "OS:",
                device.os.clone().unwrap_or_else(|| "-".to_string()),
            ),
            row![
                text("Status:").color(TEXT_MUTED).size(13),
                iced::widget::horizontal_space().width(Length::Fixed(10.0)),
                widgets::status_badge(&format!("{:?}", device.status))
            ]
            .align_y(Alignment::Center)
        ].spacing(10);
        
        detail_col = detail_col.push(info_section);

        // Ports list
        if !device.ports.is_empty() {
            detail_col = detail_col.push(text("Open Ports").color(TEXT).size(14));
            let mut ports_col = column![].spacing(8);
            for port in &device.ports {
                let svc = port.service.as_deref();
                let state_str = format!("{:?}", port.state);
                ports_col = ports_col.push(widgets::port_badge(port.number, &state_str, svc));
            }
            detail_col = detail_col.push(scrollable(ports_col).height(Length::Fixed(140.0)));
        }

        // Banner results
        if !device.banner_results.is_empty() {
            detail_col = detail_col.push(text("Service Banners").color(TEXT).size(14));
            let mut banners_col = column![].spacing(6);
            for banner in &device.banner_results {
                let banner_text = format!(
                    "Port {}: {} ({})",
                    banner.port,
                    banner.service.as_deref().unwrap_or("unknown"),
                    &banner.banner[..banner.banner.len().min(80)]
                );
                banners_col = banners_col.push(text(banner_text).color(TEXT_MUTED).size(12));
            }
            detail_col = detail_col.push(scrollable(banners_col).height(Length::Fixed(140.0)));
        }

        let detail_card = container(detail_col)
            .padding(20)
            .width(Length::Fixed(340.0))
            .style(theme::card_style);

        row![left_card, detail_card]
            .spacing(16)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        left_card.into()
    };

    content = content.push(results_block);

    // ── Scan Logs ───────────────────────────────────────────────────────
    let mut logs_list = column![].spacing(2);

    if app.scan_logs.is_empty() {
        logs_list = logs_list.push(
            text("No scan logs yet.")
                .color(TEXT_MUTED)
                .size(12),
        );
    } else {
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

    let logs_card = container(
        column![
            text("Scan Logs").color(TEXT).size(16).font(iced::Font { weight: iced::font::Weight::Bold, ..Default::default() }),
            container(scrollable(logs_list).height(Length::Fixed(150.0)))
                .padding(12)
                .width(Length::Fill)
                .style(theme::terminal_style)
        ].spacing(12)
    ).padding(20).width(Length::Fill).style(theme::card_style);

    content = content.push(logs_card);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Format a Unix timestamp into a human-readable time string.
fn format_timestamp(ts: i64) -> String {
    let dt = chrono::DateTime::from_timestamp(ts, 0);
    match dt {
        Some(dt) => dt.format("%H:%M:%S").to_string(),
        None => "never".to_string(),
    }
}

/// Helper function to style table rows as clickable buttons
fn row_button_style(is_selected: bool) -> impl Fn(&iced::Theme, iced::widget::button::Status) -> iced::widget::button::Style {
    move |_theme, status| {
        let bg = if is_selected {
            iced::Color {
                r: theme::PRIMARY.r,
                g: theme::PRIMARY.g,
                b: theme::PRIMARY.b,
                a: 0.15,
            }
        } else {
            match status {
                iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed => {
                    iced::Color {
                        r: theme::HOVER.r,
                        g: theme::HOVER.g,
                        b: theme::HOVER.b,
                        a: 0.3,
                    }
                }
                _ => iced::Color::TRANSPARENT,
            }
        };

        iced::widget::button::Style {
            background: Some(iced::Background::Color(bg)),
            text_color: theme::TEXT,
            border: iced::Border {
                radius: 4.0.into(),
                width: 0.0,
                color: iced::Color::TRANSPARENT,
            },
            ..Default::default()
        }
    }
}
