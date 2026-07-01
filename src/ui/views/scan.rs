//! Scan view — configuration panel, progress bar, results table,
//! device detail panel, and scan logs.

use iced::widget::{
    button, checkbox, column, container, pick_list, progress_bar, row, scrollable, text, text_input,
};
use iced::{Alignment, Length};

use crate::scan_plan::ScanMode;
use crate::types::ScanType;
use crate::ui::theme::{self, DANGER, TEXT, TEXT_MUTED, WARNING};
use crate::ui::widgets;
use crate::ui::{
    DeviceDetailTab, FindingStatus, GuidedScanProfile, LogSeverityFilter, Message, NetSentinelApp,
};

/// Render the Scan page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![]
        .spacing(16)
        .width(Length::Fill)
        .height(Length::Fill);

    // ── Configuration Panel ─────────────────────────────────────────────
    let cidr_input = text_input("Target CIDR (e.g. 192.168.1.0/24)", &app.scan_cidr)
        .on_input(Message::ScanCidrChanged)
        .padding(10)
        .size(14);

    let cidr_error = app
        .scan_cidr_error
        .as_ref()
        .map(|err| text(err).color(DANGER).size(11))
        .unwrap_or_else(|| text("").size(11));

    let cidr_col = column![
        text("Target Network (CIDR)").color(TEXT_MUTED).size(12),
        cidr_input,
        cidr_error,
    ]
    .spacing(6)
    .width(Length::FillPortion(3));

    let ports_input = text_input(
        "Ports (comma-separated, ranges, presets, e.g. 22,80,443 or 22-100 or top-1000)",
        &app.scan_ports_str,
    )
    .on_input(Message::ScanPortsChanged)
    .padding(10)
    .size(14);

    let ports_feedback: iced::Element<'_, Message> = if let Some(ref err) = app.scan_ports_error {
        text(err).color(DANGER).size(11).into()
    } else if let Some(ref warning) = app.scan_ports_warning {
        text(warning).color(WARNING).size(11).into()
    } else {
        text("").size(11).into()
    };

    let ports_col = column![
        text("Target Ports").color(TEXT_MUTED).size(12),
        ports_input,
        ports_feedback,
    ]
    .spacing(6)
    .width(Length::FillPortion(3));

    let scan_type_picker = pick_list(
        &ScanType::all_types()[..],
        Some(app.scan_type.clone()),
        Message::ScanTypeSelected,
    )
    .padding(10)
    .text_size(14)
    .width(Length::Fill);

    let scan_mode_picker = pick_list(
        ScanMode::all(),
        Some(app.scan_mode),
        Message::ScanModeSelected,
    )
    .padding(10)
    .text_size(14)
    .width(Length::Fill);

    let start_btn =
        button(row![text("Start Scan").color(TEXT).size(15)].align_y(Alignment::Center))
            .padding([10, 24])
            .style(theme::primary_button)
            .on_press(Message::StartScanRequested);

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
        cidr_col,
        ports_col,
        column![
            text("Scan Type").color(TEXT_MUTED).size(12),
            scan_type_picker,
        ]
        .spacing(6)
        .width(Length::FillPortion(2)),
        column![text("Mode").color(TEXT_MUTED).size(12), scan_mode_picker,]
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
        column![config_row].spacing(16).width(Length::Fill),
    );

    content = content.push(config_card);

    // ── Guided Scan Profiles ────────────────────────────────────────────
    if !app.is_scanning {
        let mut profile_row = row![text("Guided profile:").color(TEXT_MUTED).size(12)]
            .spacing(8)
            .align_y(Alignment::Center);
        for profile in GuidedScanProfile::all() {
            profile_row = profile_row.push(
                button(text(profile.label()).size(11).color(TEXT))
                    .padding([6, 12])
                    .style(theme::secondary_button)
                    .on_press(Message::ApplyGuidedProfile(*profile)),
            );
        }
        content = content.push(widgets::card(Some("Guided Profiles"), profile_row));
    }

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

        let progress_bar_widget = progress_bar(0.0..=1.0, app.scan_progress).height(8);

        let progress_card = widgets::card(
            Some("Scan Progress"),
            column![progress_bar_widget, progress_text]
                .spacing(8)
                .width(Length::Fill),
        );

        content = content.push(progress_card);
    }

    content = content.push(risk_overview_card(app));

    // ── Global Findings List ────────────────────────────────────────────
    if app.is_scanning || !app.findings.is_empty() {
        let findings_content: iced::Element<'_, Message> = if app.findings.is_empty() {
            container(
                column![text(
                    "No findings yet — vulnerabilities will appear here as the scan progresses."
                )
                .color(TEXT_MUTED)
                .size(13),]
                .align_x(Alignment::Center),
            )
            .center_x(Length::Fill)
            .center_y(Length::Fixed(220.0))
            .style(theme::empty_state_style)
            .into()
        } else {
            findings_table(app)
        };

        content = content.push(widgets::card(Some("Actionable Findings"), findings_content));
    }

    // ── Toolbar Header (Title, Exports) ─────────────────────────────────
    let toolbar = row![
        text(format!(
            "Discovered Devices ({})",
            app.discovered_devices.len()
        ))
        .color(TEXT)
        .size(15),
        iced::widget::horizontal_space().width(Length::Fill),
        button(text("Export CSV").size(12))
            .padding([4, 8])
            .style(theme::secondary_button)
            .on_press(Message::ExportCsv),
        button(text("Export JSON").size(12))
            .padding([4, 8])
            .style(theme::secondary_button)
            .on_press(Message::ExportJson),
        button(text("Export HTML").size(12))
            .padding([4, 8])
            .style(theme::secondary_button)
            .on_press(Message::ExportHtml),
        button(text("Export PDF").size(12))
            .padding([4, 8])
            .style(theme::secondary_button)
            .on_press(Message::ExportPdf),
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
    for (val, label) in &[
        ("all", "All"),
        ("online", "Online"),
        ("offline", "Offline"),
        ("unknown", "Unknown"),
    ] {
        let is_active = app.filter_status == *val;
        status_row = status_row.push(
            button(text(*label).size(11))
                .padding([4, 8])
                .style(if is_active {
                    theme::primary_button
                } else {
                    theme::secondary_button
                })
                .on_press(Message::FilterStatusChanged(val.to_string())),
        );
    }

    let open_ports_check = checkbox("Has open ports", app.filter_has_open_ports)
        .on_toggle(Message::FilterHasOpenPortsToggled)
        .size(14);

    let findings_check = checkbox("Has findings", app.filter_has_findings)
        .on_toggle(Message::FilterHasFindingsToggled)
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
        column![text("Findings").color(TEXT_MUTED).size(10), findings_check]
            .spacing(2)
            .width(Length::Shrink),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    if !app.search_query.is_empty()
        || app.filter_status != "all"
        || app.filter_has_open_ports
        || app.filter_has_findings
    {
        filter_row = filter_row.push(
            button(text("Clear").size(11))
                .padding([4, 8])
                .style(theme::danger_button)
                .on_press(Message::ClearFilters),
        );
    }

    let results_count = text(format!(
        "Showing {} of {} devices",
        app.filtered_devices.len(),
        app.discovered_devices.len()
    ))
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
                text(label)
                    .color(if is_active {
                        theme::PRIMARY
                    } else {
                        TEXT_MUTED
                    })
                    .size(11),
                text(icon).color(TEXT_MUTED).size(10),
            ]
            .spacing(2),
        )
        .style(theme::tab_button)
        .on_press(Message::SortTableBy(field))
        .width(width)
    };

    let table_header = row![
        make_header(
            "IP Address",
            crate::ui::SortField::Ip,
            Length::FillPortion(2)
        ),
        make_header(
            "MAC Address",
            crate::ui::SortField::Mac,
            Length::FillPortion(2)
        ),
        make_header(
            "Vendor",
            crate::ui::SortField::Vendor,
            Length::FillPortion(2)
        ),
        make_header(
            "Hostname",
            crate::ui::SortField::Hostname,
            Length::FillPortion(2)
        ),
        make_header(
            "Open Ports",
            crate::ui::SortField::OpenPorts,
            Length::FillPortion(1)
        ),
        make_header(
            "Findings",
            crate::ui::SortField::Findings,
            Length::FillPortion(1)
        ),
        make_header(
            "Last Seen",
            crate::ui::SortField::LastSeen,
            Length::FillPortion(2)
        ),
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
            column![text(empty_msg).color(TEXT_MUTED).size(15),].align_x(Alignment::Center),
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
            let port_count = device
                .ports
                .iter()
                .filter(|port| port.state == crate::types::PortState::Open)
                .count();
            let finding_count = device.findings.len();

            let is_selected = app
                .selected_device
                .as_ref()
                .map(|d| d.ip == device.ip)
                .unwrap_or(false);

            let row_content = row![
                text(&device.ip)
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(&device.mac)
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(vendor)
                    .color(TEXT_MUTED)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(hostname)
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(format!("{}", port_count))
                    .color(TEXT)
                    .size(12)
                    .width(Length::FillPortion(1)),
                widgets::findings_count_badge(finding_count).width(Length::FillPortion(1)),
                text(format_timestamp(device.last_seen))
                    .color(TEXT_MUTED)
                    .size(11)
                    .width(Length::FillPortion(2)),
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
        let detail_card = container(device_detail_panel(app, device))
            .padding(16)
            .width(Length::FillPortion(2))
            .height(Length::Fill)
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
        logs_list = logs_list.push(text("No scan logs yet.").color(TEXT_MUTED).size(12));
    } else {
        let search = app.log_search.to_lowercase();
        for log in &app.scan_logs {
            let level_matches = match app.log_severity_filter {
                LogSeverityFilter::All => true,
                LogSeverityFilter::Info => log.level.eq_ignore_ascii_case("info"),
                LogSeverityFilter::Warn => log.level.eq_ignore_ascii_case("warn"),
                LogSeverityFilter::Error => log.level.eq_ignore_ascii_case("error"),
            };
            let search_matches = search.is_empty()
                || log.message.to_lowercase().contains(&search)
                || log
                    .target
                    .as_ref()
                    .map(|target| target.to_lowercase().contains(&search))
                    .unwrap_or(false);
            if !level_matches || !search_matches {
                continue;
            }
            let level_color = match log.level.as_str() {
                "error" => crate::ui::theme::DANGER,
                "warn" => crate::ui::theme::WARNING,
                "info" => crate::ui::theme::INFO,
                _ => TEXT_MUTED,
            };
            let log_text = format!(
                "[{}] [{}] [{}] {}",
                format_timestamp(log.timestamp),
                log.level.to_uppercase(),
                log.target.as_deref().unwrap_or("-"),
                log.message
            );
            logs_list = logs_list.push(text(log_text).color(level_color).size(11));
        }
    }

    let logs_card = container(
        column![
            row![
                text("Scan Logs").color(TEXT).size(16).font(iced::Font {
                    weight: iced::font::Weight::Bold,
                    ..Default::default()
                }),
                iced::widget::horizontal_space().width(Length::Fill),
                log_filter_buttons(app),
                button(text("Export").size(11))
                    .padding([4, 8])
                    .style(theme::secondary_button)
                    .on_press(Message::ExportLogs),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            row![
                text_input("Search logs...", &app.log_search)
                    .on_input(Message::LogSearchChanged)
                    .padding(6)
                    .size(12)
                    .width(Length::Fill),
                checkbox("Auto-scroll", app.log_auto_scroll)
                    .on_toggle(Message::LogAutoScrollToggled)
                    .size(14),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            text(app.log_export_status.as_deref().unwrap_or(""))
                .color(TEXT_MUTED)
                .size(11),
            container(scrollable(logs_list).height(Length::Fixed(150.0)))
                .padding(12)
                .width(Length::Fill)
                .style(theme::terminal_style)
        ]
        .spacing(12),
    )
    .padding(20)
    .width(Length::Fill)
    .style(theme::card_style);

    content = content.push(logs_card);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn risk_overview_card(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let overview = &app.risk_overview;
    let ports = if overview.frequent_ports.is_empty() {
        "-".to_string()
    } else {
        overview
            .frequent_ports
            .iter()
            .map(|(port, count)| format!("{} ({})", port, count))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let hosts = if overview.top_risky_hosts.is_empty() {
        "-".to_string()
    } else {
        overview
            .top_risky_hosts
            .iter()
            .map(|(ip, score)| format!("{} ({})", ip, score))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let services = if overview.exposed_services.is_empty() {
        "-".to_string()
    } else {
        overview.exposed_services.join(", ")
    };

    widgets::card(
        Some("Risk Overview"),
        column![
            row![
                metric("Hosts", overview.total_hosts.to_string()),
                metric(
                    "Hosts w/ findings",
                    overview.hosts_with_findings.to_string()
                ),
                metric("Critical", overview.critical.to_string()),
                metric("High", overview.high.to_string()),
                metric("Medium", overview.medium.to_string()),
                metric("Low", overview.low.to_string()),
            ]
            .spacing(10),
            row![
                metric("Top ports", ports),
                metric("Riskiest hosts", hosts),
                metric("Exposed services", services),
            ]
            .spacing(10)
        ]
        .spacing(10),
    )
    .into()
}

fn metric<'a>(label: &'static str, value: String) -> iced::Element<'a, Message> {
    container(
        column![
            text(label).color(TEXT_MUTED).size(10),
            text(value).color(TEXT).size(13),
        ]
        .spacing(4),
    )
    .padding(10)
    .width(Length::Fill)
    .style(theme::table_container_style)
    .into()
}

fn findings_table(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let severity_filter = row![
        severity_filter_button("all", "All", app),
        severity_filter_button("critical", "Critical", app),
        severity_filter_button("high", "High", app),
        severity_filter_button("medium", "Medium", app),
        severity_filter_button("low", "Low", app),
    ]
    .spacing(4);

    let filters = row![
        column![text("Severity").color(TEXT_MUTED).size(10), severity_filter]
            .spacing(3)
            .width(Length::Shrink),
        column![
            text("Host").color(TEXT_MUTED).size(10),
            text_input("IP / host", &app.finding_host_filter)
                .on_input(Message::FindingHostFilterChanged)
                .padding(6)
                .size(12)
        ]
        .spacing(3)
        .width(Length::FillPortion(1)),
        column![
            text("Category").color(TEXT_MUTED).size(10),
            text_input("category", &app.finding_category_filter)
                .on_input(Message::FindingCategoryFilterChanged)
                .padding(6)
                .size(12)
        ]
        .spacing(3)
        .width(Length::FillPortion(1)),
        checkbox("Exploitable", app.finding_only_exploitable)
            .on_toggle(Message::FindingOnlyExploitableToggled)
            .size(14),
        checkbox("External-like", app.finding_only_external_like)
            .on_toggle(Message::FindingOnlyExternalLikeToggled)
            .size(14),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let header = row![
        text("Severity")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(1)),
        text("Host")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(1)),
        text("Port")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(1)),
        text("Service")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(1)),
        text("Category")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(1)),
        text("Confidence")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(1)),
        text("Evidence")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(2)),
        text("Recommendation")
            .color(TEXT_MUTED)
            .size(10)
            .width(Length::FillPortion(2)),
    ]
    .spacing(8)
    .padding([4, 8]);

    let mut rows = column![header].spacing(4);
    for finding in &app.filtered_findings {
        let selected = app
            .selected_finding_id
            .as_ref()
            .map(|id| id == &finding.id)
            .unwrap_or(false);
        let row_content = row![
            widgets::finding_severity_badge(&finding.severity).width(Length::FillPortion(1)),
            text(&finding.ip)
                .color(TEXT)
                .size(11)
                .width(Length::FillPortion(1)),
            text(
                finding
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string())
            )
            .color(TEXT_MUTED)
            .size(11)
            .width(Length::FillPortion(1)),
            text(finding.service.as_deref().unwrap_or("-"))
                .color(TEXT_MUTED)
                .size(11)
                .width(Length::FillPortion(1)),
            text(format!("{:?}", finding.category))
                .color(TEXT_MUTED)
                .size(11)
                .width(Length::FillPortion(1)),
            text(format!("{:?}", finding.confidence))
                .color(TEXT_MUTED)
                .size(11)
                .width(Length::FillPortion(1)),
            text(
                finding
                    .evidence
                    .as_deref()
                    .map(|e| truncate_chars(e, 64))
                    .unwrap_or_else(|| "-".to_string())
            )
            .color(TEXT_MUTED)
            .size(11)
            .width(Length::FillPortion(2)),
            text(
                finding
                    .remediation
                    .as_deref()
                    .map(|r| truncate_chars(r, 64))
                    .unwrap_or_else(|| "Review finding".to_string())
            )
            .color(TEXT_MUTED)
            .size(11)
            .width(Length::FillPortion(2)),
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .padding([6, 8]);
        rows = rows.push(
            button(row_content)
                .style(row_button_style(selected))
                .on_press(Message::FindingSelected(Some(finding.id.clone()))),
        );
    }

    let detail = app
        .selected_finding
        .as_ref()
        .map(|finding| finding_detail(app, finding));

    let mut layout = column![filters, scrollable(rows).height(Length::Fixed(230.0))].spacing(10);
    if let Some(detail) = detail {
        layout = layout.push(detail);
    }
    layout.into()
}

fn severity_filter_button<'a>(
    value: &'static str,
    label: &'static str,
    app: &NetSentinelApp,
) -> iced::Element<'a, Message> {
    let active = app.finding_severity_filter == value;
    button(text(label).size(10))
        .padding([4, 8])
        .style(if active {
            theme::primary_button
        } else {
            theme::secondary_button
        })
        .on_press(Message::FindingSeverityFilterChanged(value.to_string()))
        .into()
}

fn finding_detail<'a>(
    app: &NetSentinelApp,
    finding: &'a crate::types::Finding,
) -> iced::Element<'a, Message> {
    let status = app
        .finding_statuses
        .get(&finding.id)
        .copied()
        .unwrap_or(FindingStatus::New);
    let mut status_row = row![text("Status:").color(TEXT_MUTED).size(12)].spacing(6);
    for item in FindingStatus::all() {
        status_row = status_row.push(
            button(text(item.label()).size(10))
                .padding([4, 8])
                .style(if *item == status {
                    theme::primary_button
                } else {
                    theme::secondary_button
                })
                .on_press(Message::FindingStatusChanged(finding.id.clone(), *item)),
        );
    }

    container(
        column![
            row![
                widgets::finding_severity_badge(&finding.severity),
                text(&finding.title).color(TEXT).size(14)
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            text(&finding.description).color(TEXT_MUTED).size(12),
            widgets::info_row(
                "Evidence:",
                finding.evidence.clone().unwrap_or_else(|| "-".to_string())
            ),
            widgets::info_row(
                "Risk:",
                format!("{:?} / {:?}", finding.severity, finding.confidence)
            ),
            widgets::info_row(
                "Recommendation:",
                finding
                    .remediation
                    .clone()
                    .unwrap_or_else(|| "Review and remediate according to policy.".to_string())
            ),
            widgets::info_row(
                "CVE:",
                finding
                    .cve
                    .as_ref()
                    .map(|cve| cve.cve_id.clone())
                    .unwrap_or_else(|| "-".to_string())
            ),
            status_row,
        ]
        .spacing(8),
    )
    .padding(12)
    .style(theme::table_container_style)
    .into()
}

fn device_detail_panel<'a>(
    app: &NetSentinelApp,
    device: &'a crate::types::Device,
) -> iced::Element<'a, Message> {
    let known = app.known_devices.get(&device.ip).copied().unwrap_or(false);
    let note = app
        .host_notes
        .get(&device.ip)
        .map(String::as_str)
        .unwrap_or("");
    let mut tabs = row![].spacing(4);
    for tab in DeviceDetailTab::all() {
        tabs = tabs.push(
            button(text(tab.label()).size(10))
                .padding([4, 8])
                .style(if *tab == app.device_detail_tab {
                    theme::primary_button
                } else {
                    theme::secondary_button
                })
                .on_press(Message::DeviceDetailTabSelected(*tab)),
        );
    }

    let body = match app.device_detail_tab {
        DeviceDetailTab::Overview => overview_tab(app, device, note),
        DeviceDetailTab::Ports => ports_tab(device),
        DeviceDetailTab::Services => services_tab(device),
        DeviceDetailTab::Findings => host_findings_tab(device),
        DeviceDetailTab::Tls => tls_tab(device),
        DeviceDetailTab::Web => web_tab(device),
        DeviceDetailTab::History => history_tab(device, known),
    };

    column![
        row![
            text(format!("Device {}", device.ip)).color(TEXT).size(16),
            iced::widget::horizontal_space().width(Length::Fill),
            button(text("✕").size(14).color(TEXT_MUTED))
                .padding([4, 8])
                .style(theme::secondary_button)
                .on_press(Message::DeviceSelected(None)),
        ]
        .align_y(Alignment::Center),
        row![
            button(text("Re-scan").size(10))
                .padding([4, 8])
                .style(theme::secondary_button)
                .on_press(Message::RescanSelectedHost(device.ip.clone())),
            button(text("Export").size(10))
                .padding([4, 8])
                .style(theme::secondary_button)
                .on_press(Message::ExportSelectedHost(device.ip.clone())),
            button(text("Copy IP").size(10))
                .padding([4, 8])
                .style(theme::secondary_button)
                .on_press(Message::CopyHostIp(device.ip.clone())),
            button(text("HTTP").size(10))
                .padding([4, 8])
                .style(theme::secondary_button)
                .on_press(Message::OpenHostHttp(device.ip.clone(), false)),
            button(text("HTTPS").size(10))
                .padding([4, 8])
                .style(theme::secondary_button)
                .on_press(Message::OpenHostHttp(device.ip.clone(), true)),
            button(text(if known { "Known" } else { "Mark known" }).size(10))
                .padding([4, 8])
                .style(if known {
                    theme::success_button
                } else {
                    theme::secondary_button
                })
                .on_press(Message::ToggleKnownDevice(device.ip.clone())),
        ]
        .spacing(4),
        tabs,
        scrollable(body).height(Length::Fill),
    ]
    .spacing(12)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn overview_tab<'a>(
    app: &NetSentinelApp,
    device: &'a crate::types::Device,
    note: &str,
) -> iced::Element<'a, Message> {
    column![
        widgets::info_row("IP Address:", device.ip.clone()),
        widgets::info_row("MAC Address:", device.mac.clone()),
        widgets::info_row(
            "Hostname:",
            device.hostname.clone().unwrap_or_else(|| "-".to_string())
        ),
        widgets::info_row(
            "Vendor:",
            device.vendor.clone().unwrap_or_else(|| "-".to_string())
        ),
        widgets::info_row("OS:", device.os.clone().unwrap_or_else(|| "-".to_string())),
        row![
            text("Status:").color(TEXT_MUTED).size(13),
            widgets::status_badge(&format!("{:?}", device.status))
        ]
        .spacing(10),
        text_input("Host note...", note)
            .on_input({
                let ip = device.ip.clone();
                move |value| Message::HostNoteChanged(ip.clone(), value)
            })
            .padding(8)
            .size(12),
        text(format!(
            "Known device: {}",
            app.known_devices.get(&device.ip).copied().unwrap_or(false)
        ))
        .color(TEXT_MUTED)
        .size(11),
    ]
    .spacing(10)
    .into()
}

fn ports_tab<'a>(device: &'a crate::types::Device) -> iced::Element<'a, Message> {
    let mut col = column![].spacing(8);
    for port in &device.ports {
        col = col.push(widgets::port_badge(
            port.number,
            &format!("{:?}", port.state),
            port.service.as_deref(),
        ));
    }
    if device.ports.is_empty() {
        col = col.push(text("No ports recorded.").color(TEXT_MUTED).size(12));
    }
    col.into()
}

fn services_tab<'a>(device: &'a crate::types::Device) -> iced::Element<'a, Message> {
    let mut col = column![].spacing(8);
    for banner in &device.banner_results {
        col = col.push(
            text(format!(
                "Port {}: {} — {}",
                banner.port,
                banner.service.as_deref().unwrap_or("unknown"),
                truncate_chars(&banner.banner, 96)
            ))
            .color(TEXT_MUTED)
            .size(12),
        );
    }
    if device.banner_results.is_empty() {
        col = col.push(
            text("No service banners recorded.")
                .color(TEXT_MUTED)
                .size(12),
        );
    }
    col.into()
}

fn host_findings_tab<'a>(device: &'a crate::types::Device) -> iced::Element<'a, Message> {
    let mut col = column![].spacing(8);
    for finding in &device.findings {
        col = col.push(
            row![
                widgets::finding_severity_badge(&finding.severity),
                text(&finding.title).color(TEXT).size(12)
            ]
            .spacing(8),
        );
        col = col.push(
            text(
                finding
                    .evidence
                    .as_deref()
                    .unwrap_or("No evidence recorded"),
            )
            .color(TEXT_MUTED)
            .size(11),
        );
    }
    if device.findings.is_empty() {
        col = col.push(
            text("No findings for this host.")
                .color(TEXT_MUTED)
                .size(12),
        );
    }
    col.into()
}

fn tls_tab<'a>(device: &'a crate::types::Device) -> iced::Element<'a, Message> {
    let mut col = column![].spacing(8);
    let mut has_tls = false;
    for banner in &device.banner_results {
        if banner.tls_info.is_some() {
            has_tls = true;
            col = col.push(
                text(format!("TLS observed on port {}", banner.port))
                    .color(TEXT_MUTED)
                    .size(12),
            );
        }
    }
    if !has_tls {
        col = col.push(text("No TLS details recorded.").color(TEXT_MUTED).size(12));
    }
    col.into()
}

fn web_tab<'a>(device: &'a crate::types::Device) -> iced::Element<'a, Message> {
    let mut col = column![].spacing(8);
    for audit in &device.web_audits {
        col = col.push(
            text(format!(
                "{} — status {} — {} exposed path(s)",
                audit.url,
                audit.status_code,
                audit.exposed_directories.len()
            ))
            .color(TEXT_MUTED)
            .size(12),
        );
    }
    if device.web_audits.is_empty() {
        col = col.push(
            text("No web audit results recorded.")
                .color(TEXT_MUTED)
                .size(12),
        );
    }
    col.into()
}

fn history_tab<'a>(device: &'a crate::types::Device, known: bool) -> iced::Element<'a, Message> {
    column![
        widgets::info_row("Last seen:", format_timestamp(device.last_seen)),
        widgets::info_row("Known device:", known.to_string()),
        text("Persistent per-host history is not enabled for this milestone.")
            .color(TEXT_MUTED)
            .size(12),
    ]
    .spacing(8)
    .into()
}

fn log_filter_buttons(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut row = row![].spacing(4);
    for filter in LogSeverityFilter::all() {
        row = row.push(
            button(text(filter.label()).size(10))
                .padding([4, 8])
                .style(if *filter == app.log_severity_filter {
                    theme::primary_button
                } else {
                    theme::secondary_button
                })
                .on_press(Message::LogSeverityFilterChanged(*filter)),
        );
    }
    row.into()
}

/// Format a Unix timestamp into a human-readable time string.
fn format_timestamp(ts: i64) -> String {
    let dt = chrono::DateTime::from_timestamp(ts, 0);
    match dt {
        Some(dt) => dt.format("%H:%M:%S").to_string(),
        None => "never".to_string(),
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut truncated: String = value.chars().take(max_chars).collect();
    if value.chars().count() > max_chars {
        truncated.push_str("...");
    }
    truncated
}

/// Helper function to style table rows as clickable buttons
fn row_button_style(
    is_selected: bool,
) -> impl Fn(&iced::Theme, iced::widget::button::Status) -> iced::widget::button::Style {
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
