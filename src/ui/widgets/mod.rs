//! Reusable widget components for NetSentinel UI.
//!
//! Provides common UI building blocks used across multiple views:
//! cards, info rows, status badges, port badges, loading spinners,
//! and privilege banners.

use iced::widget::{container, row, text};
use iced::{Border, Color, Length, Theme};

use crate::types::FindingSeverity;
use crate::ui::theme::{DANGER, INFO, SUCCESS, SURFACE, TEXT, TEXT_MUTED, WARNING, WARNING_BG};

/// Create a styled card container with optional title
pub fn card<'a, Message: 'a>(
    title: Option<impl ToString>,
    content: impl Into<iced::Element<'a, Message>>,
) -> container::Container<'a, Message> {
    let mut col = iced::widget::column![].spacing(8);

    if let Some(title) = title {
        col = col.push(text(title.to_string()).color(TEXT).size(15));
    }

    col = col.push(content);

    container(col)
        .padding(16)
        .width(Length::Fill)
        .style(crate::ui::theme::card_style)
}

/// Create an info row with a label and value
pub fn info_row<'a, Message: 'a>(label: &'a str, value: String) -> iced::widget::Row<'a, Message> {
    row![
        text(label).color(TEXT_MUTED).size(13),
        iced::widget::horizontal_space().width(Length::Fixed(8.0)),
        text(value).color(TEXT).size(13),
    ]
}

/// Create a status badge (colored pill indicator)
pub fn status_badge<'a, Message: 'a>(status: &str) -> container::Container<'a, Message> {
    let (bg_color, text_color) = match status.to_lowercase().as_str() {
        "online" | "completed" | "success" | "open" => (SUCCESS, TEXT),
        "offline" | "error" | "failed" | "closed" => (DANGER, TEXT),
        "unknown" | "pending" | "filtered" => (WARNING, TEXT),
        "scanning" | "paused" | "in_progress" => (INFO, TEXT),
        _ => (SURFACE, TEXT_MUTED),
    };

    container(text(status.to_string()).color(text_color).size(11))
        .padding([2, 8])
        .style(move |_theme: &Theme| badge_appearance(bg_color))
}

/// Create a port state badge
pub fn port_badge<'a, Message: 'a>(
    port: u16,
    state: &str,
    service: Option<&str>,
) -> iced::widget::Row<'a, Message> {
    let state_color = match state {
        "open" | "Open" => SUCCESS,
        "closed" | "Closed" => DANGER,
        "filtered" | "Filtered" => WARNING,
        _ => TEXT_MUTED,
    };

    let label = if let Some(svc) = service {
        format!("{}/{} ({})", port, state, svc)
    } else {
        format!("{}/{}", port, state)
    };

    row![container(text(label).color(TEXT).size(12))
        .padding([2, 6])
        .style(move |_theme: &Theme| badge_appearance(state_color)),]
}

/// Theme color for a finding severity.
pub fn finding_severity_color(severity: &FindingSeverity) -> Color {
    match severity {
        FindingSeverity::Critical | FindingSeverity::High => DANGER,
        FindingSeverity::Medium => WARNING,
        FindingSeverity::Low => INFO,
        FindingSeverity::Info => TEXT_MUTED,
    }
}

/// Create a finding severity badge.
pub fn finding_severity_badge<'a, Message: 'a>(
    severity: &FindingSeverity,
) -> container::Container<'a, Message> {
    let color = finding_severity_color(severity);
    container(text(format!("{:?}", severity)).color(TEXT).size(11))
        .padding([2, 8])
        .style(move |_theme: &Theme| badge_appearance(color))
}

/// Create a compact findings count badge.
pub fn findings_count_badge<'a, Message: 'a>(count: usize) -> container::Container<'a, Message> {
    let color = if count > 0 { WARNING } else { SURFACE };
    container(text(count.to_string()).color(TEXT).size(11))
        .padding([2, 8])
        .style(move |_theme: &Theme| badge_appearance(color))
}

/// Create a loading spinner indicator (text-based for simplicity)
pub fn loading_spinner<'a, Message: 'a>(message: &'a str) -> iced::widget::Row<'a, Message> {
    row![
        text("[*]").color(INFO).size(14),
        iced::widget::horizontal_space().width(Length::Fixed(8.0)),
        text(message).color(TEXT_MUTED).size(13),
    ]
}

/// Create a privilege warning banner
pub fn privilege_banner<'a, Message: 'a>(
    warnings: &'a [String],
) -> Option<container::Container<'a, Message>> {
    if warnings.is_empty() {
        return None;
    }

    let mut col =
        iced::widget::column![text("Privilege Warning").color(WARNING).size(14),].spacing(4);

    for warning in warnings {
        col = col.push(text(warning.as_str()).color(TEXT_MUTED).size(12));
    }

    Some(
        container(col)
            .padding(12)
            .width(Length::Fill)
            .style(warning_banner_style),
    )
}

// ── Private Style Helpers ───────────────────────────────────────────────

/// Badge background style
fn badge_appearance(bg_color: Color) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(iced::Background::Color(Color {
            r: bg_color.r * 0.3,
            g: bg_color.g * 0.3,
            b: bg_color.b * 0.3,
            a: 1.0,
        })),
        border: Border {
            radius: 4.0.into(),
            width: 1.0,
            color: bg_color,
        },
        text_color: Some(TEXT),
        ..Default::default()
    }
}

/// Warning banner style
fn warning_banner_style(_theme: &Theme) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(iced::Background::Color(WARNING_BG)),
        border: Border {
            radius: 6.0.into(),
            width: 1.0,
            color: WARNING,
        },
        text_color: Some(TEXT),
        ..Default::default()
    }
}
