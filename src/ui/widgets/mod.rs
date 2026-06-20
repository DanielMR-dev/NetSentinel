//! Reusable widget components for NetSentinel UI.
//!
//! Provides common UI building blocks used across multiple views:
//! cards, info rows, status badges, port badges, loading spinners,
//! and privilege banners.

use iced::{Border, Color, Length};
use iced::widget::{container, row, text};

use crate::ui::theme::{
    self, BG, BORDER_COLOR, DANGER, INFO, PRIMARY, SUCCESS, SURFACE, TEXT, TEXT_MUTED, WARNING,
};

/// Create a styled card container with optional title
pub fn card<'a, Message: 'a>(
    title: Option<&'a str>,
    content: impl Into<iced::Element<'a, Message>>,
) -> container::Container<'a, Message> {
    let mut col = iced::widget::column![].spacing(8);

    if let Some(title) = title {
        col = col.push(
            text(title)
                .color(TEXT)
                .size(15),
        );
    }

    col = col.push(content);

    container(col)
        .padding(16)
        .width(Length::Fill)
        .style(theme::CardStyle)
}

/// Create an info row with a label and value
pub fn info_row<'a, Message: 'a>(
    label: &'a str,
    value: String,
) -> iced::widget::Row<'a, Message> {
    row![
        text(label)
            .color(TEXT_MUTED)
            .size(13),
        iced::widget::horizontal_space(8),
        text(value)
            .color(TEXT)
            .size(13),
    ]
}

/// Create a status badge (colored pill indicator)
pub fn status_badge<'a, Message: 'a>(
    status: &str,
) -> container::Container<'a, Message> {
    let (bg_color, text_color) = match status.to_lowercase().as_str() {
        "online" | "completed" | "success" | "open" => (SUCCESS, TEXT),
        "offline" | "error" | "failed" | "closed" => (DANGER, TEXT),
        "unknown" | "pending" | "filtered" => (WARNING, TEXT),
        "scanning" | "paused" | "in_progress" => (INFO, TEXT),
        _ => (SURFACE, TEXT_MUTED),
    };

    container(text(status.to_string()).color(text_color).size(11))
        .padding([2, 8])
        .style(BadgeStyle(bg_color))
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

    row![
        container(text(label).color(TEXT).size(12))
            .padding([2, 6])
            .style(BadgeStyle(state_color)),
    ]
}

/// Create a loading spinner indicator (text-based for simplicity)
pub fn loading_spinner<'a, Message: 'a>(
    message: &'a str,
) -> iced::widget::Row<'a, Message> {
    row![
        text("[*]")
            .color(INFO)
            .size(14),
        iced::widget::horizontal_space(8),
        text(message)
            .color(TEXT_MUTED)
            .size(13),
    ]
}

/// Create a privilege warning banner
pub fn privilege_banner<'a, Message: 'a>(
    warnings: &'a [String],
) -> Option<container::Container<'a, Message>> {
    if warnings.is_empty() {
        return None;
    }

    let mut col = iced::widget::column![
        text("Privilege Warning")
            .color(WARNING)
            .size(14),
    ]
    .spacing(4);

    for warning in warnings {
        col = col.push(
            text(warning.as_str())
                .color(TEXT_MUTED)
                .size(12),
        );
    }

    Some(
        container(col)
            .padding(12)
            .width(Length::Fill)
            .style(WarningBannerStyle),
    )
}

// ── Private Style Structs ───────────────────────────────────────────────

/// Badge background style
struct BadgeStyle(Color);

impl container::StyleSheet for BadgeStyle {
    type Style = iced::Theme;

    fn appearance(&self, _theme: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(iced::Background::Color(Color {
                r: self.0.r * 0.3,
                g: self.0.g * 0.3,
                b: self.0.b * 0.3,
                a: 1.0,
            })),
            border: Border {
                radius: 4.0.into(),
                width: 1.0,
                color: self.0,
            },
            text_color: Some(TEXT),
            ..Default::default()
        }
    }
}

/// Warning banner style
struct WarningBannerStyle;

impl container::StyleSheet for WarningBannerStyle {
    type Style = iced::Theme;

    fn appearance(&self, _theme: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb8(
                42, 35, 20,
            ))),
            border: Border {
                radius: 6.0.into(),
                width: 1.0,
                color: WARNING,
            },
            text_color: Some(TEXT),
            ..Default::default()
        }
    }
}
