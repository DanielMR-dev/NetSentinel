//! Theme system for NetSentinel's dark UI.
//!
//! Provides color constants, style structs, and helper functions
//! for consistent styling across all views and widgets.

use iced::{Border, Color, Theme};
use iced::widget::{button, container};

// ── Color Palette (Dark Theme) ─────────────────────────────────────────

/// Main window background (ultra-dark charcoal)
pub const BG: Color = Color::from_rgb8(17, 24, 39);

/// Elevated surface for cards and panels
pub const SURFACE: Color = Color::from_rgb8(31, 41, 55);

/// Primary action color (blue)
pub const PRIMARY: Color = Color::from_rgb8(59, 130, 246);

/// Success / online status (green)
pub const SUCCESS: Color = Color::from_rgb8(16, 185, 129);

/// Danger / error / CVE critical (crimson)
pub const DANGER: Color = Color::from_rgb8(239, 68, 68);

/// Warning / caution (amber)
pub const WARNING: Color = Color::from_rgb8(245, 158, 11);

/// Primary text color (near-white)
pub const TEXT: Color = Color::from_rgb8(243, 244, 246);

/// Muted / secondary text (gray)
pub const TEXT_MUTED: Color = Color::from_rgb8(156, 163, 175);

/// Border color (subtle gray)
pub const BORDER_COLOR: Color = Color::from_rgb8(55, 65, 81);

/// Hover state for interactive elements
pub const HOVER: Color = Color::from_rgb8(75, 85, 99);

/// Info / neutral accent (cyan)
pub const INFO: Color = Color::from_rgb8(6, 182, 212);

// ── Container Styles ────────────────────────────────────────────────────

/// Style for card containers (elevated surface with border)
pub struct CardStyle;

impl container::StyleSheet for CardStyle {
    type Style = Theme;

    fn appearance(&self, _theme: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(iced::Background::Color(SURFACE)),
            border: Border {
                radius: 8.0.into(),
                width: 1.0,
                color: BORDER_COLOR,
            },
            text_color: Some(TEXT),
            ..Default::default()
        }
    }
}

/// Style for header sections
pub struct HeaderStyle;

impl container::StyleSheet for HeaderStyle {
    type Style = Theme;

    fn appearance(&self, _theme: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb8(24, 32, 48))),
            border: Border {
                radius: 0.0.into(),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
            text_color: Some(TEXT),
            ..Default::default()
        }
    }
}

/// Style for the main application background
pub struct AppBackground;

impl container::StyleSheet for AppBackground {
    type Style = Theme;

    fn appearance(&self, _theme: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(iced::Background::Color(BG)),
            ..Default::default()
        }
    }
}

// ── Button Styles ───────────────────────────────────────────────────────

/// Primary action button (blue)
pub struct PrimaryButton;

impl button::StyleSheet for PrimaryButton {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> button::Style {
        button::Style {
            background: Some(iced::Background::Color(PRIMARY)),
            text_color: TEXT,
            border: Border {
                radius: 6.0.into(),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Self::Style) -> button::Style {
        let active = self.active(style);
        button::Style {
            background: Some(iced::Background::Color(Color::from_rgb8(37, 99, 235))),
            ..active
        }
    }
}

/// Danger button (red) for destructive actions
pub struct DangerButton;

impl button::StyleSheet for DangerButton {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> button::Style {
        button::Style {
            background: Some(iced::Background::Color(DANGER)),
            text_color: TEXT,
            border: Border {
                radius: 6.0.into(),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Self::Style) -> button::Style {
        let active = self.active(style);
        button::Style {
            background: Some(iced::Background::Color(Color::from_rgb8(185, 28, 28))),
            ..active
        }
    }
}

/// Secondary button (outlined) for non-primary actions
pub struct SecondaryButton;

impl button::StyleSheet for SecondaryButton {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> button::Style {
        button::Style {
            background: Some(iced::Background::Color(SURFACE)),
            text_color: TEXT,
            border: Border {
                radius: 6.0.into(),
                width: 1.0,
                color: BORDER_COLOR,
            },
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Self::Style) -> button::Style {
        let active = self.active(style);
        button::Style {
            background: Some(iced::Background::Color(HOVER)),
            ..active
        }
    }
}

/// Success button (green) for confirmations
pub struct SuccessButton;

impl button::StyleSheet for SuccessButton {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> button::Style {
        button::Style {
            background: Some(iced::Background::Color(SUCCESS)),
            text_color: TEXT,
            border: Border {
                radius: 6.0.into(),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Self::Style) -> button::Style {
        let active = self.active(style);
        button::Style {
            background: Some(iced::Background::Color(Color::from_rgb8(5, 150, 105))),
            ..active
        }
    }
}

// ── Helper Functions ────────────────────────────────────────────────────

/// Create a styled card container with padding
pub fn card<'a, Message: 'a>(
    content: impl Into<iced::Element<'a, Message>>,
) -> container::Container<'a, Message> {
    container(content)
        .padding(16)
        .style(CardStyle)
}

/// Create an info row with label and value
pub fn info_row<'a, Message: 'a>(
    label: &'a str,
    value: String,
) -> iced::widget::Row<'a, Message> {
    iced::widget::row![
        iced::widget::text(label)
            .color(TEXT_MUTED)
            .size(13),
        iced::widget::horizontal_space(10),
        iced::widget::text(value)
            .color(TEXT)
            .size(13),
    ]
    .spacing(0)
}

/// Create a section header text
pub fn section_header<'a, Message: 'a>(
    title: &'a str,
) -> iced::widget::Text<'a, Message> {
    iced::widget::text(title)
        .color(TEXT)
        .size(16)
}
