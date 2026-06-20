//! Theme system for NetSentinel's dark UI.
//!
//! Provides color constants, style functions, and helper functions
//! for consistent styling across all views and widgets.

use iced::{Border, Color, Length, Theme};

// ── Color Palette (Dark Theme) ─────────────────────────────────────────

/// Main window background (ultra-dark charcoal)
pub const BG: Color = Color { r: 17.0 / 255.0, g: 24.0 / 255.0, b: 39.0 / 255.0, a: 1.0 };

/// Elevated surface for cards and panels
pub const SURFACE: Color = Color { r: 31.0 / 255.0, g: 41.0 / 255.0, b: 55.0 / 255.0, a: 1.0 };

/// Primary action color (blue)
pub const PRIMARY: Color = Color { r: 59.0 / 255.0, g: 130.0 / 255.0, b: 246.0 / 255.0, a: 1.0 };

/// Success / online status (green)
pub const SUCCESS: Color = Color { r: 16.0 / 255.0, g: 185.0 / 255.0, b: 129.0 / 255.0, a: 1.0 };

/// Danger / error / CVE critical (crimson)
pub const DANGER: Color = Color { r: 239.0 / 255.0, g: 68.0 / 255.0, b: 68.0 / 255.0, a: 1.0 };

/// Warning / caution (amber)
pub const WARNING: Color = Color { r: 245.0 / 255.0, g: 158.0 / 255.0, b: 11.0 / 255.0, a: 1.0 };

/// Primary text color (near-white)
pub const TEXT: Color = Color { r: 243.0 / 255.0, g: 244.0 / 255.0, b: 246.0 / 255.0, a: 1.0 };

/// Muted / secondary text (gray)
pub const TEXT_MUTED: Color = Color { r: 156.0 / 255.0, g: 163.0 / 255.0, b: 175.0 / 255.0, a: 1.0 };

/// Border color (subtle gray)
pub const BORDER_COLOR: Color = Color { r: 55.0 / 255.0, g: 65.0 / 255.0, b: 81.0 / 255.0, a: 1.0 };

/// Hover state for interactive elements
pub const HOVER: Color = Color { r: 75.0 / 255.0, g: 85.0 / 255.0, b: 99.0 / 255.0, a: 1.0 };

/// Info / neutral accent (cyan)
pub const INFO: Color = Color { r: 6.0 / 255.0, g: 182.0 / 255.0, b: 212.0 / 255.0, a: 1.0 };

/// Header / nav bar background (dark navy)
pub const HEADER_BG: Color = Color { r: 24.0 / 255.0, g: 32.0 / 255.0, b: 48.0 / 255.0, a: 1.0 };

/// Primary button hover (deeper blue)
pub const PRIMARY_HOVER: Color = Color { r: 37.0 / 255.0, g: 99.0 / 255.0, b: 235.0 / 255.0, a: 1.0 };

/// Primary button pressed (darkest blue)
pub const PRIMARY_PRESSED: Color = Color { r: 29.0 / 255.0, g: 78.0 / 255.0, b: 216.0 / 255.0, a: 1.0 };

/// Danger button hover (deeper red)
pub const DANGER_HOVER: Color = Color { r: 185.0 / 255.0, g: 28.0 / 255.0, b: 28.0 / 255.0, a: 1.0 };

/// Danger button pressed (darkest red)
pub const DANGER_PRESSED: Color = Color { r: 153.0 / 255.0, g: 27.0 / 255.0, b: 27.0 / 255.0, a: 1.0 };

/// Success button hover (deeper green)
pub const SUCCESS_HOVER: Color = Color { r: 5.0 / 255.0, g: 150.0 / 255.0, b: 105.0 / 255.0, a: 1.0 };

/// Success button pressed (darkest green)
pub const SUCCESS_PRESSED: Color = Color { r: 4.0 / 255.0, g: 120.0 / 255.0, b: 87.0 / 255.0, a: 1.0 };

/// Disabled / inactive elements (gray)
pub const DISABLED: Color = Color { r: 107.0 / 255.0, g: 114.0 / 255.0, b: 128.0 / 255.0, a: 1.0 };

/// Warning banner background (dark amber tint)
pub const WARNING_BG: Color = Color { r: 42.0 / 255.0, g: 35.0 / 255.0, b: 20.0 / 255.0, a: 1.0 };

// ── Container Styles ────────────────────────────────────────────────────

/// Style for card containers (elevated surface with border)
pub fn card_style(_theme: &Theme) -> iced::widget::container::Style {
    iced::widget::container::Style {
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

/// Style for header sections
pub fn header_style(_theme: &Theme) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(iced::Background::Color(HEADER_BG)),
        border: Border {
            radius: 0.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        text_color: Some(TEXT),
        ..Default::default()
    }
}

/// Style for the main application background
pub fn app_background(_theme: &Theme) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(iced::Background::Color(BG)),
        ..Default::default()
    }
}

// ── Button Styles ───────────────────────────────────────────────────────

/// Primary action button (blue)
pub fn primary_button(_theme: &Theme, status: iced::widget::button::Status) -> iced::widget::button::Style {
    let active = iced::widget::button::Style {
        background: Some(iced::Background::Color(PRIMARY)),
        text_color: TEXT,
        border: Border {
            radius: 6.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    };

    match status {
        iced::widget::button::Status::Active => active,
        iced::widget::button::Status::Hovered => iced::widget::button::Style {
            background: Some(iced::Background::Color(PRIMARY_HOVER)),
            ..active
        },
        iced::widget::button::Status::Pressed => iced::widget::button::Style {
            background: Some(iced::Background::Color(PRIMARY_PRESSED)),
            ..active
        },
        iced::widget::button::Status::Disabled => iced::widget::button::Style {
            background: Some(iced::Background::Color(DISABLED)),
            ..active
        },
    }
}

/// Danger button (red) for destructive actions
pub fn danger_button(_theme: &Theme, status: iced::widget::button::Status) -> iced::widget::button::Style {
    let active = iced::widget::button::Style {
        background: Some(iced::Background::Color(DANGER)),
        text_color: TEXT,
        border: Border {
            radius: 6.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    };

    match status {
        iced::widget::button::Status::Active => active,
        iced::widget::button::Status::Hovered => iced::widget::button::Style {
            background: Some(iced::Background::Color(DANGER_HOVER)),
            ..active
        },
        iced::widget::button::Status::Pressed => iced::widget::button::Style {
            background: Some(iced::Background::Color(DANGER_PRESSED)),
            ..active
        },
        iced::widget::button::Status::Disabled => iced::widget::button::Style {
            background: Some(iced::Background::Color(DISABLED)),
            ..active
        },
    }
}

/// Secondary button (outlined) for non-primary actions
pub fn secondary_button(_theme: &Theme, status: iced::widget::button::Status) -> iced::widget::button::Style {
    let active = iced::widget::button::Style {
        background: Some(iced::Background::Color(SURFACE)),
        text_color: TEXT,
        border: Border {
            radius: 6.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
        ..Default::default()
    };

    match status {
        iced::widget::button::Status::Active => active,
        iced::widget::button::Status::Hovered => iced::widget::button::Style {
            background: Some(iced::Background::Color(HOVER)),
            ..active
        },
        iced::widget::button::Status::Pressed => iced::widget::button::Style {
            background: Some(iced::Background::Color(BORDER_COLOR)),
            ..active
        },
        iced::widget::button::Status::Disabled => iced::widget::button::Style {
            background: Some(iced::Background::Color(BORDER_COLOR)),
            ..active
        },
    }
}

/// Success button (green) for confirmations
pub fn success_button(_theme: &Theme, status: iced::widget::button::Status) -> iced::widget::button::Style {
    let active = iced::widget::button::Style {
        background: Some(iced::Background::Color(SUCCESS)),
        text_color: TEXT,
        border: Border {
            radius: 6.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    };

    match status {
        iced::widget::button::Status::Active => active,
        iced::widget::button::Status::Hovered => iced::widget::button::Style {
            background: Some(iced::Background::Color(SUCCESS_HOVER)),
            ..active
        },
        iced::widget::button::Status::Pressed => iced::widget::button::Style {
            background: Some(iced::Background::Color(SUCCESS_PRESSED)),
            ..active
        },
        iced::widget::button::Status::Disabled => iced::widget::button::Style {
            background: Some(iced::Background::Color(DISABLED)),
            ..active
        },
    }
}

// ── Helper Functions ────────────────────────────────────────────────────

/// Create a styled card container with padding
pub fn card<'a, Message: 'a>(
    content: impl Into<iced::Element<'a, Message>>,
) -> iced::widget::container::Container<'a, Message> {
    iced::widget::container(content)
        .padding(16)
        .style(card_style)
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
        iced::widget::horizontal_space().width(Length::Fixed(10.0)),
        iced::widget::text(value)
            .color(TEXT)
            .size(13),
    ]
    .spacing(0)
}

/// Create a section header text
pub fn section_header<'a>(
    title: &'a str,
) -> iced::widget::Text<'a, Theme> {
    iced::widget::text(title)
        .color(TEXT)
        .size(16)
}
