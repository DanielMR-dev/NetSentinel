//! Settings view — profile manager, scan config editor, UI preferences.

use iced::{Alignment, Length};
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};

use crate::ui::theme::{self, TEXT, TEXT_MUTED};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

/// Render the Settings page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).width(Length::Fill);

    // ── Profile Manager ─────────────────────────────────────────────────
    let mut profile_list = column![].spacing(4);

    if app.settings_profiles.is_empty() {
        profile_list = profile_list.push(
            text("No profiles saved yet.")
                .color(TEXT_MUTED)
                .size(13),
        );
    } else {
        for profile in &app.settings_profiles {
            let is_active = app.settings_profile.id == profile.id;
            let label = if is_active {
                format!("{} (active)", profile.name)
            } else {
                profile.name.clone()
            };

            let mut profile_row = row![
                text(label)
                    .color(if is_active { TEXT } else { TEXT_MUTED })
                    .size(13)
                    .width(Length::Fill),
                button(text("Load").color(TEXT).size(11))
                    .padding([4, 10])
                    .style(theme::secondary_button)
                    .on_press(Message::ProfileSelected(profile.id.clone())),
            ]
            .spacing(8)
            .padding([4, 8])
            .align_y(Alignment::Center);

            if profile.id != "default" {
                profile_row = profile_row.push(
                    button(text("Delete").color(TEXT).size(11))
                        .padding([4, 10])
                        .style(theme::danger_button)
                        .on_press(Message::ProfileDeleted(profile.id.clone())),
                );
            }

            profile_list = profile_list.push(profile_row);
        }
    }

    let create_btn = button(text("New Profile").color(TEXT).size(13))
        .padding([6, 14])
        .style(theme::primary_button)
        .on_press(Message::ProfileCreated);

    let profile_card = widgets::card(
        Some("Settings Profiles"),
        column![
            scrollable(profile_list).height(Length::Fixed(150.0)),
            create_btn,
        ]
        .spacing(8),
    );

    content = content.push(profile_card);

    // ── Scan Configuration Editor ───────────────────────────────────────
    let profile = &app.settings_profile;

    let cidr_input = text_input("Default CIDR", &profile.scan_config.default_cidr)
        .on_input(Message::SettingsCidrChanged)
        .padding(8)
        .size(13);

    let timeout_input = text_input(
        "Timeout (ms)",
        &profile.scan_config.timeout_ms.to_string(),
    )
    .on_input(Message::SettingsTimeoutChanged)
    .padding(8)
    .size(13);

    let max_hosts_input = text_input(
        "Max Concurrent Hosts",
        &profile.scan_config.max_concurrent_hosts.to_string(),
    )
    .on_input(Message::SettingsMaxHostsChanged)
    .padding(8)
    .size(13);

    let max_ports_input = text_input(
        "Max Concurrent Ports",
        &profile.scan_config.max_concurrent_ports.to_string(),
    )
    .on_input(Message::SettingsMaxPortsChanged)
    .padding(8)
    .size(13);

    let retry_input = text_input(
        "Retry Count",
        &profile.scan_config.retry_count.to_string(),
    )
    .on_input(Message::SettingsRetryChanged)
    .padding(8)
    .size(13);

    let scan_ports_check = checkbox(
        "Enable Port Scanning",
        profile.scan_config.scan_ports_enabled,
    )
    .on_toggle(Message::SettingsScanPortsToggled)
    .size(14);

    let scan_config_card = widgets::card(
        Some("Scan Configuration"),
        column![
            row![
                column![
                    text("Default CIDR").color(TEXT_MUTED).size(11),
                    cidr_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(1)),
                column![
                    text("Timeout (ms)").color(TEXT_MUTED).size(11),
                    timeout_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(1)),
            ]
            .spacing(12),
            row![
                column![
                    text("Max Hosts").color(TEXT_MUTED).size(11),
                    max_hosts_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(1)),
                column![
                    text("Max Ports").color(TEXT_MUTED).size(11),
                    max_ports_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(1)),
            ]
            .spacing(12),
            row![
                column![
                    text("Retries").color(TEXT_MUTED).size(11),
                    retry_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(1)),
                column![].width(Length::FillPortion(1)),
            ]
            .spacing(12),
            scan_ports_check,
        ]
        .spacing(10),
    );

    content = content.push(scan_config_card);

    // ── UI Preferences ──────────────────────────────────────────────────
    let auto_refresh_check = checkbox(
        "Auto-refresh scan results",
        profile.ui_preferences.auto_refresh,
    )
    .on_toggle(Message::SettingsAutoRefreshToggled)
    .size(14);

    let confirm_check = checkbox(
        "Confirm before scan",
        profile.ui_preferences.confirm_before_scan,
    )
    .on_toggle(Message::SettingsConfirmScanToggled)
    .size(14);

    let advanced_check = checkbox(
        "Show advanced options",
        profile.ui_preferences.show_advanced_options,
    )
    .on_toggle(Message::SettingsAdvancedToggled)
    .size(14);

    let refresh_input = text_input(
        "Refresh Rate (ms)",
        &profile.ui_preferences.refresh_rate_ms.to_string(),
    )
    .on_input(Message::SettingsRefreshRateChanged)
    .padding(8)
    .size(13);

    let ui_prefs_card = widgets::card(
        Some("UI Preferences"),
        column![
            row![
                column![
                    text("Refresh Rate (ms)").color(TEXT_MUTED).size(11),
                    refresh_input,
                ]
                .spacing(2)
                .width(Length::FillPortion(1)),
                column![].width(Length::FillPortion(1)),
            ]
            .spacing(12),
            auto_refresh_check,
            confirm_check,
            advanced_check,
        ]
        .spacing(8),
    );

    content = content.push(ui_prefs_card);

    // ── Save Button ─────────────────────────────────────────────────────
    let save_btn = button(text("Save Settings").color(TEXT).size(14))
        .padding([8, 20])
        .style(theme::success_button)
        .on_press(Message::SaveSettings);

    content = content.push(save_btn);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
            .style(theme::app_background)
        .into()
}
