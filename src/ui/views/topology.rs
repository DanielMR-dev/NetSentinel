//! Topology view — static, refreshable network graph summary.
//!
//! Renders the cached `TopologyGraph` as summary cards, a legend, a node list,
//! and an edge list. The view is intentionally non-interactive and avoids
//! canvas-heavy layouts so it cannot block the UI thread.

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Length};

use crate::types::{EdgeKind, NodeKind, TopologyGraph};
use crate::ui::theme::{self, INFO, SUCCESS, TEXT, TEXT_MUTED, WARNING};
use crate::ui::widgets;
use crate::ui::{Message, NetSentinelApp};

/// Render the Topology page.
pub fn view(app: &NetSentinelApp) -> iced::Element<'_, Message> {
    let mut content = column![].spacing(16).width(Length::Fill);

    // ── Header with refresh control ───────────────────────────────────────
    let title = text("Network Topology").color(TEXT).size(20);

    let refresh_btn = button(text("Refresh").color(TEXT).size(13))
        .padding([6, 14])
        .style(theme::primary_button)
        .on_press(Message::TopologyRefresh);

    let header_row = row![
        title,
        iced::widget::horizontal_space().width(Length::Fill),
        refresh_btn,
    ]
    .spacing(16)
    .align_y(Alignment::Center)
    .width(Length::Fill);

    content = content.push(header_row);

    // ── Loading / error states ────────────────────────────────────────────
    if app.topology_loading {
        content = content.push(widgets::card(
            Some("Loading topology"),
            widgets::loading_spinner("Building topology graph..."),
        ));
    }

    if let Some(ref error) = app.topology_error {
        content = content.push(widgets::card(
            Some("Topology error"),
            text(error.as_str()).color(theme::DANGER).size(13),
        ));
    }

    // ── Graph content ─────────────────────────────────────────────────────
    match app.topology_graph {
        Some(ref graph) => {
            content = content.push(summary_card(graph));
            content = content.push(legend_card());
            content = content.push(nodes_card(graph));
            content = content.push(edges_card(graph));
        }
        None if !app.topology_loading => {
            content = content.push(widgets::card(
                None::<&str>,
                text("No topology data available. Click Refresh to build the graph from discovered devices and the ARP cache.")
                    .color(TEXT_MUTED)
                    .size(13),
            ));
        }
        None => {}
    }

    scrollable(
        container(content)
            .padding(0)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .into()
}

/// Summary card with node/edge counts.
fn summary_card(graph: &TopologyGraph) -> iced::Element<'_, Message> {
    let gateway_count = graph
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, NodeKind::Gateway))
        .count();
    let endpoint_count = graph
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, NodeKind::Endpoint | NodeKind::LocalHost))
        .count();
    let server_count = graph
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, NodeKind::Server))
        .count();

    let summary_row = row![
        stat_column("Nodes", graph.nodes.len()),
        stat_column("Edges", graph.edges.len()),
        stat_column("Gateways", gateway_count),
        stat_column("Endpoints", endpoint_count),
        stat_column("Servers", server_count),
    ]
    .spacing(16)
    .width(Length::Fill);

    widgets::card(Some("Topology Summary"), summary_row).into()
}

/// A single stat column for the summary card.
fn stat_column(label: &str, value: usize) -> iced::Element<'_, Message> {
    column![
        text(value.to_string())
            .color(TEXT)
            .size(22)
            .align_x(iced::alignment::Horizontal::Center),
        text(label)
            .color(TEXT_MUTED)
            .size(12)
            .align_x(iced::alignment::Horizontal::Center),
    ]
    .spacing(4)
    .width(Length::Fill)
    .into()
}

/// Legend describing node kind colors.
fn legend_card<'a>() -> iced::Element<'a, Message> {
    let items = vec![
        ("Gateway", NodeKind::Gateway),
        ("Localhost", NodeKind::LocalHost),
        ("Server", NodeKind::Server),
        ("Endpoint", NodeKind::Endpoint),
        ("Router", NodeKind::Router),
        ("Unknown", NodeKind::Unknown),
    ];

    let mut legend_row = row![].spacing(12).align_y(Alignment::Center);
    for (label, kind) in items {
        legend_row = legend_row.push(legend_item(label, node_kind_color(&kind)));
    }

    widgets::card(Some("Legend"), legend_row).into()
}

/// A single legend item: colored dot + label.
fn legend_item(label: &str, color: iced::Color) -> iced::Element<'_, Message> {
    row![
        container(iced::widget::horizontal_space().width(Length::Fixed(10.0)))
            .height(Length::Fixed(10.0))
            .style(move |_theme: &iced::Theme| iced::widget::container::Style {
                background: Some(iced::Background::Color(color)),
                ..Default::default()
            }),
        text(label).color(TEXT).size(12),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .into()
}

/// Card listing all topology nodes.
fn nodes_card(graph: &TopologyGraph) -> iced::Element<'_, Message> {
    let mut node_list = column![].spacing(4).width(Length::Fill);

    // Header
    node_list = node_list.push(
        row![
            text("Node")
                .color(TEXT_MUTED)
                .size(12)
                .width(Length::FillPortion(2)),
            text("Kind")
                .color(TEXT_MUTED)
                .size(12)
                .width(Length::FillPortion(1)),
            text("Source")
                .color(TEXT_MUTED)
                .size(12)
                .width(Length::FillPortion(1)),
        ]
        .spacing(8)
        .padding([4, 8])
        .width(Length::Fill),
    );

    if graph.nodes.is_empty() {
        node_list = node_list.push(
            text("No nodes in topology graph.")
                .color(TEXT_MUTED)
                .size(13),
        );
    } else {
        for node in &graph.nodes {
            let kind_badge = node_kind_badge(&node.kind);
            let source_badge = topology_source_badge(&node.source);

            node_list = node_list.push(
                row![
                    text(&node.label)
                        .color(TEXT)
                        .size(12)
                        .width(Length::FillPortion(2)),
                    kind_badge.width(Length::FillPortion(1)),
                    source_badge.width(Length::FillPortion(1)),
                ]
                .spacing(8)
                .padding([4, 8])
                .align_y(Alignment::Center)
                .width(Length::Fill),
            );
        }
    }

    widgets::card(
        Some("Nodes"),
        scrollable(node_list).height(Length::Fixed(240.0)),
    )
    .into()
}

/// Card listing all topology edges.
fn edges_card(graph: &TopologyGraph) -> iced::Element<'_, Message> {
    let mut edge_list = column![].spacing(4).width(Length::Fill);

    edge_list = edge_list.push(
        row![
            text("Source")
                .color(TEXT_MUTED)
                .size(12)
                .width(Length::FillPortion(2)),
            text("Target")
                .color(TEXT_MUTED)
                .size(12)
                .width(Length::FillPortion(2)),
            text("Kind")
                .color(TEXT_MUTED)
                .size(12)
                .width(Length::FillPortion(1)),
        ]
        .spacing(8)
        .padding([4, 8])
        .width(Length::Fill),
    );

    if graph.edges.is_empty() {
        edge_list = edge_list.push(
            text("No edges in topology graph.")
                .color(TEXT_MUTED)
                .size(13),
        );
    } else {
        for edge in &graph.edges {
            edge_list = edge_list.push(
                row![
                    text(&edge.source)
                        .color(TEXT)
                        .size(12)
                        .width(Length::FillPortion(2)),
                    text(&edge.target)
                        .color(TEXT)
                        .size(12)
                        .width(Length::FillPortion(2)),
                    edge_kind_badge(&edge.kind).width(Length::FillPortion(1)),
                ]
                .spacing(8)
                .padding([4, 8])
                .align_y(Alignment::Center)
                .width(Length::Fill),
            );
        }
    }

    widgets::card(
        Some("Edges"),
        scrollable(edge_list).height(Length::Fixed(200.0)),
    )
    .into()
}

/// Badge for a node kind.
fn node_kind_badge(kind: &NodeKind) -> iced::widget::Container<'_, Message> {
    container(text(format!("{:?}", kind)).color(TEXT).size(11))
        .padding([2, 8])
        .style(move |_theme: &iced::Theme| badge_appearance(node_kind_color(kind)))
}

/// Badge for an edge kind.
fn edge_kind_badge(kind: &EdgeKind) -> iced::widget::Container<'_, Message> {
    let color = match kind {
        EdgeKind::GatewayLink => SUCCESS,
        EdgeKind::DirectLink => INFO,
        EdgeKind::Inferred => WARNING,
        EdgeKind::Unknown => TEXT_MUTED,
    };

    container(text(format!("{:?}", kind)).color(TEXT).size(11))
        .padding([2, 8])
        .style(move |_theme: &iced::Theme| badge_appearance(color))
}

/// Badge for a topology source.
fn topology_source_badge(
    source: &crate::types::TopologySource,
) -> iced::widget::Container<'_, Message> {
    let label = match source {
        crate::types::TopologySource::Discovery => "Discovery",
        crate::types::TopologySource::ArpTable => "ARP",
        crate::types::TopologySource::NetworkInfo => "Network",
        crate::types::TopologySource::FlowObserved => "Flow",
        crate::types::TopologySource::Inferred => "Inferred",
    };

    container(text(label).color(TEXT).size(11))
        .padding([2, 8])
        .style(move |_theme: &iced::Theme| badge_appearance(TEXT_MUTED))
}

/// Map a node kind to a theme color.
fn node_kind_color(kind: &NodeKind) -> iced::Color {
    match kind {
        NodeKind::Gateway => SUCCESS,
        NodeKind::LocalHost => INFO,
        NodeKind::Server => theme::PRIMARY,
        NodeKind::Router => WARNING,
        NodeKind::Endpoint => TEXT,
        NodeKind::Peripheral => TEXT_MUTED,
        NodeKind::Virtual => INFO,
        NodeKind::Unknown => TEXT_MUTED,
    }
}

/// Shared badge appearance helper.
fn badge_appearance(bg_color: iced::Color) -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(iced::Background::Color(iced::Color {
            r: bg_color.r * 0.3,
            g: bg_color.g * 0.3,
            b: bg_color.b * 0.3,
            a: 1.0,
        })),
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: bg_color,
        },
        text_color: Some(TEXT),
        ..Default::default()
    }
}
