//! HTML & PDF Report Generation
//!
//! Generates self-contained HTML reports with inline SVG charts, and PDF reports.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use chrono::Utc;
use html_escape::encode_text;
use printpdf::*;

use crate::reporting::compliance::ComplianceEngine;
use crate::reporting::risk::{finding_risk_score, top_hosts_by_risk};
use crate::types::{Device, Finding, FindingCategory, FindingSeverity};

// ── HTML color constants ───────────────────────────────────────────────────

const HTML_CRITICAL: &str = "#991b1b";
const HTML_HIGH: &str = "#dc2626";
const HTML_MEDIUM: &str = "#d97706";
const HTML_LOW: &str = "#0891b2";
const HTML_INFO: &str = "#6b7280";
const HTML_PRIMARY: &str = "#2563eb";
const HTML_AXIS: &str = "#9ca3af";
const HTML_GRID: &str = "#e5e7eb";

fn severity_rank(severity: &FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Info => 4,
    }
}

fn finding_counts(devices: &[Device]) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut info = 0usize;

    for finding in devices.iter().flat_map(|device| &device.findings) {
        match &finding.severity {
            FindingSeverity::Critical => critical += 1,
            FindingSeverity::High => high += 1,
            FindingSeverity::Medium => medium += 1,
            FindingSeverity::Low => low += 1,
            FindingSeverity::Info => info += 1,
        }
    }

    (critical, high, medium, low, info)
}

fn aggregate_findings_by_category(findings: &[&Finding]) -> Vec<(FindingCategory, [usize; 5])> {
    let mut map: HashMap<FindingCategory, [usize; 5]> = HashMap::new();
    for finding in findings {
        let entry = map.entry(finding.category.clone()).or_insert([0; 5]);
        let idx = severity_rank(&finding.severity) as usize;
        entry[idx] += 1;
    }

    let order = [
        FindingCategory::Cve,
        FindingCategory::Web,
        FindingCategory::ActiveCheck,
        FindingCategory::Tls,
        FindingCategory::Compliance,
        FindingCategory::Traffic,
        FindingCategory::Exposure,
    ];

    order
        .iter()
        .filter_map(|cat| map.get(cat).map(|counts| (cat.clone(), *counts)))
        .collect()
}

// ── SVG charts ─────────────────────────────────────────────────────────────

fn svg_severity_by_category(findings: &[&Finding]) -> String {
    let data = aggregate_findings_by_category(findings);
    let width = 800.0;
    let height = 400.0;
    let left = 120.0;
    let right = 40.0;
    let top = 40.0;
    let bottom = 80.0;
    let plot_w = width - left - right;
    let plot_h = height - top - bottom;

    let max_value = data
        .iter()
        .flat_map(|(_, counts)| counts.iter())
        .copied()
        .max()
        .unwrap_or(0);

    if max_value == 0 {
        return format!(
            "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\"><text x=\"{}\" y=\"{}\" text-anchor=\"middle\" fill=\"{}\" font-size=\"16\">No data</text></svg>",
            width, height, width / 2.0, height / 2.0, HTML_AXIS
        );
    }

    let n = data.len().max(1);
    let group_w = plot_w / n as f64;
    let bar_w = group_w / 6.5;
    let colors = [HTML_CRITICAL, HTML_HIGH, HTML_MEDIUM, HTML_LOW, HTML_INFO];
    let labels = ["Critical", "High", "Medium", "Low", "Info"];

    let mut svg = format!(
        "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\">",
        width, height
    );

    // Grid lines
    for i in 0..=5 {
        let y = bottom - (i as f64 / 5.0) * plot_h;
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
            left,
            y,
            width - right,
            y,
            HTML_GRID
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"end\" fill=\"{}\" font-size=\"11\">{}</text>",
            left - 8.0,
            y + 4.0,
            HTML_AXIS,
            (max_value as f64 * i as f64 / 5.0).round()
        ));
    }

    // Bars and category labels
    for (i, (category, counts)) in data.iter().enumerate() {
        let group_x = left + i as f64 * group_w + group_w * 0.05;
        for (j, count) in counts.iter().enumerate() {
            let h = (*count as f64 / max_value as f64) * plot_h;
            let x = group_x + j as f64 * bar_w;
            let y = bottom - h;
            svg.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>",
                x,
                y,
                bar_w * 0.9,
                h,
                colors[j]
            ));
        }
        let label_x = group_x + (bar_w * 5.0) / 2.0;
        let category_text = format!("{:?}", category);
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" fill=\"{}\" font-size=\"12\">{}</text>",
            label_x,
            height - 55.0,
            HTML_AXIS,
            encode_text(&category_text)
        ));
    }

    // Legend
    for (j, label) in labels.iter().enumerate() {
        let lx = left + j as f64 * 90.0;
        let ly = height - 25.0;
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"12\" height=\"12\" fill=\"{}\"/>",
            lx, ly, colors[j]
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" fill=\"{}\" font-size=\"12\">{}</text>",
            lx + 18.0,
            ly + 11.0,
            HTML_AXIS,
            encode_text(label)
        ));
    }

    svg.push_str("</svg>");
    svg
}

fn svg_top_hosts_by_risk(devices: &[Device], top_n: usize) -> String {
    let top = top_hosts_by_risk(devices, top_n);
    let width = 800.0;
    let height = 400.0;
    let left = 140.0;
    let right = 80.0;
    let top_m = 20.0;
    let bottom_m = 20.0;
    let plot_w = width - left - right;
    let plot_h = height - top_m - bottom_m;

    if top.is_empty() {
        return format!(
            "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\"><text x=\"{}\" y=\"{}\" text-anchor=\"middle\" fill=\"{}\" font-size=\"16\">No data</text></svg>",
            width, height, width / 2.0, height / 2.0, HTML_AXIS
        );
    }

    let max_score = top
        .iter()
        .map(|(_, score)| *score)
        .fold(0.0, f64::max)
        .max(1.0);
    let n = top.len().max(1);
    let row_h = plot_h / n as f64;
    let bar_h = row_h * 0.65;

    let mut svg = format!(
        "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\">",
        width, height
    );

    for (i, (device, score)) in top.iter().enumerate() {
        let y = top_m + i as f64 * row_h + (row_h - bar_h) / 2.0;
        let bar_w = (*score / max_score) * plot_w;
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\" rx=\"4\"/>",
            left, y, bar_w, bar_h, HTML_PRIMARY
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"end\" fill=\"{}\" font-size=\"12\">{}</text>",
            left - 10.0,
            y + bar_h * 0.7,
            HTML_AXIS,
            encode_text(&device.ip)
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" fill=\"{}\" font-size=\"12\">{:.1}</text>",
            left + bar_w + 8.0,
            y + bar_h * 0.7,
            HTML_AXIS,
            score
        ));
    }

    svg.push_str("</svg>");
    svg
}

fn svg_open_ports_chart(devices: &[Device], top_n: usize) -> String {
    let mut counts: HashMap<u16, usize> = HashMap::new();
    for device in devices {
        for port in &device.ports {
            if port.state == crate::types::PortState::Open {
                *counts.entry(port.number).or_insert(0) += 1;
            }
        }
    }

    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let top: Vec<_> = sorted.into_iter().take(top_n).collect();

    let width = 800.0;
    let height = 400.0;
    let left = 60.0;
    let right = 40.0;
    let top_m = 40.0;
    let bottom_m = 80.0;
    let plot_w = width - left - right;
    let plot_h = height - top_m - bottom_m;

    if top.is_empty() {
        return format!(
            "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\"><text x=\"{}\" y=\"{}\" text-anchor=\"middle\" fill=\"{}\" font-size=\"16\">No data</text></svg>",
            width, height, width / 2.0, height / 2.0, HTML_AXIS
        );
    }

    let max_value = top.iter().map(|(_, c)| *c).max().unwrap_or(0).max(1);
    let n = top.len().max(1);
    let bar_w = plot_w / (n as f64 * 1.5);

    let mut svg = format!(
        "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\">",
        width, height
    );

    for i in 0..=5 {
        let y = bottom_m - (i as f64 / 5.0) * plot_h;
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
            left,
            y,
            width - right,
            y,
            HTML_GRID
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"end\" fill=\"{}\" font-size=\"11\">{}</text>",
            left - 8.0,
            y + 4.0,
            HTML_AXIS,
            (max_value as f64 * i as f64 / 5.0).round()
        ));
    }

    for (i, (port, count)) in top.iter().enumerate() {
        let h = (*count as f64 / max_value as f64) * plot_h;
        let x = left + i as f64 * (plot_w / n as f64) + (plot_w / n as f64 - bar_w) / 2.0;
        let y = bottom_m - h;
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\" rx=\"4\"/>",
            x, y, bar_w, h, HTML_PRIMARY
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" fill=\"{}\" font-size=\"12\">{}</text>",
            x + bar_w / 2.0,
            bottom_m + 20.0,
            HTML_AXIS,
            port
        ));
    }

    svg.push_str("</svg>");
    svg
}

fn svg_compliance_summary(devices: &[Device]) -> String {
    let frameworks = ["CIS", "HIPAA", "PCI DSS"];
    let colors = [HTML_CRITICAL, HTML_HIGH, HTML_MEDIUM, HTML_LOW, HTML_INFO];
    let severity_labels = ["Critical", "High", "Medium", "Low", "Info"];

    let mut map: HashMap<&'static str, [usize; 5]> = HashMap::new();
    for device in devices {
        for issue in ComplianceEngine::audit_device(device) {
            let key: &'static str = match issue.framework.as_str() {
                "CIS" => "CIS",
                "HIPAA" => "HIPAA",
                "PCI DSS" => "PCI DSS",
                _ => "Other",
            };
            let entry = map.entry(key).or_insert([0; 5]);
            let idx = severity_rank(
                &crate::reporting::compliance::compliance_severity_to_finding(&issue.severity),
            ) as usize;
            entry[idx] += 1;
        }
    }

    // Filter to frameworks with data
    let data: Vec<_> = frameworks
        .iter()
        .filter_map(|fw| map.get(*fw).map(|counts| (*fw, *counts)))
        .collect();

    let width = 800.0;
    let height = 400.0;
    let left = 100.0;
    let right = 40.0;
    let top_m = 40.0;
    let bottom_m = 80.0;
    let plot_w = width - left - right;
    let plot_h = height - top_m - bottom_m;

    let max_value = data
        .iter()
        .flat_map(|(_, counts)| counts.iter())
        .copied()
        .max()
        .unwrap_or(0);

    if max_value == 0 {
        return format!(
            "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\"><text x=\"{}\" y=\"{}\" text-anchor=\"middle\" fill=\"{}\" font-size=\"16\">No data</text></svg>",
            width, height, width / 2.0, height / 2.0, HTML_AXIS
        );
    }

    let n = data.len().max(1);
    let group_w = plot_w / n as f64;
    let bar_w = group_w / 6.5;

    let mut svg = format!(
        "<svg viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\">",
        width, height
    );

    for i in 0..=5 {
        let y = bottom_m - (i as f64 / 5.0) * plot_h;
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>",
            left,
            y,
            width - right,
            y,
            HTML_GRID
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"end\" fill=\"{}\" font-size=\"11\">{}</text>",
            left - 8.0,
            y + 4.0,
            HTML_AXIS,
            (max_value as f64 * i as f64 / 5.0).round()
        ));
    }

    for (i, (framework, counts)) in data.iter().enumerate() {
        let group_x = left + i as f64 * group_w + group_w * 0.05;
        for (j, count) in counts.iter().enumerate() {
            let h = (*count as f64 / max_value as f64) * plot_h;
            let x = group_x + j as f64 * bar_w;
            let y = bottom_m - h;
            svg.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>",
                x,
                y,
                bar_w * 0.9,
                h,
                colors[j]
            ));
        }
        let label_x = group_x + (bar_w * 5.0) / 2.0;
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" fill=\"{}\" font-size=\"12\">{}</text>",
            label_x,
            height - 55.0,
            HTML_AXIS,
            encode_text(framework)
        ));
    }

    for (j, label) in severity_labels.iter().enumerate() {
        let lx = left + j as f64 * 90.0;
        let ly = height - 25.0;
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"12\" height=\"12\" fill=\"{}\"/>",
            lx, ly, colors[j]
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" fill=\"{}\" font-size=\"12\">{}</text>",
            lx + 18.0,
            ly + 11.0,
            HTML_AXIS,
            encode_text(label)
        ));
    }

    svg.push_str("</svg>");
    svg
}

// ── HTML report ────────────────────────────────────────────────────────────

/// Generates a self-contained HTML report for the scan.
///
/// This function is synchronous and must be called from `spawn_blocking`.
pub fn generate_html_report(
    devices: &[Device],
    filepath: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(filepath)?;
    let mut writer = BufWriter::new(file);

    let total_devices = devices.len();
    let open_ports: usize = devices
        .iter()
        .map(|d| {
            d.ports
                .iter()
                .filter(|p| p.state == crate::types::PortState::Open)
                .count()
        })
        .sum();
    let finding_counts = finding_counts(devices);
    let total_findings: usize = devices.iter().map(|device| device.findings.len()).sum();

    let all_findings: Vec<&Finding> = devices
        .iter()
        .flat_map(|device| device.findings.iter())
        .collect();

    writeln!(
        writer,
        "<!DOCTYPE html>\n<html>\n<head>\n<title>NetSentinel Audit Report</title>\n<style>"
    )?;
    writeln!(
        writer,
        "body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #f9fafb; color: #111827; }}"
    )?;
    writeln!(
        writer,
        "h1 {{ color: {}; }} h2 {{ color: #111827; }} h3 {{ color: #374151; }}",
        HTML_PRIMARY
    )?;
    writeln!(
        writer,
        ".card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }}"
    )?;
    writeln!(
        writer,
        "table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}"
    )?;
    writeln!(
        writer,
        "th, td {{ border: 1px solid {}; padding: 8px; text-align: left; vertical-align: top; }}",
        HTML_GRID
    )?;
    writeln!(writer, "th {{ background-color: #f3f4f6; }}")?;
    writeln!(
        writer,
        ".severity-Critical {{ color: {}; font-weight: bold; }} .severity-High {{ color: {}; font-weight: bold; }} .severity-Medium {{ color: {}; font-weight: bold; }} .severity-Low {{ color: {}; font-weight: bold; }} .severity-Info {{ color: {}; font-weight: bold; }}"
        , HTML_CRITICAL, HTML_HIGH, HTML_MEDIUM, HTML_LOW, HTML_INFO
    )?;
    writeln!(
        writer,
        ".chart-container {{ background: white; padding: 16px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }}"
    )?;
    writeln!(
        writer,
        ".chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}"
    )?;
    writeln!(
        writer,
        "@media (max-width: 900px) {{ .chart-grid {{ grid-template-columns: 1fr; }} }}"
    )?;
    writeln!(writer, "</style>\n</head>\n<body>")?;

    writeln!(
        writer,
        "<h1>NetSentinel Audit Report</h1>\n<p>Generated on {}</p>",
        encode_text(&Utc::now().to_rfc2822())
    )?;

    writeln!(writer, "<div class='card'>")?;
    writeln!(writer, "<h2>Summary</h2>")?;
    writeln!(writer, "<p>Total Devices: {}</p>", total_devices)?;
    writeln!(writer, "<p>Total Open Ports: {}</p>", open_ports)?;
    writeln!(writer, "<p>Total Findings: {}</p>", total_findings)?;
    writeln!(
        writer,
        "<p>Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}</p>",
        finding_counts.0, finding_counts.1, finding_counts.2, finding_counts.3, finding_counts.4
    )?;
    writeln!(writer, "</div>")?;

    writeln!(writer, "<div class='card'>")?;
    writeln!(writer, "<h2>Visual Summary</h2>")?;
    writeln!(writer, "<div class='chart-grid'>")?;

    writeln!(writer, "<div class='chart-container'>")?;
    writeln!(writer, "<h3>Severity by Category</h3>")?;
    writeln!(writer, "{}", svg_severity_by_category(&all_findings))?;
    writeln!(writer, "</div>")?;

    writeln!(writer, "<div class='chart-container'>")?;
    writeln!(writer, "<h3>Top Hosts by Risk</h3>")?;
    writeln!(writer, "{}", svg_top_hosts_by_risk(devices, 10))?;
    writeln!(writer, "</div>")?;

    writeln!(writer, "<div class='chart-container'>")?;
    writeln!(writer, "<h3>Top Open Ports</h3>")?;
    writeln!(writer, "{}", svg_open_ports_chart(devices, 15))?;
    writeln!(writer, "</div>")?;

    writeln!(writer, "<div class='chart-container'>")?;
    writeln!(writer, "<h3>Compliance Summary</h3>")?;
    writeln!(writer, "{}", svg_compliance_summary(devices))?;
    writeln!(writer, "</div>")?;

    writeln!(writer, "</div></div>")?;

    // Findings by Host
    writeln!(writer, "<div class='card'>")?;
    writeln!(writer, "<h2>Findings by Host</h2>")?;
    if all_findings.is_empty() {
        writeln!(writer, "<p>No findings recorded.</p>")?;
    } else {
        writeln!(writer, "<table><tr><th>Severity</th><th>Category</th><th>Source</th><th>Title</th><th>Target</th><th>CVSS</th><th>EPSS</th><th>Risk</th><th>Evidence</th><th>Remediation</th></tr>")?;
        for finding in &all_findings {
            let severity = format!("{:?}", finding.severity);
            let target = finding
                .port
                .map(|port| format!("{}:{}", finding.ip, port))
                .unwrap_or_else(|| finding.ip.clone());
            let cvss = finding
                .cvss_score
                .map(|s| format!("{:.1}", s))
                .unwrap_or_else(|| "-".to_string());
            let epss = finding
                .epss_probability
                .map(|s| format!("{:.2}", s))
                .unwrap_or_else(|| "-".to_string());
            let risk = finding_risk_score(finding);
            let evidence = finding.evidence.as_deref().unwrap_or("");
            let remediation = finding.remediation.as_deref().unwrap_or("");
            writeln!(
                writer,
                "<tr><td class='severity-{}'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1}</td><td>{}</td><td>{}</td></tr>",
                encode_text(&severity),
                encode_text(&severity),
                encode_text(&format!("{:?}", finding.category)),
                encode_text(&format!("{:?}", finding.source)),
                encode_text(&finding.title),
                encode_text(&target),
                encode_text(&cvss),
                encode_text(&epss),
                risk,
                encode_text(evidence),
                encode_text(remediation)
            )?;
        }
        writeln!(writer, "</table>")?;
    }
    writeln!(writer, "</div>")?;

    // Compliance Issues
    writeln!(writer, "<div class='card'>")?;
    writeln!(writer, "<h2>Compliance Issues</h2>")?;
    let mut has_compliance = false;
    writeln!(writer, "<table><tr><th>Framework</th><th>Rule</th><th>Severity</th><th>Host</th><th>Port</th><th>Description</th></tr>")?;
    for device in devices {
        for issue in ComplianceEngine::audit_device(device) {
            has_compliance = true;
            let port_text = issue
                .port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            writeln!(
                writer,
                "<tr><td>{}</td><td>{}</td><td class='severity-{}'>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                encode_text(&issue.framework),
                encode_text(&issue.rule),
                encode_text(&issue.severity),
                encode_text(&issue.severity),
                encode_text(&device.ip),
                encode_text(&port_text),
                encode_text(&issue.description)
            )?;
        }
    }
    writeln!(writer, "</table>")?;
    if !has_compliance {
        writeln!(writer, "<p>No compliance issues identified.</p>")?;
    }
    writeln!(writer, "</div>")?;

    writeln!(writer, "</body>\n</html>")?;
    writer.flush()?;
    Ok(())
}

// ── PDF report ─────────────────────────────────────────────────────────────

/// Generates a PDF report using printpdf.
pub fn generate_pdf_report(
    devices: &[Device],
    filepath: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (doc, page1, layer1) =
        PdfDocument::new("NetSentinel Audit Report", Mm(210.0), Mm(297.0), "Layer 1");
    let mut current_layer = doc.get_page(page1).get_layer(layer1);

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let mut page_number = 1usize;
    let mut y_pos = 270.0;

    let counts = finding_counts(devices);
    let total_findings: usize = devices.iter().map(|d| d.findings.len()).sum();

    // Cover page
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font_bold,
        &mut y_pos,
        &mut page_number,
        "NetSentinel Audit Report",
        26.0,
        20.0,
        14.0,
    );
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        &format!("Generated on {}", Utc::now().to_rfc2822()),
        12.0,
        20.0,
        10.0,
    );
    y_pos -= 8.0;
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        &format!("Total Devices Scanned: {}", devices.len()),
        12.0,
        20.0,
        8.0,
    );
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        &format!(
            "Total Findings: {} (Critical {}, High {}, Medium {}, Low {}, Info {})",
            total_findings, counts.0, counts.1, counts.2, counts.3, counts.4
        ),
        12.0,
        20.0,
        8.0,
    );
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        "This report includes all discovered hosts, security findings, and compliance issues.",
        10.0,
        20.0,
        8.0,
    );
    y_pos -= 8.0;

    // Summary tables
    write_pdf_section_header(
        &doc,
        &mut current_layer,
        &font_bold,
        &mut y_pos,
        &mut page_number,
        "Executive Summary",
    );
    write_pdf_summary_table(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        devices,
        counts,
    );

    // Detailed findings
    if total_findings > 0 {
        write_pdf_section_header(
            &doc,
            &mut current_layer,
            &font_bold,
            &mut y_pos,
            &mut page_number,
            "Detailed Findings",
        );

        let mut findings: Vec<&Finding> = devices
            .iter()
            .flat_map(|device| device.findings.iter())
            .collect();
        findings.sort_by(|a, b| {
            severity_rank(&a.severity)
                .cmp(&severity_rank(&b.severity))
                .then_with(|| {
                    let ra = finding_risk_score(b);
                    let rb = finding_risk_score(a);
                    ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        write_pdf_findings_table(
            &doc,
            &mut current_layer,
            &font,
            &mut y_pos,
            &mut page_number,
            &findings,
        );
    }

    // Compliance issues
    write_pdf_section_header(
        &doc,
        &mut current_layer,
        &font_bold,
        &mut y_pos,
        &mut page_number,
        "Compliance Issues",
    );
    write_pdf_compliance_table(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        devices,
    );

    let file = File::create(filepath)?;
    let mut buf_writer = BufWriter::new(file);
    doc.save(&mut buf_writer)?;

    Ok(())
}

fn write_pdf_section_header(
    doc: &PdfDocumentReference,
    current_layer: &mut PdfLayerReference,
    font: &IndirectFontRef,
    y_pos: &mut f64,
    page_number: &mut usize,
    title: &str,
) {
    *y_pos -= 4.0;
    ensure_pdf_space(doc, current_layer, y_pos, page_number, 12.0);
    current_layer.use_text(sanitize_pdf_text(title), 14.0, Mm(20.0), Mm(*y_pos), font);
    *y_pos -= 12.0;
}

fn write_pdf_summary_table(
    doc: &PdfDocumentReference,
    current_layer: &mut PdfLayerReference,
    font: &IndirectFontRef,
    y_pos: &mut f64,
    page_number: &mut usize,
    devices: &[Device],
    counts: (usize, usize, usize, usize, usize),
) {
    ensure_pdf_space(doc, current_layer, y_pos, page_number, 10.0);
    write_pdf_line(
        doc,
        current_layer,
        font,
        y_pos,
        page_number,
        "Severity Counts",
        11.0,
        20.0,
        10.0,
    );

    let labels = ["Critical", "High", "Medium", "Low", "Info"];
    let values = [counts.0, counts.1, counts.2, counts.3, counts.4];
    let max_value = values.iter().copied().max().unwrap_or(0).max(1);

    for (label, value) in labels.iter().zip(values.iter()) {
        let bar_len = (*value * 20) / max_value;
        let bar: String = "█".repeat(bar_len);
        write_pdf_line(
            doc,
            current_layer,
            font,
            y_pos,
            page_number,
            &format!("{:<8} {:>4} {}", label, value, bar),
            10.0,
            25.0,
            6.0,
        );
    }

    *y_pos -= 4.0;
    ensure_pdf_space(doc, current_layer, y_pos, page_number, 10.0);
    write_pdf_line(
        doc,
        current_layer,
        font,
        y_pos,
        page_number,
        "Top 10 Hosts by Risk",
        11.0,
        20.0,
        10.0,
    );

    write_pdf_line(
        doc,
        current_layer,
        font,
        y_pos,
        page_number,
        "IP Address                       Risk Score   Findings",
        9.0,
        25.0,
        6.0,
    );

    let top_hosts = top_hosts_by_risk(devices, 10);
    for (device, score) in top_hosts {
        write_pdf_line(
            doc,
            current_layer,
            font,
            y_pos,
            page_number,
            &format!(
                "{:<32} {:>8.1}   {}",
                device.ip,
                score,
                device.findings.len()
            ),
            9.0,
            25.0,
            6.0,
        );
    }

    // Compliance counts
    *y_pos -= 4.0;
    ensure_pdf_space(doc, current_layer, y_pos, page_number, 10.0);
    write_pdf_line(
        doc,
        current_layer,
        font,
        y_pos,
        page_number,
        "Compliance Counts by Framework",
        11.0,
        20.0,
        10.0,
    );

    let mut compliance_counts: HashMap<&str, usize> = HashMap::new();
    for device in devices {
        for issue in ComplianceEngine::audit_device(device) {
            let key = match issue.framework.as_str() {
                "CIS" => "CIS",
                "HIPAA" => "HIPAA",
                "PCI DSS" => "PCI DSS",
                _ => "Other",
            };
            *compliance_counts.entry(key).or_insert(0) += 1;
        }
    }

    for framework in &["CIS", "HIPAA", "PCI DSS"] {
        let value = compliance_counts.get(*framework).copied().unwrap_or(0);
        write_pdf_line(
            doc,
            current_layer,
            font,
            y_pos,
            page_number,
            &format!("{:<10} {}", framework, value),
            9.0,
            25.0,
            6.0,
        );
    }
}

fn write_pdf_findings_table(
    doc: &PdfDocumentReference,
    current_layer: &mut PdfLayerReference,
    font: &IndirectFontRef,
    y_pos: &mut f64,
    page_number: &mut usize,
    findings: &[&Finding],
) {
    for finding in findings {
        let target = finding
            .port
            .map(|port| format!("{}:{}", finding.ip, port))
            .unwrap_or_else(|| finding.ip.clone());

        ensure_pdf_space(doc, current_layer, y_pos, page_number, 8.0);
        write_pdf_line(
            doc,
            current_layer,
            font,
            y_pos,
            page_number,
            &format!(
                "[{:?}] {} | {} | Risk {:.1}",
                finding.severity,
                target,
                finding.title,
                finding_risk_score(finding)
            ),
            9.0,
            20.0,
            7.0,
        );

        write_wrapped_pdf_text(
            doc,
            current_layer,
            font,
            y_pos,
            page_number,
            &finding.description,
            8.0,
            25.0,
            4.5,
            105,
        );

        if let Some(evidence) = &finding.evidence {
            write_wrapped_pdf_text(
                doc,
                current_layer,
                font,
                y_pos,
                page_number,
                &format!("Evidence: {}", evidence),
                8.0,
                25.0,
                4.5,
                105,
            );
        }

        if let Some(remediation) = &finding.remediation {
            write_wrapped_pdf_text(
                doc,
                current_layer,
                font,
                y_pos,
                page_number,
                &format!("Remediation: {}", remediation),
                8.0,
                25.0,
                4.5,
                105,
            );
        }

        *y_pos -= 2.0;
    }
}

fn write_pdf_compliance_table(
    doc: &PdfDocumentReference,
    current_layer: &mut PdfLayerReference,
    font: &IndirectFontRef,
    y_pos: &mut f64,
    page_number: &mut usize,
    devices: &[Device],
) {
    let mut any = false;
    for device in devices {
        for issue in ComplianceEngine::audit_device(device) {
            any = true;
            let port_text = issue
                .port
                .map(|p| format!("{}", p))
                .unwrap_or_else(|| "-".to_string());

            ensure_pdf_space(doc, current_layer, y_pos, page_number, 8.0);
            write_pdf_line(
                doc,
                current_layer,
                font,
                y_pos,
                page_number,
                &format!(
                    "{}: {} | {} | {}:{}",
                    issue.framework, issue.rule, issue.severity, device.ip, port_text
                ),
                9.0,
                20.0,
                7.0,
            );

            write_wrapped_pdf_text(
                doc,
                current_layer,
                font,
                y_pos,
                page_number,
                &issue.description,
                8.0,
                25.0,
                4.5,
                105,
            );

            *y_pos -= 2.0;
        }
    }

    if !any {
        ensure_pdf_space(doc, current_layer, y_pos, page_number, 8.0);
        write_pdf_line(
            doc,
            current_layer,
            font,
            y_pos,
            page_number,
            "No compliance issues identified.",
            9.0,
            20.0,
            7.0,
        );
    }
}

fn write_pdf_line(
    doc: &PdfDocumentReference,
    current_layer: &mut PdfLayerReference,
    font: &IndirectFontRef,
    y_pos: &mut f64,
    page_number: &mut usize,
    text: &str,
    font_size: f64,
    x_pos: f64,
    line_height: f64,
) {
    ensure_pdf_space(doc, current_layer, y_pos, page_number, line_height);
    current_layer.use_text(
        sanitize_pdf_text(text),
        font_size,
        Mm(x_pos),
        Mm(*y_pos),
        font,
    );
    *y_pos -= line_height;
}

fn write_wrapped_pdf_text(
    doc: &PdfDocumentReference,
    current_layer: &mut PdfLayerReference,
    font: &IndirectFontRef,
    y_pos: &mut f64,
    page_number: &mut usize,
    text: &str,
    font_size: f64,
    x_pos: f64,
    line_height: f64,
    max_chars: usize,
) {
    for line in wrap_pdf_text(text, max_chars) {
        write_pdf_line(
            doc,
            current_layer,
            font,
            y_pos,
            page_number,
            &line,
            font_size,
            x_pos,
            line_height,
        );
    }
}

fn ensure_pdf_space(
    doc: &PdfDocumentReference,
    current_layer: &mut PdfLayerReference,
    y_pos: &mut f64,
    page_number: &mut usize,
    required_height: f64,
) {
    if *y_pos - required_height >= 20.0 {
        return;
    }

    *page_number += 1;
    let layer_name = format!("Layer {}", page_number);
    let (page, layer) = doc.add_page(Mm(210.0), Mm(297.0), layer_name);
    *current_layer = doc.get_page(page).get_layer(layer);
    *y_pos = 270.0;
}

fn wrap_pdf_text(text: &str, max_chars: usize) -> Vec<String> {
    if max_chars == 0 {
        return vec![sanitize_pdf_text(text)];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if word_len > max_chars {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let mut chunk = String::new();
            for ch in word.chars() {
                if chunk.chars().count() >= max_chars {
                    lines.push(std::mem::take(&mut chunk));
                }
                chunk.push(ch);
            }
            if !chunk.is_empty() {
                current = chunk;
            }
            continue;
        }

        let separator_len = usize::from(!current.is_empty());
        if current.chars().count() + separator_len + word_len > max_chars {
            lines.push(std::mem::take(&mut current));
        }

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
        .into_iter()
        .map(|line| sanitize_pdf_text(&line))
        .collect()
}

fn sanitize_pdf_text(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, FindingConfidence, FindingSource};

    #[test]
    fn html_report_escapes_finding_text() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "netsentinel-report-test-{}.html",
            uuid::Uuid::new_v4()
        ));

        let mut device = Device::new("192.0.2.30".to_string());
        device.findings.push(Finding {
            id: "finding-html".to_string(),
            scan_id: String::new(),
            source: FindingSource::WebAudit,
            severity: FindingSeverity::High,
            confidence: FindingConfidence::High,
            title: "<script>alert(1)</script>".to_string(),
            description: "escaped".to_string(),
            ip: device.ip.clone(),
            port: Some(80),
            service: Some("http".to_string()),
            evidence: Some("<b>/.env</b>".to_string()),
            cve: None,
            timestamp: 0,
            category: FindingCategory::Web,
            cvss_score: None,
            epss_probability: None,
            remediation: Some("Restrict exposed paths.".to_string()),
        });

        let result = generate_html_report(&[device], &path);
        assert!(result.is_ok());

        let html = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;b&gt;/.env&lt;/b&gt;"));
        assert!(html.contains("<svg"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pdf_report_generates_without_error() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "netsentinel-report-test-{}.pdf",
            uuid::Uuid::new_v4()
        ));

        let device = Device::new("192.0.2.30".to_string());
        let result = generate_pdf_report(&[device], &path);
        assert!(result.is_ok());

        let _ = std::fs::remove_file(path);
    }
}
