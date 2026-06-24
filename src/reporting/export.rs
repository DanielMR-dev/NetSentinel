//! HTML & PDF Report Generation
//!
//! Generates self-contained HTML reports with JS charts, and PDF reports.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use chrono::Utc;
use html_escape::encode_text;
use printpdf::*;

use crate::reporting::compliance::ComplianceEngine;
use crate::types::Device;

/// Generates a self-contained HTML report for the scan.
pub fn generate_html_report(
    devices: &[Device],
    filepath: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(filepath)?;

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

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
    html.push_str("<title>NetSentinel Audit Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #f9fafb; color: #111827; }\n");
    html.push_str("h1 { color: #2563eb; }\n");
    html.push_str(".card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }\n");
    html.push_str("table { width: 100%; border-collapse: collapse; margin-top: 10px; }\n");
    html.push_str("th, td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; }\n");
    html.push_str("th { background-color: #f3f4f6; }\n");
    html.push_str(".severity-High { color: #dc2626; font-weight: bold; }\n");
    html.push_str(".severity-Medium { color: #d97706; font-weight: bold; }\n");
    html.push_str("</style>\n");
    html.push_str("</head>\n<body>\n");

    html.push_str(&format!("<h1>NetSentinel Audit Report</h1>\n"));
    html.push_str(&format!(
        "<p>Generated on {}</p>\n",
        Utc::now().to_rfc2822()
    ));

    html.push_str("<div class='card'>\n");
    html.push_str("<h2>Summary</h2>\n");
    html.push_str(&format!("<p>Total Devices: {}</p>\n", total_devices));
    html.push_str(&format!("<p>Total Open Ports: {}</p>\n", open_ports));
    html.push_str("</div>\n");

    for device in devices {
        html.push_str("<div class='card'>\n");
        html.push_str(&format!("<h3>Host: {}</h3>\n", encode_text(&device.ip)));

        if !device.mac.is_empty() {
            html.push_str(&format!("<p>MAC: {}</p>\n", encode_text(&device.mac)));
        }

        // Ports
        if !device.ports.is_empty() {
            html.push_str("<h4>Open Ports</h4>\n");
            html.push_str("<table><tr><th>Port</th><th>Service</th></tr>\n");
            for port in &device.ports {
                if port.state == crate::types::PortState::Open {
                    let service = port.service.as_deref().unwrap_or("Unknown");
                    html.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td></tr>\n",
                        port.number,
                        encode_text(service)
                    ));
                }
            }
            html.push_str("</table>\n");
        }

        // Compliance
        let issues = ComplianceEngine::audit_device(device);
        if !issues.is_empty() {
            html.push_str("<h4>Compliance Issues</h4>\n");
            html.push_str(
                "<table><tr><th>Framework</th><th>Severity</th><th>Description</th></tr>\n",
            );
            for issue in issues {
                html.push_str(&format!(
                    "<tr><td>{}</td><td class='severity-{}'>{}</td><td>{}</td></tr>\n",
                    encode_text(&issue.framework),
                    encode_text(&issue.severity),
                    encode_text(&issue.severity),
                    encode_text(&issue.description)
                ));
            }
            html.push_str("</table>\n");
        }

        html.push_str("</div>\n");
    }

    html.push_str("</body>\n</html>");

    file.write_all(html.as_bytes())?;
    Ok(())
}

/// Generates a PDF report using printpdf.
pub fn generate_pdf_report(
    devices: &[Device],
    filepath: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (doc, page1, layer1) =
        PdfDocument::new("NetSentinel Audit Report", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);

    // Set font (Built-in Helvetica)
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;

    current_layer.use_text("NetSentinel Audit Report", 24.0, Mm(20.0), Mm(270.0), &font);

    let generated_text = format!("Generated on {}", Utc::now().to_rfc2822());
    current_layer.use_text(generated_text, 12.0, Mm(20.0), Mm(260.0), &font);

    let mut y_pos = 240.0;

    current_layer.use_text(
        format!("Total Devices Scanned: {}", devices.len()),
        14.0,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 10.0;

    for device in devices {
        if y_pos < 30.0 {
            // Very basic pagination: if we run out of room, just stop for now in this MVP
            current_layer.use_text(
                "... (report truncated due to length)",
                10.0,
                Mm(20.0),
                Mm(y_pos),
                &font,
            );
            break;
        }

        current_layer.use_text(
            format!("Host: {}", device.ip),
            12.0,
            Mm(25.0),
            Mm(y_pos),
            &font,
        );
        y_pos -= 8.0;

        let issues = ComplianceEngine::audit_device(device);
        if !issues.is_empty() {
            current_layer.use_text(
                format!("  {} compliance issues found.", issues.len()),
                10.0,
                Mm(30.0),
                Mm(y_pos),
                &font,
            );
            y_pos -= 6.0;
        }
    }

    let file = File::create(filepath)?;
    let mut buf_writer = BufWriter::new(file);
    doc.save(&mut buf_writer)?;

    Ok(())
}
