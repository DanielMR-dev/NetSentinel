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
use crate::types::{Device, FindingSeverity};

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
    let finding_counts = finding_counts(devices);
    let total_findings: usize = devices.iter().map(|device| device.findings.len()).sum();

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
    html.push_str(".severity-Critical { color: #991b1b; font-weight: bold; }\n");
    html.push_str(".severity-Low { color: #0891b2; font-weight: bold; }\n");
    html.push_str(".severity-Info { color: #6b7280; font-weight: bold; }\n");
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
    html.push_str(&format!("<p>Total Findings: {}</p>\n", total_findings));
    html.push_str(&format!(
        "<p>Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}</p>\n",
        finding_counts.0, finding_counts.1, finding_counts.2, finding_counts.3, finding_counts.4
    ));
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

        if !device.findings.is_empty() {
            html.push_str("<h4>Findings</h4>\n");
            html.push_str("<table><tr><th>Severity</th><th>Source</th><th>Title</th><th>Target</th><th>Evidence</th></tr>\n");
            for finding in &device.findings {
                let severity = format!("{:?}", finding.severity);
                let target = finding
                    .port
                    .map(|port| format!("{}:{}", finding.ip, port))
                    .unwrap_or_else(|| finding.ip.clone());
                html.push_str(&format!(
                    "<tr><td class='severity-{}'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    encode_text(&severity),
                    encode_text(&severity),
                    encode_text(&format!("{:?}", finding.source)),
                    encode_text(&finding.title),
                    encode_text(&target),
                    encode_text(finding.evidence.as_deref().unwrap_or(""))
                ));
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
    let mut current_layer = doc.get_page(page1).get_layer(layer1);

    // Set font (Built-in Helvetica)
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let mut page_number = 1usize;
    let mut y_pos = 270.0;

    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        "NetSentinel Audit Report",
        24.0,
        20.0,
        12.0,
    );
    let generated_text = format!("Generated on {}", Utc::now().to_rfc2822());
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        &generated_text,
        12.0,
        20.0,
        10.0,
    );
    y_pos -= 6.0;

    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        &format!("Total Devices Scanned: {}", devices.len()),
        14.0,
        20.0,
        10.0,
    );
    let total_findings: usize = devices.iter().map(|device| device.findings.len()).sum();
    let counts = finding_counts(devices);
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        &format!(
            "Findings: {} total (Critical {}, High {}, Medium {}, Low {}, Info {})",
            total_findings, counts.0, counts.1, counts.2, counts.3, counts.4
        ),
        12.0,
        20.0,
        9.0,
    );
    write_pdf_line(
        &doc,
        &mut current_layer,
        &font,
        &mut y_pos,
        &mut page_number,
        "All findings are included below; no lower-severity findings were omitted.",
        10.0,
        20.0,
        8.0,
    );
    y_pos -= 4.0;

    for device in devices {
        write_pdf_line(
            &doc,
            &mut current_layer,
            &font,
            &mut y_pos,
            &mut page_number,
            &format!("Host: {}", device.ip),
            12.0,
            25.0,
            8.0,
        );

        let issues = ComplianceEngine::audit_device(device);
        if !device.findings.is_empty() {
            write_pdf_line(
                &doc,
                &mut current_layer,
                &font,
                &mut y_pos,
                &mut page_number,
                &format!("{} findings found.", device.findings.len()),
                10.0,
                30.0,
                6.0,
            );
        }
        if !issues.is_empty() {
            write_pdf_line(
                &doc,
                &mut current_layer,
                &font,
                &mut y_pos,
                &mut page_number,
                &format!("{} compliance issues found.", issues.len()),
                10.0,
                30.0,
                6.0,
            );
        }
        y_pos -= 2.0;
    }

    if total_findings > 0 {
        y_pos -= 4.0;
        write_pdf_line(
            &doc,
            &mut current_layer,
            &font,
            &mut y_pos,
            &mut page_number,
            "Findings by Severity",
            14.0,
            20.0,
            10.0,
        );
    }

    let mut findings: Vec<_> = devices
        .iter()
        .flat_map(|device| device.findings.iter())
        .collect();
    findings.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then_with(|| left.ip.cmp(&right.ip))
            .then_with(|| left.port.cmp(&right.port))
            .then_with(|| left.title.cmp(&right.title))
    });

    for finding in findings {
        let target = finding
            .port
            .map(|port| format!("{}:{}", finding.ip, port))
            .unwrap_or_else(|| finding.ip.clone());
        let line = format!(
            "[{:?}] {} | {:?} | {}",
            finding.severity, target, finding.source, finding.title
        );
        write_wrapped_pdf_text(
            &doc,
            &mut current_layer,
            &font,
            &mut y_pos,
            &mut page_number,
            &line,
            8.5,
            25.0,
            5.0,
            110,
        );

        if let Some(evidence) = &finding.evidence {
            let evidence_line = format!("Evidence: {}", evidence);
            write_wrapped_pdf_text(
                &doc,
                &mut current_layer,
                &font,
                &mut y_pos,
                &mut page_number,
                &evidence_line,
                8.0,
                30.0,
                4.5,
                105,
            );
        }
        y_pos -= 1.0;
    }

    let file = File::create(filepath)?;
    let mut buf_writer = BufWriter::new(file);
    doc.save(&mut buf_writer)?;

    Ok(())
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
        });

        let result = generate_html_report(&[device], &path);
        assert!(result.is_ok());

        let html = std::fs::read_to_string(&path);
        assert!(html.is_ok());
        let html = html.unwrap_or_default();
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;b&gt;/.env&lt;/b&gt;"));

        let _ = std::fs::remove_file(path);
    }
}
