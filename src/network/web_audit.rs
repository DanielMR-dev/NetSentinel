//! Web Auditing Engine
//!
//! Provides "Safe/Passive" and "Aggressive" auditing for discovered HTTP/HTTPS services.

use std::time::Duration;

use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::error::ScanError;

/// Web Auditing Profile configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAuditProfile {
    /// Only makes a single request to `/` and inspects headers. Never sends destructive payloads.
    Safe,
    /// Performs directory brute forcing, attempts to access sensitive files (`/.git`, `/.env`).
    Aggressive,
}

impl WebAuditProfile {
    /// All web audit profiles available in the UI.
    pub fn all_profiles() -> &'static [WebAuditProfile] {
        &[WebAuditProfile::Safe, WebAuditProfile::Aggressive]
    }
}

impl std::fmt::Display for WebAuditProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebAuditProfile::Safe => write!(f, "Safe"),
            WebAuditProfile::Aggressive => write!(f, "Aggressive"),
        }
    }
}

/// The result of a web audit on a specific service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuditResult {
    pub url: String,
    pub server_header: Option<String>,
    pub powered_by_header: Option<String>,
    pub exposed_directories: Vec<String>,
    pub status_code: u16,
    pub title: Option<String>,
}

/// Run a web audit against a specific target.
pub async fn audit_web_service(
    ip: &str,
    port: u16,
    is_https: bool,
    profile: WebAuditProfile,
) -> Result<WebAuditResult, ScanError> {
    let scheme = if is_https { "https" } else { "http" };
    let base_url = format!("{}://{}:{}", scheme, ip, port);
    info!("Starting web audit for {}", base_url);

    // Build a client that ignores cert errors for local scanning, follows max 3 redirects
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(Policy::limited(3))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| ScanError::NetworkError(format!("Failed to build HTTP client: {}", e)))?;

    // 1. Safe / Passive check (root path)
    let root_res = client
        .get(&base_url)
        .send()
        .await
        .map_err(|e| ScanError::NetworkError(format!("Failed to fetch {}: {}", base_url, e)))?;

    let status_code = root_res.status().as_u16();
    let headers = root_res.headers().clone();

    let server_header = headers
        .get("Server")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let powered_by_header = headers
        .get("X-Powered-By")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let body_text = root_res.text().await.unwrap_or_default();
    let title = extract_html_title(&body_text);

    let mut exposed_directories = Vec::new();

    // 2. Aggressive checks
    if profile == WebAuditProfile::Aggressive {
        debug!("Running aggressive checks against {}", base_url);

        let sensitive_paths = vec![
            "/.env",
            "/.git/config",
            "/.DS_Store",
            "/admin/",
            "/phpinfo.php",
            "/server-status",
            "/wp-config.php.bak",
        ];

        for path in sensitive_paths {
            let target_url = format!("{}{}", base_url, path);
            if let Ok(res) = client.get(&target_url).send().await {
                // If it's a 200 OK, and it actually looks like the file we wanted (not a 200 soft-404)
                if res.status().is_success() {
                    // Quick heuristic: check if it's a soft-404 by comparing body length or seeing if it has standard 404 text
                    let text = res.text().await.unwrap_or_default();
                    let text_lower = text.to_lowercase();
                    if !text_lower.contains("404 not found")
                        && !text_lower.contains("page not found")
                    {
                        // Very likely exposed
                        exposed_directories.push(path.to_string());
                    }
                }
            }
        }
    }

    Ok(WebAuditResult {
        url: base_url,
        server_header,
        powered_by_header,
        exposed_directories,
        status_code,
        title,
    })
}

/// Helper to extract `<title>` from HTML
fn extract_html_title(html: &str) -> Option<String> {
    let title_start = html.find("<title>")?;
    let title_end = html[title_start..].find("</title>")?;
    let title = &html[title_start + 7..title_start + title_end];
    Some(title.trim().to_string())
}
