//! Local offline CVE matching engine using SQLite.
//!
//! Loads a bundled SQLite CVE database and matches service banners against
//! known vulnerabilities. This provides immediate vulnerability
//! awareness without requiring network access to external CVE feeds.

use std::sync::Mutex;

use once_cell::sync::Lazy;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::error::ScanError;
use crate::network::banner;

/// CVE severity levels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CveSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// A CVE match result with full vulnerability details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveMatch {
    /// CVE identifier (e.g., "CVE-2024-12345")
    pub cve_id: String,
    /// Severity level
    pub severity: CveSeverity,
    /// Human-readable description
    pub description: String,
    /// Affected software name
    pub affected_software: String,
    /// Affected version patterns
    pub affected_versions: Vec<String>,
    /// CVSS score (0.0 - 10.0)
    pub cvss_score: f64,
    /// IP address where the match was found
    pub ip: String,
    /// Port where the match was found
    pub port: u16,
}

/// A single vulnerability entry retrieved from the database.
#[derive(Debug, Clone)]
struct CveEntry {
    cve_id: String,
    severity: String,
    description: String,
    affected_software: String,
    cvss_score: f64,
    affected_versions: Vec<String>,
}

/// The CVE database connection manager.
pub struct CveDatabase {
    /// Mutex over the SQLite connection, if one could be established.
    /// A `None` value means CVE lookups are unavailable (graceful degradation).
    conn: Option<Mutex<Connection>>,
}

/// Bundled SQLite CVE database bytes.
///
/// This is embedded at compile time via `include_bytes!` and extracted
/// to the app's local data directory on first run.
static CVE_DB_BYTES: &[u8] = include_bytes!("../../assets/cve-database.db");

/// Helper to determine the application's local data directory.
fn get_app_local_data_dir() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|p| p.join("com.netsentinel.app"))
}

/// Global CVE database instance, loaded once at startup.
static CVE_DATABASE: Lazy<std::sync::Arc<CveDatabase>> = Lazy::new(|| {
    let mut db_path = None;
    if let Some(mut path) = get_app_local_data_dir() {
        if !path.exists() {
            let _ = std::fs::create_dir_all(&path);
        }
        path.push("cve-database.db");

        // Always extract the embedded database if it doesn't exist, or if we want to ensure it's up to date.
        // For now, if it doesn't exist, write it.
        if !path.exists() {
            if let Err(e) = std::fs::write(&path, CVE_DB_BYTES) {
                tracing::error!(
                    "Failed to write embedded SQLite database to {:?}: {}",
                    path,
                    e
                );
            } else {
                tracing::info!("Extracted embedded SQLite database to {:?}", path);
            }
        }
        db_path = Some(path);
    }

    let conn = if let Some(path) = db_path {
        match Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(conn) => Some(conn),
            Err(e) => {
                tracing::error!("Failed to open CVE database at {:?}: {}", path, e);
                match Connection::open_in_memory() {
                    Ok(conn) => Some(conn),
                    Err(e2) => {
                        tracing::error!("Failed to open in-memory CVE database: {}", e2);
                        None
                    }
                }
            }
        }
    } else {
        match Connection::open_in_memory() {
            Ok(conn) => Some(conn),
            Err(e) => {
                tracing::error!("Failed to open in-memory CVE database: {}", e);
                None
            }
        }
    };

    std::sync::Arc::new(CveDatabase {
        conn: conn.map(Mutex::new),
    })
});

impl CveDatabase {
    /// Look up CVE matches for a given banner and service.
    pub fn lookup(&self, banner_str: &str, service: &str, ip: &str, port: u16) -> Vec<CveMatch> {
        let mut matches = Vec::new();
        let detected_version = banner::extract_version(banner_str);
        let search_keys = get_search_keys(service, banner_str);

        let conn_mutex = match self.conn.as_ref() {
            Some(conn) => conn,
            None => return matches, // CVE database unavailable
        };

        let conn = match conn_mutex.lock() {
            Ok(guard) => guard,
            Err(_) => return matches, // Poisoned lock
        };

        for key in &search_keys {
            let key_lower = key.to_lowercase();
            // We use a LIKE query to do fuzzy matching on the affected_software
            let query = "SELECT cve_id, severity, description, affected_software, cvss_score FROM cves WHERE affected_software LIKE ?1";
            let like_pattern = format!("%{}%", key_lower);

            let mut stmt = match conn.prepare(query) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to prepare CVE query: {}", e);
                    continue;
                }
            };

            let cve_iter = match stmt.query_map(params![like_pattern], |row| {
                let cve_id: String = row.get(0)?;
                // We need to fetch versions in a separate query, but inside query_map we can't borrow conn mutably.
                // So we just fetch the core info and fetch versions after.
                Ok(CveEntry {
                    cve_id,
                    severity: row.get(1)?,
                    description: row.get(2)?,
                    affected_software: row.get(3)?,
                    cvss_score: row.get(4)?,
                    affected_versions: Vec::new(),
                })
            }) {
                Ok(iter) => iter,
                Err(e) => {
                    tracing::error!("Failed to execute CVE query: {}", e);
                    continue;
                }
            };

            let mut fetched_entries: Vec<CveEntry> = cve_iter.filter_map(Result::ok).collect();

            // Now fetch versions for each entry
            for entry in &mut fetched_entries {
                let mut vstmt = match conn
                    .prepare("SELECT version_pattern FROM affected_versions WHERE cve_id = ?1")
                {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let v_iter =
                    match vstmt.query_map(params![entry.cve_id], |row| row.get::<_, String>(0)) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                entry.affected_versions = v_iter.filter_map(Result::ok).collect();
            }

            // Now perform version matching and filtering
            for entry in fetched_entries {
                if version_matches(&entry, detected_version.as_deref()) {
                    if !matches.iter().any(|m: &CveMatch| m.cve_id == entry.cve_id) {
                        matches.push(CveMatch {
                            cve_id: entry.cve_id.clone(),
                            severity: parse_severity(&entry.severity),
                            description: entry.description.clone(),
                            affected_software: entry.affected_software.clone(),
                            affected_versions: entry.affected_versions.clone(),
                            cvss_score: entry.cvss_score,
                            ip: ip.to_string(),
                            port,
                        });
                    }
                }
            }
        }

        // Sort by CVSS score descending (most critical first)
        matches.sort_by(|a, b| {
            b.cvss_score
                .partial_cmp(&a.cvss_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        matches
    }
}

/// Look up CVEs for a banner result.
pub fn lookup_cves(banner_result: &banner::BannerResult) -> Vec<CveMatch> {
    let service = banner_result.service.as_deref().unwrap_or("");
    CVE_DATABASE.lookup(
        &banner_result.banner,
        service,
        &banner_result.ip,
        banner_result.port,
    )
}

/// Update the CVE database by replacing the SQLite DB file.
pub async fn update_cve_database(db_bytes: Vec<u8>) -> Result<(), ScanError> {
    let local_data_dir = get_app_local_data_dir().ok_or_else(|| {
        ScanError::NetworkError("Could not determine local data directory".to_string())
    })?;

    tokio::fs::create_dir_all(&local_data_dir)
        .await
        .map_err(|e| {
            ScanError::NetworkError(format!("Failed to create local data directory: {}", e))
        })?;

    let target_path = local_data_dir.join("cve-database.db");
    let temp_path = local_data_dir.join("cve-database.tmp");

    tokio::fs::write(&temp_path, &db_bytes).await.map_err(|e| {
        ScanError::NetworkError(format!("Failed to write temporary CVE database: {}", e))
    })?;

    // In a real scenario we'd need to close the SQLite connection before overwriting it on Windows,
    // but we can just overwrite on Linux.
    tokio::fs::rename(&temp_path, &target_path)
        .await
        .map_err(|e| ScanError::NetworkError(format!("Failed to save CVE database: {}", e)))?;

    tracing::info!(
        "CVE database successfully updated and saved to {:?}",
        target_path
    );
    // Note: The global connection will still be pointing to the old handle until app restart,
    // unless we re-initialize it. For Phase 2, a restart requirement is acceptable.
    Ok(())
}

/// Generate search keys from service name and banner.
fn get_search_keys(service: &str, banner_str: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let banner_lower = banner_str.to_lowercase();

    if !service.is_empty() {
        let base_name = service
            .split_whitespace()
            .next()
            .unwrap_or(service)
            .to_lowercase();
        keys.push(base_name);
    }

    let software_patterns = [
        "openssh",
        "nginx",
        "apache",
        "httpd",
        "iis",
        "vsftpd",
        "proftpd",
        "mysql",
        "mariadb",
        "postgres",
        "openssl",
        "samba",
        "smbd",
        "lighttpd",
        "tomcat",
        "jetty",
        "exim",
        "postfix",
        "sendmail",
        "openvpn",
        "redis",
        "memcached",
        "mongodb",
    ];

    for pattern in &software_patterns {
        if banner_lower.contains(pattern) {
            keys.push(pattern.to_string());
        }
    }

    keys.sort();
    keys.dedup();

    if keys.is_empty() {
        keys.push(service.to_lowercase());
    }

    keys
}

fn version_matches(entry: &CveEntry, detected_version: Option<&str>) -> bool {
    let detected = match detected_version {
        Some(v) => v,
        None => return true,
    };

    for pattern in &entry.affected_versions {
        if version_pattern_matches(pattern, detected) {
            return true;
        }
    }

    false
}

fn version_pattern_matches(pattern: &str, version: &str) -> bool {
    let pattern = pattern.trim();

    if pattern.starts_with("< ") || pattern.starts_with("<= ") {
        let is_inclusive = pattern.starts_with("<=");
        let threshold = if is_inclusive {
            pattern.trim_start_matches("<=").trim()
        } else {
            pattern.trim_start_matches("<").trim()
        };

        match compare_versions(version, threshold) {
            Some(ord) => {
                if is_inclusive {
                    ord != std::cmp::Ordering::Greater
                } else {
                    ord == std::cmp::Ordering::Less
                }
            }
            None => true,
        }
    } else if pattern.contains("-") {
        let parts: Vec<&str> = pattern.split('-').collect();
        if parts.len() == 2 {
            let low = parts[0].trim();
            let high = parts[1].trim();
            let above_low = compare_versions(version, low)
                .map(|o| o != std::cmp::Ordering::Less)
                .unwrap_or(true);
            let below_high = compare_versions(version, high)
                .map(|o| o != std::cmp::Ordering::Greater)
                .unwrap_or(true);
            above_low && below_high
        } else {
            false
        }
    } else {
        version.starts_with(pattern) || pattern == version
    }
}

fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let a_parts = parse_version_parts(a);
    let b_parts = parse_version_parts(b);

    if a_parts.is_empty() || b_parts.is_empty() {
        return None;
    }

    let max_len = a_parts.len().max(b_parts.len());

    for i in 0..max_len {
        let a_val = a_parts.get(i).copied().unwrap_or(0);
        let b_val = b_parts.get(i).copied().unwrap_or(0);

        match a_val.cmp(&b_val) {
            std::cmp::Ordering::Equal => continue,
            other => return Some(other),
        }
    }

    Some(std::cmp::Ordering::Equal)
}

fn parse_version_parts(version: &str) -> Vec<u32> {
    let mut parts = Vec::new();
    let mut current = String::new();

    for c in version.chars() {
        if c.is_ascii_digit() {
            current.push(c);
        } else if c == '.' || c == '-' || c == '_' {
            if !current.is_empty() {
                if let Ok(n) = current.parse::<u32>() {
                    parts.push(n);
                }
                current.clear();
            }
        } else if c.is_ascii_alphabetic() {
            if !current.is_empty() {
                if let Ok(n) = current.parse::<u32>() {
                    parts.push(n);
                }
                current.clear();
            }
        }
    }

    if !current.is_empty() {
        if let Ok(n) = current.parse::<u32>() {
            parts.push(n);
        }
    }

    parts
}

fn parse_severity(s: &str) -> CveSeverity {
    match s.to_lowercase().as_str() {
        "critical" => CveSeverity::Critical,
        "high" => CveSeverity::High,
        "medium" => CveSeverity::Medium,
        "low" => CveSeverity::Low,
        _ => CveSeverity::Medium,
    }
}
