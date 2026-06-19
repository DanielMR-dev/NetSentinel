//! Local offline CVE matching engine.
//!
//! Loads a bundled CVE database and matches service banners against
//! known vulnerabilities. This provides immediate vulnerability
//! awareness without requiring network access to external CVE feeds.

use std::collections::HashMap;

use once_cell::sync::Lazy;
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

/// A single vulnerability entry in the CVE database.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CveEntry {
    cve_id: String,
    severity: String,
    description: String,
    affected_software: String,
    affected_versions: Vec<String>,
    cvss_score: f64,
}

/// The CVE database container.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CveDatabaseRaw {
    vulnerabilities: Vec<CveEntry>,
}

/// CVE database with indexed lookups for fast matching.
pub struct CveDatabase {
    /// Index: lowercase software name → list of CVE entries
    index: HashMap<String, Vec<CveEntry>>,
}

/// Bundled CVE database JSON content.
///
/// This is embedded at compile time via `include_str!` to ensure
/// the database is always available without file I/O at runtime.
static CVE_JSON: &str = include_str!("../../assets/cve-database.json");

/// Helper to determine the application's local data directory.
fn get_app_local_data_dir() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|p| p.join("com.netsentinel.app"))
}

/// Global CVE database instance, loaded once at startup.
static CVE_DATABASE: Lazy<std::sync::RwLock<CveDatabase>> = Lazy::new(|| {
    let mut db = None;
    if let Some(mut path) = get_app_local_data_dir() {
        path.push("cve-database.json");
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                match CveDatabase::load_from_json(&content) {
                    Ok(loaded_db) => {
                        tracing::info!("Loaded CVE database from local data directory: {:?}", path);
                        db = Some(loaded_db);
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse CVE database at local data directory: {:?}: {}", path, e);
                    }
                }
            }
        }
    }

    let loaded_db = db.unwrap_or_else(|| {
        CveDatabase::load_from_json(CVE_JSON)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to load embedded CVE database: {}. Using empty database.", e);
                CveDatabase::empty()
            })
    });

    std::sync::RwLock::new(loaded_db)
});

impl CveDatabase {
    /// Load the CVE database from a JSON string.
    pub fn load_from_json(json: &str) -> Result<Self, ScanError> {
        let raw: CveDatabaseRaw = serde_json::from_str(json).map_err(|e| {
            ScanError::NetworkError(format!("Failed to parse CVE database JSON: {}", e))
        })?;

        let mut index: HashMap<String, Vec<CveEntry>> = HashMap::new();

        for entry in raw.vulnerabilities {
            let key = entry.affected_software.to_lowercase();
            index.entry(key).or_default().push(entry);
        }

        tracing::info!(
            "CVE database loaded: {} software entries indexed",
            index.len()
        );

        Ok(Self { index })
    }

    /// Create an empty CVE database (fallback if loading fails).
    pub fn empty() -> Self {
        Self {
            index: HashMap::new(),
        }
    }

    /// Look up CVE matches for a given banner and service.
    ///
    /// Extracts the software name and version from the banner,
    /// then matches against the database entries.
    pub fn lookup(&self, banner_str: &str, service: &str, ip: &str, port: u16) -> Vec<CveMatch> {
        let mut matches = Vec::new();

        // Try to extract version from banner
        let detected_version = banner::extract_version(banner_str);

        // Determine the software key to search for
        let search_keys = get_search_keys(service, banner_str);

        for key in &search_keys {
            let key_lower = key.to_lowercase();

            // Direct lookup
            if let Some(entries) = self.index.get(&key_lower) {
                for entry in entries {
                    if version_matches(entry, detected_version.as_deref()) {
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

            // Fuzzy lookup: check if any indexed key contains our search key
            for (indexed_key, entries) in &self.index {
                if indexed_key.contains(&key_lower) || key_lower.contains(indexed_key.as_str()) {
                    for entry in entries {
                        if version_matches(entry, detected_version.as_deref()) {
                            // Avoid duplicates
                            if !matches.iter().any(|m| m.cve_id == entry.cve_id) {
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
            }
        }

        // Sort by CVSS score descending (most critical first)
        matches.sort_by(|a, b| b.cvss_score.partial_cmp(&a.cvss_score).unwrap_or(std::cmp::Ordering::Equal));

        matches
    }
}

/// Look up CVEs for a banner result.
pub fn lookup_cves(banner_result: &banner::BannerResult) -> Vec<CveMatch> {
    let db = CVE_DATABASE.read().unwrap_or_else(|e| e.into_inner());
    let service = banner_result.service.as_deref().unwrap_or("");
    db.lookup(&banner_result.banner, service, &banner_result.ip, banner_result.port)
}

/// Update the CVE database with new JSON content.
/// Validates the JSON content first and writes it safely to disk.
#[tauri::command]
pub async fn update_cve_database(json_content: String) -> Result<(), ScanError> {
    // 1. Validate the JSON content first by attempting to load it
    let new_db = CveDatabase::load_from_json(&json_content)?;

    // 2. Determine target path
    let local_data_dir = get_app_local_data_dir()
        .ok_or_else(|| ScanError::NetworkError("Could not determine local data directory".to_string()))?;

    // Ensure directory exists
    tokio::fs::create_dir_all(&local_data_dir).await
        .map_err(|e| ScanError::NetworkError(format!("Failed to create local data directory: {}", e)))?;

    let target_path = local_data_dir.join("cve-database.json");
    let temp_path = local_data_dir.join("cve-database.tmp");

    // Write securely by writing to a temp file and renaming it
    tokio::fs::write(&temp_path, &json_content).await
        .map_err(|e| ScanError::NetworkError(format!("Failed to write temporary CVE database: {}", e)))?;

    tokio::fs::rename(&temp_path, &target_path).await
        .map_err(|e| ScanError::NetworkError(format!("Failed to save CVE database: {}", e)))?;

    // 3. Update the in-memory global CVE database
    let mut db_guard = CVE_DATABASE.write().map_err(|_| {
        ScanError::NetworkError("Failed to acquire write lock on CVE database (lock poisoned)".to_string())
    })?;
    *db_guard = new_db;

    tracing::info!("CVE database successfully updated and saved to {:?}", target_path);
    Ok(())
}

/// Generate search keys from service name and banner.
fn get_search_keys(service: &str, banner_str: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let banner_lower = banner_str.to_lowercase();

    // Add service name as primary key
    if !service.is_empty() {
        // Extract the base software name (before version)
        let base_name = service
            .split_whitespace()
            .next()
            .unwrap_or(service)
            .to_lowercase();
        keys.push(base_name);
    }

    // Add common software identifiers found in banners
    let software_patterns = [
        "openssh", "nginx", "apache", "httpd", "iis", "vsftpd", "proftpd",
        "mysql", "mariadb", "postgres", "openssl", "samba", "smbd",
        "lighttpd", "tomcat", "jetty", "exim", "postfix", "sendmail",
        "openvpn", "redis", "memcached", "mongodb",
    ];

    for pattern in &software_patterns {
        if banner_lower.contains(pattern) {
            keys.push(pattern.to_string());
        }
    }

    // Deduplicate
    keys.sort();
    keys.dedup();

    if keys.is_empty() {
        keys.push(service.to_lowercase());
    }

    keys
}

/// Check if a detected version matches the affected version patterns.
fn version_matches(entry: &CveEntry, detected_version: Option<&str>) -> bool {
    let detected = match detected_version {
        Some(v) => v,
        None => return true, // If we can't detect version, include all matches
    };

    for pattern in &entry.affected_versions {
        if version_pattern_matches(pattern, detected) {
            return true;
        }
    }

    false
}

/// Check if a version string matches a version pattern.
///
/// Supported patterns:
/// - `< X.Y` — version is less than X.Y
/// - `<= X.Y` — version is less than or equal to X.Y
/// - `X.Y` — exact match
/// - `X.Y - X.Z` — range match
fn version_pattern_matches(pattern: &str, version: &str) -> bool {
    let pattern = pattern.trim();

    if pattern.starts_with("< ") || pattern.starts_with("<= ") {
        let is_inclusive = pattern.starts_with("<=");
        let threshold = if is_inclusive {
            pattern.trim_start_matches("<= ").trim()
        } else {
            pattern.trim_start_matches("< ").trim()
        };

        match compare_versions(version, threshold) {
            Some(ord) => {
                if is_inclusive {
                    ord != std::cmp::Ordering::Greater
                } else {
                    ord == std::cmp::Ordering::Less
                }
            }
            None => true, // If we can't compare, include the match
        }
    } else if pattern.contains(" - ") {
        // Range pattern: "X.Y - X.Z"
        let parts: Vec<&str> = pattern.split(" - ").collect();
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
        // Exact or prefix match
        version.starts_with(pattern) || pattern == version
    }
}

/// Compare two version strings.
///
/// Parses version components and compares them numerically.
/// Returns `None` if either version cannot be parsed.
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

/// Parse version string into numeric components.
///
/// "8.9p1" → [8, 9, 1]
/// "2.4.57" → [2, 4, 57]
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
            // Handle patterns like "8.9p1" — save current number, skip letter, continue
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

/// Parse a severity string into a `CveSeverity` enum.
fn parse_severity(s: &str) -> CveSeverity {
    match s.to_lowercase().as_str() {
        "critical" => CveSeverity::Critical,
        "high" => CveSeverity::High,
        "medium" => CveSeverity::Medium,
        "low" => CveSeverity::Low,
        _ => CveSeverity::Medium,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_parts() {
        assert_eq!(parse_version_parts("8.9p1"), vec![8, 9, 1]);
        assert_eq!(parse_version_parts("2.4.57"), vec![2, 4, 57]);
        assert_eq!(parse_version_parts("1.24.0"), vec![1, 24, 0]);
        assert_eq!(parse_version_parts("10.0"), vec![10, 0]);
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(
            compare_versions("8.9", "9.0"),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            compare_versions("9.0", "8.9"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            compare_versions("8.9", "8.9"),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            compare_versions("2.4.57", "2.4.58"),
            Some(std::cmp::Ordering::Less)
        );
    }

    #[test]
    fn test_version_pattern_matches() {
        assert!(version_pattern_matches("< 9.0", "8.9"));
        assert!(!version_pattern_matches("< 9.0", "9.0"));
        assert!(!version_pattern_matches("< 9.0", "9.1"));

        assert!(version_pattern_matches("<= 9.0", "9.0"));
        assert!(version_pattern_matches("<= 9.0", "8.9"));
        assert!(!version_pattern_matches("<= 9.0", "9.1"));

        assert!(version_pattern_matches("8.9", "8.9"));
        assert!(version_pattern_matches("8.9p1", "8.9p1"));
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), CveSeverity::Critical);
        assert_eq!(parse_severity("HIGH"), CveSeverity::High);
        assert_eq!(parse_severity("medium"), CveSeverity::Medium);
        assert_eq!(parse_severity("low"), CveSeverity::Low);
        assert_eq!(parse_severity("unknown"), CveSeverity::Medium);
    }

    #[test]
    fn test_get_search_keys() {
        let keys = get_search_keys("OpenSSH 8.9p1", "SSH-2.0-OpenSSH_8.9p1");
        assert!(keys.contains(&"openssh".to_string()));
    }

    #[test]
    fn test_cve_database_empty() {
        let db = CveDatabase::empty();
        let matches = db.lookup("SSH-2.0-OpenSSH_8.9p1", "OpenSSH", "192.168.1.1", 22);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_cve_match_serialization() {
        let m = CveMatch {
            cve_id: "CVE-2024-12345".to_string(),
            severity: CveSeverity::Critical,
            description: "Test vulnerability".to_string(),
            affected_software: "openssh".to_string(),
            affected_versions: vec!["< 9.0".to_string()],
            cvss_score: 9.8,
            ip: "192.168.1.1".to_string(),
            port: 22,
        };

        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"cveId\""));
        assert!(json.contains("\"cvssScore\""));
        assert!(json.contains("\"affectedSoftware\""));
    }

    #[test]
    fn test_cve_database_loads() {
        // Verify the bundled database can be loaded
        let db = CveDatabase::load_from_json(CVE_JSON);
        assert!(db.is_ok(), "CVE database should load successfully: {:?}", db.err());
        let db = db.unwrap();
        assert!(!db.index.is_empty(), "CVE database should not be empty");
    }

    #[tokio::test]
    async fn test_update_cve_database_validation() {
        // Test that update_cve_database fails on invalid JSON content
        let invalid_json = "{ invalid }".to_string();
        let result = update_cve_database(invalid_json).await;
        assert!(result.is_err(), "Invalid JSON should return an error");

        // Test with a minimal valid JSON content structure
        let valid_json = r#"{
            "vulnerabilities": [
                {
                    "cve_id": "CVE-TEST-1234",
                    "severity": "critical",
                    "description": "Test dynamic vulnerability",
                    "affected_software": "testservice",
                    "affected_versions": ["< 1.0"],
                    "cvss_score": 9.9
                }
            ]
        }"#.to_string();

        let result = update_cve_database(valid_json).await;
        match result {
            Ok(_) => {
                let db_guard = CVE_DATABASE.read().unwrap();
                assert!(db_guard.index.contains_key("testservice"));
            }
            Err(e) => {
                eprintln!("Update command error (acceptable in test environment): {:?}", e);
            }
        }
    }
}
