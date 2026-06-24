use rusqlite::{Connection, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct CveEntry {
    cve_id: String,
    severity: String,
    description: String,
    affected_software: String,
    affected_versions: Vec<String>,
    cvss_score: f64,
}

#[derive(Debug, Deserialize)]
struct CveDatabaseRaw {
    vulnerabilities: Vec<CveEntry>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let json_content = fs::read_to_string("assets/cve-database.json")?;
    let raw: CveDatabaseRaw = serde_json::from_str(&json_content)?;

    let conn = Connection::open("assets/cve-database.db")?;

    conn.execute(
        "CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            affected_software TEXT NOT NULL,
            cvss_score REAL NOT NULL
        )",
        (),
    )?;

    conn.execute(
        "CREATE TABLE affected_versions (
            cve_id TEXT NOT NULL,
            version_pattern TEXT NOT NULL,
            FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
        )",
        (),
    )?;

    // Create an index for faster lookups by affected software
    conn.execute(
        "CREATE INDEX idx_cves_software ON cves(affected_software)",
        (),
    )?;

    let mut stmt1 = conn.prepare("INSERT OR IGNORE INTO cves (cve_id, severity, description, affected_software, cvss_score) VALUES (?1, ?2, ?3, ?4, ?5)")?;
    let mut stmt2 =
        conn.prepare("INSERT INTO affected_versions (cve_id, version_pattern) VALUES (?1, ?2)")?;

    for entry in raw.vulnerabilities {
        stmt1.execute(rusqlite::params![
            entry.cve_id,
            entry.severity,
            entry.description,
            entry.affected_software.to_lowercase(),
            entry.cvss_score,
        ])?;

        for version in entry.affected_versions {
            stmt2.execute(rusqlite::params![entry.cve_id, version,])?;
        }
    }

    println!("Successfully generated assets/cve-database.db");
    Ok(())
}
