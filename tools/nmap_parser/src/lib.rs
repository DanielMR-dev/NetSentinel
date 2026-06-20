//! Service probes definitions for binary compilation

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Probe {
    pub protocol: String,     // "TCP" or "UDP"
    pub name: String,         // Probe name e.g., "NULL"
    pub probe_string: Vec<u8>,// The actual byte string to send
    pub matches: Vec<Match>,  // List of match rules
    pub softmatches: Vec<Match>, // List of softmatch rules
    pub ports: Option<String>, // Target ports for this probe
    pub sslports: Option<String>,
    pub totalwaitms: Option<u64>,
    pub tcpwrappedms: Option<u64>,
    pub rarity: Option<u32>,
    pub fallback: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Match {
    pub service: String,
    pub pattern: String,
    pub versioninfo: String, // String containing v// i// h// o// cpe:/a:/ etc.
    pub is_soft: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProbeDatabase {
    pub probes: Vec<Probe>,
    pub excludes: Option<String>,
}
