//! CVSS v3.1 Calculation and EPSS Integration
//!
//! Provides structures to calculate CVSS v3.1 Base Scores from metrics
//! and fetches Exploit Prediction Scoring System (EPSS) probabilities.

use lazy_static::lazy_static;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::warn;

// --- CVSS v3.1 Base Score Calculator ---

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttackComplexity {
    Low,
    High,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserInteraction {
    None,
    Required,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scope {
    Unchanged,
    Changed,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CiaImpact {
    None,
    Low,
    High,
} // Confidentiality, Integrity, Availability

pub struct Cvss31Metrics {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: CiaImpact,
    pub integrity: CiaImpact,
    pub availability: CiaImpact,
}

impl Cvss31Metrics {
    fn round_up_1(n: f64) -> f64 {
        let int_input = (n * 100000.0).round() as i64;
        if int_input % 10000 == 0 {
            int_input as f64 / 100000.0
        } else {
            ((int_input / 10000) as f64 + 1.0) / 10.0
        }
    }

    pub fn calculate_base_score(&self) -> f64 {
        let av = match self.attack_vector {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.20,
        };
        let ac = match self.attack_complexity {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        };
        let pr = match (self.privileges_required, self.scope) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, Scope::Unchanged) => 0.62,
            (PrivilegesRequired::Low, Scope::Changed) => 0.68,
            (PrivilegesRequired::High, Scope::Unchanged) => 0.27,
            (PrivilegesRequired::High, Scope::Changed) => 0.50,
        };
        let ui = match self.user_interaction {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        };

        let exp = 8.22 * av * ac * pr * ui;

        let conf = match self.confidentiality {
            CiaImpact::High => 0.56,
            CiaImpact::Low => 0.22,
            CiaImpact::None => 0.0,
        };
        let integ = match self.integrity {
            CiaImpact::High => 0.56,
            CiaImpact::Low => 0.22,
            CiaImpact::None => 0.0,
        };
        let avail = match self.availability {
            CiaImpact::High => 0.56,
            CiaImpact::Low => 0.22,
            CiaImpact::None => 0.0,
        };

        let iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail));

        let impact = if self.scope == Scope::Unchanged {
            6.42 * iss
        } else {
            7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02_f64).powf(13.0)
        };

        if impact <= 0.0 {
            return 0.0;
        }

        let base_score = if self.scope == Scope::Unchanged {
            Self::round_up_1((impact + exp).min(10.0_f64))
        } else {
            Self::round_up_1((1.08 * (impact + exp)).min(10.0_f64))
        };

        base_score
    }
}

// --- EPSS Integration ---

#[derive(Debug, Deserialize)]
struct EpssDataItem {
    epss: String,
    percentile: String,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Vec<EpssDataItem>,
}

pub struct EpssScore {
    pub probability: f64,
    pub percentile: f64,
}

lazy_static! {
    static ref EPSS_CACHE: Mutex<HashMap<String, (EpssScore, Instant)>> =
        Mutex::new(HashMap::new());
}

pub async fn get_epss_score(cve_id: &str) -> Option<EpssScore> {
    // Check cache first
    if let Ok(mut cache) = EPSS_CACHE.lock() {
        if let Some((score, timestamp)) = cache.get(cve_id) {
            if timestamp.elapsed() < Duration::from_secs(3600) {
                return Some(EpssScore {
                    probability: score.probability,
                    percentile: score.percentile,
                });
            } else {
                cache.remove(cve_id);
            }
        }
    }

    // Query API
    let url = format!("https://api.first.org/data/v1/epss?cve={}", cve_id);
    let client = Client::new();
    match client.get(&url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(epss_resp) = resp.json::<EpssResponse>().await {
                    if let Some(item) = epss_resp.data.first() {
                        let prob = item.epss.parse::<f64>().unwrap_or(0.0);
                        let perc = item.percentile.parse::<f64>().unwrap_or(0.0);

                        let score = EpssScore {
                            probability: prob,
                            percentile: perc,
                        };

                        if let Ok(mut cache) = EPSS_CACHE.lock() {
                            cache.insert(
                                cve_id.to_string(),
                                (
                                    EpssScore {
                                        probability: prob,
                                        percentile: perc,
                                    },
                                    Instant::now(),
                                ),
                            );
                        }

                        return Some(score);
                    }
                }
            } else {
                warn!("EPSS API returned status {} for {}", resp.status(), cve_id);
            }
        }
        Err(e) => {
            warn!("Failed to query EPSS API for {}: {}", cve_id, e);
        }
    }

    None
}
