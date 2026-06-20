//! Advanced service detection using nmap-service-probes.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use once_cell::sync::Lazy;
use regex::Regex;

use nmap_parser::{ProbeDatabase, Probe};
use crate::error::ScanError;

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub service: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub hostname: Option<String>,
    pub cpe: Vec<String>,
    pub banner: String,
}

static PROBE_DB: Lazy<ProbeDatabase> = Lazy::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/nmap_probes.bin"));
    bincode::deserialize(bytes).expect("Failed to deserialize nmap probes database")
});

pub struct ServiceDetector {
    timeout: Duration,
}

impl ServiceDetector {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn detect_tcp(&self, ip: &str, port: u16) -> Result<ServiceInfo, ScanError> {
        let addr = format!("{}:{}", ip, port);
        
        // Find applicable probes
        // 1. NULL probe
        // 2. Probes where 'ports' includes this port
        
        let null_probe = PROBE_DB.probes.iter().find(|p| p.name == "NULL");
        
        // Try NULL probe first
        if let Some(probe) = null_probe {
            if let Ok(info) = self.execute_probe(&addr, probe, port).await {
                if info.service.is_some() {
                    return Ok(info);
                }
            }
        }
        
        // Try specific probes for this port
        for probe in PROBE_DB.probes.iter() {
            if probe.name == "NULL" || probe.protocol != "TCP" { continue; }
            
            // Simple check if this port is targeted
            let targets_port = probe.ports.as_ref().map(|p_str| p_str.contains(&port.to_string())).unwrap_or(false);
            
            if targets_port {
                if let Ok(info) = self.execute_probe(&addr, probe, port).await {
                    if info.service.is_some() {
                        return Ok(info);
                    }
                }
            }
        }

        // Fallback: Just return basic connection success info
        Ok(ServiceInfo {
            service: None,
            version: None,
            os: None,
            hostname: None,
            cpe: vec![],
            banner: String::new(),
        })
    }

    async fn execute_probe(&self, addr: &str, probe: &Probe, _port: u16) -> Result<ServiceInfo, ScanError> {
        let connect_result = tokio::time::timeout(self.timeout, TcpStream::connect(addr)).await;
        let mut stream = match connect_result {
            Ok(Ok(s)) => s,
            _ => return Err(ScanError::Timeout),
        };

        if !probe.probe_string.is_empty() {
            if tokio::time::timeout(self.timeout, stream.write_all(&probe.probe_string)).await.is_err() {
                return Err(ScanError::Timeout);
            }
        }

        let mut buf = vec![0u8; 8192];
        let bytes_read = match tokio::time::timeout(self.timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Err(ScanError::Timeout),
        };

        let response = String::from_utf8_lossy(&buf[..bytes_read]);

        for m in &probe.matches {
            // Very naive match check using unanchored regex
            // Some patterns might fail to compile, so we handle it gracefully
            if let Ok(re) = Regex::new(&m.pattern) {
                if let Some(caps) = re.captures(&response) {
                    let mut info = ServiceInfo {
                        service: Some(m.service.clone()),
                        version: None,
                        os: None,
                        hostname: None,
                        cpe: vec![],
                        banner: response.trim().to_string(),
                    };

                    // Extract version info fields (v/version/ p/product/ o/os/ etc)
                    let vinfo = &m.versioninfo;
                    
                    // Simple extraction of v/ and o/ and cpe:/a:
                    // Using basic string parsing since the format is space-separated or bounded by /
                    if let Some(v_start) = vinfo.find("v/") {
                        let after_v = &vinfo[v_start + 2..];
                        let v_end = after_v.find('/').unwrap_or(after_v.len());
                        let v_str = &after_v[..v_end];
                        // Replace $1, $2 with captures
                        let version = Self::expand_captures(v_str, &caps);
                        info.version = Some(version);
                    }

                    if let Some(o_start) = vinfo.find("o/") {
                        let after_o = &vinfo[o_start + 2..];
                        let o_end = after_o.find('/').unwrap_or(after_o.len());
                        let o_str = &after_o[..o_end];
                        info.os = Some(Self::expand_captures(o_str, &caps));
                    }

                    return Ok(info);
                }
            }
        }

        Ok(ServiceInfo {
            service: None,
            version: None,
            os: None,
            hostname: None,
            cpe: vec![],
            banner: response.trim().to_string(),
        })
    }

    fn expand_captures(template: &str, caps: &regex::Captures) -> String {
        let mut result = template.to_string();
        for i in 1..=9 {
            let placeholder = format!("${}", i);
            if result.contains(&placeholder) {
                if let Some(capture) = caps.get(i) {
                    result = result.replace(&placeholder, capture.as_str());
                }
            }
        }
        result
    }
}
