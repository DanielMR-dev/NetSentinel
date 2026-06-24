fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    println!("cargo:rerun-if-changed=proto/nexus_ipc.proto");
    println!("cargo:rerun-if-changed=assets/nmap-service-probes");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/nexus_ipc.proto"], &["proto"])?;
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("nmap_probes.bin");

    if let Ok(db) = parse_nmap_service_probes("assets/nmap-service-probes") {
        let file = File::create(dest_path)?;
        bincode::serialize_into(file, &db)?;
    }

    Ok(())
}
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use nmap_parser::{Match, Probe, ProbeDatabase};

pub fn parse_nmap_service_probes<P: AsRef<Path>>(
    path: P,
) -> Result<ProbeDatabase, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut probes = Vec::new();
    let mut current_probe: Option<Probe> = None;
    let mut excludes: Option<String> = None;

    // We use a simple best-effort PCRE to Rust Regex translation.
    // Rust's regex crate doesn't support lookarounds (?=), (?<=) or backreferences \1.
    // For nmap-service-probes, many matches use \s or basic wildcards, which works fine.

    // Nmap syntax: match <Service> <pattern> [<versioninfo>]
    // <pattern> format: m|[pattern]|s or m=[pattern]=i or q|[pattern]|

    // We will handle the parsing of `m|...|` manually to avoid backreferences.
    let probe_re = Regex::new(r"^Probe\s+(TCP|UDP)\s+([-\w_.]+)\s+q(.)(.*)$").unwrap();

    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with("Exclude ") {
            excludes = Some(trimmed["Exclude ".len()..].trim().to_string());
            continue;
        }

        if trimmed.starts_with("Probe ") {
            if let Some(probe) = current_probe.take() {
                probes.push(probe);
            }

            if let Some(caps) = probe_re.captures(trimmed) {
                let protocol = caps[1].to_string();
                let name = caps[2].to_string();

                let mut raw_str = caps[4].to_string();
                if raw_str.ends_with(&caps[3]) {
                    raw_str.pop();
                }

                // We need to unescape the probe string (e.g. \0 \x01 \r \n)
                let raw_string = unescape(&raw_str);

                current_probe = Some(Probe {
                    protocol,
                    name,
                    probe_string: raw_string,
                    matches: Vec::new(),
                    softmatches: Vec::new(),
                    ports: None,
                    sslports: None,
                    totalwaitms: None,
                    tcpwrappedms: None,
                    rarity: None,
                    fallback: None,
                });
            }
            continue;
        }

        if let Some(probe) = &mut current_probe {
            if trimmed.starts_with("ports ") {
                probe.ports = Some(trimmed["ports ".len()..].trim().to_string());
            } else if trimmed.starts_with("sslports ") {
                probe.sslports = Some(trimmed["sslports ".len()..].trim().to_string());
            } else if trimmed.starts_with("totalwaitms ") {
                if let Ok(val) = trimmed["totalwaitms ".len()..].trim().parse::<u64>() {
                    probe.totalwaitms = Some(val);
                }
            } else if trimmed.starts_with("tcpwrappedms ") {
                if let Ok(val) = trimmed["tcpwrappedms ".len()..].trim().parse::<u64>() {
                    probe.tcpwrappedms = Some(val);
                }
            } else if trimmed.starts_with("rarity ") {
                if let Ok(val) = trimmed["rarity ".len()..].trim().parse::<u32>() {
                    probe.rarity = Some(val);
                }
            } else if trimmed.starts_with("fallback ") {
                probe.fallback = Some(trimmed["fallback ".len()..].trim().to_string());
            } else if trimmed.starts_with("match ") || trimmed.starts_with("softmatch ") {
                let is_soft = trimmed.starts_with("softmatch ");
                let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();

                if parts.len() >= 3 {
                    let service = parts[1].to_string();
                    let rest = parts[2];

                    if rest.starts_with("m") && rest.len() > 1 {
                        let delim = rest.chars().nth(1).unwrap();
                        let mut pattern_end = 0;
                        let mut found_delim = false;

                        let chars: Vec<char> = rest.chars().collect();
                        let mut i = 2;
                        while i < chars.len() {
                            if chars[i] == delim {
                                // Check if escaped? Nmap probes usually don't escape the delimiter if it's not /, but let's be careful.
                                // If it's escaped it might be `\delim`
                                if i > 0 && chars[i - 1] == '\\' {
                                    // escaped
                                } else {
                                    found_delim = true;
                                    pattern_end = i;
                                    break;
                                }
                            }
                            i += 1;
                        }

                        if found_delim {
                            let raw_pattern = &rest[2..pattern_end];

                            // strip unsupported lookarounds
                            let translated = raw_pattern
                                .replace("(?=", "(?:")
                                .replace("(?!", "(?:")
                                .replace("(?<=", "(?:")
                                .replace("(?<!", "(?:");

                            // get flags and versioninfo
                            let mut after_delim = &rest[pattern_end + 1..];
                            let flags = after_delim
                                .chars()
                                .take_while(|c| *c == 'i' || *c == 's')
                                .collect::<String>();
                            after_delim = &after_delim[flags.len()..];
                            let versioninfo = after_delim.trim().to_string();

                            let match_rule = Match {
                                service,
                                pattern: translated,
                                versioninfo,
                                is_soft,
                            };

                            if is_soft {
                                probe.softmatches.push(match_rule);
                            } else {
                                probe.matches.push(match_rule);
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(probe) = current_probe {
        probes.push(probe);
    }

    Ok(ProbeDatabase { probes, excludes })
}

/// Very basic unescaping of C-style string literals found in nmap probes
fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                't' => {
                    out.push(b'\t');
                    i += 2;
                }
                '0' => {
                    out.push(b'\0');
                    i += 2;
                }
                'x' if i + 3 < chars.len() => {
                    let hex = format!("{}{}", chars[i + 2], chars[i + 3]);
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        out.push(byte);
                    }
                    i += 4;
                }
                c => {
                    out.push(c as u8);
                    i += 2;
                }
            }
        } else {
            out.push(chars[i] as u8);
            i += 1;
        }
    }
    out
}
