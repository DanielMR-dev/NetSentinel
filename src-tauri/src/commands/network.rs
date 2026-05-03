use log::info;
use sysinfo::Networks;

use crate::commands::{CommandError, NetworkInfo};

/// Get the default gateway IP by reading /proc/net/route on Linux
fn get_default_gateway() -> Option<String> {
    // Try to read gateway from /proc/net/route on Linux
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 3 {
                let _interface = fields[0];
                let destination = fields[1];
                let gateway = fields[2];

                // Default route has destination 00000000 and gateway not 00000000
                if destination == "00000000" && gateway != "00000000" {
                    // Convert hex IP to dotted notation
                    let gateway_hex = gateway.to_string();
                    if gateway_hex.len() == 8 {
                        let ip_str = format!(
                            "{}.{}.{}.{}",
                            u8::from_str_radix(&gateway_hex[6..8], 16).ok()?,
                            u8::from_str_radix(&gateway_hex[4..6], 16).ok()?,
                            u8::from_str_radix(&gateway_hex[2..4], 16).ok()?,
                            u8::from_str_radix(&gateway_hex[0..2], 16).ok()?
                        );
                        return Some(ip_str);
                    }
                }
            }
        }
    }
    None
}

/// Get network information (IP address, MAC address, gateway, network name)
#[tauri::command]
pub async fn get_network_info() -> Result<NetworkInfo, CommandError> {
    let networks = Networks::new_with_refreshed_list();

    let mut ip_address = String::from("unknown");
    let mut mac_address = String::from("unknown");
    let mut network_name = String::from("unknown");

    let gateway = get_default_gateway().unwrap_or_else(|| "unknown".to_string());

    for (interface_name, data) in networks.iter() {
        // Skip loopback interfaces
        if interface_name == "lo" || interface_name == "lo0" {
            continue;
        }

        // Get the IP address from ip_networks
        if let Some(ip_network) = data.ip_networks().first() {
            ip_address = ip_network.addr.to_string();
        }

        // Get MAC address - skip if it's zero/empty
        let mac = data.mac_address().to_string();
        if !mac.is_empty() && mac != "00:00:00:00:00:00" {
            mac_address = mac;
        }

        // Use interface name as network name
        if ip_address != "unknown" && network_name == "unknown" {
            network_name = interface_name.clone();
        }

        // If we found a valid interface with IP, we're done
        if ip_address != "unknown" && ip_address != "127.0.0.1" {
            info!(
                "Network info retrieved: interface={}, ip_address={}, mac_address={}, gateway={}",
                interface_name, ip_address, mac_address, gateway
            );
            break;
        }
    }

    Ok(NetworkInfo {
        ip_address,
        mac_address,
        gateway,
        network_name,
    })
}