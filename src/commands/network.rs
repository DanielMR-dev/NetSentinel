use log::info;
use sysinfo::Networks;

use crate::commands::{CommandError, NetworkInfo};
use crate::network::platform;

/// Get the default gateway IP using the platform-specific gateway provider.
///
/// Delegates to the platform-specific `GatewayProvider` implementation:
/// - **Linux**: Parses `/proc/net/route`
/// - **Windows**: Executes `route print 0.0.0.0` and parses output
/// - **macOS**: Executes `route -n get default` (fallback: `netstat -rn`)
async fn get_default_gateway() -> Option<String> {
    let provider = platform::create_gateway_provider();
    provider.get_default_gateway().await
}

/// Get network information (IP address, MAC address, gateway, network name)
#[tauri::command]
pub async fn get_network_info() -> Result<NetworkInfo, CommandError> {
    let networks = Networks::new_with_refreshed_list();

    let mut ip_address = String::from("unknown");
    let mut mac_address = String::from("unknown");
    let mut network_name = String::from("unknown");

    let gateway = get_default_gateway()
        .await
        .unwrap_or_else(|| "unknown".to_string());

    for (interface_name, data) in networks.iter() {
        // Skip loopback interfaces (cross-platform)
        if platform::is_loopback_interface(interface_name) {
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
