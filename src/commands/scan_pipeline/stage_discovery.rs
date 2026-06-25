use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use crate::error::ScanError;
use crate::events::AppEvent;
use crate::types::{Device, DeviceStatus};
use crate::network::host_discovery::{check_host_alive_with_retry, reverse_dns_lookup};
use crate::network::oui;
use crate::network::cidr;
use super::context::{PipelineContext, wait_if_paused};

const PROGRESS_INTERVAL: u32 = 10;

enum DiscoveryTaskResult {
    Passive(Vec<Device>),
    Active(Option<Device>, IpAddr),
}

/// Stage 2: Host Discovery
/// Discovers live hosts using configured methods. Runs passive resolution (NetBIOS, mDNS, IPv6)
/// in parallel, and processes targets from the input channel via active TCP pings.
pub async fn stage_host_discovery(
    ctx: Arc<PipelineContext>,
    cidr_str: String,
    discovery_methods: Vec<String>,
    retry_count: u8,
    mut in_rx: mpsc::Receiver<IpAddr>,
    out_tx: mpsc::Sender<Device>,
) -> Result<(), ScanError> {
    let mut join_set = JoinSet::new();
    let mut pause_rx = ctx.pause_rx.clone();
    let mut cancel_rx = ctx.cancel_rx.clone();
    let mut emitted_ips = HashSet::new();

    let use_arp = discovery_methods.iter().any(|m| m == "arp");
    let total_hosts = ctx.state.get_total_hosts();

    let _ = ctx.event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: format!(
            "Starting host discovery stage (max {} concurrent, {} retries)",
            ctx.host_semaphore.available_permits(),
            retry_count
        ),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    // Reconstruct network for broadcast address if ARP/NetBIOS is enabled
    let bcast_addr = if use_arp {
        if let Ok(network) = cidr::validate_cidr(&cidr_str) {
            let ipv4 = network.ip();
            Some(Ipv4Addr::new(ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2], 255))
        } else {
            None
        }
    } else {
        None
    };

    // Spawn passive/supplementary discovery task if ARP is enabled
    if use_arp {
        let ctx_clone = ctx.clone();
        join_set.spawn(async move {
            let mut passive_devices = Vec::new();

            // 1. NetBIOS discovery
            if let Some(bcast) = bcast_addr {
                if let Ok(nbns_devs) = crate::network::mdns_netbios::discover_netbios(bcast).await {
                    passive_devices.extend(nbns_devs);
                }
            }

            // 2. mDNS discovery
            if let Ok(mdns_devs) = crate::network::mdns_netbios::discover_mdns().await {
                passive_devices.extend(mdns_devs);
            }

            // 3. IPv6 discovery
            if let Ok(ipv6_devs) = crate::network::ipv6_discovery::discover_ipv6_hosts(ctx_clone.event_tx.clone()).await {
                passive_devices.extend(ipv6_devs);
            }

            Ok::<DiscoveryTaskResult, ScanError>(DiscoveryTaskResult::Passive(passive_devices))
        });
    }

    loop {
        tokio::select! {
            // Immediate cancellation check
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    join_set.abort_all();
                    return Err(ScanError::Cancelled);
                }
            }

            // Process finished sub-tasks
            Some(res) = join_set.join_next(), if !join_set.is_empty() => {
                if let Ok(Ok(task_res)) = res {
                    match task_res {
                        DiscoveryTaskResult::Passive(devices) => {
                            for device in devices {
                                if let Ok(ip) = device.ip.parse::<IpAddr>() {
                                    if emitted_ips.insert(ip) {
                                        let _ = ctx.event_tx.send(AppEvent::DeviceFound(device.clone()));
                                        if out_tx.send(device).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        DiscoveryTaskResult::Active(maybe_device, ip) => {
                            let current = ctx.state.scanned_count.fetch_add(1, Ordering::SeqCst) + 1;
                            
                            if current % PROGRESS_INTERVAL == 0 || current == 1 {
                                let _ = ctx.event_tx.send(AppEvent::ScanLog {
                                    level: "debug".to_string(),
                                    message: format!("Scanning {} ({}/{})", ip, current, total_hosts),
                                    target: Some(ip.to_string()),
                                    timestamp: chrono::Utc::now().timestamp(),
                                });
                            }

                            if current % PROGRESS_INTERVAL == 0 || current == total_hosts {
                                let _ = ctx.event_tx.send(AppEvent::ScanProgress {
                                    scanned: current,
                                    total: total_hosts,
                                    current_target: ip.to_string(),
                                });
                            }

                            if let Some(device) = maybe_device {
                                if emitted_ips.insert(ip) {
                                    let _ = ctx.event_tx.send(AppEvent::ScanLog {
                                        level: "info".to_string(),
                                        message: format!("Host found: {}", ip),
                                        target: Some(ip.to_string()),
                                        timestamp: chrono::Utc::now().timestamp(),
                                    });
                                    let _ = ctx.event_tx.send(AppEvent::DeviceFound(device.clone()));
                                    if out_tx.send(device).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Read next IP from Target Stream Stage
            Some(ip) = in_rx.recv() => {
                wait_if_paused(&mut pause_rx).await;

                if *cancel_rx.borrow() {
                    join_set.abort_all();
                    return Err(ScanError::Cancelled);
                }

                // Acquire host semaphore permit before spawning
                let sem_permit = ctx.host_semaphore.clone().acquire_owned().await;
                
                join_set.spawn(async move {
                    let _permit = sem_permit; // Hold permit during check
                    
                    let is_alive = check_host_alive_with_retry(ip, retry_count as u32).await;
                    if is_alive {
                        let mut device = Device::new(ip.to_string());
                        device.status = DeviceStatus::Online;

                        // Try to get MAC address from ARP cache
                        let provider = crate::network::platform::create_arp_provider();
                        if let Some(mac) = provider.get_mac_for_ip(&ip.to_string()).await {
                            let vendor = oui::lookup_vendor(&mac);
                            device = device.with_mac(mac).with_vendor(vendor);
                        }

                        // Attempt reverse DNS
                        if let Some(hostname) = reverse_dns_lookup(&ip.to_string()).await {
                            device = device.with_hostname(Some(hostname));
                        }

                        Ok::<DiscoveryTaskResult, ScanError>(DiscoveryTaskResult::Active(Some(device), ip))
                    } else {
                        Ok::<DiscoveryTaskResult, ScanError>(DiscoveryTaskResult::Active(None, ip))
                    }
                });
            }

            else => {
                // Input channel closed and all tasks joined
                if join_set.is_empty() {
                    break;
                }
            }
        }
    }

    let _ = ctx.event_tx.send(AppEvent::ScanLog {
        level: "info".to_string(),
        message: format!("Host discovery stage complete. Found {} devices.", emitted_ips.len()),
        target: None,
        timestamp: chrono::Utc::now().timestamp(),
    });

    Ok(())
}
