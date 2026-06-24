use std::net::IpAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

/// TCP port probing as a fallback discovery method when ARP is not available.
/// This method probes common ports to detect active hosts on the network.
pub async fn probe_hosts(
    ips: Vec<IpAddr>,
    concurrency_limit: usize,
    port_timeout_ms: u64,
) -> Vec<IpAddr> {
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let sem = Arc::new(Semaphore::new(concurrency_limit));
    let timeout_duration = Duration::from_millis(port_timeout_ms);

    let active_ips: Vec<IpAddr> = stream::iter(ips)
        .map(|ip| {
            let sem = sem.clone();
            let timeout_dur = timeout_duration;

            async move {
                let _permit = sem.acquire().await.ok()?;
                let timeout_ms = timeout_dur.as_millis() as u64;
                let alive = probe_host_alive(ip, timeout_ms).await.unwrap_or(false);
                if alive {
                    Some(ip)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(concurrency_limit)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    active_ips
}

/// Check if a host is alive by probing common ports
pub async fn probe_host_alive(ip: IpAddr, timeout_ms: u64) -> Option<bool> {
    let timeout_duration = Duration::from_millis(timeout_ms);

    // Common ports to check for host liveness
    let probe_ports = [22, 80, 443, 445, 3389, 8080, 139];

    for port in probe_ports {
        if probe_port(ip, port, timeout_duration).await {
            return Some(true);
        }
    }

    Some(false)
}

/// Probe a specific port on a host
async fn probe_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
    let addr = std::net::SocketAddr::new(ip, port);

    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => true,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => false,
        Ok(Err(_)) => false,
        Err(_) => false, // timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_probe_port_invalid_ip() {
        // This will timeout or fail, which is expected for an invalid IP
        let result = probe_port(
            "192.168.255.255".parse().unwrap(),
            80,
            Duration::from_millis(100),
        )
        .await;
        // Result should be false (can't connect)
        assert!(!result);
    }
}
