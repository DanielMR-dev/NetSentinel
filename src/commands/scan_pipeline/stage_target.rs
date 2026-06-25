use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::error::ScanError;
use crate::network::cidr;
use super::context::{PipelineContext, wait_if_paused};

/// Stage 1: Target Stream
/// Parses the CIDR block and streams individual IP addresses to the next stage.
pub async fn stage_target_stream(
    ctx: Arc<PipelineContext>,
    cidr: String,
    out_tx: mpsc::Sender<IpAddr>,
) -> Result<(), ScanError> {
    let network = cidr::validate_cidr(&cidr)?;
    let mut pause_rx = ctx.pause_rx.clone();
    let cancel_rx = ctx.cancel_rx.clone();

    for ip in network.iter() {
        wait_if_paused(&mut pause_rx).await;

        if *cancel_rx.borrow() {
            return Err(ScanError::Cancelled);
        }

        let ip_addr = IpAddr::from(ip);
        if out_tx.send(ip_addr).await.is_err() {
            // Downstream channel closed, exit loop
            break;
        }
    }

    Ok(())
}
