pub mod nexus_ipc {
    tonic::include_proto!("nexus.ipc");
}

use std::net::IpAddr;
use std::path::Path;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status, Streaming};

use crate::events::AppEvent;
use crate::types::{Device, DeviceStatus, Port};
use nexus_ipc::nexus_intercom_server::{NexusIntercom, NexusIntercomServer};
use nexus_ipc::IpcMessage;

pub struct NexusIntercomImpl {
    event_tx: mpsc::Sender<AppEvent>,
}

#[tonic::async_trait]
impl NexusIntercom for NexusIntercomImpl {
    type StreamEventsStream = ReceiverStream<Result<IpcMessage, Status>>;

    async fn stream_events(
        &self,
        request: Request<Streaming<IpcMessage>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let mut in_stream = request.into_inner();
        let (tx, rx) = mpsc::channel(128);

        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            while let Ok(Some(msg)) = in_stream.message().await {
                if let Some(payload) = msg.payload {
                    match payload {
                        nexus_ipc::ipc_message::Payload::HostDiscovered(host) => {
                            // Strict IP sanitization
                            if host.ip_address.parse::<IpAddr>().is_err() {
                                let _ = tx
                                    .send(Err(Status::invalid_argument(
                                        "Invalid IP address format",
                                    )))
                                    .await;
                                continue;
                            }

                            let mut device = Device::new(host.ip_address);
                            device.mac = host.mac_address;
                            device.status = DeviceStatus::Online;
                            if !host.os_guess.is_empty() {
                                device.os = Some(host.os_guess);
                            }
                            device.ports = host
                                .open_ports
                                .into_iter()
                                .map(|p| Port {
                                    number: p as u16,
                                    protocol: "tcp".to_string(),
                                    service: crate::types::get_service_name(p as u16),
                                    state: crate::types::PortState::Open,
                                })
                                .collect();

                            let event = AppEvent::DeviceFound(device);

                            // Backpressure check using try_send on the bounded channel
                            if let Err(mpsc::error::TrySendError::Full(_)) =
                                event_tx.try_send(event)
                            {
                                let _ = tx
                                    .send(Err(Status::resource_exhausted(
                                        "NetSentinel event queue is full",
                                    )))
                                    .await;
                            }
                        }
                        nexus_ipc::ipc_message::Payload::Alert(alert) => {
                            let severity_str = match alert.severity {
                                0 => "INFO",
                                1 => "LOW",
                                2 => "MEDIUM",
                                3 => "HIGH",
                                4 => "CRITICAL",
                                _ => "UNKNOWN",
                            };

                            let tool_str = match alert.source_tool {
                                0 => "NET_SENTINEL",
                                1 => "SHADOW_DECOY",
                                2 => "VENOM_WEAVER",
                                3 => "AEGIS_FUZZ",
                                4 => "SLEUTH_HOUND",
                                _ => "UNKNOWN",
                            };

                            let event = AppEvent::SecurityAlert {
                                source_tool: tool_str.to_string(),
                                severity: severity_str.to_string(),
                                title: alert.title,
                                description: alert.description,
                                target_artifact: alert.target_artifact,
                                timestamp: alert.timestamp,
                            };

                            if let Err(mpsc::error::TrySendError::Full(_)) =
                                event_tx.try_send(event)
                            {
                                let _ = tx
                                    .send(Err(Status::resource_exhausted(
                                        "NetSentinel event queue is full",
                                    )))
                                    .await;
                            }
                        }
                        nexus_ipc::ipc_message::Payload::CommandTrigger(cmd) => {
                            let event = AppEvent::IpcCommand(cmd);
                            if let Err(mpsc::error::TrySendError::Full(_)) =
                                event_tx.try_send(event)
                            {
                                let _ = tx
                                    .send(Err(Status::resource_exhausted(
                                        "NetSentinel event queue is full",
                                    )))
                                    .await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn trigger_action(
        &self,
        request: Request<IpcMessage>,
    ) -> Result<Response<IpcMessage>, Status> {
        let msg = request.into_inner();

        if let Some(payload) = msg.payload.clone() {
            match payload {
                nexus_ipc::ipc_message::Payload::HostDiscovered(host) => {
                    if host.ip_address.parse::<IpAddr>().is_err() {
                        return Err(Status::invalid_argument("Invalid IP address format"));
                    }
                    let mut device = Device::new(host.ip_address);
                    device.mac = host.mac_address;
                    device.status = DeviceStatus::Online;

                    let event = AppEvent::DeviceFound(device);
                    if let Err(mpsc::error::TrySendError::Full(_)) = self.event_tx.try_send(event) {
                        return Err(Status::resource_exhausted(
                            "NetSentinel event queue is full",
                        ));
                    }
                }
                nexus_ipc::ipc_message::Payload::Alert(alert) => {
                    let event = AppEvent::SecurityAlert {
                        source_tool: format!("{:?}", alert.source_tool),
                        severity: format!("{:?}", alert.severity),
                        title: alert.title,
                        description: alert.description,
                        target_artifact: alert.target_artifact,
                        timestamp: alert.timestamp,
                    };
                    if let Err(mpsc::error::TrySendError::Full(_)) = self.event_tx.try_send(event) {
                        return Err(Status::resource_exhausted(
                            "NetSentinel event queue is full",
                        ));
                    }
                }
                nexus_ipc::ipc_message::Payload::CommandTrigger(cmd) => {
                    let event = AppEvent::IpcCommand(cmd);
                    if let Err(mpsc::error::TrySendError::Full(_)) = self.event_tx.try_send(event) {
                        return Err(Status::resource_exhausted(
                            "NetSentinel event queue is full",
                        ));
                    }
                }
            }
        }

        Ok(Response::new(msg))
    }
}

pub struct IpcServer {
    socket_path: String,
}

impl IpcServer {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    pub async fn run(
        self,
        event_tx: mpsc::Sender<AppEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = Path::new(&self.socket_path);

        // Clean up any stale socket file
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let uds = tokio::net::UnixListener::bind(path)?;
        let stream = UnixListenerStream::new(uds);

        let intercom = NexusIntercomImpl { event_tx };
        let server = NexusIntercomServer::new(intercom);

        // Surgical cleanup via tokio::signal::ctrl_c shutdown hook
        tonic::transport::Server::builder()
            .add_service(server)
            .serve_with_incoming_shutdown(stream, async {
                tokio::signal::ctrl_c().await.ok();
            })
            .await?;

        Ok(())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        // Surgical cleanup on drop
        let path = Path::new(&self.socket_path);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
}
