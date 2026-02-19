use std::net::SocketAddr;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;

const SERVICE_TYPE: &str = "_tessera._udp.local.";
const SERVICE_NAME: &str = "tessera-node";

/// mDNS LAN discovery for finding Tessera nodes on the local network.
pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
    discovered_rx: mpsc::Receiver<SocketAddr>,
}

impl MdnsDiscovery {
    /// Start mDNS discovery and register this node.
    pub fn new(local_port: u16) -> Result<Self, crate::error::TesseraError> {
        let daemon = ServiceDaemon::new().map_err(|e| {
            crate::error::TesseraError::Network(format!("mdns init: {}", e))
        })?;

        // Register our service
        let host_name = format!("{}.local.", hostname());
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            SERVICE_NAME,
            &host_name,
            "",
            local_port,
            None,
        )
        .map_err(|e| {
            crate::error::TesseraError::Network(format!(
                "mdns service info: {}",
                e
            ))
        })?;

        daemon.register(service_info).map_err(|e| {
            crate::error::TesseraError::Network(format!("mdns register: {}", e))
        })?;

        // Browse for other tessera nodes
        let receiver = daemon.browse(SERVICE_TYPE).map_err(|e| {
            crate::error::TesseraError::Network(format!("mdns browse: {}", e))
        })?;

        let (discovered_tx, discovered_rx) = mpsc::channel(64);

        // Spawn a background task to process mDNS events
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let port = info.get_port();
                    for addr in info.get_addresses() {
                        let socket_addr = SocketAddr::new(*addr, port);
                        let _ = discovered_tx.send(socket_addr).await;
                    }
                }
            }
        });

        Ok(Self {
            daemon,
            discovered_rx,
        })
    }

    /// Get the next discovered peer address.
    pub async fn next_discovered(&mut self) -> Option<SocketAddr> {
        self.discovered_rx.recv().await
    }

    /// Shutdown mDNS.
    pub fn shutdown(self) {
        let _ = self.daemon.shutdown();
    }
}

fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    // mDNS tests require network access and multicast support,
    // which may not be available in CI. These are integration tests.

    #[test]
    fn test_service_type_format() {
        assert!(super::SERVICE_TYPE.ends_with(".local."));
        assert!(super::SERVICE_TYPE.starts_with("_tessera."));
    }
}
