use std::net::{IpAddr, SocketAddr};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;
use tracing::{debug, warn};

const SERVICE_TYPE: &str = "_tessera._udp.local.";

/// mDNS LAN discovery for finding Tessera nodes on the local network.
pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
    discovered_rx: mpsc::Receiver<SocketAddr>,
}

impl MdnsDiscovery {
    /// Start mDNS discovery and register this node.
    pub fn new(local_port: u16) -> Result<Self, crate::error::TesseraError> {
        let host_name = format!("{}.local.", hostname());
        // Use a unique instance name per node so multiple nodes on the same
        // machine each get their own mDNS record instead of colliding.
        let instance_name = format!("tessera-{}-{}", hostname(), local_port);
        debug!(port = local_port, hostname = %host_name, instance = %instance_name, "mDNS: initializing daemon");

        let daemon = ServiceDaemon::new().map_err(|e| {
            crate::error::TesseraError::Network(format!("mdns init: {}", e))
        })?;
        debug!("mDNS: daemon created successfully");

        // Register our service with automatic address detection
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
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
        })?
        .enable_addr_auto();

        debug!(
            service_type = SERVICE_TYPE,
            service_name = %instance_name,
            hostname = %host_name,
            port = local_port,
            fullname = %service_info.get_fullname(),
            "mDNS: registering service (addr_auto=true)"
        );

        daemon.register(service_info).map_err(|e| {
            crate::error::TesseraError::Network(format!("mdns register: {}", e))
        })?;
        debug!("mDNS: service registered successfully");

        // Browse for other tessera nodes
        let receiver = daemon.browse(SERVICE_TYPE).map_err(|e| {
            crate::error::TesseraError::Network(format!("mdns browse: {}", e))
        })?;
        debug!(service_type = SERVICE_TYPE, "mDNS: browsing for peers");

        let (discovered_tx, discovered_rx) = mpsc::channel(64);

        // Spawn a background task to process mDNS events
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                match event {
                    ServiceEvent::SearchStarted(service_type) => {
                        debug!(service_type = %service_type, "mDNS: search started");
                    }
                    ServiceEvent::ServiceFound(service_type, fullname) => {
                        debug!(
                            service_type = %service_type,
                            fullname = %fullname,
                            "mDNS: service found (awaiting resolution)"
                        );
                    }
                    ServiceEvent::ServiceResolved(info) => {
                        let port = info.get_port();
                        let addrs: Vec<_> =
                            info.get_addresses().iter().copied().collect();
                        debug!(
                            fullname = %info.get_fullname(),
                            hostname = %info.get_hostname(),
                            port = port,
                            addresses = ?addrs,
                            "mDNS: service resolved"
                        );
                        if addrs.is_empty() {
                            warn!(
                                fullname = %info.get_fullname(),
                                "mDNS: resolved service has no addresses, skipping"
                            );
                            continue;
                        }
                        for addr in &addrs {
                            // Skip IPv6 link-local addresses — they lack
                            // scope_id when obtained from mDNS, causing QUIC
                            // connection failures ("invalid remote address").
                            if let IpAddr::V6(v6) = addr
                                && v6.is_unicast_link_local()
                            {
                                debug!(
                                    addr = %addr,
                                    "mDNS: skipping link-local IPv6 address (no scope_id)"
                                );
                                continue;
                            }
                            let socket_addr = SocketAddr::new(*addr, port);
                            debug!(peer = %socket_addr, "mDNS: sending discovered peer to bootstrap");
                            if discovered_tx.send(socket_addr).await.is_err() {
                                debug!(
                                    "mDNS: discovery channel closed, stopping event loop"
                                );
                                return;
                            }
                        }
                    }
                    ServiceEvent::ServiceRemoved(service_type, fullname) => {
                        debug!(
                            service_type = %service_type,
                            fullname = %fullname,
                            "mDNS: service removed"
                        );
                    }
                    ServiceEvent::SearchStopped(service_type) => {
                        debug!(service_type = %service_type, "mDNS: search stopped");
                    }
                }
            }
            debug!("mDNS: event receiver closed, stopping event loop");
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
        debug!("mDNS: shutting down daemon");
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
