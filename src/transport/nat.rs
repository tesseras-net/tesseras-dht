use std::net::SocketAddr;

use crate::error::TesseraError;

/// Default public STUN servers for NAT discovery.
pub const DEFAULT_STUN_SERVERS: &[&str] =
    &["stun.l.google.com:19302", "stun1.l.google.com:19302"];

/// STUN binding request to discover external IP:port.
/// Uses a minimal STUN implementation (RFC 5389).
///
/// Returns the server-reflexive address (our external IP:port as seen by the STUN server).
pub async fn discover_external_addr(
    local_addr: SocketAddr,
    stun_server: &str,
) -> Result<SocketAddr, TesseraError> {
    let socket = tokio::net::UdpSocket::bind(local_addr)
        .await
        .map_err(|e| TesseraError::Network(format!("bind: {}", e)))?;

    let server_addr: SocketAddr = tokio::net::lookup_host(stun_server)
        .await
        .map_err(|e| {
            TesseraError::Network(format!("resolve stun server: {}", e))
        })?
        .next()
        .ok_or(TesseraError::Network("no addresses for stun server".into()))?;

    // Build a minimal STUN Binding Request (RFC 5389)
    let mut request = [0u8; 20];
    // Message type: Binding Request (0x0001)
    request[0] = 0x00;
    request[1] = 0x01;
    // Message length: 0 (no attributes)
    request[2] = 0x00;
    request[3] = 0x00;
    // Magic cookie: 0x2112A442
    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;
    // Transaction ID: random 12 bytes
    let mut txn_id = [0u8; 12];
    rand::fill(&mut txn_id);
    request[8..20].copy_from_slice(&txn_id);

    socket
        .send_to(&request, server_addr)
        .await
        .map_err(|e| TesseraError::Network(format!("send stun: {}", e)))?;

    let mut buf = [0u8; 256];
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| TesseraError::Timeout)?
    .map_err(|e| TesseraError::Network(format!("recv stun: {}", e)))?;

    let (len, _) = timeout;
    let response = &buf[..len];

    // Parse STUN response
    if response.len() < 20 {
        return Err(TesseraError::Network("stun response too short".into()));
    }

    // Verify magic cookie
    if response[4..8] != [0x21, 0x12, 0xA4, 0x42] {
        return Err(TesseraError::Network("invalid stun magic cookie".into()));
    }

    // Verify transaction ID
    if response[8..20] != txn_id {
        return Err(TesseraError::Network(
            "stun transaction id mismatch".into(),
        ));
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    let msg_len = u16::from_be_bytes([response[2], response[3]]) as usize;
    let attrs = &response[20..20 + msg_len.min(response.len() - 20)];

    parse_mapped_address(attrs, &txn_id)
}

/// Parse STUN attributes to find the mapped address.
fn parse_mapped_address(
    attrs: &[u8],
    txn_id: &[u8; 12],
) -> Result<SocketAddr, TesseraError> {
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len =
            u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
        let attr_data = &attrs
            [offset + 4..offset + 4 + attr_len.min(attrs.len() - offset - 4)];

        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS
                return parse_xor_mapped(attr_data, txn_id);
            }
            0x0001 => {
                // MAPPED-ADDRESS
                return parse_mapped(attr_data);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundary
        offset += 4 + ((attr_len + 3) & !3);
    }

    Err(TesseraError::Network(
        "no mapped address in stun response".into(),
    ))
}

fn parse_xor_mapped(
    data: &[u8],
    txn_id: &[u8; 12],
) -> Result<SocketAddr, TesseraError> {
    if data.len() < 8 {
        return Err(TesseraError::Network(
            "xor-mapped-address too short".into(),
        ));
    }

    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]) ^ 0x2112;

    match family {
        0x01 => {
            // IPv4
            let ip = [
                data[4] ^ 0x21,
                data[5] ^ 0x12,
                data[6] ^ 0xA4,
                data[7] ^ 0x42,
            ];
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    ip[0], ip[1], ip[2], ip[3],
                )),
                xport,
            ))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(TesseraError::Network(
                    "xor-mapped-address ipv6 too short".into(),
                ));
            }
            let mut ip_bytes = [0u8; 16];
            // XOR with magic cookie + transaction ID
            let xor_key: Vec<u8> = [0x21, 0x12, 0xA4, 0x42]
                .iter()
                .chain(txn_id.iter())
                .copied()
                .collect();
            for i in 0..16 {
                ip_bytes[i] = data[4 + i] ^ xor_key[i];
            }
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)),
                xport,
            ))
        }
        _ => Err(TesseraError::Network(format!(
            "unknown address family: {}",
            family
        ))),
    }
}

fn parse_mapped(data: &[u8]) -> Result<SocketAddr, TesseraError> {
    if data.len() < 8 {
        return Err(TesseraError::Network("mapped-address too short".into()));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => Ok(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                data[4], data[5], data[6], data[7],
            )),
            port,
        )),
        _ => Err(TesseraError::Network(format!(
            "unsupported address family: {}",
            family
        ))),
    }
}

/// Attempt hole punching by sending probes to the target's external address.
/// Both peers must send probes simultaneously (coordinated by a relay).
///
/// Returns Ok(()) if the punch succeeded (we received a response), or an error.
pub async fn attempt_hole_punch(
    local_addr: SocketAddr,
    target_external: SocketAddr,
    attempts: u32,
) -> Result<(), TesseraError> {
    let socket =
        tokio::net::UdpSocket::bind(local_addr).await.map_err(|e| {
            TesseraError::Network(format!("bind for hole punch: {}", e))
        })?;

    let probe = b"TESSERA_PUNCH";

    for _ in 0..attempts {
        // Send a probe to create a NAT mapping
        let _ = socket.send_to(probe, target_external).await;

        // Brief wait then check for response
        let mut buf = [0u8; 64];
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((len, from))) => {
                if len >= probe.len() && &buf[..probe.len()] == probe {
                    tracing::info!("hole punch succeeded with {}", from);
                    return Ok(());
                }
            }
            _ => continue,
        }
    }

    Err(TesseraError::Network(
        "hole punch failed after all attempts".into(),
    ))
}

// --- Relay ---

/// A relay session for forwarding packets between two peers
/// when direct connectivity isn't possible (symmetric NAT).
///
/// The relay node receives packets from peer A, rewrites the source,
/// and forwards to peer B (and vice versa).
#[derive(Debug)]
pub struct RelaySession {
    pub peer_a: SocketAddr,
    pub peer_b: SocketAddr,
}

impl RelaySession {
    pub fn new(peer_a: SocketAddr, peer_b: SocketAddr) -> Self {
        Self { peer_a, peer_b }
    }

    /// Determine which peer to forward to based on the sender.
    pub fn forward_target(&self, from: &SocketAddr) -> Option<SocketAddr> {
        if *from == self.peer_a {
            Some(self.peer_b)
        } else if *from == self.peer_b {
            Some(self.peer_a)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xor_mapped_address_ipv4() {
        // XOR-MAPPED-ADDRESS attribute for 192.168.1.1:12345
        // After XOR: port = 12345 ^ 0x2112, ip = 192^0x21, 168^0x12, 1^0xA4, 1^0x42
        let port: u16 = 12345;
        let ip = [192u8, 168, 1, 1];

        let xport = port ^ 0x2112;
        let xip = [ip[0] ^ 0x21, ip[1] ^ 0x12, ip[2] ^ 0xA4, ip[3] ^ 0x42];

        let mut data = vec![0u8; 8];
        data[1] = 0x01; // IPv4
        data[2..4].copy_from_slice(&xport.to_be_bytes());
        data[4..8].copy_from_slice(&xip);

        let txn_id = [0u8; 12];
        let result = parse_xor_mapped(&data, &txn_id).unwrap();
        assert_eq!(result.port(), 12345);
        assert_eq!(
            result.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn test_default_stun_servers() {
        assert!(!DEFAULT_STUN_SERVERS.is_empty());
        for server in DEFAULT_STUN_SERVERS {
            assert!(server.contains(':'));
        }
    }

    #[test]
    fn test_relay_session_forwarding() {
        let a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let session = RelaySession::new(a, b);

        assert_eq!(session.forward_target(&a), Some(b));
        assert_eq!(session.forward_target(&b), Some(a));

        let unknown: SocketAddr = "10.0.0.3:5000".parse().unwrap();
        assert_eq!(session.forward_target(&unknown), None);
    }
}
