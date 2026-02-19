//! Helper binary for NAT integration tests.
//! Runs inside network namespaces via `ip netns exec`.

use std::net::SocketAddr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: nat-test-helper <subcommand> [args...]");
        eprintln!(
            "Subcommands: stun-server, stun-discover, hole-punch, udp-echo"
        );
        std::process::exit(1);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = match args[1].as_str() {
        "stun-server" => {
            // nat-test-helper stun-server <bind-addr>
            let bind: SocketAddr = args[2].parse().expect("invalid bind addr");
            rt.block_on(run_stun_server(bind))
        }
        "stun-discover" => {
            // nat-test-helper stun-discover <local-addr> <stun-server>
            let local: SocketAddr =
                args[2].parse().expect("invalid local addr");
            let server = &args[3];
            rt.block_on(run_stun_discover(local, server))
        }
        "hole-punch" => {
            // nat-test-helper hole-punch <local-addr> <target-external> <attempts>
            let local: SocketAddr =
                args[2].parse().expect("invalid local addr");
            let target: SocketAddr =
                args[3].parse().expect("invalid target addr");
            let attempts: u32 = args[4].parse().expect("invalid attempts");
            rt.block_on(run_hole_punch(local, target, attempts))
        }
        "udp-echo" => {
            // nat-test-helper udp-echo <bind-addr>
            // Echoes received UDP packets back to sender. Used as relay target.
            let bind: SocketAddr = args[2].parse().expect("invalid bind addr");
            rt.block_on(run_udp_echo(bind))
        }
        other => {
            eprintln!("Unknown subcommand: {other}");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

/// Minimal STUN server: listens for Binding Requests, replies with XOR-MAPPED-ADDRESS.
async fn run_stun_server(
    bind: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    // Signal readiness on stdout
    println!("STUN_READY {}", socket.local_addr()?);

    let mut buf = [0u8; 256];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        if len < 20 {
            continue;
        }
        // Verify it's a Binding Request (0x0001)
        if buf[0] != 0x00 || buf[1] != 0x01 {
            continue;
        }
        // Verify magic cookie
        if buf[4..8] != [0x21, 0x12, 0xA4, 0x42] {
            continue;
        }
        let txn_id = &buf[8..20];

        // Build Binding Success Response (0x0101)
        let mut resp = Vec::with_capacity(32);
        // Message type: Binding Success Response
        resp.extend_from_slice(&[0x01, 0x01]);
        // Message length placeholder (fill after building attributes)
        resp.extend_from_slice(&[0x00, 0x00]);
        // Magic cookie
        resp.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        // Transaction ID
        resp.extend_from_slice(txn_id);

        // XOR-MAPPED-ADDRESS attribute (0x0020)
        match from {
            SocketAddr::V4(v4) => {
                let port = v4.port() ^ 0x2112;
                let octets = v4.ip().octets();
                let xip = [
                    octets[0] ^ 0x21,
                    octets[1] ^ 0x12,
                    octets[2] ^ 0xA4,
                    octets[3] ^ 0x42,
                ];
                // Attr type
                resp.extend_from_slice(&[0x00, 0x20]);
                // Attr length: 8
                resp.extend_from_slice(&[0x00, 0x08]);
                // Reserved + family
                resp.extend_from_slice(&[0x00, 0x01]);
                // XOR'd port
                resp.extend_from_slice(&port.to_be_bytes());
                // XOR'd IP
                resp.extend_from_slice(&xip);
            }
            SocketAddr::V6(_) => continue, // skip IPv6 for simplicity
        }

        // Fill in message length (total - 20 byte header)
        let msg_len = (resp.len() - 20) as u16;
        resp[2..4].copy_from_slice(&msg_len.to_be_bytes());

        socket.send_to(&resp, from).await?;
    }
}

/// Call discover_external_addr and print the result.
async fn run_stun_discover(
    local: SocketAddr,
    server: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr =
        tesseras_dht::transport::nat::discover_external_addr(local, server)
            .await?;
    println!("EXTERNAL_ADDR {addr}");
    Ok(())
}

/// Call attempt_hole_punch and print the result.
async fn run_hole_punch(
    local: SocketAddr,
    target: SocketAddr,
    attempts: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("PUNCHING {local} -> {target}");
    tesseras_dht::transport::nat::attempt_hole_punch(local, target, attempts)
        .await?;
    println!("PUNCH_OK");
    Ok(())
}

/// Echo received UDP packets back to sender.
async fn run_udp_echo(
    bind: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    println!("ECHO_READY {}", socket.local_addr()?);

    let mut buf = [0u8; 1500];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        socket.send_to(&buf[..len], from).await?;
    }
}
