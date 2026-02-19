//! NAT integration tests using Linux network namespaces.
//!
//! Requires root or CAP_NET_ADMIN. Gated by TESSERA_NAT_TEST=1 env var.
//! Run: `sudo TESSERA_NAT_TEST=1 cargo test --test nat_integration -- --test-threads=1`
//!
//! Tests MUST run serially (--test-threads=1) because they share namespace names.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Check if NAT tests should run.
fn should_run() -> bool {
    std::env::var("TESSERA_NAT_TEST").is_ok_and(|v| v == "1")
}

/// Path to the nat-test-helper binary.
fn helper_bin() -> String {
    // Use the binary from the target directory
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    path.push("nat-test-helper");
    path.to_string_lossy().into_owned()
}

/// Network namespace test environment.
///
/// Creates 3 namespaces (tess-alice, tess-bob, tess-stun) connected via
/// veth pairs to the host, which routes between them with iptables MASQUERADE.
///
/// Topology:
///   tess-alice (10.0.1.2/24) <--veth--> host (10.0.1.1) --MASQUERADE-->
///   tess-bob   (10.0.2.2/24) <--veth--> host (10.0.2.1) --MASQUERADE-->
///   tess-stun  (10.0.0.2/24) <--veth--> host (10.0.0.1) [no NAT]
struct NetnsEnv {
    created: bool,
}

impl NetnsEnv {
    fn setup() -> Result<Self, String> {
        // Clean up any stale namespaces from previous runs
        for ns in &["tess-alice", "tess-bob", "tess-stun"] {
            let _ = Command::new("ip").args(["netns", "delete", ns]).output();
        }
        // Clean up stale veth interfaces on host
        for veth in &["veth-a", "veth-b", "veth-s"] {
            let _ = Command::new("ip").args(["link", "delete", veth]).output();
        }

        let cmds = vec![
            // Create namespaces
            "ip netns add tess-alice",
            "ip netns add tess-bob",
            "ip netns add tess-stun",
            // Create veth pairs
            "ip link add veth-a type veth peer name veth-ar",
            "ip link add veth-b type veth peer name veth-br",
            "ip link add veth-s type veth peer name veth-sr",
            // Move peer ends into namespaces
            "ip link set veth-ar netns tess-alice",
            "ip link set veth-br netns tess-bob",
            "ip link set veth-sr netns tess-stun",
            // Configure host-side IPs
            "ip addr add 10.0.1.1/24 dev veth-a",
            "ip addr add 10.0.2.1/24 dev veth-b",
            "ip addr add 10.0.0.1/24 dev veth-s",
            "ip link set veth-a up",
            "ip link set veth-b up",
            "ip link set veth-s up",
            // Configure alice namespace
            "ip netns exec tess-alice ip addr add 10.0.1.2/24 dev veth-ar",
            "ip netns exec tess-alice ip link set veth-ar up",
            "ip netns exec tess-alice ip link set lo up",
            "ip netns exec tess-alice ip route add default via 10.0.1.1",
            // Configure bob namespace
            "ip netns exec tess-bob ip addr add 10.0.2.2/24 dev veth-br",
            "ip netns exec tess-bob ip link set veth-br up",
            "ip netns exec tess-bob ip link set lo up",
            "ip netns exec tess-bob ip route add default via 10.0.2.1",
            // Configure stun namespace (public, no NAT)
            "ip netns exec tess-stun ip addr add 10.0.0.2/24 dev veth-sr",
            "ip netns exec tess-stun ip link set veth-sr up",
            "ip netns exec tess-stun ip link set lo up",
            "ip netns exec tess-stun ip route add default via 10.0.0.1",
            // Enable IP forwarding on host
            "sysctl -w net.ipv4.ip_forward=1",
            // MASQUERADE for alice (10.0.1.0/24 -> host)
            "iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o veth-s -j MASQUERADE",
            "iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o veth-b -j MASQUERADE",
            // MASQUERADE for bob (10.0.2.0/24 -> host)
            "iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o veth-s -j MASQUERADE",
            "iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o veth-a -j MASQUERADE",
            // Allow forwarding between namespaces
            "iptables -A FORWARD -i veth-a -j ACCEPT",
            "iptables -A FORWARD -i veth-b -j ACCEPT",
            "iptables -A FORWARD -i veth-s -j ACCEPT",
            "iptables -A FORWARD -o veth-a -j ACCEPT",
            "iptables -A FORWARD -o veth-b -j ACCEPT",
            "iptables -A FORWARD -o veth-s -j ACCEPT",
        ];

        for cmd_str in &cmds {
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            let output = Command::new(parts[0])
                .args(&parts[1..])
                .output()
                .map_err(|e| format!("exec {cmd_str}: {e}"))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("{cmd_str}: {stderr}"));
            }
        }

        Ok(Self { created: true })
    }

    /// Spawn a process inside a namespace, returning it with piped stdout.
    fn exec_in_ns(
        &self,
        ns: &str,
        bin: &str,
        args: &[&str],
    ) -> Result<Child, String> {
        let mut cmd_args = vec!["netns", "exec", ns, bin];
        cmd_args.extend_from_slice(args);

        Command::new("ip")
            .args(&cmd_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn in {ns}: {e}"))
    }

    /// Read one line from a child's stdout (blocking, with timeout).
    /// Takes ownership of stdout — can only be called once per child.
    fn read_line(
        child: &mut Child,
        timeout: Duration,
    ) -> Result<String, String> {
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let result = reader.read_line(&mut line);
            let _ = tx.send((line, result));
        });

        match rx.recv_timeout(timeout) {
            Ok((line, Ok(_))) => Ok(line.trim().to_string()),
            Ok((_, Err(e))) => Err(format!("read error: {e}")),
            Err(_) => Err("timeout reading from child".into()),
        }
    }

    /// Switch alice's NAT to symmetric (random port mapping).
    fn make_alice_symmetric(&self) -> Result<(), String> {
        let cmds = [
            // Remove endpoint-independent MASQUERADE for alice
            "iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o veth-s -j MASQUERADE",
            "iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o veth-b -j MASQUERADE",
            // Add random-port MASQUERADE (simulates symmetric NAT)
            "iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o veth-s -j MASQUERADE --random",
            "iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o veth-b -j MASQUERADE --random",
        ];
        for cmd_str in &cmds {
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            let output = Command::new(parts[0])
                .args(&parts[1..])
                .output()
                .map_err(|e| format!("{cmd_str}: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "{cmd_str}: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        Ok(())
    }
}

impl Drop for NetnsEnv {
    fn drop(&mut self) {
        if !self.created {
            return;
        }
        // Clean up iptables rules
        let cleanup_cmds = [
            "iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o veth-s -j MASQUERADE",
            "iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o veth-b -j MASQUERADE",
            "iptables -t nat -D POSTROUTING -s 10.0.2.0/24 -o veth-s -j MASQUERADE",
            "iptables -t nat -D POSTROUTING -s 10.0.2.0/24 -o veth-a -j MASQUERADE",
            "iptables -D FORWARD -i veth-a -j ACCEPT",
            "iptables -D FORWARD -i veth-b -j ACCEPT",
            "iptables -D FORWARD -i veth-s -j ACCEPT",
            "iptables -D FORWARD -o veth-a -j ACCEPT",
            "iptables -D FORWARD -o veth-b -j ACCEPT",
            "iptables -D FORWARD -o veth-s -j ACCEPT",
            // Also try cleaning up --random rules in case symmetric NAT was enabled
            "iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o veth-s -j MASQUERADE --random",
            "iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o veth-b -j MASQUERADE --random",
        ];
        for cmd_str in &cleanup_cmds {
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            let _ = Command::new(parts[0]).args(&parts[1..]).output();
        }

        // Deleting namespaces auto-cleans veth pairs
        for ns in &["tess-alice", "tess-bob", "tess-stun"] {
            let _ = Command::new("ip").args(["netns", "delete", ns]).output();
        }
    }
}

#[test]
fn test_stun_discovery_through_nat() {
    if !should_run() {
        eprintln!("Skipping NAT test (set TESSERA_NAT_TEST=1 and run as root)");
        return;
    }

    let env = NetnsEnv::setup().expect("namespace setup failed");
    let bin = helper_bin();

    // Start mock STUN server in tess-stun namespace
    let mut stun = env
        .exec_in_ns("tess-stun", &bin, &["stun-server", "10.0.0.2:3478"])
        .expect("spawn stun server");

    // Wait for STUN server readiness
    let ready = NetnsEnv::read_line(&mut stun, Duration::from_secs(5))
        .expect("stun server ready");
    assert!(ready.starts_with("STUN_READY"), "unexpected: {ready}");

    // Run STUN discovery from alice (behind NAT)
    let discover = env
        .exec_in_ns(
            "tess-alice",
            &bin,
            &["stun-discover", "0.0.0.0:0", "10.0.0.2:3478"],
        )
        .expect("spawn stun discover");

    let output = discover.wait_with_output().expect("wait for discover");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stun discover failed: {stderr}");

    // The external address should be the host's IP on the stun-facing veth (10.0.0.1:ephemeral)
    // because alice's traffic is MASQUERADEd through the host
    let line = stdout.trim();
    assert!(
        line.starts_with("EXTERNAL_ADDR 10.0.0.1:"),
        "unexpected addr: {line}"
    );

    // Clean up STUN server
    let _ = stun.kill();
}

#[test]
fn test_hole_punch_endpoint_independent() {
    if !should_run() {
        eprintln!("Skipping NAT test (set TESSERA_NAT_TEST=1 and run as root)");
        return;
    }

    let env = NetnsEnv::setup().expect("namespace setup failed");
    let bin = helper_bin();

    // Alice and bob punch to each other's private addresses through host routing.
    // Traffic goes through iptables MASQUERADE (alice→bob exits via veth-b),
    // so this exercises attempt_hole_punch through real NAT conntrack.
    //
    // Note: We don't use STUN-discovered external addresses here because both
    // peers are NATted through the same host — their external addresses resolve
    // to the host's own IP, making direct peer-to-peer impossible without
    // separate router namespaces. The STUN discovery path is tested separately
    // in test_stun_discovery_through_nat.

    // Both punch simultaneously (spawn both, then wait)
    let alice_punch = env
        .exec_in_ns(
            "tess-alice",
            &bin,
            &["hole-punch", "10.0.1.2:9000", "10.0.2.2:9000", "10"],
        )
        .expect("spawn alice punch");

    let bob_punch = env
        .exec_in_ns(
            "tess-bob",
            &bin,
            &["hole-punch", "10.0.2.2:9000", "10.0.1.2:9000", "10"],
        )
        .expect("spawn bob punch");

    let alice_result = alice_punch.wait_with_output().unwrap();
    let bob_result = bob_punch.wait_with_output().unwrap();

    let alice_stdout = String::from_utf8_lossy(&alice_result.stdout);
    let bob_stdout = String::from_utf8_lossy(&bob_result.stdout);

    // At least one side should succeed (both probing simultaneously creates the NAT mapping)
    let alice_ok = alice_stdout.contains("PUNCH_OK");
    let bob_ok = bob_stdout.contains("PUNCH_OK");
    assert!(
        alice_ok || bob_ok,
        "hole punch failed on both sides.\nalice: {}\nbob: {}",
        String::from_utf8_lossy(&alice_result.stderr),
        String::from_utf8_lossy(&bob_result.stderr),
    );
}

#[test]
fn test_hole_punch_fails_symmetric_nat() {
    if !should_run() {
        eprintln!("Skipping NAT test (set TESSERA_NAT_TEST=1 and run as root)");
        return;
    }

    let env = NetnsEnv::setup().expect("namespace setup failed");
    let bin = helper_bin();

    // Make alice's NAT symmetric (random port mapping)
    env.make_alice_symmetric().expect("make alice symmetric");

    // Start mock STUN server
    let mut stun = env
        .exec_in_ns("tess-stun", &bin, &["stun-server", "10.0.0.2:3478"])
        .expect("spawn stun server");
    let ready = NetnsEnv::read_line(&mut stun, Duration::from_secs(5)).unwrap();
    assert!(ready.starts_with("STUN_READY"));

    // Alice discovers her external addr (will be mapped with random port)
    let alice_discover = env
        .exec_in_ns(
            "tess-alice",
            &bin,
            &["stun-discover", "10.0.1.2:9000", "10.0.0.2:3478"],
        )
        .expect("spawn alice discover");
    let alice_out = alice_discover.wait_with_output().unwrap();
    assert!(alice_out.status.success());
    let alice_ext: SocketAddr = String::from_utf8_lossy(&alice_out.stdout)
        .trim()
        .strip_prefix("EXTERNAL_ADDR ")
        .unwrap()
        .parse()
        .unwrap();

    // Bob discovers his external addr
    let bob_discover = env
        .exec_in_ns(
            "tess-bob",
            &bin,
            &["stun-discover", "10.0.2.2:9000", "10.0.0.2:3478"],
        )
        .expect("spawn bob discover");
    let bob_out = bob_discover.wait_with_output().unwrap();
    assert!(bob_out.status.success());
    let bob_ext: SocketAddr = String::from_utf8_lossy(&bob_out.stdout)
        .trim()
        .strip_prefix("EXTERNAL_ADDR ")
        .unwrap()
        .parse()
        .unwrap();

    // Try hole punch with fewer attempts (should fail due to symmetric NAT)
    let alice_punch = env
        .exec_in_ns(
            "tess-alice",
            &bin,
            &["hole-punch", "10.0.1.2:9000", &bob_ext.to_string(), "3"],
        )
        .expect("spawn alice punch");

    let bob_punch = env
        .exec_in_ns(
            "tess-bob",
            &bin,
            &["hole-punch", "10.0.2.2:9000", &alice_ext.to_string(), "3"],
        )
        .expect("spawn bob punch");

    let alice_result = alice_punch.wait_with_output().unwrap();
    let bob_result = bob_punch.wait_with_output().unwrap();

    // With symmetric NAT, the port alice used for STUN differs from the port
    // her NAT assigns for packets to bob. So bob's probes go to the wrong port.
    // At least alice should fail (she has symmetric NAT).
    assert!(
        !alice_result.status.success() || !bob_result.status.success(),
        "hole punch should fail with symmetric NAT"
    );

    let _ = stun.kill();
}

#[test]
fn test_relay_session_through_nat() {
    if !should_run() {
        eprintln!("Skipping NAT test (set TESSERA_NAT_TEST=1 and run as root)");
        return;
    }

    let env = NetnsEnv::setup().expect("namespace setup failed");
    let bin = helper_bin();

    // Start a UDP echo server in the stun namespace (acts as relay endpoint)
    let mut echo = env
        .exec_in_ns("tess-stun", &bin, &["udp-echo", "10.0.0.2:4000"])
        .expect("spawn echo server");
    let ready = NetnsEnv::read_line(&mut echo, Duration::from_secs(5)).unwrap();
    assert!(ready.starts_with("ECHO_READY"));

    // Alice sends a UDP packet to the echo server through NAT
    // The echo server reflects it back — proving NAT traversal via relay works
    let alice_punch = env
        .exec_in_ns(
            "tess-alice",
            &bin,
            &["hole-punch", "10.0.1.2:9001", "10.0.0.2:4000", "3"],
        )
        .expect("spawn alice relay test");

    let result = alice_punch.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout);

    // The echo server reflects TESSERA_PUNCH back, so hole-punch sees success
    assert!(
        stdout.contains("PUNCH_OK"),
        "relay echo failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let _ = echo.kill();
}
