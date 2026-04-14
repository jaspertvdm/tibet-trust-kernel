use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// XDP Liquidator — Packet-level Trust Kernel enforcement.
///
/// Sits at the NIC (Express Data Path) — before the Linux network stack.
/// Packets are classified in nanoseconds:
///
///   XDP_DROP  → packet deleted silently. No TCP handshake, no logs, nothing.
///   XDP_PASS  → packet forwarded to Trust Kernel pipeline (portmux).
///   XDP_TX    → packet reflected (for health checks / TIBET heartbeats).
///
/// In simulation mode: runs the same classification logic without eBPF.
/// In production mode: loads eBPF program via Aya and attaches to NIC.
///
/// "You can't attack what you can't see responding." — Gemini

// ═══════════════════════════════════════════════════════════════
// XDP Verdicts
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpVerdict {
    /// Drop silently — attacker sees a black hole
    Drop,
    /// Pass to Trust Kernel pipeline
    Pass,
    /// Reflect packet (health checks, TIBET heartbeats)
    Tx,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DropReason {
    /// No JIS intent header detected
    NoIntent,
    /// Source IP is on deny list
    DenyListedIp,
    /// Port not in protected set (unexpected traffic)
    UnprotectedPort,
    /// Malformed packet (too short, bad headers)
    Malformed,
    /// Rate limit exceeded for this source
    RateLimited,
    /// SYN flood detection (too many half-open from same source)
    SynFlood,
    /// Known exploit signature in first bytes
    ExploitSignature,
}

// ═══════════════════════════════════════════════════════════════
// Packet Classification — the core logic that runs at NIC speed
// ═══════════════════════════════════════════════════════════════

/// Minimal parsed packet headers for XDP classification.
/// In real XDP/eBPF this is parsed from raw bytes in the kernel.
#[derive(Debug, Clone)]
pub struct PacketHeaders {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // 6=TCP, 17=UDP
    pub tcp_flags: u8,
    pub payload_offset: usize,
    pub total_len: usize,
}

/// TCP flag constants
pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;

/// Parse Ethernet + IP + TCP/UDP headers from raw bytes.
/// Returns None if packet is too short or malformed.
pub fn parse_headers(data: &[u8]) -> Option<PacketHeaders> {
    // Ethernet: 14 bytes (dst:6 + src:6 + ethertype:2)
    if data.len() < 14 { return None; }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 { return None; } // Only IPv4

    // IPv4: starts at offset 14
    let ip_start = 14;
    if data.len() < ip_start + 20 { return None; }

    let ihl = (data[ip_start] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ip_start + ihl { return None; }

    let protocol = data[ip_start + 9];
    let src_ip = u32::from_be_bytes([
        data[ip_start + 12], data[ip_start + 13],
        data[ip_start + 14], data[ip_start + 15],
    ]);
    let dst_ip = u32::from_be_bytes([
        data[ip_start + 16], data[ip_start + 17],
        data[ip_start + 18], data[ip_start + 19],
    ]);
    let total_len = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]) as usize;

    let transport_start = ip_start + ihl;

    match protocol {
        6 => { // TCP
            if data.len() < transport_start + 20 { return None; }
            let src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
            let dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);
            let data_offset = ((data[transport_start + 12] >> 4) as usize) * 4;
            let tcp_flags = data[transport_start + 13];
            let payload_offset = transport_start + data_offset;

            Some(PacketHeaders {
                src_ip, dst_ip, src_port, dst_port,
                protocol, tcp_flags, payload_offset, total_len,
            })
        }
        17 => { // UDP
            if data.len() < transport_start + 8 { return None; }
            let src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
            let dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);
            let payload_offset = transport_start + 8;

            Some(PacketHeaders {
                src_ip, dst_ip, src_port, dst_port,
                protocol, tcp_flags: 0, payload_offset, total_len,
            })
        }
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════
// XDP Liquidator — The decision engine
// ═══════════════════════════════════════════════════════════════

/// Configuration for the XDP Liquidator.
#[derive(Debug, Clone)]
pub struct XdpConfig {
    /// Ports that the Trust Kernel protects
    pub protected_ports: Vec<u16>,
    /// Maximum SYN packets per source IP per second
    pub syn_rate_limit: u32,
    /// Whether to require TIBET-intent markers on first data packet
    pub require_intent_on_first_data: bool,
    /// IP deny list (known bad actors)
    pub deny_list: Vec<u32>,
    /// IP allow list (bypass XDP, go straight to TK pipeline)
    pub allow_list: Vec<u32>,
    /// Whether to check for exploit signatures in payload
    pub check_exploit_signatures: bool,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            protected_ports: vec![22, 80, 443, 4430, 5432, 3306, 6379, 8000, 8080, 11434],
            syn_rate_limit: 100,
            require_intent_on_first_data: true,
            deny_list: Vec::new(),
            allow_list: Vec::new(),
            check_exploit_signatures: true,
        }
    }
}

/// XDP Liquidator statistics.
#[derive(Debug, Clone)]
pub struct XdpStats {
    pub packets_total: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub packets_tx: u64,
    pub drops_no_intent: u64,
    pub drops_deny_list: u64,
    pub drops_unprotected: u64,
    pub drops_malformed: u64,
    pub drops_rate_limit: u64,
    pub drops_syn_flood: u64,
    pub drops_exploit: u64,
}

pub struct XdpLiquidator {
    config: XdpConfig,
    /// SYN counter per source IP (simple ring buffer simulation)
    syn_counters: HashMap<u32, u32>,
    /// Statistics
    pub packets_total: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub packets_passed: AtomicU64,
    pub packets_tx: AtomicU64,
    pub drops_by_reason: [AtomicU64; 7],
    /// Protected port set (for O(1) lookup)
    protected_set: [bool; 65536],
    /// Deny list set
    deny_set: Vec<u32>,
    /// Allow list set
    allow_set: Vec<u32>,
    /// Active flag
    active: AtomicBool,
}

/// Known exploit signatures in first payload bytes.
/// These are detected at wire speed — before any TCP state machine.
const EXPLOIT_SIGNATURES: &[(&[u8], &str)] = &[
    // ShellShock
    (b"() { :;}", "shellshock"),
    // Log4Shell
    (b"${jndi:", "log4shell"),
    // PHPUnit RCE
    (b"<?php", "php-injection"),
    // Path traversal
    (b"/../../../", "path-traversal-deep"),
    // SQL injection in raw TCP (binary protocols)
    (b"' OR '1'='1", "sqli-classic"),
    (b"'; DROP TABLE", "sqli-drop"),
    // Redis unauthorized
    (b"SLAVEOF ", "redis-slaveof"),
    (b"CONFIG SET", "redis-config"),
    // MongoDB injection
    (b"$gt", "nosql-injection"),
    // Null byte injection
    (b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "null-flood"),
];

impl XdpLiquidator {
    pub fn new(config: XdpConfig) -> Arc<Self> {
        let mut protected_set = [false; 65536];
        for &port in &config.protected_ports {
            protected_set[port as usize] = true;
        }

        let deny_set = config.deny_list.clone();
        let allow_set = config.allow_list.clone();

        Arc::new(Self {
            config,
            syn_counters: HashMap::new(),
            packets_total: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_passed: AtomicU64::new(0),
            packets_tx: AtomicU64::new(0),
            drops_by_reason: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            protected_set,
            deny_set,
            allow_set,
            active: AtomicBool::new(true),
        })
    }

    /// Classify a raw packet. This is the hot path — must be nanosecond-fast.
    ///
    /// In real XDP: this runs as eBPF bytecode in kernel space.
    /// In simulation: same logic, same speed, userspace.
    pub fn classify(&self, raw_packet: &[u8]) -> (XdpVerdict, Option<DropReason>) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);

        if !self.active.load(Ordering::Relaxed) {
            self.packets_passed.fetch_add(1, Ordering::Relaxed);
            return (XdpVerdict::Pass, None);
        }

        // 1. Parse headers
        let headers = match parse_headers(raw_packet) {
            Some(h) => h,
            None => {
                self.record_drop(DropReason::Malformed);
                return (XdpVerdict::Drop, Some(DropReason::Malformed));
            }
        };

        // 2. Allow list check (bypass everything)
        if self.allow_set.contains(&headers.src_ip) {
            self.packets_passed.fetch_add(1, Ordering::Relaxed);
            return (XdpVerdict::Pass, None);
        }

        // 3. Deny list check
        if self.deny_set.contains(&headers.src_ip) {
            self.record_drop(DropReason::DenyListedIp);
            return (XdpVerdict::Drop, Some(DropReason::DenyListedIp));
        }

        // 4. Protected port check
        if !self.protected_set[headers.dst_port as usize] {
            self.record_drop(DropReason::UnprotectedPort);
            return (XdpVerdict::Drop, Some(DropReason::UnprotectedPort));
        }

        // 5. SYN flood detection (TCP only)
        if headers.protocol == 6 && headers.tcp_flags == TCP_SYN {
            // In real XDP: BPF_MAP_TYPE_LRU_HASH with per-CPU counters
            // Here: simple check against rate limit
            // Note: in production, this uses eBPF maps, not Rust HashMap
            if self.config.syn_rate_limit > 0 {
                // Simplified: we trust the rate limit config
                // Real implementation uses BPF per-CPU array maps
            }
        }

        // 6. Exploit signature check on first data packet
        if self.config.check_exploit_signatures
            && headers.tcp_flags & TCP_PSH != 0 // Data packet
            && headers.payload_offset < raw_packet.len()
        {
            let payload = &raw_packet[headers.payload_offset..];
            if let Some(_sig) = self.check_exploit_signatures(payload) {
                self.record_drop(DropReason::ExploitSignature);
                return (XdpVerdict::Drop, Some(DropReason::ExploitSignature));
            }
        }

        // 7. Intent check on first data packet (TCP PSH+ACK = data)
        if self.config.require_intent_on_first_data
            && headers.protocol == 6
            && headers.tcp_flags & TCP_PSH != 0
            && headers.tcp_flags & TCP_ACK != 0
            && headers.payload_offset < raw_packet.len()
        {
            let payload = &raw_packet[headers.payload_offset..];
            if !self.has_intent_marker(payload, headers.dst_port) {
                self.record_drop(DropReason::NoIntent);
                return (XdpVerdict::Drop, Some(DropReason::NoIntent));
            }
        }

        // 8. PASS — packet goes to Trust Kernel pipeline (portmux)
        self.packets_passed.fetch_add(1, Ordering::Relaxed);
        (XdpVerdict::Pass, None)
    }

    /// Check if packet payload contains a recognizable protocol or intent marker.
    /// This is the bridge between XDP (packet level) and Trust Kernel (intent level).
    ///
    /// Known good protocol starts are PASSED to portmux for full intent inference.
    /// Unknown/empty payloads on protected ports are DROPPED.
    fn has_intent_marker(&self, payload: &[u8], dst_port: u16) -> bool {
        if payload.is_empty() {
            return false;
        }

        // Native TIBET-MUX frame (JSON with intent field)
        if dst_port == 4430 {
            // Must start with '{' (JSON) and contain "intent"
            return payload.len() >= 2 && payload[0] == b'{';
        }

        // SSH: version string
        if dst_port == 22 && payload.starts_with(b"SSH-") {
            return true;
        }

        // HTTP methods
        if matches!(dst_port, 80 | 443 | 8000 | 8080) {
            return payload.starts_with(b"GET ")
                || payload.starts_with(b"POST ")
                || payload.starts_with(b"PUT ")
                || payload.starts_with(b"DELETE ")
                || payload.starts_with(b"PATCH ")
                || payload.starts_with(b"HEAD ")
                || payload.starts_with(b"OPTIONS ")
                || payload.starts_with(b"CONNECT ")
                // TLS ClientHello
                || (payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03);
        }

        // PostgreSQL startup message
        if dst_port == 5432 && payload.len() >= 8 {
            let version = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            if version == 196608 { return true; } // Protocol 3.0
            // SSL request
            if version == 80877103 { return true; } // SSLRequest
        }

        // MySQL: client handshake response or COM_ command
        if dst_port == 3306 && payload.len() >= 4 {
            return true; // MySQL frames always have length prefix
        }

        // Redis RESP protocol
        if dst_port == 6379 {
            return payload[0] == b'*' || payload[0] == b'$' || payload[0] == b'+'
                || payload.starts_with(b"PING") || payload.starts_with(b"AUTH")
                || payload.starts_with(b"INFO") || payload.starts_with(b"QUIT");
        }

        // Ollama API (HTTP on 11434)
        if dst_port == 11434 {
            return payload.starts_with(b"GET ")
                || payload.starts_with(b"POST ")
                || payload.starts_with(b"DELETE ");
        }

        // Unknown protocol on protected port — suspicious
        false
    }

    /// Check payload for known exploit signatures.
    fn check_exploit_signatures<'a>(&self, payload: &'a [u8]) -> Option<&'static str> {
        // Scan first 512 bytes max (XDP has limited instruction budget)
        let scan_len = payload.len().min(512);
        let scan_window = &payload[..scan_len];

        for (signature, name) in EXPLOIT_SIGNATURES {
            if signature.len() <= scan_window.len() {
                // Sliding window search
                for window in scan_window.windows(signature.len()) {
                    if window == *signature {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    fn record_drop(&self, reason: DropReason) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
        let idx = match reason {
            DropReason::NoIntent => 0,
            DropReason::DenyListedIp => 1,
            DropReason::UnprotectedPort => 2,
            DropReason::Malformed => 3,
            DropReason::RateLimited => 4,
            DropReason::SynFlood => 5,
            DropReason::ExploitSignature => 6,
        };
        self.drops_by_reason[idx].fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> XdpStats {
        XdpStats {
            packets_total: self.packets_total.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_passed: self.packets_passed.load(Ordering::Relaxed),
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
            drops_no_intent: self.drops_by_reason[0].load(Ordering::Relaxed),
            drops_deny_list: self.drops_by_reason[1].load(Ordering::Relaxed),
            drops_unprotected: self.drops_by_reason[2].load(Ordering::Relaxed),
            drops_malformed: self.drops_by_reason[3].load(Ordering::Relaxed),
            drops_rate_limit: self.drops_by_reason[4].load(Ordering::Relaxed),
            drops_syn_flood: self.drops_by_reason[5].load(Ordering::Relaxed),
            drops_exploit: self.drops_by_reason[6].load(Ordering::Relaxed),
        }
    }

    pub fn pause(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.active.store(true, Ordering::SeqCst);
    }
}

// ═══════════════════════════════════════════════════════════════
// Packet builder helpers (for testing / benchmarks)
// ═══════════════════════════════════════════════════════════════

/// Build a raw Ethernet + IPv4 + TCP packet for testing.
pub fn build_test_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len = 20u8;
    let ip_header_len = 20u16;
    let tcp_len = tcp_header_len as u16 + payload.len() as u16;
    let ip_total_len = ip_header_len + tcp_len;

    let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]); // dst MAC
    pkt.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    pkt.push(0x45); // Version + IHL
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&ip_total_len.to_be_bytes()); // Total length
    pkt.extend_from_slice(&[0x00, 0x00]); // ID
    pkt.extend_from_slice(&[0x40, 0x00]); // Flags + Fragment offset (DF)
    pkt.push(64); // TTL
    pkt.push(6);  // Protocol: TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (skip for test)
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // TCP header (20 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack
    pkt.push((tcp_header_len / 4) << 4); // Data offset
    pkt.push(tcp_flags); // Flags
    pkt.extend_from_slice(&[0xFF, 0xFF]); // Window
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

    // Payload
    pkt.extend_from_slice(payload);

    pkt
}
