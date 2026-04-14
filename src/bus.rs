use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use serde::{Serialize, Deserialize};

/// Virtual Bus: one-way communication channel from Kernel A (Voorproever) to Kernel B (Archivaris).
///
/// Design principles:
/// - One-way: A → B only. B never sends data back through the bus.
/// - Signed payloads only: raw pointers never cross the bus.
/// - Monotonically increasing sequence numbers: gaps = TIBET event.
/// - No raw memory sharing in v1: serialized messages over channel.

/// A signed payload that has been approved by the Voorproever.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BusPayload {
    /// Monotonically increasing sequence number
    pub seq: u64,
    /// The original intent
    pub intent: String,
    /// The verified, safe payload content
    pub payload: String,
    /// Agent identity (from .aint domain)
    pub from_aint: String,
    /// Ed25519 signature placeholder (Voorproever signs this)
    pub voorproever_seal: String,
    /// Observed syscalls that passed SNAFT
    pub observed_syscalls: Vec<String>,
    /// FIR/A trust score at time of approval
    pub fira_score: f64,
    /// Timestamp of Voorproever approval (nanos since boot)
    pub approved_at_ns: u64,
}

/// Bus statistics for monitoring and TIBET events.
#[derive(Debug, Clone, Default)]
pub struct BusStats {
    pub payloads_passed: u64,
    pub payloads_rejected: u64,
    pub sequence_gaps_detected: u64,
    pub watchdog_kills: u64,
}

/// The Virtual Bus between Kernel A and Kernel B.
pub struct VirtualBus {
    /// Next expected sequence number (Kernel B side)
    next_expected_seq: AtomicU64,
    /// Sequence counter (Kernel A side)
    seq_counter: AtomicU64,
    /// Bus creation time for relative timestamps
    boot_time: Instant,
    /// Max payload size in bytes
    max_payload_bytes: usize,
    /// Whether the bus is open
    open: std::sync::atomic::AtomicBool,
    /// Stats
    stats: std::sync::Mutex<BusStats>,
}

/// Result of a bus transmission attempt.
#[derive(Debug)]
pub enum BusResult {
    /// Payload delivered to Kernel B
    Delivered(BusPayload),
    /// Bus is closed (watchdog killed it)
    BusClosed,
    /// Payload too large
    PayloadTooLarge { size: usize, max: usize },
    /// Sequence gap detected — missing payloads between expected and received
    SequenceGap { expected: u64, received: u64, gap_size: u64 },
}

impl VirtualBus {
    pub fn new(max_payload_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            next_expected_seq: AtomicU64::new(0),
            seq_counter: AtomicU64::new(0),
            boot_time: Instant::now(),
            max_payload_bytes,
            open: std::sync::atomic::AtomicBool::new(true),
            stats: std::sync::Mutex::new(BusStats::default()),
        })
    }

    /// Kernel A: stamp a payload with the next sequence number.
    pub fn stamp_payload(
        &self,
        intent: &str,
        payload: &str,
        from_aint: &str,
        syscalls: Vec<String>,
        fira_score: f64,
    ) -> BusPayload {
        let seq = self.seq_counter.fetch_add(1, Ordering::SeqCst);
        let elapsed_ns = self.boot_time.elapsed().as_nanos() as u64;

        BusPayload {
            seq,
            intent: intent.to_string(),
            payload: payload.to_string(),
            from_aint: from_aint.to_string(),
            voorproever_seal: format!("vp_seal_seq{}_{}", seq, elapsed_ns),
            observed_syscalls: syscalls,
            fira_score,
            approved_at_ns: elapsed_ns,
        }
    }

    /// Kernel B: receive and validate a payload from the bus.
    pub fn receive(&self, payload: &BusPayload) -> BusResult {
        // Check if bus is open
        if !self.open.load(Ordering::SeqCst) {
            return BusResult::BusClosed;
        }

        // Check payload size
        let size = payload.payload.len();
        if size > self.max_payload_bytes {
            return BusResult::PayloadTooLarge { size, max: self.max_payload_bytes };
        }

        // Check sequence number
        let expected = self.next_expected_seq.load(Ordering::SeqCst);
        if payload.seq != expected {
            let gap_size = payload.seq.saturating_sub(expected);
            let mut stats = self.stats.lock().unwrap();
            stats.sequence_gaps_detected += 1;

            // Accept the payload but report the gap (Kernel B is append-only, doesn't reject)
            self.next_expected_seq.store(payload.seq + 1, Ordering::SeqCst);
            stats.payloads_passed += 1;

            return BusResult::SequenceGap {
                expected,
                received: payload.seq,
                gap_size,
            };
        }

        // Normal delivery
        self.next_expected_seq.store(payload.seq + 1, Ordering::SeqCst);
        let mut stats = self.stats.lock().unwrap();
        stats.payloads_passed += 1;

        BusResult::Delivered(payload.clone())
    }

    /// Watchdog: close the bus (Kernel A is unresponsive).
    pub fn shutdown(&self) {
        self.open.store(false, Ordering::SeqCst);
        let mut stats = self.stats.lock().unwrap();
        stats.watchdog_kills += 1;
    }

    /// Re-open after recovery.
    pub fn reopen(&self) {
        self.open.store(true, Ordering::SeqCst);
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> BusStats {
        self.stats.lock().unwrap().clone()
    }

    pub fn current_seq(&self) -> u64 {
        self.seq_counter.load(Ordering::SeqCst)
    }
}
