use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Watchdog: monitors Kernel A's responsiveness.
///
/// If Kernel A doesn't send a PASS or KILL within the timeout,
/// the watchdog auto-KILLs and shuts down the bus.
/// Every missed heartbeat is a TIBET event.

pub struct Watchdog {
    /// Last time Kernel A responded (PASS or KILL)
    last_response_ns: AtomicU64,
    /// Boot time for relative timestamps
    boot_time: Instant,
    /// Maximum allowed response time
    timeout: Duration,
    /// Heartbeat interval
    heartbeat_interval: Duration,
    /// Max consecutive misses before bus shutdown
    max_missed: u32,
    /// Current consecutive missed heartbeats
    missed_count: AtomicU64,
    /// Whether the watchdog has triggered (auto-KILL fired)
    triggered: AtomicBool,
    /// Whether the watchdog is active
    active: AtomicBool,
}

#[derive(Debug, Clone)]
pub enum WatchdogEvent {
    /// Kernel A responded in time
    Healthy { response_time_us: u64 },
    /// Heartbeat missed (not fatal yet)
    HeartbeatMissed { consecutive: u32, max: u32 },
    /// Watchdog triggered: auto-KILL, bus shutdown
    Triggered { last_response_ms: f64, timeout_ms: u64 },
}

impl Watchdog {
    pub fn new(timeout_ms: u64, heartbeat_interval_ms: u64, max_missed: u32) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            last_response_ns: AtomicU64::new(0),
            boot_time: now,
            timeout: Duration::from_millis(timeout_ms),
            heartbeat_interval: Duration::from_millis(heartbeat_interval_ms),
            max_missed,
            missed_count: AtomicU64::new(0),
            triggered: AtomicBool::new(false),
            active: AtomicBool::new(true),
        })
    }

    /// Called when Kernel A sends a response (PASS or KILL).
    /// Resets the watchdog timer.
    pub fn kernel_a_responded(&self) {
        let now_ns = self.boot_time.elapsed().as_nanos() as u64;
        self.last_response_ns.store(now_ns, Ordering::SeqCst);
        self.missed_count.store(0, Ordering::SeqCst);
    }

    /// Check if Kernel A is still responsive.
    /// Returns a WatchdogEvent describing the current state.
    pub fn check(&self) -> WatchdogEvent {
        if !self.active.load(Ordering::SeqCst) {
            return WatchdogEvent::Healthy { response_time_us: 0 };
        }

        let now_ns = self.boot_time.elapsed().as_nanos() as u64;
        let last_ns = self.last_response_ns.load(Ordering::SeqCst);
        let elapsed_ns = now_ns.saturating_sub(last_ns);
        let elapsed = Duration::from_nanos(elapsed_ns);

        if elapsed > self.timeout {
            let missed = self.missed_count.fetch_add(1, Ordering::SeqCst) as u32 + 1;

            if missed >= self.max_missed {
                self.triggered.store(true, Ordering::SeqCst);
                return WatchdogEvent::Triggered {
                    last_response_ms: elapsed_ns as f64 / 1_000_000.0,
                    timeout_ms: self.timeout.as_millis() as u64,
                };
            }

            return WatchdogEvent::HeartbeatMissed {
                consecutive: missed,
                max: self.max_missed,
            };
        }

        WatchdogEvent::Healthy {
            response_time_us: (elapsed_ns / 1000) as u64,
        }
    }

    /// Has the watchdog triggered an auto-KILL?
    pub fn has_triggered(&self) -> bool {
        self.triggered.load(Ordering::SeqCst)
    }

    /// Reset after recovery (new Kernel A instance).
    pub fn reset(&self) {
        self.triggered.store(false, Ordering::SeqCst);
        self.missed_count.store(0, Ordering::SeqCst);
        self.kernel_a_responded(); // Reset timer
    }

    /// Pause watchdog (during maintenance).
    pub fn pause(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    /// Resume watchdog.
    pub fn resume(&self) {
        self.active.store(true, Ordering::SeqCst);
        self.kernel_a_responded(); // Reset timer on resume
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout.as_millis() as u64
    }

    pub fn heartbeat_interval_ms(&self) -> u64 {
        self.heartbeat_interval.as_millis() as u64
    }
}
