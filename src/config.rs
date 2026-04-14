use serde::{Deserialize, Serialize};

/// Trust Kernel security/speed profiles.
/// Enterprise → paranoid, MKB → balanced, Dev/test → fast.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustKernelConfig {
    pub profile: ProfileConfig,
    pub watchdog: WatchdogConfig,
    pub bus: BusConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileConfig {
    /// Kernel A dry-runs all syscalls before passing to B
    pub voorproever_dryrun: bool,
    /// Every action gets JIS-signed before Archivaris accepts it
    pub jis_signing_per_action: bool,
    /// Snapshot to .tza after every state change (vs only checkpoints)
    pub zstd_snap_per_change: bool,
    /// When to zero-fill deallocated memory
    pub memory_zerofill: ZerofillPolicy,
    /// TIBET token granularity
    pub tibet_token_granularity: TokenGranularity,
    /// FIR/A behavioral trust scoring mode
    pub fira_scoring: FiraMode,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ZerofillPolicy {
    EveryDealloc,
    OnExit,
    Never,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenGranularity {
    PerIo,
    PerSession,
    Batch,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FiraMode {
    Live,
    Static,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WatchdogConfig {
    /// Max ms Kernel A has to respond before auto-KILL
    pub timeout_ms: u64,
    /// Heartbeat interval in ms
    pub heartbeat_interval_ms: u64,
    /// Max consecutive missed heartbeats before bus shutdown
    pub max_missed_heartbeats: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BusConfig {
    /// Shared memory region size in bytes
    pub shared_memory_bytes: usize,
    /// Max payload size that can traverse the bus
    pub max_payload_bytes: usize,
}

impl TrustKernelConfig {
    /// Enterprise: everything on, maximum security
    pub fn paranoid() -> Self {
        Self {
            profile: ProfileConfig {
                voorproever_dryrun: true,
                jis_signing_per_action: true,
                zstd_snap_per_change: true,
                memory_zerofill: ZerofillPolicy::EveryDealloc,
                tibet_token_granularity: TokenGranularity::PerIo,
                fira_scoring: FiraMode::Live,
            },
            watchdog: WatchdogConfig {
                timeout_ms: 50,
                heartbeat_interval_ms: 10,
                max_missed_heartbeats: 3,
            },
            bus: BusConfig {
                shared_memory_bytes: 4 * 1024 * 1024,   // 4MB
                max_payload_bytes: 1024 * 1024,           // 1MB
            },
        }
    }

    /// MKB: balanced security and speed
    pub fn balanced() -> Self {
        Self {
            profile: ProfileConfig {
                voorproever_dryrun: true,
                jis_signing_per_action: true,
                zstd_snap_per_change: false,
                memory_zerofill: ZerofillPolicy::OnExit,
                tibet_token_granularity: TokenGranularity::PerSession,
                fira_scoring: FiraMode::Live,
            },
            watchdog: WatchdogConfig {
                timeout_ms: 100,
                heartbeat_interval_ms: 25,
                max_missed_heartbeats: 5,
            },
            bus: BusConfig {
                shared_memory_bytes: 8 * 1024 * 1024,
                max_payload_bytes: 2 * 1024 * 1024,
            },
        }
    }

    /// Dev/test: speed first, minimal overhead
    pub fn fast() -> Self {
        Self {
            profile: ProfileConfig {
                voorproever_dryrun: false,
                jis_signing_per_action: false,
                zstd_snap_per_change: false,
                memory_zerofill: ZerofillPolicy::OnExit,
                tibet_token_granularity: TokenGranularity::Batch,
                fira_scoring: FiraMode::Static,
            },
            watchdog: WatchdogConfig {
                timeout_ms: 500,
                heartbeat_interval_ms: 100,
                max_missed_heartbeats: 10,
            },
            bus: BusConfig {
                shared_memory_bytes: 16 * 1024 * 1024,
                max_payload_bytes: 4 * 1024 * 1024,
            },
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name {
            "paranoid" => Self::paranoid(),
            "balanced" => Self::balanced(),
            "fast" => Self::fast(),
            _ => {
                eprintln!("◈ [Config] Unknown profile '{}', defaulting to balanced", name);
                Self::balanced()
            }
        }
    }
}
