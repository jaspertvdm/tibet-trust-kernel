use std::time::Instant;

/// Recovery Engine — Intent-based state restore from .tza snapshots.
///
/// When something goes wrong (watchdog KILL, bus failure, memory overflow),
/// the Recovery Engine can restore the system to a known good state.
///
/// Recovery flow:
///   1. Intent → resolve which .tza snapshot to restore
///   2. Load .tza from disk (or git if local is corrupted)
///   3. Verify Ed25519 signature + SHA256 integrity
///   4. Decompress zstd → raw memory
///   5. Inject into Zandbak memory region
///   6. Mint TIBET recovery token
///
/// Recovery strategies:
///   - **LastGood**: Restore the most recent successful snapshot
///   - **Checkpoint**: Restore a specific checkpoint by seq number
///   - **CleanBoot**: Discard all state, restore from pre-warmed image
///   - **GitRecover**: Pull from git if local .tza is corrupted
///
/// "Intent routing voor recovery: snapshot terugzetten via AINS-style routing"

// ═══════════════════════════════════════════════════════════════
// Recovery types
// ═══════════════════════════════════════════════════════════════

/// Recovery strategy — how to find the right snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecoveryStrategy {
    /// Most recent successful snapshot for this intent
    LastGood,
    /// Specific checkpoint by bus sequence number
    Checkpoint { target_seq: u64 },
    /// Clean boot — discard all state
    CleanBoot,
    /// Pull from git (local may be corrupted)
    GitRecover,
}

/// A discovered snapshot on disk that could be restored.
#[derive(Debug, Clone)]
pub struct SnapshotCandidate {
    /// Path to the .tza file
    pub path: String,
    /// Intent this snapshot belongs to
    pub intent: String,
    /// Bus sequence number at capture time
    pub bus_seq: u64,
    /// File size in bytes
    pub file_size: usize,
    /// Whether the Ed25519 signature verifies
    pub signature_valid: bool,
    /// Whether the SHA256 hash matches
    pub hash_valid: bool,
    /// Timestamp of capture (nanos since epoch)
    pub captured_at_ns: u64,
}

/// Result of a recovery operation.
#[derive(Debug, Clone)]
pub enum RecoveryResult {
    /// State restored successfully
    Restored {
        /// Which snapshot was used
        snapshot_path: String,
        /// Sequence number restored to
        restored_seq: u64,
        /// Raw bytes injected into memory
        bytes_injected: usize,
        /// Time to find + verify + decompress + inject
        total_us: u64,
        /// Verification passed
        integrity_verified: bool,
        /// TIBET recovery token ID
        tibet_token_id: String,
        /// Strategy that was used
        strategy: RecoveryStrategy,
    },
    /// Clean boot — no snapshot needed, fresh state
    CleanBooted {
        /// Time to reset all state
        reset_us: u64,
        /// TIBET token ID
        tibet_token_id: String,
    },
    /// Recovery failed — no valid snapshot found
    Failed {
        reason: String,
        /// Strategies attempted
        strategies_tried: Vec<RecoveryStrategy>,
    },
}

/// Incident that triggered recovery.
#[derive(Debug, Clone)]
pub enum RecoveryTrigger {
    /// Watchdog killed Kernel A
    WatchdogKill { last_response_ms: f64 },
    /// Bus closed unexpectedly
    BusFailure { last_seq: u64 },
    /// Memory overflow in Zandbak
    MemoryOverflow { intent: String, allocated: usize, budget: usize },
    /// Sequence gap detected on bus
    SequenceGap { expected: u64, received: u64 },
    /// Manual recovery request
    Manual { requested_by: String },
    /// JIS denied access — rollback to pre-attempt state
    JisDenied { reason: String },
}

// ═══════════════════════════════════════════════════════════════
// Snapshot Index — in-memory catalog of available snapshots
// ═══════════════════════════════════════════════════════════════

/// The Snapshot Index tracks all available .tza snapshots.
/// In production: scans disk on startup, watches for new files via inotify.
/// In simulation: maintains an in-memory list.
pub struct SnapshotIndex {
    /// All known snapshots, newest first per intent
    snapshots: Vec<SnapshotCandidate>,
    /// Base path for snapshot storage
    store_path: String,
    /// Git repository path (if enabled)
    git_path: Option<String>,
}

impl SnapshotIndex {
    pub fn new(store_path: &str, git_path: Option<&str>) -> Self {
        Self {
            snapshots: Vec::new(),
            store_path: store_path.to_string(),
            git_path: git_path.map(|s| s.to_string()),
        }
    }

    /// Register a newly captured snapshot.
    pub fn register(&mut self, candidate: SnapshotCandidate) {
        self.snapshots.push(candidate);
        // Keep sorted by timestamp, newest first
        self.snapshots.sort_by(|a, b| b.captured_at_ns.cmp(&a.captured_at_ns));
    }

    /// Register from a Snapshot capture.
    pub fn register_from_snapshot(&mut self, snapshot: &crate::snapshot::Snapshot) {
        let candidate = SnapshotCandidate {
            path: format!("{}/{}/{}.tza",
                self.store_path,
                snapshot.intent.replace(':', "/"),
                snapshot.id),
            intent: snapshot.intent.clone(),
            bus_seq: snapshot.bus_seq,
            file_size: snapshot.compressed_size + crate::snapshot::TZA_HEADER_SIZE,
            signature_valid: true,
            hash_valid: true,
            captured_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
        };
        self.register(candidate);
    }

    /// Find the best snapshot for an intent using a given strategy.
    pub fn resolve(&self, intent: &str, strategy: RecoveryStrategy) -> Option<&SnapshotCandidate> {
        match strategy {
            RecoveryStrategy::LastGood => {
                // Find most recent valid snapshot for this intent (prefix match)
                self.snapshots.iter().find(|s| {
                    (s.intent == intent || intent.starts_with(&s.intent))
                    && s.signature_valid
                    && s.hash_valid
                })
            }
            RecoveryStrategy::Checkpoint { target_seq } => {
                // Find the snapshot closest to (but not after) the target sequence
                self.snapshots.iter()
                    .filter(|s| {
                        (s.intent == intent || intent.starts_with(&s.intent))
                        && s.bus_seq <= target_seq
                        && s.signature_valid
                    })
                    .min_by_key(|s| target_seq - s.bus_seq)
            }
            RecoveryStrategy::CleanBoot => {
                // No snapshot needed for clean boot
                None
            }
            RecoveryStrategy::GitRecover => {
                // In production: `git log --oneline -- '*.tza'` → find latest
                // Return the newest even if local signature hasn't been verified
                self.snapshots.iter().find(|s| {
                    s.intent == intent || intent.starts_with(&s.intent)
                })
            }
        }
    }

    /// How many snapshots are indexed for a given intent.
    pub fn count_for_intent(&self, intent: &str) -> usize {
        self.snapshots.iter()
            .filter(|s| s.intent == intent || intent.starts_with(&s.intent))
            .count()
    }

    /// Total indexed snapshots.
    pub fn total(&self) -> usize {
        self.snapshots.len()
    }

    /// Total disk usage (all indexed snapshots).
    pub fn total_disk_bytes(&self) -> usize {
        self.snapshots.iter().map(|s| s.file_size).sum()
    }
}

// ═══════════════════════════════════════════════════════════════
// Recovery Engine
// ═══════════════════════════════════════════════════════════════

pub struct RecoveryEngine {
    /// Snapshot index
    pub index: SnapshotIndex,
    /// Recovery attempts this session
    pub recoveries_attempted: u64,
    /// Successful recoveries
    pub recoveries_succeeded: u64,
    /// Failed recoveries
    pub recoveries_failed: u64,
}

impl RecoveryEngine {
    pub fn new(store_path: &str, git_path: Option<&str>) -> Self {
        Self {
            index: SnapshotIndex::new(store_path, git_path),
            recoveries_attempted: 0,
            recoveries_succeeded: 0,
            recoveries_failed: 0,
        }
    }

    /// Recover state for an intent after an incident.
    ///
    /// Tries strategies in order: LastGood → Checkpoint(0) → GitRecover → CleanBoot
    pub fn recover(
        &mut self,
        intent: &str,
        trigger: &RecoveryTrigger,
        preferred_strategy: Option<RecoveryStrategy>,
    ) -> RecoveryResult {
        let t0 = Instant::now();
        self.recoveries_attempted += 1;

        let strategies = if let Some(preferred) = preferred_strategy {
            vec![preferred]
        } else {
            vec![
                RecoveryStrategy::LastGood,
                RecoveryStrategy::Checkpoint { target_seq: 0 },
                RecoveryStrategy::GitRecover,
                RecoveryStrategy::CleanBoot,
            ]
        };

        let mut tried = Vec::new();

        for strategy in &strategies {
            tried.push(*strategy);

            // CleanBoot always succeeds — it's the nuclear option
            if *strategy == RecoveryStrategy::CleanBoot {
                let reset_us = t0.elapsed().as_micros() as u64;
                let token_id = format!("tibet_recovery_clean_{}",
                    chrono::Utc::now().timestamp_micros());

                self.recoveries_succeeded += 1;
                return RecoveryResult::CleanBooted {
                    reset_us,
                    tibet_token_id: token_id,
                };
            }

            // Try to find a snapshot
            if let Some(candidate) = self.index.resolve(intent, *strategy) {
                // Step 1: Verify integrity
                if !candidate.signature_valid || !candidate.hash_valid {
                    continue; // Try next strategy
                }

                // Step 2: Simulate load + decompress + inject
                // In production:
                //   let blob = std::fs::read(&candidate.path)?;
                //   let header = SnapshotEngine::parse_tza_header(&blob)?;
                //   let compressed = &blob[header.data_offset..];
                //   let raw = zstd::decode_all(compressed)?;
                //   zandbak_region.inject(raw);

                let total_us = t0.elapsed().as_micros() as u64;
                let token_id = format!("tibet_recovery_seq{}_{}_{}",
                    candidate.bus_seq,
                    trigger_name(trigger),
                    chrono::Utc::now().timestamp_micros());

                self.recoveries_succeeded += 1;
                return RecoveryResult::Restored {
                    snapshot_path: candidate.path.clone(),
                    restored_seq: candidate.bus_seq,
                    bytes_injected: candidate.file_size, // Approximation
                    total_us,
                    integrity_verified: candidate.signature_valid && candidate.hash_valid,
                    tibet_token_id: token_id,
                    strategy: *strategy,
                };
            }
        }

        // All strategies exhausted
        self.recoveries_failed += 1;
        RecoveryResult::Failed {
            reason: format!("No valid snapshot found for intent '{}' after {} strategies",
                intent, tried.len()),
            strategies_tried: tried,
        }
    }

    /// Quick health check: can we recover this intent if needed?
    pub fn can_recover(&self, intent: &str) -> RecoveryHealth {
        let total = self.index.count_for_intent(intent);
        let valid = self.index.snapshots.iter()
            .filter(|s| {
                (s.intent == intent || intent.starts_with(&s.intent))
                && s.signature_valid
                && s.hash_valid
            })
            .count();

        let newest_age_ms = self.index.snapshots.iter()
            .filter(|s| s.intent == intent || intent.starts_with(&s.intent))
            .next()
            .map(|s| {
                let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
                (now_ns.saturating_sub(s.captured_at_ns)) / 1_000_000
            })
            .unwrap_or(u64::MAX);

        RecoveryHealth {
            intent: intent.to_string(),
            snapshots_available: total,
            snapshots_valid: valid,
            newest_snapshot_age_ms: newest_age_ms,
            can_last_good: valid > 0,
            can_git_recover: self.index.git_path.is_some() && total > 0,
            can_clean_boot: true, // Always available
        }
    }

    /// Stats.
    pub fn stats(&self) -> RecoveryStats {
        RecoveryStats {
            recoveries_attempted: self.recoveries_attempted,
            recoveries_succeeded: self.recoveries_succeeded,
            recoveries_failed: self.recoveries_failed,
            snapshots_indexed: self.index.total(),
            total_snapshot_bytes: self.index.total_disk_bytes(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryHealth {
    pub intent: String,
    pub snapshots_available: usize,
    pub snapshots_valid: usize,
    pub newest_snapshot_age_ms: u64,
    pub can_last_good: bool,
    pub can_git_recover: bool,
    pub can_clean_boot: bool,
}

#[derive(Debug, Clone)]
pub struct RecoveryStats {
    pub recoveries_attempted: u64,
    pub recoveries_succeeded: u64,
    pub recoveries_failed: u64,
    pub snapshots_indexed: usize,
    pub total_snapshot_bytes: usize,
}

/// Human-readable trigger name for TIBET tokens.
fn trigger_name(trigger: &RecoveryTrigger) -> &'static str {
    match trigger {
        RecoveryTrigger::WatchdogKill { .. } => "watchdog_kill",
        RecoveryTrigger::BusFailure { .. } => "bus_failure",
        RecoveryTrigger::MemoryOverflow { .. } => "memory_overflow",
        RecoveryTrigger::SequenceGap { .. } => "sequence_gap",
        RecoveryTrigger::Manual { .. } => "manual",
        RecoveryTrigger::JisDenied { .. } => "jis_denied",
    }
}
