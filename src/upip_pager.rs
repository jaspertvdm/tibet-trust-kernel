use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use serde::{Serialize, Deserialize};

/// UPIP Pager — Cryptographisch Veilige Applicatie-Level Paging
///
/// Wat Linux swap doet op OS-niveau, doet UPIP op applicatieniveau:
///   - Chunks uit RAM trekken wanneer de Zandbak vol raakt
///   - Elke chunk voorzien van TIBET-handtekening (Ed25519 + SHA256)
///   - Veilig parkeren als Fork Tokens in Archivaris of Git Store
///   - Bij hergebruik: verificatie + SNAFT check + terug in RAM
///
/// Waarom niet gewoon Linux swap?
///   1. Linux swap is ONVEILIG: plaintext op disk, malware kan lezen/manipuleren
///   2. Linux swap is ONBEWEZEN: geen audit trail, geen integriteitscheck
///   3. Linux swap is ONCONTROLEERBAAR: kernel beslist, niet de applicatie
///   4. Linux swap is LANGZAAM: page faults → kernel trap → disk I/O → context switch
///
/// UPIP Pager:
///   1. VEILIG: elke chunk is Ed25519-gesigned + zstd-compressed
///   2. BEWEZEN: TIBET token per chunk, volledige audit trail
///   3. CONTROLEERBAAR: intent-based budgets, SNAFT per chunk
///   4. SNEL: proactief pagen vóór het plafond, geen page faults
///
/// Flow — Lage Drukte (past in RAM):
///   ┌─────────────────────────────────────────┐
///   │  Taak → Zandbak (512MB) → Klaar         │
///   │  Geen UPIP nodig. Snelste pad.          │
///   └─────────────────────────────────────────┘
///
/// Flow — Hoge Drukte (overschrijdt RAM):
///   ┌─────────────────────────────────────────────────────────┐
///   │  Taak start → Zandbak bereikt 80% budget               │
///   │                                                         │
///   │  ┌─── UPIP Pager activeert ───┐                        │
///   │  │                             │                        │
///   │  │  Chunk 1 (coldest data)     │                        │
///   │  │    → zstd compress          │                        │
///   │  │    → SHA256 hash            │                        │
///   │  │    → Ed25519 sign           │                        │
///   │  │    → Fork Token mint        │                        │
///   │  │    → Archivaris store       │                        │
///   │  │    → RAM vrijgeven          │                        │
///   │  │                             │                        │
///   │  │  Chunk 2 (next coldest)     │                        │
///   │  │    → zelfde pipeline        │                        │
///   │  │                             │                        │
///   │  └─────────────────────────────┘                        │
///   │                                                         │
///   │  Zandbak heeft weer ruimte → taak gaat door            │
///   │                                                         │
///   │  ┌─── Chunk nodig? Page In ────┐                       │
///   │  │                              │                       │
///   │  │  Fork Token ophalen          │                       │
///   │  │    → Archivaris/Git lookup   │                       │
///   │  │    → Ed25519 verify          │                       │
///   │  │    → SHA256 verify           │                       │
///   │  │    → SNAFT re-check          │                       │
///   │  │    → zstd decompress         │                       │
///   │  │    → Inject in Zandbak       │                       │
///   │  │    → Fork Token consumed     │                       │
///   │  │                              │                       │
///   │  └──────────────────────────────┘                       │
///   │                                                         │
///   │  Alle chunks verwerkt → resultaten assembleren          │
///   └─────────────────────────────────────────────────────────┘
///
/// Multi-Kernel Continuation:
///   Chunks kunnen zelfs naar een ANDERE kernel verhuizen!
///   Fork Token van Kernel A → Bus → Kernel B → andere machine
///   = Gedistribueerde paging met cryptografisch bewijs
///
/// "Paging/Swapping, maar dan op Applicatie-Niveau en Cryptografisch Veilig" — Jasper

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Default chunk size: 2MB (matches HugePage size for alignment)
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Pressure threshold: start paging when Zandbak reaches this % of budget
pub const PRESSURE_THRESHOLD_PCT: f64 = 80.0;

/// Critical threshold: aggressive paging
pub const CRITICAL_THRESHOLD_PCT: f64 = 95.0;

/// Maximum chunks that can be paged out simultaneously
pub const MAX_PAGED_CHUNKS: usize = 256;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// A Fork Token represents a chunk of memory that has been paged out.
/// Named "Fork" because it forks the execution state — the chunk can
/// continue its journey on any kernel that holds a valid token.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ForkToken {
    /// Unique token ID
    pub id: String,
    /// Chunk sequence number within this task
    pub chunk_seq: u64,
    /// Total chunks for this task (known after all chunks are created)
    pub total_chunks: Option<u64>,
    /// Intent this chunk belongs to
    pub intent: String,
    /// Source agent (.aint domain)
    pub from_aint: String,
    /// Bus sequence at time of page-out
    pub bus_seq: u64,
    /// Original offset in Zandbak memory region
    pub memory_offset: usize,
    /// Original size (uncompressed)
    pub raw_size: usize,
    /// Compressed size
    pub compressed_size: usize,
    /// SHA256 of raw chunk data (integrity check on page-in)
    pub content_hash: String,
    /// SHA256 of compressed data
    pub compressed_hash: String,
    /// Ed25519 signature of (content_hash + compressed_hash + intent + seq)
    pub ed25519_seal: String,
    /// TIBET token reference
    pub tibet_token_id: String,
    /// Where this chunk is stored
    pub storage: ChunkStorage,
    /// State of this token
    pub state: ForkTokenState,
    /// Timestamp of creation
    pub created_at: String,
    /// Access count (LRU tracking)
    pub access_count: u64,
    /// Last access time (nanos since epoch)
    pub last_access_ns: u64,
}

/// Where a paged-out chunk lives.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ChunkStorage {
    /// In Archivaris append-only store (fast, local)
    Archivaris { path: String },
    /// In Git store (slower, distributed)
    GitStore { commit_hash: String },
    /// On another kernel (Multi-Kernel Continuation!)
    RemoteKernel { kernel_id: String, endpoint: String },
    /// Still in transit (being paged out)
    InTransit,
}

/// Lifecycle of a Fork Token.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ForkTokenState {
    /// Just created, chunk data is being compressed/signed
    Creating,
    /// Chunk is safely stored, RAM has been freed
    PagedOut,
    /// Chunk is being loaded back into RAM
    PagingIn,
    /// Chunk is back in RAM, token can be consumed
    PagedIn,
    /// Token consumed (chunk processed and no longer needed)
    Consumed,
    /// Token invalid (verification failed on page-in)
    Invalid { reason: String },
}

/// Memory pressure level — determines paging aggressiveness.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PressureLevel {
    /// Under 80%: no paging needed
    Normal { utilization_pct: f64 },
    /// 80-95%: start paging coldest chunks
    Elevated { utilization_pct: f64, chunks_to_free: usize },
    /// 95%+: aggressive paging, page everything non-essential
    Critical { utilization_pct: f64, chunks_to_free: usize },
    /// 100%: budget exhausted, must page before any new allocation
    Exhausted { over_budget_bytes: usize },
}

/// Result of a page-out operation.
#[derive(Debug, Clone)]
pub enum PageOutResult {
    /// Chunk successfully paged out
    Success {
        token: ForkToken,
        bytes_freed: usize,
        compress_us: u64,
        seal_us: u64,
        store_us: u64,
        total_us: u64,
    },
    /// Page-out not needed (pressure is normal)
    NotNeeded { pressure: PressureLevel },
    /// Page-out failed
    Failed { reason: String },
}

/// Result of a page-in operation.
#[derive(Debug, Clone)]
pub enum PageInResult {
    /// Chunk successfully paged in
    Success {
        token_id: String,
        bytes_restored: usize,
        memory_offset: usize,
        verify_us: u64,
        decompress_us: u64,
        inject_us: u64,
        total_us: u64,
    },
    /// Verification failed — chunk was tampered with!
    IntegrityViolation {
        token_id: String,
        expected_hash: String,
        actual_hash: String,
    },
    /// Token not found
    TokenNotFound { token_id: String },
    /// Token already consumed
    AlreadyConsumed { token_id: String },
}

/// Result of assembling all chunks back together.
#[derive(Debug, Clone)]
pub enum AssembleResult {
    /// All chunks assembled successfully
    Complete {
        total_chunks: usize,
        total_bytes: usize,
        total_us: u64,
        all_verified: bool,
    },
    /// Some chunks missing
    Incomplete {
        present: usize,
        missing: Vec<u64>,  // Missing chunk_seq numbers
    },
    /// Integrity violation during assembly
    IntegrityFailed {
        failed_chunk: u64,
        reason: String,
    },
}

// ═══════════════════════════════════════════════════════════════
// Simulated crypto (same as snapshot.rs)
// ═══════════════════════════════════════════════════════════════

fn simulate_sha256(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("sha256:{:016x}{:016x}{:016x}{:016x}",
        hash, hash.rotate_left(16), hash.rotate_left(32), hash.rotate_left(48))
}

fn simulate_ed25519_sign(data: &[u8]) -> String {
    let hash = simulate_sha256(data);
    format!("ed25519_fork:{}", &hash[7..39])
}

fn simulate_zstd_compress(data: &[u8]) -> (Vec<u8>, u64) {
    let t0 = Instant::now();

    let zero_count = data.iter().filter(|&&b| b == 0).count();
    let zero_ratio = zero_count as f64 / data.len().max(1) as f64;

    let ratio = if zero_ratio > 0.9 { 8.0 }
        else if zero_ratio > 0.7 { 5.0 }
        else if zero_ratio > 0.5 { 3.5 }
        else { 2.5 };

    let compressed_size = (data.len() as f64 / ratio) as usize;
    let mut compressed = vec![0u8; compressed_size];
    let fill = compressed_size.min(data.len());
    compressed[..fill].copy_from_slice(&data[..fill]);

    let ns = (data.len() as u64 * 25) / 10;
    (compressed, ns.max(t0.elapsed().as_nanos() as u64))
}

fn simulate_zstd_decompress(compressed_size: usize, original_size: usize) -> u64 {
    // ~1000 MB/s = 1ns per byte
    original_size as u64
}

// ═══════════════════════════════════════════════════════════════
// UPIP Pager
// ═══════════════════════════════════════════════════════════════

/// The UPIP Pager manages application-level paging with cryptographic safety.
pub struct UpipPager {
    /// Active fork tokens (paged-out chunks)
    pub tokens: Vec<ForkToken>,
    /// Chunk size in bytes
    pub chunk_size: usize,
    /// Token ID counter
    next_token_id: AtomicU64,
    /// Stats
    pub pages_out: u64,
    pub pages_in: u64,
    pub bytes_paged_out: u64,
    pub bytes_paged_in: u64,
    pub integrity_violations: u64,
    /// Multi-kernel continuation counter
    pub remote_continuations: u64,
}

impl UpipPager {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            tokens: Vec::new(),
            chunk_size,
            next_token_id: AtomicU64::new(0),
            pages_out: 0,
            pages_in: 0,
            bytes_paged_out: 0,
            bytes_paged_in: 0,
            integrity_violations: 0,
            remote_continuations: 0,
        }
    }

    pub fn with_default_chunk_size() -> Self {
        Self::new(DEFAULT_CHUNK_SIZE)
    }

    /// Check memory pressure against Zandbak budget.
    pub fn check_pressure(&self, allocated: usize, budget: usize) -> PressureLevel {
        let utilization = (allocated as f64 / budget as f64) * 100.0;

        if utilization >= 100.0 {
            PressureLevel::Exhausted {
                over_budget_bytes: allocated - budget,
            }
        } else if utilization >= CRITICAL_THRESHOLD_PCT {
            let target_util = PRESSURE_THRESHOLD_PCT / 100.0;
            let target_bytes = (budget as f64 * target_util) as usize;
            let to_free = allocated.saturating_sub(target_bytes);
            let chunks = (to_free + self.chunk_size - 1) / self.chunk_size;
            PressureLevel::Critical {
                utilization_pct: utilization,
                chunks_to_free: chunks,
            }
        } else if utilization >= PRESSURE_THRESHOLD_PCT {
            let target_util = 0.7; // Page down to 70%
            let target_bytes = (budget as f64 * target_util) as usize;
            let to_free = allocated.saturating_sub(target_bytes);
            let chunks = (to_free + self.chunk_size - 1) / self.chunk_size;
            PressureLevel::Elevated {
                utilization_pct: utilization,
                chunks_to_free: chunks,
            }
        } else {
            PressureLevel::Normal {
                utilization_pct: utilization,
            }
        }
    }

    /// Page out a chunk of memory.
    ///
    /// Takes raw bytes from the Zandbak, compresses+signs them,
    /// and returns a Fork Token that can be used to page them back in.
    pub fn page_out(
        &mut self,
        chunk_data: &[u8],
        memory_offset: usize,
        intent: &str,
        from_aint: &str,
        bus_seq: u64,
    ) -> PageOutResult {
        let t0 = Instant::now();

        if chunk_data.is_empty() {
            return PageOutResult::Failed {
                reason: "Cannot page out empty chunk".to_string(),
            };
        }

        if self.tokens.len() >= MAX_PAGED_CHUNKS {
            return PageOutResult::Failed {
                reason: format!("Max paged chunks reached ({})", MAX_PAGED_CHUNKS),
            };
        }

        // Step 1: Compress
        let compress_t0 = Instant::now();
        let (compressed, _) = simulate_zstd_compress(chunk_data);
        let compress_us = compress_t0.elapsed().as_micros() as u64;

        // Step 2: Hash
        let content_hash = simulate_sha256(chunk_data);
        let compressed_hash = simulate_sha256(&compressed);

        // Step 3: Sign
        let seal_t0 = Instant::now();
        let seal_data = format!("{}:{}:{}:{}", content_hash, compressed_hash, intent, bus_seq);
        let seal = simulate_ed25519_sign(seal_data.as_bytes());
        let seal_us = seal_t0.elapsed().as_micros() as u64;

        // Step 4: Store (simulate Archivaris write)
        let store_t0 = Instant::now();
        let token_id_num = self.next_token_id.fetch_add(1, Ordering::SeqCst);
        let token_id = format!("upip_fork_{}_{}", intent.replace(':', "_"), token_id_num);

        let store_path = format!("/var/lib/airlock/paged/{}/{}.chunk",
            intent.replace(':', "/"), token_id);
        let store_us = store_t0.elapsed().as_micros() as u64;

        let now = chrono::Utc::now();
        let token = ForkToken {
            id: token_id,
            chunk_seq: token_id_num,
            total_chunks: None, // Set when task completes
            intent: intent.to_string(),
            from_aint: from_aint.to_string(),
            bus_seq,
            memory_offset,
            raw_size: chunk_data.len(),
            compressed_size: compressed.len(),
            content_hash,
            compressed_hash,
            ed25519_seal: seal,
            tibet_token_id: format!("tibet_upip_fork_{}", token_id_num),
            storage: ChunkStorage::Archivaris { path: store_path },
            state: ForkTokenState::PagedOut,
            created_at: now.to_rfc3339(),
            access_count: 0,
            last_access_ns: now.timestamp_nanos_opt().unwrap_or(0) as u64,
        };

        let total_us = t0.elapsed().as_micros() as u64;
        let bytes_freed = chunk_data.len();

        self.tokens.push(token.clone());
        self.pages_out += 1;
        self.bytes_paged_out += bytes_freed as u64;

        PageOutResult::Success {
            token,
            bytes_freed,
            compress_us,
            seal_us,
            store_us,
            total_us,
        }
    }

    /// Page in a chunk — verify integrity and return the data.
    ///
    /// In production: load from Archivaris/Git, verify Ed25519+SHA256,
    /// decompress, SNAFT re-check, inject into Zandbak.
    pub fn page_in(&mut self, token_id: &str) -> PageInResult {
        let t0 = Instant::now();

        // Find the token
        let token_idx = match self.tokens.iter().position(|t| t.id == token_id) {
            Some(idx) => idx,
            None => return PageInResult::TokenNotFound {
                token_id: token_id.to_string(),
            },
        };

        // Check state
        if self.tokens[token_idx].state == ForkTokenState::Consumed {
            return PageInResult::AlreadyConsumed {
                token_id: token_id.to_string(),
            };
        }

        self.tokens[token_idx].state = ForkTokenState::PagingIn;

        // Step 1: Verify Ed25519 signature
        let verify_t0 = Instant::now();
        // In production: ed25519_dalek::VerifyingKey::verify(&sig, &data)
        let seal_data = format!("{}:{}:{}:{}",
            self.tokens[token_idx].content_hash,
            self.tokens[token_idx].compressed_hash,
            self.tokens[token_idx].intent,
            self.tokens[token_idx].bus_seq);
        let expected_seal = simulate_ed25519_sign(seal_data.as_bytes());
        let seal_valid = self.tokens[token_idx].ed25519_seal == expected_seal;
        let verify_us = verify_t0.elapsed().as_micros() as u64;

        if !seal_valid {
            self.tokens[token_idx].state = ForkTokenState::Invalid {
                reason: "Ed25519 signature mismatch".to_string(),
            };
            self.integrity_violations += 1;
            return PageInResult::IntegrityViolation {
                token_id: token_id.to_string(),
                expected_hash: expected_seal,
                actual_hash: self.tokens[token_idx].ed25519_seal.clone(),
            };
        }

        // Step 2: Load + decompress
        let decompress_t0 = Instant::now();
        let _decompress_ns = simulate_zstd_decompress(
            self.tokens[token_idx].compressed_size,
            self.tokens[token_idx].raw_size,
        );
        let decompress_us = decompress_t0.elapsed().as_micros() as u64;

        // Step 3: Verify content hash
        // In production: SHA256(decompressed) == token.content_hash
        // Simulated: always passes

        // Step 4: Inject into Zandbak
        let inject_t0 = Instant::now();
        // In production: memcpy(zandbak_ptr + offset, decompressed, size)
        let inject_us = inject_t0.elapsed().as_micros() as u64;

        let bytes_restored = self.tokens[token_idx].raw_size;
        let memory_offset = self.tokens[token_idx].memory_offset;

        // Update token state
        self.tokens[token_idx].state = ForkTokenState::PagedIn;
        self.tokens[token_idx].access_count += 1;
        self.tokens[token_idx].last_access_ns =
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

        let total_us = t0.elapsed().as_micros() as u64;
        self.pages_in += 1;
        self.bytes_paged_in += bytes_restored as u64;

        PageInResult::Success {
            token_id: token_id.to_string(),
            bytes_restored,
            memory_offset,
            verify_us,
            decompress_us,
            inject_us,
            total_us,
        }
    }

    /// Consume a token (chunk fully processed, no longer needed).
    pub fn consume(&mut self, token_id: &str) -> bool {
        if let Some(token) = self.tokens.iter_mut().find(|t| t.id == token_id) {
            token.state = ForkTokenState::Consumed;
            true
        } else {
            false
        }
    }

    /// Page out multiple chunks at once (bulk operation for high pressure).
    /// Splits `data` into chunks and pages each one out.
    pub fn page_out_bulk(
        &mut self,
        data: &[u8],
        base_offset: usize,
        intent: &str,
        from_aint: &str,
        bus_seq: u64,
    ) -> Vec<PageOutResult> {
        let mut results = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let chunk_end = (offset + self.chunk_size).min(data.len());
            let chunk = &data[offset..chunk_end];

            let result = self.page_out(
                chunk,
                base_offset + offset,
                intent,
                from_aint,
                bus_seq,
            );
            results.push(result);
            offset = chunk_end;
        }

        // Set total_chunks on all tokens from this bulk operation
        let total = results.len() as u64;
        let start_seq = self.next_token_id.load(Ordering::SeqCst) - total;
        for token in self.tokens.iter_mut() {
            if token.chunk_seq >= start_seq && token.total_chunks.is_none() {
                token.total_chunks = Some(total);
            }
        }

        results
    }

    /// Assemble all chunks for a task back together.
    /// Pages in all chunks in sequence order, verifies each one.
    pub fn assemble(&mut self, intent: &str, bus_seq: u64) -> AssembleResult {
        let t0 = Instant::now();

        // Find all tokens for this task
        let token_ids: Vec<String> = self.tokens.iter()
            .filter(|t| t.intent == intent && t.bus_seq == bus_seq
                && t.state != ForkTokenState::Consumed
                && !matches!(t.state, ForkTokenState::Invalid { .. }))
            .map(|t| t.id.clone())
            .collect();

        if token_ids.is_empty() {
            return AssembleResult::Incomplete {
                present: 0,
                missing: vec![0],
            };
        }

        let mut total_bytes = 0;
        let mut all_verified = true;

        for token_id in &token_ids {
            match self.page_in(token_id) {
                PageInResult::Success { bytes_restored, .. } => {
                    total_bytes += bytes_restored;
                    self.consume(token_id);
                }
                PageInResult::IntegrityViolation { .. } => {
                    all_verified = false;
                    // Find chunk_seq for error reporting
                    let chunk_seq = self.tokens.iter()
                        .find(|t| t.id == *token_id)
                        .map(|t| t.chunk_seq)
                        .unwrap_or(0);
                    return AssembleResult::IntegrityFailed {
                        failed_chunk: chunk_seq,
                        reason: "Integrity verification failed during assembly".to_string(),
                    };
                }
                _ => {}
            }
        }

        let total_us = t0.elapsed().as_micros() as u64;

        AssembleResult::Complete {
            total_chunks: token_ids.len(),
            total_bytes,
            total_us,
            all_verified,
        }
    }

    /// Prepare a Multi-Kernel Continuation — transfer a Fork Token to another kernel.
    /// The receiving kernel can page-in the chunk and continue processing.
    pub fn prepare_continuation(
        &mut self,
        token_id: &str,
        target_kernel: &str,
        endpoint: &str,
    ) -> Option<ForkToken> {
        if let Some(token) = self.tokens.iter_mut().find(|t| t.id == token_id) {
            token.storage = ChunkStorage::RemoteKernel {
                kernel_id: target_kernel.to_string(),
                endpoint: endpoint.to_string(),
            };
            self.remote_continuations += 1;
            Some(token.clone())
        } else {
            None
        }
    }

    /// Find the coldest (least recently accessed) chunks for eviction.
    /// Used by the pressure system to decide what to page out first.
    pub fn find_coldest_offsets(&self, region_allocated: usize, count: usize) -> Vec<(usize, usize)> {
        // Return (offset, size) pairs for the coldest memory regions
        // In production: track access patterns per page
        // In simulation: return evenly-spaced chunks from the end of allocation
        let mut offsets = Vec::new();
        let mut offset = region_allocated.saturating_sub(self.chunk_size * count);

        for _ in 0..count {
            if offset + self.chunk_size <= region_allocated {
                offsets.push((offset, self.chunk_size));
                offset += self.chunk_size;
            }
        }

        offsets
    }

    /// Active (paged-out) tokens count.
    pub fn active_tokens(&self) -> usize {
        self.tokens.iter()
            .filter(|t| t.state == ForkTokenState::PagedOut)
            .count()
    }

    /// Total bytes currently paged out.
    pub fn bytes_currently_paged(&self) -> usize {
        self.tokens.iter()
            .filter(|t| t.state == ForkTokenState::PagedOut)
            .map(|t| t.raw_size)
            .sum()
    }

    /// Pager stats.
    pub fn stats(&self) -> PagerStats {
        PagerStats {
            pages_out: self.pages_out,
            pages_in: self.pages_in,
            bytes_paged_out: self.bytes_paged_out,
            bytes_paged_in: self.bytes_paged_in,
            active_tokens: self.active_tokens(),
            bytes_currently_paged: self.bytes_currently_paged(),
            integrity_violations: self.integrity_violations,
            remote_continuations: self.remote_continuations,
            chunk_size: self.chunk_size,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PagerStats {
    pub pages_out: u64,
    pub pages_in: u64,
    pub bytes_paged_out: u64,
    pub bytes_paged_in: u64,
    pub active_tokens: usize,
    pub bytes_currently_paged: usize,
    pub integrity_violations: u64,
    pub remote_continuations: u64,
    pub chunk_size: usize,
}
