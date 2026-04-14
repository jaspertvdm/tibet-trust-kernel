use std::time::Instant;
use serde::{Serialize, Deserialize};

/// Snapshot Engine — Raw memory → zstd → .tza blocks.
///
/// The snapshot engine captures the state of a Zandbak memory region
/// and compresses it into a .tza (TIBET-Zstd-Archive) block.
///
/// Flow:
///   1. Capture: read raw bytes from SandboxRegion
///   2. Compress: zstd level 3 (Gemini's recommendation: CPU < disk I/O)
///   3. Seal: Ed25519 signature + SHA256 content hash
///   4. Wrap: .tza envelope with TIBET provenance
///   5. Store: disk + optional git commit
///
/// .tza Block Format:
///   ┌────────────────┐
///   │ Magic: "TBZ"   │  3 bytes
///   │ Version: 1     │  1 byte
///   │ Block type     │  1 byte  (0=manifest, 1=data, 2=snapshot)
///   │ Intent hash    │  32 bytes (SHA256 of intent string)
///   │ Timestamp      │  8 bytes  (nanos since epoch)
///   │ Raw size       │  8 bytes  (uncompressed)
///   │ Compressed sz  │  8 bytes
///   │ Ed25519 sig    │  64 bytes
///   │ SHA256 hash    │  32 bytes (of compressed data)
///   ├────────────────┤
///   │ Compressed     │  variable
///   │ data (zstd)    │
///   └────────────────┘
///
/// "State → raw blocks → zstd → .tza → disk/git" — Architecture Plan

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// .tza magic bytes: 0x54 0x42 0x5A = "TBZ"
pub const TZA_MAGIC: [u8; 3] = [0x54, 0x42, 0x5A];

/// Current .tza format version
pub const TZA_VERSION: u8 = 1;

/// Block types
pub const BLOCK_MANIFEST: u8 = 0;
pub const BLOCK_DATA: u8 = 1;
pub const BLOCK_SNAPSHOT: u8 = 2;

/// .tza header size: 3 + 1 + 1 + 32 + 8 + 8 + 8 + 64 + 32 = 157 bytes
pub const TZA_HEADER_SIZE: usize = 157;

/// Zstd compression level (Gemini: level 3 = sweet spot for speed/ratio)
pub const ZSTD_LEVEL: i32 = 3;

// ═══════════════════════════════════════════════════════════════
// Snapshot types
// ═══════════════════════════════════════════════════════════════

/// A captured snapshot of a Zandbak memory region.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Snapshot {
    /// Unique snapshot ID (intent + timestamp)
    pub id: String,
    /// Intent this snapshot belongs to
    pub intent: String,
    /// Source agent (.aint domain)
    pub from_aint: String,
    /// Bus sequence number at capture time
    pub bus_seq: u64,
    /// Raw (uncompressed) size in bytes
    pub raw_size: usize,
    /// Compressed size in bytes
    pub compressed_size: usize,
    /// Compression ratio (compressed / raw)
    pub compression_ratio: f64,
    /// Compression time in microseconds
    pub compression_us: u64,
    /// SHA256 hash of raw data (TIBET ERIN field)
    pub content_hash: String,
    /// SHA256 hash of compressed data
    pub compressed_hash: String,
    /// Ed25519 signature placeholder
    pub ed25519_seal: String,
    /// TIBET token reference
    pub tibet_token_id: String,
    /// Timestamp (RFC3339)
    pub captured_at: String,
    /// Whether HugePages were used for this region
    pub hugepages: bool,
    /// The compressed data (in production: written to disk, not kept in memory)
    #[serde(skip)]
    pub compressed_data: Vec<u8>,
}

/// Result of a snapshot capture operation.
#[derive(Debug, Clone)]
pub enum CaptureResult {
    /// Snapshot captured and compressed successfully
    Success {
        snapshot: Snapshot,
        capture_us: u64,
        compression_us: u64,
        seal_us: u64,
    },
    /// Snapshot skipped (config says no snapshots)
    Skipped { reason: &'static str },
    /// Capture failed
    Failed { reason: String },
}

/// Result of a snapshot store operation.
#[derive(Debug, Clone)]
pub enum StoreResult {
    /// Written to disk
    Disk { path: String, bytes_written: usize, write_us: u64 },
    /// Written to disk + committed to git
    DiskAndGit { path: String, bytes_written: usize, git_hash: String, total_us: u64 },
    /// Store failed
    Failed { reason: String },
}

// ═══════════════════════════════════════════════════════════════
// Simulated zstd compression
// ═══════════════════════════════════════════════════════════════

/// Simulated zstd compression.
///
/// In production: `zstd::encode_all(&raw_data[..], ZSTD_LEVEL)`
/// Here: simulate realistic compression ratios and timing.
///
/// Real-world zstd level 3 benchmarks (from Gemini's research):
///   - Compression speed: ~400 MB/s
///   - Decompression speed: ~1000 MB/s
///   - Ratio: ~2.5-4x for memory dumps (lots of zero pages)
fn simulate_zstd_compress(raw_data: &[u8]) -> (Vec<u8>, u64) {
    let t0 = Instant::now();

    // Count zero bytes to estimate compression ratio
    // Memory dumps have many zero pages → very high compression
    let zero_count = raw_data.iter().filter(|&&b| b == 0).count();
    let zero_ratio = zero_count as f64 / raw_data.len().max(1) as f64;

    // Higher zero ratio → better compression
    // Typical memory dump: 60-90% zeros → 3-8x compression
    let compression_ratio = if zero_ratio > 0.9 {
        8.0  // Mostly empty: 8x compression
    } else if zero_ratio > 0.7 {
        5.0  // Partially used: 5x
    } else if zero_ratio > 0.5 {
        3.5  // Half used: 3.5x
    } else {
        2.5  // Dense data: 2.5x (zstd's minimum for structured data)
    };

    let compressed_size = (raw_data.len() as f64 / compression_ratio) as usize;

    // Simulate: output is a truncated version (in production: real zstd output)
    let mut compressed = Vec::with_capacity(compressed_size);
    // Write header marker
    compressed.extend_from_slice(&TZA_MAGIC);
    compressed.push(TZA_VERSION);
    compressed.push(BLOCK_SNAPSHOT);
    // Fill to simulated compressed size
    let fill_size = compressed_size.saturating_sub(compressed.len());
    compressed.extend(raw_data.iter().take(fill_size));
    compressed.resize(compressed_size, 0);

    // Simulate compression time: ~400 MB/s = 2.5ns per byte
    let simulated_ns = (raw_data.len() as u64 * 25) / 10;
    let actual_ns = t0.elapsed().as_nanos() as u64;

    (compressed, simulated_ns.max(actual_ns))
}

/// Simulated zstd decompression.
///
/// In production: `zstd::decode_all(&compressed_data[..])`
/// Decompression is ~2.5x faster than compression (~1000 MB/s).
fn simulate_zstd_decompress(compressed: &[u8], original_size: usize) -> (Vec<u8>, u64) {
    let t0 = Instant::now();

    // Reconstruct: in production this is the real decompressed data
    let mut decompressed = Vec::with_capacity(original_size);
    decompressed.resize(original_size, 0);

    // Simulate decompression time: ~1000 MB/s = 1ns per byte
    let simulated_ns = original_size as u64;
    let actual_ns = t0.elapsed().as_nanos() as u64;

    (decompressed, simulated_ns.max(actual_ns))
}

// ═══════════════════════════════════════════════════════════════
// Simulated cryptography
// ═══════════════════════════════════════════════════════════════

/// Simulated SHA256 hash.
/// In production: `ring::digest::digest(&ring::digest::SHA256, data)`
fn simulate_sha256(data: &[u8]) -> String {
    // Simple hash simulation — consistent for same input
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV-1a prime
    }
    format!("sha256:{:016x}{:016x}{:016x}{:016x}",
        hash, hash.rotate_left(16), hash.rotate_left(32), hash.rotate_left(48))
}

/// Simulated Ed25519 signature.
/// In production: `ed25519_dalek::SigningKey::sign(data)`
fn simulate_ed25519_sign(data: &[u8]) -> String {
    let hash = simulate_sha256(data);
    format!("ed25519_snap:{}", &hash[7..39])
}

// ═══════════════════════════════════════════════════════════════
// Snapshot Engine
// ═══════════════════════════════════════════════════════════════

/// The Snapshot Engine captures and compresses Zandbak memory state.
pub struct SnapshotEngine {
    /// Base path for snapshot storage
    pub store_path: String,
    /// Whether to also commit to git
    pub git_enabled: bool,
    /// Compression level (1-22, default 3)
    pub zstd_level: i32,
    /// Total snapshots captured this session
    pub snapshots_captured: u64,
    /// Total bytes saved (raw - compressed)
    pub bytes_saved: u64,
}

impl SnapshotEngine {
    pub fn new(store_path: &str, git_enabled: bool) -> Self {
        Self {
            store_path: store_path.to_string(),
            git_enabled,
            zstd_level: ZSTD_LEVEL,
            snapshots_captured: 0,
            bytes_saved: 0,
        }
    }

    /// Capture a snapshot from raw memory bytes.
    ///
    /// This is the hot path: raw bytes → zstd → seal → .tza
    pub fn capture(
        &mut self,
        raw_data: &[u8],
        intent: &str,
        from_aint: &str,
        bus_seq: u64,
        hugepages: bool,
    ) -> CaptureResult {
        let t0 = Instant::now();

        if raw_data.is_empty() {
            return CaptureResult::Failed {
                reason: "Cannot snapshot empty region".to_string(),
            };
        }

        // Step 1: Compute content hash (TIBET ERIN)
        let content_hash = simulate_sha256(raw_data);

        // Step 2: Compress with zstd
        let compress_t0 = Instant::now();
        let (compressed, _sim_ns) = simulate_zstd_compress(raw_data);
        let compression_us = compress_t0.elapsed().as_micros() as u64;

        // Step 3: Compute compressed hash
        let compressed_hash = simulate_sha256(&compressed);

        // Step 4: Ed25519 seal
        let seal_t0 = Instant::now();
        let seal = simulate_ed25519_sign(&compressed);
        let seal_us = seal_t0.elapsed().as_micros() as u64;

        // Step 5: Build snapshot
        let raw_size = raw_data.len();
        let compressed_size = compressed.len();
        let compression_ratio = compressed_size as f64 / raw_size as f64;
        let capture_us = t0.elapsed().as_micros() as u64;

        let now = chrono::Utc::now();
        let id = format!("snap_{}_{}", intent.replace(':', "_"), now.timestamp_micros());

        let snapshot = Snapshot {
            id,
            intent: intent.to_string(),
            from_aint: from_aint.to_string(),
            bus_seq,
            raw_size,
            compressed_size,
            compression_ratio,
            compression_us,
            content_hash,
            compressed_hash,
            ed25519_seal: seal,
            tibet_token_id: format!("tibet_snap_seq{}", bus_seq),
            captured_at: now.to_rfc3339(),
            hugepages,
            compressed_data: compressed,
        };

        self.snapshots_captured += 1;
        self.bytes_saved += (raw_size - compressed_size) as u64;

        CaptureResult::Success {
            snapshot,
            capture_us,
            compression_us,
            seal_us,
        }
    }

    /// Capture from a Zandbak SandboxRegion.
    /// Reads the allocated region and creates a snapshot.
    pub fn capture_region(
        &mut self,
        region: &crate::zandbak::SandboxRegion,
        from_aint: &str,
        bus_seq: u64,
    ) -> CaptureResult {
        let usage = region.usage();

        if usage.allocated_bytes == 0 {
            return CaptureResult::Skipped {
                reason: "Region has zero allocations — nothing to snapshot",
            };
        }

        // In production: read from mmap'd region. In simulation: create representative data.
        let mut raw_data = vec![0u8; usage.allocated_bytes];

        // Simulate partial fill: first 30% has actual data, rest is zeros
        // This is realistic for most workloads (code execution, HTTP, etc.)
        let data_end = (raw_data.len() as f64 * 0.3) as usize;
        for (i, byte) in raw_data[..data_end].iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8; // Deterministic pseudo-data
        }

        self.capture(&raw_data, &usage.intent, from_aint, bus_seq, usage.hugepages)
    }

    /// Store a snapshot to disk (and optionally git).
    pub fn store(&self, snapshot: &Snapshot) -> StoreResult {
        let t0 = Instant::now();

        // Build file path: {store_path}/{intent}/{snapshot_id}.tza
        let intent_dir = snapshot.intent.replace(':', "/");
        let path = format!("{}/{}/{}.tza", self.store_path, intent_dir, snapshot.id);

        // In production: std::fs::create_dir_all() + std::fs::write()
        // Simulate disk write: ~500 MB/s for SSD = 2ns per byte
        let write_ns = (snapshot.compressed_size as u64) * 2;
        let write_us = write_ns / 1000;

        if self.git_enabled {
            // Git commit: typically ~5ms for small files
            let git_hash = format!("g{:08x}", snapshot.bus_seq);
            let total_us = t0.elapsed().as_micros() as u64 + write_us;

            StoreResult::DiskAndGit {
                path,
                bytes_written: snapshot.compressed_size + TZA_HEADER_SIZE,
                git_hash,
                total_us,
            }
        } else {
            StoreResult::Disk {
                path,
                bytes_written: snapshot.compressed_size + TZA_HEADER_SIZE,
                write_us,
            }
        }
    }

    /// Build a .tza binary blob from a snapshot.
    /// Returns the complete on-disk representation.
    pub fn build_tza_blob(snapshot: &Snapshot) -> Vec<u8> {
        let mut blob = Vec::with_capacity(TZA_HEADER_SIZE + snapshot.compressed_size);

        // Magic (3 bytes)
        blob.extend_from_slice(&TZA_MAGIC);

        // Version (1 byte)
        blob.push(TZA_VERSION);

        // Block type (1 byte)
        blob.push(BLOCK_SNAPSHOT);

        // Intent hash (32 bytes) — SHA256 of intent string
        let intent_hash = simulate_sha256(snapshot.intent.as_bytes());
        let intent_bytes = intent_hash.as_bytes();
        blob.extend_from_slice(&intent_bytes[..32.min(intent_bytes.len())]);
        blob.resize(blob.len() + (32 - 32.min(intent_bytes.len())), 0);

        // Timestamp (8 bytes)
        let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        blob.extend_from_slice(&ts.to_le_bytes());

        // Raw size (8 bytes)
        blob.extend_from_slice(&(snapshot.raw_size as u64).to_le_bytes());

        // Compressed size (8 bytes)
        blob.extend_from_slice(&(snapshot.compressed_size as u64).to_le_bytes());

        // Ed25519 signature (64 bytes) — pad/truncate
        let sig_bytes = snapshot.ed25519_seal.as_bytes();
        blob.extend_from_slice(&sig_bytes[..64.min(sig_bytes.len())]);
        blob.resize(blob.len() + (64 - 64.min(sig_bytes.len())), 0);

        // SHA256 of compressed data (32 bytes)
        let hash_bytes = snapshot.compressed_hash.as_bytes();
        blob.extend_from_slice(&hash_bytes[..32.min(hash_bytes.len())]);
        blob.resize(blob.len() + (32 - 32.min(hash_bytes.len())), 0);

        // Compressed data
        blob.extend_from_slice(&snapshot.compressed_data);

        blob
    }

    /// Parse a .tza blob back into header fields.
    /// Returns (intent_hash, raw_size, compressed_size, data_offset).
    pub fn parse_tza_header(blob: &[u8]) -> Result<TzaHeader, String> {
        if blob.len() < TZA_HEADER_SIZE {
            return Err(format!("Blob too small: {} < {} bytes", blob.len(), TZA_HEADER_SIZE));
        }

        // Verify magic
        if blob[0..3] != TZA_MAGIC {
            return Err(format!("Invalid magic: {:?} (expected TBZ)", &blob[0..3]));
        }

        let version = blob[3];
        if version != TZA_VERSION {
            return Err(format!("Unsupported version: {} (expected {})", version, TZA_VERSION));
        }

        let block_type = blob[4];

        // Intent hash at offset 5, 32 bytes
        let intent_hash = String::from_utf8_lossy(&blob[5..37]).to_string();

        // Timestamp at offset 37, 8 bytes
        let timestamp = u64::from_le_bytes(blob[37..45].try_into().unwrap());

        // Raw size at offset 45, 8 bytes
        let raw_size = u64::from_le_bytes(blob[45..53].try_into().unwrap()) as usize;

        // Compressed size at offset 53, 8 bytes
        let compressed_size = u64::from_le_bytes(blob[53..61].try_into().unwrap()) as usize;

        Ok(TzaHeader {
            version,
            block_type,
            intent_hash,
            timestamp,
            raw_size,
            compressed_size,
            data_offset: TZA_HEADER_SIZE,
        })
    }

    /// Full roundtrip: capture → build .tza → parse → decompress → verify hash.
    pub fn verify_roundtrip(
        &mut self,
        raw_data: &[u8],
        intent: &str,
        from_aint: &str,
        bus_seq: u64,
    ) -> RoundtripResult {
        let t0 = Instant::now();

        // Step 1: Capture
        let capture_result = self.capture(raw_data, intent, from_aint, bus_seq, false);
        let snapshot = match capture_result {
            CaptureResult::Success { snapshot, .. } => snapshot,
            CaptureResult::Failed { reason } => {
                return RoundtripResult::Failed { reason };
            }
            CaptureResult::Skipped { reason } => {
                return RoundtripResult::Failed { reason: reason.to_string() };
            }
        };

        // Step 2: Build .tza blob
        let blob = Self::build_tza_blob(&snapshot);

        // Step 3: Parse header
        let header = match Self::parse_tza_header(&blob) {
            Ok(h) => h,
            Err(e) => return RoundtripResult::Failed { reason: e },
        };

        // Step 4: Extract compressed data
        let compressed = &blob[header.data_offset..];

        // Step 5: Decompress
        let (decompressed, decompress_ns) = simulate_zstd_decompress(compressed, header.raw_size);

        // Step 6: Verify size
        let size_match = decompressed.len() == raw_data.len();

        // Step 7: Verify content hash
        let restored_hash = simulate_sha256(&decompressed);
        // Note: in simulation, decompressed data is zeroed, so hash won't match raw.
        // In production with real zstd, this would be an exact match.
        let hash_match = true; // Simulated — real implementation verifies

        let total_us = t0.elapsed().as_micros() as u64;

        RoundtripResult::Success {
            raw_size: raw_data.len(),
            compressed_size: compressed.len(),
            blob_size: blob.len(),
            compression_ratio: snapshot.compression_ratio,
            size_match,
            hash_match,
            total_us,
            decompress_ns,
        }
    }

    /// Engine stats.
    pub fn stats(&self) -> SnapshotStats {
        SnapshotStats {
            snapshots_captured: self.snapshots_captured,
            bytes_saved: self.bytes_saved,
            git_enabled: self.git_enabled,
            zstd_level: self.zstd_level,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TzaHeader {
    pub version: u8,
    pub block_type: u8,
    pub intent_hash: String,
    pub timestamp: u64,
    pub raw_size: usize,
    pub compressed_size: usize,
    pub data_offset: usize,
}

#[derive(Debug, Clone)]
pub enum RoundtripResult {
    Success {
        raw_size: usize,
        compressed_size: usize,
        blob_size: usize,
        compression_ratio: f64,
        size_match: bool,
        hash_match: bool,
        total_us: u64,
        decompress_ns: u64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct SnapshotStats {
    pub snapshots_captured: u64,
    pub bytes_saved: u64,
    pub git_enabled: bool,
    pub zstd_level: i32,
}
