// ═══════════════════════════════════════════════════════════════
// LLM Memory Mapper — DIME Aperture voor AI Modellen
//
// Geïnspireerd door 3dfx Voodoo AGP Texture Aperture (1997):
//   GPU definieerde een "venster" in systeemgeheugen, textures
//   werden on-demand geladen via AGP bus. Dezelfde truc, maar
//   2026-stijl: AI-modellen tot 48GB+ over 10Gbps TCP.
//
// Architectuur:
//   ┌────────────────────────────────────────────────────────────┐
//   │  Ollama / llama.cpp / vLLM                                │
//   │  mmap("model.gguf") → ziet 48GB aaneengesloten RAM       │
//   └──────────────────────┬─────────────────────────────────────┘
//                          │ page fault op unmapped block
//   ┌──────────────────────▼─────────────────────────────────────┐
//   │  LLM Memory Mapper — DIME Aperture                        │
//   │                                                            │
//   │  Block Status:                                             │
//   │    Unmapped  → spaceholder, weet hash+size maar geen data  │
//   │    Loading   → MUX fetch in progress                       │
//   │    Resident  → data in RAM, app kan lezen                  │
//   │    Evicted   → was resident, nu op remote (reclaimable)    │
//   │                                                            │
//   │  Aperture: [B0|B1|B2|B3|...|B23]  (24 × 2MB = 48GB)     │
//   │             ↓  ↓  ↓  ↓       ↓                           │
//   │            RAM A  RAM B  RAM A  ...  (RAID-0 stripe)      │
//   └────────────────────────────────────────────────────────────┘
//
// DIME = Direct Interface Memory Engine
//   - Aperture size: vooraf gedefinieerd (totale model grootte)
//   - Blocks starten als Unmapped (spaceholder met bekende hash)
//   - On-demand materialisatie via userfaultfd page fault
//   - Heartbeat blocks: periodieke placeholder-pings voor
//     connectie-warmte en latency monitoring
//
// "Het is eigenlijk DIME qua werking — die aperture die openstaat
//  en dan bekende filesizes erdoorheen jassen. 2026 AGP poort."
//                                                      — Jasper
// ═══════════════════════════════════════════════════════════════

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use serde::{Serialize, Deserialize};

use crate::ram_raid::{
    RamRaidController, RaidConfig, RaidStripe,
    RAID_BLOCK_SIZE,
};
use crate::cluster_mux::ClusterMuxClient;
use crate::cluster_transport::BlockStore;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Heartbeat interval: send a placeholder ping every N seconds
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Maximum aperture size: 256GB (128 × 2GB or 131072 × 2MB blocks)
pub const MAX_APERTURE_BYTES: usize = 256 * 1024 * 1024 * 1024;

/// Prefetch window: how many layers ahead to load
pub const DEFAULT_PREFETCH_WINDOW: usize = 4;

/// Minimum blocks that must stay resident (working set)
pub const MIN_RESIDENT_BLOCKS: usize = 4;

// ═══════════════════════════════════════════════════════════════
// Types — Aperture Block Status
// ═══════════════════════════════════════════════════════════════

/// Status of a block in the DIME aperture.
///
/// Like AGP texture slots: each block has a known size and hash,
/// but may or may not have data loaded in RAM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApertureStatus {
    /// Spaceholder — hash and size known, no data in RAM.
    /// The block exists in the manifest but hasn't been fetched yet.
    Unmapped {
        /// Expected SHA-256 hash of this block's content
        expected_hash: String,
        /// Size of this block in bytes
        size: usize,
    },

    /// Data is being fetched from remote right now.
    Loading,

    /// Data is in RAM, app can access it.
    Resident {
        /// When this block was loaded
        loaded_at_us: u64,
        /// How long the fetch took
        fetch_duration_us: u64,
    },

    /// Was resident, evicted to make room for other blocks.
    /// Can be re-fetched from remote.
    Evicted {
        /// When it was evicted
        evicted_at_us: u64,
    },
}

/// A single block in the model aperture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApertureBlock {
    /// Block index (0-based)
    pub index: usize,
    /// Which transformer layer this block belongs to (if known)
    pub layer: Option<usize>,
    /// RAID stripe: RAM A (local) or RAM B (remote)
    pub stripe: RaidStripe,
    /// Current status
    pub status: ApertureStatus,
    /// Content hash (SHA-256)
    pub content_hash: String,
    /// Block size in bytes
    pub size: usize,
    /// Access count for LRU
    pub access_count: u64,
    /// Tensor name/label (e.g. "layers.0.attention.wq.weight")
    pub label: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Model Manifest — describes the model's block layout
// ═══════════════════════════════════════════════════════════════

/// Describes a model file's block layout for aperture mapping.
///
/// Like a GGUF header but for our block-level granularity.
/// Created by scanning the model file once (or from .oom metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManifest {
    /// Model name (e.g. "llama-3.1-70B-Q4_K_M")
    pub name: String,
    /// Total model size in bytes
    pub total_bytes: usize,
    /// Number of transformer layers
    pub num_layers: usize,
    /// Block size used for chunking
    pub block_size: usize,
    /// Total number of blocks
    pub num_blocks: usize,
    /// Per-block metadata: (hash, size, layer_index, label)
    pub blocks: Vec<ManifestBlock>,
    /// Quantization format (e.g. "Q4_K_M", "Q8_0", "F16")
    pub quantization: String,
    /// Source format (e.g. "gguf", "safetensors", "oom")
    pub format: String,
}

/// Per-block entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBlock {
    /// Block index
    pub index: usize,
    /// SHA-256 hash of block content
    pub hash: String,
    /// Size in bytes (last block may be smaller)
    pub size: usize,
    /// Which transformer layer (None for embeddings/head)
    pub layer: Option<usize>,
    /// Tensor label
    pub label: Option<String>,
}

impl ModelManifest {
    /// Create a manifest by scanning a model file (or simulating one).
    ///
    /// In production: reads GGUF/safetensors header, chunks into blocks,
    /// hashes each block. For now: generates a synthetic manifest.
    pub fn synthetic(name: &str, total_bytes: usize, num_layers: usize, quantization: &str) -> Self {
        let block_size = RAID_BLOCK_SIZE;
        let num_blocks = (total_bytes + block_size - 1) / block_size;

        let blocks_per_layer = if num_layers > 0 { num_blocks / num_layers } else { num_blocks };

        let blocks: Vec<ManifestBlock> = (0..num_blocks).map(|i| {
            let size = if i == num_blocks - 1 {
                let remainder = total_bytes % block_size;
                if remainder > 0 { remainder } else { block_size }
            } else {
                block_size
            };

            // Deterministic synthetic hash based on block index
            let hash = format!("{:064x}", i as u128 * 0xDEADBEEF_CAFEBABE_u128);

            let layer = if num_layers > 0 && i < num_blocks {
                Some(i / blocks_per_layer.max(1))
            } else {
                None
            };

            let label = layer.map(|l| format!("layers.{}.block.{}", l, i % blocks_per_layer.max(1)));

            ManifestBlock { index: i, hash, size, layer, label }
        }).collect();

        Self {
            name: name.to_string(),
            total_bytes,
            num_layers,
            block_size,
            num_blocks,
            blocks,
            quantization: quantization.to_string(),
            format: "synthetic".to_string(),
        }
    }

    /// Blocks per transformer layer.
    pub fn blocks_per_layer(&self) -> usize {
        if self.num_layers > 0 {
            self.num_blocks / self.num_layers
        } else {
            self.num_blocks
        }
    }

    /// Get all block indices for a specific layer.
    pub fn layer_blocks(&self, layer: usize) -> Vec<usize> {
        self.blocks.iter()
            .filter(|b| b.layer == Some(layer))
            .map(|b| b.index)
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// LLM Memory Mapper — The DIME Aperture Controller
// ═══════════════════════════════════════════════════════════════

/// LLM Memory Mapper: maps AI models into virtual memory using
/// the DIME aperture pattern.
///
/// Like a 3dfx Voodoo AGP aperture but for transformer weights:
/// define the window size (model size), blocks start as Unmapped
/// spaceholders, and materialize on-demand via page faults.
pub struct LlmMemoryMapper {
    /// Model manifest (block layout, hashes, layers)
    pub manifest: ModelManifest,
    /// Aperture blocks (status tracking)
    pub aperture: Vec<ApertureBlock>,
    /// Underlying RAM RAID controller
    pub raid_controller: RamRaidController,
    /// MUX client for remote fetches
    pub mux_client: Option<Arc<ClusterMuxClient>>,
    /// Local block store (for RAM A blocks)
    pub local_store: Option<Arc<BlockStore>>,
    /// Tokio runtime handle
    pub runtime_handle: Option<tokio::runtime::Handle>,
    /// Prefetch window size
    pub prefetch_window: usize,
    /// Stats
    pub stats: MapperStats,
    /// Active flag
    pub active: AtomicBool,
    /// Start timestamp
    start_time: Instant,
}

/// Stats for the memory mapper.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MapperStats {
    /// Total page faults handled
    pub faults_handled: u64,
    /// Blocks materialized from remote
    pub blocks_materialized: u64,
    /// Blocks evicted to make room
    pub blocks_evicted: u64,
    /// Blocks prefetched ahead of time
    pub blocks_prefetched: u64,
    /// Cache hits (SHA-256 skipped)
    pub cache_hits: u64,
    /// Total bytes transferred from remote
    pub bytes_from_remote: u64,
    /// Total bytes served from local
    pub bytes_from_local: u64,
    /// Heartbeats sent
    pub heartbeats_sent: u64,
    /// Current layer being processed
    pub current_layer: usize,
    /// Layers fully loaded
    pub layers_complete: usize,
    /// Total materialization time (µs)
    pub total_materialize_us: u64,
    /// Average fault latency (µs)
    pub avg_fault_latency_us: u64,
}

impl LlmMemoryMapper {
    /// Create a new LLM Memory Mapper from a model manifest.
    ///
    /// All blocks start as `Unmapped` — spaceholders with known
    /// hash and size but no data in RAM.
    pub fn new(manifest: ModelManifest) -> Self {
        let num_blocks = manifest.num_blocks;

        // Create aperture blocks — all start Unmapped
        let aperture: Vec<ApertureBlock> = manifest.blocks.iter().map(|mb| {
            ApertureBlock {
                index: mb.index,
                layer: mb.layer,
                stripe: RaidStripe::from_block_index(mb.index),
                status: ApertureStatus::Unmapped {
                    expected_hash: mb.hash.clone(),
                    size: mb.size,
                },
                content_hash: mb.hash.clone(),
                size: mb.size,
                access_count: 0,
                label: mb.label.clone(),
            }
        }).collect();

        // Create underlying RAID controller
        let config = RaidConfig::new(
            num_blocks * manifest.block_size,
            &format!("llm:{}", manifest.name),
            "mapper.aint",
        );
        let raid_controller = RamRaidController::new(config);

        Self {
            manifest,
            aperture,
            raid_controller,
            mux_client: None,
            local_store: None,
            runtime_handle: None,
            prefetch_window: DEFAULT_PREFETCH_WINDOW,
            stats: MapperStats::default(),
            active: AtomicBool::new(true),
            start_time: Instant::now(),
        }
    }

    /// Attach MUX transport for remote block fetches (RAM B on DL360).
    pub fn with_mux_transport(mut self, client: Arc<ClusterMuxClient>, handle: tokio::runtime::Handle) -> Self {
        self.raid_controller = self.raid_controller.with_mux_transport(client.clone(), handle.clone());
        self.mux_client = Some(client);
        self.runtime_handle = Some(handle);
        self
    }

    /// Attach local block store (RAM A).
    pub fn with_local_store(mut self, store: Arc<BlockStore>) -> Self {
        self.raid_controller = self.raid_controller.with_local_block_store(store.clone());
        self.local_store = Some(store);
        self
    }

    /// Set prefetch window size.
    pub fn with_prefetch_window(mut self, window: usize) -> Self {
        self.prefetch_window = window;
        self
    }

    /// Set max resident blocks (physical RAM budget).
    pub fn with_ram_budget_blocks(mut self, max_blocks: usize) -> Self {
        self.raid_controller.config.max_resident_blocks = max_blocks;
        self
    }

    /// Set max resident blocks by bytes.
    pub fn with_ram_budget_bytes(self, bytes: usize) -> Self {
        let blocks = bytes / self.manifest.block_size;
        self.with_ram_budget_blocks(blocks.max(MIN_RESIDENT_BLOCKS))
    }

    // ═══════════════════════════════════════════════════════════
    // Aperture Operations
    // ═══════════════════════════════════════════════════════════

    /// How many blocks are currently Unmapped (spaceholders).
    pub fn unmapped_count(&self) -> usize {
        self.aperture.iter()
            .filter(|b| matches!(b.status, ApertureStatus::Unmapped { .. }))
            .count()
    }

    /// How many blocks are Resident (in RAM).
    pub fn resident_count(&self) -> usize {
        self.aperture.iter()
            .filter(|b| matches!(b.status, ApertureStatus::Resident { .. }))
            .count()
    }

    /// How many blocks have been evicted.
    pub fn evicted_count(&self) -> usize {
        self.aperture.iter()
            .filter(|b| matches!(b.status, ApertureStatus::Evicted { .. }))
            .count()
    }

    /// Percentage of the model that is materialized (Resident).
    pub fn materialized_pct(&self) -> f64 {
        if self.manifest.num_blocks == 0 { return 0.0; }
        self.resident_count() as f64 / self.manifest.num_blocks as f64 * 100.0
    }

    /// Materialize a single block: fetch from remote if needed.
    ///
    /// This is what happens when userfaultfd triggers a page fault:
    /// Unmapped → Loading → Resident
    pub fn materialize_block(&mut self, block_index: usize) -> MaterializeResult {
        if block_index >= self.aperture.len() {
            return MaterializeResult::OutOfRange;
        }

        let t0 = Instant::now();

        // Read block info upfront (copy what we need to avoid borrow issues)
        let status_tag = match &self.aperture[block_index].status {
            ApertureStatus::Resident { .. } => 0,
            ApertureStatus::Loading => 1,
            ApertureStatus::Unmapped { .. } => 2,
            ApertureStatus::Evicted { .. } => 3,
        };
        let stripe = self.aperture[block_index].stripe;
        let block_size = self.aperture[block_index].size;
        let layer = self.aperture[block_index].layer;

        match status_tag {
            0 => {
                // Already resident — just bump access count
                self.aperture[block_index].access_count += 1;
                MaterializeResult::AlreadyResident
            }
            1 => {
                MaterializeResult::InProgress
            }
            2 | 3 => {
                // Unmapped or Evicted → Loading → Resident
                self.aperture[block_index].status = ApertureStatus::Loading;

                // Use RAID controller to fetch/restore
                let _result = self.raid_controller.simulate_read(block_index);

                let elapsed_us = t0.elapsed().as_micros() as u64;
                let is_remote = matches!(stripe, RaidStripe::RamB);

                // Update aperture status
                self.aperture[block_index].status = ApertureStatus::Resident {
                    loaded_at_us: self.start_time.elapsed().as_micros() as u64,
                    fetch_duration_us: elapsed_us,
                };
                self.aperture[block_index].access_count += 1;

                // Update stats
                self.stats.faults_handled += 1;
                self.stats.blocks_materialized += 1;
                self.stats.total_materialize_us += elapsed_us;
                if is_remote {
                    self.stats.bytes_from_remote += block_size as u64;
                } else {
                    self.stats.bytes_from_local += block_size as u64;
                }
                self.stats.avg_fault_latency_us =
                    self.stats.total_materialize_us / self.stats.faults_handled;

                MaterializeResult::Loaded {
                    block_index,
                    source: if is_remote { BlockSource::RemoteRamB } else { BlockSource::LocalRamA },
                    duration_us: elapsed_us,
                    layer,
                }
            }
            _ => unreachable!(),
        }
    }

    /// Materialize an entire transformer layer.
    ///
    /// Loads all blocks belonging to the given layer, using batch
    /// fetch for remote blocks (pipelined).
    pub fn materialize_layer(&mut self, layer: usize) -> LayerResult {
        let t0 = Instant::now();

        let block_indices: Vec<usize> = self.manifest.layer_blocks(layer);
        if block_indices.is_empty() {
            return LayerResult {
                layer,
                blocks_loaded: 0,
                blocks_already_resident: 0,
                blocks_from_remote: 0,
                blocks_from_local: 0,
                duration_us: 0,
            };
        }

        let mut loaded = 0;
        let mut already = 0;
        let mut from_remote = 0;
        let mut from_local = 0;

        for &idx in &block_indices {
            match self.materialize_block(idx) {
                MaterializeResult::Loaded { source, .. } => {
                    loaded += 1;
                    match source {
                        BlockSource::RemoteRamB => from_remote += 1,
                        BlockSource::LocalRamA => from_local += 1,
                    }
                }
                MaterializeResult::AlreadyResident => already += 1,
                _ => {}
            }
        }

        self.stats.current_layer = layer;
        if loaded + already == block_indices.len() {
            self.stats.layers_complete += 1;
        }

        LayerResult {
            layer,
            blocks_loaded: loaded,
            blocks_already_resident: already,
            blocks_from_remote: from_remote,
            blocks_from_local: from_local,
            duration_us: t0.elapsed().as_micros() as u64,
        }
    }

    /// Prefetch upcoming layers while current layer is being processed.
    ///
    /// The LLM inference pattern: process layer N, prefetch N+1..N+W
    /// so data is already in RAM when the model needs it.
    pub fn prefetch_layers(&mut self, current_layer: usize) -> PrefetchResult {
        let t0 = Instant::now();
        let mut total_prefetched = 0;
        let mut layers_touched = 0;

        for layer in (current_layer + 1)..=(current_layer + self.prefetch_window) {
            if layer >= self.manifest.num_layers {
                break;
            }

            let block_indices: Vec<usize> = self.manifest.layer_blocks(layer);
            for &idx in &block_indices {
                if matches!(self.aperture.get(idx).map(|b| &b.status),
                    Some(ApertureStatus::Unmapped { .. }) | Some(ApertureStatus::Evicted { .. }))
                {
                    let _ = self.materialize_block(idx);
                    total_prefetched += 1;
                }
            }
            layers_touched += 1;
        }

        self.stats.blocks_prefetched += total_prefetched;

        PrefetchResult {
            layers_ahead: layers_touched,
            blocks_prefetched: total_prefetched as usize,
            duration_us: t0.elapsed().as_micros() as u64,
        }
    }

    /// Evict coldest blocks to make room for new data.
    ///
    /// Keeps at least `min_resident` blocks in RAM.
    pub fn evict_cold_blocks(&mut self, target_free: usize) -> usize {
        let mut evicted = 0;

        // Sort resident blocks by access count (ascending = coldest first)
        let mut resident_indices: Vec<usize> = self.aperture.iter()
            .filter(|b| matches!(b.status, ApertureStatus::Resident { .. }))
            .map(|b| b.index)
            .collect();

        resident_indices.sort_by_key(|&idx| self.aperture[idx].access_count);

        for idx in resident_indices {
            if evicted >= target_free {
                break;
            }
            if self.resident_count() <= MIN_RESIDENT_BLOCKS {
                break;
            }

            self.aperture[idx].status = ApertureStatus::Evicted {
                evicted_at_us: self.start_time.elapsed().as_micros() as u64,
            };
            self.raid_controller.proactive_evict();
            self.stats.blocks_evicted += 1;
            evicted += 1;
        }

        evicted
    }

    /// Simulate full LLM inference: process all layers sequentially
    /// with prefetch window.
    pub fn simulate_inference(&mut self) -> InferenceResult {
        let t0 = Instant::now();
        let mut layer_results = Vec::with_capacity(self.manifest.num_layers);

        for layer in 0..self.manifest.num_layers {
            // Materialize current layer
            let layer_result = self.materialize_layer(layer);

            // Prefetch upcoming layers
            let _prefetch = self.prefetch_layers(layer);

            // Evict old layers if needed (keep RAM budget)
            let max = self.raid_controller.config.max_resident_blocks;
            if self.resident_count() > max {
                self.evict_cold_blocks(self.resident_count() - max);
            }

            layer_results.push(layer_result);
        }

        let total_us = t0.elapsed().as_micros() as u64;

        InferenceResult {
            layers_processed: self.manifest.num_layers,
            total_blocks_loaded: self.stats.blocks_materialized,
            total_prefetched: self.stats.blocks_prefetched,
            total_evicted: self.stats.blocks_evicted,
            cache_hits: self.stats.cache_hits,
            bytes_transferred: self.stats.bytes_from_remote + self.stats.bytes_from_local,
            total_us,
            avg_layer_us: if self.manifest.num_layers > 0 {
                total_us / self.manifest.num_layers as u64
            } else { 0 },
            layer_results,
        }
    }

    /// Send a heartbeat block to keep the MUX connection warm.
    ///
    /// "Die lege blokken — is het niet handig om een bepaalde grote
    ///  nono blokken erdoor te gooien zo nu en dan als ping?"
    ///                                                    — Jasper
    ///
    /// Sends a small placeholder block to verify the connection is
    /// alive and measure current RTT.
    pub fn heartbeat(&mut self) -> Option<HeartbeatResult> {
        let client = self.mux_client.as_ref()?;

        // Use the MUX ping (lightweight, no data transfer)
        let rtt = crate::ram_raid::block_on_safe(client.ping());

        let rtt_us = match rtt {
            Ok(us) => us,
            Err(_) => return Some(HeartbeatResult {
                rtt_us: 0,
                connection_alive: false,
                timestamp_us: self.start_time.elapsed().as_micros() as u64,
            }),
        };

        self.stats.heartbeats_sent += 1;

        Some(HeartbeatResult {
            rtt_us,
            connection_alive: true,
            timestamp_us: self.start_time.elapsed().as_micros() as u64,
        })
    }

    /// Get a snapshot of the aperture state for display.
    pub fn aperture_map(&self) -> String {
        let mut map = String::new();
        for block in &self.aperture {
            let ch = match &block.status {
                ApertureStatus::Unmapped { .. } => '░', // spaceholder
                ApertureStatus::Loading => '▒',         // loading
                ApertureStatus::Resident { .. } => '█', // loaded
                ApertureStatus::Evicted { .. } => '·',  // evicted
            };
            map.push(ch);
        }
        map
    }

    /// Print a visual representation of the aperture.
    pub fn print_aperture(&self) {
        let map = self.aperture_map();
        let blocks_per_row = 64;

        println!("  Aperture: {} blocks, {:.1} MB total",
            self.manifest.num_blocks,
            self.manifest.total_bytes as f64 / 1_000_000.0);
        println!("  Legend: █=Resident ░=Unmapped ·=Evicted ▒=Loading");
        println!();

        for (i, chunk) in map.as_bytes().chunks(blocks_per_row).enumerate() {
            let start = i * blocks_per_row;
            let end = (start + chunk.len()).min(self.manifest.num_blocks);
            let s = std::str::from_utf8(chunk).unwrap_or("");
            println!("  {:>4}-{:<4} {}", start, end - 1, s);
        }

        println!();
        println!("  Resident: {} ({:.0}%)", self.resident_count(), self.materialized_pct());
        println!("  Unmapped: {}", self.unmapped_count());
        println!("  Evicted:  {}", self.evicted_count());
    }
}

// ═══════════════════════════════════════════════════════════════
// Result Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub enum MaterializeResult {
    /// Block was already in RAM
    AlreadyResident,
    /// Block is currently being loaded
    InProgress,
    /// Block was loaded successfully
    Loaded {
        block_index: usize,
        source: BlockSource,
        duration_us: u64,
        layer: Option<usize>,
    },
    /// Block index out of range
    OutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockSource {
    LocalRamA,
    RemoteRamB,
}

#[derive(Debug, Clone)]
pub struct LayerResult {
    pub layer: usize,
    pub blocks_loaded: usize,
    pub blocks_already_resident: usize,
    pub blocks_from_remote: usize,
    pub blocks_from_local: usize,
    pub duration_us: u64,
}

#[derive(Debug, Clone)]
pub struct PrefetchResult {
    pub layers_ahead: usize,
    pub blocks_prefetched: usize,
    pub duration_us: u64,
}

#[derive(Debug, Clone)]
pub struct HeartbeatResult {
    pub rtt_us: u64,
    pub connection_alive: bool,
    pub timestamp_us: u64,
}

#[derive(Debug, Clone)]
pub struct InferenceResult {
    pub layers_processed: usize,
    pub total_blocks_loaded: u64,
    pub total_prefetched: u64,
    pub total_evicted: u64,
    pub cache_hits: u64,
    pub bytes_transferred: u64,
    pub total_us: u64,
    pub avg_layer_us: u64,
    pub layer_results: Vec<LayerResult>,
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_manifest() {
        // Simulate a 48MB model (24 layers, ~2MB each)
        let manifest = ModelManifest::synthetic(
            "test-model-7B",
            48 * 1024 * 1024,  // 48MB
            24,                 // 24 layers
            "Q4_K_M",
        );

        assert_eq!(manifest.num_blocks, 24);
        assert_eq!(manifest.num_layers, 24);
        assert_eq!(manifest.blocks_per_layer(), 1);
        assert_eq!(manifest.block_size, RAID_BLOCK_SIZE);

        // Each layer should have blocks
        let layer0 = manifest.layer_blocks(0);
        assert!(!layer0.is_empty(), "Layer 0 should have blocks");
    }

    #[test]
    fn test_aperture_all_unmapped_initially() {
        let manifest = ModelManifest::synthetic("test", 16 * 1024 * 1024, 8, "Q4");
        let mapper = LlmMemoryMapper::new(manifest);

        assert_eq!(mapper.unmapped_count(), 8);
        assert_eq!(mapper.resident_count(), 0);
        assert_eq!(mapper.evicted_count(), 0);
        assert_eq!(mapper.materialized_pct(), 0.0);

        // All blocks should be Unmapped spaceholders
        for block in &mapper.aperture {
            assert!(matches!(block.status, ApertureStatus::Unmapped { .. }));
        }
    }

    #[test]
    fn test_materialize_single_block() {
        let manifest = ModelManifest::synthetic("test", 16 * 1024 * 1024, 8, "Q4");
        let mut mapper = LlmMemoryMapper::new(manifest);

        // Materialize block 0
        let result = mapper.materialize_block(0);
        assert!(matches!(result, MaterializeResult::Loaded { block_index: 0, .. }));

        assert_eq!(mapper.resident_count(), 1);
        assert_eq!(mapper.unmapped_count(), 7);
        assert_eq!(mapper.stats.blocks_materialized, 1);

        // Second access should be AlreadyResident
        let result2 = mapper.materialize_block(0);
        assert!(matches!(result2, MaterializeResult::AlreadyResident));
    }

    #[test]
    fn test_materialize_layer() {
        let manifest = ModelManifest::synthetic("test", 16 * 1024 * 1024, 8, "Q4");
        let mut mapper = LlmMemoryMapper::new(manifest);

        let result = mapper.materialize_layer(0);
        assert_eq!(result.layer, 0);
        assert!(result.blocks_loaded > 0 || result.blocks_already_resident > 0);
        assert_eq!(result.blocks_loaded + result.blocks_already_resident,
                   mapper.manifest.blocks_per_layer());
    }

    #[test]
    fn test_full_inference_simulation() {
        // 8-layer model, 16MB, 4 blocks max resident
        let manifest = ModelManifest::synthetic("small-test", 16 * 1024 * 1024, 8, "Q4");
        let mut mapper = LlmMemoryMapper::new(manifest);
        mapper = mapper.with_ram_budget_blocks(4);
        mapper = mapper.with_prefetch_window(2);

        let result = mapper.simulate_inference();

        assert_eq!(result.layers_processed, 8);
        assert!(result.total_blocks_loaded > 0);

        // With 4-block budget and 8 layers, we should have evictions
        // (depends on blocks_per_layer — with 1 block per layer and prefetch,
        // we'll exceed the budget)
    }

    #[test]
    fn test_aperture_map_display() {
        let manifest = ModelManifest::synthetic("test", 16 * 1024 * 1024, 8, "Q4");
        let mut mapper = LlmMemoryMapper::new(manifest);

        // All unmapped
        let map = mapper.aperture_map();
        assert_eq!(map.chars().filter(|&c| c == '░').count(), 8);

        // Materialize some
        mapper.materialize_block(0);
        mapper.materialize_block(3);
        let map = mapper.aperture_map();
        assert_eq!(map.chars().filter(|&c| c == '█').count(), 2);
        assert_eq!(map.chars().filter(|&c| c == '░').count(), 6);
    }

    #[test]
    fn test_out_of_range() {
        let manifest = ModelManifest::synthetic("test", 4 * 1024 * 1024, 2, "Q4");
        let mut mapper = LlmMemoryMapper::new(manifest);

        let result = mapper.materialize_block(999);
        assert!(matches!(result, MaterializeResult::OutOfRange));
    }

    #[test]
    fn test_prefetch_window() {
        let manifest = ModelManifest::synthetic("test", 16 * 1024 * 1024, 8, "Q4");
        let mut mapper = LlmMemoryMapper::new(manifest);
        mapper = mapper.with_prefetch_window(3);

        // Materialize layer 0, prefetch 1-3
        mapper.materialize_layer(0);
        let prefetch = mapper.prefetch_layers(0);

        assert!(prefetch.layers_ahead <= 3);
        assert!(prefetch.blocks_prefetched > 0);
        assert!(mapper.stats.blocks_prefetched > 0);
    }

    #[test]
    fn test_evict_cold_blocks() {
        let manifest = ModelManifest::synthetic("test", 16 * 1024 * 1024, 8, "Q4");
        let mut mapper = LlmMemoryMapper::new(manifest);

        // Materialize all 8 blocks
        for i in 0..8 {
            mapper.materialize_block(i);
        }
        assert_eq!(mapper.resident_count(), 8);

        // Evict 4 (keep MIN_RESIDENT_BLOCKS)
        let evicted = mapper.evict_cold_blocks(4);
        assert_eq!(evicted, 4);
        assert_eq!(mapper.resident_count(), 4);
        assert_eq!(mapper.evicted_count(), 4);
    }

    #[test]
    fn test_stripe_assignment() {
        let manifest = ModelManifest::synthetic("test", 16 * 1024 * 1024, 8, "Q4");
        let mapper = LlmMemoryMapper::new(manifest);

        // Even blocks → RAM A, odd → RAM B
        for block in &mapper.aperture {
            let expected = RaidStripe::from_block_index(block.index);
            assert_eq!(block.stripe, expected);
        }
    }

    #[test]
    fn test_large_model_aperture() {
        // Simulate 70B model: ~40GB at Q4_K_M
        let model_size = 40 * 1024 * 1024 * 1024_usize; // 40GB
        let manifest = ModelManifest::synthetic("llama-70B-Q4", model_size, 80, "Q4_K_M");

        assert_eq!(manifest.num_blocks, 20480); // 40GB / 2MB
        assert_eq!(manifest.blocks_per_layer(), 256); // 256 blocks per layer

        let mapper = LlmMemoryMapper::new(manifest);
        assert_eq!(mapper.unmapped_count(), 20480);
        assert_eq!(mapper.resident_count(), 0);

        // Aperture map should be all unmapped
        let map = mapper.aperture_map();
        assert_eq!(map.chars().count(), 20480);
    }
}
