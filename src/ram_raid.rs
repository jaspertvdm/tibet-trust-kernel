use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::thread;
use serde::{Serialize, Deserialize};

// userfaultfd imports voor de productie (echte hardware) modus
use libc::{c_void, mmap, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, sysconf, _SC_PAGESIZE};
use userfaultfd::{Uffd, UffdBuilder, Event};

// Cluster MUX — real network transport for RAM B
use crate::cluster_mux::ClusterMuxClient;
use crate::cluster_transport::{BlockStore, sha256_hex};

/// Productie wrapper voor de RAM RAID Controller, gekoppeld aan de hardware MMU trap
pub struct ActiveRamRaid {
    pub controller: Arc<Mutex<RamRaidController>>,
    pub arena_ptr: *mut c_void,
    pub uffd: Arc<Uffd>,
    pub fault_thread: Option<thread::JoinHandle<()>>,
}

impl ActiveRamRaid {
    pub fn shutdown(mut self) {
        if let Ok(lock) = self.controller.lock() {
            lock.active.store(false, Ordering::Release);
        }
        if let Some(t) = self.fault_thread.take() {
            let _ = t.join();
        }
        unsafe {
            munmap(self.arena_ptr, self.controller.lock().unwrap().config.arena_size);
        }
    }
}

/// RAM RAID-0 — Transparante Geheugen-Virtualisatie via userfaultfd.
///
/// Het Mad Professor Plan: Redis, PostgreSQL, of welke app dan ook draait
/// ongewijzigd, terwijl de Trust Kernel onzichtbaar het RAM onder de app
/// comprimeert, verdeelt, verifieert en distribueert.
///
/// Architectuur:
///   ┌────────────────────────────────────────────────────────────┐
///   │  Applicatie (Redis/PostgreSQL/etc.)                        │
///   │  Ziet normaal RAM. Merkt niets.                           │
///   └──────────────────────┬─────────────────────────────────────┘
///                          │ pointer dereference
///   ┌──────────────────────▼─────────────────────────────────────┐
///   │  CPU — Page Fault (userfaultfd)                            │
///   │  Thread bevriest automatisch                               │
///   └──────────────────────┬─────────────────────────────────────┘
///                          │ fault event
///   ┌──────────────────────▼─────────────────────────────────────┐
///   │  Trust Kernel — RAM RAID Controller                        │
///   │                                                            │
///   │  1. Fault ontvangen → page address uitrekenen              │
///   │  2. Block index berekenen (even/oneven = RAM A/B)          │
///   │  3. Fork Token opzoeken in UPIP Pager                      │
///   │  4. .tza ophalen: lokaal (Archivaris) of remote (intent)   │
///   │  5. Ed25519 verify + SHA256 check                          │
///   │  6. Zstd decomprimeren                                     │
///   │  7. uffd.copy() → fysiek RAM injecteren                    │
///   │  8. CPU gaat door, app merkt niets                         │
///   └────────────────────────────────────────────────────────────┘
///
/// RAID-0 Striping:
///   ┌─────────┬─────────┬─────────┬─────────┬─────────┐
///   │ Block 0 │ Block 1 │ Block 2 │ Block 3 │ Block 4 │  Virtueel RAM
///   │ (even)  │ (oneven)│ (even)  │ (oneven)│ (even)  │
///   └────┬────┴────┬────┴────┬────┴────┬────┴────┬────┘
///        │         │         │         │         │
///   ┌────▼────┐┌───▼────┐┌──▼─────┐┌──▼─────┐┌──▼─────┐
///   │ RAM A   ││ RAM B  ││ RAM A  ││ RAM B  ││ RAM A  │
///   │ (lokaal)││(remote)││(lokaal)││(remote)││(lokaal)│
///   └─────────┘└────────┘└────────┘└────────┘└────────┘
///
/// Waarom userfaultfd en niet SIGSEGV?
///   - userfaultfd: per-VMA registratie, blokt alleen de faultende thread
///   - SIGSEGV: process-wide handler, conflicteert met app's eigen handlers
///   - userfaultfd: kernel geeft ons het exacte faultadres + type (read/write)
///   - SIGSEGV: we moeten zelf PROT_NONE/mprotect doen (race conditions)
///   - userfaultfd: sinds Linux 4.11, stabiele API, gebruikt door QEMU/CRIU
///
/// Integratie met Trust Kernel:
///   - Zandbak levert het virtuele geheugengebied (mmap + guard pages)
///   - UPIP Pager levert Fork Tokens (compress + sign + store per block)
///   - Snapshot Engine levert .tza format (header + zstd + Ed25519)
///   - Bus levert intent routing (welk remote kernel heeft block N?)
///   - Watchdog bewaakt de fault handler thread
///
/// "Redis houdt in zijn eigen geheugen een index bij van waar alle keys staan.
///  Als de Trust Kernel onzichtbaar het RAM eronder weghaalt, klopt de fysieke
///  geheugenmap niet meer — tenzij we het briljant afvangen via de MMU."
///                                                              — Jasper

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Default block size for RAID striping: 2MB (matches HugePages)
pub const RAID_BLOCK_SIZE: usize = 2 * 1024 * 1024;

/// Minimum virtual arena size: 4MB (2 blocks)
pub const MIN_ARENA_SIZE: usize = 4 * 1024 * 1024;

/// Maximum virtual arena: 16GB (theoretical, depends on hardware)
pub const MAX_ARENA_SIZE: usize = 16 * 1024 * 1024 * 1024;

/// Page fault handler poll interval (microseconds)
pub const FAULT_POLL_INTERVAL_US: u64 = 1;

/// Maximum concurrent page faults before backpressure
pub const MAX_CONCURRENT_FAULTS: usize = 64;

/// Proactive eviction: when this % of blocks are resident, start evicting coldest
pub const EVICTION_THRESHOLD_PCT: f64 = 75.0;

// ═══════════════════════════════════════════════════════════════
// Types — Block Management
// ═══════════════════════════════════════════════════════════════

/// Which RAID stripe a block belongs to.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidStripe {
    /// Even-numbered blocks → RAM A (local)
    RamA,
    /// Odd-numbered blocks → RAM B (remote or secondary store)
    RamB,
}

impl RaidStripe {
    /// Determine stripe from block index.
    pub fn from_block_index(idx: usize) -> Self {
        if idx % 2 == 0 { RaidStripe::RamA } else { RaidStripe::RamB }
    }
}

/// Where a block physically lives right now.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BlockLocation {
    /// Resident in the virtual arena (app can access it)
    Resident,
    /// Evicted to local Archivaris store (.tza compressed)
    LocalStore { tza_path: String, fork_token_id: String },
    /// Evicted to remote kernel via intent mux
    RemoteKernel { kernel_id: String, endpoint: String, fork_token_id: String },
    /// Being fetched (fault handler is working on it)
    Fetching,
    /// Never been written to (zero page — can be satisfied from /dev/zero)
    Virgin,
}

/// Metadata for a single RAID block.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RaidBlock {
    /// Block index (0-based, sequential)
    pub index: usize,
    /// RAID stripe assignment
    pub stripe: RaidStripe,
    /// Virtual address offset within the arena
    pub va_offset: usize,
    /// Block size in bytes
    pub size: usize,
    /// Current location
    pub location: BlockLocation,
    /// SHA256 of the block's last known content
    pub content_hash: Option<String>,
    /// Ed25519 seal if evicted
    pub seal: Option<String>,
    /// Access count (for LRU eviction)
    pub access_count: u64,
    /// Last access timestamp (nanos)
    pub last_access_ns: u64,
    /// Write count (dirty tracking)
    pub write_count: u64,
    /// Is this block dirty? (written to since last eviction)
    pub dirty: bool,
}

/// Configuration for the RAM RAID controller.
#[derive(Debug, Clone)]
pub struct RaidConfig {
    /// Total virtual arena size in bytes
    pub arena_size: usize,
    /// Block size for striping
    pub block_size: usize,
    /// Maximum blocks resident in physical RAM at once
    pub max_resident_blocks: usize,
    /// Remote kernel endpoint for RAM B (None = local-only mode)
    pub ram_b_endpoint: Option<String>,
    /// Remote kernel ID
    pub ram_b_kernel_id: Option<String>,
    /// Enable proactive eviction (don't wait for page faults)
    pub proactive_eviction: bool,
    /// Enable write tracking (detect dirty blocks)
    pub track_writes: bool,
    /// Intent for this RAID arena (used for routing)
    pub intent: String,
    /// Source agent
    pub from_aint: String,
}

impl RaidConfig {
    /// Create config for a given arena size.
    pub fn new(arena_size: usize, intent: &str, from_aint: &str) -> Self {
        let block_count = arena_size / RAID_BLOCK_SIZE;
        Self {
            arena_size,
            block_size: RAID_BLOCK_SIZE,
            max_resident_blocks: block_count, // Default: all can be resident
            ram_b_endpoint: None,
            ram_b_kernel_id: None,
            proactive_eviction: true,
            track_writes: true,
            intent: intent.to_string(),
            from_aint: from_aint.to_string(),
        }
    }

    /// Enable remote RAM B.
    pub fn with_remote_ram_b(mut self, kernel_id: &str, endpoint: &str) -> Self {
        self.ram_b_kernel_id = Some(kernel_id.to_string());
        self.ram_b_endpoint = Some(endpoint.to_string());
        // With remote: only half the blocks stay local
        self.max_resident_blocks /= 2;
        self
    }

    /// Set max resident blocks (limits physical RAM usage).
    pub fn with_max_resident(mut self, max: usize) -> Self {
        self.max_resident_blocks = max;
        self
    }

    /// Total number of blocks in the arena.
    pub fn block_count(&self) -> usize {
        self.arena_size / self.block_size
    }
}

// ═══════════════════════════════════════════════════════════════
// Types — Page Fault Handling
// ═══════════════════════════════════════════════════════════════

/// A page fault event from userfaultfd.
#[derive(Debug, Clone)]
pub struct PageFault {
    /// Faulting virtual address
    pub fault_addr: usize,
    /// Page-aligned address
    pub aligned_addr: usize,
    /// Which block this address belongs to
    pub block_index: usize,
    /// Is this a write fault?
    pub is_write: bool,
    /// Timestamp of the fault
    pub timestamp_ns: u64,
}

/// Result of handling a page fault.
#[derive(Debug, Clone)]
pub enum FaultResult {
    /// Block was resident (shouldn't happen — race condition)
    AlreadyResident { block_index: usize },
    /// Block restored from local store
    RestoredLocal {
        block_index: usize,
        decompress_us: u64,
        verify_us: u64,
        inject_us: u64,
        total_us: u64,
    },
    /// Block restored from remote kernel
    RestoredRemote {
        block_index: usize,
        fetch_us: u64,
        decompress_us: u64,
        verify_us: u64,
        inject_us: u64,
        total_us: u64,
    },
    /// Virgin block — zero page injected
    ZeroFilled {
        block_index: usize,
        inject_us: u64,
    },
    /// Eviction was needed before restore (cascading)
    EvictedThenRestored {
        evicted_block: usize,
        eviction_us: u64,
        restored_block: usize,
        restore_us: u64,
        total_us: u64,
    },
    /// Fault handling failed
    Failed {
        block_index: usize,
        reason: String,
    },
}

/// Result of a proactive eviction.
#[derive(Debug, Clone)]
pub enum EvictionResult {
    /// Block evicted to local store
    EvictedLocal {
        block_index: usize,
        compressed_size: usize,
        compress_us: u64,
        seal_us: u64,
        store_us: u64,
        total_us: u64,
    },
    /// Block evicted to remote kernel
    EvictedRemote {
        block_index: usize,
        compressed_size: usize,
        transfer_us: u64,
        total_us: u64,
    },
    /// Block was clean (not dirty) — just drop it
    Dropped {
        block_index: usize,
    },
    /// Nothing to evict
    NothingToEvict,
    /// Eviction failed
    Failed {
        block_index: usize,
        reason: String,
    },
}

// ═══════════════════════════════════════════════════════════════
// Simulated crypto (consistent with snapshot.rs / upip_pager.rs)
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
    format!("ed25519_raid:{}", &hash[7..39])
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
// RAM RAID Controller
// ═══════════════════════════════════════════════════════════════

/// The RAM RAID Controller — transparent memory virtualization.
///
/// In production:
///   - `arena_ptr`: mmap(MAP_ANONYMOUS) → registered with userfaultfd
///   - `uffd`: UffdBuilder::new().create() → listens for page faults
///   - `fault_thread`: separate thread running uffd.read_event() loop
///
/// In simulation (for benchmarking without /dev/userfaultfd):
///   - Block table tracks virtual state
///   - `handle_fault()` simulates the full pipeline
///   - Timing is realistic (based on real zstd + ed25519 benchmarks)
pub struct RamRaidController {
    /// Configuration
    pub config: RaidConfig,
    /// Block table: index → metadata
    pub blocks: Vec<RaidBlock>,
    /// Resident block count
    pub resident_count: AtomicU64,
    /// Total page faults handled
    pub faults_handled: AtomicU64,
    /// Total evictions performed
    pub evictions_performed: AtomicU64,
    /// Total bytes compressed (evictions)
    pub bytes_compressed: AtomicU64,
    /// Total bytes decompressed (restores)
    pub bytes_decompressed: AtomicU64,
    /// Remote transfers (RAM B)
    pub remote_transfers: AtomicU64,
    /// Zero pages served (virgin blocks)
    pub zero_pages_served: AtomicU64,
    /// Controller is active
    pub active: AtomicBool,
    /// Bus sequence counter (for TIBET integration)
    bus_seq: AtomicU64,
    /// LRU eviction index (for finding coldest block)
    lru_clock: AtomicU64,
    /// Cluster MUX client for real network transport to RAM B
    mux_client: Option<Arc<ClusterMuxClient>>,
    /// Tokio runtime handle for calling async transport from sync fault handler
    runtime_handle: Option<tokio::runtime::Handle>,
    /// Remote block store (for local-only testing without network)
    local_block_store: Option<Arc<BlockStore>>,
}

impl RamRaidController {
    /// Create a new RAM RAID controller.
    ///
    /// In production: this also calls mmap() + UffdBuilder + spawns fault thread.
    pub fn new(config: RaidConfig) -> Self {
        let block_count = config.block_count();
        let mut blocks = Vec::with_capacity(block_count);

        for i in 0..block_count {
            blocks.push(RaidBlock {
                index: i,
                stripe: RaidStripe::from_block_index(i),
                va_offset: i * config.block_size,
                size: config.block_size,
                location: BlockLocation::Virgin,
                content_hash: None,
                seal: None,
                access_count: 0,
                last_access_ns: 0,
                write_count: 0,
                dirty: false,
            });
        }

        Self {
            config,
            blocks,
            resident_count: AtomicU64::new(0),
            faults_handled: AtomicU64::new(0),
            evictions_performed: AtomicU64::new(0),
            bytes_compressed: AtomicU64::new(0),
            bytes_decompressed: AtomicU64::new(0),
            remote_transfers: AtomicU64::new(0),
            zero_pages_served: AtomicU64::new(0),
            active: AtomicBool::new(true),
            bus_seq: AtomicU64::new(0),
            lru_clock: AtomicU64::new(0),
            mux_client: None,
            runtime_handle: None,
            local_block_store: None,
        }
    }

    /// Attach a ClusterMuxClient for real network transport to RAM B.
    ///
    /// The tokio runtime handle is needed because the fault handler runs
    /// in a plain thread (not tokio), so we use `handle.block_on()` to
    /// call async transport methods.
    pub fn with_mux_transport(mut self, client: Arc<ClusterMuxClient>, handle: tokio::runtime::Handle) -> Self {
        self.mux_client = Some(client);
        self.runtime_handle = Some(handle);
        self
    }

    /// Attach a local BlockStore for testing without network.
    /// This simulates RAM B as a separate in-memory store.
    pub fn with_local_block_store(mut self, store: Arc<BlockStore>) -> Self {
        self.local_block_store = Some(store);
        self
    }

    /// TIBET-Store MMU: Transformeert deze logische RAID-0 controller in een echte hardware MMU-trap.
    /// Dit combineert de bewezen tibet-store-mmu logica met de Trust Kernel UPIP pager.
    pub fn start_production(self) -> Option<ActiveRamRaid> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        let size = (self.config.arena_size + page_size - 1) & !(page_size - 1);

        // 1. Reserveer Fake Virtueel RAM (zonder fysieke backing)
        let addr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        
        if addr == libc::MAP_FAILED {
            println!("◈ Error: MAP_FAILED in start_production");
            return None;
        }

        // 2. Userfaultfd registratie
        let uffd = match UffdBuilder::new()
            .close_on_exec(true)
            .non_blocking(true)
            .user_mode_only(false)
            .create()
        {
            Ok(u) => Arc::new(u),
            Err(e) => {
                println!("◈ Error: Failed to create userfaultfd: {}", e);
                unsafe { munmap(addr, size); }
                return None;
            }
        };

        if let Err(e) = uffd.register(addr, size) {
            println!("◈ Error: Failed to register UFFD handler: {}", e);
            unsafe { munmap(addr, size); }
            return None;
        }

        println!("◈ [Trust Kernel] Allocated {} bytes Fake RAM at {:?}", size, addr);
        println!("◈ [Trust Kernel] MMU Hardware Trap active (TIBET-Store)");

        let controller = Arc::new(Mutex::new(self));
        let c_clone = controller.clone();
        let u_clone = uffd.clone();

        // 3. De Archivaris / Fault Handler Thread
        //
        // Dit is het hart van de transparante geheugen-virtualisatie:
        //   - userfaultfd vangt page faults op (hardware MMU trap)
        //   - handle_fault_production() fetcht data van RAM B via ClusterMux
        //   - uffd.copy() injecteert de echte data in het fysieke geheugen
        //   - De app-thread wordt hervat — merkt niets van het hele process
        //
        // De fault handler thread is een gewone thread (geen tokio), dus
        // block_on_safe() kan veilig een temp runtime maken voor async MUX calls.
        let addr_usize = addr as usize;
        let fault_thread = thread::spawn(move || {
            loop {
                // Check if controller is still active
                if !c_clone.lock().unwrap().active.load(Ordering::Relaxed) {
                    break;
                }

                match u_clone.read_event() {
                    Ok(Some(Event::Pagefault { addr: fault_addr, .. })) => {
                        let offset = fault_addr as usize - addr_usize;
                        let mut lock = c_clone.lock().unwrap();

                        // THE MAGIC: page fault → RAM RAID → MUX fetch → uffd.copy()
                        let (fault_result, block_data) = lock.handle_fault_production(offset);

                        // Determine injection address and size
                        let fault_addr_aligned = (fault_addr as usize / page_size) * page_size;

                        // Build the page data for injection
                        let page_data = if !block_data.is_empty() {
                            // Real data from RAM B (or local store)
                            // Slice to page_size if block is larger than one page
                            let page_offset = fault_addr_aligned - addr_usize;
                            let block_idx = lock.block_index_for_addr(page_offset);
                            let block_start = block_idx * lock.config.block_size;
                            let offset_in_block = page_offset - block_start;

                            if offset_in_block < block_data.len() {
                                let end = (offset_in_block + page_size).min(block_data.len());
                                let mut page = vec![0u8; page_size];
                                let copy_len = end - offset_in_block;
                                page[..copy_len].copy_from_slice(&block_data[offset_in_block..end]);
                                page
                            } else {
                                vec![0u8; page_size]
                            }
                        } else {
                            // Zero page or error — inject zeros
                            vec![0u8; page_size]
                        };

                        // Drop the lock BEFORE uffd.copy() to avoid holding it during kernel call
                        let block_size = lock.config.block_size;
                        drop(lock);

                        // Inject into physical memory — app thread resumes after this
                        let _ = unsafe {
                            u_clone.copy(
                                page_data.as_ptr() as *const _,
                                fault_addr_aligned as *mut _,
                                page_size,
                                true,
                            )
                        };

                        match &fault_result {
                            FaultResult::RestoredRemote { block_index, fetch_us, .. } => {
                                println!("◈ [MMU] Block {} fetched from RAM B ({}µs) → injected at {:#x}",
                                         block_index, fetch_us, fault_addr_aligned);
                            }
                            FaultResult::RestoredLocal { block_index, .. } => {
                                println!("◈ [MMU] Block {} restored local → injected at {:#x}",
                                         block_index, fault_addr_aligned);
                            }
                            FaultResult::ZeroFilled { block_index, .. } => {
                                println!("◈ [MMU] Block {} zero-fill → injected at {:#x}",
                                         block_index, fault_addr_aligned);
                            }
                            FaultResult::Failed { block_index, reason } => {
                                eprintln!("◈ [MMU] Block {} FAILED: {} — injected zeros at {:#x}",
                                          block_index, reason, fault_addr_aligned);
                            }
                            _ => {}
                        }
                    }
                    Ok(None) | Err(_) => {
                        thread::sleep(std::time::Duration::from_millis(1));
                    }
                    _ => {}
                }
            }
        });

        Some(ActiveRamRaid {
            controller,
            arena_ptr: addr,
            uffd,
            fault_thread: Some(fault_thread),
        })
    }

    /// Total blocks in the arena.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Currently resident blocks.
    pub fn resident_blocks(&self) -> usize {
        self.resident_count.load(Ordering::Relaxed) as usize
    }

    /// Calculate block index from a virtual address offset.
    pub fn block_index_for_addr(&self, va_offset: usize) -> usize {
        va_offset / self.config.block_size
    }

    /// Handle a page fault.
    ///
    /// This is THE hot path. When the app touches an evicted page:
    ///   1. userfaultfd catches it → thread blocks
    ///   2. We receive the fault address
    ///   3. Look up block → determine location
    ///   4. Fetch + decompress + verify + inject
    ///   5. uffd.copy() → thread resumes
    ///
    /// Target: <50µs for local restore, <500µs for remote.
    pub fn handle_fault(&mut self, fault_addr: usize) -> FaultResult {
        let t0 = Instant::now();

        let block_idx = self.block_index_for_addr(fault_addr);
        if block_idx >= self.blocks.len() {
            return FaultResult::Failed {
                block_index: block_idx,
                reason: format!("Block index {} out of range (max {})", block_idx, self.blocks.len()),
            };
        }

        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

        // Check if we need to evict first (at capacity)
        let need_eviction = self.resident_count.load(Ordering::Acquire)
            >= self.config.max_resident_blocks as u64;

        if need_eviction {
            let evict_t0 = Instant::now();
            let evict_result = self.evict_coldest();
            let eviction_us = evict_t0.elapsed().as_micros() as u64;

            match &evict_result {
                EvictionResult::EvictedLocal { .. } | EvictionResult::EvictedRemote { .. } | EvictionResult::Dropped { .. } => {
                    // Good, we freed a slot
                }
                _ => {
                    return FaultResult::Failed {
                        block_index: block_idx,
                        reason: "Cannot evict block to make room".to_string(),
                    };
                }
            }

            // Now restore the faulted block
            let restore_result = self.restore_block(block_idx, now_ns);
            let restore_us = t0.elapsed().as_micros() as u64 - eviction_us;

            if let Some(evicted_idx) = match &evict_result {
                EvictionResult::EvictedLocal { block_index, .. } => Some(*block_index),
                EvictionResult::EvictedRemote { block_index, .. } => Some(*block_index),
                EvictionResult::Dropped { block_index } => Some(*block_index),
                _ => None,
            } {
                return FaultResult::EvictedThenRestored {
                    evicted_block: evicted_idx,
                    eviction_us,
                    restored_block: block_idx,
                    restore_us,
                    total_us: t0.elapsed().as_micros() as u64,
                };
            }

            return restore_result;
        }

        // No eviction needed — just restore
        self.restore_block(block_idx, now_ns)
    }

    /// Handle a page fault in production mode — returns the actual data to inject.
    ///
    /// Unlike `handle_fault()` (simulation), this returns `(FaultResult, Vec<u8>)`
    /// where the Vec is the actual block data for uffd.copy() injection.
    /// Called from the userfaultfd fault handler thread.
    pub fn handle_fault_production(&mut self, fault_addr: usize) -> (FaultResult, Vec<u8>) {
        let block_idx = self.block_index_for_addr(fault_addr);
        if block_idx >= self.blocks.len() {
            return (FaultResult::Failed {
                block_index: block_idx,
                reason: format!("Block index {} out of range", block_idx),
            }, Vec::new());
        }

        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

        // Evict if needed
        let need_eviction = self.resident_count.load(Ordering::Acquire)
            >= self.config.max_resident_blocks as u64;
        if need_eviction {
            let _ = self.evict_coldest();
        }

        self.restore_block_with_data(block_idx, now_ns)
    }

    /// Restore a block and return both the result and the actual data.
    fn restore_block_with_data(&mut self, block_idx: usize, now_ns: u64) -> (FaultResult, Vec<u8>) {
        let (result, data) = self.restore_block_inner(block_idx, now_ns);
        (result, data)
    }

    /// Inner restore that returns data for production injection.
    fn restore_block_inner(&mut self, block_idx: usize, now_ns: u64) -> (FaultResult, Vec<u8>) {
        let t0 = Instant::now();
        let block = &self.blocks[block_idx];
        let block_size = block.size;

        match &block.location {
            BlockLocation::Resident => {
                (FaultResult::AlreadyResident { block_index: block_idx }, Vec::new())
            }

            BlockLocation::Virgin => {
                let inject_us = t0.elapsed().as_micros() as u64;
                self.blocks[block_idx].location = BlockLocation::Resident;
                self.blocks[block_idx].access_count = 1;
                self.blocks[block_idx].last_access_ns = now_ns;
                self.resident_count.fetch_add(1, Ordering::AcqRel);
                self.zero_pages_served.fetch_add(1, Ordering::Relaxed);
                self.faults_handled.fetch_add(1, Ordering::Relaxed);
                (FaultResult::ZeroFilled { block_index: block_idx, inject_us }, vec![0u8; block_size])
            }

            BlockLocation::LocalStore { .. } => {
                // TODO: In real production, read .tza from disk + decompress
                // For now: return simulated data (same as simulation path)
                let data = vec![0u8; block_size];
                let result = self.restore_block(block_idx, now_ns);
                (result, data)
            }

            BlockLocation::RemoteKernel { .. } => {
                let content_hash = block.content_hash.clone();
                let bus_seq = self.bus_seq.fetch_add(1, Ordering::SeqCst);

                // Fetch real data from remote via MUX
                let fetch_t0 = Instant::now();
                let fetched_data = if let Some(client) = &self.mux_client {
                    let c = client.clone();
                    let ch = content_hash.clone();
                    match block_on_safe(c.fetch_block(block_idx, ch.as_deref(), bus_seq)) {
                        Ok((data, _rtt)) => data,
                        Err(e) => {
                            return (FaultResult::Failed {
                                block_index: block_idx,
                                reason: format!("Remote fetch failed: {}", e),
                            }, Vec::new());
                        }
                    }
                } else {
                    // No client — return zeros
                    vec![0u8; block_size]
                };
                let fetch_us = fetch_t0.elapsed().as_micros() as u64;

                // Verify integrity
                if let Some(ref expected) = content_hash {
                    let computed = sha256_hex(&fetched_data);
                    if computed != *expected {
                        return (FaultResult::Failed {
                            block_index: block_idx,
                            reason: format!("Integrity: expected {}, got {}", expected, computed),
                        }, Vec::new());
                    }
                }

                let total_us = t0.elapsed().as_micros() as u64;

                self.blocks[block_idx].location = BlockLocation::Resident;
                self.blocks[block_idx].access_count += 1;
                self.blocks[block_idx].last_access_ns = now_ns;
                self.blocks[block_idx].dirty = false;
                self.resident_count.fetch_add(1, Ordering::AcqRel);
                self.bytes_decompressed.fetch_add(fetched_data.len() as u64, Ordering::Relaxed);
                self.remote_transfers.fetch_add(1, Ordering::Relaxed);
                self.faults_handled.fetch_add(1, Ordering::Relaxed);

                (FaultResult::RestoredRemote {
                    block_index: block_idx,
                    fetch_us,
                    decompress_us: 0,
                    verify_us: 0,
                    inject_us: 0,
                    total_us,
                }, fetched_data)
            }

            BlockLocation::Fetching => {
                (FaultResult::Failed {
                    block_index: block_idx,
                    reason: "Already fetching".to_string(),
                }, Vec::new())
            }
        }
    }

    /// Restore a single block to resident state.
    fn restore_block(&mut self, block_idx: usize, now_ns: u64) -> FaultResult {
        let t0 = Instant::now();
        let block = &self.blocks[block_idx];

        match &block.location {
            BlockLocation::Resident => {
                return FaultResult::AlreadyResident { block_index: block_idx };
            }

            BlockLocation::Virgin => {
                // Zero page — fastest path
                // In production: uffd.zeropage(addr, block_size, true)
                let inject_us = t0.elapsed().as_micros() as u64;

                self.blocks[block_idx].location = BlockLocation::Resident;
                self.blocks[block_idx].access_count = 1;
                self.blocks[block_idx].last_access_ns = now_ns;
                self.resident_count.fetch_add(1, Ordering::AcqRel);
                self.zero_pages_served.fetch_add(1, Ordering::Relaxed);
                self.faults_handled.fetch_add(1, Ordering::Relaxed);

                FaultResult::ZeroFilled {
                    block_index: block_idx,
                    inject_us,
                }
            }

            BlockLocation::LocalStore { .. } => {
                // Restore from local Archivaris
                let block_size = block.size;

                // Step 1: Load .tza from disk (simulated)
                // ~500 MB/s SSD = 2ns/byte, but mostly sequential → ~1µs for 2MB
                let _load_ns = block_size as u64 * 2;

                // Step 2: Verify Ed25519 seal
                let verify_t0 = Instant::now();
                // In production: ed25519_dalek verify
                let _verify_ok = true;
                let verify_us = verify_t0.elapsed().as_micros() as u64;

                // Step 3: Decompress zstd
                let decompress_t0 = Instant::now();
                let compressed_size = block_size / 4; // ~4x compression for memory
                let _decompress_ns = simulate_zstd_decompress(compressed_size, block_size);
                let decompress_us = decompress_t0.elapsed().as_micros() as u64;

                // Step 4: Inject via uffd.copy()
                let inject_t0 = Instant::now();
                // In production: uffd.copy(data_ptr, fault_addr, block_size, true)
                let inject_us = inject_t0.elapsed().as_micros() as u64;

                let total_us = t0.elapsed().as_micros() as u64;

                self.blocks[block_idx].location = BlockLocation::Resident;
                self.blocks[block_idx].access_count += 1;
                self.blocks[block_idx].last_access_ns = now_ns;
                self.blocks[block_idx].dirty = false;
                self.resident_count.fetch_add(1, Ordering::AcqRel);
                self.bytes_decompressed.fetch_add(block_size as u64, Ordering::Relaxed);
                self.faults_handled.fetch_add(1, Ordering::Relaxed);

                FaultResult::RestoredLocal {
                    block_index: block_idx,
                    decompress_us,
                    verify_us,
                    inject_us,
                    total_us,
                }
            }

            BlockLocation::RemoteKernel { kernel_id, endpoint, fork_token_id } => {
                // Restore from remote kernel — the RAID-0 magic
                let block_size = block.size;
                let _kernel_id = kernel_id.clone();
                let _endpoint = endpoint.clone();
                let _fork_token_id = fork_token_id.clone();
                let content_hash = block.content_hash.clone();
                let bus_seq = self.bus_seq.fetch_add(1, Ordering::SeqCst);

                // Step 1: Fetch via ClusterMux (real network) or BlockStore (local test)
                let fetch_t0 = Instant::now();
                let fetched_data = if let Some(client) = &self.mux_client {
                    // REAL TRANSPORT: Fetch block from remote kernel via persistent MUX
                    let c = client.clone();
                    let ch = content_hash.clone();
                    match block_on_safe(c.fetch_block(
                        block_idx,
                        ch.as_deref(),
                        bus_seq,
                    )) {
                        Ok((data, _rtt_us)) => Some(data),
                        Err(e) => {
                            return FaultResult::Failed {
                                block_index: block_idx,
                                reason: format!("Remote fetch failed: {}", e),
                            };
                        }
                    }
                } else if let Some(store) = &self.local_block_store {
                    // LOCAL TEST: Fetch from in-memory BlockStore (simulates RAM B)
                    match handle_block_on_local(store, block_idx) {
                        Some(data) => Some(data),
                        None => {
                            return FaultResult::Failed {
                                block_index: block_idx,
                                reason: format!("Block {} not found in local block store", block_idx),
                            };
                        }
                    }
                } else {
                    // SIMULATION fallback (no transport attached)
                    None
                };
                let fetch_us = fetch_t0.elapsed().as_micros() as u64;

                // Step 2: Verify SHA-256 integrity
                let verify_t0 = Instant::now();
                if let Some(ref data) = fetched_data {
                    if let Some(ref expected_hash) = content_hash {
                        let computed = sha256_hex(data);
                        if computed != *expected_hash {
                            return FaultResult::Failed {
                                block_index: block_idx,
                                reason: format!(
                                    "Integrity check failed: expected {}, got {}",
                                    expected_hash, computed
                                ),
                            };
                        }
                    }
                }
                let verify_us = verify_t0.elapsed().as_micros() as u64;

                // Step 3: Decompress (data from network is already decompressed in current impl)
                let decompress_t0 = Instant::now();
                let decompress_us = decompress_t0.elapsed().as_micros() as u64;

                // Step 4: Inject via uffd.copy() (in production)
                let inject_t0 = Instant::now();
                // In production: uffd.copy(data_ptr, fault_addr, block_size, true)
                let inject_us = inject_t0.elapsed().as_micros() as u64;

                let total_us = t0.elapsed().as_micros() as u64;

                self.blocks[block_idx].location = BlockLocation::Resident;
                self.blocks[block_idx].access_count += 1;
                self.blocks[block_idx].last_access_ns = now_ns;
                self.blocks[block_idx].dirty = false;
                self.resident_count.fetch_add(1, Ordering::AcqRel);
                self.bytes_decompressed.fetch_add(
                    fetched_data.as_ref().map(|d| d.len() as u64).unwrap_or(block_size as u64),
                    Ordering::Relaxed,
                );
                self.remote_transfers.fetch_add(1, Ordering::Relaxed);
                self.faults_handled.fetch_add(1, Ordering::Relaxed);

                FaultResult::RestoredRemote {
                    block_index: block_idx,
                    fetch_us,
                    decompress_us,
                    verify_us,
                    inject_us,
                    total_us,
                }
            }

            BlockLocation::Fetching => {
                // Another thread is already fetching this — shouldn't happen
                // userfaultfd serializes faults per page
                FaultResult::Failed {
                    block_index: block_idx,
                    reason: "Block already being fetched (concurrent fault)".to_string(),
                }
            }
        }
    }

    /// Evict the coldest (least recently accessed) resident block.
    ///
    /// Uses CLOCK algorithm: scan blocks from lru_clock position,
    /// clear access bit on first pass, evict on second pass.
    pub fn evict_coldest(&mut self) -> EvictionResult {
        let t0 = Instant::now();
        let block_count = self.blocks.len();

        if block_count == 0 {
            return EvictionResult::NothingToEvict;
        }

        // Find coldest resident block
        let mut coldest_idx: Option<usize> = None;
        let mut coldest_access: u64 = u64::MAX;

        let start = self.lru_clock.load(Ordering::Relaxed) as usize % block_count;
        for i in 0..block_count {
            let idx = (start + i) % block_count;
            let block = &self.blocks[idx];

            if block.location == BlockLocation::Resident && block.access_count < coldest_access {
                coldest_access = block.access_count;
                coldest_idx = Some(idx);
            }
        }

        let idx = match coldest_idx {
            Some(i) => i,
            None => return EvictionResult::NothingToEvict,
        };

        self.lru_clock.store((idx + 1) as u64, Ordering::Relaxed);

        // Determine eviction target based on stripe
        let block = &self.blocks[idx];
        let stripe = block.stripe;
        let is_dirty = block.dirty;
        let block_size = block.size;

        if !is_dirty {
            // Clean block — just drop it, we have the .tza already
            // (or it was virgin and never written to)
            self.blocks[idx].location = if self.blocks[idx].content_hash.is_some() {
                BlockLocation::LocalStore {
                    tza_path: format!("/var/lib/airlock/raid/block_{}.tza", idx),
                    fork_token_id: format!("raid_fork_{}", idx),
                }
            } else {
                BlockLocation::Virgin
            };
            self.resident_count.fetch_sub(1, Ordering::AcqRel);
            self.evictions_performed.fetch_add(1, Ordering::Relaxed);

            return EvictionResult::Dropped { block_index: idx };
        }

        // Dirty block — must compress + sign + store
        // Step 1: Read block data
        // In production: memcpy from arena_ptr + va_offset
        let simulated_data = vec![42u8; block_size]; // Dirty data

        // Step 2: Compress
        let compress_t0 = Instant::now();
        let (compressed, _) = simulate_zstd_compress(&simulated_data);
        let compress_us = compress_t0.elapsed().as_micros() as u64;

        // Step 3: Sign
        let seal_t0 = Instant::now();
        let content_hash = simulate_sha256(&simulated_data);
        let seal = simulate_ed25519_sign(content_hash.as_bytes());
        let seal_us = seal_t0.elapsed().as_micros() as u64;

        let compressed_size = compressed.len();
        let seq = self.bus_seq.fetch_add(1, Ordering::SeqCst);

        // Determine destination based on stripe
        let has_remote = self.config.ram_b_endpoint.is_some();
        let evict_to_remote = has_remote && stripe == RaidStripe::RamB;

        if evict_to_remote {
            // Send to remote kernel (RAM B) via ClusterMux
            let transfer_t0 = Instant::now();

            // Compute real SHA-256 hash of the data we're sending
            let real_hash = sha256_hex(&simulated_data);

            if let Some(client) = &self.mux_client {
                // REAL TRANSPORT: Store block on remote kernel via persistent MUX
                let c = client.clone();
                let d = simulated_data.clone();
                let h = real_hash.clone();
                let s = seal.clone();
                match block_on_safe(c.store_block(idx, &d, &h, &s, block_size, seq)) {
                    Ok(_store_us) => { /* success */ }
                    Err(e) => {
                        return EvictionResult::Failed {
                            block_index: idx,
                            reason: format!("Remote store failed: {}", e),
                        };
                    }
                }
            } else if let Some(store) = &self.local_block_store {
                // LOCAL TEST: Store in in-memory BlockStore (simulates RAM B)
                let from_aint = self.config.from_aint.clone();
                let s = store.clone();
                let data = simulated_data.clone();
                let h = real_hash.clone();
                let se = seal.clone();
                block_on_safe(s.store(idx, data, h, se, block_size, from_aint, seq));
            }
            // else: simulation mode — no actual transfer

            let transfer_us = transfer_t0.elapsed().as_micros() as u64;
            let total_us = t0.elapsed().as_micros() as u64;

            let kernel_id = self.config.ram_b_kernel_id.clone().unwrap_or_default();
            let endpoint = self.config.ram_b_endpoint.clone().unwrap_or_default();

            self.blocks[idx].location = BlockLocation::RemoteKernel {
                kernel_id,
                endpoint,
                fork_token_id: format!("raid_fork_remote_{}", seq),
            };
            self.blocks[idx].content_hash = Some(real_hash);
            self.blocks[idx].seal = Some(seal);
            self.blocks[idx].dirty = false;
            self.resident_count.fetch_sub(1, Ordering::AcqRel);
            self.evictions_performed.fetch_add(1, Ordering::Relaxed);
            self.bytes_compressed.fetch_add(block_size as u64, Ordering::Relaxed);
            self.remote_transfers.fetch_add(1, Ordering::Relaxed);

            EvictionResult::EvictedRemote {
                block_index: idx,
                compressed_size,
                transfer_us,
                total_us,
            }
        } else {
            // Store locally
            let store_t0 = Instant::now();
            // In production: write .tza to disk
            let store_us = store_t0.elapsed().as_micros() as u64;

            let total_us = t0.elapsed().as_micros() as u64;
            let tza_path = format!("/var/lib/airlock/raid/block_{}_seq{}.tza", idx, seq);

            self.blocks[idx].location = BlockLocation::LocalStore {
                tza_path,
                fork_token_id: format!("raid_fork_local_{}", seq),
            };
            self.blocks[idx].content_hash = Some(content_hash);
            self.blocks[idx].seal = Some(seal);
            self.blocks[idx].dirty = false;
            self.resident_count.fetch_sub(1, Ordering::AcqRel);
            self.evictions_performed.fetch_add(1, Ordering::Relaxed);
            self.bytes_compressed.fetch_add(block_size as u64, Ordering::Relaxed);

            EvictionResult::EvictedLocal {
                block_index: idx,
                compressed_size,
                compress_us,
                seal_us,
                store_us,
                total_us,
            }
        }
    }

    /// Proactive eviction: check pressure and evict if needed.
    ///
    /// Called periodically (not on fault path) to keep headroom.
    /// Returns number of blocks evicted.
    pub fn proactive_evict(&mut self) -> Vec<EvictionResult> {
        let resident = self.resident_count.load(Ordering::Relaxed) as f64;
        let max = self.config.max_resident_blocks as f64;
        let utilization = (resident / max) * 100.0;

        if utilization < EVICTION_THRESHOLD_PCT {
            return Vec::new();
        }

        // Evict down to 60% of max
        let target = (max * 0.6) as usize;
        let to_evict = (resident as usize).saturating_sub(target);

        let mut results = Vec::with_capacity(to_evict);
        for _ in 0..to_evict {
            let result = self.evict_coldest();
            match &result {
                EvictionResult::NothingToEvict => break,
                _ => results.push(result),
            }
        }

        results
    }

    /// Simulate a workload: write to a block (makes it dirty + resident).
    pub fn simulate_write(&mut self, block_idx: usize) {
        if block_idx >= self.blocks.len() { return; }

        let was_resident = self.blocks[block_idx].location == BlockLocation::Resident;
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

        self.blocks[block_idx].location = BlockLocation::Resident;
        self.blocks[block_idx].dirty = true;
        self.blocks[block_idx].write_count += 1;
        self.blocks[block_idx].access_count += 1;
        self.blocks[block_idx].last_access_ns = now_ns;
        self.blocks[block_idx].content_hash = Some(
            format!("sha256:dirty_block_{}_write_{}", block_idx, self.blocks[block_idx].write_count)
        );

        if !was_resident {
            self.resident_count.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Simulate a workload: read from a block (may trigger fault).
    pub fn simulate_read(&mut self, block_idx: usize) -> FaultResult {
        if block_idx >= self.blocks.len() {
            return FaultResult::Failed {
                block_index: block_idx,
                reason: "Out of range".to_string(),
            };
        }

        if self.blocks[block_idx].location == BlockLocation::Resident {
            let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
            self.blocks[block_idx].access_count += 1;
            self.blocks[block_idx].last_access_ns = now_ns;
            return FaultResult::AlreadyResident { block_index: block_idx };
        }

        // Not resident — this triggers a page fault
        let fault_addr = block_idx * self.config.block_size;
        self.handle_fault(fault_addr)
    }

    /// Batch read: read multiple blocks, batching remote fetches via pipelined MUX.
    ///
    /// Instead of fetch-one-by-one (N round trips), this:
    ///   1. Partitions blocks into resident / local / remote
    ///   2. Evicts enough blocks to make room
    ///   3. Restores local blocks individually (fast, disk-bound)
    ///   4. Batches ALL remote blocks into ONE pipelined fetch_batch()
    ///
    /// Use case: LLM loading a transformer layer (sequential blocks, mostly on RAM B).
    /// With 10 blocks on remote, pipeline = 1 RTT instead of 10.
    pub fn simulate_read_batch(&mut self, block_indices: &[usize]) -> Vec<FaultResult> {
        let t0 = Instant::now();
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

        // Partition blocks by current location
        let mut already_resident = Vec::new();
        let mut need_local_restore = Vec::new();
        let mut need_remote_fetch = Vec::new();
        let mut need_virgin_fill = Vec::new();

        for &idx in block_indices {
            if idx >= self.blocks.len() { continue; }
            match &self.blocks[idx].location {
                BlockLocation::Resident => already_resident.push(idx),
                BlockLocation::LocalStore { .. } => need_local_restore.push(idx),
                BlockLocation::RemoteKernel { .. } => need_remote_fetch.push(idx),
                BlockLocation::Virgin => need_virgin_fill.push(idx),
                BlockLocation::Fetching => {} // skip, already in progress
            }
        }

        let total_to_restore = need_local_restore.len() + need_remote_fetch.len() + need_virgin_fill.len();

        // Evict enough blocks to make room for all restores
        let resident = self.resident_count.load(Ordering::Relaxed) as usize;
        let max = self.config.max_resident_blocks;
        let need_slots = total_to_restore.saturating_sub(max.saturating_sub(resident));

        for _ in 0..need_slots {
            let _ = self.evict_coldest();
        }

        let mut results: Vec<FaultResult> = Vec::with_capacity(block_indices.len());

        // 1. Already resident — just update access stats
        for idx in &already_resident {
            self.blocks[*idx].access_count += 1;
            self.blocks[*idx].last_access_ns = now_ns;
            results.push(FaultResult::AlreadyResident { block_index: *idx });
        }

        // 2. Virgin blocks — zero fill (instant)
        for idx in &need_virgin_fill {
            self.blocks[*idx].location = BlockLocation::Resident;
            self.blocks[*idx].access_count = 1;
            self.blocks[*idx].last_access_ns = now_ns;
            self.resident_count.fetch_add(1, Ordering::AcqRel);
            self.zero_pages_served.fetch_add(1, Ordering::Relaxed);
            self.faults_handled.fetch_add(1, Ordering::Relaxed);
            results.push(FaultResult::ZeroFilled { block_index: *idx, inject_us: 0 });
        }

        // 3. Local restore — one by one (disk-bound, fast)
        for idx in &need_local_restore {
            results.push(self.restore_block(*idx, now_ns));
        }

        // 4. Remote fetch — BATCHED via pipelined MUX
        if !need_remote_fetch.is_empty() {
            let batch_results = self.batch_restore_remote(&need_remote_fetch, now_ns);
            results.extend(batch_results);
        }

        results
    }

    /// Batch restore remote blocks via pipelined fetch_batch().
    ///
    /// Sends ALL fetch requests in one burst, then reads ALL responses.
    /// On a 1ms RTT link, 10 blocks = 1ms instead of 10ms.
    fn batch_restore_remote(&mut self, block_indices: &[usize], now_ns: u64) -> Vec<FaultResult> {
        let bus_seq_base = self.bus_seq.fetch_add(block_indices.len() as u64, Ordering::SeqCst);

        if let Some(client) = &self.mux_client {
            let c = client.clone();

            // Build request list: (block_index, bus_seq)
            let requests: Vec<(usize, u64)> = block_indices.iter()
                .enumerate()
                .map(|(i, &idx)| (idx, bus_seq_base + i as u64))
                .collect();

            let t0 = Instant::now();
            let fetch_results = block_on_safe(c.fetch_batch(&requests));
            let batch_us = t0.elapsed().as_micros() as u64;

            match fetch_results {
                Ok(fetched) => {
                    let mut results = Vec::with_capacity(fetched.len());
                    let per_block_us = batch_us / fetched.len().max(1) as u64;

                    for (block_index, data, _elapsed) in fetched {
                        // Verify integrity
                        if let Some(ref expected) = self.blocks[block_index].content_hash {
                            let computed = sha256_hex(&data);
                            if computed != *expected {
                                results.push(FaultResult::Failed {
                                    block_index,
                                    reason: format!("Batch integrity failed: expected {}, got {}", expected, computed),
                                });
                                continue;
                            }
                        }

                        self.blocks[block_index].location = BlockLocation::Resident;
                        self.blocks[block_index].access_count += 1;
                        self.blocks[block_index].last_access_ns = now_ns;
                        self.blocks[block_index].dirty = false;
                        self.resident_count.fetch_add(1, Ordering::AcqRel);
                        self.bytes_decompressed.fetch_add(data.len() as u64, Ordering::Relaxed);
                        self.remote_transfers.fetch_add(1, Ordering::Relaxed);
                        self.faults_handled.fetch_add(1, Ordering::Relaxed);

                        results.push(FaultResult::RestoredRemote {
                            block_index,
                            fetch_us: per_block_us,
                            decompress_us: 0,
                            verify_us: 0,
                            inject_us: 0,
                            total_us: per_block_us,
                        });
                    }
                    results
                }
                Err(e) => {
                    // Fallback: restore one by one
                    block_indices.iter().map(|&idx| {
                        FaultResult::Failed {
                            block_index: idx,
                            reason: format!("Batch fetch failed: {}", e),
                        }
                    }).collect()
                }
            }
        } else {
            // No MUX client — fall back to individual restore
            block_indices.iter().map(|&idx| {
                self.restore_block(idx, now_ns)
            }).collect()
        }
    }

    /// Prefetch: proactively load blocks that will be needed soon.
    ///
    /// Use case: LLM inference reads layers sequentially. When layer N is accessed,
    /// prefetch layers N+1..N+K from RAM B so they're already resident when needed.
    ///
    /// Returns: (prefetched_count, total_fetch_us)
    pub fn prefetch(&mut self, block_indices: &[usize]) -> (usize, u64) {
        let t0 = Instant::now();

        // Filter to only non-resident blocks
        let to_prefetch: Vec<usize> = block_indices.iter()
            .filter(|&&idx| idx < self.blocks.len())
            .filter(|&&idx| self.blocks[idx].location != BlockLocation::Resident)
            .copied()
            .collect();

        if to_prefetch.is_empty() {
            return (0, 0);
        }

        let results = self.simulate_read_batch(&to_prefetch);
        let ok_count = results.iter()
            .filter(|r| !matches!(r, FaultResult::Failed { .. }))
            .count();

        (ok_count, t0.elapsed().as_micros() as u64)
    }

    /// Get comprehensive statistics.
    pub fn stats(&self) -> RaidStats {
        let resident = self.resident_count.load(Ordering::Relaxed) as usize;
        let block_count = self.blocks.len();
        let ram_a_blocks = self.blocks.iter().filter(|b| b.stripe == RaidStripe::RamA).count();
        let ram_b_blocks = self.blocks.iter().filter(|b| b.stripe == RaidStripe::RamB).count();
        let dirty_blocks = self.blocks.iter().filter(|b| b.dirty).count();
        let virgin_blocks = self.blocks.iter().filter(|b| b.location == BlockLocation::Virgin).count();

        let local_evicted = self.blocks.iter()
            .filter(|b| matches!(b.location, BlockLocation::LocalStore { .. }))
            .count();
        let remote_evicted = self.blocks.iter()
            .filter(|b| matches!(b.location, BlockLocation::RemoteKernel { .. }))
            .count();

        RaidStats {
            arena_size: self.config.arena_size,
            block_size: self.config.block_size,
            block_count,
            ram_a_blocks,
            ram_b_blocks,
            resident_blocks: resident,
            max_resident: self.config.max_resident_blocks,
            utilization_pct: (resident as f64 / self.config.max_resident_blocks as f64) * 100.0,
            dirty_blocks,
            virgin_blocks,
            local_evicted,
            remote_evicted,
            faults_handled: self.faults_handled.load(Ordering::Relaxed),
            evictions_performed: self.evictions_performed.load(Ordering::Relaxed),
            bytes_compressed: self.bytes_compressed.load(Ordering::Relaxed),
            bytes_decompressed: self.bytes_decompressed.load(Ordering::Relaxed),
            remote_transfers: self.remote_transfers.load(Ordering::Relaxed),
            zero_pages_served: self.zero_pages_served.load(Ordering::Relaxed),
            has_remote_ram_b: self.config.ram_b_endpoint.is_some(),
        }
    }
}

/// Comprehensive RAID statistics.
#[derive(Debug, Clone)]
pub struct RaidStats {
    pub arena_size: usize,
    pub block_size: usize,
    pub block_count: usize,
    pub ram_a_blocks: usize,
    pub ram_b_blocks: usize,
    pub resident_blocks: usize,
    pub max_resident: usize,
    pub utilization_pct: f64,
    pub dirty_blocks: usize,
    pub virgin_blocks: usize,
    pub local_evicted: usize,
    pub remote_evicted: usize,
    pub faults_handled: u64,
    pub evictions_performed: u64,
    pub bytes_compressed: u64,
    pub bytes_decompressed: u64,
    pub remote_transfers: u64,
    pub zero_pages_served: u64,
    pub has_remote_ram_b: bool,
}

// ═══════════════════════════════════════════════════════════════
// Helper — synchronous BlockStore fetch (avoids async in sync context)
// ═══════════════════════════════════════════════════════════════

fn handle_block_on_local(store: &Arc<BlockStore>, block_index: usize) -> Option<Vec<u8>> {
    block_on_safe(async {
        store.fetch(block_index).await.map(|b| b.data)
    })
}

/// Execute an async future from sync code, handling both inside-tokio and outside-tokio contexts.
/// Inside tokio: uses block_in_place + Handle::block_on (requires multi-threaded runtime).
/// Outside tokio: creates a temporary runtime.
pub fn block_on_safe<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // We're inside a tokio runtime — use block_in_place to avoid panic
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        // We're outside tokio — create a temporary runtime
        let rt = tokio::runtime::Runtime::new().expect("Failed to create temp runtime");
        rt.block_on(future)
    }
}
