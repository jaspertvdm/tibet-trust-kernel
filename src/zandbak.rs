use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// De Onbuigzame Zandbak — Memory hardening for the Trust Kernel.
///
/// The sandbox enforces:
/// 1. Fixed memory allocation (no dynamic growth)
/// 2. Guard pages around allocations (detect overflow/underflow)
/// 3. Zero-fill on deallocation (no data leakage between requests)
/// 4. HugePages support (2MB pages → fewer TLB misses)
/// 5. Memory budget per intent (prevent resource exhaustion)
///
/// Memory layout:
///   ┌─────────┐
///   │ GUARD   │ ← read/write protected (PROT_NONE)
///   ├─────────┤
///   │         │
///   │ WORK    │ ← the actual usable memory region
///   │ REGION  │
///   │         │
///   ├─────────┤
///   │ GUARD   │ ← read/write protected (PROT_NONE)
///   └─────────┘
///
/// On overflow: guard page triggers SIGSEGV → caught by watchdog → KILL + TIBET event.
/// On deallocation: entire work region is zeroed before reuse.
///
/// "Vaste RAM/swap, buffer overflow → 0x00" — Jasper

// ═══════════════════════════════════════════════════════════════
// Memory budget per intent category
// ═══════════════════════════════════════════════════════════════

/// Memory budget in bytes for each intent category.
/// Prevents a single request from consuming all available memory.
pub fn memory_budget(intent: &str) -> MemoryBudget {
    match intent {
        // Pure computation: small memory, no I/O
        "math_calculation" => MemoryBudget {
            work_region_bytes: 4 * 1024 * 1024,     // 4 MB
            stack_bytes: 512 * 1024,                  // 512 KB
            use_hugepages: false,
            max_allocations: 64,
        },

        // Code execution: moderate memory
        "code:execute" => MemoryBudget {
            work_region_bytes: 64 * 1024 * 1024,    // 64 MB
            stack_bytes: 2 * 1024 * 1024,             // 2 MB
            use_hugepages: true,
            max_allocations: 1024,
        },

        // File scan: read buffers
        "file:scan" => MemoryBudget {
            work_region_bytes: 32 * 1024 * 1024,    // 32 MB
            stack_bytes: 1 * 1024 * 1024,             // 1 MB
            use_hugepages: false,
            max_allocations: 256,
        },

        // AI inference: large for model weights
        i if i.starts_with("ai:") => MemoryBudget {
            work_region_bytes: 512 * 1024 * 1024,   // 512 MB
            stack_bytes: 4 * 1024 * 1024,             // 4 MB
            use_hugepages: true,                      // Critical for matrix ops
            max_allocations: 4096,
        },

        // Database queries: moderate
        i if i.starts_with("db:") => MemoryBudget {
            work_region_bytes: 16 * 1024 * 1024,    // 16 MB
            stack_bytes: 1 * 1024 * 1024,
            use_hugepages: false,
            max_allocations: 512,
        },

        // HTTP: moderate with buffer room
        i if i.starts_with("http:") => MemoryBudget {
            work_region_bytes: 32 * 1024 * 1024,    // 32 MB
            stack_bytes: 2 * 1024 * 1024,
            use_hugepages: false,
            max_allocations: 1024,
        },

        // Shell session: moderate
        i if i.starts_with("shell:") => MemoryBudget {
            work_region_bytes: 32 * 1024 * 1024,
            stack_bytes: 2 * 1024 * 1024,
            use_hugepages: false,
            max_allocations: 512,
        },

        // Voice/video: large for media buffers
        i if i.starts_with("call:") => MemoryBudget {
            work_region_bytes: 128 * 1024 * 1024,   // 128 MB
            stack_bytes: 2 * 1024 * 1024,
            use_hugepages: true,
            max_allocations: 2048,
        },

        // Default: conservative
        _ => MemoryBudget {
            work_region_bytes: 8 * 1024 * 1024,     // 8 MB
            stack_bytes: 512 * 1024,
            use_hugepages: false,
            max_allocations: 128,
        },
    }
}

#[derive(Debug, Clone)]
pub struct MemoryBudget {
    /// Maximum bytes for the work region
    pub work_region_bytes: usize,
    /// Stack size for the sandboxed process
    pub stack_bytes: usize,
    /// Whether to request 2MB HugePages (MAP_HUGETLB)
    pub use_hugepages: bool,
    /// Maximum number of distinct allocations
    pub max_allocations: usize,
}

// ═══════════════════════════════════════════════════════════════
// Zandbak — The sandbox memory manager
// ═══════════════════════════════════════════════════════════════

/// Page size constants
pub const PAGE_SIZE: usize = 4096;
pub const HUGEPAGE_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// A managed memory region with guard pages.
#[derive(Debug)]
pub struct SandboxRegion {
    /// Intent this region was created for
    pub intent: String,
    /// Budget constraints
    pub budget: MemoryBudget,
    /// Total allocated bytes in work region
    pub allocated_bytes: AtomicU64,
    /// Number of allocations
    pub allocation_count: AtomicU64,
    /// Whether this region has been zeroed since last use
    pub is_clean: AtomicBool,
    /// Whether guard pages are active
    pub guards_active: AtomicBool,
    /// Page size used (4KB or 2MB for HugePages)
    pub effective_page_size: usize,
}

/// Result of a sandbox allocation attempt.
#[derive(Debug, Clone)]
pub enum AllocResult {
    /// Allocation succeeded
    Success {
        offset: usize,
        size: usize,
        remaining_bytes: usize,
        remaining_allocations: usize,
    },
    /// Allocation denied: budget exceeded
    BudgetExceeded {
        requested: usize,
        available: usize,
    },
    /// Allocation denied: too many allocations
    AllocationLimitReached {
        current: usize,
        max: usize,
    },
    /// Allocation denied: region is dirty (needs zero-fill first)
    RegionDirty,
}

/// What happens on zero-fill.
#[derive(Debug, Clone, Copy)]
pub enum ZerofillEvent {
    /// Routine cleanup (normal deallocation)
    Routine { bytes_zeroed: usize, duration_ns: u64 },
    /// Emergency cleanup (after overflow/crash)
    Emergency { bytes_zeroed: usize, duration_ns: u64, triggered_by: &'static str },
    /// Skip (fast profile, only on exit)
    Skipped,
}

impl SandboxRegion {
    /// Create a new sandbox region for an intent.
    pub fn new(intent: &str) -> Self {
        let budget = memory_budget(intent);
        let page_size = if budget.use_hugepages { HUGEPAGE_SIZE } else { PAGE_SIZE };

        Self {
            intent: intent.to_string(),
            budget,
            allocated_bytes: AtomicU64::new(0),
            allocation_count: AtomicU64::new(0),
            is_clean: AtomicBool::new(true),
            guards_active: AtomicBool::new(true),
            effective_page_size: page_size,
        }
    }

    /// Attempt to allocate memory within this sandbox.
    pub fn allocate(&self, size: usize) -> AllocResult {
        if !self.is_clean.load(Ordering::Acquire) {
            return AllocResult::RegionDirty;
        }

        let current_allocs = self.allocation_count.load(Ordering::Acquire);
        if current_allocs >= self.budget.max_allocations as u64 {
            return AllocResult::AllocationLimitReached {
                current: current_allocs as usize,
                max: self.budget.max_allocations,
            };
        }

        // Align size to page boundary
        let aligned_size = align_to_page(size, self.effective_page_size);
        let current_bytes = self.allocated_bytes.load(Ordering::Acquire);

        if current_bytes + aligned_size as u64 > self.budget.work_region_bytes as u64 {
            return AllocResult::BudgetExceeded {
                requested: aligned_size,
                available: self.budget.work_region_bytes - current_bytes as usize,
            };
        }

        // Commit allocation
        let offset = self.allocated_bytes.fetch_add(aligned_size as u64, Ordering::AcqRel) as usize;
        self.allocation_count.fetch_add(1, Ordering::AcqRel);
        self.is_clean.store(false, Ordering::Release);

        let remaining_bytes = self.budget.work_region_bytes - (offset + aligned_size);
        let remaining_allocs = self.budget.max_allocations - (current_allocs as usize + 1);

        AllocResult::Success {
            offset,
            size: aligned_size,
            remaining_bytes,
            remaining_allocations: remaining_allocs,
        }
    }

    /// Zero-fill the entire work region.
    /// In production: memset(region, 0, size) on the mmap'd region.
    /// Here: simulates the cost.
    pub fn zerofill(&self, policy: ZerofillPolicy) -> ZerofillEvent {
        match policy {
            ZerofillPolicy::EveryDealloc => {
                let bytes = self.allocated_bytes.load(Ordering::Acquire) as usize;
                let t0 = std::time::Instant::now();
                // Simulate: in real implementation this is memset(ptr, 0, bytes)
                // Cost: ~1ns per 8 bytes (cache line fills)
                let simulated_ns = (bytes as u64) / 8;
                self.allocated_bytes.store(0, Ordering::Release);
                self.allocation_count.store(0, Ordering::Release);
                self.is_clean.store(true, Ordering::Release);
                ZerofillEvent::Routine {
                    bytes_zeroed: bytes,
                    duration_ns: simulated_ns.max(t0.elapsed().as_nanos() as u64),
                }
            }
            ZerofillPolicy::OnExit => {
                // Only zero on region destruction, not per-request
                ZerofillEvent::Skipped
            }
            ZerofillPolicy::Never => {
                ZerofillEvent::Skipped
            }
        }
    }

    /// Emergency zero-fill (after overflow or crash).
    /// Zeros the ENTIRE budget, not just allocated bytes.
    pub fn emergency_zerofill(&self, reason: &'static str) -> ZerofillEvent {
        let bytes = self.budget.work_region_bytes;
        let t0 = std::time::Instant::now();
        let simulated_ns = (bytes as u64) / 8;
        self.allocated_bytes.store(0, Ordering::Release);
        self.allocation_count.store(0, Ordering::Release);
        self.is_clean.store(true, Ordering::Release);
        ZerofillEvent::Emergency {
            bytes_zeroed: bytes,
            duration_ns: simulated_ns.max(t0.elapsed().as_nanos() as u64),
            triggered_by: reason,
        }
    }

    /// Get current usage stats.
    pub fn usage(&self) -> SandboxUsage {
        let allocated = self.allocated_bytes.load(Ordering::Relaxed) as usize;
        let alloc_count = self.allocation_count.load(Ordering::Relaxed) as usize;
        SandboxUsage {
            intent: self.intent.clone(),
            allocated_bytes: allocated,
            budget_bytes: self.budget.work_region_bytes,
            utilization_pct: (allocated as f64 / self.budget.work_region_bytes as f64) * 100.0,
            allocation_count: alloc_count,
            max_allocations: self.budget.max_allocations,
            page_size: self.effective_page_size,
            hugepages: self.budget.use_hugepages,
            is_clean: self.is_clean.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ZerofillPolicy {
    /// Zero after every request (paranoid)
    EveryDealloc,
    /// Zero only when the region is destroyed (balanced)
    OnExit,
    /// Never zero (fast, for dev/test)
    Never,
}

#[derive(Debug, Clone)]
pub struct SandboxUsage {
    pub intent: String,
    pub allocated_bytes: usize,
    pub budget_bytes: usize,
    pub utilization_pct: f64,
    pub allocation_count: usize,
    pub max_allocations: usize,
    pub page_size: usize,
    pub hugepages: bool,
    pub is_clean: bool,
}

/// Align a size up to the nearest page boundary.
fn align_to_page(size: usize, page_size: usize) -> usize {
    (size + page_size - 1) & !(page_size - 1)
}
