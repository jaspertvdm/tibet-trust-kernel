//! Trust Kernel v1 — Seccomp-BPF + Zandbak Benchmark
//! Tests: filter compilation, syscall validation, memory sandboxing

use std::time::Instant;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ═══════════════════════════════════════════════════════════════
// Inline Seccomp logic
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
enum Syscall {
    Read=0, Write=1, Open=2, Close=3, Stat=4, Fstat=5, Poll=7,
    Mmap=9, Mprotect=10, Brk=12, Ioctl=16, Access=21, Pipe=22,
    Select=23, SchedYield=24, Dup=32, Dup2=33, Getpid=39,
    Socket=41, Connect=42, Accept=43, Sendto=44, Recvfrom=45,
    Bind=49, Listen=50, Clone=56, Fork=57, Execve=59, Exit=60,
    Fcntl=72, Getdents=78, Getcwd=79, Ptrace=101, Getuid=102,
    Mount=165, Reboot=169, Kexec=246, ExitGroup=231, Openat=257,
}

const BASE_ALLOWED: &[Syscall] = &[
    Syscall::Read, Syscall::Write, Syscall::Close, Syscall::Fstat,
    Syscall::Brk, Syscall::Mprotect, Syscall::Exit, Syscall::ExitGroup,
    Syscall::Getcwd, Syscall::Access, Syscall::Fcntl, Syscall::Dup,
    Syscall::Dup2, Syscall::SchedYield, Syscall::Getuid, Syscall::Getpid,
];

const ALWAYS_DENIED: &[Syscall] = &[
    Syscall::Ptrace, Syscall::Mount, Syscall::Reboot, Syscall::Kexec,
];

struct SeccompFilter {
    intent: String,
    allowed: Vec<Syscall>,
    instruction_count: usize,
}

fn compile_filter(intent: &str) -> SeccompFilter {
    let mut allowed = BASE_ALLOWED.to_vec();
    let extra: &[Syscall] = match intent {
        "code:execute" => &[Syscall::Open, Syscall::Openat, Syscall::Stat, Syscall::Mmap, Syscall::Pipe, Syscall::Select],
        "file:scan" => &[Syscall::Open, Syscall::Openat, Syscall::Stat, Syscall::Getdents],
        i if i.starts_with("shell:") => &[Syscall::Open, Syscall::Openat, Syscall::Stat, Syscall::Ioctl, Syscall::Pipe, Syscall::Select, Syscall::Poll],
        i if i.starts_with("http:") => &[Syscall::Open, Syscall::Openat, Syscall::Stat, Syscall::Socket, Syscall::Connect, Syscall::Bind, Syscall::Listen, Syscall::Accept, Syscall::Sendto, Syscall::Recvfrom, Syscall::Mmap, Syscall::Poll, Syscall::Select],
        i if i.starts_with("db:") => &[Syscall::Open, Syscall::Openat, Syscall::Stat, Syscall::Socket, Syscall::Connect, Syscall::Sendto, Syscall::Recvfrom, Syscall::Poll, Syscall::Select],
        i if i.starts_with("ai:") => &[Syscall::Open, Syscall::Openat, Syscall::Stat, Syscall::Socket, Syscall::Connect, Syscall::Sendto, Syscall::Recvfrom, Syscall::Mmap, Syscall::Poll],
        "math_calculation" => &[Syscall::Mmap],
        _ => &[],
    };
    for s in extra {
        if !allowed.contains(s) { allowed.push(*s); }
    }
    let insn_count = allowed.len() + 5; // arch check + load + JEQs + KILL + ALLOW
    SeccompFilter { intent: intent.to_string(), allowed, instruction_count: insn_count }
}

fn validate_syscall(filter: &SeccompFilter, nr: u32) -> bool {
    for denied in ALWAYS_DENIED {
        if *denied as u32 == nr { return false; }
    }
    filter.allowed.iter().any(|s| *s as u32 == nr)
}

fn validate_sequence(filter: &SeccompFilter, syscalls: &[u32]) -> usize {
    syscalls.iter().filter(|nr| !validate_syscall(filter, **nr)).count()
}

// ═══════════════════════════════════════════════════════════════
// Inline Zandbak logic
// ═══════════════════════════════════════════════════════════════

const PAGE_SIZE: usize = 4096;
const HUGEPAGE_SIZE: usize = 2 * 1024 * 1024;

struct MemoryBudget {
    work_region_bytes: usize,
    use_hugepages: bool,
    max_allocations: usize,
}

fn memory_budget(intent: &str) -> MemoryBudget {
    match intent {
        "math_calculation" => MemoryBudget { work_region_bytes: 4*1024*1024, use_hugepages: false, max_allocations: 64 },
        "code:execute" => MemoryBudget { work_region_bytes: 64*1024*1024, use_hugepages: true, max_allocations: 1024 },
        i if i.starts_with("ai:") => MemoryBudget { work_region_bytes: 512*1024*1024, use_hugepages: true, max_allocations: 4096 },
        i if i.starts_with("http:") => MemoryBudget { work_region_bytes: 32*1024*1024, use_hugepages: false, max_allocations: 1024 },
        _ => MemoryBudget { work_region_bytes: 8*1024*1024, use_hugepages: false, max_allocations: 128 },
    }
}

struct SandboxRegion {
    budget: MemoryBudget,
    allocated: AtomicU64,
    alloc_count: AtomicU64,
    is_clean: AtomicBool,
    page_size: usize,
}

enum AllocResult { Success { offset: usize, remaining: usize }, BudgetExceeded, LimitReached, Dirty }

impl SandboxRegion {
    fn new(intent: &str) -> Self {
        let budget = memory_budget(intent);
        let ps = if budget.use_hugepages { HUGEPAGE_SIZE } else { PAGE_SIZE };
        Self { budget, allocated: AtomicU64::new(0), alloc_count: AtomicU64::new(0), is_clean: AtomicBool::new(true), page_size: ps }
    }
    fn allocate(&self, size: usize) -> AllocResult {
        if !self.is_clean.load(Ordering::Acquire) { return AllocResult::Dirty; }
        let count = self.alloc_count.load(Ordering::Acquire);
        if count >= self.budget.max_allocations as u64 { return AllocResult::LimitReached; }
        let aligned = (size + self.page_size - 1) & !(self.page_size - 1);
        let current = self.allocated.load(Ordering::Acquire);
        if current + aligned as u64 > self.budget.work_region_bytes as u64 { return AllocResult::BudgetExceeded; }
        let offset = self.allocated.fetch_add(aligned as u64, Ordering::AcqRel) as usize;
        self.alloc_count.fetch_add(1, Ordering::AcqRel);
        self.is_clean.store(false, Ordering::Release);
        AllocResult::Success { offset, remaining: self.budget.work_region_bytes - offset - aligned }
    }
    fn zerofill(&self) -> u64 {
        let bytes = self.allocated.load(Ordering::Acquire);
        let simulated_ns = bytes / 8;
        self.allocated.store(0, Ordering::Release);
        self.alloc_count.store(0, Ordering::Release);
        self.is_clean.store(true, Ordering::Release);
        simulated_ns
    }
}

// ═══════════════════════════════════════════════════════════════
// Benchmark
// ═══════════════════════════════════════════════════════════════

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

struct R { name: String, avg_ns: f64, p50_ns: f64, p95_ns: f64, p99_ns: f64 }

fn bench_ns(name: &str, n: usize, f: impl Fn()) -> R {
    for _ in 0..200 { f(); }
    let mut times: Vec<f64> = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        f();
        times.push(t0.elapsed().as_nanos() as f64);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    R { name: name.to_string(), avg_ns: times.iter().sum::<f64>()/times.len() as f64,
        p50_ns: percentile(&times, 50.0), p95_ns: percentile(&times, 95.0), p99_ns: percentile(&times, 99.0) }
}

fn pr(r: &R) {
    println!("  {:52} avg={:>6.0}ns  p50={:>6.0}ns  p95={:>6.0}ns  p99={:>6.0}ns  ({:.2}µs)",
        r.name, r.avg_ns, r.p50_ns, r.p95_ns, r.p99_ns, r.avg_ns / 1000.0);
}

fn main() {
    let n = 100_000;

    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════");
    println!("◈ TRUST KERNEL v1 — Seccomp-BPF + Zandbak Benchmark");
    println!("◈ Kernel-level syscall enforcement + memory hardening");
    println!("◈ {} iteraties per test", n);
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════\n");

    // ─── Seccomp-BPF ───
    println!("◈ DEEL 1: Seccomp-BPF filter compilation + validation");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    let r1 = bench_ns("Compile filter: code:execute", n, || {
        std::hint::black_box(compile_filter("code:execute"));
    });
    pr(&r1);

    let r2 = bench_ns("Compile filter: http:api:get", n, || {
        std::hint::black_box(compile_filter("http:api:get"));
    });
    pr(&r2);

    let r3 = bench_ns("Compile filter: math_calculation", n, || {
        std::hint::black_box(compile_filter("math_calculation"));
    });
    pr(&r3);

    let r4 = bench_ns("Compile filter: ai:inference", n, || {
        std::hint::black_box(compile_filter("ai:inference"));
    });
    pr(&r4);

    let filter_code = compile_filter("code:execute");
    let filter_http = compile_filter("http:api:get");
    let filter_math = compile_filter("math_calculation");

    let r5 = bench_ns("Validate: read(0) on code:execute → ALLOW", n, || {
        std::hint::black_box(validate_syscall(&filter_code, 0)); // read
    });
    pr(&r5);

    let r6 = bench_ns("Validate: ptrace(101) on code:execute → DENY", n, || {
        std::hint::black_box(validate_syscall(&filter_code, 101)); // ptrace
    });
    pr(&r6);

    let r7 = bench_ns("Validate: socket(41) on math → DENY", n, || {
        std::hint::black_box(validate_syscall(&filter_math, 41)); // socket
    });
    pr(&r7);

    let r8 = bench_ns("Validate: socket(41) on http → ALLOW", n, || {
        std::hint::black_box(validate_syscall(&filter_http, 41)); // socket
    });
    pr(&r8);

    // Validate a typical execution sequence
    let safe_sequence = vec![59u32, 0, 1, 2, 3, 12, 10, 0, 1, 60]; // execve, read, write, open, close, brk, mprotect, read, write, exit
    let attack_sequence = vec![59u32, 0, 41, 42, 1, 101, 60]; // execve, read, socket, connect, write, ptrace, exit

    let r9 = bench_ns("Validate sequence: 10 safe syscalls", n, || {
        std::hint::black_box(validate_sequence(&filter_code, &safe_sequence));
    });
    pr(&r9);

    let r10 = bench_ns("Validate sequence: 7 syscalls (2 denied)", n, || {
        std::hint::black_box(validate_sequence(&filter_code, &attack_sequence));
    });
    pr(&r10);

    // ─── Zandbak ───
    println!("\n◈ DEEL 2: Zandbak memory hardening");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    let r11 = bench_ns("Create sandbox: code:execute (64MB, HugePages)", n, || {
        std::hint::black_box(SandboxRegion::new("code:execute"));
    });
    pr(&r11);

    let r12 = bench_ns("Create sandbox: math_calculation (4MB)", n, || {
        std::hint::black_box(SandboxRegion::new("math_calculation"));
    });
    pr(&r12);

    let r13 = bench_ns("Create sandbox: ai:inference (512MB, HugePages)", n, || {
        std::hint::black_box(SandboxRegion::new("ai:inference"));
    });
    pr(&r13);

    let sandbox = SandboxRegion::new("code:execute");
    let r14 = bench_ns("Allocate 4KB in sandbox (page-aligned)", n, || {
        // Reset for each iteration
        sandbox.allocated.store(0, Ordering::Relaxed);
        sandbox.alloc_count.store(0, Ordering::Relaxed);
        sandbox.is_clean.store(true, Ordering::Relaxed);
        std::hint::black_box(sandbox.allocate(4096));
    });
    pr(&r14);

    let r15 = bench_ns("Allocate 2MB in HugePages sandbox", n, || {
        sandbox.allocated.store(0, Ordering::Relaxed);
        sandbox.alloc_count.store(0, Ordering::Relaxed);
        sandbox.is_clean.store(true, Ordering::Relaxed);
        std::hint::black_box(sandbox.allocate(2 * 1024 * 1024));
    });
    pr(&r15);

    let r16 = bench_ns("Budget check: exceed 64MB → DENIED", n, || {
        sandbox.allocated.store(63 * 1024 * 1024, Ordering::Relaxed);
        sandbox.alloc_count.store(1, Ordering::Relaxed);
        sandbox.is_clean.store(true, Ordering::Relaxed);
        std::hint::black_box(sandbox.allocate(2 * 1024 * 1024)); // would exceed
    });
    pr(&r16);

    let r17 = bench_ns("Zerofill 64MB sandbox (simulated)", n, || {
        sandbox.allocated.store(64 * 1024 * 1024, Ordering::Relaxed);
        sandbox.alloc_count.store(100, Ordering::Relaxed);
        sandbox.is_clean.store(false, Ordering::Relaxed);
        std::hint::black_box(sandbox.zerofill());
    });
    pr(&r17);

    // ─── Combined: seccomp + zandbak per intent ───
    println!("\n◈ DEEL 3: Combined — compile filter + create sandbox per intent");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    let intents = [
        "code:execute", "http:api:get", "shell:session",
        "db:query", "ai:inference", "math_calculation",
    ];

    for intent in &intents {
        let r = bench_ns(&format!("Setup: {}", intent), n, || {
            let filter = compile_filter(intent);
            let sandbox = SandboxRegion::new(intent);
            std::hint::black_box((&filter, &sandbox));
        });
        pr(&r);
    }

    // ─── Summary ───
    println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════════════");
    println!("◈ SAMENVATTING");
    println!("  ───────────────────────────────────────────────────────────────────────────────────────────────────");

    println!("  Seccomp filter compilatie:    avg {:.0}ns ({:.2}µs)", r1.avg_ns, r1.avg_ns/1000.0);
    println!("  Syscall validatie (single):   avg {:.0}ns", r5.avg_ns);
    println!("  Syscall validatie (sequence):  avg {:.0}ns ({:.0}ns/syscall)", r9.avg_ns, r9.avg_ns/10.0);
    println!("  Sandbox creatie:              avg {:.0}ns ({:.2}µs)", r11.avg_ns, r11.avg_ns/1000.0);
    println!("  Sandbox allocatie:            avg {:.0}ns", r14.avg_ns);
    println!("  Budget enforcement:           avg {:.0}ns", r16.avg_ns);
    println!();

    // Filter complexity
    println!("  Seccomp filter complexiteit per intent:");
    for intent in &intents {
        let f = compile_filter(intent);
        let has_net = f.allowed.iter().any(|s| matches!(s, Syscall::Socket|Syscall::Connect|Syscall::Sendto));
        let has_fs = f.allowed.iter().any(|s| matches!(s, Syscall::Open|Syscall::Openat));
        println!("    {:24} {:>2} syscalls allowed  {:>2} BPF insns  net={:5}  fs={:5}",
            intent, f.allowed.len(), f.instruction_count,
            if has_net { "yes" } else { "no" },
            if has_fs { "yes" } else { "no" });
    }
    println!();

    // Memory budgets
    println!("  Zandbak memory budgets per intent:");
    for intent in &intents {
        let b = memory_budget(intent);
        println!("    {:24} {:>5}MB work  {:>5} max allocs  hugepages={}",
            intent, b.work_region_bytes / (1024*1024), b.max_allocations,
            if b.use_hugepages { "yes" } else { "no " });
    }

    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════");
}
