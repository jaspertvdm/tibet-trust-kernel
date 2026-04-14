use std::collections::HashMap;

/// Seccomp-BPF — Kernel-level syscall enforcement per intent.
///
/// While SNAFT monitors syscalls at the application level (pattern detection),
/// seccomp-BPF enforces at the Linux kernel level. A blocked syscall never
/// executes — the kernel kills it in nanoseconds.
///
/// Architecture:
///   1. PortMux infers intent (e.g., "http:api:get")
///   2. Voorproever validates with SNAFT
///   3. Seccomp-BPF loads a filter matching that intent
///   4. The process runs with ONLY the allowed syscalls
///   5. Any forbidden syscall → SECCOMP_RET_KILL_THREAD
///
/// This is defense-in-depth: even if an attacker bypasses SNAFT,
/// the kernel itself blocks the syscall. Two independent layers.
///
/// In simulation mode: validates filter logic without loading BPF.
/// In production mode: loads via prctl(PR_SET_SECCOMP) or libseccomp.

// ═══════════════════════════════════════════════════════════════
// Syscall numbers (x86_64 Linux)
// ═══════════════════════════════════════════════════════════════

/// x86_64 syscall numbers (subset relevant to Trust Kernel)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Syscall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Fstat = 5,
    Poll = 7,
    Mmap = 9,
    Mprotect = 10,
    Brk = 12,
    Ioctl = 16,
    Access = 21,
    Pipe = 22,
    Select = 23,
    SchedYield = 24,
    Dup = 32,
    Dup2 = 33,
    Getpid = 39,
    Socket = 41,
    Connect = 42,
    Accept = 43,
    Sendto = 44,
    Recvfrom = 45,
    Bind = 49,
    Listen = 50,
    Clone = 56,
    Fork = 57,
    Execve = 59,
    Exit = 60,
    Fcntl = 72,
    Getdents = 78,
    Getcwd = 79,
    Chdir = 80,
    Mkdir = 83,
    Rmdir = 84,
    Unlink = 87,
    Chmod = 90,
    Chown = 92,
    Ptrace = 101,
    Getuid = 102,
    Syslog = 103,
    Setuid = 105,
    Mount = 165,
    Reboot = 169,
    Kexec = 246,
    ExitGroup = 231,
    Openat = 257,
}

impl Syscall {
    pub fn from_nr(nr: u32) -> Option<Self> {
        match nr {
            0 => Some(Self::Read), 1 => Some(Self::Write), 2 => Some(Self::Open),
            3 => Some(Self::Close), 4 => Some(Self::Stat), 5 => Some(Self::Fstat),
            7 => Some(Self::Poll), 9 => Some(Self::Mmap), 10 => Some(Self::Mprotect),
            12 => Some(Self::Brk), 16 => Some(Self::Ioctl), 21 => Some(Self::Access),
            22 => Some(Self::Pipe), 23 => Some(Self::Select), 24 => Some(Self::SchedYield),
            32 => Some(Self::Dup), 33 => Some(Self::Dup2), 39 => Some(Self::Getpid),
            41 => Some(Self::Socket), 42 => Some(Self::Connect), 43 => Some(Self::Accept),
            44 => Some(Self::Sendto), 45 => Some(Self::Recvfrom),
            49 => Some(Self::Bind), 50 => Some(Self::Listen),
            56 => Some(Self::Clone), 57 => Some(Self::Fork), 59 => Some(Self::Execve),
            60 => Some(Self::Exit), 72 => Some(Self::Fcntl), 78 => Some(Self::Getdents),
            79 => Some(Self::Getcwd), 80 => Some(Self::Chdir),
            83 => Some(Self::Mkdir), 84 => Some(Self::Rmdir), 87 => Some(Self::Unlink),
            90 => Some(Self::Chmod), 92 => Some(Self::Chown),
            101 => Some(Self::Ptrace), 102 => Some(Self::Getuid),
            103 => Some(Self::Syslog), 105 => Some(Self::Setuid),
            165 => Some(Self::Mount), 169 => Some(Self::Reboot), 246 => Some(Self::Kexec),
            231 => Some(Self::ExitGroup), 257 => Some(Self::Openat),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Read => "read", Self::Write => "write", Self::Open => "open",
            Self::Close => "close", Self::Stat => "stat", Self::Fstat => "fstat",
            Self::Poll => "poll", Self::Mmap => "mmap", Self::Mprotect => "mprotect",
            Self::Brk => "brk", Self::Ioctl => "ioctl", Self::Access => "access",
            Self::Pipe => "pipe", Self::Select => "select", Self::SchedYield => "sched_yield",
            Self::Dup => "dup", Self::Dup2 => "dup2", Self::Getpid => "getpid",
            Self::Socket => "socket", Self::Connect => "connect", Self::Accept => "accept",
            Self::Sendto => "sendto", Self::Recvfrom => "recvfrom",
            Self::Bind => "bind", Self::Listen => "listen",
            Self::Clone => "clone", Self::Fork => "fork", Self::Execve => "execve",
            Self::Exit => "exit", Self::Fcntl => "fcntl", Self::Getdents => "getdents",
            Self::Getcwd => "getcwd", Self::Chdir => "chdir",
            Self::Mkdir => "mkdir", Self::Rmdir => "rmdir", Self::Unlink => "unlink",
            Self::Chmod => "chmod", Self::Chown => "chown",
            Self::Ptrace => "ptrace", Self::Getuid => "getuid",
            Self::Syslog => "syslog", Self::Setuid => "setuid",
            Self::Mount => "mount", Self::Reboot => "reboot", Self::Kexec => "kexec_load",
            Self::ExitGroup => "exit_group", Self::Openat => "openat",
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Seccomp BPF filter representation
// ═══════════════════════════════════════════════════════════════

/// BPF instruction (simplified sock_filter struct)
/// Real BPF: struct { u16 code; u8 jt; u8 jf; u32 k; }
#[derive(Debug, Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// BPF instruction codes
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp return values
const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
const SECCOMP_RET_ALLOW: u32 = 0x7FFF0000;
const SECCOMP_RET_LOG: u32 = 0x7FFC0000;

// seccomp_data offsets
const SECCOMP_DATA_NR: u32 = 0; // syscall number offset
const SECCOMP_DATA_ARCH: u32 = 4; // arch offset

// x86_64 audit arch
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

/// A compiled seccomp-BPF filter for a specific intent.
#[derive(Debug, Clone)]
pub struct SeccompFilter {
    pub intent: String,
    pub instructions: Vec<BpfInsn>,
    pub allowed_syscalls: Vec<Syscall>,
    pub denied_syscalls: Vec<Syscall>,
    /// Number of BPF instructions (complexity metric)
    pub instruction_count: usize,
}

// ═══════════════════════════════════════════════════════════════
// Intent → Seccomp filter compiler
// ═══════════════════════════════════════════════════════════════

/// Base syscalls allowed for ALL intents (minimal process operation)
const BASE_ALLOWED: &[Syscall] = &[
    Syscall::Read, Syscall::Write, Syscall::Close,
    Syscall::Fstat, Syscall::Brk, Syscall::Mprotect,
    Syscall::Exit, Syscall::ExitGroup, Syscall::Getcwd,
    Syscall::Access, Syscall::Fcntl, Syscall::Dup, Syscall::Dup2,
    Syscall::SchedYield, Syscall::Getuid, Syscall::Getpid,
];

/// Syscalls that are ALWAYS denied (regardless of intent)
const ALWAYS_DENIED: &[Syscall] = &[
    Syscall::Ptrace,
    Syscall::Mount,
    Syscall::Reboot,
    Syscall::Kexec,
    Syscall::Syslog,
    Syscall::Setuid,
];

/// Compile a seccomp-BPF filter for a given intent.
/// Returns the filter ready to be loaded via prctl().
pub fn compile_filter(intent: &str) -> SeccompFilter {
    let mut allowed: Vec<Syscall> = BASE_ALLOWED.to_vec();

    // Add intent-specific syscalls
    let extra: &[Syscall] = match intent {
        // Code execution: file I/O, no network
        "code:execute" => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Mmap, Syscall::Pipe, Syscall::Select,
        ],

        // File scanning: directory listing, read-only
        "file:scan" => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Getdents,
        ],

        // SSH session: process management, TTY
        i if i.starts_with("shell:") => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Ioctl, Syscall::Pipe, Syscall::Select,
            Syscall::Poll,
        ],

        // HTTP: network + file I/O
        i if i.starts_with("http:") => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Socket, Syscall::Connect, Syscall::Bind,
            Syscall::Listen, Syscall::Accept,
            Syscall::Sendto, Syscall::Recvfrom,
            Syscall::Mmap, Syscall::Poll, Syscall::Select,
        ],

        // TLS: same as HTTP (TLS runs over TCP)
        i if i.starts_with("tls:") => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Socket, Syscall::Connect,
            Syscall::Sendto, Syscall::Recvfrom,
            Syscall::Mmap,
        ],

        // Database: network + limited file
        i if i.starts_with("db:") => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Socket, Syscall::Connect,
            Syscall::Sendto, Syscall::Recvfrom,
            Syscall::Poll, Syscall::Select,
        ],

        // DNS: UDP network only
        i if i.starts_with("dns:") => &[
            Syscall::Socket, Syscall::Sendto, Syscall::Recvfrom,
        ],

        // AI inference: network + mmap (model loading)
        i if i.starts_with("ai:") => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Socket, Syscall::Connect,
            Syscall::Sendto, Syscall::Recvfrom,
            Syscall::Mmap, Syscall::Poll,
        ],

        // Voice/video: network + ioctl (audio/video devices)
        i if i.starts_with("call:") => &[
            Syscall::Socket, Syscall::Connect, Syscall::Bind,
            Syscall::Sendto, Syscall::Recvfrom,
            Syscall::Ioctl, Syscall::Mmap, Syscall::Poll,
        ],

        // Math: pure computation, no I/O
        "math_calculation" => &[
            Syscall::Mmap,
        ],

        // Data transform/validate: file I/O only
        i if i.starts_with("data:") => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Mmap,
        ],

        // Metrics: limited network
        i if i.starts_with("metrics:") => &[
            Syscall::Open, Syscall::Stat,
            Syscall::Socket, Syscall::Sendto,
        ],

        // Native MUX: file + limited network
        "mux:native" => &[
            Syscall::Open, Syscall::Openat, Syscall::Stat,
            Syscall::Socket, Syscall::Sendto, Syscall::Recvfrom,
        ],

        // Unknown intent: base only (very restrictive)
        _ => &[],
    };

    for s in extra {
        if !allowed.contains(s) {
            allowed.push(*s);
        }
    }

    // Generate BPF instructions
    let instructions = generate_bpf(&allowed);
    let instruction_count = instructions.len();

    SeccompFilter {
        intent: intent.to_string(),
        instructions,
        allowed_syscalls: allowed,
        denied_syscalls: ALWAYS_DENIED.to_vec(),
        instruction_count,
    }
}

/// Generate BPF bytecode for a seccomp filter.
///
/// Structure:
///   1. Load arch → verify x86_64 → kill if wrong
///   2. Load syscall number
///   3. For each allowed syscall: JEQ → ALLOW
///   4. Default: KILL
fn generate_bpf(allowed: &[Syscall]) -> Vec<BpfInsn> {
    let mut insns = Vec::with_capacity(allowed.len() + 5);

    // Instruction 0: Load architecture
    insns.push(BpfInsn {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0, jf: 0,
        k: SECCOMP_DATA_ARCH,
    });

    // Instruction 1: Verify x86_64 arch (jump to kill if wrong)
    let kill_offset = (allowed.len() + 1) as u8; // jump past all JEQ + the RET_ALLOW
    insns.push(BpfInsn {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0, // continue to next instruction
        jf: kill_offset.min(255), // jump to KILL
        k: AUDIT_ARCH_X86_64,
    });

    // Instruction 2: Load syscall number
    insns.push(BpfInsn {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0, jf: 0,
        k: SECCOMP_DATA_NR,
    });

    // Instructions 3..N: For each allowed syscall, JEQ → ALLOW
    for (i, syscall) in allowed.iter().enumerate() {
        let remaining = allowed.len() - i - 1;
        insns.push(BpfInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: (remaining + 1) as u8, // jump to ALLOW (past remaining JEQs + KILL)
            jf: 0, // continue checking
            k: *syscall as u32,
        });
    }

    // Second-to-last: KILL (default action for non-allowed syscalls)
    insns.push(BpfInsn {
        code: BPF_RET | BPF_K,
        jt: 0, jf: 0,
        k: SECCOMP_RET_KILL_THREAD,
    });

    // Last: ALLOW
    insns.push(BpfInsn {
        code: BPF_RET | BPF_K,
        jt: 0, jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    insns
}

/// Validate a syscall against a compiled filter (simulation mode).
/// Returns true if the syscall would be ALLOWED.
pub fn validate_syscall(filter: &SeccompFilter, syscall_nr: u32) -> bool {
    // Check against always-denied first
    if let Some(s) = Syscall::from_nr(syscall_nr) {
        if ALWAYS_DENIED.contains(&s) {
            return false;
        }
    }

    // Check against allowed list
    filter.allowed_syscalls.iter().any(|s| *s as u32 == syscall_nr)
}

/// Validate a sequence of syscalls against a filter.
/// Returns list of denied syscall numbers.
pub fn validate_sequence(filter: &SeccompFilter, syscalls: &[u32]) -> Vec<u32> {
    syscalls.iter()
        .filter(|nr| !validate_syscall(filter, **nr))
        .cloned()
        .collect()
}

/// Get a summary of what a filter allows/denies for display.
pub fn filter_summary(filter: &SeccompFilter) -> FilterSummary {
    let allows_network = filter.allowed_syscalls.iter().any(|s| matches!(s,
        Syscall::Socket | Syscall::Connect | Syscall::Bind |
        Syscall::Listen | Syscall::Accept | Syscall::Sendto | Syscall::Recvfrom
    ));

    let allows_filesystem = filter.allowed_syscalls.iter().any(|s| matches!(s,
        Syscall::Open | Syscall::Openat | Syscall::Mkdir | Syscall::Rmdir |
        Syscall::Unlink | Syscall::Chmod | Syscall::Chown
    ));

    let allows_process = filter.allowed_syscalls.iter().any(|s| matches!(s,
        Syscall::Fork | Syscall::Clone | Syscall::Execve
    ));

    let allows_memory = filter.allowed_syscalls.iter().any(|s| matches!(s,
        Syscall::Mmap | Syscall::Mprotect
    ));

    FilterSummary {
        intent: filter.intent.clone(),
        total_allowed: filter.allowed_syscalls.len(),
        bpf_instructions: filter.instruction_count,
        allows_network,
        allows_filesystem,
        allows_process,
        allows_memory,
    }
}

#[derive(Debug, Clone)]
pub struct FilterSummary {
    pub intent: String,
    pub total_allowed: usize,
    pub bpf_instructions: usize,
    pub allows_network: bool,
    pub allows_filesystem: bool,
    pub allows_process: bool,
    pub allows_memory: bool,
}
