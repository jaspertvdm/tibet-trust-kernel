use std::collections::HashSet;

/// Syscall allowlist per intent category.
/// If an observed syscall is NOT in the allowlist for the active intent,
/// it's a violation.
fn intent_allowlist(intent: &str) -> HashSet<&'static str> {
    let base: HashSet<&str> = ["sys_execve", "sys_write", "sys_read", "sys_exit", "sys_brk", "sys_mprotect"]
        .into_iter().collect();

    let extra: &[&str] = match intent {
        "analyze_malware_sample" => &["sys_open", "sys_stat", "sys_close"],
        "code:execute"           => &["sys_open", "sys_stat", "sys_close", "sys_getpid"],
        "file:scan"              => &["sys_open", "sys_stat", "sys_close", "sys_getdents"],
        i if i.starts_with("call:voice") => &["sys_sendto", "sys_recvfrom", "sys_ioctl"],
        i if i.starts_with("call:video") => &["sys_sendto", "sys_recvfrom", "sys_ioctl", "sys_mmap"],
        // ─── Port-wrapped service allowlists ───
        i if i.starts_with("shell:") => &["sys_open", "sys_stat", "sys_close", "sys_getpid", "sys_ioctl"],
        i if i.starts_with("http:")  => &["sys_open", "sys_stat", "sys_close", "sys_sendto", "sys_recvfrom"],
        i if i.starts_with("tls:")   => &["sys_open", "sys_stat", "sys_close"],
        i if i.starts_with("db:")    => &["sys_open", "sys_stat", "sys_close", "sys_sendto", "sys_recvfrom"],
        i if i.starts_with("dns:")   => &["sys_sendto", "sys_recvfrom"],
        i if i.starts_with("mail:")  => &["sys_open", "sys_sendto", "sys_recvfrom"],
        i if i.starts_with("ai:")    => &["sys_open", "sys_stat", "sys_close", "sys_sendto", "sys_recvfrom", "sys_mmap"],
        i if i.starts_with("metrics:") => &["sys_open", "sys_stat", "sys_sendto"],
        "mux:native"             => &["sys_open", "sys_stat", "sys_close"],
        _ => &[],
    };

    let mut allowed = base;
    for s in extra {
        allowed.insert(s);
    }
    allowed
}

/// Dangerous syscalls that always flag regardless of intent.
const ALWAYS_DANGEROUS: &[&str] = &[
    "sys_ptrace",      // Process tracing — debugger/injection
    "sys_socket",      // Network access — data exfiltration
    "sys_connect",     // Outbound connection
    "sys_dlopen",      // Dynamic library loading
    "sys_fork",        // Process forking
    "sys_clone",       // Thread/process cloning
    "sys_mount",       // Filesystem mount
    "sys_reboot",      // System reboot
    "sys_kexec_load",  // Kernel replacement
];

pub struct SnaftMonitor {
    intent: String,
    observed_syscalls: Vec<String>,
    violations: Vec<String>,
    allowlist: HashSet<&'static str>,
}

pub struct Decision {
    pub is_safe: bool,
    pub reason: String,
    pub violations: Vec<String>,
    pub observed_syscalls: Vec<String>,
}

impl Decision {
    pub fn is_kill(&self) -> bool {
        !self.is_safe
    }
}

impl SnaftMonitor {
    pub fn new(intent: &str) -> Self {
        Self {
            intent: intent.to_string(),
            observed_syscalls: Vec::new(),
            violations: Vec::new(),
            allowlist: intent_allowlist(intent),
        }
    }

    pub fn intent(&self) -> &str {
        &self.intent
    }

    /// Log an observed syscall. Immediately checks against policy.
    pub fn log_syscall(&mut self, call: &str) {
        self.observed_syscalls.push(call.to_string());

        // Check against always-dangerous list
        if ALWAYS_DANGEROUS.contains(&call) {
            let msg = format!("{} (blocked: dangerous syscall for any intent)", call);
            println!("◈ [SNAFT] VIOLATION: {}", msg);
            self.violations.push(msg);
            return;
        }

        // Check against intent-specific allowlist
        if !self.allowlist.contains(call) {
            let msg = format!("{} (not allowed for intent '{}')", call, self.intent);
            println!("◈ [SNAFT] VIOLATION: {}", msg);
            self.violations.push(msg);
            return;
        }

        println!("◈ [SNAFT] OK: {}", call);
    }

    /// Check current violations without triggering triage.
    pub fn check_violations(&self) -> &[String] {
        &self.violations
    }

    /// Get all observed syscalls so far.
    pub fn get_observed_syscalls(&self) -> &[String] {
        &self.observed_syscalls
    }

    /// Get current violation count.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    /// Final triage decision based on all observations.
    pub fn triage(&self, execution_result: &Result<String, String>) -> Decision {
        // If execution itself reported an error
        if let Err(msg) = execution_result {
            return Decision {
                is_safe: false,
                reason: msg.clone(),
                violations: self.violations.clone(),
                observed_syscalls: self.observed_syscalls.clone(),
            };
        }

        // If SNAFT flagged any violations during monitoring
        if !self.violations.is_empty() {
            return Decision {
                is_safe: false,
                reason: format!("SNAFT detected {} violation(s): {}", self.violations.len(), self.violations.join("; ")),
                violations: self.violations.clone(),
                observed_syscalls: self.observed_syscalls.clone(),
            };
        }

        Decision {
            is_safe: true,
            reason: format!("All {} syscalls within intent '{}' bounds", self.observed_syscalls.len(), self.intent),
            violations: vec![],
            observed_syscalls: self.observed_syscalls.clone(),
        }
    }
}
