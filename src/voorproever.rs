use std::sync::Arc;
use std::time::Instant;

use crate::bus::{BusPayload, VirtualBus};
use crate::config::TrustKernelConfig;
use crate::mux::TibetMuxFrame;
use crate::snaft::SnaftMonitor;
use crate::watchdog::Watchdog;

/// Kernel A — De Voorproever ("De Kogelvrije Glazen Kooi")
///
/// All untrusted input enters here first. The Voorproever:
/// 1. Validates intent via SNAFT (22 poison rules + allowlists)
/// 2. Dry-runs syscalls (pattern detection, not ptrace)
/// 3. Computes FIR/A behavioral trust score
/// 4. On PASS: signs payload and sends to Bus → Kernel B
/// 5. On KILL: generates incident token, zeroes memory, destroys
///
/// The Voorproever never stores anything. It is ephemeral and disposable.
/// If it crashes (due to malicious payload), the Watchdog detects it
/// and the bus auto-closes. That's by design.

/// Result of Voorproever evaluation.
#[derive(Debug)]
pub enum VoorproeverVerdict {
    /// Payload is safe — signed and ready for bus
    Pass {
        bus_payload: BusPayload,
        evaluation_us: u64,
        syscalls_checked: usize,
    },
    /// Payload is dangerous — KILL
    Kill {
        reason: String,
        violations: Vec<String>,
        observed_syscalls: Vec<String>,
        evaluation_us: u64,
    },
    /// Intent not recognized — REJECT (before any execution)
    Reject {
        reason: String,
    },
}

pub struct Voorproever {
    config: TrustKernelConfig,
    bus: Arc<VirtualBus>,
    watchdog: Arc<Watchdog>,
}

impl Voorproever {
    pub fn new(
        config: TrustKernelConfig,
        bus: Arc<VirtualBus>,
        watchdog: Arc<Watchdog>,
    ) -> Self {
        Self { config, bus, watchdog }
    }

    /// Evaluate an incoming frame. This is the main entry point.
    ///
    /// The Voorproever does NOT execute the payload — it analyzes it.
    /// If dry_run is enabled, it simulates all syscalls.
    /// If dry_run is disabled (fast mode), it only does SNAFT pattern check.
    pub fn evaluate(&self, frame: &TibetMuxFrame) -> VoorproeverVerdict {
        let t0 = Instant::now();

        // 1. Route intent — do we even know this intent?
        if !Self::is_known_intent(&frame.intent) {
            return VoorproeverVerdict::Reject {
                reason: format!("Unknown intent '{}' — no safe execution path", frame.intent),
            };
        }

        // 2. SNAFT monitoring
        let mut monitor = SnaftMonitor::new(&frame.intent);

        if self.config.profile.voorproever_dryrun {
            // Full dry-run: simulate all syscalls
            self.dry_run_syscalls(&frame.payload, &mut monitor);
        } else {
            // Fast mode: only pattern detection (no syscall simulation)
            self.pattern_check_only(&frame.payload, &mut monitor);
        }

        // 3. Check violations
        let violations = monitor.check_violations();
        if !violations.is_empty() {
            let elapsed_us = t0.elapsed().as_micros() as u64;

            // Notify watchdog that we responded (even with KILL)
            self.watchdog.kernel_a_responded();

            return VoorproeverVerdict::Kill {
                reason: format!("SNAFT: {} violation(s) detected", violations.len()),
                violations: violations.to_vec(),
                observed_syscalls: monitor.get_observed_syscalls().to_vec(),
                evaluation_us: elapsed_us,
            };
        }

        // 4. Compute FIR/A score
        let fira_score = self.compute_fira(&frame.from_aint, &monitor);

        // 5. Stamp payload for bus
        let bus_payload = self.bus.stamp_payload(
            &frame.intent,
            &frame.payload,
            &frame.from_aint,
            monitor.get_observed_syscalls().to_vec(),
            fira_score,
        );

        let elapsed_us = t0.elapsed().as_micros() as u64;
        let syscalls_checked = monitor.get_observed_syscalls().len();

        // Notify watchdog
        self.watchdog.kernel_a_responded();

        VoorproeverVerdict::Pass {
            bus_payload,
            evaluation_us: elapsed_us,
            syscalls_checked,
        }
    }

    /// Full dry-run: simulate the complete syscall sequence.
    fn dry_run_syscalls(&self, payload: &str, monitor: &mut SnaftMonitor) {
        // Process start
        monitor.log_syscall("sys_execve");

        // Scan payload for dangerous patterns → map to syscalls
        let dangerous_patterns = [
            ("os.system", "sys_socket"),
            ("subprocess", "sys_socket"),
            ("curl ", "sys_socket"),
            ("wget ", "sys_socket"),
            ("bash", "sys_socket"),
            ("/bin/sh", "sys_socket"),
            ("eval(", "sys_ptrace"),
            ("exec(", "sys_ptrace"),
            ("ptrace", "sys_ptrace"),
            ("mmap", "sys_mmap"),
            ("dlopen", "sys_dlopen"),
            ("LD_PRELOAD", "sys_dlopen"),
            ("fork(", "sys_fork"),
            ("clone(", "sys_clone"),
            ("mount(", "sys_mount"),
            ("reboot(", "sys_reboot"),
            ("kexec", "sys_kexec_load"),
            ("import socket", "sys_socket"),
            ("import os", "sys_fork"),
            ("__import__", "sys_dlopen"),
        ];

        for (pattern, syscall) in &dangerous_patterns {
            if payload.contains(pattern) {
                monitor.log_syscall(syscall);
            }
        }

        // If no violations so far, simulate clean execution syscalls
        if monitor.check_violations().is_empty() {
            monitor.log_syscall("sys_read");
            monitor.log_syscall("sys_write");
            monitor.log_syscall("sys_brk");
            monitor.log_syscall("sys_exit");
        }
    }

    /// Fast mode: only check dangerous patterns, skip syscall simulation.
    fn pattern_check_only(&self, payload: &str, monitor: &mut SnaftMonitor) {
        monitor.log_syscall("sys_execve");

        // Only check the most critical patterns
        let critical_patterns = [
            ("os.system", "sys_socket"),
            ("subprocess", "sys_socket"),
            ("eval(", "sys_ptrace"),
            ("ptrace", "sys_ptrace"),
            ("LD_PRELOAD", "sys_dlopen"),
        ];

        for (pattern, syscall) in &critical_patterns {
            if payload.contains(pattern) {
                monitor.log_syscall(syscall);
            }
        }
    }

    /// Compute FIR/A trust score for the actor.
    /// Frequency (20%) + Integrity (40%) + Recency (25%) + Anomaly (15%)
    fn compute_fira(&self, _from_aint: &str, _monitor: &SnaftMonitor) -> f64 {
        match self.config.profile.fira_scoring {
            crate::config::FiraMode::Live => {
                // TODO: integrate with SNAFT TrustKernel for real FIR/A
                // For now: high trust for clean execution
                0.85
            }
            crate::config::FiraMode::Static => {
                // Static mode: fixed trust score
                0.50
            }
        }
    }

    fn is_known_intent(intent: &str) -> bool {
        let known = [
            // ─── Original airlock intents ───
            "code:execute",
            "analyze_malware_sample",
            "file:scan",
            "call:voice",
            "call:video",
            "math_calculation",
            "data:transform",
            "data:validate",
            // ─── Port-wrapped service intents ───
            "shell:session",       // SSH sessions
            "shell:command",       // SSH commands
            "http:get",            // HTTP methods
            "http:post",
            "http:put",
            "http:delete",
            "http:patch",
            "http:head",
            "http:options",
            "http:api",            // API calls
            "http:auth",           // Auth endpoints
            "http:upload",         // File uploads
            "http:webhook",        // Webhooks
            "http:admin",          // Admin panels
            "tls:handshake",       // TLS negotiation
            "db:connect",          // Database connections
            "db:query",            // Database queries
            "db:redis",            // Redis commands
            "dns:query",           // DNS lookups
            "dns:resolve",
            "mail:send",           // SMTP
            "ai:inference",        // Ollama / LLM endpoints
            "metrics:scrape",      // Prometheus
            "mux:native",          // Native TIBET-MUX
        ];

        known.iter().any(|k| intent.starts_with(k))
    }
}

