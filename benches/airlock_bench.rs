//! Trust Kernel v1 — Performance Harness
//! Benchmarks: SNAFT check, TIBET token mint, full airlock roundtrip (sim mode)

use std::time::{Instant, Duration};

// We can't use criterion without adding it as dep, so we do simple stat benches
// that give us p50/p95/p99

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

fn run_bench(name: &str, iterations: usize, f: impl Fn() -> ()) {
    let mut times_us: Vec<f64> = Vec::with_capacity(iterations);

    // Warmup
    for _ in 0..10 {
        f();
    }

    // Measured runs
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed();
        times_us.push(elapsed.as_nanos() as f64 / 1000.0); // microseconds
    }

    times_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg = times_us.iter().sum::<f64>() / times_us.len() as f64;
    let p50 = percentile(&times_us, 50.0);
    let p95 = percentile(&times_us, 95.0);
    let p99 = percentile(&times_us, 99.0);
    let min = times_us[0];
    let max = times_us[times_us.len() - 1];

    println!("◈ {name}");
    println!("  n={iterations}  avg={avg:.1}µs  p50={p50:.1}µs  p95={p95:.1}µs  p99={p99:.1}µs  min={min:.1}µs  max={max:.1}µs");
    if avg < 1000.0 {
        println!("  → {:.3}ms_avg average", avg / 1000.0);
    } else {
        println!("  → {:.1}ms_avg average", avg / 1000.0);
    }
    println!();
}

fn main() {
    println!("═══════════════════════════════════════════════════════");
    println!("◈ TRUST KERNEL v1 — Performance Harness");
    println!("◈ tibet-airlock benchmarks (simulation mode)");
    println!("═══════════════════════════════════════════════════════\n");

    // ─── Bench 1: SNAFT allowlist creation ───
    run_bench("SNAFT monitor creation (per intent)", 10000, || {
        // Simulate creating a SNAFT monitor with allowlist lookup
        let intents = ["code:execute", "file:scan", "analyze_malware_sample", "call:voice:sip", "call:video:webrtc"];
        for intent in &intents {
            let _: std::collections::HashSet<&str> = [
                "sys_execve", "sys_write", "sys_read", "sys_exit", "sys_brk", "sys_mprotect",
            ].into_iter().collect();
            // Extra per intent
            match *intent {
                "code:execute" => { let _ = ["sys_open", "sys_stat", "sys_close", "sys_getpid"]; }
                "file:scan" => { let _ = ["sys_open", "sys_stat", "sys_close", "sys_getdents"]; }
                _ => {}
            }
        }
    });

    // ─── Bench 2: SNAFT syscall check (allowlist lookup) ───
    run_bench("SNAFT syscall check (HashSet lookup)", 100000, || {
        let allowlist: std::collections::HashSet<&str> = [
            "sys_execve", "sys_write", "sys_read", "sys_exit", "sys_brk",
            "sys_mprotect", "sys_open", "sys_stat", "sys_close", "sys_getpid",
        ].into_iter().collect();
        let dangerous = ["sys_ptrace", "sys_socket", "sys_connect", "sys_fork", "sys_mount"];

        // Check 10 syscalls (typical execution)
        let calls = ["sys_read", "sys_write", "sys_open", "sys_close", "sys_brk",
                      "sys_execve", "sys_stat", "sys_read", "sys_write", "sys_exit"];
        for call in &calls {
            let _ = dangerous.contains(call);
            let _ = allowlist.contains(call);
        }
    });

    // ─── Bench 3: TIBET token generation (JSON serialization) ───
    run_bench("TIBET token mint (4-dim JSON)", 10000, || {
        let token = serde_json::json!({
            "tbz_version": "1.0.0",
            "token_type": "SAFE_EXECUTION",
            "timestamp": "2026-04-13T18:00:00.000Z",
            "ains_identity": "root_idd.aint",
            "intent": "code:execute",
            "erin": {
                "content": "print('hello')",
                "result": "hello",
                "hash": "sha256:abcdef1234567890"
            },
            "eraan": {
                "vm_id": "airlock-abc-123",
                "dependencies": ["python:3.13", "tibet-core:2.0.0"]
            },
            "eromheen": {
                "context": "sandbox execution",
                "triage_decision": "SAFE",
                "observed_syscalls": ["sys_read", "sys_write", "sys_exit"],
                "execution_time_ms": 0.42
            },
            "erachter": {
                "intent": "code:execute",
                "actor": "root_idd.aint",
                "purpose": "benchmark test"
            },
            "cryptographic_seal": "tbz_sign_ed25519_safeboot_placeholder"
        });
        let _ = serde_json::to_string(&token).unwrap();
    });

    // ─── Bench 4: Intent routing (pattern match) ───
    run_bench("Intent routing (pattern match)", 100000, || {
        let intents = ["code:execute", "file:scan", "call:voice:sip",
                        "call:video:webrtc", "analyze_malware_sample", "unknown:bad"];
        for intent in &intents {
            let _result = match *intent {
                "code:execute" | "analyze_malware_sample" => Some(("humotica/airlock-python:latest", "python-safe-boot")),
                "file:scan" => Some(("humotica/airlock-scanner:latest", "scanner-ready")),
                i if i.starts_with("call:voice") => Some(("humotica/airlock-sip:v2", "sip-ready")),
                i if i.starts_with("call:video") => Some(("humotica/airlock-webrtc:v1", "webrtc-ready")),
                _ => None,
            };
        }
    });

    // ─── Bench 5: Full simulation roundtrip ───
    run_bench("Full airlock roundtrip (sim, no network)", 10000, || {
        // Simulate the full flow without TCP:
        // 1. Parse intent
        let intent = "code:execute";
        let payload = "print('hello world')";

        // 2. Route intent
        let _image = match intent {
            "code:execute" => "humotica/airlock-python:latest",
            _ => "unknown",
        };

        // 3. SNAFT pre-check (pattern scan)
        let dangerous_patterns = ["os.system", "subprocess", "curl", "eval(", "ptrace", "LD_PRELOAD"];
        let _has_violation = dangerous_patterns.iter().any(|p| payload.contains(p));

        // 4. Create allowlist + check syscalls
        let allowlist: std::collections::HashSet<&str> = [
            "sys_execve", "sys_write", "sys_read", "sys_exit", "sys_brk",
        ].into_iter().collect();
        let observed = ["sys_execve", "sys_write", "sys_exit"];
        let _all_ok = observed.iter().all(|s| allowlist.contains(s));

        // 5. Mint TIBET token
        let token = serde_json::json!({
            "token_type": "SAFE_EXECUTION",
            "intent": intent,
            "erin": {"result": "hello world"},
            "erachter": {"intent": intent},
        });
        let _ = serde_json::to_string(&token).unwrap();
    });

    // ─── Bench 6: Watchdog timer check (proposed for Trust Kernel) ───
    run_bench("Watchdog timer check (Instant::elapsed)", 100000, || {
        let deadline = Instant::now() + Duration::from_millis(50);
        // Simulate checking if Kernel A has responded
        let responded = true;
        let _timed_out = !responded && Instant::now() > deadline;
    });

    // ─── Bench 7: Sequence number validation (proposed for bus) ───
    run_bench("Bus sequence validation (gap detection)", 100000, || {
        let mut expected_seq: u64 = 0;
        let incoming = [0u64, 1, 2, 3, 5, 6, 7]; // gap at 4
        let mut gaps: Vec<u64> = Vec::new();
        for seq in &incoming {
            if *seq != expected_seq {
                // Gap detected — would be a TIBET event
                for missing in expected_seq..*seq {
                    gaps.push(missing);
                }
            }
            expected_seq = seq + 1;
        }
        let _ = gaps; // gap at 4 detected
    });

    println!("═══════════════════════════════════════════════════════");
    println!("◈ Benchmark complete. All times are per-iteration.");
    println!("═══════════════════════════════════════════════════════");
}
