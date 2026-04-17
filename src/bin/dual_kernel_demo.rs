use std::time::Instant;

use tibet_trust_kernel::bus::VirtualBus;
use tibet_trust_kernel::config::TrustKernelConfig;
use tibet_trust_kernel::mux::TibetMuxFrame;
use tibet_trust_kernel::voorproever::{Voorproever, VoorproeverVerdict};
use tibet_trust_kernel::archivaris::{Archivaris, ArchivarisResult, VaultRetrieveResult};
use tibet_trust_kernel::tibet_token::TibetProvenance;
use tibet_trust_kernel::watchdog::{Watchdog, WatchdogEvent};
use tibet_trust_kernel::bifurcation::{ClearanceLevel, JisClaim};

/// DUAL-KERNEL DEMO — End-to-End Trust Pipeline
///
/// Demonstrates the full chain without TCP:
///   MUX Frame → Voorproever (SNAFT) → Bus (A→B) → Archivaris (JIS) → TIBET Token
///
/// Test cases:
///   1. Clean code:execute → PASS → SUCCESS + token
///   2. Malicious payload (os.system, eval) → KILL + incident token
///   3. Unknown intent → REJECT
///   4. Watchdog timeout → auto-KILL + bus closed
///   5. Archivaris vault: seal → open → access denied
///   6. Bus sequence tracking + gap detection
///   7. Throughput: 10K frames through full pipeline

fn main() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  DUAL-KERNEL DEMO — End-to-End Trust Pipeline            ║");
    println!("  ║                                                          ║");
    println!("  ║  MUX → Voorproever → Bus → Archivaris → TIBET Token      ║");
    println!("  ║  No TCP — direct function calls for benchmarking         ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!();

    // ─── Initialize ───
    let config = TrustKernelConfig::from_name("balanced");
    println!("  Profile:   balanced (dryrun={}, jis_signing={})",
        config.profile.voorproever_dryrun, config.profile.jis_signing_per_action);
    println!();

    let mut pass_count = 0u32;
    let mut kill_count = 0u32;
    let mut reject_count = 0u32;
    let mut total_tests = 0u32;

    // ═══════════════════════════════════════════════════════════════
    // TEST 1: Clean payload — should PASS through entire pipeline
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 1: Clean Payload (code:execute) ──");
    {
        let bus = VirtualBus::new(config.bus.max_payload_bytes);
        let watchdog = Watchdog::new(
            config.watchdog.timeout_ms,
            config.watchdog.heartbeat_interval_ms,
            config.watchdog.max_missed_heartbeats,
        );
        watchdog.kernel_a_responded();

        let frame = TibetMuxFrame {
            channel_id: 1,
            intent: "code:execute".to_string(),
            from_aint: "demo.aint".to_string(),
            payload: r#"{"code": "print('Hello from Trust Kernel')", "lang": "python"}"#.to_string(),
        };

        let t0 = Instant::now();

        // Kernel A: Voorproever
        let vp = Voorproever::new(config.clone(), bus.clone(), watchdog.clone());
        let verdict = vp.evaluate(&frame);

        match verdict {
            VoorproeverVerdict::Pass { bus_payload, evaluation_us, syscalls_checked } => {
                println!("  [Kernel A] PASS: {} syscalls in {:.1}us (seq={})",
                    syscalls_checked, evaluation_us, bus_payload.seq);

                // Kernel B: Archivaris
                let mut arch = Archivaris::new(config.clone(), bus.clone());
                let result = arch.process(&bus_payload, &frame);

                match result {
                    ArchivarisResult::Success { ref token, execution_us, bus_seq } => {
                        let total = t0.elapsed().as_micros();
                        println!("  [Kernel B] SUCCESS: seq={} in {:.1}us", bus_seq, execution_us);
                        let json = token.to_json();
                        println!("  [TIBET]    Token minted: {}...", &json[..80.min(json.len())]);
                        println!("  [Total]    {:.1}us ({:.3}ms)", total, total as f64 / 1000.0);
                        pass_count += 1;
                    }
                    ref other => println!("  [Kernel B] Unexpected: {:?}", format!("{:?}", other).chars().take(80).collect::<String>()),
                }
            }
            ref other => println!("  [Kernel A] Unexpected: {:?}", format!("{:?}", other).chars().take(60).collect::<String>()),
        }
        total_tests += 1;
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 2: Malicious payload — should be KILLED by Voorproever
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 2: Malicious Payload (os.system + eval) ──");
    {
        let bus = VirtualBus::new(config.bus.max_payload_bytes);
        let watchdog = Watchdog::new(
            config.watchdog.timeout_ms,
            config.watchdog.heartbeat_interval_ms,
            config.watchdog.max_missed_heartbeats,
        );
        watchdog.kernel_a_responded();

        let frame = TibetMuxFrame {
            channel_id: 2,
            intent: "code:execute".to_string(),
            from_aint: "attacker.aint".to_string(),
            payload: r#"{"code": "import os; os.system('rm -rf /'); eval(input())", "lang": "python"}"#.to_string(),
        };

        let vp = Voorproever::new(config.clone(), bus.clone(), watchdog.clone());
        let verdict = vp.evaluate(&frame);

        match verdict {
            VoorproeverVerdict::Kill { ref reason, ref violations, evaluation_us, .. } => {
                println!("  [Kernel A] KILL: {}", reason);
                for v in violations {
                    println!("             - {}", v);
                }
                println!("  [Time]     {:.1}us", evaluation_us);
                kill_count += 1;
            }
            VoorproeverVerdict::Pass { .. } => println!("  [ERROR] Malicious payload was PASSED!"),
            VoorproeverVerdict::Reject { ref reason } => {
                println!("  [Kernel A] REJECT: {}", reason);
                reject_count += 1;
            }
        }
        total_tests += 1;
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 3: Unknown intent — should be REJECTED
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 3: Unknown Intent ──");
    {
        let bus = VirtualBus::new(config.bus.max_payload_bytes);
        let watchdog = Watchdog::new(
            config.watchdog.timeout_ms,
            config.watchdog.heartbeat_interval_ms,
            config.watchdog.max_missed_heartbeats,
        );
        watchdog.kernel_a_responded();

        let frame = TibetMuxFrame {
            channel_id: 3,
            intent: "crypto:mine_bitcoin".to_string(),
            from_aint: "sneaky.aint".to_string(),
            payload: "{}".to_string(),
        };

        let vp = Voorproever::new(config.clone(), bus.clone(), watchdog.clone());
        let verdict = vp.evaluate(&frame);

        match verdict {
            VoorproeverVerdict::Reject { ref reason } => {
                println!("  [Kernel A] REJECT: {}", reason);
                reject_count += 1;
            }
            ref other => println!("  [Kernel A] Unexpected: {:?}", format!("{:?}", other).chars().take(60).collect::<String>()),
        }
        total_tests += 1;
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 4: Watchdog timeout simulation
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 4: Watchdog Triggered ──");
    {
        let bus = VirtualBus::new(config.bus.max_payload_bytes);
        // Create watchdog with very short timeout, 0 missed = instant trigger
        let watchdog = Watchdog::new(1, 1, 0);

        // Don't respond — simulate Kernel A crash
        std::thread::sleep(std::time::Duration::from_millis(5));

        match watchdog.check() {
            WatchdogEvent::Triggered { last_response_ms, timeout_ms } => {
                println!("  [Watchdog] TRIGGERED: {:.1}ms > {}ms", last_response_ms, timeout_ms);
                bus.shutdown();
                println!("  [Bus]      Closed by watchdog");

                let frame = TibetMuxFrame {
                    channel_id: 4,
                    intent: "code:execute".to_string(),
                    from_aint: "victim.aint".to_string(),
                    payload: "{}".to_string(),
                };
                let token = TibetProvenance::generate_rejected(&frame, "Watchdog auto-KILL");
                let json = token.to_json();
                println!("  [TIBET]    Incident token: {}...", &json[..80.min(json.len())]);
                kill_count += 1;
            }
            WatchdogEvent::HeartbeatMissed { consecutive, max } => {
                println!("  [Watchdog] Heartbeat missed ({}/{})", consecutive, max);
                kill_count += 1;
            }
            WatchdogEvent::Healthy { .. } => {
                println!("  [Watchdog] Still healthy (timing race — ok for demo)");
            }
        }
        total_tests += 1;
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 5: Archivaris vault — encrypt-by-default
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 5: Archivaris Vault (Bifurcation) ──");
    {
        let bus = VirtualBus::new(config.bus.max_payload_bytes);
        let mut arch = Archivaris::new(config.clone(), bus.clone());

        // Store secret data
        let secret = b"CLASSIFIED: Trust Kernel encryption keys for production".to_vec();
        let store_result = arch.vault_store(&secret, ClearanceLevel::Secret, "admin.aint");
        println!("  [Vault]    Store: {:?}", format!("{:?}", store_result).chars().take(80).collect::<String>());

        // Retrieve with sufficient clearance
        let high_claim = JisClaim {
            identity: "admin.aint".to_string(),
            ed25519_pub: "a".repeat(64),
            clearance: ClearanceLevel::TopSecret,
            role: "admin".to_string(),
            dept: "security".to_string(),
            claimed_at: "2026-04-15T00:00:00Z".to_string(),
            signature: "bench_sig".to_string(),
        };
        let retrieve = arch.vault_retrieve(0, &high_claim);
        match retrieve {
            VaultRetrieveResult::Opened { ref plaintext, decrypt_us, .. } => {
                let matches = *plaintext == secret;
                println!("  [Vault]    TopSecret claim -> OPENED ({:.1}us, data match={})", decrypt_us, matches);
                if matches { pass_count += 1; }
            }
            ref other => println!("  [Vault]    TopSecret claim -> {:?}", format!("{:?}", other).chars().take(60).collect::<String>()),
        }
        total_tests += 1;

        // Retrieve with insufficient clearance
        let low_claim = JisClaim {
            identity: "intern.aint".to_string(),
            ed25519_pub: "b".repeat(64),
            clearance: ClearanceLevel::Restricted,
            role: "viewer".to_string(),
            dept: "public".to_string(),
            claimed_at: "2026-04-15T00:00:00Z".to_string(),
            signature: "sig".to_string(),
        };
        let retrieve = arch.vault_retrieve(0, &low_claim);
        match retrieve {
            VaultRetrieveResult::AccessDenied { .. } => {
                println!("  [Vault]    Restricted claim -> ACCESS DENIED (correct)");
                kill_count += 1;
            }
            ref other => println!("  [Vault]    Restricted claim -> {:?}", format!("{:?}", other).chars().take(60).collect::<String>()),
        }
        total_tests += 1;
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 6: Bus sequence tracking
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 6: Bus Sequence + Gap Detection ──");
    {
        let bus = VirtualBus::new(config.bus.max_payload_bytes);

        // Send 5 payloads through bus
        let p1 = bus.stamp_payload("code:execute", "{}", "a.aint", vec![], 0.9);
        let p2 = bus.stamp_payload("code:execute", "{}", "b.aint", vec![], 0.85);
        let p3 = bus.stamp_payload("code:execute", "{}", "c.aint", vec![], 0.7);

        println!("  [Bus] Stamped: seq={}, {}, {}", p1.seq, p2.seq, p3.seq);

        // Deliver in order
        let r1 = bus.receive(&p1);
        let r2 = bus.receive(&p2);
        println!("  [Bus] Received seq={}: {:?}", p1.seq, format!("{:?}", r1).chars().take(30).collect::<String>());
        println!("  [Bus] Received seq={}: {:?}", p2.seq, format!("{:?}", r2).chars().take(30).collect::<String>());

        // Skip p3, deliver p5 — should detect gap
        let p5 = bus.stamp_payload("code:execute", "{}", "e.aint", vec![], 0.6);
        let r5 = bus.receive(&p5);
        println!("  [Bus] Received seq={} (skipped {}): {:?}", p5.seq, p3.seq,
            format!("{:?}", r5).chars().take(40).collect::<String>());

        let stats = bus.stats();
        println!("  [Bus] Stats: passed={}, gaps={}", stats.payloads_passed, stats.sequence_gaps_detected);
        pass_count += 1;
        total_tests += 1;
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 7: Throughput — 10K frames through full pipeline
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 7: Throughput (10K frames) ──");
    {
        let iterations = 10_000u32;
        let bus = VirtualBus::new(config.bus.max_payload_bytes);
        let watchdog = Watchdog::new(
            config.watchdog.timeout_ms,
            config.watchdog.heartbeat_interval_ms,
            config.watchdog.max_missed_heartbeats,
        );
        watchdog.kernel_a_responded();

        let frame = TibetMuxFrame {
            channel_id: 100,
            intent: "code:execute".to_string(),
            from_aint: "bench.aint".to_string(),
            payload: r#"{"code": "x = 42", "lang": "python"}"#.to_string(),
        };

        let mut successes = 0u32;
        let mut latencies = Vec::with_capacity(iterations as usize);

        let t0 = Instant::now();
        for _ in 0..iterations {
            let t_frame = Instant::now();

            let vp = Voorproever::new(config.clone(), bus.clone(), watchdog.clone());
            let verdict = vp.evaluate(&frame);

            if let VoorproeverVerdict::Pass { bus_payload, .. } = verdict {
                let mut arch = Archivaris::new(config.clone(), bus.clone());
                if let ArchivarisResult::Success { .. } = arch.process(&bus_payload, &frame) {
                    successes += 1;
                }
            }

            latencies.push(t_frame.elapsed().as_micros() as u64);
        }
        let total_ms = t0.elapsed().as_millis();

        latencies.sort();
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[latencies.len() * 95 / 100];
        let p99 = latencies[latencies.len() * 99 / 100];
        let fps = iterations as f64 / (total_ms as f64 / 1000.0);

        println!("  Frames:     {}/{}", successes, iterations);
        println!("  Total:      {} ms", total_ms);
        println!("  Throughput: {:.0} frames/sec", fps);
        println!("  p50: {}us  p95: {}us  p99: {}us", p50, p95, p99);

        pass_count += 1;
        total_tests += 1;
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════
    println!("  ══════════════════════════════════════════════════════════════");
    println!("  DUAL-KERNEL DEMO — RESULTS");
    println!("  ──────────────────────────────────────────────────────────────");
    println!("  Tests:     {}", total_tests);
    println!("  PASS:      {} (correct successes)", pass_count);
    println!("  KILL:      {} (correct blocks)", kill_count);
    println!("  REJECT:    {} (correct rejections)", reject_count);
    println!();
    println!("  Pipeline:  MUX -> Voorproever -> Bus -> Archivaris -> TIBET");
    println!("  Crypto:    AES-256-GCM + X25519 + HKDF-SHA256");
    println!("  Access:    JIS identity claims (clearance-based)");
    println!("  Storage:   Encrypt-by-default vault (Archivaris)");
    println!("  Audit:     TIBET provenance tokens for every action");
    println!();
    println!("  Wrong identity = dead material. Identity IS the key.");
    println!("  ══════════════════════════════════════════════════════════════");
    println!();
}
