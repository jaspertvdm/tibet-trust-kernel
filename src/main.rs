use std::sync::Arc;
use std::time::Instant;

use tibet_trust_kernel::bus::VirtualBus;
use tibet_trust_kernel::config::TrustKernelConfig;
use tibet_trust_kernel::mux::{self, start_mux_listener};
use tibet_trust_kernel::voorproever::{Voorproever, VoorproeverVerdict};
use tibet_trust_kernel::archivaris::{Archivaris, ArchivarisResult};
use tibet_trust_kernel::tibet_token::TibetProvenance;
use tibet_trust_kernel::watchdog::{Watchdog, WatchdogEvent};
use tibet_trust_kernel::{osapi_adapter, snaft};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ─── Argument inspection (early, before any bind) ───
    let args: Vec<String> = std::env::args().collect();
    let osapi_enabled = args.iter().any(|a| a == "--osapi");

    // ─── Configuration ───
    let profile = std::env::var("TRUST_KERNEL_PROFILE").unwrap_or_else(|_| "balanced".to_string());
    let config = TrustKernelConfig::from_name(&profile);

    println!("═══════════════════════════════════════════════════════════════");
    println!("◈ TRUST KERNEL v1.0.0 — Dual-Kernel Airlock");
    println!("◈ Profile: {} (voorproever_dryrun={}, jis_signing={})",
        profile, config.profile.voorproever_dryrun, config.profile.jis_signing_per_action);
    println!("◈ Watchdog: {}ms timeout, {}ms heartbeat, max {} missed",
        config.watchdog.timeout_ms, config.watchdog.heartbeat_interval_ms, config.watchdog.max_missed_heartbeats);
    println!("◈ Bus: {}KB shared, {}KB max payload",
        config.bus.shared_memory_bytes / 1024, config.bus.max_payload_bytes / 1024);
    println!("═══════════════════════════════════════════════════════════════\n");

    // ─── Initialize components ───
    let bus = VirtualBus::new(config.bus.max_payload_bytes);
    let watchdog = Watchdog::new(
        config.watchdog.timeout_ms,
        config.watchdog.heartbeat_interval_ms,
        config.watchdog.max_missed_heartbeats,
    );

    // Mark initial heartbeat
    watchdog.kernel_a_responded();

    println!("◈ [Kernel A] Voorproever initialized (SNAFT + FIR/A)");
    println!("◈ [Kernel B] Archivaris initialized (JIS + append-only archive)");
    println!("◈ [Bus]      Virtual bus open (seq=0, one-way A→B)");
    println!("◈ [Watchdog] Active ({}ms timeout)\n", config.watchdog.timeout_ms);

    // ─── Start MUX listener ───
    let mut listener = start_mux_listener("127.0.0.1:4430").await?;
    println!("◈ [MUX] Listening on 127.0.0.1:4430\n");

    // ─── OSAPI v1.1 — opt-in TCP/LDJSON side-channel ───
    // Default-OFF. --osapi opens TCP listeners on 18443 (verdict.v1 ingest)
    // and 18444 (TAT envelope ingest with biometric vehicle dispatch).
    // Bolle runtime stays unchanged; OSAPI is the explicit operator/observability path.
    if osapi_enabled {
        let host = std::env::var("OSAPI_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        match osapi_adapter::spawn_osapi(
            &host,
            osapi_adapter::VERDICT_PORT_DEFAULT,
            osapi_adapter::TAT_PORT_DEFAULT,
        )
        .await
        {
            Ok(handles) => {
                println!(
                    "◈ [OSAPI] v1.1 active on {}:{} (verdict.v1) + {}:{} (TAT envelope)\n",
                    host,
                    osapi_adapter::VERDICT_PORT_DEFAULT,
                    host,
                    osapi_adapter::TAT_PORT_DEFAULT
                );
                // Handles are detached; they run until process exit.
                std::mem::forget(handles);
            }
            Err(e) => {
                eprintln!("◈ [OSAPI] BIND FAILED ({}); continuing without OSAPI", e);
            }
        }
    }

    // Shared state for the connection handler
    let config = Arc::new(config);

    loop {
        let (mut socket, frame) = match listener.accept_frame().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("◈ [MUX] Accept error: {} — continuing", e);
                continue;
            }
        };

        let bus = bus.clone();
        let watchdog = watchdog.clone();
        let config = config.clone();

        tokio::spawn(async move {
            let t0 = Instant::now();
            let frame_clone = frame.clone();

            println!("◈ ═══════════════════════════════════════════════════════");
            println!("◈ [MUX] Frame received: intent='{}' from='{}'", frame.intent, frame.from_aint);

            // ─── PHASE 1: Watchdog check ───
            match watchdog.check() {
                WatchdogEvent::Triggered { last_response_ms, timeout_ms } => {
                    println!("◈ [Watchdog] TRIGGERED: Kernel A unresponsive ({:.1}ms > {}ms)", last_response_ms, timeout_ms);
                    println!("◈ [Watchdog] Auto-KILL: bus closed, generating incident token");
                    bus.shutdown();

                    let token = TibetProvenance::generate_rejected(
                        &frame,
                        &format!("Watchdog auto-KILL: Kernel A unresponsive for {:.1}ms", last_response_ms),
                    );
                    mux::send_response(&mut socket, &frame, &token.to_json(), 503).await;
                    return;
                }
                WatchdogEvent::HeartbeatMissed { consecutive, max } => {
                    println!("◈ [Watchdog] WARNING: heartbeat missed ({}/{})", consecutive, max);
                }
                WatchdogEvent::Healthy { .. } => {}
            }

            // ─── PHASE 2: Kernel A — Voorproever ───
            let voorproever = Voorproever::new(
                (*config).clone(),
                bus.clone(),
                watchdog.clone(),
            );

            let verdict = voorproever.evaluate(&frame);
            let vp_elapsed_us = t0.elapsed().as_micros() as u64;

            match verdict {
                VoorproeverVerdict::Reject { reason } => {
                    println!("◈ [Kernel A] REJECT: {}", reason);
                    let token = TibetProvenance::generate_rejected(&frame, &reason);
                    mux::send_response(&mut socket, &frame, &token.to_json(), 400).await;
                    println!("◈ [Flow] Rejected in {:.1}µs", vp_elapsed_us);
                    return;
                }
                VoorproeverVerdict::Kill { reason, violations, observed_syscalls: _, evaluation_us } => {
                    println!("◈ [Kernel A] KILL: {} ({} violations)", reason, violations.len());
                    for v in &violations {
                        println!("◈   ✗ {}", v);
                    }

                    let decision = snaft::Decision {
                        is_safe: false,
                        reason: reason.clone(),
                        violations: violations.clone(),
                        observed_syscalls: vec![],
                    };
                    let token = TibetProvenance::generate_incident(
                        &frame, &decision, "voorproever", evaluation_us as f64 / 1000.0,
                    );
                    mux::send_response(&mut socket, &frame, &token.to_json(), 403).await;
                    println!("◈ [Flow] Killed in {:.1}µs", evaluation_us);
                    return;
                }
                VoorproeverVerdict::Pass { bus_payload, evaluation_us, syscalls_checked } => {
                    println!("◈ [Kernel A] PASS: {} syscalls checked in {:.1}µs (seq={})",
                        syscalls_checked, evaluation_us, bus_payload.seq);

                    // ─── PHASE 3: Bus transfer A → B ───
                    println!("◈ [Bus] Payload seq={} → Kernel B", bus_payload.seq);

                    // ─── PHASE 4: Kernel B — Archivaris ───
                    let mut archivaris = Archivaris::new((*config).clone(), bus.clone());
                    let result = archivaris.process(&bus_payload, &frame_clone);

                    match result {
                        ArchivarisResult::Success { token, execution_us, bus_seq } => {
                            let total_us = t0.elapsed().as_micros() as u64;
                            println!("◈ [Kernel B] SUCCESS: archived seq={} in {:.1}µs", bus_seq, execution_us);
                            println!("◈ [TIBET] Success token minted by Archivaris");
                            println!("◈ [Flow] Complete: {:.1}µs total ({:.3}ms)",
                                total_us, total_us as f64 / 1000.0);
                            mux::send_response(&mut socket, &frame_clone, &token.to_json(), 200).await;
                        }
                        ArchivarisResult::SequenceGap { expected, received, result } => {
                            println!("◈ [Bus] SEQUENCE GAP: expected seq={}, got seq={} — TIBET event", expected, received);
                            // Process the inner result
                            if let ArchivarisResult::Success { token, execution_us: _, bus_seq: _ } = *result {
                                mux::send_response(&mut socket, &frame_clone, &token.to_json(), 200).await;
                            }
                        }
                        ArchivarisResult::BusClosed => {
                            println!("◈ [Kernel B] Bus closed — watchdog triggered");
                            let token = TibetProvenance::generate_rejected(&frame_clone, "Bus closed by watchdog");
                            mux::send_response(&mut socket, &frame_clone, &token.to_json(), 503).await;
                        }
                        ArchivarisResult::BusVerifyFailed { reason, bus_seq } => {
                            println!("◈ [Kernel B] VERIFY FAILED: {} (seq={})", reason, bus_seq);
                            let token = TibetProvenance::generate_rejected(&frame_clone, &reason);
                            mux::send_response(&mut socket, &frame_clone, &token.to_json(), 403).await;
                        }
                        ArchivarisResult::JisDenied { reason, bus_seq } => {
                            println!("◈ [Kernel B] JIS DENIED: {} (seq={})", reason, bus_seq);
                            let token = TibetProvenance::generate_rejected(&frame_clone, &reason);
                            mux::send_response(&mut socket, &frame_clone, &token.to_json(), 403).await;
                        }
                    }
                }
            }

            println!("◈ ═══════════════════════════════════════════════════════\n");
        });
    }
}
