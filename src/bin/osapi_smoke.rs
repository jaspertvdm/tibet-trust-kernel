//! osapi-smoke — standalone end-to-end smoke for the OSAPI v1.1 adapter.
//!
//! Spawns only the two OSAPI listeners (verdict + TAT) on a configurable host,
//! prints what it would do for each line received, and exits on Ctrl-C.
//! Avoids the MUX listener bind that the full daemon does — useful when 4430
//! is held by another tibet-airlock instance, and for CI / live demos.
//!
//! Usage:
//!     osapi-smoke [--host 127.0.0.1] [--verdict-port 18443] [--tat-port 18444]

use tibet_trust_kernel::osapi_adapter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let host = args
        .windows(2)
        .find_map(|w| if w[0] == "--host" { Some(w[1].clone()) } else { None })
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let verdict_port: u16 = args
        .windows(2)
        .find_map(|w| if w[0] == "--verdict-port" { w[1].parse().ok() } else { None })
        .unwrap_or(osapi_adapter::VERDICT_PORT_DEFAULT);
    let tat_port: u16 = args
        .windows(2)
        .find_map(|w| if w[0] == "--tat-port" { w[1].parse().ok() } else { None })
        .unwrap_or(osapi_adapter::TAT_PORT_DEFAULT);

    eprintln!("═══════════════════════════════════════════════════════════════");
    eprintln!("◈ OSAPI v1.1 smoke daemon (trust-kernel adapter only)");
    eprintln!("◈   verdict.v1   ingest: {}:{}", host, verdict_port);
    eprintln!("◈   tat.v0.1     ingest: {}:{}", host, tat_port);
    eprintln!("◈ Send LDJSON (one JSON per line) and read the LDJSON response.");
    eprintln!("◈ Ctrl-C to exit.");
    eprintln!("═══════════════════════════════════════════════════════════════");

    let _handles = osapi_adapter::spawn_osapi(&host, verdict_port, tat_port).await?;

    // Park forever; tokio runtime keeps the spawned listeners alive.
    tokio::signal::ctrl_c().await?;
    eprintln!("◈ Ctrl-C — shutting down");
    Ok(())
}
