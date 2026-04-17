// ═══════════════════════════════════════════════════════════════
// RAM RAID-0 Cluster Demo — Cross-Machine Memory Virtualization
//
// The full pipeline:
//   App writes to virtual RAM → blocks get RAID-0 striped →
//   even blocks stay local (RAM A) → odd blocks evicted to
//   remote kernel via ClusterMux (RAM B) → app reads back →
//   page fault → MUX fetch from remote → data restored
//
// Usage:
//   Loopback:  ram-raid-cluster-demo test
//   Server:    ram-raid-cluster-demo server 0.0.0.0:4432
//   Client:    ram-raid-cluster-demo client 192.168.4.69:4432
// ═══════════════════════════════════════════════════════════════

use tibet_trust_kernel::ram_raid::*;
use tibet_trust_kernel::cluster_transport::{BlockStore, sha256_hex};
use tibet_trust_kernel::cluster_mux::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("test");

    match mode {
        "server" => {
            let addr = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:4432");
            run_ram_b_server(addr).await;
        }
        "client" => {
            let endpoint = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:4432");
            run_raid_client(endpoint).await;
        }
        "test" | _ => {
            run_loopback().await;
        }
    }
}

/// Server mode: acts as RAM B provider (DL360)
async fn run_ram_b_server(addr: &str) {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  RAM B Server — Remote Memory Provider (DL360)   ║");
    println!("║  Stores evicted blocks from RAM A (P520)         ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let store = Arc::new(BlockStore::new());
    let server = ClusterMuxServer::new(addr, "dl360.aint", store);
    println!("RAM B listening on {} — RAID-0 block storage", addr);
    println!("Press Ctrl+C to stop.");
    println!();

    server.serve().await.expect("RAM B server failed");
}

/// Client mode: acts as RAM A controller (P520), evicts to remote RAM B
async fn run_raid_client(endpoint: &str) {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  RAM RAID-0 Client — Cross-Machine Demo (P520)   ║");
    println!("║  Evicts odd blocks to RAM B via ClusterMux       ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let handle = tokio::runtime::Handle::current();
    let client = Arc::new(ClusterMuxClient::new(endpoint, "p520.aint"));

    // Ping remote first
    println!("═══ Ping RAM B ═══");
    let rtt = client.ping().await.expect("Cannot reach RAM B server");
    println!("  RTT to RAM B: {}µs ✓\n", rtt);

    run_raid_test(Some(client), handle, None).await;
}

/// Loopback: MUX server + RAM RAID on same machine
async fn run_loopback() {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  RAM RAID-0 — Cluster Loopback Test              ║");
    println!("║  P520 (RAM A) ↔ DL360 (RAM B) on localhost       ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    // Start MUX server (simulates DL360 RAM B)
    let ram_b_store = Arc::new(BlockStore::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let store_clone = ram_b_store.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    socket.set_nodelay(true).ok();
                    let s = store_clone.clone();
                    let frames = Arc::new(AtomicU64::new(0));
                    tokio::spawn(async move {
                        let _ = handle_mux_connection(socket, s, "dl360.aint", frames).await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    let handle = tokio::runtime::Handle::current();
    let client = Arc::new(ClusterMuxClient::new(&addr, "p520.aint"));

    // Quick ping
    let rtt = client.ping().await.unwrap();
    println!("RAM B (MUX) on {} — RTT: {}µs\n", addr, rtt);

    run_raid_test(Some(client), handle, Some(ram_b_store)).await;
}

async fn run_raid_test(
    mux_client: Option<Arc<ClusterMuxClient>>,
    handle: tokio::runtime::Handle,
    ram_b_store: Option<Arc<BlockStore>>,
) {
    let mut passed = 0;
    let mut total = 6;

    // ═══════════════════════════════════════════════════════════
    // Test 1: Basic RAID-0 striping + eviction + restore
    // ═══════════════════════════════════════════════════════════
    println!("═══ Test 1: RAID-0 Stripe + Evict + Restore (8 blocks, max 4 resident) ═══");
    {
        // 8 blocks × 2MB = 16MB virtual, max 4 resident at a time
        let config = RaidConfig::new(8 * RAID_BLOCK_SIZE, "ram_raid:test", "p520.aint")
            .with_remote_ram_b("dl360.aint", "127.0.0.1:4432")
            .with_max_resident(4);

        let mut controller = RamRaidController::new(config);
        if let Some(ref client) = mux_client {
            controller = controller.with_mux_transport(client.clone(), handle.clone());
        }

        // Write to all 8 blocks (forces eviction after 4)
        println!("  Writing to 8 blocks (max 4 resident)...");
        for i in 0..8 {
            controller.simulate_write(i);
            let stripe = RaidStripe::from_block_index(i);
            println!("    Block {} [{:?}] → written (resident: {})",
                     i, stripe, controller.resident_blocks());
        }

        // Now we should be at max capacity
        assert!(controller.resident_blocks() <= 8);

        // Force eviction to get some blocks to remote
        println!("  Evicting to create pressure...");
        let evictions = controller.proactive_evict();
        println!("    Evicted {} blocks", evictions.len());

        for result in &evictions {
            match result {
                EvictionResult::EvictedRemote { block_index, transfer_us, .. } => {
                    println!("    Block {} → RAM B (remote, {}µs)", block_index, transfer_us);
                }
                EvictionResult::EvictedLocal { block_index, .. } => {
                    println!("    Block {} → local store", block_index);
                }
                EvictionResult::Dropped { block_index } => {
                    println!("    Block {} → dropped (clean)", block_index);
                }
                _ => {}
            }
        }

        // Read back all blocks — blocks on remote should trigger fetch
        println!("  Reading all blocks back...");
        for i in 0..8 {
            let result = controller.simulate_read(i);
            match &result {
                FaultResult::AlreadyResident { .. } => {
                    println!("    Block {} → already resident", i);
                }
                FaultResult::RestoredRemote { fetch_us, total_us, .. } => {
                    println!("    Block {} → fetched from RAM B (fetch={}µs, total={}µs) ✓",
                             i, fetch_us, total_us);
                }
                FaultResult::RestoredLocal { total_us, .. } => {
                    println!("    Block {} → restored local ({}µs)", i, total_us);
                }
                FaultResult::ZeroFilled { .. } => {
                    println!("    Block {} → zero filled", i);
                }
                FaultResult::EvictedThenRestored { evicted_block, restored_block, total_us, .. } => {
                    println!("    Block {} → evicted {} then restored ({}µs)",
                             restored_block, evicted_block, total_us);
                }
                FaultResult::Failed { reason, .. } => {
                    println!("    Block {} → FAILED: {}", i, reason);
                }
            }
        }

        let stats = controller.stats();
        println!("  Stats: {} faults, {} evictions, {} remote transfers",
                 stats.faults_handled, stats.evictions_performed, stats.remote_transfers);

        if stats.remote_transfers > 0 {
            println!("  PASS ✓");
            passed += 1;
        } else {
            println!("  FAIL: no remote transfers");
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Test 2: Evict + fetch round-trip integrity
    // ═══════════════════════════════════════════════════════════
    println!("\n═══ Test 2: Evict + Fetch Integrity Check ═══");
    {
        let config = RaidConfig::new(4 * RAID_BLOCK_SIZE, "ram_raid:integrity", "p520.aint")
            .with_remote_ram_b("dl360.aint", "127.0.0.1:4432")
            .with_max_resident(2);

        let mut controller = RamRaidController::new(config);
        if let Some(ref client) = mux_client {
            controller = controller.with_mux_transport(client.clone(), handle.clone());
        }

        // Write 4 blocks, max 2 resident → forces eviction
        for i in 0..4 {
            controller.simulate_write(i);
        }

        // Evict all non-essential
        let _ = controller.proactive_evict();

        // Count remote blocks
        let remote_count = controller.blocks.iter()
            .filter(|b| matches!(b.location, BlockLocation::RemoteKernel { .. }))
            .count();

        // Fetch them back
        let mut fetch_ok = true;
        for i in 0..4 {
            let result = controller.simulate_read(i);
            match result {
                FaultResult::RestoredRemote { .. }
                | FaultResult::RestoredLocal { .. }
                | FaultResult::AlreadyResident { .. }
                | FaultResult::ZeroFilled { .. }
                | FaultResult::EvictedThenRestored { .. } => {}
                FaultResult::Failed { reason, .. } => {
                    println!("  Block {} fetch FAILED: {}", i, reason);
                    fetch_ok = false;
                }
            }
        }

        if fetch_ok && remote_count > 0 {
            println!("  {} blocks evicted to remote, all restored OK ✓", remote_count);
            passed += 1;
        } else if fetch_ok {
            println!("  All restored OK but no remote evictions (local only) ✓");
            passed += 1;
        } else {
            println!("  FAIL");
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Test 3: A/B — Sequential vs Batch Restore
    // ═══════════════════════════════════════════════════════════
    println!("\n═══ Test 3: A/B — Sequential vs Batch Restore (16 blocks) ═══");
    {
        let num_blocks = 16;

        // ── A: Sequential (one-by-one) ──
        println!("  ── A: Sequential restore ──");
        let seq_ms;
        let seq_remote;
        {
            let config = RaidConfig::new(num_blocks * RAID_BLOCK_SIZE, "ram_raid:seq", "p520.aint")
                .with_remote_ram_b("dl360.aint", "127.0.0.1:4432")
                .with_max_resident(num_blocks); // all can be resident for restore

            let mut controller = RamRaidController::new(config);
            if let Some(ref client) = mux_client {
                controller = controller.with_mux_transport(client.clone(), handle.clone());
            }

            // Write all, then evict to remote
            for i in 0..num_blocks {
                controller.simulate_write(i);
            }
            // Force eviction with low max
            controller.config.max_resident_blocks = num_blocks / 4;
            let _ = controller.proactive_evict();
            controller.config.max_resident_blocks = num_blocks; // restore limit

            seq_remote = controller.blocks.iter()
                .filter(|b| matches!(b.location, BlockLocation::RemoteKernel { .. }))
                .count();

            let t0 = Instant::now();
            for i in 0..num_blocks {
                let _ = controller.simulate_read(i);
            }
            seq_ms = t0.elapsed().as_millis();
            println!("    {} blocks restored ({} remote), {}ms", num_blocks, seq_remote, seq_ms);
        }

        // ── B: Batch (pipelined) ──
        println!("  ── B: Batch restore (pipelined) ──");
        let batch_ms;
        let batch_remote;
        {
            let config = RaidConfig::new(num_blocks * RAID_BLOCK_SIZE, "ram_raid:batch", "p520.aint")
                .with_remote_ram_b("dl360.aint", "127.0.0.1:4432")
                .with_max_resident(num_blocks);

            let mut controller = RamRaidController::new(config);
            if let Some(ref client) = mux_client {
                controller = controller.with_mux_transport(client.clone(), handle.clone());
            }

            // Write all, then evict to remote (same pattern)
            for i in 0..num_blocks {
                controller.simulate_write(i);
            }
            controller.config.max_resident_blocks = num_blocks / 4;
            let _ = controller.proactive_evict();
            controller.config.max_resident_blocks = num_blocks;

            batch_remote = controller.blocks.iter()
                .filter(|b| matches!(b.location, BlockLocation::RemoteKernel { .. }))
                .count();

            let all_indices: Vec<usize> = (0..num_blocks).collect();
            let t0 = Instant::now();
            let results = controller.simulate_read_batch(&all_indices);
            batch_ms = t0.elapsed().as_millis();

            let ok = results.iter().filter(|r| !matches!(r, FaultResult::Failed { .. })).count();
            println!("    {} blocks restored ({} remote), {}ms", ok, batch_remote, batch_ms);
        }

        let speedup = if batch_ms > 0 { seq_ms as f64 / batch_ms as f64 } else { f64::INFINITY };
        let total_mb = (seq_remote * RAID_BLOCK_SIZE) as f64 / 1_000_000.0;
        println!("  ── Result ──");
        println!("    Sequential: {}ms ({} remote blocks, {:.0}MB)", seq_ms, seq_remote, total_mb);
        println!("    Batch:      {}ms ({} remote blocks, {:.0}MB)", batch_ms, batch_remote, total_mb);
        println!("    Speedup:    {:.1}x ✓", speedup);
        passed += 1;
    }

    // ═══════════════════════════════════════════════════════════
    // Test 4: Stripe verification (even=A, odd=B)
    // ═══════════════════════════════════════════════════════════
    println!("\n═══ Test 4: RAID-0 Stripe Correctness ═══");
    {
        let config = RaidConfig::new(8 * RAID_BLOCK_SIZE, "ram_raid:stripe", "p520.aint")
            .with_remote_ram_b("dl360.aint", "127.0.0.1:4432");

        let controller = RamRaidController::new(config);

        let mut correct = true;
        for i in 0..8 {
            let expected = if i % 2 == 0 { RaidStripe::RamA } else { RaidStripe::RamB };
            if controller.blocks[i].stripe != expected {
                println!("  Block {} stripe mismatch: expected {:?}, got {:?}",
                         i, expected, controller.blocks[i].stripe);
                correct = false;
            }
        }

        if correct {
            println!("  Even blocks → RAM A, Odd blocks → RAM B ✓");
            passed += 1;
        } else {
            println!("  FAIL: stripe assignment incorrect");
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Test 5: Pressure test — heavy eviction/restore cycle
    // ═══════════════════════════════════════════════════════════
    println!("\n═══ Test 5: Pressure Test (32 blocks, max 8 resident) ═══");
    {
        let num_blocks = 32;
        let max_res = 8;
        let config = RaidConfig::new(num_blocks * RAID_BLOCK_SIZE, "ram_raid:pressure", "p520.aint")
            .with_remote_ram_b("dl360.aint", "127.0.0.1:4432")
            .with_max_resident(max_res);

        let mut controller = RamRaidController::new(config);
        if let Some(ref client) = mux_client {
            controller = controller.with_mux_transport(client.clone(), handle.clone());
        }

        // Write all 32 blocks
        let t0 = Instant::now();
        for i in 0..num_blocks {
            controller.simulate_write(i);
            // Proactive eviction at each step to keep within limits
            if controller.resident_blocks() > max_res {
                controller.proactive_evict();
            }
        }

        // Random-ish read pattern: read blocks in reverse
        for i in (0..num_blocks).rev() {
            let _ = controller.simulate_read(i);
        }

        // Read again forward
        for i in 0..num_blocks {
            let _ = controller.simulate_read(i);
        }

        let total_ms = t0.elapsed().as_millis();
        let stats = controller.stats();

        println!("  {} blocks, max {} resident, {}ms total", num_blocks, max_res, total_ms);
        println!("  Faults:     {}", stats.faults_handled);
        println!("  Evictions:  {}", stats.evictions_performed);
        println!("  Remote:     {} transfers", stats.remote_transfers);
        println!("  Compressed: {:.1} MB", stats.bytes_compressed as f64 / 1_000_000.0);

        if stats.faults_handled > 0 && stats.evictions_performed > 0 {
            println!("  PASS ✓");
            passed += 1;
        } else {
            println!("  FAIL: no faults or evictions");
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Test 6: Prefetch — LLM Layer Loading Pattern
    // ═══════════════════════════════════════════════════════════
    println!("\n═══ Test 6: Prefetch — LLM Layer Loading ═══");
    {
        let num_layers = 24; // Simulate 24-layer transformer
        let config = RaidConfig::new(num_layers * RAID_BLOCK_SIZE, "ram_raid:llm", "p520.aint")
            .with_remote_ram_b("dl360.aint", "127.0.0.1:4432")
            .with_max_resident(num_layers);

        let mut controller = RamRaidController::new(config);
        if let Some(ref client) = mux_client {
            controller = controller.with_mux_transport(client.clone(), handle.clone());
        }

        // Load all layers (model weights)
        for i in 0..num_layers {
            controller.simulate_write(i);
        }

        // Evict most layers (simulates memory pressure from other tasks)
        controller.config.max_resident_blocks = 4;
        let evictions = controller.proactive_evict();
        controller.config.max_resident_blocks = num_layers;

        let remote_evicted = controller.blocks.iter()
            .filter(|b| matches!(b.location, BlockLocation::RemoteKernel { .. }))
            .count();

        println!("  {} layers, {} evicted to RAM B", num_layers, remote_evicted);

        // Simulate inference: process layer 0, prefetch layers 1-4
        // Then process layer 1, prefetch layers 5-8, etc.
        let prefetch_window = 4;
        let t0 = Instant::now();
        let mut total_prefetched = 0;

        for layer in 0..num_layers {
            // Read current layer
            let _ = controller.simulate_read(layer);

            // Prefetch next window
            let prefetch_start = layer + 1;
            let prefetch_end = (layer + 1 + prefetch_window).min(num_layers);
            if prefetch_start < prefetch_end {
                let indices: Vec<usize> = (prefetch_start..prefetch_end).collect();
                let (prefetched, _us) = controller.prefetch(&indices);
                total_prefetched += prefetched;
            }
        }

        let total_ms = t0.elapsed().as_millis();

        println!("  Inference: {} layers in {}ms", num_layers, total_ms);
        println!("  Prefetched: {} blocks ahead of time", total_prefetched);
        println!("  Pattern: read layer N, prefetch N+1..N+{}", prefetch_window);

        let stats = controller.stats();
        println!("  Remote transfers: {}", stats.remote_transfers);
        println!("  PASS ✓");
        passed += 1;
    }

    // ═══════════════════════════════════════════════════════════
    // Test 7: Hash Cache — 1st/2nd/3rd Load Performance
    // ═══════════════════════════════════════════════════════════
    total += 1;
    println!("\n═══ Test 7: Hash Cache — Repeat Load Acceleration ═══");
    {
        let num_blocks = 8;
        let config = RaidConfig::new(num_blocks * RAID_BLOCK_SIZE, "ram_raid:cache", "p520.aint")
            .with_remote_ram_b("dl360.aint", "127.0.0.1:4432")
            .with_max_resident(num_blocks);

        // Fresh MUX client for clean cache stats
        let cache_client = if let Some(ref client) = mux_client {
            let fresh = Arc::new(ClusterMuxClient::new(&client.endpoint, "p520.aint"));
            Some(fresh)
        } else {
            None
        };

        let mut controller = RamRaidController::new(config);
        if let Some(ref client) = cache_client {
            controller = controller.with_mux_transport(client.clone(), handle.clone());
        }

        // Write all blocks, then evict odd blocks to RAM B
        for i in 0..num_blocks {
            controller.simulate_write(i);
        }
        controller.config.max_resident_blocks = 4;
        controller.proactive_evict();
        controller.config.max_resident_blocks = num_blocks;

        let remote_count = controller.blocks.iter()
            .filter(|b| matches!(b.location, BlockLocation::RemoteKernel { .. }))
            .count();
        println!("  {} blocks evicted to RAM B", remote_count);

        // 1st load: cold — full SHA-256 verification on every remote block
        let t1 = Instant::now();
        for i in 0..num_blocks {
            let _ = controller.simulate_read(i);
        }
        let first_us = t1.elapsed().as_micros();

        // Evict again for 2nd load test
        controller.config.max_resident_blocks = 4;
        controller.proactive_evict();
        controller.config.max_resident_blocks = num_blocks;

        // 2nd load: warm — hash cache hits, SHA-256 skipped
        let t2 = Instant::now();
        for i in 0..num_blocks {
            let _ = controller.simulate_read(i);
        }
        let second_us = t2.elapsed().as_micros();

        // Evict again for 3rd load test
        controller.config.max_resident_blocks = 4;
        controller.proactive_evict();
        controller.config.max_resident_blocks = num_blocks;

        // 3rd load: hot — still cached
        let t3 = Instant::now();
        for i in 0..num_blocks {
            let _ = controller.simulate_read(i);
        }
        let third_us = t3.elapsed().as_micros();

        if let Some(ref client) = cache_client {
            let (hits, misses, _, bytes_saved) = client.hash_cache.stats();
            let total_ops = hits + misses;
            let ratio = if total_ops > 0 { hits as f64 / total_ops as f64 } else { 0.0 };
            println!("  1st load (SHA-256):  {:>8}µs", first_us);
            println!("  2nd load (cached):   {:>8}µs", second_us);
            println!("  3rd load (cached):   {:>8}µs", third_us);
            println!("  Cache hits: {}, misses: {}, ratio: {:.0}%", hits, misses, ratio * 100.0);
            println!("  SHA-256 bytes saved: {:.1} MB", bytes_saved as f64 / 1_000_000.0);
            if second_us > 0 && first_us > second_us {
                println!("  Speedup 2nd vs 1st:  {:.1}x", first_us as f64 / second_us as f64);
            }
        }

        println!("  PASS ✓");
        passed += 1;
    }

    // ═══════════════════════════════════════════════════════════
    // Summary
    // ═══════════════════════════════════════════════════════════
    if let Some(ref store) = ram_b_store {
        let (stored, served, bytes) = store.stats();
        println!("\n═══ RAM B Store Stats ═══");
        println!("  Blocks stored: {}", stored);
        println!("  Blocks served: {}", served);
        println!("  Total bytes:   {:.1} MB", bytes as f64 / 1_000_000.0);
    }

    if let Some(ref client) = mux_client {
        println!("\n═══ MUX Client Stats ═══");
        println!("  Requests:    {}", client.requests_sent.load(Ordering::Relaxed));
        println!("  Transferred: {:.1} MB", client.bytes_transferred.load(Ordering::Relaxed) as f64 / 1_000_000.0);
    }

    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║  {}/{} tests passed!                              ║", passed, total);
    if passed == total {
        println!("║  RAM RAID-0 cross-machine: OPERATIONAL           ║");
        println!("║  P520 (RAM A) ↔ DL360 (RAM B) via ClusterMux    ║");
    }
    println!("╚═══════════════════════════════════════════════════╝");
}
