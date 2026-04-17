// ═══════════════════════════════════════════════════════════════
// LLM Memory Mapper Demo — DIME Aperture in Action
//
// Simulates loading a 48GB LLM model (llama-70B at Q4_K_M)
// across two machines using the DIME aperture pattern:
//   P520 (RAM A, 32GB) ↔ DL360 (RAM B, 32GB) = 64GB virtual
//
// "Het is eigenlijk DIME — die aperture die openstaat en dan
//  bekende filesizes erdoorheen jassen. 2026 AGP poort."
//                                              — Jasper
//
// Usage:
//   llm-mapper-demo              # Quick 48MB simulation
//   llm-mapper-demo large        # 1GB simulation (256 layers)
//   llm-mapper-demo 70b          # Aperture-only 40GB/70B model
// ═══════════════════════════════════════════════════════════════

use tibet_trust_kernel::llm_mapper::*;
use tibet_trust_kernel::cluster_mux::*;
use tibet_trust_kernel::cluster_transport::BlockStore;
use tibet_trust_kernel::ram_raid::RAID_BLOCK_SIZE;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("quick");

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  LLM Memory Mapper — DIME Aperture Demo                 ║");
    println!("║  3dfx Voodoo AGP Texture Aperture, maar dan voor AI     ║");
    println!("║  P520 (RAM A) ↔ DL360 (RAM B) via ClusterMux            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    match mode {
        "large" => run_large_simulation().await,
        "70b" => run_70b_aperture(),
        _ => run_quick_simulation().await,
    }
}

/// Quick simulation: 48MB model, 24 layers, with real MUX transport
async fn run_quick_simulation() {
    println!("═══ Quick Simulation: 48MB model, 24 layers ═══\n");

    // Start MUX server (simulates DL360 RAM B)
    let (addr, _store) = start_mux_server().await;
    let handle = tokio::runtime::Handle::current();
    let client = Arc::new(ClusterMuxClient::new(&addr, "p520.aint"));

    // Ping RAM B
    let rtt = client.ping().await.unwrap();
    println!("  RAM B (DL360) on {} — RTT: {}µs\n", addr, rtt);

    // Create model manifest
    let manifest = ModelManifest::synthetic(
        "llama-3.1-8B-Q4_K_M",
        48 * 1024 * 1024,  // 48MB (scaled down for demo)
        24,                 // 24 transformer layers
        "Q4_K_M",
    );

    println!("  Model: {}", manifest.name);
    println!("  Size:  {:.1} MB ({} blocks × {} MB)",
        manifest.total_bytes as f64 / 1_000_000.0,
        manifest.num_blocks,
        manifest.block_size / (1024 * 1024));
    println!("  Layers: {}, blocks/layer: {}", manifest.num_layers, manifest.blocks_per_layer());
    println!("  Quant: {}, format: {}", manifest.quantization, manifest.format);
    println!();

    // Create mapper with 12-block RAM budget (half the model)
    let mut mapper = LlmMemoryMapper::new(manifest)
        .with_mux_transport(client.clone(), handle.clone())
        .with_ram_budget_blocks(12)
        .with_prefetch_window(4);

    // ─── Phase 1: Initial aperture (all unmapped) ───
    println!("═══ Phase 1: Aperture Created (all Unmapped) ═══\n");
    mapper.print_aperture();

    // ─── Phase 2: Materialize first 4 layers ───
    println!("\n═══ Phase 2: Materialize Layers 0-3 ═══\n");
    for layer in 0..4 {
        let result = mapper.materialize_layer(layer);
        println!("  Layer {:>2}: {} blocks loaded, {} from remote, {}µs",
            result.layer, result.blocks_loaded, result.blocks_from_remote, result.duration_us);
    }
    println!();
    mapper.print_aperture();

    // ─── Phase 3: Prefetch layers 4-7 ───
    println!("\n═══ Phase 3: Prefetch Layers 4-7 ═══\n");
    let prefetch = mapper.prefetch_layers(3);
    println!("  Prefetched: {} blocks across {} layers in {}µs",
        prefetch.blocks_prefetched, prefetch.layers_ahead, prefetch.duration_us);
    println!();
    mapper.print_aperture();

    // ─── Phase 4: Full inference simulation ───
    println!("\n═══ Phase 4: Full Inference (24 layers, sliding window) ═══\n");

    // Reset mapper for clean inference
    let manifest2 = ModelManifest::synthetic("llama-3.1-8B-Q4_K_M", 48 * 1024 * 1024, 24, "Q4_K_M");
    let mut mapper2 = LlmMemoryMapper::new(manifest2)
        .with_mux_transport(client.clone(), handle.clone())
        .with_ram_budget_blocks(8)
        .with_prefetch_window(4);

    let t0 = Instant::now();
    let result = mapper2.simulate_inference();
    let total_ms = t0.elapsed().as_millis();

    println!("  Layers processed:  {}", result.layers_processed);
    println!("  Blocks loaded:     {}", result.total_blocks_loaded);
    println!("  Blocks prefetched: {}", result.total_prefetched);
    println!("  Blocks evicted:    {}", result.total_evicted);
    println!("  Total time:        {}ms", total_ms);
    println!("  Avg per layer:     {}µs", result.avg_layer_us);
    println!("  Data transferred:  {:.1} MB", result.bytes_transferred as f64 / 1_000_000.0);
    println!();
    mapper2.print_aperture();

    // ─── Phase 5: Heartbeat ───
    println!("\n═══ Phase 5: Heartbeat ═══\n");
    if let Some(hb) = mapper2.heartbeat() {
        println!("  Connection alive: {}", hb.connection_alive);
        println!("  RTT: {}µs", hb.rtt_us);
    }

    // ─── MUX Stats ───
    println!("\n═══ MUX Client Stats ═══");
    println!("  Requests:    {}", client.requests_sent.load(Ordering::Relaxed));
    println!("  Transferred: {:.1} MB", client.bytes_transferred.load(Ordering::Relaxed) as f64 / 1_000_000.0);
    let (hits, misses, ratio, saved) = client.hash_cache.stats();
    println!("  Cache hits:  {} ({:.0}%), misses: {}", hits, ratio * 100.0, misses);
    println!("  SHA-256 saved: {:.1} MB", saved as f64 / 1_000_000.0);

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  DIME Aperture: OPERATIONAL                             ║");
    println!("║  Model transparently mapped across two machines         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
}

/// Larger simulation: 1GB model, 256 layers
async fn run_large_simulation() {
    println!("═══ Large Simulation: 1GB model, 256 layers ═══\n");

    let (addr, _store) = start_mux_server().await;
    let handle = tokio::runtime::Handle::current();
    let client = Arc::new(ClusterMuxClient::new(&addr, "p520.aint"));

    let rtt = client.ping().await.unwrap();
    println!("  RAM B RTT: {}µs\n", rtt);

    let model_size = 1024 * 1024 * 1024; // 1GB
    let manifest = ModelManifest::synthetic("llama-3.1-70B-Q4_K_M-scaled", model_size, 80, "Q4_K_M");

    println!("  Model: {}", manifest.name);
    println!("  Size:  {:.0} MB ({} blocks)", model_size as f64 / 1_000_000.0, manifest.num_blocks);
    println!("  Layers: {}, blocks/layer: {}", manifest.num_layers, manifest.blocks_per_layer());
    println!();

    // RAM budget: 25% of model (simulates 32GB RAM for 128GB model)
    let budget = manifest.num_blocks / 4;
    let mut mapper = LlmMemoryMapper::new(manifest)
        .with_mux_transport(client.clone(), handle.clone())
        .with_ram_budget_blocks(budget)
        .with_prefetch_window(4);

    println!("  RAM budget: {} blocks ({:.0} MB, {:.0}% of model)\n",
        budget, budget as f64 * 2.0, 25.0);

    let t0 = Instant::now();
    let result = mapper.simulate_inference();
    let total_ms = t0.elapsed().as_millis();

    println!("  ── Inference Complete ──");
    println!("  Layers:      {}", result.layers_processed);
    println!("  Loaded:      {} blocks", result.total_blocks_loaded);
    println!("  Prefetched:  {} blocks", result.total_prefetched);
    println!("  Evicted:     {} blocks", result.total_evicted);
    println!("  Time:        {}ms ({:.1}s)", total_ms, total_ms as f64 / 1000.0);
    println!("  Avg/layer:   {}µs", result.avg_layer_us);
    println!("  Data:        {:.1} MB transferred", result.bytes_transferred as f64 / 1_000_000.0);

    let (hits, misses, ratio, saved) = client.hash_cache.stats();
    println!("  Cache:       {} hits ({:.0}%), {} misses", hits, ratio * 100.0, misses);
    println!("  SHA-256 saved: {:.1} MB", saved as f64 / 1_000_000.0);

    println!();
    println!("  Aperture snapshot (first 128 blocks):");
    let map = mapper.aperture_map();
    let preview: String = map.chars().take(128).collect();
    println!("  {}", preview);
    println!("  █=Resident ░=Unmapped ·=Evicted");

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  1GB Model Inference: COMPLETE                          ║");
    println!("║  Cross-machine DIME aperture: OPERATIONAL               ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
}

/// Aperture-only demo for 70B model (no data transfer, just the map)
fn run_70b_aperture() {
    println!("═══ 70B Model Aperture Map (40GB, Q4_K_M) ═══\n");

    let model_size = 40_usize * 1024 * 1024 * 1024; // 40GB
    let manifest = ModelManifest::synthetic("llama-3.1-70B-Q4_K_M", model_size, 80, "Q4_K_M");

    println!("  Model:         {}", manifest.name);
    println!("  Total size:    {:.1} GB", model_size as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("  Blocks:        {} × 2MB", manifest.num_blocks);
    println!("  Layers:        {}", manifest.num_layers);
    println!("  Blocks/layer:  {}", manifest.blocks_per_layer());
    println!("  Quantization:  {}", manifest.quantization);
    println!();

    let mapper = LlmMemoryMapper::new(manifest.clone());

    // RAID-0 stripe distribution
    let ram_a_blocks = mapper.aperture.iter().filter(|b| b.stripe == tibet_trust_kernel::ram_raid::RaidStripe::RamA).count();
    let ram_b_blocks = mapper.aperture.iter().filter(|b| b.stripe == tibet_trust_kernel::ram_raid::RaidStripe::RamB).count();

    println!("  ── RAID-0 Stripe Distribution ──");
    println!("  RAM A (P520, local):  {} blocks ({:.1} GB)", ram_a_blocks, ram_a_blocks as f64 * 2.0 / 1024.0);
    println!("  RAM B (DL360, remote): {} blocks ({:.1} GB)", ram_b_blocks, ram_b_blocks as f64 * 2.0 / 1024.0);
    println!();

    // Per-layer breakdown
    println!("  ── Layer Layout (first 10 of {}) ──", manifest.num_layers);
    for layer in 0..10.min(manifest.num_layers) {
        let blocks = manifest.layer_blocks(layer);
        let remote = blocks.iter().filter(|&&i| i % 2 == 1).count();
        let local = blocks.len() - remote;
        println!("  Layer {:>2}: {} blocks ({}L + {}R), {:.1} MB",
            layer, blocks.len(), local, remote,
            blocks.len() as f64 * 2.0);
    }
    println!("  ...");
    println!();

    // Scenarios
    println!("  ── Memory Scenarios ──");
    let scenarios = [
        ("P520 alleen (32GB RAM)", 32_usize * 1024 / 2),    // 16384 blocks
        ("P520 + DL360 (64GB RAM)", 64_usize * 1024 / 2),   // 32768 blocks (> model!)
        ("P520 + 2× DL360 (96GB)", 96_usize * 1024 / 2),
    ];

    for (name, budget_blocks) in &scenarios {
        let resident_pct = (*budget_blocks as f64 / manifest.num_blocks as f64 * 100.0).min(100.0);
        let fits = *budget_blocks >= manifest.num_blocks;
        println!("  {}: {:.0}% resident {}",
            name, resident_pct,
            if fits { "✓ fits entirely!" } else { "— needs streaming" });
    }

    println!();
    println!("  All {} blocks start as Unmapped spaceholders.", manifest.num_blocks);
    println!("  On first page fault → MUX fetch from RAM B → block materializes.");
    println!("  2nd+ access → hash cache hit → SHA-256 skipped → 14x faster.");

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║  70B Aperture: {} blocks across P520 ↔ DL360     ║", manifest.num_blocks);
    println!("║  With 64GB combined: model fits entirely in RAM!        ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
}

/// Start a loopback MUX server
async fn start_mux_server() -> (String, Arc<BlockStore>) {
    let store = Arc::new(BlockStore::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let store_clone = store.clone();
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

    (addr, store)
}
