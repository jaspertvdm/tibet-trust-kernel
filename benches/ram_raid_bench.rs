use std::time::Instant;

/// RAM RAID-0 Benchmark — Transparante Geheugen-Virtualisatie
///
/// Meet de kernprestaties van het Mad Professor Plan:
///   1. Block striping (even/oneven → RAM A/B)
///   2. Page fault handling (userfaultfd simulatie)
///   3. Eviction (compress + sign + store)
///   4. Remote restore (fetch + decompress + verify + inject)
///   5. Mixed workload (Redis-achtig patroon)
///   6. RAID-0 vs traditioneel vergelijking

#[path = "../src/ram_raid.rs"]
mod ram_raid;

use ram_raid::*;

fn main() {
    println!("═══════════════════════════════════════════════════════════════");
    println!("◈ RAM RAID-0 Benchmark — Trust Kernel v1");
    println!("◈ Transparante Geheugen-Virtualisatie via userfaultfd");
    println!("═══════════════════════════════════════════════════════════════\n");

    bench_block_setup();
    bench_page_fault_virgin();
    bench_page_fault_local_restore();
    bench_page_fault_remote_restore();
    bench_eviction();
    bench_mixed_workload();
    bench_raid_striping();
    bench_redis_simulation();
    bench_scaling();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("◈ RAM RAID-0 Benchmark Complete");
    println!("═══════════════════════════════════════════════════════════════");
}

// ═══════════════════════════════════════════════════════════════
// Part 1: Block Setup & Configuration
// ═══════════════════════════════════════════════════════════════

fn bench_block_setup() {
    println!("── Part 1: Block Setup & Configuration ──\n");

    let iterations = 1000;

    // Test arena creation for various sizes
    let sizes = [
        ("4MB", 4 * 1024 * 1024),
        ("64MB", 64 * 1024 * 1024),
        ("512MB", 512 * 1024 * 1024),
        ("1GB", 1024 * 1024 * 1024),
    ];

    for (label, size) in &sizes {
        let t0 = Instant::now();
        for _ in 0..iterations {
            let config = RaidConfig::new(*size, "db:redis", "root_idd.aint");
            let controller = RamRaidController::new(config);
            std::hint::black_box(&controller);
        }
        let elapsed = t0.elapsed();
        let per_op = elapsed / iterations;

        let config = RaidConfig::new(*size, "db:redis", "root_idd.aint");
        let blocks = config.block_count();
        let ram_a = blocks / 2 + blocks % 2;
        let ram_b = blocks / 2;

        println!("  {} arena: {:?}/create ({} blocks: {} RAM-A, {} RAM-B)",
            label, per_op, blocks, ram_a, ram_b);
    }

    // Stripe assignment speed
    let t0 = Instant::now();
    let stripe_iters = 100_000u64;
    for i in 0..stripe_iters {
        let stripe = RaidStripe::from_block_index(i as usize);
        std::hint::black_box(stripe);
    }
    let elapsed = t0.elapsed();
    println!("\n  Stripe assignment: {:?}/op ({} ops)",
        elapsed / stripe_iters as u32, stripe_iters);

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 2: Virgin Page Faults (Zero Pages)
// ═══════════════════════════════════════════════════════════════

fn bench_page_fault_virgin() {
    println!("── Part 2: Virgin Page Faults (Zero Pages) ──\n");

    let iterations = 10_000;
    let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint");
    let mut controller = RamRaidController::new(config);

    let t0 = Instant::now();
    for i in 0..iterations {
        let block_idx = i % controller.block_count();
        let fault_addr = block_idx * RAID_BLOCK_SIZE;

        // Reset block to virgin for next iteration
        if controller.blocks[block_idx].location == BlockLocation::Resident {
            controller.blocks[block_idx].location = BlockLocation::Virgin;
            controller.resident_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        let result = controller.handle_fault(fault_addr);
        std::hint::black_box(&result);
    }
    let elapsed = t0.elapsed();
    let per_op = elapsed / iterations as u32;

    let stats = controller.stats();
    println!("  Virgin page fault: {:?}/fault ({} faults, {} zero pages served)",
        per_op, iterations, stats.zero_pages_served);
    println!("  = App touches empty memory → zero page in {:?} (no disk, no network)", per_op);

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 3: Local Restore (from Archivaris .tza)
// ═══════════════════════════════════════════════════════════════

fn bench_page_fault_local_restore() {
    println!("── Part 3: Local Restore (from Archivaris .tza) ──\n");

    let iterations = 10_000;
    let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint");
    let mut controller = RamRaidController::new(config);

    // Pre-populate blocks as locally evicted
    for i in 0..controller.block_count() {
        controller.blocks[i].location = BlockLocation::LocalStore {
            tza_path: format!("/var/lib/airlock/raid/block_{}.tza", i),
            fork_token_id: format!("raid_fork_{}", i),
        };
        controller.blocks[i].content_hash = Some(format!("sha256:block_{}", i));
        controller.blocks[i].seal = Some(format!("ed25519:seal_{}", i));
    }

    let t0 = Instant::now();
    for i in 0..iterations {
        let block_idx = i % controller.block_count();
        let fault_addr = block_idx * RAID_BLOCK_SIZE;

        // Reset to evicted state
        controller.blocks[block_idx].location = BlockLocation::LocalStore {
            tza_path: format!("/var/lib/airlock/raid/block_{}.tza", block_idx),
            fork_token_id: format!("raid_fork_{}", block_idx),
        };
        if controller.resident_count.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            controller.resident_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        let result = controller.handle_fault(fault_addr);
        std::hint::black_box(&result);
    }
    let elapsed = t0.elapsed();
    let per_op = elapsed / iterations as u32;

    println!("  Local restore: {:?}/fault", per_op);
    println!("  = .tza load → Ed25519 verify → zstd decompress → uffd.copy()");
    println!("  = App leest geëvict blok → data terug in {:?}", per_op);

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 4: Remote Restore (from RAM B via Intent Mux)
// ═══════════════════════════════════════════════════════════════

fn bench_page_fault_remote_restore() {
    println!("── Part 4: Remote Restore (from RAM B via Intent Mux) ──\n");

    let iterations = 5_000;
    let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint")
        .with_remote_ram_b("kernel_b.aint", "192.168.4.85:4430");
    let mut controller = RamRaidController::new(config);

    // Pre-populate odd blocks as remotely evicted
    for i in 0..controller.block_count() {
        if i % 2 == 1 {
            controller.blocks[i].location = BlockLocation::RemoteKernel {
                kernel_id: "kernel_b.aint".to_string(),
                endpoint: "192.168.4.85:4430".to_string(),
                fork_token_id: format!("raid_fork_remote_{}", i),
            };
        }
    }

    let t0 = Instant::now();
    let mut remote_count = 0u32;
    for i in 0..iterations {
        let block_idx = (i * 2 + 1) % controller.block_count(); // Only odd blocks
        if block_idx >= controller.block_count() { continue; }
        let fault_addr = block_idx * RAID_BLOCK_SIZE;

        // Reset to remote state
        controller.blocks[block_idx].location = BlockLocation::RemoteKernel {
            kernel_id: "kernel_b.aint".to_string(),
            endpoint: "192.168.4.85:4430".to_string(),
            fork_token_id: format!("raid_fork_remote_{}", block_idx),
        };

        let result = controller.handle_fault(fault_addr);
        if matches!(result, FaultResult::RestoredRemote { .. }) {
            remote_count += 1;
        }
        std::hint::black_box(&result);
    }
    let elapsed = t0.elapsed();
    let per_op = if remote_count > 0 { elapsed / remote_count } else { elapsed };

    println!("  Remote restore: {:?}/fault ({} remote fetches)", per_op, remote_count);
    println!("  = Intent mux → TCP fetch → verify → decompress → inject");
    println!("  = Odd block op andere machine → terug in {:?}", per_op);

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 5: Eviction (Compress + Sign + Store)
// ═══════════════════════════════════════════════════════════════

fn bench_eviction() {
    println!("── Part 5: Eviction (Compress + Sign + Store) ──\n");

    let iterations = 5_000;

    // Local eviction
    {
        let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint");
        let mut controller = RamRaidController::new(config);

        // Make all blocks dirty + resident
        for i in 0..controller.block_count() {
            controller.simulate_write(i);
        }

        let t0 = Instant::now();
        for _ in 0..iterations {
            // Keep re-dirtying evicted blocks
            let stats = controller.stats();
            if stats.resident_blocks < 2 {
                for i in 0..controller.block_count() {
                    controller.simulate_write(i);
                }
            }
            let result = controller.evict_coldest();
            std::hint::black_box(&result);
        }
        let elapsed = t0.elapsed();
        let per_op = elapsed / iterations as u32;

        println!("  Local eviction: {:?}/block (dirty → compress → sign → .tza)", per_op);
    }

    // Remote eviction
    {
        let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint")
            .with_remote_ram_b("kernel_b.aint", "192.168.4.85:4430");
        let mut controller = RamRaidController::new(config);

        for i in 0..controller.block_count() {
            controller.simulate_write(i);
        }

        let t0 = Instant::now();
        for _ in 0..iterations {
            let stats = controller.stats();
            if stats.resident_blocks < 2 {
                for i in 0..controller.block_count() {
                    controller.simulate_write(i);
                }
            }
            let result = controller.evict_coldest();
            std::hint::black_box(&result);
        }
        let elapsed = t0.elapsed();
        let per_op = elapsed / iterations as u32;

        println!("  Remote eviction: {:?}/block (dirty → compress → sign → transfer)", per_op);
    }

    // Proactive eviction batch
    {
        let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint")
            .with_max_resident(16);
        let mut controller = RamRaidController::new(config);

        // Fill to 100%
        for i in 0..controller.block_count().min(16) {
            controller.simulate_write(i);
        }

        let t0 = Instant::now();
        let results = controller.proactive_evict();
        let elapsed = t0.elapsed();

        println!("\n  Proactive eviction: {:?} total for {} blocks ({:?}/block)",
            elapsed, results.len(),
            if results.is_empty() { elapsed } else { elapsed / results.len() as u32 });
    }

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 6: Mixed Workload (Read/Write Pattern)
// ═══════════════════════════════════════════════════════════════

fn bench_mixed_workload() {
    println!("── Part 6: Mixed Workload (Read/Write Pattern) ──\n");

    // 64MB arena with only 16 blocks resident (force evictions)
    let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint")
        .with_max_resident(16);
    let mut controller = RamRaidController::new(config);

    let total_ops = 50_000;
    let block_count = controller.block_count();

    // Seed some data
    for i in 0..block_count.min(16) {
        controller.simulate_write(i);
    }

    let t0 = Instant::now();
    let mut reads = 0u64;
    let mut writes = 0u64;
    let mut faults = 0u64;

    for i in 0..total_ops {
        let block_idx = (i * 7 + 13) % block_count; // Pseudo-random access pattern

        if i % 3 == 0 {
            // Write (33%)
            controller.simulate_write(block_idx);
            writes += 1;
        } else {
            // Read (67%)
            let result = controller.simulate_read(block_idx);
            reads += 1;
            if !matches!(result, FaultResult::AlreadyResident { .. }) {
                faults += 1;
            }
        }

        // Periodic proactive eviction
        if i % 1000 == 0 {
            controller.proactive_evict();
        }
    }
    let elapsed = t0.elapsed();
    let per_op = elapsed / total_ops as u32;

    let stats = controller.stats();
    let fault_rate = (faults as f64 / reads as f64) * 100.0;

    println!("  Mixed workload: {} ops in {:?}", total_ops, elapsed);
    println!("    Per op: {:?}", per_op);
    println!("    Reads: {}, Writes: {}, Faults: {} ({:.1}% fault rate)",
        reads, writes, faults, fault_rate);
    println!("    Resident: {}/{} blocks, Dirty: {}",
        stats.resident_blocks, stats.block_count, stats.dirty_blocks);
    println!("    Evictions: {}, Compressions: {} bytes",
        stats.evictions_performed, stats.bytes_compressed);

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 7: RAID-0 Striping Validation
// ═══════════════════════════════════════════════════════════════

fn bench_raid_striping() {
    println!("── Part 7: RAID-0 Striping Validation ──\n");

    let config = RaidConfig::new(64 * 1024 * 1024, "db:redis", "root_idd.aint")
        .with_remote_ram_b("kernel_b.aint", "192.168.4.85:4430");
    let controller = RamRaidController::new(config);

    let stats = controller.stats();
    println!("  Arena: {}MB ({} blocks x {}MB)",
        stats.arena_size / (1024 * 1024),
        stats.block_count,
        stats.block_size / (1024 * 1024));
    println!("  RAM A (even/local):  {} blocks ({}MB)",
        stats.ram_a_blocks, stats.ram_a_blocks * stats.block_size / (1024 * 1024));
    println!("  RAM B (odd/remote):  {} blocks ({}MB)",
        stats.ram_b_blocks, stats.ram_b_blocks * stats.block_size / (1024 * 1024));

    // Verify stripe assignment
    let mut a_correct = 0;
    let mut b_correct = 0;
    for block in &controller.blocks {
        match (block.index % 2, &block.stripe) {
            (0, RaidStripe::RamA) => a_correct += 1,
            (1, RaidStripe::RamB) => b_correct += 1,
            _ => {}
        }
    }
    println!("  Stripe correctness: RAM-A {}/{}, RAM-B {}/{}",
        a_correct, stats.ram_a_blocks, b_correct, stats.ram_b_blocks);

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 8: Redis Simulation
// ═══════════════════════════════════════════════════════════════

fn bench_redis_simulation() {
    println!("── Part 8: Redis Simulation (Transparent Memory Virtualization) ──\n");

    // Simulate: Redis has 256MB of data, but we only give it 64MB of physical RAM
    // The rest is transparently paged via RAM RAID
    let virtual_size = 256 * 1024 * 1024; // 256MB virtual
    let config = RaidConfig::new(virtual_size, "db:redis", "root_idd.aint")
        .with_max_resident(32)  // Only 64MB physical (32 blocks x 2MB)
        .with_remote_ram_b("kernel_b.aint", "192.168.4.85:4430");
    let mut controller = RamRaidController::new(config);

    println!("  Virtual memory:  {}MB ({} blocks)", virtual_size / (1024 * 1024), controller.block_count());
    println!("  Physical limit:  {}MB ({} resident blocks)",
        32 * RAID_BLOCK_SIZE / (1024 * 1024), 32);
    println!("  Overcommit:      {}x", controller.block_count() / 32);

    // Phase 1: Initial writes (Redis populating data)
    let populate_ops = 10_000;
    let block_count = controller.block_count();
    let t0 = Instant::now();
    for i in 0..populate_ops {
        let block_idx = i % block_count;
        controller.simulate_write(block_idx);

        // Evict when at capacity
        if controller.resident_blocks() >= 32 {
            controller.evict_coldest();
        }
    }
    let populate_time = t0.elapsed();

    // Phase 2: Hot key pattern (80% of reads hit 20% of blocks)
    let read_ops = 50_000;
    let hot_range = block_count / 5; // 20% of blocks
    let mut hot_hits = 0u64;
    let mut cold_faults = 0u64;

    let t0 = Instant::now();
    for i in 0..read_ops {
        let block_idx = if i % 5 < 4 {
            // 80% hot reads
            i % hot_range
        } else {
            // 20% cold reads (will fault)
            hot_range + (i % (block_count - hot_range))
        };

        let result = controller.simulate_read(block_idx);
        match result {
            FaultResult::AlreadyResident { .. } => hot_hits += 1,
            _ => cold_faults += 1,
        }

        if i % 500 == 0 {
            controller.proactive_evict();
        }
    }
    let read_time = t0.elapsed();
    let per_read = read_time / read_ops as u32;

    let stats = controller.stats();
    let hit_rate = (hot_hits as f64 / read_ops as f64) * 100.0;

    println!("\n  Populate phase: {} writes in {:?}", populate_ops, populate_time);
    println!("  Read phase:     {} reads in {:?} ({:?}/read)", read_ops, read_time, per_read);
    println!("  Cache hit rate: {:.1}% ({} hits, {} faults)", hit_rate, hot_hits, cold_faults);
    println!("  Evictions:      {}", stats.evictions_performed);
    println!("  Remote xfers:   {}", stats.remote_transfers);

    println!("\n  Redis ziet: {}MB RAM, alles werkt normaal", virtual_size / (1024 * 1024));
    println!("  Werkelijk:  {}MB fysiek + rest via RAID-0 paging", 32 * RAID_BLOCK_SIZE / (1024 * 1024));
    println!("  Verschil:   App merkt NIETS. Trust Kernel handelt alles af.");

    println!();
}

// ═══════════════════════════════════════════════════════════════
// Part 9: Scaling Test
// ═══════════════════════════════════════════════════════════════

fn bench_scaling() {
    println!("── Part 9: Scaling — Arena Size vs Performance ──\n");

    let arena_sizes = [
        ("16MB", 16 * 1024 * 1024usize),
        ("64MB", 64 * 1024 * 1024),
        ("256MB", 256 * 1024 * 1024),
        ("1GB", 1024 * 1024 * 1024),
    ];

    println!("  {:<8} {:<8} {:<12} {:<12} {:<12} {:<10}",
        "Arena", "Blocks", "Create", "Fault(V)", "Fault(L)", "Evict");

    for (label, size) in &arena_sizes {
        // Create
        let t0 = Instant::now();
        let config = RaidConfig::new(*size, "db:redis", "root_idd.aint");
        let mut controller = RamRaidController::new(config);
        let create_time = t0.elapsed();

        let block_count = controller.block_count();

        // Virgin fault
        let t0 = Instant::now();
        let iters = 1000.min(block_count);
        for i in 0..iters {
            let addr = i * RAID_BLOCK_SIZE;
            controller.handle_fault(addr);
        }
        let virgin_per = t0.elapsed() / iters as u32;

        // Local restore fault
        for i in 0..iters {
            controller.blocks[i].location = BlockLocation::LocalStore {
                tza_path: format!("/tmp/b{}.tza", i),
                fork_token_id: format!("f{}", i),
            };
            controller.blocks[i].content_hash = Some("hash".to_string());
            controller.resident_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        let t0 = Instant::now();
        for i in 0..iters {
            let addr = i * RAID_BLOCK_SIZE;
            controller.handle_fault(addr);
        }
        let local_per = t0.elapsed() / iters as u32;

        // Eviction
        for i in 0..iters {
            controller.simulate_write(i);
        }
        let t0 = Instant::now();
        let evict_iters = 100.min(iters);
        for _ in 0..evict_iters {
            controller.evict_coldest();
            // Re-dirty for next iteration
            let s = controller.stats();
            if s.resident_blocks < 2 {
                for j in 0..iters {
                    controller.simulate_write(j);
                }
            }
        }
        let evict_per = t0.elapsed() / evict_iters as u32;

        println!("  {:<8} {:<8} {:<12?} {:<12?} {:<12?} {:<10?}",
            label, block_count, create_time, virgin_per, local_per, evict_per);
    }

    println!("\n  Conclusie: page fault latency is O(1) — onafhankelijk van arena size.");
    println!("  Alleen create time schaalt lineair (block table allocatie).");

    println!();
}
