use std::time::Instant;

use tibet_trust_kernel::ram_raid::{RamRaidController, RaidConfig};
use tibet_trust_kernel::upip_pager::{UpipPager, PageOutResult, PageInResult};
use tibet_trust_kernel::bifurcation::{AirlockBifurcation, BifurcationResult, ClearanceLevel, JisClaim};

/// CLUSTER PAGING DEMO — RAM RAID-0 + UPIP over simulated network
///
/// Demonstrates distributed memory across machines:
///   Machine A (P520):  Even blocks -> local RAM A
///   Machine B (DL360): Odd blocks  -> "remote" RAM B (simulated)
///
/// Pipeline:
///   1. RAM RAID-0: stripe data across A/B
///   2. LRU eviction: compress + seal + store cold pages
///   3. UPIP Pager: fork tokens for cross-machine continuation
///   4. Throughput: paging in/out with crypto overhead
///
/// In production: A<->B over TCP/QUIC (10Gbps link)
/// In this demo: simulated transport in-process

fn main() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  CLUSTER PAGING — RAM RAID-0 + UPIP Fork Tokens          ║");
    println!("  ║                                                          ║");
    println!("  ║  Even blocks -> RAM A (local)                            ║");
    println!("  ║  Odd blocks  -> RAM B (remote/simulated)                 ║");
    println!("  ║  LRU eviction -> compress + encrypt + store              ║");
    println!("  ║  UPIP -> Fork Token -> resume on any machine             ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 1: RAM RAID-0 — Striped Write + Read
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 1: RAM RAID-0 Striped I/O ──");

    let arena_size = 100 * 4096; // 100 blocks of 4KB
    let raid_config = RaidConfig::new(arena_size, "cluster:paging", "p520.aint");
    let mut raid = RamRaidController::new(raid_config);

    // Write workload: 100 blocks
    let num_blocks = raid.block_count();
    let t0 = Instant::now();
    for i in 0..num_blocks {
        raid.simulate_write(i);
    }
    let write_ms = t0.elapsed().as_millis();

    // Read all blocks back
    let t0 = Instant::now();
    let mut read_ok = 0u32;
    for i in 0..num_blocks {
        let result = raid.simulate_read(i);
        if matches!(result, tibet_trust_kernel::ram_raid::FaultResult::AlreadyResident { .. }) {
            read_ok += 1;
        }
    }
    let read_ms = t0.elapsed().as_millis();

    let stats = raid.stats();
    println!("  Write:      {} blocks in {}ms", num_blocks, write_ms);
    println!("  Read:       {}/{} resident in {}ms", read_ok, num_blocks, read_ms);
    println!("  RAM A:      {} blocks (even)", stats.ram_a_blocks);
    println!("  RAM B:      {} blocks (odd)", stats.ram_b_blocks);
    println!("  Evictions:  {}", stats.evictions_performed);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 2: LRU Eviction Under Pressure
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 2: LRU Eviction Under Pressure ──");

    let arena_size = 80 * 4096; // 80 blocks
    let raid_config = RaidConfig::new(arena_size, "eviction:test", "p520.aint")
        .with_max_resident(32); // Only 32 can be resident
    let mut raid = RamRaidController::new(raid_config);

    // Fill to trigger eviction
    let t0 = Instant::now();
    for i in 0..80 {
        raid.simulate_write(i);
        // After exceeding max_resident, try proactive evict
        if raid.resident_blocks() > 30 {
            let _evictions = raid.proactive_evict();
        }
    }
    let fill_ms = t0.elapsed().as_millis();

    let stats = raid.stats();
    println!("  Filled:     80 blocks into 32-slot resident set in {}ms", fill_ms);
    println!("  Resident:   {}/{} blocks", stats.resident_blocks, stats.max_resident);
    println!("  Evictions:  {} (cold pages compressed+sealed)", stats.evictions_performed);
    println!("  Local cold: {} blocks", stats.local_evicted);
    println!("  Remote:     {} blocks", stats.remote_evicted);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 3: Remote RAM B (simulated DL360)
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 3: Remote RAM B (P520 <-> DL360 simulated) ──");

    let arena_size = 64 * 4096;
    let raid_config = RaidConfig::new(arena_size, "remote:test", "p520.aint")
        .with_remote_ram_b("dl360.aint", "tcp://192.168.4.69:4430");
    let mut raid = RamRaidController::new(raid_config);

    let t0 = Instant::now();
    for i in 0..64 {
        raid.simulate_write(i);
    }

    // Read back — odd blocks are "remote"
    let mut local_reads = 0u32;
    let mut remote_reads = 0u32;
    for i in 0..64 {
        let result = raid.simulate_read(i);
        match result {
            tibet_trust_kernel::ram_raid::FaultResult::AlreadyResident { .. } => local_reads += 1,
            tibet_trust_kernel::ram_raid::FaultResult::RestoredRemote { .. } => remote_reads += 1,
            tibet_trust_kernel::ram_raid::FaultResult::RestoredLocal { .. } => local_reads += 1,
            _ => {}
        }
    }
    let remote_ms = t0.elapsed().as_millis();

    let stats = raid.stats();
    println!("  Time:       {}ms", remote_ms);
    println!("  Local:      {} reads (even blocks)", local_reads);
    println!("  Remote:     {} reads (odd blocks -> DL360)", remote_reads);
    println!("  Transfers:  {} remote", stats.remote_transfers);
    println!("  Has remote: {}", stats.has_remote_ram_b);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 4: UPIP Pager — Page Out / Page In
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 4: UPIP Pager (Application-Level Paging) ──");

    let mut pager = UpipPager::new(4096); // 4KB chunk size

    // Page out 20 chunks
    let t0 = Instant::now();
    let mut paged_out = 0u32;
    let mut token_ids = Vec::new();
    for i in 0..20 {
        let data = vec![(i * 3 + 7) as u8; 4096];
        match pager.page_out(&data, i * 4096, "code:execute", "p520.aint", 0) {
            PageOutResult::Success { ref token, bytes_freed, .. } => {
                paged_out += 1;
                token_ids.push(token.id.clone());
                if i == 0 {
                    println!("  PageOut[0]: {} bytes freed, token={}", bytes_freed, &token.id);
                }
            }
            ref other => {
                if i == 0 { println!("  PageOut[0]: {:?}", format!("{:?}", other).chars().take(60).collect::<String>()); }
            }
        }
    }
    let pageout_ms = t0.elapsed().as_millis();
    println!("  PageOut:    {}/20 chunks in {}ms", paged_out, pageout_ms);

    // Page in 10 chunks
    let t0 = Instant::now();
    let mut paged_in = 0u32;
    for (i, token_id) in token_ids.iter().take(10).enumerate() {
        match pager.page_in(token_id) {
            PageInResult::Success { bytes_restored, .. } => {
                paged_in += 1;
                if i == 0 {
                    println!("  PageIn[0]:  {} bytes restored", bytes_restored);
                }
            }
            ref other => {
                if i == 0 { println!("  PageIn[0]:  {:?}", format!("{:?}", other).chars().take(60).collect::<String>()); }
            }
        }
    }
    let pagein_ms = t0.elapsed().as_millis();
    println!("  PageIn:     {}/10 chunks in {}ms", paged_in, pagein_ms);

    let stats = pager.stats();
    println!("  Stats:      out={} in={} active={} violations={}",
        stats.pages_out, stats.pages_in, stats.active_tokens, stats.integrity_violations);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 5: Fork Tokens — Cross-Machine Continuation
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 5: Fork Tokens (Cross-Machine Continuation) ──");

    let mut pager = UpipPager::new(4096);

    // Page out a few chunks
    let mut token_ids = Vec::new();
    for i in 0..5 {
        let data = vec![0xAB; 4096];
        if let PageOutResult::Success { ref token, .. } =
            pager.page_out(&data, i * 4096, "ai:inference", "p520.aint", 42)
        {
            token_ids.push(token.id.clone());
        }
    }

    // Prepare continuation to remote kernel (DL360)
    let t0 = Instant::now();
    let mut continued = 0u32;
    for token_id in &token_ids {
        if let Some(token) = pager.prepare_continuation(
            token_id, "dl360.aint", "tcp://192.168.4.69:4430"
        ) {
            continued += 1;
            if continued == 1 {
                println!("  Continuation: {} -> {:?}", token.id, token.storage);
            }
        }
    }
    let cont_ms = t0.elapsed().as_millis();

    println!("  Continued:  {}/{} tokens to DL360 in {}ms", continued, token_ids.len(), cont_ms);
    println!("  Remote continuations: {}", pager.remote_continuations);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 6: Bulk Page Out + Assemble
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 6: Bulk Page Out + Assemble ──");
    {
        let mut pager = UpipPager::new(4096);
        let big_data = vec![0x42u8; 32768]; // 32KB = 8 chunks of 4KB

        let t0 = Instant::now();
        let results = pager.page_out_bulk(&big_data, 0, "code:execute", "p520.aint", 100);
        let bulk_ms = t0.elapsed().as_millis();

        let success_count = results.iter()
            .filter(|r| matches!(r, PageOutResult::Success { .. }))
            .count();
        println!("  Bulk out:   {} chunks in {}ms", success_count, bulk_ms);

        // Assemble back
        let t0 = Instant::now();
        let assemble = pager.assemble("code:execute", 100);
        let assemble_ms = t0.elapsed().as_millis();
        println!("  Assemble:   {:?} in {}ms", format!("{:?}", assemble).chars().take(70).collect::<String>(), assemble_ms);
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 7: Encrypted Paging — Bifurcation + RAID
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 7: Encrypted Paging (Bifurcation + RAID) ──");
    {
        let mut engine = AirlockBifurcation::new();
        let claim = JisClaim {
            identity: "cluster.aint".to_string(),
            ed25519_pub: "a".repeat(64),
            clearance: ClearanceLevel::TopSecret,
            role: "operator".to_string(),
            dept: "infrastructure".to_string(),
            claimed_at: "2026-04-15T00:00:00Z".to_string(),
            signature: "sig".to_string(),
        };

        let page_count = 1000;
        let page_size = 4096;

        // Seal 1000 pages (simulating eviction to encrypted cold store)
        let t0 = Instant::now();
        let mut sealed_blocks = Vec::with_capacity(page_count);
        for i in 0..page_count {
            let data = vec![(i & 0xFF) as u8; page_size];
            if let BifurcationResult::Sealed { block, .. } =
                engine.seal_session(&data, i, ClearanceLevel::Secret, "raid-evict")
            {
                sealed_blocks.push(block);
            }
        }
        let seal_ms = t0.elapsed().as_millis();
        let seal_per_us = (seal_ms as f64 * 1000.0) / page_count as f64;
        let seal_mbs = (page_count as f64 * page_size as f64) / (seal_ms.max(1) as f64 / 1000.0) / (1024.0 * 1024.0);

        // Open all pages (simulating page-in from cold store)
        let t0 = Instant::now();
        let mut open_ok = 0u32;
        for block in &sealed_blocks {
            if let BifurcationResult::Opened { .. } = engine.open(block, &claim) {
                open_ok += 1;
            }
        }
        let open_ms = t0.elapsed().as_millis();
        let open_per_us = (open_ms as f64 * 1000.0) / page_count as f64;
        let open_mbs = (page_count as f64 * page_size as f64) / (open_ms.max(1) as f64 / 1000.0) / (1024.0 * 1024.0);

        println!("  Seal:       {} pages in {}ms ({:.1}us/pg, {:.0} MB/s)", page_count, seal_ms, seal_per_us, seal_mbs);
        println!("  Open:       {}/{} in {}ms ({:.1}us/pg, {:.0} MB/s)", open_ok, page_count, open_ms, open_per_us, open_mbs);
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 8: Network Transport Simulation (P520 <-> DL360)
    // ═══════════════════════════════════════════════════════════════
    println!("  ── Test 8: Network Transport Simulation ──");
    {
        let mut engine = AirlockBifurcation::new();
        let claim = JisClaim {
            identity: "dl360.aint".to_string(),
            ed25519_pub: "a".repeat(64),
            clearance: ClearanceLevel::TopSecret,
            role: "operator".to_string(),
            dept: "infrastructure".to_string(),
            claimed_at: "2026-04-15T00:00:00Z".to_string(),
            signature: "sig".to_string(),
        };

        let page_size = 4096;
        println!("  Seal on P520 -> wire transfer -> open on DL360:");

        for &count in &[256, 1024, 4096] {
            let pages: Vec<Vec<u8>> = (0..count).map(|i| vec![(i & 0xFF) as u8; page_size]).collect();

            let t0 = Instant::now();
            // Seal on P520
            let sealed: Vec<_> = pages.iter().enumerate().filter_map(|(i, p)| {
                if let BifurcationResult::Sealed { block, .. } =
                    engine.seal_session(p, i, ClearanceLevel::Secret, "p520")
                { Some(block) } else { None }
            }).collect();

            // Wire bytes = ciphertext (includes GCM tag) + nonce + ephemeral pub
            let wire_bytes: usize = sealed.iter()
                .map(|b| b.ciphertext.len() + b.nonce.len() + b.ephemeral_pub.len())
                .sum();

            // Open on DL360
            let mut ok = 0u32;
            for block in &sealed {
                if let BifurcationResult::Opened { .. } = engine.open(block, &claim) {
                    ok += 1;
                }
            }
            let total_ms = t0.elapsed().as_millis();
            let throughput = (count as f64 * page_size as f64) / (total_ms.max(1) as f64 / 1000.0) / (1024.0 * 1024.0);

            println!("  {:>5} pages: {}ms, {} KB wire, {:.0} MB/s, {}/{} verified",
                count, total_ms, wire_bytes / 1024, throughput, ok, count);
        }
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════
    println!("  ══════════════════════════════════════════════════════════════");
    println!("  CLUSTER PAGING — RESULTS");
    println!("  ──────────────────────────────────────────────────────────────");
    println!("  RAM RAID-0:    Even/odd striping, LRU eviction, cold store");
    println!("  UPIP Pager:    Page out/in with compression + signing");
    println!("  Fork Tokens:   Cross-machine session continuation");
    println!("  Bifurcation:   AES-256-GCM encrypted cold storage");
    println!("  Transport:     Sealed blocks over wire (10Gbps simulated)");
    println!();
    println!("  Production: P520 (192.168.4.85) <-> DL360 (192.168.4.69)");
    println!("  Protocol:   TCP/QUIC with TIBET provenance per transfer");
    println!("  ══════════════════════════════════════════════════════════════");
    println!();
}
