use std::time::Instant;
use tibet_trust_kernel::bifurcation::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");

    println!();
    println!("  ████████╗██╗██████╗ ███████╗████████╗");
    println!("  ╚══██╔══╝██║██╔══██╗██╔════╝╚══██╔══╝");
    println!("     ██║   ██║██████╔╝█████╗     ██║   ");
    println!("     ██║   ██║██╔══██╗██╔══╝     ██║   ");
    println!("     ██║   ██║██████╔╝███████╗   ██║   ");
    println!("     ╚═╝   ╚═╝╚═════╝ ╚══════╝   ╚═╝   ");
    println!();
    println!("  Airlock Bifurcatie — Encrypt-by-Default Benchmark");
    println!("  \"In 7 microseconden legt licht 2.1 km af. Wij encrypten een block.\"");
    println!();

    // Platform detectie
    println!("  ── Platform ──");
    println!("  Arch:     {}", std::env::consts::ARCH);
    println!("  OS:       {}", std::env::consts::OS);
    println!();

    // Hardware detectie
    println!("  ── Hardware ──");
    print!("  RDRAND:   ");
    if rdrand_available() { println!("YES (hardware nonces)"); }
    else { println!("no (OsRng fallback)"); }
    print!("  RDSEED:   ");
    if rdseed_available() { println!("YES (true entropy)"); }
    else { println!("no"); }
    print!("  AES HW:   ");
    #[cfg(target_arch = "x86_64")]
    {
        let ecx: u32;
        unsafe {
            std::arch::asm!(
                "push rbx", "mov eax, 1", "cpuid", "pop rbx",
                out("ecx") ecx, out("eax") _, out("edx") _,
                options(nostack),
            );
        }
        if (ecx >> 25) & 1 == 1 { println!("YES (AES-NI)"); }
        else { println!("no (software AES)"); }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // ARM Crypto Extensions zijn standaard op ARMv8+
        // De aes-gcm crate detecteert dit automatisch via cpufeatures
        println!("YES (ARM Crypto Extensions)");
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { println!("software (geen hardware detectie)"); }
    print!("  CAT L3:   ");
    match cat_l3_status() {
        CatL3Status::Active { ways_reserved, ways_total, .. } =>
            println!("ACTIVE ({}/{} ways reserved)", ways_reserved, ways_total),
        CatL3Status::Available { ways_total } =>
            println!("available ({} ways, not activated)", ways_total),
        CatL3Status::NotMounted =>
            println!("supported (mount resctrl to activate)"),
        _ => println!("not available"),
    }
    println!("  Threads:  {}", rayon::current_num_threads());
    println!();

    // ── Test 1: Single-thread seal ──
    println!("  ── Seal (encrypt-on-write) ──");
    let data_4k = vec![0x42u8; 4096];
    let iterations = 10_000;

    // Regular seal
    let mut engine = AirlockBifurcation::new();
    let t0 = Instant::now();
    for i in 0..iterations {
        let _ = engine.seal(&data_4k, i, ClearanceLevel::Confidential, "tibet-bench");
    }
    let regular_us = t0.elapsed().as_micros();
    let regular_per = regular_us / iterations as u128;
    let regular_mbs = (iterations as f64 * 4096.0) / (regular_us as f64 / 1_000_000.0) / (1024.0 * 1024.0);

    // Session seal
    let mut engine = AirlockBifurcation::new();
    let t0 = Instant::now();
    for i in 0..iterations {
        let _ = engine.seal_session(&data_4k, i, ClearanceLevel::Confidential, "tibet-bench");
    }
    let session_us = t0.elapsed().as_micros();
    let session_per = session_us / iterations as u128;
    let session_mbs = (iterations as f64 * 4096.0) / (session_us as f64 / 1_000_000.0) / (1024.0 * 1024.0);

    println!("  Regular:  {:>6} us/seal   {:>7.1} MB/s   (full X25519 DH per block)", regular_per, regular_mbs);
    println!("  Session:  {:>6} us/seal   {:>7.1} MB/s   (cached DH, HKDF+AES only)", session_per, session_mbs);
    println!("  Speedup:  {:.1}x", regular_per as f64 / session_per.max(1) as f64);
    println!();

    // ── Test 2: Open (decrypt) ──
    println!("  ── Open (decrypt-on-read) ──");
    let mut engine = AirlockBifurcation::new();
    let claim = JisClaim {
        identity: "tibet-bench.aint".to_string(),
        ed25519_pub: "a".repeat(64),
        clearance: ClearanceLevel::TopSecret,
        role: "operator".to_string(),
        dept: "security".to_string(),
        claimed_at: "2026-04-15T00:00:00Z".to_string(),
        signature: "bench_sig".to_string(),
    };

    // Seal blocks first
    let mut blocks = Vec::new();
    let open_data = vec![0xAB; 4096];
    for i in 0..1000 {
        if let BifurcationResult::Sealed { block, .. } =
            engine.seal_session(&open_data, i, ClearanceLevel::Confidential, "bench")
        {
            blocks.push(block);
        }
    }

    // Cold open (no cache)
    engine.key_cache.flush();
    let t0 = Instant::now();
    for block in &blocks {
        let _ = engine.open(block, &claim);
    }
    let cold_us = t0.elapsed().as_micros();
    let cold_per = cold_us / blocks.len() as u128;

    // Cached open
    let t0 = Instant::now();
    for block in &blocks {
        let _ = engine.open(block, &claim);
    }
    let cached_us = t0.elapsed().as_micros();
    let cached_per = cached_us / blocks.len() as u128;

    println!("  Cold:     {:>6} us/open   (full DH + HKDF + AES)", cold_per);
    println!("  Cached:   {:>6} us/open   (cache hit, AES only)", cached_per);
    println!("  Speedup:  {:.1}x", cold_per as f64 / cached_per.max(1) as f64);
    println!();

    // ── Test 3: Access control ──
    println!("  ── Access Control ──");
    let mut engine = AirlockBifurcation::new();
    let secret_block = if let BifurcationResult::Sealed { block, .. } =
        engine.seal(&vec![0xCC; 4096], 0, ClearanceLevel::Secret, "system")
    { block } else { panic!() };

    let low_claim = JisClaim {
        identity: "low.aint".to_string(),
        ed25519_pub: "a".repeat(64),
        clearance: ClearanceLevel::Restricted,
        role: "viewer".to_string(),
        dept: "public".to_string(),
        claimed_at: "2026-04-15T00:00:00Z".to_string(),
        signature: "sig".to_string(),
    };

    match engine.open(&secret_block, &low_claim) {
        BifurcationResult::AccessDenied { .. } => println!("  Restricted -> Secret:  DENIED (correct)"),
        _ => println!("  Restricted -> Secret:  ERROR!"),
    }
    match engine.open(&secret_block, &claim) {
        BifurcationResult::Opened { .. } => println!("  TopSecret  -> Secret:  OPENED (correct)"),
        _ => println!("  TopSecret  -> Secret:  ERROR!"),
    }
    println!();

    // ── Test 4: Throughput scaling ──
    println!("  ── Throughput Scaling (session seal) ──");
    let mut engine = AirlockBifurcation::new();
    for &(label, size) in &[
        ("1KB", 1024), ("4KB", 4096), ("16KB", 16384),
        ("64KB", 65536), ("256KB", 262144), ("1MB", 1048576),
    ] {
        let data = vec![0x42u8; size];
        let iters: usize = if size >= 262144 { 100 } else { 1000 };
        let t0 = Instant::now();
        for i in 0..iters {
            let _ = engine.seal_session(&data, i, ClearanceLevel::Unclassified, "bench");
        }
        let us = t0.elapsed().as_micros();
        let per = us / iters as u128;
        let mbs = (iters as f64 * size as f64) / (us as f64 / 1_000_000.0) / (1024.0 * 1024.0);
        println!("  {:>5}:    {:>6} us/seal   {:>8.1} MB/s", label, per, mbs);
    }
    println!();

    // ── Test 5: Multi-core parallel (session + batch) ──
    println!("  ── Von Braun Mode (multi-core + session keys) ──");

    for &(label, size, count) in &[
        ("4KB", 4096usize, 10_000usize),
        ("16KB", 16384, 4_000),
        ("64KB", 65536, 1_000),
    ] {
        let plaintexts: Vec<Vec<u8>> = (0..count).map(|_| vec![0x42u8; size]).collect();

        // Single-thread session seal
        let mut eng = AirlockBifurcation::new();
        let t0 = Instant::now();
        for (i, pt) in plaintexts.iter().enumerate() {
            let _ = eng.seal_session(pt, i, ClearanceLevel::Confidential, "b");
        }
        let single_mbs = (count as f64 * size as f64) / (t0.elapsed().as_micros() as f64 / 1_000_000.0) / (1024.0 * 1024.0);

        // Multi-core batch seal (session + parallel)
        let mut eng = AirlockBifurcation::new();
        let result = eng.seal_batch(&plaintexts, ClearanceLevel::Confidential, "b");
        println!("  {:>5}:    {:>7.1} MB/s session -> {:>7.1} MB/s batch  ({:.1}x, {} threads)",
            label, single_mbs, result.throughput_mbs,
            result.throughput_mbs / single_mbs, result.threads_used);
    }
    println!();

    // ── Test 6: Integrity ──
    println!("  ── Integrity Roundtrip ──");
    let mut engine = AirlockBifurcation::new();
    let tests: Vec<(&str, Vec<u8>)> = vec![
        ("text", b"Hello TIBET! Encrypt-by-default.".to_vec()),
        ("zeros", vec![0u8; 65536]),
        ("pattern", (0..255).collect()),
        ("1MB", vec![0xFF; 1048576]),
    ];
    for (name, data) in &tests {
        let block = if let BifurcationResult::Sealed { block, .. } =
            engine.seal_session(data, 0, ClearanceLevel::Unclassified, "test")
        { block } else { print!("  {}: SEAL FAIL  ", name); continue; };

        match engine.open(&block, &claim) {
            BifurcationResult::Opened { plaintext, .. } if plaintext == *data =>
                println!("  {:>7}: {:>8} bytes  OK", name, data.len()),
            _ => println!("  {:>7}: FAIL!", name),
        }
    }
    println!();

    // ── Entropy benchmark ──
    println!("  ── Entropy Sources ──");
    let n = 100_000u128;

    if rdseed_available() {
        let t0 = Instant::now();
        for _ in 0..n { let _ = rdseed64(); }
        let rdseed_ns = (t0.elapsed().as_micros() * 1000) / n;
        let fast = rdseed_ns < 5_000;
        println!("  RDSEED:   {} ns/call  (true entropy, {})",
            rdseed_ns, if fast { "FAST — used in cascade" } else { "SLOW — skipped in cascade" });
    }

    // Nonce bench — altijd draaien, rdrand_nonce() kiest automatisch beste bron
    {
        let t0 = Instant::now();
        for _ in 0..n { let _ = rdrand_nonce(); }
        let nonce_ns = (t0.elapsed().as_micros() * 1000) / n;
        let source = if rdseed_available() { "RDSEED" }
            else if rdrand_available() { "RDRAND" }
            else { "OsRng" };
        println!("  Nonce:    {} ns/nonce (via {})", nonce_ns, source);
    }

    // OsRng baseline — altijd beschikbaar
    {
        let t0 = Instant::now();
        for _ in 0..n {
            let mut nonce = [0u8; 12];
            rand::Rng::fill(&mut rand::rngs::OsRng, &mut nonce);
        }
        let osrng_ns = (t0.elapsed().as_micros() * 1000) / n;
        println!("  OsRng:    {} ns/nonce (kernel entropy)", osrng_ns);
    }
    println!();

    // Summary
    println!("  ═══════════════════════════════════════════════════════");
    println!("  TIBET Airlock Bifurcatie — Encrypt-by-Default");
    println!();
    println!("  Platform:  {} / {}", std::env::consts::ARCH, std::env::consts::OS);
    println!("  Crypto:    AES-256-GCM + X25519 + HKDF-SHA256");
    let nonce_src = if rdseed_available() { "RDSEED (true entropy)" }
        else if rdrand_available() { "RDRAND (hardware PRNG)" }
        else { "OsRng (kernel entropy)" };
    println!("  Nonces:    {}", nonce_src);
    println!("  Best seal: {} us (session, 4KB)", session_per);
    println!("  Best open: {} us (cached, 4KB)", cached_per);
    println!();
    println!("  Geen JIS claim = dood materiaal.");
    println!("  Identity IS the key.");
    println!();
    println!("  #HashesFromHolland");
    println!("  ═══════════════════════════════════════════════════════");
    println!();

    if verbose {
        println!("  Run with: RUSTFLAGS=\"-C target-cpu=native\" cargo run --release --bin tibet-bench");
        println!("  Source:   https://github.com/jaspertvdm/tibet-trust-kernel");
        println!();
    }
}
