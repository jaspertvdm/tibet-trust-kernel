// ═══════════════════════════════════════════════════════════════
// Cluster Transport Demo — P520 ↔ DL360 block transfer
//
// Usage:
//   TCP-per-block:
//     Server:   cluster-transport-demo server 0.0.0.0:4430
//     Client:   cluster-transport-demo client 192.168.4.69:4430
//
//   MUX persistent (faster):
//     Server:   cluster-transport-demo mux-server 0.0.0.0:4431
//     Client:   cluster-transport-demo mux-client 192.168.4.69:4431
//
//   Loopback:
//     cluster-transport-demo test          # TCP-per-block
//     cluster-transport-demo mux-test      # MUX persistent
//     cluster-transport-demo bench         # A/B comparison
// ═══════════════════════════════════════════════════════════════

use tibet_trust_kernel::cluster_transport::*;
use tibet_trust_kernel::cluster_mux::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("test");

    match mode {
        "server" => {
            let addr = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:4430");
            run_server(addr).await;
        }
        "client" => {
            let endpoint = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:4430");
            run_client(endpoint).await;
        }
        "mux-server" => {
            let addr = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:4431");
            run_mux_server(addr).await;
        }
        "mux-client" => {
            let endpoint = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:4431");
            run_mux_client(endpoint).await;
        }
        "mux-test" => {
            run_mux_loopback().await;
        }
        "bench" => {
            run_ab_bench().await;
        }
        "test" | _ => {
            run_loopback_test().await;
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// TCP-per-block mode (original)
// ═══════════════════════════════════════════════════════════════

async fn run_server(addr: &str) {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  Cluster Transport Server — TCP-per-block        ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let server = ClusterTransportServer::new(addr, "dl360.aint");
    println!("Waiting for block requests on {}...", addr);
    println!("Press Ctrl+C to stop.");
    println!();

    server.serve().await.expect("Server failed");
}

async fn run_client(endpoint: &str) {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  Cluster Transport Client — TCP-per-block        ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let client = ClusterTransportClient::new("p520.aint");

    // 1. Ping
    println!("═══ Test 1: Ping ═══");
    match client.ping(endpoint).await {
        Ok(rtt) => println!("  PASS: RTT = {}µs", rtt),
        Err(e) => {
            println!("  FAIL: {}", e);
            return;
        }
    }

    // 2. Store a block
    println!("\n═══ Test 2: Store Block ═══");
    let test_data = vec![0xAB; 65536]; // 64KB block
    let hash = sha256_hex(&test_data);
    let seal = format!("{:0<128}", "ed25519_demo_seal");

    match client.store_block(endpoint, 0, &test_data, &hash, &seal, 131072, 1).await {
        Ok(resp) => println!("  PASS: Stored block 0 — {}B, server={}µs",
                             resp.payload_size, resp.server_latency_us),
        Err(e) => println!("  FAIL: {}", e),
    }

    // 3. Fetch it back
    println!("\n═══ Test 3: Fetch Block ═══");
    match client.fetch_block(endpoint, 0, "fork_0", 1, Some(&hash)).await {
        Ok((data, resp)) => {
            assert_eq!(data, test_data);
            println!("  PASS: Fetched block 0 — {}B, hash verified, server={}µs",
                     data.len(), resp.server_latency_us);
        }
        Err(e) => println!("  FAIL: {}", e),
    }

    // 4. Throughput test
    println!("\n═══ Test 4: Throughput (100 × 64KB blocks) ═══");
    let block_size = 65536;
    let num_blocks: usize = 100;

    let store_t0 = std::time::Instant::now();
    for i in 0..num_blocks {
        let data = vec![(i & 0xFF) as u8; block_size];
        let h = sha256_hex(&data);
        let s = format!("{:0<128}", format!("seal_{}", i));
        client.store_block(endpoint, i, &data, &h, &s, block_size * 2, i as u64).await
            .expect("Store failed");
    }
    let store_elapsed = store_t0.elapsed();
    let store_mbps = (num_blocks * block_size) as f64 / store_elapsed.as_secs_f64() / 1_000_000.0;
    println!("  Store: {} blocks in {:?} ({:.1} MB/s)", num_blocks, store_elapsed, store_mbps);

    let fetch_t0 = std::time::Instant::now();
    for i in 0..num_blocks {
        let (data, _) = client.fetch_block(endpoint, i, &format!("fork_{}", i), i as u64, None).await
            .expect("Fetch failed");
        assert_eq!(data.len(), block_size);
    }
    let fetch_elapsed = fetch_t0.elapsed();
    let fetch_mbps = (num_blocks * block_size) as f64 / fetch_elapsed.as_secs_f64() / 1_000_000.0;
    println!("  Fetch: {} blocks in {:?} ({:.1} MB/s)", num_blocks, fetch_elapsed, fetch_mbps);

    println!("\n═══ Done ═══");
}

// ═══════════════════════════════════════════════════════════════
// MUX persistent mode (faster)
// ═══════════════════════════════════════════════════════════════

async fn run_mux_server(addr: &str) {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  Cluster MUX Server — Persistent Connection      ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let store = Arc::new(BlockStore::new());
    let server = ClusterMuxServer::new(addr, "dl360.aint", store);
    println!("MUX server on {} — persistent connections, pipelined fetches", addr);
    println!("Press Ctrl+C to stop.");
    println!();

    server.serve().await.expect("MUX server failed");
}

async fn run_mux_client(endpoint: &str) {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  Cluster MUX Client — Persistent Connection      ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let client = ClusterMuxClient::new(endpoint, "p520.aint");

    // 1. Ping
    println!("═══ Test 1: Ping (persistent) ═══");
    let rtt = client.ping().await.expect("Ping failed");
    println!("  PASS: RTT = {}µs", rtt);

    // Warm ping (connection already established)
    let rtt2 = client.ping().await.unwrap();
    println!("  PASS: Warm RTT = {}µs (connection reused)", rtt2);

    // 2. Store + fetch roundtrip
    println!("\n═══ Test 2: Store + Fetch Roundtrip ═══");
    let test_data = vec![0xDE; 131072]; // 128KB
    let hash = sha256_hex(&test_data);
    let seal = format!("{:0<128}", "mux_demo_seal");

    let store_us = client.store_block(0, &test_data, &hash, &seal, 262144, 1).await
        .expect("Store failed");
    println!("  Stored 128KB in {}µs", store_us);

    let (fetched, fetch_us) = client.fetch_block(0, Some(&hash), 1).await
        .expect("Fetch failed");
    assert_eq!(fetched, test_data);
    println!("  Fetched 128KB in {}µs, hash verified ✓", fetch_us);

    // 3. Throughput test — sequential
    println!("\n═══ Test 3: Throughput — Sequential (100 × 64KB) ═══");
    let block_size = 65536;
    let num_blocks: usize = 100;

    let t0 = std::time::Instant::now();
    for i in 0..num_blocks {
        let data = vec![(i & 0xFF) as u8; block_size];
        let h = sha256_hex(&data);
        let s = format!("{:0<128}", format!("seal_{}", i));
        client.store_block(i + 1, &data, &h, &s, block_size, i as u64).await.unwrap();
    }
    let store_ms = t0.elapsed().as_millis();
    let store_mbps = (num_blocks * block_size) as f64 / t0.elapsed().as_secs_f64() / 1_000_000.0;

    let t1 = std::time::Instant::now();
    for i in 0..num_blocks {
        let (data, _us) = client.fetch_block(i + 1, None, i as u64).await.unwrap();
        assert_eq!(data.len(), block_size);
    }
    let fetch_ms = t1.elapsed().as_millis();
    let fetch_mbps = (num_blocks * block_size) as f64 / t1.elapsed().as_secs_f64() / 1_000_000.0;

    println!("  Store: {}ms ({:.1} MB/s)", store_ms, store_mbps);
    println!("  Fetch: {}ms ({:.1} MB/s)", fetch_ms, fetch_mbps);

    // 4. Throughput test — batch pipeline
    println!("\n═══ Test 4: Throughput — Batch Pipeline (100 × 64KB) ═══");
    let requests: Vec<(usize, u64)> = (0..num_blocks).map(|i| (i + 1, i as u64)).collect();
    let t2 = std::time::Instant::now();
    let results = client.fetch_batch(&requests).await.unwrap();
    let batch_ms = t2.elapsed().as_millis();
    let batch_mbps = (num_blocks * block_size) as f64 / t2.elapsed().as_secs_f64() / 1_000_000.0;

    assert_eq!(results.len(), num_blocks);
    println!("  Batch Fetch: {}ms ({:.1} MB/s)", batch_ms, batch_mbps);
    println!("  Speedup vs sequential: {:.1}x", fetch_ms as f64 / batch_ms.max(1) as f64);

    // Stats
    println!("\n═══ Client Stats ═══");
    println!("  Total requests: {}", client.requests_sent.load(Ordering::Relaxed));
    println!("  Total bytes:    {:.1} MB", client.bytes_transferred.load(Ordering::Relaxed) as f64 / 1_000_000.0);

    client.disconnect().await;
    println!("\n═══ Done ═══");
}

async fn run_mux_loopback() {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  Cluster MUX — Loopback Test                     ║");
    println!("║  Persistent multiplexed TCP on localhost          ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let store = Arc::new(BlockStore::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    // Spawn MUX server
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

    let client = ClusterMuxClient::new(&addr, "p520.aint");
    let mut passed = 0;
    let total = 5;

    // Test 1: Ping
    println!("═══ Test 1: Ping ═══");
    let rtt = client.ping().await.unwrap();
    println!("  RTT: {}µs ✓", rtt);
    let rtt2 = client.ping().await.unwrap();
    println!("  Warm: {}µs (reused connection) ✓", rtt2);
    passed += 1;

    // Test 2: Store + fetch
    println!("\n═══ Test 2: Store + Fetch (128KB) ═══");
    let big = vec![0xDE; 131072];
    let hash = sha256_hex(&big);
    let seal = format!("{:0<128}", "loopback_seal");

    let store_us = client.store_block(0, &big, &hash, &seal, 262144, 1).await.unwrap();
    println!("  Store: {}µs ✓", store_us);

    let (fetched, fetch_us) = client.fetch_block(0, Some(&hash), 1).await.unwrap();
    assert_eq!(fetched, big);
    println!("  Fetch: {}µs, hash verified ✓", fetch_us);
    passed += 1;

    // Test 3: Sequential — 50 × 64KB
    println!("\n═══ Test 3: Sequential Throughput (50 × 64KB) ═══");
    let block_size = 65536;
    let num = 50usize;

    for i in 0..num {
        let data = vec![(i & 0xFF) as u8; block_size];
        let h = sha256_hex(&data);
        client.store_block(i + 1, &data, &h, "s", block_size, i as u64).await.unwrap();
    }

    let t0 = std::time::Instant::now();
    for i in 0..num {
        let (data, _) = client.fetch_block(i + 1, None, i as u64).await.unwrap();
        assert_eq!(data.len(), block_size);
    }
    let seq_ms = t0.elapsed().as_millis();
    let seq_mbps = (num * block_size) as f64 / t0.elapsed().as_secs_f64() / 1_000_000.0;
    println!("  Sequential: {}ms ({:.1} MB/s) ✓", seq_ms, seq_mbps);
    passed += 1;

    // Test 4: Batch pipeline — same 50 blocks
    println!("\n═══ Test 4: Batch Pipeline (50 × 64KB) ═══");
    let requests: Vec<(usize, u64)> = (0..num).map(|i| (i + 1, i as u64)).collect();
    let t1 = std::time::Instant::now();
    let results = client.fetch_batch(&requests).await.unwrap();
    let batch_ms = t1.elapsed().as_millis();
    let batch_mbps = (num * block_size) as f64 / t1.elapsed().as_secs_f64() / 1_000_000.0;

    assert_eq!(results.len(), num);
    println!("  Pipeline:   {}ms ({:.1} MB/s) ✓", batch_ms, batch_mbps);
    println!("  Speedup:    {:.1}x", seq_ms as f64 / batch_ms.max(1) as f64);
    passed += 1;

    // Test 5: Error handling
    println!("\n═══ Test 5: Error Handling ═══");
    let err = client.fetch_block(9999, None, 0).await;
    assert!(matches!(err, Err(MuxError::RemoteStatus { status: 404, .. })));
    println!("  404 on missing block ✓");
    passed += 1;

    // Stats
    let (stored, served, bytes) = store.stats();
    println!("\n═══ Store Stats ═══");
    println!("  Blocks stored: {}", stored);
    println!("  Blocks served: {}", served);
    println!("  Total bytes:   {:.1} KB", bytes as f64 / 1024.0);

    println!("\n═══ Client Stats ═══");
    println!("  Requests:      {}", client.requests_sent.load(Ordering::Relaxed));
    println!("  Transferred:   {:.1} MB", client.bytes_transferred.load(Ordering::Relaxed) as f64 / 1_000_000.0);

    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║  MUX: {}/{} tests passed!                         ║", passed, total);
    if passed == total {
        println!("║  Ready for P520 ↔ DL360 real network test        ║");
    }
    println!("╚═══════════════════════════════════════════════════╝");

    client.disconnect().await;
}

// ═══════════════════════════════════════════════════════════════
// A/B Benchmark — TCP-per-block vs MUX persistent
// ═══════════════════════════════════════════════════════════════

async fn run_ab_bench() {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  A/B Benchmark: TCP-per-block vs MUX persistent  ║");
    println!("║  50 × 64KB blocks, loopback                      ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    let block_size = 65536usize;
    let num_blocks = 50usize;
    let total_bytes = block_size * num_blocks;

    // ── Prepare test data ──
    let blocks: Vec<Vec<u8>> = (0..num_blocks)
        .map(|i| vec![(i & 0xFF) as u8; block_size])
        .collect();
    let hashes: Vec<String> = blocks.iter().map(|b| sha256_hex(b)).collect();

    // ═══ A: TCP-per-block ═══
    println!("═══ A: TCP-per-block ═══");
    {
        let store = Arc::new(BlockStore::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let store_clone = store.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, _)) => {
                        let s = store_clone.clone();
                        tokio::spawn(async move {
                            let _ = handle_connection(socket, s, "dl360.aint").await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let client = ClusterTransportClient::new("p520.aint");

        // Store
        let t0 = std::time::Instant::now();
        for i in 0..num_blocks {
            let seal = format!("{:0<128}", format!("seal_{}", i));
            client.store_block(&addr, i, &blocks[i], &hashes[i], &seal, block_size, i as u64)
                .await.unwrap();
        }
        let store_elapsed = t0.elapsed();

        // Fetch
        let t1 = std::time::Instant::now();
        for i in 0..num_blocks {
            let (data, _) = client.fetch_block(&addr, i, &format!("f_{}", i), i as u64, None)
                .await.unwrap();
            assert_eq!(data.len(), block_size);
        }
        let fetch_elapsed = t1.elapsed();

        let store_mbps = total_bytes as f64 / store_elapsed.as_secs_f64() / 1_000_000.0;
        let fetch_mbps = total_bytes as f64 / fetch_elapsed.as_secs_f64() / 1_000_000.0;

        println!("  Store: {:>5}ms ({:>6.1} MB/s)", store_elapsed.as_millis(), store_mbps);
        println!("  Fetch: {:>5}ms ({:>6.1} MB/s)", fetch_elapsed.as_millis(), fetch_mbps);
    }

    // ═══ B: MUX persistent ═══
    println!("\n═══ B: MUX persistent ═══");
    let mux_fetch_mbps;
    let mux_batch_mbps;
    {
        let store = Arc::new(BlockStore::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

        let client = ClusterMuxClient::new(&addr, "p520.aint");

        // Store
        let t0 = std::time::Instant::now();
        for i in 0..num_blocks {
            client.store_block(i, &blocks[i], &hashes[i], "seal", block_size, i as u64)
                .await.unwrap();
        }
        let store_elapsed = t0.elapsed();

        // Fetch (sequential)
        let t1 = std::time::Instant::now();
        for i in 0..num_blocks {
            let (data, _) = client.fetch_block(i, None, i as u64).await.unwrap();
            assert_eq!(data.len(), block_size);
        }
        let fetch_elapsed = t1.elapsed();

        // Fetch (batch pipeline)
        let requests: Vec<(usize, u64)> = (0..num_blocks).map(|i| (i, i as u64)).collect();
        let t2 = std::time::Instant::now();
        let results = client.fetch_batch(&requests).await.unwrap();
        let batch_elapsed = t2.elapsed();
        assert_eq!(results.len(), num_blocks);

        let store_mbps = total_bytes as f64 / store_elapsed.as_secs_f64() / 1_000_000.0;
        mux_fetch_mbps = total_bytes as f64 / fetch_elapsed.as_secs_f64() / 1_000_000.0;
        mux_batch_mbps = total_bytes as f64 / batch_elapsed.as_secs_f64() / 1_000_000.0;

        println!("  Store:      {:>5}ms ({:>6.1} MB/s)", store_elapsed.as_millis(), store_mbps);
        println!("  Fetch seq:  {:>5}ms ({:>6.1} MB/s)", fetch_elapsed.as_millis(), mux_fetch_mbps);
        println!("  Fetch pipe: {:>5}ms ({:>6.1} MB/s)", batch_elapsed.as_millis(), mux_batch_mbps);

        client.disconnect().await;
    }

    // ═══ Summary ═══
    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║  MUX eliminates TCP connect overhead per block    ║");
    println!("║  Pipeline eliminates per-request RTT waiting      ║");
    println!("║                                                   ║");
    println!("║  Best throughput: {:.1} MB/s (MUX pipeline)      ║", mux_batch_mbps);
    println!("║  Next: QUIC (0-RTT, no head-of-line blocking)    ║");
    println!("╚═══════════════════════════════════════════════════╝");
}

// ═══════════════════════════════════════════════════════════════
// TCP-per-block loopback (original)
// ═══════════════════════════════════════════════════════════════

async fn run_loopback_test() {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║  Cluster Transport — Loopback Test               ║");
    println!("║  Simulates P520 ↔ DL360 on localhost             ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();

    // Start server on random port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store = Arc::new(BlockStore::new());

    // Pre-load 10 blocks
    println!("Pre-loading 10 blocks into remote store...");
    for i in 0..10usize {
        let size = 4096 * (i + 1);
        let data = vec![(i & 0xFF) as u8; size];
        let hash = sha256_hex(&data);
        store.store(i, data, hash, format!("seal_{}", i),
                    size * 2, "p520.aint".to_string(), i as u64).await;
    }
    println!("  Stored 10 blocks ({:.1} KB total)\n",
             store.stats().2 as f64 / 1024.0);

    // Spawn server
    let store_clone = store.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    let s = store_clone.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(socket, s, "dl360.aint").await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    let client = ClusterTransportClient::new("p520.aint");
    let endpoint = addr.to_string();
    let mut passed = 0;
    let total = 5;

    // Test 1: Ping
    println!("═══ Test 1: Ping ═══");
    let rtt = client.ping(&endpoint).await.unwrap();
    println!("  RTT: {}µs ✓", rtt);
    passed += 1;

    // Test 2: Fetch pre-loaded blocks
    println!("\n═══ Test 2: Fetch Pre-loaded Blocks ═══");
    let mut total_fetch_us = 0u64;
    for i in 0..10usize {
        let t0 = std::time::Instant::now();
        let (data, resp) = client.fetch_block(
            &endpoint, i, &format!("fork_{}", i), i as u64, None,
        ).await.unwrap();

        let elapsed = t0.elapsed().as_micros() as u64;
        total_fetch_us += elapsed;

        let expected_size = 4096 * (i + 1);
        assert_eq!(data.len(), expected_size);
        assert_eq!(data[0], (i & 0xFF) as u8);
        println!("  Block {:>2} ({:>5}B): {:>4}µs  server={:>3}µs ✓",
                 i, data.len(), elapsed, resp.server_latency_us);
    }
    println!("  Avg: {}µs per block", total_fetch_us / 10);
    passed += 1;

    // Test 3: Store + fetch roundtrip
    println!("\n═══ Test 3: Store + Fetch Roundtrip (128KB) ═══");
    let big_block = vec![0xDE; 131072];
    let big_hash = sha256_hex(&big_block);
    let big_seal = format!("{:0<128}", "big_block_seal");

    let store_resp = client.store_block(
        &endpoint, 100, &big_block, &big_hash, &big_seal, 262144, 42,
    ).await.unwrap();
    println!("  Stored: 128KB, server={}µs ✓", store_resp.server_latency_us);

    let (fetched, fetch_resp) = client.fetch_block(
        &endpoint, 100, "fork_100", 42, Some(&big_hash),
    ).await.unwrap();
    assert_eq!(fetched, big_block);
    println!("  Fetched: 128KB, hash verified, server={}µs ✓", fetch_resp.server_latency_us);
    passed += 1;

    // Test 4: Error handling
    println!("\n═══ Test 4: Error Handling ═══");
    let err = client.fetch_block(&endpoint, 9999, "x", 0, None).await;
    assert!(matches!(err, Err(TransportError::Remote { status: 404, .. })));
    println!("  404 on missing block ✓");

    let err = client.fetch_block(&endpoint, 0, "x", 0, Some("wrong_hash")).await;
    assert!(matches!(err, Err(TransportError::Remote { status: 409, .. })));
    println!("  409 on hash mismatch ✓");
    passed += 1;

    // Test 5: Throughput
    println!("\n═══ Test 5: Throughput (50 × 64KB) ═══");
    let block_size = 65536;
    let num_blocks: usize = 50;

    let t0 = std::time::Instant::now();
    for i in 0..num_blocks {
        let data = vec![(i & 0xFF) as u8; block_size];
        let h = sha256_hex(&data);
        let s = format!("{:0<128}", format!("bench_{}", i));
        client.store_block(&endpoint, 200 + i, &data, &h, &s, block_size, i as u64).await.unwrap();
    }
    let store_ms = t0.elapsed().as_millis();
    let store_mbps = (num_blocks * block_size) as f64 / t0.elapsed().as_secs_f64() / 1_000_000.0;

    let t1 = std::time::Instant::now();
    for i in 0..num_blocks {
        let (data, _) = client.fetch_block(
            &endpoint, 200 + i, &format!("bench_{}", i), i as u64, None,
        ).await.unwrap();
        assert_eq!(data.len(), block_size);
    }
    let fetch_ms = t1.elapsed().as_millis();
    let fetch_mbps = (num_blocks * block_size) as f64 / t1.elapsed().as_secs_f64() / 1_000_000.0;

    println!("  Store: {}ms ({:.1} MB/s)", store_ms, store_mbps);
    println!("  Fetch: {}ms ({:.1} MB/s)", fetch_ms, fetch_mbps);
    passed += 1;

    // Summary
    let (stored, served, bytes) = store.stats();
    println!("\n═══ Store Stats ═══");
    println!("  Blocks stored: {}", stored);
    println!("  Blocks served: {}", served);
    println!("  Total bytes:   {:.1} KB", bytes as f64 / 1024.0);

    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║  {}/{} tests passed!                              ║", passed, total);
    if passed == total {
        println!("║  Ready for P520 ↔ DL360 real network test        ║");
    }
    println!("╚═══════════════════════════════════════════════════╝");
}
