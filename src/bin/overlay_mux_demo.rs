// ═══════════════════════════════════════════════════════════════
// Overlay MUX Demo — "Establish Once, Stream Infinite"
//
// Demonstrates identity-native networking:
//   1. Server registers as jis:pixel:jasper
//   2. Client resolves IDD → endpoint
//   3. One QUIC connection, multiple intent streams
//
// Usage:
//   cargo run --bin overlay-mux-demo --features full
// ═══════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tibet_trust_kernel::overlay_mux::*;

#[tokio::main]
async fn main() {
    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  OVERLAY MUX — Identity-Native Networking Demo");
    println!("  \"Establish Once, Stream Infinite\"");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    // ── Step 1: Start server (simulates remote device) ──
    println!("▸ Starting OverlayMuxServer as jis:pixel:jasper...");

    let server = OverlayMuxServer::new("127.0.0.1:0", "pixel-jasper.aint");

    // Intent handler — dispatches based on intent type
    server.on_intent(Arc::new(|frame: IntentFrame, payload: Vec<u8>| {
        let intent = StreamIntent::from_str(&frame.intent);
        let msg = match intent {
            StreamIntent::Chat => format!("Chat received: {} bytes from {}", payload.len(), frame.from_aint),
            StreamIntent::Voice => format!("Voice frame: {} bytes (20ms @ 16kHz)", payload.len()),
            StreamIntent::Video => format!("Video frame: {} bytes", payload.len()),
            StreamIntent::LlmSync => format!("LLM memory sync: {} bytes", payload.len()),
            StreamIntent::File => format!("File chunk: {} bytes", payload.len()),
            StreamIntent::Control => format!("Control signal from {}", frame.from_aint),
            StreamIntent::Finance => format!("Financial tx: {} bytes (triage required)", payload.len()),
            StreamIntent::Industrial => format!("Industrial data: {} bytes (Modbus/OPC-UA)", payload.len()),
            StreamIntent::Custom(ref s) => format!("Custom intent '{}': {} bytes", s, payload.len()),
        };
        println!("  ◈ [SERVER] {}", msg);

        IntentResponse {
            channel_id: frame.channel_id,
            status: 200,
            intent: frame.intent,
            tibet_token_id: format!("tibet_{}_{}", frame.channel_id, chrono::Utc::now().timestamp_millis()),
            payload_size: payload.len(),
            error: None,
        }
    })).await;

    // Start server and get the port
    let port = server.start_background().await.expect("server start");
    println!("  ✓ Server listening on 127.0.0.1:{}", port);
    println!();

    // ── Step 2: Create OverlayMux client ──
    println!("▸ Creating OverlayMux client as root_idd.aint...");
    let mux = OverlayMux::new("root_idd.aint");

    // Register known device (simulates overlay resolve)
    let endpoint_str = format!("127.0.0.1:{}", port);
    mux.resolver().register("jis:pixel:jasper", &endpoint_str, 0.95).await;
    println!("  ✓ Registered jis:pixel:jasper → {} (trust: 0.95)", endpoint_str);
    println!();

    // ── Step 3: Send intents (each opens a QUIC stream) ──
    println!("═══════════════════════════════════════════════════════════");
    println!("  PHASE 1: Multi-intent over single connection");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    let intents: Vec<(StreamIntent, Vec<u8>, &str)> = vec![
        (StreamIntent::Chat, b"Hoi vanuit root_idd! Identity is key.".to_vec(), "Chat message"),
        (StreamIntent::Voice, vec![0xAA; 320], "20ms voice frame (320 bytes)"),
        (StreamIntent::Video, vec![0xBB; 4096], "Video keyframe (4KB)"),
        (StreamIntent::LlmSync, b"{\"model\":\"qwen-32b\",\"context_window\":32768}".to_vec(), "LLM memory state"),
        (StreamIntent::File, vec![0xCC; 1024], "File chunk (1KB)"),
        (StreamIntent::Control, b"ping".to_vec(), "Control signal"),
        (StreamIntent::Finance, b"{\"amount\":42.50,\"to\":\"NL91ABNA0417164300\"}".to_vec(), "Financial tx"),
        (StreamIntent::Industrial, b"\x01\x03\x00\x00\x00\x0A".to_vec(), "Modbus read registers"),
    ];

    let t_total = Instant::now();

    for (intent, payload, description) in &intents {
        let t0 = Instant::now();
        let resp = mux.send("jis:pixel:jasper", intent.clone(), payload).await.unwrap();
        let us = t0.elapsed().as_micros();
        let token_short = if resp.tibet_token_id.len() > 30 {
            &resp.tibet_token_id[..30]
        } else {
            &resp.tibet_token_id
        };
        println!("  ✓ {} → {} ({}µs, token: {}...)", description, resp.status, us, token_short);
    }

    let total_us = t_total.elapsed().as_micros();
    println!();
    println!("  ⚡ 8 intents in {}µs ({:.0}µs/intent avg)", total_us, total_us as f64 / 8.0);
    println!("  ⚡ All over 1 QUIC connection, 0 extra NAT entries");

    println!();

    // ── Step 4: Parallel intents (KIT app scenario) ──
    println!("═══════════════════════════════════════════════════════════");
    println!("  PHASE 2: Parallel streams (KIT app real-world)");
    println!("═══════════════════════════════════════════════════════════");
    println!();
    println!("  Simulating: voice call + chat + LLM sync simultaneously...");

    let mux_ref = &mux;
    let t0 = Instant::now();

    let voice_data = vec![0xAA; 320];
    let (voice, chat, llm) = tokio::join!(
        mux_ref.send("jis:pixel:jasper", StreamIntent::Voice, &voice_data),
        mux_ref.send("jis:pixel:jasper", StreamIntent::Chat, b"concurrent message!"),
        mux_ref.send("jis:pixel:jasper", StreamIntent::LlmSync, b"{\"sync\":true}"),
    );

    let parallel_us = t0.elapsed().as_micros();

    println!("  ✓ Voice: {}", voice.unwrap().status);
    println!("  ✓ Chat:  {}", chat.unwrap().status);
    println!("  ✓ LLM:   {}", llm.unwrap().status);
    println!();
    println!("  ⚡ 3 parallel intents in {}µs (no head-of-line blocking!)", parallel_us);

    println!();

    // ── Step 5: Show status ──
    println!("═══════════════════════════════════════════════════════════");
    println!("  CONNECTION STATUS");
    println!("═══════════════════════════════════════════════════════════");

    let status = mux.status().await;
    println!("  Identity: {}", status.our_aint);
    println!("  Total intents sent: {}", status.total_intents);
    println!("  Peers connected: {}", status.total_peers);
    println!("  Resolver cache hits: {}", status.resolver_cache_hits);
    println!("  Resolver cache misses: {}", status.resolver_cache_misses);

    for peer in &status.peers {
        println!();
        println!("  Peer: {}", peer.idd);
        println!("    Endpoint: {}", peer.endpoint);
        println!("    Trust: {:.2}", peer.trust_score);
        println!("    Intents: {}", peer.intents_sent);
        println!("    Bytes: {}", peer.bytes_sent);
        println!("    Connected: {}s", peer.connected_secs);
    }

    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  Identity is key. IDD, not IP. One connection, ∞ streams.");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    // Cleanup
    mux.disconnect_all().await;
}
