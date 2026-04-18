// ═══════════════════════════════════════════════════════════════
// QUIC MUX — Multi-stream multiplexed transport for block transfer
//
// Replaces TCP's head-of-line blocking with QUIC's independent
// streams. Each block operation gets its own bidirectional stream,
// so a slow 70B layer fetch doesn't stall a fast 1B ping.
//
// Key advantages over TCP MUX:
//   - No head-of-line blocking (stream-level, not connection-level)
//   - Multi-stream parallel fetches (N streams in flight)
//   - 0-RTT reconnection (session tickets)
//   - Connection migration (IP change doesn't drop session)
//   - Built-in TLS 1.3 (no separate handshake overhead)
//
// Wire protocol is identical to cluster_mux.rs:
//   [4 bytes: frame_len][JSON MuxFrame][optional binary payload]
//
// Self-signed certs via rcgen — this runs on a private 10Gbps
// link between P520 and DL360, not the public internet.
// ═══════════════════════════════════════════════════════════════

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;
use std::net::SocketAddr;

use quinn::{Endpoint, ServerConfig, ClientConfig, Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Sha256, Digest};

use crate::cluster_transport::BlockStore;
use crate::cluster_mux::{MuxFrame, MuxError, HashCache, VerifyResult};

// ═══════════════════════════════════════════════════════════════
// TLS Configuration — Self-signed certs for internal links
// ═══════════════════════════════════════════════════════════════

/// Generate a self-signed certificate for QUIC.
/// Used on private links (10Gbps P520 ↔ DL360) — not public internet.
fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec![
        "tibet-cluster.local".to_string(),
        "localhost".to_string(),
    ]).expect("cert generation");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    (vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
}

/// Create QUIC server config with self-signed cert.
pub fn make_server_config() -> ServerConfig {
    let (certs, key) = generate_self_signed();

    let crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server TLS config");

    let mut config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("QUIC server config"),
    ));

    // Tune for high-throughput internal links
    let transport = Arc::get_mut(&mut config.transport).unwrap();
    transport.max_concurrent_bidi_streams(256u32.into());      // 256 parallel streams
    transport.max_concurrent_uni_streams(0u32.into());         // We don't use uni streams
    transport.initial_rtt(std::time::Duration::from_micros(100)); // 10Gbps link ≈ 50µs RTT
    // 16MB receive window — large blocks need room
    transport.receive_window((16 * 1024 * 1024u32).into());
    transport.send_window(16 * 1024 * 1024);
    transport.stream_receive_window((4 * 1024 * 1024u32).into());

    config
}

/// Create QUIC client config that trusts self-signed certs.
pub fn make_client_config() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();

    ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("QUIC client config"),
    ))
}

/// Skip certificate verification for self-signed internal certs.
/// Only used on private 10Gbps links — never on public internet.
#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ═══════════════════════════════════════════════════════════════
// Frame I/O — Same wire format as TCP MUX, over QUIC streams
// ═══════════════════════════════════════════════════════════════

async fn write_frame_quic(send: &mut SendStream, frame: &MuxFrame) -> std::io::Result<()> {
    let json = serde_json::to_vec(frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let len = (json.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&json).await?;
    Ok(())
}

async fn write_frame_with_payload_quic(
    send: &mut SendStream,
    frame: &MuxFrame,
    payload: &[u8],
) -> std::io::Result<()> {
    write_frame_quic(send, frame).await?;
    send.write_all(payload).await?;
    Ok(())
}

async fn read_frame_quic(recv: &mut RecvStream) -> std::io::Result<MuxFrame> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 4 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Frame too large: {} bytes", len),
        ));
    }

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Streaming SHA-256 read over QUIC RecvStream.
async fn read_payload_streaming_quic(
    recv: &mut RecvStream,
    payload_size: usize,
) -> std::io::Result<(Vec<u8>, String)> {
    const CHUNK_SIZE: usize = 65536;

    let mut data = vec![0u8; payload_size];
    let mut hasher = Sha256::new();
    let mut offset = 0;

    while offset < payload_size {
        let end = (offset + CHUNK_SIZE).min(payload_size);
        recv.read_exact(&mut data[offset..end]).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        hasher.update(&data[offset..end]);
        offset = end;
    }

    let hash = format!("{:x}", hasher.finalize());
    Ok((data, hash))
}

/// Cache-aware read over QUIC RecvStream.
async fn read_payload_cached_quic(
    recv: &mut RecvStream,
    payload_size: usize,
    server_hash: &str,
    block_index: usize,
    cache: &HashCache,
) -> std::io::Result<(Vec<u8>, String, VerifyResult)> {
    if cache.is_verified(block_index, server_hash).await {
        // CACHE HIT — skip SHA-256
        let mut data = vec![0u8; payload_size];
        let mut offset = 0;
        while offset < payload_size {
            let end = (offset + 65536).min(payload_size);
            recv.read_exact(&mut data[offset..end]).await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            offset = end;
        }

        let saved_us = (payload_size as u64) / 2500;
        cache.hits.fetch_add(1, Ordering::Relaxed);
        cache.bytes_saved.fetch_add(payload_size as u64, Ordering::Relaxed);

        return Ok((data, server_hash.to_string(), VerifyResult::CacheHit {
            hash: server_hash.to_string(),
            saved_us,
        }));
    }

    // CACHE MISS — full streaming SHA-256
    let t0 = Instant::now();
    let (data, computed_hash) = read_payload_streaming_quic(recv, payload_size).await?;
    let duration_us = t0.elapsed().as_micros() as u64;

    cache.mark_verified(block_index, computed_hash.clone()).await;
    cache.misses.fetch_add(1, Ordering::Relaxed);

    Ok((data, computed_hash.clone(), VerifyResult::FullVerify {
        hash: computed_hash,
        duration_us,
    }))
}

// ═══════════════════════════════════════════════════════════════
// QUIC MUX Server
// ═══════════════════════════════════════════════════════════════

pub struct QuicMuxServer {
    bind_addr: SocketAddr,
    store: Arc<BlockStore>,
    kernel_aint: String,
    /// Stats
    pub streams_handled: Arc<AtomicU64>,
    pub connections_total: Arc<AtomicU64>,
}

impl QuicMuxServer {
    pub fn new(bind_addr: SocketAddr, kernel_aint: &str, store: Arc<BlockStore>) -> Self {
        Self {
            bind_addr,
            store,
            kernel_aint: kernel_aint.to_string(),
            streams_handled: Arc::new(AtomicU64::new(0)),
            connections_total: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn serve(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = make_server_config();
        let endpoint = Endpoint::server(config, self.bind_addr)?;

        println!("◈ [QUIC-MUX-SERVER] Listening on {} (kernel: {})",
                 self.bind_addr, self.kernel_aint);

        while let Some(incoming) = endpoint.accept().await {
            let connection = incoming.await?;
            let peer = connection.remote_address();
            let conn_num = self.connections_total.fetch_add(1, Ordering::Relaxed) + 1;

            println!("◈ [QUIC-MUX-SERVER] Connection #{} from {} (QUIC)",
                     conn_num, peer);

            let store = self.store.clone();
            let kernel_aint = self.kernel_aint.clone();
            let streams_handled = self.streams_handled.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_quic_connection(
                    connection, store, &kernel_aint, streams_handled,
                ).await {
                    eprintln!("◈ [QUIC-MUX-SERVER] Connection #{} error: {}", conn_num, e);
                }
                println!("◈ [QUIC-MUX-SERVER] Connection #{} closed", conn_num);
            });
        }

        Ok(())
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.connections_total.load(Ordering::Relaxed),
            self.streams_handled.load(Ordering::Relaxed),
        )
    }
}

/// Handle a single QUIC connection — each request opens a new bidi stream.
async fn handle_quic_connection(
    connection: Connection,
    store: Arc<BlockStore>,
    kernel_aint: &str,
    streams_handled: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Each operation = one bidirectional stream (no head-of-line blocking!)
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let store = store.clone();
        let kernel_aint = kernel_aint.to_string();
        let streams_handled = streams_handled.clone();

        // Each stream handled independently — true parallelism
        tokio::spawn(async move {
            if let Err(e) = handle_quic_stream(
                send, recv, store, &kernel_aint,
            ).await {
                eprintln!("◈ [QUIC-MUX-SERVER] Stream error: {}", e);
            }
            streams_handled.fetch_add(1, Ordering::Relaxed);
        });
    }
}

/// Handle one bidirectional QUIC stream (one MuxFrame request → one response).
async fn handle_quic_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    store: Arc<BlockStore>,
    kernel_aint: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let frame = read_frame_quic(&mut recv).await?;
    let t0 = Instant::now();

    match frame {
        MuxFrame::Fetch { channel_id, block_index, expected_hash, .. } => {
            let block = store.fetch(block_index).await;

            match block {
                Some(b) => {
                    if let Some(ref expected) = expected_hash {
                        if &b.content_hash != expected {
                            let resp = MuxFrame::Response {
                                channel_id, status: 409, block_index,
                                content_hash: b.content_hash,
                                payload_size: 0, raw_size: 0,
                                server_latency_us: t0.elapsed().as_micros() as u64,
                                tibet_token_id: String::new(),
                                error: Some("Hash mismatch".into()),
                            };
                            write_frame_quic(&mut send, &resp).await?;
                            send.finish()?;
                            return Ok(());
                        }
                    }

                    let resp = MuxFrame::Response {
                        channel_id, status: 200, block_index,
                        content_hash: b.content_hash,
                        payload_size: b.data.len(), raw_size: b.raw_size,
                        server_latency_us: t0.elapsed().as_micros() as u64,
                        tibet_token_id: format!("quic_fetch_{}_{}", block_index, channel_id),
                        error: None,
                    };
                    write_frame_quic(&mut send, &resp).await?;
                    send.write_all(&b.data).await?;
                    send.finish()?;
                }
                None => {
                    let resp = MuxFrame::Response {
                        channel_id, status: 404, block_index,
                        content_hash: String::new(),
                        payload_size: 0, raw_size: 0,
                        server_latency_us: t0.elapsed().as_micros() as u64,
                        tibet_token_id: String::new(),
                        error: Some(format!("Block {} not found", block_index)),
                    };
                    write_frame_quic(&mut send, &resp).await?;
                    send.finish()?;
                }
            }
        }

        MuxFrame::Store {
            channel_id, block_index, from_aint,
            payload_size, raw_size, content_hash, ed25519_seal, bus_seq,
        } => {
            let (data, computed) = read_payload_streaming_quic(&mut recv, payload_size).await?;

            if computed != content_hash {
                let resp = MuxFrame::Response {
                    channel_id, status: 409, block_index,
                    content_hash: computed,
                    payload_size: 0, raw_size: 0,
                    server_latency_us: t0.elapsed().as_micros() as u64,
                    tibet_token_id: String::new(),
                    error: Some("Store hash mismatch".into()),
                };
                write_frame_quic(&mut send, &resp).await?;
                send.finish()?;
                return Ok(());
            }

            store.store(block_index, data.clone(), content_hash.clone(),
                       ed25519_seal, raw_size, from_aint, bus_seq).await;

            let resp = MuxFrame::Response {
                channel_id, status: 200, block_index,
                content_hash,
                payload_size: data.len(), raw_size,
                server_latency_us: t0.elapsed().as_micros() as u64,
                tibet_token_id: format!("quic_store_{}_{}", block_index, channel_id),
                error: None,
            };
            write_frame_quic(&mut send, &resp).await?;
            send.finish()?;
        }

        MuxFrame::Ping { channel_id, .. } => {
            let resp = MuxFrame::Response {
                channel_id, status: 200, block_index: 0,
                content_hash: String::new(),
                payload_size: 0, raw_size: 0,
                server_latency_us: t0.elapsed().as_micros() as u64,
                tibet_token_id: format!("quic_pong_{}", kernel_aint),
                error: None,
            };
            write_frame_quic(&mut send, &resp).await?;
            send.finish()?;
        }

        MuxFrame::Response { .. } => {
            // Server shouldn't receive responses
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// QUIC MUX Client — Multi-stream, no head-of-line blocking
// ═══════════════════════════════════════════════════════════════

pub struct QuicMuxClient {
    from_aint: String,
    /// QUIC connection (lazily established)
    connection: tokio::sync::Mutex<Option<Connection>>,
    /// Target endpoint
    pub endpoint: String,
    /// QUIC endpoint (bound once, reused)
    quic_endpoint: tokio::sync::Mutex<Option<Endpoint>>,
    /// Channel ID counter
    next_channel: AtomicU32,
    /// Stats
    pub requests_sent: AtomicU64,
    pub bytes_transferred: AtomicU64,
    pub streams_opened: AtomicU64,
    /// Hash cache — skip SHA-256 on verified blocks
    pub hash_cache: HashCache,
}

impl QuicMuxClient {
    pub fn new(endpoint: &str, from_aint: &str) -> Self {
        Self {
            from_aint: from_aint.to_string(),
            connection: tokio::sync::Mutex::new(None),
            endpoint: endpoint.to_string(),
            quic_endpoint: tokio::sync::Mutex::new(None),
            next_channel: AtomicU32::new(1),
            requests_sent: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            hash_cache: HashCache::new(),
        }
    }

    /// Ensure we have a live QUIC connection (lazy connect).
    /// Public so overlay_mux can open raw streams on the connection.
    pub async fn ensure_connected_pub(&self) -> Result<Connection, MuxError> {
        self.ensure_connected().await
    }

    /// Ensure we have a live QUIC connection (lazy connect).
    async fn ensure_connected(&self) -> Result<Connection, MuxError> {
        let mut conn_guard = self.connection.lock().await;
        if let Some(ref conn) = *conn_guard {
            // Check if connection is still alive
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }

        // Create or reuse QUIC endpoint
        let mut ep_guard = self.quic_endpoint.lock().await;
        let endpoint = if let Some(ref ep) = *ep_guard {
            ep.clone()
        } else {
            let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| MuxError::Connect(e.to_string()))?;
            ep.set_default_client_config(make_client_config());
            *ep_guard = Some(ep.clone());
            ep
        };
        drop(ep_guard);

        let addr: SocketAddr = self.endpoint.parse()
            .map_err(|e: std::net::AddrParseError| MuxError::Connect(e.to_string()))?;

        let connection = endpoint
            .connect(addr, "tibet-cluster.local")
            .map_err(|e| MuxError::Connect(e.to_string()))?
            .await
            .map_err(|e| MuxError::Connect(e.to_string()))?;

        *conn_guard = Some(connection.clone());
        Ok(connection)
    }

    fn next_channel_id(&self) -> u32 {
        self.next_channel.fetch_add(1, Ordering::Relaxed)
    }

    /// Ping — measure RTT over QUIC (opens a fresh stream).
    pub async fn ping(&self) -> Result<u64, MuxError> {
        let t0 = Instant::now();
        let conn = self.ensure_connected().await?;

        let channel_id = self.next_channel_id();
        let (mut send, mut recv) = conn.open_bi().await
            .map_err(|e| MuxError::Connect(e.to_string()))?;
        self.streams_opened.fetch_add(1, Ordering::Relaxed);

        let frame = MuxFrame::Ping {
            channel_id,
            from_aint: self.from_aint.clone(),
        };

        write_frame_quic(&mut send, &frame).await.map_err(|e| MuxError::Io(e.to_string()))?;
        send.finish().map_err(|e| MuxError::Io(e.to_string()))?;

        let resp = read_frame_quic(&mut recv).await.map_err(|e| MuxError::Io(e.to_string()))?;
        self.requests_sent.fetch_add(1, Ordering::Relaxed);

        match resp {
            MuxFrame::Response { status: 200, .. } => Ok(t0.elapsed().as_micros() as u64),
            MuxFrame::Response { error, .. } => Err(MuxError::Remote(error.unwrap_or_default())),
            _ => Err(MuxError::Protocol("Unexpected frame type".into())),
        }
    }

    /// Fetch a block over QUIC (one stream per fetch — no HOL blocking).
    pub async fn fetch_block(
        &self,
        block_index: usize,
        expected_hash: Option<&str>,
        bus_seq: u64,
    ) -> Result<(Vec<u8>, u64), MuxError> {
        let t0 = Instant::now();
        let conn = self.ensure_connected().await?;

        let channel_id = self.next_channel_id();
        let (mut send, mut recv) = conn.open_bi().await
            .map_err(|e| MuxError::Connect(e.to_string()))?;
        self.streams_opened.fetch_add(1, Ordering::Relaxed);

        let frame = MuxFrame::Fetch {
            channel_id,
            block_index,
            from_aint: self.from_aint.clone(),
            expected_hash: expected_hash.map(|s| s.to_string()),
            bus_seq,
        };

        write_frame_quic(&mut send, &frame).await.map_err(|e| MuxError::Io(e.to_string()))?;
        send.finish().map_err(|e| MuxError::Io(e.to_string()))?;

        let resp = read_frame_quic(&mut recv).await.map_err(|e| MuxError::Io(e.to_string()))?;

        match resp {
            MuxFrame::Response { status: 200, payload_size, content_hash, .. } => {
                let (data, verified_hash, _verify_result) = read_payload_cached_quic(
                    &mut recv, payload_size, &content_hash,
                    block_index, &self.hash_cache,
                ).await.map_err(|e| MuxError::Io(e.to_string()))?;

                if verified_hash != content_hash {
                    return Err(MuxError::IntegrityFailed { expected: content_hash, got: verified_hash });
                }

                let total_us = t0.elapsed().as_micros() as u64;
                self.requests_sent.fetch_add(1, Ordering::Relaxed);
                self.bytes_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);

                Ok((data, total_us))
            }
            MuxFrame::Response { status, error, .. } => {
                Err(MuxError::RemoteStatus { status, error: error.unwrap_or_default() })
            }
            _ => Err(MuxError::Protocol("Unexpected frame type".into())),
        }
    }

    /// Store a block over QUIC.
    pub async fn store_block(
        &self,
        block_index: usize,
        data: &[u8],
        content_hash: &str,
        ed25519_seal: &str,
        raw_size: usize,
        bus_seq: u64,
    ) -> Result<u64, MuxError> {
        let t0 = Instant::now();
        let conn = self.ensure_connected().await?;

        let channel_id = self.next_channel_id();
        let (mut send, mut recv) = conn.open_bi().await
            .map_err(|e| MuxError::Connect(e.to_string()))?;
        self.streams_opened.fetch_add(1, Ordering::Relaxed);

        let frame = MuxFrame::Store {
            channel_id,
            block_index,
            from_aint: self.from_aint.clone(),
            payload_size: data.len(),
            raw_size,
            content_hash: content_hash.to_string(),
            ed25519_seal: ed25519_seal.to_string(),
            bus_seq,
        };

        write_frame_with_payload_quic(&mut send, &frame, data).await
            .map_err(|e| MuxError::Io(e.to_string()))?;
        send.finish().map_err(|e| MuxError::Io(e.to_string()))?;

        let resp = read_frame_quic(&mut recv).await.map_err(|e| MuxError::Io(e.to_string()))?;

        let total_us = t0.elapsed().as_micros() as u64;
        self.requests_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);

        match resp {
            MuxFrame::Response { status: 200, .. } => {
                self.hash_cache.mark_verified(block_index, content_hash.to_string()).await;
                Ok(total_us)
            }
            MuxFrame::Response { status, error, .. } => {
                Err(MuxError::RemoteStatus { status, error: error.unwrap_or_default() })
            }
            _ => Err(MuxError::Protocol("Unexpected frame type".into())),
        }
    }

    /// Parallel batch fetch — opens N streams simultaneously!
    /// This is where QUIC truly shines: no head-of-line blocking.
    /// Each stream independently fetches a block in parallel.
    pub async fn fetch_batch_parallel(
        &self,
        requests: &[(usize, u64)], // (block_index, bus_seq)
    ) -> Result<Vec<(usize, Vec<u8>, u64)>, MuxError> {
        let t0 = Instant::now();
        let conn = self.ensure_connected().await?;

        // Spawn all fetches as parallel tasks — each on its own QUIC stream
        let mut handles = Vec::with_capacity(requests.len());

        for &(block_index, bus_seq) in requests {
            let conn = conn.clone();
            let from_aint = self.from_aint.clone();
            let channel_id = self.next_channel_id();
            let hash_cache = &self.hash_cache;

            // We can't move hash_cache into the spawned task, so we use
            // a simpler approach: fetch without cache in parallel mode.
            // The overhead is acceptable because QUIC parallelism dominates.
            let handle = tokio::spawn(async move {
                let (mut send, mut recv) = conn.open_bi().await
                    .map_err(|e| MuxError::Connect(e.to_string()))?;

                let frame = MuxFrame::Fetch {
                    channel_id,
                    block_index,
                    from_aint,
                    expected_hash: None,
                    bus_seq,
                };

                write_frame_quic(&mut send, &frame).await
                    .map_err(|e| MuxError::Io(e.to_string()))?;
                send.finish().map_err(|e| MuxError::Io(e.to_string()))?;

                let resp = read_frame_quic(&mut recv).await
                    .map_err(|e| MuxError::Io(e.to_string()))?;

                match resp {
                    MuxFrame::Response { status: 200, payload_size, content_hash, .. } => {
                        let (data, computed_hash) = read_payload_streaming_quic(
                            &mut recv, payload_size,
                        ).await.map_err(|e| MuxError::Io(e.to_string()))?;

                        if computed_hash != content_hash {
                            return Err(MuxError::IntegrityFailed {
                                expected: content_hash, got: computed_hash,
                            });
                        }

                        Ok((block_index, data, content_hash))
                    }
                    MuxFrame::Response { status, error, .. } => {
                        Err(MuxError::RemoteStatus {
                            status, error: error.unwrap_or_default(),
                        })
                    }
                    _ => Err(MuxError::Protocol("Unexpected frame".into())),
                }
            });

            handles.push(handle);
        }

        // Collect all results
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            let (block_index, data, content_hash) = handle.await
                .map_err(|e| MuxError::Io(e.to_string()))??;

            self.bytes_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);
            // Update hash cache with verified blocks
            self.hash_cache.mark_verified(block_index, content_hash).await;

            let elapsed = t0.elapsed().as_micros() as u64;
            results.push((block_index, data, elapsed));
        }

        self.requests_sent.fetch_add(requests.len() as u64, Ordering::Relaxed);
        self.streams_opened.fetch_add(requests.len() as u64, Ordering::Relaxed);

        Ok(results)
    }

    /// Disconnect — close the QUIC connection gracefully.
    pub async fn disconnect(&self) {
        let mut conn = self.connection.lock().await;
        if let Some(c) = conn.take() {
            c.close(0u32.into(), b"bye");
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_transport::sha256_hex;

    async fn setup_quic_server() -> (SocketAddr, Arc<BlockStore>) {
        let store = Arc::new(BlockStore::new());
        let config = make_server_config();

        let endpoint = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        let store_clone = store.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let connection = incoming.await.unwrap();
                let store = store_clone.clone();
                let streams = Arc::new(AtomicU64::new(0));
                tokio::spawn(async move {
                    let _ = handle_quic_connection(
                        connection, store, "test.aint", streams,
                    ).await;
                });
            }
        });

        (addr, store)
    }

    #[tokio::test]
    async fn test_quic_ping() {
        let (addr, _store) = setup_quic_server().await;
        let client = QuicMuxClient::new(&addr.to_string(), "p520.aint");

        let rtt = client.ping().await.unwrap();
        assert!(rtt < 50_000, "QUIC ping too slow: {}µs", rtt);

        // Second ping reuses QUIC connection (new stream, same connection)
        let rtt2 = client.ping().await.unwrap();
        assert!(rtt2 < 50_000, "Second QUIC ping too slow: {}µs", rtt2);
    }

    #[tokio::test]
    async fn test_quic_store_fetch() {
        let (addr, _store) = setup_quic_server().await;
        let client = QuicMuxClient::new(&addr.to_string(), "p520.aint");

        let data = vec![0xCA; 8192];
        let hash = sha256_hex(&data);

        let store_us = client.store_block(0, &data, &hash, "seal", 16384, 1).await.unwrap();
        assert!(store_us < 100_000);

        let (fetched, fetch_us) = client.fetch_block(0, Some(&hash), 1).await.unwrap();
        assert_eq!(fetched, data);
        assert!(fetch_us < 100_000);
    }

    #[tokio::test]
    async fn test_quic_multiple_blocks() {
        let (addr, _store) = setup_quic_server().await;
        let client = QuicMuxClient::new(&addr.to_string(), "p520.aint");

        // Store 20 blocks — each on its own QUIC stream
        for i in 0..20usize {
            let data = vec![(i & 0xFF) as u8; 4096];
            let hash = sha256_hex(&data);
            client.store_block(i, &data, &hash, "seal", 4096, i as u64).await.unwrap();
        }

        // Fetch all 20 back — each on its own QUIC stream
        for i in 0..20usize {
            let (data, _us) = client.fetch_block(i, None, i as u64).await.unwrap();
            assert_eq!(data.len(), 4096);
            assert_eq!(data[0], (i & 0xFF) as u8);
        }

        assert_eq!(client.requests_sent.load(Ordering::Relaxed), 40);
    }

    #[tokio::test]
    async fn test_quic_parallel_batch() {
        let (addr, _store) = setup_quic_server().await;
        let client = QuicMuxClient::new(&addr.to_string(), "p520.aint");

        // Pre-store 10 blocks
        for i in 0..10usize {
            let data = vec![(i & 0xFF) as u8; 65536]; // 64KB each
            let hash = sha256_hex(&data);
            client.store_block(i, &data, &hash, "seal", 65536, i as u64).await.unwrap();
        }

        // Parallel fetch all 10 — each on its own QUIC stream, true parallelism!
        let requests: Vec<(usize, u64)> = (0..10).map(|i| (i, i as u64)).collect();
        let t0 = Instant::now();
        let results = client.fetch_batch_parallel(&requests).await.unwrap();
        let parallel_us = t0.elapsed().as_micros();

        assert_eq!(results.len(), 10);
        for (block_index, data, _elapsed) in &results {
            assert_eq!(data.len(), 65536);
            assert_eq!(data[0], (*block_index & 0xFF) as u8);
        }

        // Sequential fetch for comparison
        let t1 = Instant::now();
        for i in 0..10usize {
            let (_data, _us) = client.fetch_block(i, None, i as u64).await.unwrap();
        }
        let sequential_us = t1.elapsed().as_micros();

        println!("=== QUIC Multi-Stream Performance ===");
        println!("Parallel (10 streams): {:>8}µs for 10 × 64KB", parallel_us);
        println!("Sequential (1 stream): {:>8}µs for 10 × 64KB", sequential_us);
        println!("Speedup:               {:.1}x", sequential_us as f64 / parallel_us as f64);
    }

    #[tokio::test]
    async fn test_quic_fetch_not_found() {
        let (addr, _store) = setup_quic_server().await;
        let client = QuicMuxClient::new(&addr.to_string(), "p520.aint");

        let result = client.fetch_block(999, None, 0).await;
        assert!(matches!(result, Err(MuxError::RemoteStatus { status: 404, .. })));
    }

    #[tokio::test]
    async fn test_quic_connection_reuse() {
        let (addr, _store) = setup_quic_server().await;
        let client = QuicMuxClient::new(&addr.to_string(), "p520.aint");

        // 50 pings — one QUIC connection, 50 streams
        for _ in 0..50 {
            client.ping().await.unwrap();
        }

        assert_eq!(client.requests_sent.load(Ordering::Relaxed), 50);
        assert_eq!(client.streams_opened.load(Ordering::Relaxed), 50);
    }

    #[tokio::test]
    async fn test_quic_hash_cache() {
        let (addr, _store) = setup_quic_server().await;
        let client = QuicMuxClient::new(&addr.to_string(), "p520.aint");

        let block_size = 2 * 1024 * 1024; // 2MB
        for i in 0..3usize {
            let data = vec![(i & 0xFF) as u8; block_size];
            let hash = sha256_hex(&data);
            client.store_block(i, &data, &hash, "seal", block_size, i as u64).await.unwrap();
        }

        // 1st fetch: cache hits (store pre-warmed)
        for i in 0..3usize {
            let (_data, _us) = client.fetch_block(i, None, i as u64).await.unwrap();
        }
        let (hits, misses, _, _) = client.hash_cache.stats();
        assert_eq!(hits, 3, "store pre-warms cache");
        assert_eq!(misses, 0);

        // 2nd fetch: still cached
        for i in 0..3usize {
            let (_data, _us) = client.fetch_block(i, None, i as u64).await.unwrap();
        }
        let (hits, _, _, _) = client.hash_cache.stats();
        assert_eq!(hits, 6);
    }
}
