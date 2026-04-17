// ═══════════════════════════════════════════════════════════════
// Cluster Transport — TCP block transfer for RAM RAID-0
//
// The missing 20%: actual bytes over the wire between P520 ↔ DL360.
//
// Uses the MUX protocol (JSON header + binary payload) on port 4430.
// Every block transfer is:
//   - Bifurcation encrypted (AES-256-GCM)
//   - Ed25519 sealed (integrity)
//   - TIBET tokened (provenance)
//
// Wire protocol:
//   REQUEST:  [4 bytes: header_len][JSON header][binary: N/A for fetch]
//   RESPONSE: [4 bytes: header_len][JSON header][binary: .tza block data]
//
// Intents:
//   "ram_raid:fetch"  — request a block from remote kernel
//   "ram_raid:store"  — push a block to remote kernel for storage
//   "ram_raid:ping"   — health check / latency probe
// ═══════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Wire Protocol
// ═══════════════════════════════════════════════════════════════

/// Request header sent by the client (P520 fetching from DL360).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockRequest {
    /// MUX intent: "ram_raid:fetch", "ram_raid:store", "ram_raid:ping"
    pub intent: String,
    /// Requesting kernel's .aint identity
    pub from_aint: String,
    /// Block index in the RAID array
    pub block_index: usize,
    /// Fork token ID (for verification)
    pub fork_token_id: String,
    /// Bus sequence number (ordering guarantee)
    pub bus_seq: u64,
    /// Expected content hash (client knows what it evicted)
    pub expected_hash: Option<String>,
}

/// Response header sent back by the server (DL360 → P520).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockResponse {
    /// Original intent echoed back
    pub intent: String,
    /// Status: 200 = OK, 404 = not found, 403 = JIS denied, 500 = error
    pub status: u16,
    /// Block index
    pub block_index: usize,
    /// SHA-256 of the (compressed, encrypted) payload
    pub content_hash: String,
    /// Ed25519 seal of (content_hash + block_index + bus_seq)
    pub ed25519_seal: String,
    /// Payload size in bytes (so receiver knows how much to read)
    pub payload_size: usize,
    /// Original uncompressed size (for buffer allocation)
    pub raw_size: usize,
    /// Compression ratio achieved
    pub compression_ratio: f64,
    /// TIBET token ID for this transfer
    pub tibet_token_id: String,
    /// Server-side latency in microseconds
    pub server_latency_us: u64,
    /// Error message (if status != 200)
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Block Store — Server-side storage of evicted blocks
// ═══════════════════════════════════════════════════════════════

/// A stored block on the remote kernel.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    /// Block index
    pub block_index: usize,
    /// Compressed + encrypted block data (.tza format)
    pub data: Vec<u8>,
    /// SHA-256 of the data
    pub content_hash: String,
    /// Ed25519 seal
    pub ed25519_seal: String,
    /// Original uncompressed size
    pub raw_size: usize,
    /// Who stored this block
    pub stored_by: String,
    /// Bus sequence at store time
    pub bus_seq: u64,
    /// When it was stored
    pub stored_at: Instant,
    /// Access count (for LRU)
    pub access_count: u64,
}

/// Thread-safe block store backing the remote kernel's RAM B.
pub struct BlockStore {
    blocks: Arc<RwLock<HashMap<usize, StoredBlock>>>,
    /// Total bytes stored
    total_bytes: Arc<std::sync::atomic::AtomicU64>,
    /// Total blocks served
    blocks_served: Arc<std::sync::atomic::AtomicU64>,
    /// Total blocks stored
    blocks_stored: Arc<std::sync::atomic::AtomicU64>,
}

impl BlockStore {
    pub fn new() -> Self {
        Self {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            total_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocks_served: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocks_stored: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Store a block received from a remote kernel.
    pub async fn store(&self, block_index: usize, data: Vec<u8>, content_hash: String,
                       ed25519_seal: String, raw_size: usize, from_aint: String, bus_seq: u64) {
        let data_len = data.len() as u64;
        let stored = StoredBlock {
            block_index,
            data,
            content_hash,
            ed25519_seal,
            raw_size,
            stored_by: from_aint,
            bus_seq,
            stored_at: Instant::now(),
            access_count: 0,
        };
        self.blocks.write().await.insert(block_index, stored);
        self.total_bytes.fetch_add(data_len, std::sync::atomic::Ordering::Relaxed);
        self.blocks_stored.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Fetch a block for a remote kernel.
    pub async fn fetch(&self, block_index: usize) -> Option<StoredBlock> {
        let mut blocks = self.blocks.write().await;
        if let Some(block) = blocks.get_mut(&block_index) {
            block.access_count += 1;
            self.blocks_served.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(block.clone())
        } else {
            None
        }
    }

    /// Stats for monitoring.
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.blocks_stored.load(std::sync::atomic::Ordering::Relaxed),
            self.blocks_served.load(std::sync::atomic::Ordering::Relaxed),
            self.total_bytes.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// Cluster Transport Server — Runs on DL360 (RAM B provider)
// ═══════════════════════════════════════════════════════════════

pub struct ClusterTransportServer {
    /// TCP listener address (e.g., "0.0.0.0:4430")
    bind_addr: String,
    /// Block store
    store: Arc<BlockStore>,
    /// This kernel's .aint identity
    kernel_aint: String,
}

impl ClusterTransportServer {
    pub fn new(bind_addr: &str, kernel_aint: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            store: Arc::new(BlockStore::new()),
            kernel_aint: kernel_aint.to_string(),
        }
    }

    /// Get a handle to the block store (for pre-loading blocks).
    pub fn store(&self) -> Arc<BlockStore> {
        self.store.clone()
    }

    /// Start serving block requests. Runs forever.
    pub async fn serve(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        println!("◈ [CLUSTER] Transport server on {} (kernel: {})",
                 self.bind_addr, self.kernel_aint);

        loop {
            let (socket, peer) = listener.accept().await?;
            let store = self.store.clone();
            let kernel_aint = self.kernel_aint.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, store, &kernel_aint).await {
                    eprintln!("◈ [CLUSTER] Error from {}: {}", peer, e);
                }
            });
        }
    }
}

/// Handle a single TCP connection (one request-response cycle).
pub async fn handle_connection(
    mut socket: TcpStream,
    store: Arc<BlockStore>,
    kernel_aint: &str,
) -> std::io::Result<()> {
    let t0 = Instant::now();

    // Read header length (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let header_len = u32::from_be_bytes(len_buf) as usize;

    if header_len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Header too large: {} bytes", header_len),
        ));
    }

    // Read JSON header
    let mut header_buf = vec![0u8; header_len];
    socket.read_exact(&mut header_buf).await?;
    let request: BlockRequest = serde_json::from_slice(&header_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    match request.intent.as_str() {
        "ram_raid:fetch" => {
            handle_fetch(&mut socket, &request, &store, kernel_aint, t0).await
        }
        "ram_raid:store" => {
            handle_store(&mut socket, &request, &store, kernel_aint, t0).await
        }
        "ram_raid:ping" => {
            handle_ping(&mut socket, &request, kernel_aint, t0).await
        }
        _ => {
            send_error(&mut socket, &request, 400,
                       &format!("Unknown intent: {}", request.intent)).await
        }
    }
}

/// Handle a fetch request — client wants a block from our store.
async fn handle_fetch(
    socket: &mut TcpStream,
    request: &BlockRequest,
    store: &Arc<BlockStore>,
    _kernel_aint: &str,
    t0: Instant,
) -> std::io::Result<()> {
    let block = match store.fetch(request.block_index).await {
        Some(b) => b,
        None => {
            return send_error(socket, request, 404,
                              &format!("Block {} not found", request.block_index)).await;
        }
    };

    // Verify hash if client provided expected hash
    if let Some(ref expected) = request.expected_hash {
        if &block.content_hash != expected {
            return send_error(socket, request, 409,
                              &format!("Hash mismatch: expected {}, have {}",
                                       expected, block.content_hash)).await;
        }
    }

    let server_latency_us = t0.elapsed().as_micros() as u64;

    // Build TIBET token ID for this transfer
    let tibet_token_id = format!("cluster_fetch_{}_{}", request.block_index, request.bus_seq);

    let response = BlockResponse {
        intent: request.intent.clone(),
        status: 200,
        block_index: request.block_index,
        content_hash: block.content_hash,
        ed25519_seal: block.ed25519_seal,
        payload_size: block.data.len(),
        raw_size: block.raw_size,
        compression_ratio: if block.raw_size > 0 {
            block.data.len() as f64 / block.raw_size as f64
        } else {
            1.0
        },
        tibet_token_id,
        server_latency_us,
        error: None,
    };

    // Send: [4 bytes header_len][JSON header][binary payload]
    let header_json = serde_json::to_vec(&response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let header_len = (header_json.len() as u32).to_be_bytes();

    socket.write_all(&header_len).await?;
    socket.write_all(&header_json).await?;
    socket.write_all(&block.data).await?;
    socket.flush().await?;

    Ok(())
}

/// Handle a store request — client wants to evict a block to us.
async fn handle_store(
    socket: &mut TcpStream,
    request: &BlockRequest,
    store: &Arc<BlockStore>,
    _kernel_aint: &str,
    t0: Instant,
) -> std::io::Result<()> {
    // After the header, read the payload size (4 bytes)
    let mut size_buf = [0u8; 4];
    socket.read_exact(&mut size_buf).await?;
    let payload_size = u32::from_be_bytes(size_buf) as usize;

    if payload_size > 64 * 1024 * 1024 {
        return send_error(socket, request, 413,
                          &format!("Payload too large: {} bytes", payload_size)).await;
    }

    // Read the raw size (4 bytes) — original uncompressed size
    let mut raw_buf = [0u8; 4];
    socket.read_exact(&mut raw_buf).await?;
    let raw_size = u32::from_be_bytes(raw_buf) as usize;

    // Read content hash (64 bytes hex string)
    let mut hash_buf = [0u8; 64];
    socket.read_exact(&mut hash_buf).await?;
    let content_hash = String::from_utf8_lossy(&hash_buf).to_string();

    // Read ed25519 seal (128 bytes hex string)
    let mut seal_buf = [0u8; 128];
    socket.read_exact(&mut seal_buf).await?;
    let ed25519_seal = String::from_utf8_lossy(&seal_buf).to_string();

    // Read block data
    let mut data = vec![0u8; payload_size];
    socket.read_exact(&mut data).await?;

    // Verify hash
    let computed_hash = sha256_hex(&data);
    if computed_hash != content_hash {
        return send_error(socket, request, 409,
                          &format!("Store hash mismatch: sent {}, computed {}",
                                   content_hash, computed_hash)).await;
    }

    // Store it
    store.store(
        request.block_index,
        data.clone(),
        content_hash.clone(),
        ed25519_seal,
        raw_size,
        request.from_aint.clone(),
        request.bus_seq,
    ).await;

    let server_latency_us = t0.elapsed().as_micros() as u64;
    let tibet_token_id = format!("cluster_store_{}_{}", request.block_index, request.bus_seq);

    let response = BlockResponse {
        intent: request.intent.clone(),
        status: 200,
        block_index: request.block_index,
        content_hash,
        ed25519_seal: String::new(),
        payload_size: data.len(),
        raw_size,
        compression_ratio: if raw_size > 0 { data.len() as f64 / raw_size as f64 } else { 1.0 },
        tibet_token_id,
        server_latency_us,
        error: None,
    };

    let header_json = serde_json::to_vec(&response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let header_len = (header_json.len() as u32).to_be_bytes();

    socket.write_all(&header_len).await?;
    socket.write_all(&header_json).await?;
    socket.flush().await?;

    Ok(())
}

/// Handle a ping request — latency probe.
async fn handle_ping(
    socket: &mut TcpStream,
    request: &BlockRequest,
    kernel_aint: &str,
    t0: Instant,
) -> std::io::Result<()> {
    let server_latency_us = t0.elapsed().as_micros() as u64;

    let response = BlockResponse {
        intent: "ram_raid:pong".to_string(),
        status: 200,
        block_index: 0,
        content_hash: String::new(),
        ed25519_seal: String::new(),
        payload_size: 0,
        raw_size: 0,
        compression_ratio: 0.0,
        tibet_token_id: format!("cluster_ping_{}", kernel_aint),
        server_latency_us,
        error: None,
    };

    let header_json = serde_json::to_vec(&response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let header_len = (header_json.len() as u32).to_be_bytes();

    socket.write_all(&header_len).await?;
    socket.write_all(&header_json).await?;
    socket.flush().await?;

    Ok(())
}

/// Send an error response.
async fn send_error(
    socket: &mut TcpStream,
    request: &BlockRequest,
    status: u16,
    error: &str,
) -> std::io::Result<()> {
    let response = BlockResponse {
        intent: request.intent.clone(),
        status,
        block_index: request.block_index,
        content_hash: String::new(),
        ed25519_seal: String::new(),
        payload_size: 0,
        raw_size: 0,
        compression_ratio: 0.0,
        tibet_token_id: String::new(),
        server_latency_us: 0,
        error: Some(error.to_string()),
    };

    let header_json = serde_json::to_vec(&response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let header_len = (header_json.len() as u32).to_be_bytes();

    socket.write_all(&header_len).await?;
    socket.write_all(&header_json).await?;
    socket.flush().await?;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Cluster Transport Client — Runs on P520 (fetches from DL360)
// ═══════════════════════════════════════════════════════════════

/// Client for fetching/storing blocks on remote kernels.
pub struct ClusterTransportClient {
    /// This kernel's .aint identity
    from_aint: String,
    /// Connection timeout in milliseconds
    timeout_ms: u64,
}

impl ClusterTransportClient {
    pub fn new(from_aint: &str) -> Self {
        Self {
            from_aint: from_aint.to_string(),
            timeout_ms: 500, // 500ms default — generous for LAN
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Fetch a block from a remote kernel.
    ///
    /// This is what gets called when RAM RAID hits a RemoteKernel fault.
    /// Returns (block_data, response_header) on success.
    pub async fn fetch_block(
        &self,
        endpoint: &str,
        block_index: usize,
        fork_token_id: &str,
        bus_seq: u64,
        expected_hash: Option<&str>,
    ) -> Result<(Vec<u8>, BlockResponse), TransportError> {
        let t0 = Instant::now();

        // Connect
        let mut socket = tokio::time::timeout(
            std::time::Duration::from_millis(self.timeout_ms),
            TcpStream::connect(endpoint),
        ).await
            .map_err(|_| TransportError::Timeout {
                endpoint: endpoint.to_string(),
                timeout_ms: self.timeout_ms,
            })?
            .map_err(|e| TransportError::Connect {
                endpoint: endpoint.to_string(),
                error: e.to_string(),
            })?;

        let connect_us = t0.elapsed().as_micros() as u64;

        // Build request
        let request = BlockRequest {
            intent: "ram_raid:fetch".to_string(),
            from_aint: self.from_aint.clone(),
            block_index,
            fork_token_id: fork_token_id.to_string(),
            bus_seq,
            expected_hash: expected_hash.map(|s| s.to_string()),
        };

        // Send request: [4 bytes header_len][JSON header]
        let header_json = serde_json::to_vec(&request)
            .map_err(|e| TransportError::Protocol(e.to_string()))?;
        let header_len = (header_json.len() as u32).to_be_bytes();

        socket.write_all(&header_len).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        socket.write_all(&header_json).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        socket.flush().await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let send_us = t0.elapsed().as_micros() as u64 - connect_us;

        // Read response: [4 bytes header_len][JSON header][binary payload]
        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let resp_header_len = u32::from_be_bytes(len_buf) as usize;

        let mut resp_header_buf = vec![0u8; resp_header_len];
        socket.read_exact(&mut resp_header_buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let response: BlockResponse = serde_json::from_slice(&resp_header_buf)
            .map_err(|e| TransportError::Protocol(e.to_string()))?;

        if response.status != 200 {
            return Err(TransportError::Remote {
                status: response.status,
                error: response.error.unwrap_or_default(),
            });
        }

        // Read payload
        let mut data = vec![0u8; response.payload_size];
        socket.read_exact(&mut data).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let total_us = t0.elapsed().as_micros() as u64;

        // Verify hash
        let computed_hash = sha256_hex(&data);
        if computed_hash != response.content_hash {
            return Err(TransportError::IntegrityFailed {
                expected: response.content_hash.clone(),
                got: computed_hash,
            });
        }

        println!("◈ [CLUSTER] Fetched block {} from {} — {}B in {}µs (connect={}µs send={}µs server={}µs)",
                 block_index, endpoint, data.len(), total_us, connect_us, send_us,
                 response.server_latency_us);

        Ok((data, response))
    }

    /// Store a block on a remote kernel (eviction).
    pub async fn store_block(
        &self,
        endpoint: &str,
        block_index: usize,
        data: &[u8],
        content_hash: &str,
        ed25519_seal: &str,
        raw_size: usize,
        bus_seq: u64,
    ) -> Result<BlockResponse, TransportError> {
        let t0 = Instant::now();

        let mut socket = tokio::time::timeout(
            std::time::Duration::from_millis(self.timeout_ms),
            TcpStream::connect(endpoint),
        ).await
            .map_err(|_| TransportError::Timeout {
                endpoint: endpoint.to_string(),
                timeout_ms: self.timeout_ms,
            })?
            .map_err(|e| TransportError::Connect {
                endpoint: endpoint.to_string(),
                error: e.to_string(),
            })?;

        // Build request header
        let request = BlockRequest {
            intent: "ram_raid:store".to_string(),
            from_aint: self.from_aint.clone(),
            block_index,
            fork_token_id: format!("evict_{}_{}", block_index, bus_seq),
            bus_seq,
            expected_hash: None,
        };

        // Send request header
        let header_json = serde_json::to_vec(&request)
            .map_err(|e| TransportError::Protocol(e.to_string()))?;
        let header_len = (header_json.len() as u32).to_be_bytes();

        socket.write_all(&header_len).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        socket.write_all(&header_json).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        // Send payload metadata + data
        // [4 bytes: payload_size][4 bytes: raw_size][64 bytes: hash][128 bytes: seal][data]
        socket.write_all(&(data.len() as u32).to_be_bytes()).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        socket.write_all(&(raw_size as u32).to_be_bytes()).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        // Hash: pad/truncate to exactly 64 bytes
        let hash_bytes = format!("{:0<64}", content_hash);
        socket.write_all(hash_bytes.as_bytes()).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        // Seal: pad/truncate to exactly 128 bytes
        let seal_bytes = format!("{:0<128}", ed25519_seal);
        socket.write_all(seal_bytes.as_bytes()).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        // Block data
        socket.write_all(data).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        socket.flush().await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        // Read response
        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let resp_header_len = u32::from_be_bytes(len_buf) as usize;

        let mut resp_header_buf = vec![0u8; resp_header_len];
        socket.read_exact(&mut resp_header_buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let response: BlockResponse = serde_json::from_slice(&resp_header_buf)
            .map_err(|e| TransportError::Protocol(e.to_string()))?;

        let total_us = t0.elapsed().as_micros() as u64;

        if response.status != 200 {
            return Err(TransportError::Remote {
                status: response.status,
                error: response.error.unwrap_or_default(),
            });
        }

        println!("◈ [CLUSTER] Stored block {} on {} — {}B in {}µs",
                 block_index, endpoint, data.len(), total_us);

        Ok(response)
    }

    /// Ping a remote kernel — measure RTT.
    pub async fn ping(&self, endpoint: &str) -> Result<u64, TransportError> {
        let t0 = Instant::now();

        let mut socket = tokio::time::timeout(
            std::time::Duration::from_millis(self.timeout_ms),
            TcpStream::connect(endpoint),
        ).await
            .map_err(|_| TransportError::Timeout {
                endpoint: endpoint.to_string(),
                timeout_ms: self.timeout_ms,
            })?
            .map_err(|e| TransportError::Connect {
                endpoint: endpoint.to_string(),
                error: e.to_string(),
            })?;

        let request = BlockRequest {
            intent: "ram_raid:ping".to_string(),
            from_aint: self.from_aint.clone(),
            block_index: 0,
            fork_token_id: String::new(),
            bus_seq: 0,
            expected_hash: None,
        };

        let header_json = serde_json::to_vec(&request)
            .map_err(|e| TransportError::Protocol(e.to_string()))?;
        let header_len = (header_json.len() as u32).to_be_bytes();

        socket.write_all(&header_len).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        socket.write_all(&header_json).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        socket.flush().await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        // Read pong
        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        socket.read_exact(&mut resp_buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let rtt_us = t0.elapsed().as_micros() as u64;
        Ok(rtt_us)
    }
}

// ═══════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum TransportError {
    /// TCP connection timed out
    Timeout { endpoint: String, timeout_ms: u64 },
    /// TCP connection failed
    Connect { endpoint: String, error: String },
    /// I/O error during transfer
    Io(String),
    /// Protocol error (bad JSON, etc.)
    Protocol(String),
    /// Remote returned error status
    Remote { status: u16, error: String },
    /// SHA-256 hash mismatch — data corrupted in transit
    IntegrityFailed { expected: String, got: String },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { endpoint, timeout_ms } =>
                write!(f, "Connection to {} timed out ({}ms)", endpoint, timeout_ms),
            Self::Connect { endpoint, error } =>
                write!(f, "Cannot connect to {}: {}", endpoint, error),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Protocol(e) => write!(f, "Protocol error: {}", e),
            Self::Remote { status, error } =>
                write!(f, "Remote error {}: {}", status, error),
            Self::IntegrityFailed { expected, got } =>
                write!(f, "Integrity check failed: expected {}, got {}", expected, got),
        }
    }
}

impl std::error::Error for TransportError {}

// ═══════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════

/// SHA-256 hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_block_store_roundtrip() {
        let store = BlockStore::new();

        let data = vec![42u8; 4096];
        let hash = sha256_hex(&data);
        let seal = "test_seal_abc123".to_string();

        store.store(7, data.clone(), hash.clone(), seal.clone(),
                    8192, "p520.aint".to_string(), 1).await;

        let fetched = store.fetch(7).await.unwrap();
        assert_eq!(fetched.data, data);
        assert_eq!(fetched.content_hash, hash);
        assert_eq!(fetched.raw_size, 8192);
        assert_eq!(fetched.stored_by, "p520.aint");
        assert_eq!(fetched.access_count, 1);

        let (stored, served, bytes) = store.stats();
        assert_eq!(stored, 1);
        assert_eq!(served, 1);
        assert_eq!(bytes, 4096);
    }

    #[tokio::test]
    async fn test_block_store_not_found() {
        let store = BlockStore::new();
        assert!(store.fetch(999).await.is_none());
    }

    #[tokio::test]
    async fn test_block_store_overwrite() {
        let store = BlockStore::new();

        let data1 = vec![1u8; 100];
        let data2 = vec![2u8; 200];

        store.store(0, data1, sha256_hex(&[1u8; 100]), String::new(),
                    100, "a.aint".to_string(), 1).await;
        store.store(0, data2.clone(), sha256_hex(&[2u8; 200]), String::new(),
                    200, "b.aint".to_string(), 2).await;

        let fetched = store.fetch(0).await.unwrap();
        assert_eq!(fetched.data, data2);
        assert_eq!(fetched.stored_by, "b.aint");
    }

    #[tokio::test]
    async fn test_server_client_fetch_roundtrip() {
        // Start server on random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(BlockStore::new());

        // Pre-load a block
        let block_data = vec![0xCA; 8192];
        let block_hash = sha256_hex(&block_data);
        store.store(42, block_data.clone(), block_hash.clone(),
                    "seal_test".to_string(), 16384, "dl360.aint".to_string(), 10).await;

        // Spawn server
        let store_clone = store.clone();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, store_clone, "dl360.aint").await.unwrap();
        });

        // Client fetch
        let client = ClusterTransportClient::new("p520.aint");
        let (data, response) = client.fetch_block(
            &addr.to_string(), 42, "fork_42", 10, Some(&block_hash),
        ).await.unwrap();

        assert_eq!(data, block_data);
        assert_eq!(response.status, 200);
        assert_eq!(response.block_index, 42);
        assert_eq!(response.content_hash, block_hash);
        assert_eq!(response.raw_size, 16384);
        assert!(response.server_latency_us < 10_000); // < 10ms
    }

    #[tokio::test]
    async fn test_server_client_store_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(BlockStore::new());

        let store_clone = store.clone();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, store_clone, "dl360.aint").await.unwrap();
        });

        // Client stores a block
        let client = ClusterTransportClient::new("p520.aint");
        let data = vec![0xBE; 4096];
        let hash = sha256_hex(&data);
        let seal = format!("{:0<128}", "ed25519_seal_here");

        let response = client.store_block(
            &addr.to_string(), 99, &data, &hash, &seal, 8192, 5,
        ).await.unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.block_index, 99);

        // Verify it's stored
        let fetched = store.fetch(99).await.unwrap();
        assert_eq!(fetched.data, data);
        assert_eq!(fetched.raw_size, 8192);
    }

    #[tokio::test]
    async fn test_server_client_ping() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(BlockStore::new());

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, store, "dl360.aint").await.unwrap();
        });

        let client = ClusterTransportClient::new("p520.aint");
        let rtt = client.ping(&addr.to_string()).await.unwrap();

        // Loopback should be < 1ms
        assert!(rtt < 1000, "Ping RTT too high: {}µs", rtt);
    }

    #[tokio::test]
    async fn test_fetch_not_found() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(BlockStore::new());

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, store, "dl360.aint").await.unwrap();
        });

        let client = ClusterTransportClient::new("p520.aint");
        let result = client.fetch_block(
            &addr.to_string(), 999, "fork_none", 0, None,
        ).await;

        assert!(matches!(result, Err(TransportError::Remote { status: 404, .. })));
    }

    #[tokio::test]
    async fn test_fetch_hash_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(BlockStore::new());

        let data = vec![0xAA; 1024];
        let hash = sha256_hex(&data);
        store.store(5, data, hash, "seal".to_string(), 1024, "x.aint".to_string(), 1).await;

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, store, "dl360.aint").await.unwrap();
        });

        let client = ClusterTransportClient::new("p520.aint");
        let result = client.fetch_block(
            &addr.to_string(), 5, "fork_5", 1, Some("wrong_hash_1234"),
        ).await;

        assert!(matches!(result, Err(TransportError::Remote { status: 409, .. })));
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello cluster");
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }
}
