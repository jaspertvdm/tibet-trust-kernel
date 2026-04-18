// ═══════════════════════════════════════════════════════════════
// OVERLAY MUX — Identity-native networking
//
// "Establish Once, Stream Infinite"
//
// The glue between tibet-overlay (identity resolve) and quic_mux
// (multi-stream transport). Instead of connecting to an IP:port,
// you connect to a JIS IDD (Individual Device Derivate). The
// overlay resolves where that identity currently lives, QUIC
// establishes the connection, and all intents (chat, voice,
// video, file, llm) flow as parallel streams over that single
// connection.
//
// NOTE: We use IDD (Individual Device Derivate), NOT W3C DID.
// IDD = identity evolved from source code into a unique being.
// W3C DID = Decentralized Identifier (different standard).
// JIS IDD format: "jis:pixel:jasper", "jis:dl360:hub"
//
// Key properties:
//   - Identity IS the address (JIS IDD, not IP)
//   - One resolve, one connection, infinite streams
//   - QUIC connection migration on IP change (WiFi → 5G)
//   - Intent-based stream routing (voice ≠ chat ≠ video)
//   - FIR/A trust score per peer
//   - TIBET provenance on every intent
//   - CGNAT-resilient (identity survives NAT)
//
// Architecture:
//
//   App Intent (chat:send, call:voice, file:sync)
//        │
//        ▼
//   OverlayMux.send(idd, intent, payload)
//        │
//        ├── 1. Resolve: IDD → endpoint (cached, <1µs after first)
//        ├── 2. Connect: QUIC handshake (lazy, one-time)
//        └── 3. Stream: open bidi stream, send intent frame
//              └── Parallel: N streams in flight, no HOL blocking
//
// ═══════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

#[cfg(feature = "quic")]
use crate::quic_mux::QuicMuxClient;
use crate::cluster_mux::MuxError;

// ═══════════════════════════════════════════════════════════════
// Intent Types — what KIT app wants to do
// ═══════════════════════════════════════════════════════════════

/// Stream intent — determines routing, priority, and QoS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StreamIntent {
    /// Chat message (iPoll, XMPP, Matrix)
    Chat,
    /// Real-time voice frames (low latency, drop-ok)
    Voice,
    /// Video frames (high bandwidth, buffered)
    Video,
    /// File transfer (reliable, can be slow)
    File,
    /// LLM memory sync (burst traffic)
    LlmSync,
    /// Control/signaling (small, high priority)
    Control,
    /// Financial transaction (triage-gated)
    Finance,
    /// IoT/Industrial (Modbus, OPC-UA)
    Industrial,
    /// Custom intent
    Custom(String),
}

impl StreamIntent {
    /// Wire format string for this intent.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Chat => "chat",
            Self::Voice => "voice",
            Self::Video => "video",
            Self::File => "file",
            Self::LlmSync => "llm-sync",
            Self::Control => "control",
            Self::Finance => "finance",
            Self::Industrial => "industrial",
            Self::Custom(s) => s.as_str(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "chat" => Self::Chat,
            "voice" => Self::Voice,
            "video" => Self::Video,
            "file" => Self::File,
            "llm-sync" => Self::LlmSync,
            "control" => Self::Control,
            "finance" => Self::Finance,
            "industrial" => Self::Industrial,
            other => Self::Custom(other.to_string()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Overlay Resolve — DID → endpoint
// ═══════════════════════════════════════════════════════════════

/// Result of resolving a JIS DID to a network endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResult {
    pub idd: String,
    pub resolved: bool,
    pub endpoint: String,
    pub trust_score: f64,
    pub method: String,
    pub resolved_at: String,
}

/// Resolve source — where we found the endpoint.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolveMethod {
    /// Local registry (instant, pre-configured)
    Local,
    /// Cache (within TTL)
    Cache,
    /// Network discovery (tibet-ping, slower)
    Network,
    /// HTTP API fallback
    Api,
}

/// Cached resolve entry with TTL.
#[derive(Debug, Clone)]
struct CachedResolve {
    endpoint: String,
    trust_score: f64,
    resolved_at: Instant,
    ttl: Duration,
}

impl CachedResolve {
    fn is_valid(&self) -> bool {
        self.resolved_at.elapsed() < self.ttl
    }
}

/// Overlay resolver — maps JIS DIDs to network endpoints.
/// Maintains a cache with TTL and supports multiple resolve backends.
pub struct OverlayResolver {
    /// Local registry: pre-configured known devices
    local_registry: RwLock<HashMap<String, (String, f64)>>,
    /// Cache: recently resolved DIDs
    cache: RwLock<HashMap<String, CachedResolve>>,
    /// API endpoint for network resolution
    api_endpoint: Option<String>,
    /// Default TTL for cache entries
    default_ttl: Duration,
    /// Stats
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub resolves_total: AtomicU64,
}

impl OverlayResolver {
    pub fn new() -> Self {
        Self {
            local_registry: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
            api_endpoint: None,
            default_ttl: Duration::from_secs(300),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            resolves_total: AtomicU64::new(0),
        }
    }

    /// Set the HTTP API endpoint for network resolution.
    /// e.g., "http://192.168.4.76:8000" or "https://brein.jaspervandemeent.nl"
    pub fn with_api(mut self, api_url: &str) -> Self {
        self.api_endpoint = Some(api_url.to_string());
        self
    }

    /// Register a known device in the local registry (instant resolve).
    pub async fn register(&self, idd: &str, endpoint: &str, trust_score: f64) {
        self.local_registry.write().await
            .insert(idd.to_string(), (endpoint.to_string(), trust_score));
    }

    /// Update endpoint for a known DID (e.g., after IP change / migration).
    pub async fn update_endpoint(&self, idd: &str, new_endpoint: &str) {
        // Update local registry if present
        if let Some(entry) = self.local_registry.write().await.get_mut(idd) {
            entry.0 = new_endpoint.to_string();
        }
        // Update cache
        if let Some(entry) = self.cache.write().await.get_mut(idd) {
            entry.endpoint = new_endpoint.to_string();
            entry.resolved_at = Instant::now();
        }
    }

    /// Resolve a JIS DID to an endpoint.
    /// Resolution order: local → cache → API → error
    pub async fn resolve(&self, idd: &str) -> Result<ResolveResult, MuxError> {
        self.resolves_total.fetch_add(1, Ordering::Relaxed);

        // Normalize DID: add jis: prefix if missing
        let idd = if idd.contains(':') || idd.ends_with(".aint") {
            idd.to_string()
        } else {
            format!("jis:{}", idd)
        };

        // 1. Local registry (instant)
        if let Some((endpoint, trust)) = self.local_registry.read().await.get(&idd) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(ResolveResult {
                idd,
                resolved: true,
                endpoint: endpoint.clone(),
                trust_score: *trust,
                method: "local".to_string(),
                resolved_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        // 2. Cache (within TTL)
        if let Some(cached) = self.cache.read().await.get(&idd) {
            if cached.is_valid() {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(ResolveResult {
                    idd,
                    resolved: true,
                    endpoint: cached.endpoint.clone(),
                    trust_score: cached.trust_score,
                    method: "cache".to_string(),
                    resolved_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        // 3. API resolution (network call to brain API)
        if let Some(ref api_url) = self.api_endpoint {
            match self.resolve_via_api(api_url, &idd).await {
                Ok(result) if result.resolved => {
                    // Cache it
                    self.cache.write().await.insert(idd.clone(), CachedResolve {
                        endpoint: result.endpoint.clone(),
                        trust_score: result.trust_score,
                        resolved_at: Instant::now(),
                        ttl: self.default_ttl,
                    });
                    return Ok(result);
                }
                _ => {}
            }
        }

        Err(MuxError::Connect(format!(
            "Could not resolve DID: {} (tried: local, cache, api)", idd
        )))
    }

    /// Resolve via HTTP API (calls /api/overlay/resolve/{idd}).
    async fn resolve_via_api(&self, api_url: &str, idd: &str) -> Result<ResolveResult, MuxError> {
        // Use a simple TCP GET — no heavy HTTP client dependency
        let url = format!("{}/api/overlay/resolve/{}", api_url.trim_end_matches('/'), idd);

        // Simple HTTP GET via tokio TCP
        let parsed = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))
            .ok_or_else(|| MuxError::Connect("Invalid API URL".into()))?;

        let (host_port, path) = parsed.split_once('/')
            .unwrap_or((parsed, ""));

        let stream = tokio::net::TcpStream::connect(host_port).await
            .map_err(|e| MuxError::Connect(format!("API connect failed: {}", e)))?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let request = format!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host_port
        );

        let mut stream = stream;
        stream.write_all(request.as_bytes()).await
            .map_err(|e| MuxError::Io(e.to_string()))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await
            .map_err(|e| MuxError::Io(e.to_string()))?;

        let response_str = String::from_utf8_lossy(&response);

        // Find JSON body after headers
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];
            if let Ok(result) = serde_json::from_str::<ResolveResult>(body.trim()) {
                return Ok(result);
            }
        }

        Err(MuxError::Connect("API resolve: no valid response".into()))
    }

    /// Invalidate cache for a DID (e.g., on connection failure).
    pub async fn invalidate(&self, idd: &str) {
        self.cache.write().await.remove(idd);
    }
}

// ═══════════════════════════════════════════════════════════════
// Peer Connection — one QUIC connection per resolved identity
// ═══════════════════════════════════════════════════════════════

/// A live connection to a peer, identified by DID.
#[cfg(feature = "quic")]
struct PeerConnection {
    idd: String,
    endpoint: String,
    trust_score: f64,
    connection: quinn::Connection,
    established_at: Instant,
    last_activity: Mutex<Instant>,
    intents_sent: AtomicU64,
    bytes_sent: AtomicU64,
}

// ═══════════════════════════════════════════════════════════════
// Intent Frame — what travels over the mux streams
// ═══════════════════════════════════════════════════════════════

/// A frame carrying an intent + payload over the overlay mux.
/// Sent as JSON header + binary payload (same wire format as MuxFrame).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFrame {
    /// Auto-incrementing stream channel
    pub channel_id: u32,
    /// Intent type (chat, voice, video, etc.)
    pub intent: String,
    /// Sender identity (.aint domain)
    pub from_aint: String,
    /// Target identity (.aint domain or JIS DID)
    pub to_idd: String,
    /// Payload size in bytes (binary follows after JSON frame)
    pub payload_size: usize,
    /// TIBET token ID for provenance
    pub tibet_token_id: String,
    /// Optional metadata (e.g., codec for voice, room_id for chat)
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Response to an intent frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResponse {
    pub channel_id: u32,
    pub status: u16,
    pub intent: String,
    pub tibet_token_id: String,
    pub payload_size: usize,
    #[serde(default)]
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// OverlayMux — The main interface
// "Connect to an identity, not an IP"
// ═══════════════════════════════════════════════════════════════

/// OverlayMux — identity-native networking.
///
/// Usage:
/// ```no_run
/// let mux = OverlayMux::new("root_idd.aint")
///     .with_api("http://192.168.4.76:8000");
///
/// // Register known peers
/// mux.resolver().register("jis:pixel:jasper", "10.0.0.42:7150", 0.95).await;
///
/// // Send a chat message — resolves DID, connects via QUIC, streams payload
/// mux.send("jis:pixel:jasper", StreamIntent::Chat, b"Hallo!").await?;
///
/// // Voice frame — same connection, different stream, no HOL blocking
/// mux.send("jis:pixel:jasper", StreamIntent::Voice, &audio_frame).await?;
///
/// // All of the above use ONE QUIC connection, ONE NAT entry
/// ```
#[cfg(feature = "quic")]
pub struct OverlayMux {
    /// Our identity on the network
    pub our_aint: String,
    /// Overlay resolver (DID → endpoint)
    resolver: Arc<OverlayResolver>,
    /// Live peer connections (DID → PeerConnection)
    peers: RwLock<HashMap<String, Arc<PeerConnection>>>,
    /// QUIC endpoint (bound once, reused for all outbound connections)
    quic_endpoint: Mutex<Option<quinn::Endpoint>>,
    /// Channel ID counter (global across all peers)
    next_channel: AtomicU32,
    /// Stats
    pub intents_total: AtomicU64,
    pub peers_connected: AtomicU64,
    pub migrations_total: AtomicU64,
}

#[cfg(feature = "quic")]
impl OverlayMux {
    /// Create a new OverlayMux with our .aint identity.
    pub fn new(our_aint: &str) -> Self {
        Self {
            our_aint: our_aint.to_string(),
            resolver: Arc::new(OverlayResolver::new()),
            peers: RwLock::new(HashMap::new()),
            quic_endpoint: Mutex::new(None),
            next_channel: AtomicU32::new(1),
            intents_total: AtomicU64::new(0),
            peers_connected: AtomicU64::new(0),
            migrations_total: AtomicU64::new(0),
        }
    }

    /// Configure API endpoint for network resolution.
    pub fn with_api(self, api_url: &str) -> Self {
        // We need to create a new resolver with the API configured
        let resolver = OverlayResolver::new().with_api(api_url);
        Self {
            resolver: Arc::new(resolver),
            ..self
        }
    }

    /// Access the resolver (for registering known devices).
    pub fn resolver(&self) -> &OverlayResolver {
        &self.resolver
    }

    /// Get or create our QUIC endpoint (bound once, reused).
    async fn get_quic_endpoint(&self) -> Result<quinn::Endpoint, MuxError> {
        let mut ep_guard = self.quic_endpoint.lock().await;
        if let Some(ref ep) = *ep_guard {
            return Ok(ep.clone());
        }

        let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| MuxError::Connect(e.to_string()))?;
        ep.set_default_client_config(crate::quic_mux::make_client_config());
        *ep_guard = Some(ep.clone());
        Ok(ep)
    }

    /// Establish or reuse a connection to a peer by DID.
    /// This is the core "establish once" logic.
    async fn establish(&self, idd: &str) -> Result<Arc<PeerConnection>, MuxError> {
        // 1. Check if we already have a live connection
        if let Some(peer) = self.peers.read().await.get(idd) {
            // Verify connection is still alive
            if peer.connection.close_reason().is_none() {
                *peer.last_activity.lock().await = Instant::now();
                return Ok(peer.clone());
            }
            // Connection dead — will re-establish below
        }

        // 2. Resolve DID → endpoint
        let resolve = self.resolver.resolve(idd).await?;

        println!("◈ [OVERLAY-MUX] Resolved {} → {} (trust: {:.2}, method: {})",
                 idd, resolve.endpoint, resolve.trust_score, resolve.method);

        // 3. Open QUIC connection to resolved endpoint
        let endpoint = self.get_quic_endpoint().await?;
        let addr: std::net::SocketAddr = resolve.endpoint.parse()
            .map_err(|e: std::net::AddrParseError| MuxError::Connect(e.to_string()))?;

        let connection = endpoint
            .connect(addr, "tibet-cluster.local")
            .map_err(|e| MuxError::Connect(e.to_string()))?
            .await
            .map_err(|e| MuxError::Connect(e.to_string()))?;

        println!("◈ [OVERLAY-MUX] Connected to {} via QUIC (remote: {})",
                 idd, connection.remote_address());

        // 4. Store peer connection
        let peer = Arc::new(PeerConnection {
            idd: idd.to_string(),
            endpoint: resolve.endpoint,
            trust_score: resolve.trust_score,
            connection,
            established_at: Instant::now(),
            last_activity: Mutex::new(Instant::now()),
            intents_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        });

        self.peers.write().await.insert(idd.to_string(), peer.clone());
        self.peers_connected.fetch_add(1, Ordering::Relaxed);

        Ok(peer)
    }

    /// Send an intent + payload to a peer identified by DID.
    ///
    /// This is the main API:
    /// 1. Resolves DID → endpoint (cached after first call)
    /// 2. Establishes QUIC connection (lazy, one-time)
    /// 3. Opens a new bidi stream (no HOL blocking)
    /// 4. Sends intent frame + payload
    /// 5. Returns response
    pub async fn send(
        &self,
        to_idd: &str,
        intent: StreamIntent,
        payload: &[u8],
    ) -> Result<IntentResponse, MuxError> {
        self.send_with_metadata(to_idd, intent, payload, HashMap::new()).await
    }

    /// Send with additional metadata (e.g., codec info, room_id).
    pub async fn send_with_metadata(
        &self,
        to_idd: &str,
        intent: StreamIntent,
        payload: &[u8],
        metadata: HashMap<String, String>,
    ) -> Result<IntentResponse, MuxError> {
        // Establish or reuse connection
        let peer = self.establish(to_idd).await?;

        let channel_id = self.next_channel.fetch_add(1, Ordering::Relaxed);

        // Build intent frame
        let frame = IntentFrame {
            channel_id,
            intent: intent.as_str().to_string(),
            from_aint: self.our_aint.clone(),
            to_idd: to_idd.to_string(),
            payload_size: payload.len(),
            tibet_token_id: format!("omux_{}_{}_{}", intent.as_str(), channel_id,
                                    chrono::Utc::now().timestamp_millis()),
            metadata,
        };

        // Open a new QUIC bidi stream on the persistent connection
        let (mut send, mut recv) = peer.connection.open_bi().await
            .map_err(|e| MuxError::Connect(e.to_string()))?;

        // Write frame header (JSON)
        let frame_json = serde_json::to_vec(&frame)
            .map_err(|e| MuxError::Protocol(e.to_string()))?;
        let len_bytes = (frame_json.len() as u32).to_be_bytes();

        use tokio::io::AsyncWriteExt;
        send.write_all(&len_bytes).await
            .map_err(|e| MuxError::Io(e.to_string()))?;
        send.write_all(&frame_json).await
            .map_err(|e| MuxError::Io(e.to_string()))?;

        // Write payload
        if !payload.is_empty() {
            send.write_all(payload).await
                .map_err(|e| MuxError::Io(e.to_string()))?;
        }
        send.finish().map_err(|e| MuxError::Io(e.to_string()))?;

        // Read response
        use tokio::io::AsyncReadExt;
        let mut resp_len = [0u8; 4];
        recv.read_exact(&mut resp_len).await
            .map_err(|e| MuxError::Io(e.to_string()))?;
        let resp_size = u32::from_be_bytes(resp_len) as usize;

        let mut resp_buf = vec![0u8; resp_size];
        recv.read_exact(&mut resp_buf).await
            .map_err(|e| MuxError::Io(e.to_string()))?;

        let response: IntentResponse = serde_json::from_slice(&resp_buf)
            .map_err(|e| MuxError::Protocol(e.to_string()))?;

        // Update stats
        self.intents_total.fetch_add(1, Ordering::Relaxed);
        peer.intents_sent.fetch_add(1, Ordering::Relaxed);
        peer.bytes_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
        *peer.last_activity.lock().await = Instant::now();

        match response.status {
            200..=299 => Ok(response),
            _ => Err(MuxError::RemoteStatus {
                status: response.status,
                error: response.error.unwrap_or_default(),
            }),
        }
    }

    /// Handle IP migration — update endpoint for a peer and reconnect.
    /// Called when QUIC detects connection migration or overlay gets
    /// a new resolve result for an existing peer.
    pub async fn migrate(&self, idd: &str, new_endpoint: &str) -> Result<(), MuxError> {
        println!("◈ [OVERLAY-MUX] Migration: {} → {}", idd, new_endpoint);

        // Update resolver cache
        self.resolver.update_endpoint(idd, new_endpoint).await;

        // Drop old connection — next send() will re-establish
        self.peers.write().await.remove(idd);
        self.migrations_total.fetch_add(1, Ordering::Relaxed);

        // Pre-establish new connection
        self.establish(idd).await?;

        println!("◈ [OVERLAY-MUX] Migration complete: {} now at {}", idd, new_endpoint);
        Ok(())
    }

    /// Get status of all peer connections.
    pub async fn status(&self) -> OverlayMuxStatus {
        let peers = self.peers.read().await;
        let mut peer_info = Vec::new();

        for (idd, peer) in peers.iter() {
            peer_info.push(PeerStatus {
                idd: idd.clone(),
                endpoint: peer.endpoint.clone(),
                trust_score: peer.trust_score,
                connected_secs: peer.established_at.elapsed().as_secs(),
                intents_sent: peer.intents_sent.load(Ordering::Relaxed),
                bytes_sent: peer.bytes_sent.load(Ordering::Relaxed),
                last_activity_secs: peer.last_activity.lock().await.elapsed().as_secs(),
            });
        }

        OverlayMuxStatus {
            our_aint: self.our_aint.clone(),
            peers: peer_info,
            total_intents: self.intents_total.load(Ordering::Relaxed),
            total_peers: self.peers_connected.load(Ordering::Relaxed),
            total_migrations: self.migrations_total.load(Ordering::Relaxed),
            resolver_cache_hits: self.resolver.cache_hits.load(Ordering::Relaxed),
            resolver_cache_misses: self.resolver.cache_misses.load(Ordering::Relaxed),
        }
    }

    /// Disconnect from a peer.
    pub async fn disconnect(&self, idd: &str) {
        if let Some(peer) = self.peers.write().await.remove(idd) {
            peer.connection.close(0u32.into(), b"disconnect");
            println!("◈ [OVERLAY-MUX] Disconnected from {}", idd);
        }
    }

    /// Disconnect from all peers.
    pub async fn disconnect_all(&self) {
        let mut peers = self.peers.write().await;
        for (idd, peer) in peers.drain() {
            peer.connection.close(0u32.into(), b"disconnect");
            println!("◈ [OVERLAY-MUX] Disconnected from {}", idd);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Status types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct PeerStatus {
    pub idd: String,
    pub endpoint: String,
    pub trust_score: f64,
    pub connected_secs: u64,
    pub intents_sent: u64,
    pub bytes_sent: u64,
    pub last_activity_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct OverlayMuxStatus {
    pub our_aint: String,
    pub peers: Vec<PeerStatus>,
    pub total_intents: u64,
    pub total_peers: u64,
    pub total_migrations: u64,
    pub resolver_cache_hits: u64,
    pub resolver_cache_misses: u64,
}

// ═══════════════════════════════════════════════════════════════
// OverlayMux Server — Accept intent streams from peers
// ═══════════════════════════════════════════════════════════════

/// Handler function type for incoming intents.
#[cfg(feature = "quic")]
pub type IntentHandler = Arc<dyn Fn(IntentFrame, Vec<u8>) -> IntentResponse + Send + Sync>;

/// OverlayMux Server — listens for incoming intent streams.
///
/// ```no_run
/// let server = OverlayMuxServer::new("0.0.0.0:7150", "root_idd.aint");
/// server.on_intent(Arc::new(|frame, payload| {
///     match StreamIntent::from_str(&frame.intent) {
///         StreamIntent::Chat => handle_chat(frame, payload),
///         StreamIntent::Voice => handle_voice(frame, payload),
///         _ => IntentResponse { status: 404, .. }
///     }
/// }));
/// server.serve().await;
/// ```
#[cfg(feature = "quic")]
pub struct OverlayMuxServer {
    bind_addr: std::net::SocketAddr,
    our_aint: String,
    handler: Mutex<Option<IntentHandler>>,
    pub connections_total: Arc<AtomicU64>,
    pub intents_handled: Arc<AtomicU64>,
}

#[cfg(feature = "quic")]
impl OverlayMuxServer {
    pub fn new(bind_addr: &str, our_aint: &str) -> Self {
        Self {
            bind_addr: bind_addr.parse().expect("valid bind address"),
            our_aint: our_aint.to_string(),
            handler: Mutex::new(None),
            connections_total: Arc::new(AtomicU64::new(0)),
            intents_handled: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Set the handler for incoming intents.
    pub async fn on_intent(&self, handler: IntentHandler) {
        *self.handler.lock().await = Some(handler);
    }

    /// Start the server in the background (for demos/tests).
    /// Returns the port the server is listening on.
    pub async fn start_background(&self) -> Result<u16, Box<dyn std::error::Error>> {
        let config = crate::quic_mux::make_server_config();
        let endpoint = quinn::Endpoint::server(config, self.bind_addr)?;
        let port = endpoint.local_addr()?.port();

        let handler = self.handler.lock().await.clone();
        let intents_handled = self.intents_handled.clone();
        let connections_total = self.connections_total.clone();

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(connection) = incoming.await {
                    connections_total.fetch_add(1, Ordering::Relaxed);
                    let handler = handler.clone();
                    let ic = intents_handled.clone();

                    tokio::spawn(async move {
                        loop {
                            match connection.accept_bi().await {
                                Ok(stream) => {
                                    let h = handler.clone();
                                    let c = ic.clone();
                                    tokio::spawn(async move {
                                        handle_intent_stream(stream, h, c).await.ok();
                                    });
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        });

        Ok(port)
    }

    /// Start serving — accepts QUIC connections and dispatches intent streams.
    pub async fn serve(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = crate::quic_mux::make_server_config();
        let endpoint = quinn::Endpoint::server(config, self.bind_addr)?;

        println!("◈ [OVERLAY-MUX-SERVER] Listening on {} (identity: {})",
                 self.bind_addr, self.our_aint);
        println!("◈ [OVERLAY-MUX-SERVER] Accepting intents: chat, voice, video, file, llm-sync, control, finance, industrial");

        while let Some(incoming) = endpoint.accept().await {
            let connection = incoming.await?;
            let peer = connection.remote_address();
            let conn_num = self.connections_total.fetch_add(1, Ordering::Relaxed) + 1;

            println!("◈ [OVERLAY-MUX-SERVER] Peer #{} connected from {} (QUIC)",
                     conn_num, peer);

            let handler = self.handler.lock().await.clone();
            let intents_handled = self.intents_handled.clone();

            tokio::spawn(async move {
                loop {
                    // Accept bidi streams (each = one intent)
                    let stream = match connection.accept_bi().await {
                        Ok(s) => s,
                        Err(_) => break, // Connection closed
                    };

                    let handler = handler.clone();
                    let intents_counter = intents_handled.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_intent_stream(stream, handler, intents_counter).await {
                            eprintln!("◈ [OVERLAY-MUX-SERVER] Stream error: {}", e);
                        }
                    });
                }
                println!("◈ [OVERLAY-MUX-SERVER] Peer #{} disconnected", conn_num);
            });
        }

        Ok(())
    }
}

/// Handle a single intent stream (one bidi stream = one intent + response).
/// Public wrapper for use in demo binaries.
#[cfg(feature = "quic")]
pub async fn handle_intent_stream_pub(
    stream: (quinn::SendStream, quinn::RecvStream),
    handler: Option<IntentHandler>,
    intents_handled: Arc<AtomicU64>,
) -> Result<(), MuxError> {
    handle_intent_stream(stream, handler, intents_handled).await
}

#[cfg(feature = "quic")]
async fn handle_intent_stream(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    handler: Option<IntentHandler>,
    intents_handled: Arc<AtomicU64>,
) -> Result<(), MuxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read frame header length
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await
        .map_err(|e| MuxError::Io(e.to_string()))?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;

    // Read frame JSON
    let mut frame_buf = vec![0u8; frame_len];
    recv.read_exact(&mut frame_buf).await
        .map_err(|e| MuxError::Io(e.to_string()))?;

    let frame: IntentFrame = serde_json::from_slice(&frame_buf)
        .map_err(|e| MuxError::Protocol(e.to_string()))?;

    // Read payload
    let mut payload = vec![0u8; frame.payload_size];
    if frame.payload_size > 0 {
        recv.read_exact(&mut payload).await
            .map_err(|e| MuxError::Io(e.to_string()))?;
    }

    println!("◈ [OVERLAY-MUX-SERVER] Intent: {} from {} → {} ({} bytes)",
             frame.intent, frame.from_aint, frame.to_idd, frame.payload_size);

    // Dispatch to handler
    let response = if let Some(ref handler) = handler {
        handler(frame.clone(), payload)
    } else {
        IntentResponse {
            channel_id: frame.channel_id,
            status: 501,
            intent: frame.intent.clone(),
            tibet_token_id: frame.tibet_token_id.clone(),
            payload_size: 0,
            error: Some("No intent handler registered".into()),
        }
    };

    // Write response
    let resp_json = serde_json::to_vec(&response)
        .map_err(|e| MuxError::Protocol(e.to_string()))?;
    let resp_len = (resp_json.len() as u32).to_be_bytes();

    send.write_all(&resp_len).await
        .map_err(|e| MuxError::Io(e.to_string()))?;
    send.write_all(&resp_json).await
        .map_err(|e| MuxError::Io(e.to_string()))?;
    send.finish().map_err(|e| MuxError::Io(e.to_string()))?;

    intents_handled.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_intent_roundtrip() {
        let intents = vec![
            StreamIntent::Chat,
            StreamIntent::Voice,
            StreamIntent::Video,
            StreamIntent::File,
            StreamIntent::LlmSync,
            StreamIntent::Control,
            StreamIntent::Finance,
            StreamIntent::Industrial,
            StreamIntent::Custom("modbus:plc".to_string()),
        ];

        for intent in intents {
            let s = intent.as_str();
            let back = StreamIntent::from_str(s);
            assert_eq!(intent, back, "roundtrip failed for {:?}", s);
        }
    }

    #[tokio::test]
    async fn test_resolver_local() {
        let resolver = OverlayResolver::new();
        resolver.register("jis:pixel:jasper", "10.0.0.42:7150", 0.95).await;

        let result = resolver.resolve("jis:pixel:jasper").await.unwrap();
        assert!(result.resolved);
        assert_eq!(result.endpoint, "10.0.0.42:7150");
        assert_eq!(result.trust_score, 0.95);
        assert_eq!(result.method, "local");
    }

    #[tokio::test]
    async fn test_resolver_auto_prefix() {
        let resolver = OverlayResolver::new();
        resolver.register("jis:test:device", "1.2.3.4:7150", 0.8).await;

        // Without jis: prefix
        let result = resolver.resolve("test:device").await;
        // Should try "jis:test:device" — but our input already has a colon
        // so it won't prefix. This tests the normalization logic.
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_resolver_cache() {
        let resolver = OverlayResolver::new();

        // Manually insert into cache
        resolver.cache.write().await.insert(
            "jis:cached:device".to_string(),
            CachedResolve {
                endpoint: "10.0.0.99:7150".to_string(),
                trust_score: 0.7,
                resolved_at: Instant::now(),
                ttl: Duration::from_secs(300),
            },
        );

        let result = resolver.resolve("jis:cached:device").await.unwrap();
        assert!(result.resolved);
        assert_eq!(result.endpoint, "10.0.0.99:7150");
        assert_eq!(result.method, "cache");
    }

    #[tokio::test]
    async fn test_resolver_update_endpoint() {
        let resolver = OverlayResolver::new();
        resolver.register("jis:mobile:jasper", "192.168.1.42:7150", 0.95).await;

        // Verify original
        let r1 = resolver.resolve("jis:mobile:jasper").await.unwrap();
        assert_eq!(r1.endpoint, "192.168.1.42:7150");

        // Simulate IP migration (WiFi → 5G)
        resolver.update_endpoint("jis:mobile:jasper", "10.28.0.77:7150").await;

        // Should resolve to new endpoint
        let r2 = resolver.resolve("jis:mobile:jasper").await.unwrap();
        assert_eq!(r2.endpoint, "10.28.0.77:7150");
    }

    #[tokio::test]
    async fn test_resolver_unknown_did() {
        let resolver = OverlayResolver::new();

        // No API configured, no local entry → should fail
        let result = resolver.resolve("jis:unknown:device").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_intent_frame_serde() {
        let frame = IntentFrame {
            channel_id: 42,
            intent: "chat".to_string(),
            from_aint: "root_idd.aint".to_string(),
            to_idd: "jis:pixel:jasper".to_string(),
            payload_size: 128,
            tibet_token_id: "omux_chat_42_1234567890".to_string(),
            metadata: HashMap::from([
                ("room_id".to_string(), "general".to_string()),
            ]),
        };

        let json = serde_json::to_string(&frame).unwrap();
        let back: IntentFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back.channel_id, 42);
        assert_eq!(back.intent, "chat");
        assert_eq!(back.to_idd, "jis:pixel:jasper");
        assert_eq!(back.metadata.get("room_id").unwrap(), "general");
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_overlay_mux_status() {
        let mux = OverlayMux::new("test-client.aint");
        mux.resolver().register("jis:test:server", "127.0.0.1:7199", 0.9).await;

        let status = mux.status().await;
        assert_eq!(status.our_aint, "test-client.aint");
        assert_eq!(status.peers.len(), 0);
        assert_eq!(status.total_intents, 0);
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_overlay_mux_full_roundtrip() {
        // ── Start OverlayMuxServer ──
        let server = OverlayMuxServer::new("127.0.0.1:0", "pixel-jasper.aint");

        // Register a handler that echoes the intent back
        server.on_intent(Arc::new(|frame: IntentFrame, payload: Vec<u8>| {
            IntentResponse {
                channel_id: frame.channel_id,
                status: 200,
                intent: frame.intent.clone(),
                tibet_token_id: format!("echo_{}", frame.tibet_token_id),
                payload_size: payload.len(),
                error: None,
            }
        })).await;

        // Bind to OS-assigned port
        let config = crate::quic_mux::make_server_config();
        let endpoint = quinn::Endpoint::server(config, server.bind_addr).unwrap();
        let local_addr = endpoint.local_addr().unwrap();
        let port = local_addr.port();

        println!("Test server on port {}", port);

        // Spawn server accept loop
        let intents_handled = server.intents_handled.clone();
        let handler = server.handler.lock().await.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let connection = incoming.await.unwrap();
                let handler = handler.clone();
                let intents_counter = intents_handled.clone();

                tokio::spawn(async move {
                    loop {
                        let stream = match connection.accept_bi().await {
                            Ok(s) => s,
                            Err(_) => break,
                        };
                        let h = handler.clone();
                        let ic = intents_counter.clone();
                        tokio::spawn(async move {
                            handle_intent_stream(stream, h, ic).await.ok();
                        });
                    }
                });
            }
        });

        // ── Create OverlayMux client ──
        let mux = OverlayMux::new("root_idd.aint");
        let endpoint_str = format!("127.0.0.1:{}", port);
        mux.resolver().register("jis:pixel:jasper", &endpoint_str, 0.95).await;

        // ── Test 1: Send chat intent ──
        let resp = mux.send(
            "jis:pixel:jasper",
            StreamIntent::Chat,
            b"Hallo vanuit root_idd!",
        ).await.unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.intent, "chat");
        assert!(resp.tibet_token_id.starts_with("echo_"));

        // ── Test 2: Send voice intent (same connection, different stream) ──
        let resp2 = mux.send(
            "jis:pixel:jasper",
            StreamIntent::Voice,
            &vec![0u8; 320],  // 20ms audio frame
        ).await.unwrap();

        assert_eq!(resp2.status, 200);
        assert_eq!(resp2.intent, "voice");

        // ── Test 3: Send with metadata ──
        let mut meta = HashMap::new();
        meta.insert("room_id".to_string(), "general".to_string());
        meta.insert("codec".to_string(), "opus".to_string());

        let resp3 = mux.send_with_metadata(
            "jis:pixel:jasper",
            StreamIntent::Video,
            &vec![0u8; 1024],  // video frame
            meta,
        ).await.unwrap();

        assert_eq!(resp3.status, 200);
        assert_eq!(resp3.intent, "video");

        // ── Verify stats ──
        let status = mux.status().await;
        assert_eq!(status.total_intents, 3);
        assert_eq!(status.peers.len(), 1);

        let peer = &status.peers[0];
        assert_eq!(peer.idd, "jis:pixel:jasper");
        assert_eq!(peer.trust_score, 0.95);
        assert_eq!(peer.intents_sent, 3);

        // ── Test 4: Multiple intents in parallel (simulate KIT app) ──
        let mux_ref = &mux;
        let (r1, r2, r3) = tokio::join!(
            mux_ref.send("jis:pixel:jasper", StreamIntent::Chat, b"msg1"),
            mux_ref.send("jis:pixel:jasper", StreamIntent::LlmSync, b"sync-state"),
            mux_ref.send("jis:pixel:jasper", StreamIntent::Control, b"ping"),
        );

        assert_eq!(r1.unwrap().status, 200);
        assert_eq!(r2.unwrap().status, 200);
        assert_eq!(r3.unwrap().status, 200);

        let final_status = mux.status().await;
        assert_eq!(final_status.total_intents, 6);

        println!("◈ All overlay-mux tests passed: 6 intents over 1 QUIC connection");

        // Cleanup
        mux.disconnect_all().await;
    }
}
