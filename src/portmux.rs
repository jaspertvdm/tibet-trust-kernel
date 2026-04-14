use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::bus::VirtualBus;
use crate::config::TrustKernelConfig;
use crate::mux::TibetMuxFrame;
use crate::tibet_token::TibetProvenance;
use crate::voorproever::{Voorproever, VoorproeverVerdict};
use crate::archivaris::{Archivaris, ArchivarisResult};
use crate::watchdog::Watchdog;

/// Port-to-intent mapping.
/// Every known port maps to a service category + default intent.
/// Unknown ports get "unknown:raw" intent — which the Voorproever will REJECT.
#[derive(Debug, Clone)]
pub struct PortIntent {
    pub port: u16,
    pub service: &'static str,
    pub default_intent: &'static str,
    /// Whether this port requires TIBET-envelope framing (native)
    /// or gets raw traffic that needs intent inference (wrapped)
    pub mode: PortMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortMode {
    /// Native TIBET-MUX protocol (JSON frames) — e.g., port 4430
    Native,
    /// Raw protocol — Trust Kernel infers intent from traffic patterns
    Wrapped,
}

/// Build the default port→intent mapping.
pub fn default_port_map() -> HashMap<u16, PortIntent> {
    let entries = vec![
        // ─── Native TIBET ports ───
        PortIntent { port: 4430, service: "tibet-mux",  default_intent: "mux:native",      mode: PortMode::Native },

        // ─── Wrapped service ports ───
        PortIntent { port: 22,   service: "ssh",        default_intent: "shell:command",    mode: PortMode::Wrapped },
        PortIntent { port: 80,   service: "http",       default_intent: "http:request",     mode: PortMode::Wrapped },
        PortIntent { port: 443,  service: "https",      default_intent: "http:request",     mode: PortMode::Wrapped },
        PortIntent { port: 5432, service: "postgresql",  default_intent: "db:query",         mode: PortMode::Wrapped },
        PortIntent { port: 3306, service: "mysql",       default_intent: "db:query",         mode: PortMode::Wrapped },
        PortIntent { port: 6379, service: "redis",       default_intent: "db:query",         mode: PortMode::Wrapped },
        PortIntent { port: 27017,service: "mongodb",     default_intent: "db:query",         mode: PortMode::Wrapped },
        PortIntent { port: 8080, service: "http-alt",    default_intent: "http:request",     mode: PortMode::Wrapped },
        PortIntent { port: 8443, service: "https-alt",   default_intent: "http:request",     mode: PortMode::Wrapped },
        PortIntent { port: 25,   service: "smtp",        default_intent: "mail:send",        mode: PortMode::Wrapped },
        PortIntent { port: 53,   service: "dns",         default_intent: "dns:resolve",      mode: PortMode::Wrapped },
        PortIntent { port: 11434,service: "ollama",      default_intent: "ai:inference",     mode: PortMode::Wrapped },
        PortIntent { port: 5000, service: "api",         default_intent: "http:request",     mode: PortMode::Wrapped },
        PortIntent { port: 8000, service: "api",         default_intent: "http:request",     mode: PortMode::Wrapped },
        PortIntent { port: 3000, service: "app",         default_intent: "http:request",     mode: PortMode::Wrapped },
        PortIntent { port: 9090, service: "prometheus",  default_intent: "metrics:scrape",   mode: PortMode::Wrapped },
        PortIntent { port: 2222, service: "ssh-alt",     default_intent: "shell:command",    mode: PortMode::Wrapped },
    ];

    entries.into_iter().map(|e| (e.port, e)).collect()
}

/// Infer intent from raw traffic bytes.
/// This is the core of wrapped-mode: we peek at the first bytes
/// to determine what the client is trying to do.
pub fn infer_intent(port: u16, first_bytes: &[u8], port_map: &HashMap<u16, PortIntent>) -> InferredIntent {
    let default_intent = port_map
        .get(&port)
        .map(|p| p.default_intent)
        .unwrap_or("unknown:raw");

    let service = port_map
        .get(&port)
        .map(|p| p.service)
        .unwrap_or("unknown");

    // ─── SSH protocol detection ───
    if first_bytes.starts_with(b"SSH-") {
        // SSH version string: "SSH-2.0-OpenSSH_9.2p1"
        let version_str = String::from_utf8_lossy(&first_bytes[..first_bytes.len().min(256)]);
        return InferredIntent {
            intent: "shell:session".to_string(),
            service: service.to_string(),
            protocol_version: extract_until_newline(&version_str),
            client_id: extract_ssh_client(&version_str),
            payload_preview: version_str[..version_str.len().min(128)].to_string(),
            confidence: 0.95,
        };
    }

    // ─── HTTP protocol detection ───
    if first_bytes.starts_with(b"GET ")
        || first_bytes.starts_with(b"POST ")
        || first_bytes.starts_with(b"PUT ")
        || first_bytes.starts_with(b"DELETE ")
        || first_bytes.starts_with(b"PATCH ")
        || first_bytes.starts_with(b"HEAD ")
        || first_bytes.starts_with(b"OPTIONS ")
    {
        let request = String::from_utf8_lossy(&first_bytes[..first_bytes.len().min(2048)]);
        let method = request.split_whitespace().next().unwrap_or("?");
        let path = request.split_whitespace().nth(1).unwrap_or("/");

        // Refine intent based on HTTP path patterns
        let intent = match path {
            p if p.starts_with("/api/") => format!("http:api:{}", method.to_lowercase()),
            p if p.starts_with("/admin") => format!("http:admin:{}", method.to_lowercase()),
            p if p.contains("login") || p.contains("auth") => "http:auth".to_string(),
            p if p.contains("upload") => "http:upload".to_string(),
            p if p.contains("webhook") => "http:webhook".to_string(),
            _ => format!("http:{}:{}", method.to_lowercase(), categorize_path(path)),
        };

        return InferredIntent {
            intent,
            service: service.to_string(),
            protocol_version: extract_http_version(&request),
            client_id: extract_user_agent(&request),
            payload_preview: request[..request.len().min(256)].to_string(),
            confidence: 0.90,
        };
    }

    // ─── TLS ClientHello detection ───
    if first_bytes.len() >= 6
        && first_bytes[0] == 0x16  // Handshake
        && first_bytes[1] == 0x03  // TLS version major
        && first_bytes[5] == 0x01  // ClientHello
    {
        let sni = extract_tls_sni(first_bytes);
        return InferredIntent {
            intent: "tls:handshake".to_string(),
            service: service.to_string(),
            protocol_version: format!("TLS 1.{}", first_bytes[2]),
            client_id: sni.unwrap_or_else(|| "unknown".to_string()),
            payload_preview: format!("[TLS ClientHello, {} bytes]", first_bytes.len()),
            confidence: 0.85,
        };
    }

    // ─── PostgreSQL startup detection ───
    if first_bytes.len() >= 8 {
        let len = u32::from_be_bytes([first_bytes[0], first_bytes[1], first_bytes[2], first_bytes[3]]);
        let version = u32::from_be_bytes([first_bytes[4], first_bytes[5], first_bytes[6], first_bytes[7]]);
        // PostgreSQL protocol version 3.0 = 196608
        if version == 196608 && len > 8 && len < 1024 {
            let startup = String::from_utf8_lossy(&first_bytes[8..first_bytes.len().min(256)]);
            return InferredIntent {
                intent: "db:connect".to_string(),
                service: "postgresql".to_string(),
                protocol_version: "3.0".to_string(),
                client_id: extract_pg_user(&startup),
                payload_preview: format!("[PG startup, user={}]", extract_pg_user(&startup)),
                confidence: 0.90,
            };
        }
    }

    // ─── Redis RESP detection ───
    if first_bytes.starts_with(b"*") || first_bytes.starts_with(b"PING")
        || first_bytes.starts_with(b"AUTH") || first_bytes.starts_with(b"INFO")
    {
        let cmd = String::from_utf8_lossy(&first_bytes[..first_bytes.len().min(128)]);
        return InferredIntent {
            intent: "db:redis:command".to_string(),
            service: "redis".to_string(),
            protocol_version: "RESP".to_string(),
            client_id: String::new(),
            payload_preview: cmd[..cmd.len().min(64)].to_string(),
            confidence: 0.80,
        };
    }

    // ─── MySQL handshake detection ───
    if first_bytes.len() >= 5 && first_bytes[4] == 0x0a {
        // MySQL server greeting starts with protocol version 10 (0x0a)
        return InferredIntent {
            intent: "db:connect".to_string(),
            service: "mysql".to_string(),
            protocol_version: "10".to_string(),
            client_id: String::new(),
            payload_preview: format!("[MySQL handshake, {} bytes]", first_bytes.len()),
            confidence: 0.75,
        };
    }

    // ─── DNS detection (UDP-style over TCP) ───
    if port == 53 && first_bytes.len() >= 12 {
        let qr = (first_bytes[2] >> 7) & 1;
        if qr == 0 {
            return InferredIntent {
                intent: "dns:query".to_string(),
                service: "dns".to_string(),
                protocol_version: "DNS".to_string(),
                client_id: String::new(),
                payload_preview: format!("[DNS query, {} bytes]", first_bytes.len()),
                confidence: 0.85,
            };
        }
    }

    // ─── Fallback: unknown protocol ───
    InferredIntent {
        intent: default_intent.to_string(),
        service: service.to_string(),
        protocol_version: String::new(),
        client_id: String::new(),
        payload_preview: format!("[raw bytes, {} len, head=0x{:02x?}]",
            first_bytes.len(),
            &first_bytes[..first_bytes.len().min(8)]),
        confidence: 0.30,
    }
}

#[derive(Debug, Clone)]
pub struct InferredIntent {
    pub intent: String,
    pub service: String,
    pub protocol_version: String,
    pub client_id: String,
    pub payload_preview: String,
    /// How confident we are in this classification (0.0 - 1.0)
    pub confidence: f64,
}

/// PortMux: the transparent proxy that wraps all ports with Trust Kernel.
pub struct PortMux {
    port_map: HashMap<u16, PortIntent>,
    config: Arc<TrustKernelConfig>,
    bus: Arc<VirtualBus>,
    watchdog: Arc<Watchdog>,
}

impl PortMux {
    pub fn new(
        config: Arc<TrustKernelConfig>,
        bus: Arc<VirtualBus>,
        watchdog: Arc<Watchdog>,
    ) -> Self {
        Self {
            port_map: default_port_map(),
            config,
            bus,
            watchdog,
        }
    }

    /// Start listening on a wrapped port.
    /// Traffic is intercepted, intent is inferred, Trust Kernel evaluates,
    /// and only PASS traffic is forwarded to the real backend.
    pub async fn wrap_port(
        &self,
        listen_port: u16,
        backend_addr: &str,
    ) -> std::io::Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", listen_port)).await?;
        let port_map = self.port_map.clone();
        let config = self.config.clone();
        let bus = self.bus.clone();
        let watchdog = self.watchdog.clone();
        let backend = backend_addr.to_string();

        println!("◈ [PortMux] Wrapping port {} → backend {} (service: {})",
            listen_port, backend_addr,
            port_map.get(&listen_port).map(|p| p.service).unwrap_or("unknown"));

        tokio::spawn(async move {
            loop {
                let (mut client, addr) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("◈ [PortMux:{}] Accept error: {}", listen_port, e);
                        continue;
                    }
                };

                let port_map = port_map.clone();
                let config = config.clone();
                let bus = bus.clone();
                let watchdog = watchdog.clone();
                let backend = backend.clone();

                tokio::spawn(async move {
                    // 1. Peek at first bytes (non-destructive)
                    let mut peek_buf = vec![0u8; 4096];
                    let n = match client.read(&mut peek_buf).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let first_bytes = &peek_buf[..n];

                    // 2. Infer intent from raw traffic
                    let inferred = infer_intent(listen_port, first_bytes, &port_map);

                    println!("◈ [PortMux:{}] {} from {} — intent='{}' confidence={:.0}% client='{}'",
                        listen_port, inferred.service, addr,
                        inferred.intent, inferred.confidence * 100.0, inferred.client_id);

                    // 3. Build a TibetMuxFrame from inferred intent
                    let frame = TibetMuxFrame {
                        channel_id: listen_port as u32,
                        intent: inferred.intent.clone(),
                        from_aint: format!("{}@{}", inferred.client_id, addr.ip()),
                        payload: inferred.payload_preview.clone(),
                    };

                    // 4. Run Trust Kernel pipeline
                    let voorproever = Voorproever::new(
                        (*config).clone(),
                        bus.clone(),
                        watchdog.clone(),
                    );

                    let verdict = voorproever.evaluate(&frame);

                    match verdict {
                        VoorproeverVerdict::Reject { reason } => {
                            println!("◈ [PortMux:{}] REJECT: {} — connection dropped", listen_port, reason);
                            // Drop connection silently — attacker gets nothing
                            let _ = client.shutdown().await;
                            return;
                        }
                        VoorproeverVerdict::Kill { reason, violations, .. } => {
                            println!("◈ [PortMux:{}] KILL: {} ({} violations)", listen_port, reason, violations.len());
                            for v in &violations {
                                println!("◈ [PortMux:{}]   ✗ {}", listen_port, v);
                            }
                            // Generate incident token
                            let _token = TibetProvenance::generate_rejected(&frame, &reason);
                            let _ = client.shutdown().await;
                            return;
                        }
                        VoorproeverVerdict::Pass { bus_payload, evaluation_us, .. } => {
                            println!("◈ [PortMux:{}] PASS in {:.1}µs — forwarding to backend",
                                listen_port, evaluation_us);

                            // 5. Run through Archivaris (Kernel B)
                            let mut archivaris = Archivaris::new((*config).clone(), bus.clone());
                            let _result = archivaris.process(&bus_payload, &frame);

                            // 6. Forward to real backend
                            match TcpStream::connect(&backend).await {
                                Ok(mut backend_stream) => {
                                    // Send the original bytes to backend
                                    if let Err(e) = backend_stream.write_all(first_bytes).await {
                                        eprintln!("◈ [PortMux:{}] Backend write error: {}", listen_port, e);
                                        return;
                                    }

                                    // Bidirectional proxy
                                    let (mut client_read, mut client_write) = client.into_split();
                                    let (mut backend_read, mut backend_write) = backend_stream.into_split();

                                    let c2b = tokio::spawn(async move {
                                        let _ = tokio::io::copy(&mut client_read, &mut backend_write).await;
                                    });
                                    let b2c = tokio::spawn(async move {
                                        let _ = tokio::io::copy(&mut backend_read, &mut client_write).await;
                                    });

                                    let _ = tokio::join!(c2b, b2c);
                                }
                                Err(e) => {
                                    eprintln!("◈ [PortMux:{}] Backend connect error: {}", listen_port, e);
                                }
                            }
                        }
                    }
                });
            }
        });

        Ok(())
    }

    /// Wrap multiple ports at once.
    pub async fn wrap_ports(&self, mappings: &[(u16, &str)]) -> std::io::Result<()> {
        for (port, backend) in mappings {
            self.wrap_port(*port, backend).await?;
        }
        Ok(())
    }

    pub fn port_map(&self) -> &HashMap<u16, PortIntent> {
        &self.port_map
    }
}

// ─── Helper functions for protocol parsing ───

fn extract_until_newline(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

fn extract_ssh_client(version_str: &str) -> String {
    // "SSH-2.0-OpenSSH_9.2p1 Debian-2" → "OpenSSH_9.2p1"
    let parts: Vec<&str> = version_str.split('-').collect();
    if parts.len() >= 3 {
        parts[2].split_whitespace().next().unwrap_or("unknown").to_string()
    } else {
        "unknown".to_string()
    }
}

fn extract_http_version(request: &str) -> String {
    // "GET / HTTP/1.1\r\n..." → "HTTP/1.1"
    request.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(2))
        .unwrap_or("HTTP/?")
        .to_string()
}

fn extract_user_agent(request: &str) -> String {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("user-agent:") {
            return line[11..].trim().to_string();
        }
    }
    String::new()
}

fn extract_pg_user(startup: &str) -> String {
    // PostgreSQL startup message: null-terminated key-value pairs
    // "user\0postgres\0database\0mydb\0\0"
    let parts: Vec<&str> = startup.split('\0').collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "user" {
            if let Some(user) = parts.get(i + 1) {
                return user.to_string();
            }
        }
    }
    "unknown".to_string()
}

fn categorize_path(path: &str) -> &str {
    if path.ends_with(".js") || path.ends_with(".css") || path.ends_with(".png")
        || path.ends_with(".jpg") || path.ends_with(".svg") || path.ends_with(".woff2") {
        "static"
    } else if path.ends_with(".html") || path == "/" {
        "page"
    } else {
        "resource"
    }
}

fn extract_tls_sni(data: &[u8]) -> Option<String> {
    // Minimal TLS ClientHello SNI extraction
    // TLS record: [type:1][version:2][length:2][handshake...]
    // Handshake: [type:1][length:3][version:2][random:32][session_id_len:1][session_id:var]...
    // Then cipher suites, compression, extensions...
    // SNI is extension type 0x0000
    if data.len() < 43 { return None; }

    let mut pos = 5; // skip TLS record header
    if pos >= data.len() { return None; }
    pos += 1; // handshake type
    pos += 3; // handshake length
    pos += 2; // client version
    pos += 32; // random

    if pos >= data.len() { return None; }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > data.len() { return None; }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos + 1 > data.len() { return None; }
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > data.len() { return None; }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;

    while pos + 4 <= extensions_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 && ext_len > 5 && pos + ext_len <= data.len() {
            // SNI extension: [list_len:2][type:1][name_len:2][name:var]
            let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            if pos + 5 + name_len <= data.len() {
                return String::from_utf8(data[pos + 5..pos + 5 + name_len].to_vec()).ok();
            }
        }

        pos += ext_len;
    }

    None
}
