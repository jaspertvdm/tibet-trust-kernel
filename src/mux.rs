use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A frame on the TIBET-MUX channel.
/// Matches the tibet-mux Python protocol for interop.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TibetMuxFrame {
    pub channel_id: u32,
    pub intent: String,
    pub from_aint: String,
    pub payload: String,
}

/// Response envelope sent back over the MUX channel.
#[derive(Serialize, Debug)]
struct MuxResponse<'a> {
    channel_id: u32,
    status: u16,
    intent: &'a str,
    tibet_provenance: &'a serde_json::Value,
}

pub struct AirlockMuxListener {
    listener: TcpListener,
}

pub async fn start_mux_listener(addr: &str) -> std::io::Result<AirlockMuxListener> {
    let listener = TcpListener::bind(addr).await?;
    println!("◈ [MUX] Listening on {}", addr);
    Ok(AirlockMuxListener { listener })
}

impl AirlockMuxListener {
    pub async fn accept_frame(&mut self) -> std::io::Result<(TcpStream, TibetMuxFrame)> {
        let (mut socket, addr) = self.listener.accept().await?;
        println!("◈ [MUX] Connection from {}", addr);

        let mut buf = vec![0u8; 8192];
        let n = socket.read(&mut buf).await?;

        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed before sending frame",
            ));
        }

        match serde_json::from_slice::<TibetMuxFrame>(&buf[..n]) {
            Ok(frame) => {
                if frame.intent.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Frame missing intent field",
                    ));
                }
                Ok((socket, frame))
            }
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid MUX frame JSON: {}", e),
            )),
        }
    }
}

/// Send a structured response back over the MUX channel.
pub async fn send_response(socket: &mut TcpStream, frame: &TibetMuxFrame, token_json: &str, status: u16) {
    // Parse the token string back to Value for clean nesting
    let token_value: serde_json::Value = serde_json::from_str(token_json)
        .unwrap_or_else(|_| serde_json::Value::String(token_json.to_string()));

    let response = MuxResponse {
        channel_id: frame.channel_id,
        status,
        intent: &frame.intent,
        tibet_provenance: &token_value,
    };

    let response_bytes = serde_json::to_string_pretty(&response)
        .unwrap_or_else(|_| format!("{{\"error\":\"serialization failed\",\"status\":{}}}", status));

    if let Err(e) = socket.write_all(response_bytes.as_bytes()).await {
        eprintln!("◈ [MUX] Failed to send response: {}", e);
    }
}
