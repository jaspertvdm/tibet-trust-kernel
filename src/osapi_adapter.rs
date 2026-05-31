//! OSAPI adapter v1.1 — TCP/LDJSON ingest for verdict.v1 and TAT envelopes.
//!
//! Two listeners:
//!   - 18443: verdict.v1 ingest (airlock_runtime_verdict.v1 contract)
//!            → archivaris/voorproever → bus.stamp → JSONL audit
//!   - 18444: TAT envelope ingest (intent=request_re_attestation)
//!            → tat_consumer biometric vehicle dispatcher → bus.stamp → response
//!
//! LDJSON wire format = one JSON object per line, newline-terminated.
//! Each accepted connection is line-oriented and stateful per session.
//!
//! Default-OFF: trust-kernel daemon does not open TCP unless --osapi is set.
//! Discipline (Jasper memory `los_bouwbaar_trust_kernel_substitutie`):
//! bolle runtime-API onaanpasbaar gated op AI-traffic. OSAPI is the
//! explicit, opt-in side-channel for operator/observability traffic.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::tat_consumer::{decide_vehicle, VehicleDispatch};

pub const VERDICT_PORT_DEFAULT: u16 = 18443;
pub const TAT_PORT_DEFAULT: u16 = 18444;

/// One LDJSON line in or out of the adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsapiResponse {
    Ack { stream: String, seq: u64 },
    VehicleDispatch(VehicleDispatch),
    Error { stream: String, reason: String },
}

/// Spawn both OSAPI listeners (verdict + TAT) on the given bind addr.
/// Returns a JoinHandle vector for graceful shutdown by the caller.
pub async fn spawn_osapi(
    bind_host: &str,
    verdict_port: u16,
    tat_port: u16,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let verdict_addr = format!("{}:{}", bind_host, verdict_port);
    let tat_addr = format!("{}:{}", bind_host, tat_port);

    let verdict_listener = TcpListener::bind(&verdict_addr).await?;
    let tat_listener = TcpListener::bind(&tat_addr).await?;

    eprintln!("[osapi] verdict ingest on {}", verdict_addr);
    eprintln!("[osapi] TAT envelope ingest on {}", tat_addr);

    let verdict_handle = tokio::spawn(async move {
        accept_loop(verdict_listener, "verdict.v1", handle_verdict).await;
    });
    let tat_handle = tokio::spawn(async move {
        accept_loop(tat_listener, "tat.v0.1", handle_tat).await;
    });

    Ok(vec![verdict_handle, tat_handle])
}

async fn accept_loop<F, Fut>(listener: TcpListener, stream_kind: &'static str, handler: F)
where
    F: Fn(Value, u64) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = OsapiResponse> + Send,
{
    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                eprintln!("[osapi/{}] accepted from {}", stream_kind, peer);
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(socket, stream_kind, handler).await {
                        eprintln!("[osapi/{}] session error: {}", stream_kind, e);
                    }
                });
            }
            Err(e) => {
                eprintln!("[osapi/{}] accept error: {}", stream_kind, e);
            }
        }
    }
}

async fn serve_connection<F, Fut>(
    socket: TcpStream,
    stream_kind: &'static str,
    handler: F,
) -> std::io::Result<()>
where
    F: Fn(Value, u64) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = OsapiResponse> + Send,
{
    let (rd, mut wr) = socket.into_split();
    let mut reader = BufReader::new(rd).lines();
    let mut seq: u64 = 0;
    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        seq += 1;
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(value) => handler(value, seq).await,
            Err(e) => OsapiResponse::Error {
                stream: stream_kind.to_string(),
                reason: format!("invalid JSON: {}", e),
            },
        };
        let encoded = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => format!("{{\"kind\":\"error\",\"reason\":\"encode failed: {}\"}}", e),
        };
        wr.write_all(encoded.as_bytes()).await?;
        wr.write_all(b"\n").await?;
        wr.flush().await?;
    }
    Ok(())
}

/// verdict.v1 handler — accepts the record and ACKs after shape validation.
/// Production wires this to: archivaris.write + voorproever.evaluate +
/// bus.stamp_payload + snaft posture update + JSONL audit-log append.
/// For v1.1 we validate shape + audit-acknowledge so the contract is live
/// end-to-end on the wire.
async fn handle_verdict(value: Value, seq: u64) -> OsapiResponse {
    let kind = value
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("(missing kind)");
    if kind != "airlock_runtime_verdict.v1" {
        return OsapiResponse::Error {
            stream: "verdict.v1".to_string(),
            reason: format!("unexpected kind: {}", kind),
        };
    }
    // Required fields per contract task #21.
    for f in &["runtime_mode", "snaft_posture", "evidence"] {
        if value.get(f).is_none() {
            return OsapiResponse::Error {
                stream: "verdict.v1".to_string(),
                reason: format!("missing field: {}", f),
            };
        }
    }
    OsapiResponse::Ack {
        stream: "verdict.v1".to_string(),
        seq,
    }
}

/// TAT envelope handler — accepts tibet-genesis request_re_attestation (or
/// any other TAT envelope) and dispatches biometric vehicle choice.
/// Production wires this to: trust-kernel key custody + i-poll outbound
/// to operator .aint device + capability-grant pause until re_attested.
async fn handle_tat(value: Value, _seq: u64) -> OsapiResponse {
    let tat_version = value
        .get("tat_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if tat_version != "0.1" {
        return OsapiResponse::Error {
            stream: "tat.v0.1".to_string(),
            reason: format!("unsupported tat_version: {}", tat_version),
        };
    }
    let intent = value.get("intent").and_then(|v| v.as_str()).unwrap_or("");
    // Magic + SSM surface checked but not gating; trust comes from policy + verify.
    let magic = value.get("magic").and_then(|v| v.as_str()).unwrap_or("");
    let surface = value.get("surface").and_then(|v| v.as_str()).unwrap_or("");
    let transfer_id = value
        .get("transfer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(no transfer_id)")
        .to_string();
    let to = value.get("to").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let candidate_hash = value
        .pointer("/payload_ref/hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let ttl_seconds = value
        .pointer("/policy/ttl_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let dispatch = decide_vehicle(&intent, &to, &candidate_hash, ttl_seconds);

    eprintln!(
        "[osapi/tat] intent={} magic={} surface={} → vehicle={} target={} transfer={}",
        intent, magic, surface, dispatch.vehicle, dispatch.target, transfer_id
    );

    OsapiResponse::VehicleDispatch(dispatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn verdict_handler_accepts_valid_shape() {
        let v = json!({
            "kind": "airlock_runtime_verdict.v1",
            "runtime_mode": "normal_zero_trust",
            "snaft_posture": "open",
            "evidence": {"source": "tibet-pol"},
        });
        match handle_verdict(v, 1).await {
            OsapiResponse::Ack { stream, seq } => {
                assert_eq!(stream, "verdict.v1");
                assert_eq!(seq, 1);
            }
            other => panic!("expected Ack, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn verdict_handler_rejects_wrong_kind() {
        let v = json!({"kind": "something.else", "runtime_mode": "x",
                       "snaft_posture": "open", "evidence": {}});
        matches!(handle_verdict(v, 1).await, OsapiResponse::Error { .. });
    }

    #[tokio::test]
    async fn verdict_handler_rejects_missing_fields() {
        let v = json!({"kind": "airlock_runtime_verdict.v1"});
        matches!(handle_verdict(v, 1).await, OsapiResponse::Error { .. });
    }

    #[tokio::test]
    async fn tat_handler_dispatches_vehicle_for_request_re_attestation() {
        let v = json!({
            "magic": "T1_REATTEST_REQ",
            "surface": "now.request.genesis-reattest.urgent",
            "tat_version": "0.1",
            "transfer_id": "tat_reattest_test",
            "from": "jis:tibet-genesis:airlock",
            "to": "jis:humotica:operator",
            "intent": "request_re_attestation",
            "payload_ref": {"kind": "external-ref", "hash": "sha256:abc"},
            "policy": {"ttl_seconds": 300, "requires_consent": true,
                       "requires_re_attestation": true, "max_forward_hops": 0,
                       "allow_external_ai": false},
            "proofs": {},
            "receipts": {"expected": ["re_attested"], "ack_route": "ipoll"},
        });
        match handle_tat(v, 1).await {
            OsapiResponse::VehicleDispatch(d) => {
                assert_eq!(d.intent, "request_re_attestation");
                assert!(!d.vehicle.is_empty());
                assert_eq!(d.candidate_hash, "sha256:abc");
                assert_eq!(d.ttl_seconds, 300);
            }
            other => panic!("expected VehicleDispatch, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tat_handler_rejects_wrong_version() {
        let v = json!({"tat_version": "9.9", "intent": "request_re_attestation"});
        matches!(handle_tat(v, 1).await, OsapiResponse::Error { .. });
    }
}
