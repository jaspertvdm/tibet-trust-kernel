//! OSAPI v1.2 — single-port MUX with SSM-surface routing.
//!
//! v1.1 (osapi_adapter) used two TCP-fallback ports (18443 provenance / 18444 identity).
//! v1.2 collapses them into ONE port (Jasper: "die ene poort is juist goed" — one socket
//! to bind/firewall/monitor/audit) with a MUX in front that routes each frame by its
//! Semantic Surface Manifest (SSM) 4-dot label `time.context.profile.priority` WITHOUT
//! opening the payload. This is the SSM's whole point: "routable without trustable by
//! name alone" (draft-vandemeent-tibet-semantic-surface-manifest §20).
//!
//! Routing order (per OSAPI spec §1a):
//!   1. SSM `surface` present → route by context/profile (first-pass, no payload-open)
//!   2. else fall back to message-kind discrimination (interim rules 1-5)
//! The lane handler then verifies content (handle_verdict / handle_tat in osapi_adapter).

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::osapi_adapter::{handle_tat, handle_verdict, OsapiResponse};

/// One native OSAPI port (v1.2). The two v1.1 ports collapse into this.
pub const OSAPI_PORT_DEFAULT: u16 = 18443;

/// Which lane a frame routes to. Provenance = tibet-side, Identity = jis-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// emit/query/fork + verdict.v1 ingest
    Provenance,
    /// claim/bind/fira + request_re_attestation TAT
    Identity,
    /// HELLO bootstrap-handshake (§3) — not yet served by the kernel, deferred to Python
    Bootstrap,
    /// undispatchable
    Unknown,
}

/// Route a frame to its lane. SSM surface first (no payload-open), kind fallback second.
///
/// SSM 4-dot ABNF: `time-fragment.context.profile.priority`
///   e.g. `now.request.genesis-reattest.urgent`  → Identity (re-attestation)
///        `now.confirm.genesis-ready.normal`      → Provenance (clean grant evidence)
/// The MUX reads only the surface string; it never decrypts/opens the payload to route.
pub fn route_by_surface(value: &Value) -> Lane {
    // 1. SSM surface first-pass (the MUX's job — read the label, not the cargo).
    if let Some(surface) = value.get("surface").and_then(|v| v.as_str()) {
        let parts: Vec<&str> = surface.split('.').collect();
        // context = parts[1], profile = parts[2] in the 4-dot form
        let profile = parts.get(2).copied().unwrap_or("");
        let context = parts.get(1).copied().unwrap_or("");
        if profile.contains("reattest") || context == "request" || context == "important" {
            return Lane::Identity; // re-attestation is an identity act
        }
        if profile.contains("genesis-ready") || profile.contains("verdict") || profile.contains("provenance") {
            return Lane::Provenance;
        }
        // surface present but unrecognized profile → fall through to kind discrimination
    }

    // 2. Message-kind fallback (interim rules from spec §1a).
    if value.get("kind").and_then(|v| v.as_str()) == Some("airlock_runtime_verdict.v1") {
        return Lane::Provenance;
    }
    if value.get("tat_version").is_some() {
        return Lane::Identity;
    }
    if let Some(op) = value.get("op").and_then(|v| v.as_str()) {
        return match op {
            "emit" | "query" | "fork" => Lane::Provenance,
            "claim" | "bind" | "fira" => Lane::Identity,
            _ => Lane::Unknown,
        };
    }
    if value.get("actor_claim").is_some() {
        return Lane::Bootstrap; // HELLO — kernel defers; Python OSAPI still serves this
    }
    Lane::Unknown
}

/// Dispatch a routed frame to its lane handler.
async fn dispatch(lane: Lane, value: Value, seq: u64) -> OsapiResponse {
    match lane {
        Lane::Provenance => handle_verdict(value, seq).await,
        Lane::Identity => handle_tat(value, seq).await,
        Lane::Bootstrap => OsapiResponse::Error {
            stream: "osapi.v1.2".to_string(),
            reason: "bootstrap HELLO handshake is served by the Python tibet-core/jis-core OSAPI, not the kernel mux (yet)".to_string(),
        },
        Lane::Unknown => OsapiResponse::Error {
            stream: "osapi.v1.2".to_string(),
            reason: "undispatchable frame: no SSM surface, no recognized kind/op".to_string(),
        },
    }
}

/// Spawn the single-port OSAPI MUX listener. One socket, SSM-routed lanes.
pub async fn spawn_osapi_mux(
    bind_host: &str,
    port: u16,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let addr = format!("{}:{}", bind_host, port);
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("[osapi-mux] v1.2 single-port SSM-routed on {}", addr);

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((socket, peer)) => {
                    eprintln!("[osapi-mux] accepted from {}", peer);
                    tokio::spawn(async move {
                        if let Err(e) = serve(socket).await {
                            eprintln!("[osapi-mux] session error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("[osapi-mux] accept error: {}", e),
            }
        }
    });
    Ok(handle)
}

async fn serve(socket: TcpStream) -> std::io::Result<()> {
    let (rd, mut wr) = socket.into_split();
    let mut reader = BufReader::new(rd).lines();
    let mut seq: u64 = 0;
    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        seq += 1;
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(value) => {
                let lane = route_by_surface(&value);
                eprintln!("[osapi-mux] frame seq={} → lane={:?}", seq, lane);
                dispatch(lane, value, seq).await
            }
            Err(e) => OsapiResponse::Error {
                stream: "osapi.v1.2".to_string(),
                reason: format!("invalid JSON: {}", e),
            },
        };
        let encoded = serde_json::to_string(&response)
            .unwrap_or_else(|e| format!("{{\"kind\":\"error\",\"reason\":\"encode failed: {}\"}}", e));
        wr.write_all(encoded.as_bytes()).await?;
        wr.write_all(b"\n").await?;
        wr.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn surface_reattest_routes_identity() {
        let v = json!({"surface": "now.request.genesis-reattest.urgent", "tat_version": "0.1"});
        assert_eq!(route_by_surface(&v), Lane::Identity);
    }

    #[test]
    fn surface_genesis_ready_routes_provenance() {
        let v = json!({"surface": "now.confirm.genesis-ready.normal"});
        assert_eq!(route_by_surface(&v), Lane::Provenance);
    }

    #[test]
    fn no_surface_verdict_kind_routes_provenance() {
        let v = json!({"kind": "airlock_runtime_verdict.v1", "runtime_mode": "x"});
        assert_eq!(route_by_surface(&v), Lane::Provenance);
    }

    #[test]
    fn no_surface_tat_version_routes_identity() {
        let v = json!({"tat_version": "0.1", "intent": "request_re_attestation"});
        assert_eq!(route_by_surface(&v), Lane::Identity);
    }

    #[test]
    fn op_emit_routes_provenance_op_claim_routes_identity() {
        assert_eq!(route_by_surface(&json!({"op": "emit"})), Lane::Provenance);
        assert_eq!(route_by_surface(&json!({"op": "fork"})), Lane::Provenance);
        assert_eq!(route_by_surface(&json!({"op": "claim"})), Lane::Identity);
        assert_eq!(route_by_surface(&json!({"op": "fira"})), Lane::Identity);
    }

    #[test]
    fn actor_claim_routes_bootstrap() {
        let v = json!({"v": "1.0", "actor": "pkg", "actor_claim": "sig"});
        assert_eq!(route_by_surface(&v), Lane::Bootstrap);
    }

    #[test]
    fn garbage_routes_unknown() {
        assert_eq!(route_by_surface(&json!({"hello": "world"})), Lane::Unknown);
    }

    #[test]
    fn surface_takes_precedence_over_kind() {
        // surface says identity (reattest), even though no tat_version — surface wins first-pass
        let v = json!({"surface": "now.important.genesis-reattest.urgent"});
        assert_eq!(route_by_surface(&v), Lane::Identity);
    }

    #[tokio::test]
    async fn dispatch_provenance_acks_valid_verdict() {
        let v = json!({"kind": "airlock_runtime_verdict.v1", "runtime_mode": "normal_zero_trust",
                       "snaft_posture": "open", "evidence": {}});
        let r = dispatch(Lane::Provenance, v, 1).await;
        assert!(matches!(r, OsapiResponse::Ack { .. }));
    }

    #[tokio::test]
    async fn dispatch_identity_returns_vehicle_for_tat() {
        let v = json!({"tat_version": "0.1", "intent": "request_re_attestation",
                       "to": "jis:pixel10:storm", "payload_ref": {"hash": "sha256:x"},
                       "policy": {"ttl_seconds": 300}});
        let r = dispatch(Lane::Identity, v, 1).await;
        assert!(matches!(r, OsapiResponse::VehicleDispatch(_)));
    }
}
