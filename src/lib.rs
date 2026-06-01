// Tibet Trust Kernel — Library exports
//
// Modules beschikbaar voor binaries en externe crates.

// ── Core crypto ──
pub mod bifurcation;

// ── Dual-kernel pipeline ──
pub mod mux;
pub mod snaft;
pub mod tibet_token;
pub mod config;
pub mod bus;
pub mod watchdog;
pub mod voorproever;
pub mod archivaris;

// ── Hardening ──
pub mod portmux;
pub mod xdp;
pub mod seccomp;
pub mod zandbak;

// ── Storage & recovery ──
pub mod snapshot;
// ── Snapshot ACTIVE GATE (v1.2) — snapshot as precondition-for-risk ──
// Immune-memory must exist BEFORE a risky op is permitted; no-fail-open.
pub mod snapshot_gate;
pub mod recovery;
pub mod git_store;
pub mod airlock_vmm;

// ── Cluster & paging ──
pub mod ram_raid;
pub mod upip_pager;
pub mod cluster_transport;
pub mod cluster_mux;
#[cfg(feature = "quic")]
pub mod quic_mux;
pub mod overlay_mux;
pub mod llm_mapper;

// ── OSAPI v1.1 — opt-in TCP/LDJSON side-channel ──
// Default-OFF; activated via --osapi flag on the daemon. Two listeners:
//   18443: verdict.v1 ingest (airlock_runtime_verdict.v1 contract)
//   18444: TAT envelope ingest (intent=request_re_attestation + others)
pub mod osapi_adapter;
pub mod tat_consumer;
