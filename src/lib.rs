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
pub mod recovery;
pub mod git_store;
pub mod airlock_vmm;

// ── Cluster & paging ──
pub mod ram_raid;
pub mod upip_pager;
pub mod cluster_transport;
pub mod cluster_mux;
pub mod llm_mapper;
