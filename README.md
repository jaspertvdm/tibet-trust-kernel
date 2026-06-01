# tibet-trust-kernel

Zero-trust security foundation. AES-256-GCM encryption, cryptographic integrity verification, sandboxed execution, and cross-machine memory transport — every byte proven, every execution isolated.

## What it does

tibet-trust-kernel provides security primitives for any system that needs zero-trust guarantees — encrypted data at rest, verified transport, isolated execution. It works for databases, IoT devices, financial systems, AI infrastructure, or anything where you can't afford to trust the network or the host.

- **Bifurcation** — AES-256-GCM encrypt/decrypt with X25519 key exchange. Data at rest is always encrypted. Think ransomware model flipped: everything encrypted by default, access requires cryptographic proof (JIS claim).
- **Airlock** — Sandboxed execution with SNAFT syscall monitoring. Kill or Safe, no middle ground.
- **ClusterMux** — Persistent multiplexed TCP transport with streaming SHA-256 integrity verification.
- **Hash Cache** — Skip SHA-256 on previously verified blocks. 14x speedup, zero trust compromise.
- **DIME Aperture** — Virtual memory mapping for large datasets across machines. Blocks materialize on-demand via page faults.
- **RAM RAID-0** — Stripe data across machines with userfaultfd page fault handling.
- **UPIP Pager** — Crypto-safe application-level paging with fork tokens for cross-device continuation.

### Use cases

| Domain | How trust-kernel helps |
|--------|----------------------|
| **Financial systems** | Bifurcation encrypts transactions at rest, triage levels gate approvals |
| **IoT / Edge** | ClusterMux transports sensor data with SHA-256 integrity, even over unreliable links |
| **Databases** | RAM RAID-0 stripes hot data across nodes, hash cache avoids re-verification |
| **AI inference** | [tibet-dgx](https://github.com/Humotica/tibet-dgx) uses DIME Aperture to map LLM weights across machines |
| **Multi-device apps** | UPIP fork tokens seal a session on one device, resume on another |
| **Compliance (EU AI Act, NIS2)** | Every operation produces a TIBET provenance token — cryptographic audit trail |

## Install

```toml
# Security primitives only
tibet-trust-kernel = "1.0.0-alpha"

# With cross-machine transport
tibet-trust-kernel = { version = "1.0.0-alpha", features = ["cluster"] }

# Everything including LLM mapper
tibet-trust-kernel = { version = "1.0.0-alpha", features = ["full"] }
```

```bash
cargo install tibet-trust-kernel
```

## Features

| Feature | Description |
|---------|-------------|
| `simulation` | Default — simulated KVM for testing |
| `kvm` | Real Ignition KVM microVM isolation |
| `cluster` | Cross-machine RAM RAID-0 + ClusterMux transport |
| `llm` | LLM Memory Mapper (DIME aperture), implies cluster |
| `full` | All features |

## Quick start

### Bifurcation — Encrypt everything

```rust
use tibet_trust_kernel::bifurcation::AirlockBifurcation;

let bifurcation = AirlockBifurcation::new_paranoid();
let sealed = bifurcation.seal(b"sensitive data", "block-0");
let opened = bifurcation.open(&sealed, "block-0");
assert_eq!(opened, b"sensitive data");
```

### ClusterMux — Cross-machine transport

```rust
use tibet_trust_kernel::cluster_mux::ClusterMuxClient;

let client = ClusterMuxClient::new("10.0.100.1:4432", "my-node.aint");
let rtt = client.ping().await?;
client.store_block(0, &data, &hash, "seal", data.len(), 0).await?;
let (block, _us) = client.fetch_block(0, Some(&hash), 0).await?;
```

## Modules

| Module | Tests | Description |
|--------|-------|-------------|
| `bifurcation` | 5 | AES-256-GCM seal/open, X25519 key exchange, HKDF derivation |
| `cluster_transport` | 9 | TCP-per-block transport, BlockStore |
| `cluster_mux` | 8 | Persistent MUX, streaming SHA-256, hash cache |
| `llm_mapper` | 11 | DIME Aperture, model manifests, prefetch, inference simulation |
| `ram_raid` | - | RAID-0 striping, batch restore, userfaultfd, prefetch |
| `airlock_vmm` | 4 | Sandboxed execution, SNAFT monitoring |
| `upip_pager` | 6 | Application-level paging, fork tokens |
| `portmux` | 3 | Port multiplexing |
| `seccomp` | 2 | Seccomp-BPF sandbox |
| `snapshot_gate` | 9 | **v1.2** — snapshot ACTIVE GATE (precondition-for-risk) |
| `osapi_adapter` | 5 | OSAPI v1.1 — verdict.v1 + TAT envelope ingest |
| `tat_consumer` | 6 | 5-tier biometric vehicle dispatch for re-attestation |
| `osapi_mux` | 10 | **v1.2** — single-port MUX, SSM-surface routing |

## OSAPI v1.2 — trust gate + single-port mux

Two v1.2 modules harden the capability-grant path. Both are **library-complete and
unit-tested**; wiring them into the running daemon's default exec path is the next
roadmap step (today the daemon still exposes the two-port `--osapi` adapter).

### `snapshot_gate` — snapshot as precondition-for-risk

The snapshot is not a backup you restore after a fault — it is the immune-memory that
must exist *before* a risky operation is permitted. A destructive action cannot
physically run without fresh immune-memory beneath it.

```rust
use tibet_trust_kernel::snapshot::SnapshotEngine;
use tibet_trust_kernel::snapshot_gate::{SnapshotGate, GateContext, RiskClass};

let mut gate = SnapshotGate::new(SnapshotEngine::new("/var/tibet/snapshots", true));
let ctx = GateContext {
    snaft_running: true,      // snaft.runtime.running
    identity_allowed: true,   // jis.identity.verdict == "allowed"
    bifurcation_ready: true,  // bifurcation.sandbox_clone.ready (destructive only)
    max_snapshot_age_secs: 60,
};
// Risky op: gate allows only with fresh immune-memory; primes one if stale (active).
let verdict = gate.evaluate(RiskClass::Destructive, &ctx, now_epoch, Some(&mem), "rm-rf", "jis:op");
// Denied is a HARD stop (no-fail-open) — not a warning.
```

`gate.snapshot_age_seconds(now)` is the value a snaft rule
`allow_iff: trust_kernel.snapshot.age_seconds < 60` reads.

### `osapi_mux` — one port, SSM-routed lanes

Collapses the v1.1 two-port split (18443 provenance / 18444 identity) into **one socket**.
A MUX in front routes each frame by its Semantic Surface Manifest 4-dot label
(`time.context.profile.priority`) **without opening the payload** — then the lane handler
verifies the content.

```rust
use tibet_trust_kernel::osapi_mux::{spawn_osapi_mux, route_by_surface, OSAPI_PORT_DEFAULT};

// one listener, SSM-routed: now.request.genesis-reattest.urgent → Identity lane,
// now.confirm.genesis-ready.normal → Provenance lane (kind-discrimination fallback).
let _h = spawn_osapi_mux("127.0.0.1", OSAPI_PORT_DEFAULT).await?;
```

## For LLM inference

If you want to **run LLMs across machines**, use [tibet-dgx](https://github.com/Humotica/tibet-dgx) — it wraps tibet-trust-kernel into a simple CLI:

```bash
cargo install tibet-dgx
tibet-dgx serve                              # on remote machine
tibet-dgx load model.gguf -e 10.0.100.1:4432  # on local machine
```

## Part of TIBET

tibet-trust-kernel is the security foundation of the [TIBET ecosystem](https://pypi.org/project/tibet/) — Traceable Intent-Based Event Tokens.

Built by [Humotica](https://humotica.com) for the [AInternet](https://ainternet.org).

## License

MIT
