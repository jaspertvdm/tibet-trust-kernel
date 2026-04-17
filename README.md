# tibet-trust-kernel

Zero-trust security foundation for AI infrastructure. AES-256-GCM encryption, cryptographic integrity verification, and cross-machine memory transport — every byte proven, every execution isolated.

## What it does

tibet-trust-kernel provides the security primitives that AI systems need to operate in zero-trust environments:

- **Bifurcation** — AES-256-GCM encrypt/decrypt with X25519 key exchange. Data at rest is always encrypted.
- **Airlock** — Sandboxed execution with SNAFT syscall monitoring. Kill or Safe, no middle ground.
- **ClusterMux** — Persistent multiplexed TCP transport with streaming SHA-256 integrity verification.
- **Hash Cache** — Skip SHA-256 on previously verified blocks. 14x speedup, zero trust compromise.
- **DIME Aperture** — Virtual memory mapping for large datasets across machines (used by [tibet-dgx](https://github.com/Humotica/tibet-dgx) for LLM inference).
- **RAM RAID-0** — Stripe data across machines with userfaultfd page fault handling.
- **UPIP Pager** — Crypto-safe application-level paging with fork tokens for cross-device continuation.

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
