# tibet-airlock

Zero-trust microVM sandbox with TIBET provenance. Kernel isolation in <1ms, cryptographic proof of every execution.

## What it does

Tibet-airlock receives an **intent** (what the AI agent wants to do), boots a pre-warmed microVM snapshot, executes the payload under **SNAFT syscall monitoring**, and returns a **TIBET provenance token** — cryptographic proof of exactly what happened.

```
Intent → Snapshot Wake (<0.01ms) → SNAFT Monitor → Triage → TIBET Token
```

## Why

AI agents execute code. That code needs isolation. Not "container isolation" — **kernel isolation**. Every syscall monitored. Every execution proven. Every violation killed instantly.

- **Sub-milliseconde** — 0.6ms average roundtrip including TCP
- **Intent-based routing** — each intent maps to a specific OCI image and snapshot
- **SNAFT syscall monitoring** — allowlist per intent + always-dangerous blocklist
- **TIBET provenance** — every execution generates a cryptographic proof token
- **Kill or Safe** — violations terminate the VM immediately, no second chances

## Quick start

```bash
cargo install tibet-airlock
tibet-airlock  # starts MUX listener on 127.0.0.1:4430
```

Send a MUX frame (JSON over TCP):

```json
{
    "channel_id": 1,
    "intent": "code:execute",
    "from_aint": "your_agent.aint",
    "payload": "print('hello world')"
}
```

Safe execution returns status 200 + TIBET success token.
Dangerous payload returns status 403 + TIBET incident token with violations.
Unknown intent returns status 400 + TIBET rejection token.

## Supported intents

| Intent | OCI Image | Snapshot |
|--------|-----------|----------|
| `analyze_malware_sample` | airlock-python | python-safe-boot |
| `code:execute` | airlock-python | python-safe-boot |
| `file:scan` | airlock-scanner | scanner-ready |
| `call:voice:*` | airlock-sip | sip-ready |
| `call:video:*` | airlock-webrtc | webrtc-ready |

## SNAFT blocked syscalls

Always dangerous (any intent): `sys_ptrace`, `sys_socket`, `sys_connect`, `sys_dlopen`, `sys_fork`, `sys_clone`, `sys_mount`, `sys_reboot`, `sys_kexec_load`

## Features

- `simulation` (default) — simulated VM for testing without /dev/kvm
- `kvm` — real Ignition KVM isolation via [lttle.cloud](https://lttle.cloud)

## Part of TIBET

Tibet-airlock is part of the [TIBET ecosystem](https://pypi.org/project/tibet/) — Traceable Intent-Based Event Tokens. Install the full stack: `pip install tibet[full]`

Built by [Humotica](https://humotica.com) for the [AInternet](https://ainternet.org).

## License

MIT
