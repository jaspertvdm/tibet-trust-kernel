# TIBET Hardware Primitives — Silicon-Informed Trust Kernel

## Auteurs: Jasper van de Meent, Root AI
## Datum: 2026-04-14
## Status: Architectuur / v2 Roadmap

---

## Het Principe

De Trust Kernel v1 is pure software. v2 praat met de hardware.

Elke CPU heeft features die specifiek gebouwd zijn voor exact wat wij doen —
encryptie, isolatie, monitoring, cache control. Die features liggen onbenut
in het silicon. Wij activeren ze.

Het resultaat: de CPU werkt MET de Trust Kernel, niet ertegen.

---

## Hardware Feature Matrix

```
LAAG          HARDWARE FEATURE         EFFECT IN TRUST KERNEL
──────────────────────────────────────────────────────────────────────
Crypto        AES-NI + SHA-NI          Bifurcatie: 194µs → <10µs per block
Random        RDRAND / RDSEED          Nonces zonder /dev/urandom syscall
Geheugen      TME / MKTME             RAM encrypted in hardware (altijd)
VM isolatie   SEV-SNP / TDX            Hypervisor kan Zandbak niet lezen
DMA           IOMMU + P2P DMA         Zero-CPU block transfer (LiveMigration)
Cache         CAT / MPAM              Trust Kernel hot path altijd in L3
Control flow  CET Shadow Stack         ROP/JOP aanvallen onmogelijk
Monitoring    PMU + NMI                Hardware watchdog (CONTI sniffer in silicon)
Forensics     Intel PT + LBR           Instructie-level audit trail
Bus           TSX (waar veilig)        Atomische bus payload transfer
Tagging       MTE (ARM)                Buffer overflow detectie in hardware
Anti-MPK      seccomp + CET            WRPKRU hard geblokkeerd (zie §3)
```

---

## §1 — Crypto Acceleratie

### AES-NI (v1 → v2 uplift)

v1 status: AES-256-GCM via `aes-gcm` crate, gebruikt al `_mm_aesenc_si128`.
Gemeten: 128-152 MB/s bij 64-256KB blocks op legacy hardware (DL360).

De bottleneck is niet AES maar **X25519 key generation** (~150µs per block).

### SHA-NI

De `sha2` crate detecteert SHA-NI automatisch met `target-cpu=native`.
Op CPU's met SHA-NI extensies:

```
Zonder SHA-NI:  SHA-256 ~ 500 MB/s   (software)
Met SHA-NI:     SHA-256 ~ 2-5 GB/s   (hardware, 4-10x sneller)
```

**Impact op Trust Kernel:**
- Voorproever hash verificatie: sneller
- Bifurcatie plaintext_hash: sneller
- HKDF-SHA256 key derivation: sneller (SHA-256 is de inner PRF)
- Sniffer block hash checks: sneller
- TIBET token signing: content hash sneller

Detectie: `cat /proc/cpuinfo | grep sha_ni`
Build flag: `RUSTFLAGS="-C target-cpu=native"` (al in gebruik)

### RDRAND / RDSEED

Huidige nonce generatie: `OsRng` → `/dev/urandom` → syscall overhead.

Met RDRAND:
```rust
// Direct CPU instruction, geen syscall
use core::arch::x86_64::_rdrand64_step;

fn hardware_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    unsafe {
        let mut val: u64 = 0;
        _rdrand64_step(&mut val);
        nonce[..8].copy_from_slice(&val.to_le_bytes());
        _rdrand64_step(&mut val);
        nonce[8..].copy_from_slice(&val.to_le_bytes()[..4]);
    }
    nonce
}
```

Besparing: ~0.5µs per nonce (syscall overhead weg).
Bij 10.000 seals: 5ms bespaard. Klein maar gratis.

---

## §2 — Software Optimalisatiepaden (v2)

### Key Caching (de grote winst)

Huidige situatie: elke seal genereert een nieuwe X25519 ephemeral key (~150µs).
Dit is correct voor maximale forward secrecy, maar overkill voor batch operaties.

```
v1 (nu):     seal → X25519 keygen (150µs) → HKDF → AES → done
             10.000 blocks = 10.000 × 150µs = 1.5 seconden alleen keygen

v2 (cached): session_start → X25519 keygen (150µs, eenmalig)
             seal → HKDF(shared, block_index) → AES → done
             10.000 blocks = 1 × 150µs + 10.000 × ~5µs = 50ms
```

**30x sneller** met behoud van per-block unieke AES keys (via HKDF).

Implementatie:
```rust
pub struct CachedSession {
    shared_secret: [u8; 32],   // X25519 DH result (eenmalig)
    session_id: u64,           // Voor audit trail
    blocks_sealed: u64,        // Counter
}

impl AirlockBifurcation {
    pub fn start_session(&mut self) -> CachedSession {
        // Eenmalige X25519 keygen
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(self.system_pub));
        CachedSession {
            shared_secret: *shared.as_bytes(),
            session_id: self.boot_time.elapsed().as_nanos() as u64,
            blocks_sealed: 0,
        }
    }

    pub fn seal_cached(&mut self, session: &mut CachedSession, ...) {
        // HKDF direct uit cached shared secret — skip X25519
        let aes_key = self.hkdf_derive_block_key(
            &session.shared_secret, block_index
        );
        // ... AES-GCM encrypt (~5µs voor 4KB)
    }
}
```

### Parallelisatie (multi-core)

AES-GCM is per-block onafhankelijk. Meerdere blocks tegelijk:

```rust
use rayon::prelude::*;

blocks.par_iter().for_each(|block| {
    bifurcation.seal(block, ...);
});
```

Op 4 cores: ~4x throughput = 500-600 MB/s.
Op P520 (8 cores): ~1 GB/s theoretisch.

### Block Size Tuning

```
4KB blocks:   194µs/seal  →  20 MB/s   (veel key overhead per byte)
64KB blocks:  975µs/seal  → 128 MB/s   (AES-NI domineert)
256KB blocks: 3.3ms/seal  → 152 MB/s   (sweet spot)
```

Grotere blocks = betere AES-NI utilisatie.
Trade-off: grotere blocks = grovere granulariteit bij partial updates.

**Optimaal:** 64KB blocks voor algemeen gebruik, 256KB voor bulk/backup.

---

## §3 — WRPKRU Hard Block

### Het Probleem

`wrpkru` is een unprivileged x86 instructie die Memory Protection Keys wijzigt.
Geen syscall nodig. Elke userspace thread kan het uitvoeren.
In een Airlock context waar geheugenregio's VAST staan: dit is een aanvalsvector.

### De Drie-Laags Block

```
┌─────────────────────────────────────────────────────────┐
│  Laag 3: CET Shadow Stack                              │
│  ← ROP/JOP gadget chains naar wrpkru worden gevangen   │
│  ← Aanvaller kan wrpkru niet bereiken via code reuse   │
├─────────────────────────────────────────────────────────┤
│  Laag 2: Kernel MPK disable (CR4.PKE=0)                │
│  ← Als CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=n       │
│  ← wrpkru wordt een NOP, CPU negeert de instructie     │
├─────────────────────────────────────────────────────────┤
│  Laag 1: seccomp-BPF                                   │
│  ← Blokkeer pkey_alloc (329), pkey_free (331),         │
│     pkey_mprotect (330) syscalls                        │
│  ← Zonder allocated pkeys is wrpkru nutteloos           │
└─────────────────────────────────────────────────────────┘
```

**Laag 1 + Laag 3 samen = wrpkru is dood.**

Implementatie in bestaande seccomp.rs:
```rust
// Voeg toe aan BLOCKED_SYSCALLS:
const SYS_PKEY_ALLOC: i32 = 330;
const SYS_PKEY_FREE: i32 = 331;
const SYS_PKEY_MPROTECT: i32 = 329;
```

CET Shadow Stack: beschikbaar op Intel 11th gen+ en AMD Zen 3+.
Enable via: `prctl(PR_SET_SHADOW_STACK_STATUS, ...)` of compiler flag.

---

## §4 — P2P DMA (Zero-CPU Block Transfer)

### Het Inzicht

Bij LiveMigration worden encrypted blocks van Server A naar Server B gestuurd.
Als een block ongewijzigd is (niet dirty), hoeft de CPU het niet aan te raken.
Het block is al encrypted — het kan rechtstreeks over PCIe.

```
Dirty block:    NVMe → CPU (decrypt → re-encrypt) → NIC → remote
Clean block:    NVMe ─────── PCIe P2P DMA ─────────→ NIC → remote
                      CPU doet NIETS. Zero cycles.
```

### Linux P2P DMA API (kernel 4.20+)

```c
// Kernel module kant:
struct pci_dev *nvme = ...;
struct pci_dev *nic  = ...;

// Check of P2P mogelijk is tussen deze twee devices
if (pci_p2pdma_distance(nvme, nic) >= 0) {
    // Alloceer P2P DMA buffer
    void *buf = pci_alloc_p2pmem(nvme, block_size);
    // Transfer: NVMe → NIC zonder CPU
    dma_map_resource(...);
}
```

### Impact op LiveMigration

```
Huidige benchmark (CPU-path):
  256 blocks × 4KB = BulkSync in 3.9ms

Met P2P DMA (clean blocks):
  256 blocks × 4KB = BulkSync in ~0.5ms (alleen dirty blocks via CPU)

Dirty ratio 10%: 26 blocks CPU + 230 blocks P2P DMA
  CPU:  26 × 15µs  = 390µs
  P2P:  230 × 2µs  = 460µs (PCIe latency)
  Total: ~850µs vs 3.9ms = 4.5x sneller
```

### Vereisten

- PCIe switch die P2P ondersteunt (of on-CPU PCIe root complex)
- IOMMU voor DMA isolatie (VT-d / AMD-Vi) — VERPLICHT voor security
- `CONFIG_PCI_P2PDMA=y` in kernel
- NVMe en NIC op dezelfde PCIe root complex (of via switch)

P520 checken: `lspci -vvv | grep -i "Access Control"`

---

## §5 — CAT: L3 Cache Omheining

### Het Probleem

L3 cache is shared. Bulk I/O (nginx, postgres, backup) evict Trust Kernel data.
Resultaat: cache miss → DRAM access → 100ns extra latency per operatie.

### De Oplossing

Intel CAT (Cache Allocation Technology) reserveert L3 cache ways:

```bash
# Check of CAT beschikbaar is
mount -t resctrl resctrl /sys/fs/resctrl

# Reserveer 2 van 16 ways voor Trust Kernel (COS1)
mkdir /sys/fs/resctrl/trust-kernel
echo "L3:0=00003" > /sys/fs/resctrl/trust-kernel/schemata
# 0x0003 = way 0 + way 1 = 2 ways = 2/16 van L3

# Wijs Trust Kernel PID toe
echo $TK_PID > /sys/fs/resctrl/trust-kernel/tasks
```

### Effect

```
Zonder CAT:
  Voorproever: 91ns (maar 200-500ns bij cache miss door nginx bulk traffic)

Met CAT (2 ways gereserveerd):
  Voorproever: 91ns ALTIJD (hot path zit gegarandeerd in L3)
  AES key schedule: altijd warm
  HKDF state: altijd in cache
```

**Bonus:** CAT voorkomt ook cache-based side-channel attacks (Flush+Reload).
Andere processen kunnen Trust Kernel cache lines niet evicten = niet proben.

### ARM Equivalent: MPAM

Memory Partitioning and Monitoring. Zelfde concept, andere API.
Beschikbaar op ARMv8.4+. Relevant voor Raspberry Pi 5 / Apple Silicon targets.

---

## §6 — PMU + NMI: Hardware Watchdog

### Het Inzicht

Software monitoring pollt. Hardware telt continu.
PMU (Performance Monitoring Unit) kan een NMI genereren bij:

| Counter | Drempel | Betekenis |
|---------|---------|-----------|
| Cache miss rate | >80% | Mogelijke side-channel of memory scanning |
| Branch mispredict | >30% | Mogelijke Spectre-variant |
| IPC drop | <0.5 | Overbelasting of denial-of-service |
| TLB miss storm | >1000/ms | Memory probing aanval |
| L3 eviction rate | abnormaal | Cache-based aanval |

### Implementatie

```c
// perf_event_open met overflow → NMI
struct perf_event_attr attr = {
    .type = PERF_TYPE_HARDWARE,
    .config = PERF_COUNT_HW_CACHE_MISSES,
    .sample_period = 10000,  // NMI na elke 10.000 cache misses
    .exclude_kernel = 1,
};

int fd = perf_event_open(&attr, pid, cpu, -1, 0);
// Bij overflow: kernel stuurt NMI → onze handler
```

### Integratie met Trust Kernel

```
PMU overflow (NMI)
       │
       ▼
  Watchdog handler
       │
  ┌────┴────┐
  │ Analyse │
  └────┬────┘
       │
  ┌────┴──────────────────────────┐
  │ Cache storm?  → Quarantine    │
  │ IPC drop?     → MUX priority  │
  │ Branch spike? → Kill suspect  │
  │ TLB storm?    → Freeze + log  │
  └───────────────────────────────┘
```

Dit IS de CONTI sniffer — maar dan in silicon. De CPU zelf detecteert anomalieën.

---

## §7 — Intel PT + LBR: Forensische Audit Trail

### Processor Trace (Intel PT)

Logt elke genomen branch, elke instructie, op hardware-snelheid.
Overhead: <5%. Output: compressed trace buffer.

```bash
# Record Trust Kernel execution trace
perf record -e intel_pt// -p $TK_PID -- sleep 10
perf script --itrace=i1000 | head
```

Dit geeft instructie-level audit trail. Als er ooit een incident is,
kun je EXACT reconstrueren wat er gebeurd is. Elke branch, elke call.

### Last Branch Record (LBR)

Lichter dan PT. Slaat de laatste 32 branches op in een ring buffer.
Geen I/O overhead. Altijd aan.

Bij een crash of anomalie: dump de LBR → je ziet de exacte code path
die tot het incident leidde.

---

## §8 — TME/MKTME: RAM Encryptie in Hardware

### Total Memory Encryption (TME)

Alle RAM is encrypted in hardware. Transparant voor software.
De CPU encrypt/decrypt bij elke memory access.

```
Zonder TME:  RAM bevat plaintext → cold boot attack mogelijk
Met TME:     RAM bevat ciphertext → cold boot attack zinloos
```

### Multi-Key TME (MKTME)

Verschillende encryptiesleutels per VM/process.
Trust Kernel + Zandbak elk met eigen key.
Zelfs als de hypervisor gecompromitteerd is: RAM is onleesbaar.

Complementair aan Airlock Bifurcatie:
- Bifurcatie: data at REST encrypted (disk)
- TME/MKTME: data in MOTION encrypted (RAM)
- Samen: data is NOOIT plaintext buiten de CPU registers

---

## §9 — Gecombineerd v2 Pad

### Fase 1: Software (nu implementeerbaar)

```
[x] AES-NI via aes-gcm crate           — DONE (v1)
[x] SHA-256 via sha2 crate             — DONE (v1, SHA-NI auto-detect)
[ ] Key caching per sessie             — 30x seal speedup
[ ] RDRAND nonces                      — syscall overhead weg
[ ] Block size tuning (64KB default)   — betere AES-NI utilisatie
[ ] Parallelisatie (rayon)             — multi-core encrypt
```

### Fase 2: Kernel features (Linux config + sysfs)

```
[ ] CAT L3 reservering                — /sys/fs/resctrl/
[ ] seccomp pkey block                — wrpkru neutraliseren
[ ] PMU overflow NMI                  — perf_event_open()
[ ] CET shadow stack                  — compiler flag + prctl
```

### Fase 3: Hardware specifiek (P520 + DL360 testing)

```
[ ] P2P DMA (LiveMigration)           — PCIe topology check
[ ] Intel PT forensics                — trace buffer setup
[ ] TME/MKTME status                  — BIOS check
[ ] LBR always-on                     — branch recording
```

### Verwachte v2 Performance

```
v1 (nu, legacy DL360):
  Seal 4KB:     194 µs     (X25519 per block)
  Open 4KB:     126 µs
  Throughput:   128-152 MB/s

v2 (key caching + SHA-NI + RDRAND + 64KB blocks + CAT):
  Seal 64KB:    ~15 µs     (HKDF + AES-NI, geen X25519)
  Open 64KB:    ~12 µs     (AES-NI decrypt + SHA-NI verify)
  Throughput:   ~4 GB/s    (met multi-core)

v2 LiveMigration (P2P DMA voor clean blocks):
  BulkSync:     ~0.5ms     (vs 3.9ms nu, 8x sneller)
  DeltaSync:    ~0.1ms     (alleen dirty via CPU)
```

---

## De Filosofie

> De CPU is niet neutraal. Die heeft features die gebouwd zijn voor
> precies wat wij doen. AES-NI is niet toevallig in elke x86 chip.
> SHA-NI is niet toevallig. CAT is niet toevallig.
>
> Wij zijn de eerste die deze features combineren tot een coherent
> trust model. Niet als losse tools — als één systeem waar de
> hardware MEEwerkt met de software.
>
> De Trust Kernel v2 is geen software product met hardware support.
> Het is een silicon-software symbiose.
>
> — Hardware Primitives, april 2026
