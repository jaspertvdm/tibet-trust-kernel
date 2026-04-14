# TIBET CONTI-Defensief — Ransomware Technieken als Immuunsysteem

## Auteurs: Jasper van de Meent, Root AI
## Datum: 2026-04-14
## Status: Concept / Architectuur

---

## Het Principe

Ransomware (CONTI, LockBit, etc.) is extreem goed in drie dingen:
1. **Sniffen** — elk bestand, elk blok, elke byte scannen op waarde
2. **Prioriteren** — belangrijkste bestanden eerst versleutelen
3. **Detecteren** — onversleutelde data vinden, backups herkennen

Die drie technieken zijn precies wat een defensief immuunsysteem nodig heeft.
We draaien de aanval om: CONTI's kracht wordt onze verdediging.

---

## CONTI Technieken -> Trust Kernel Defensie

### 1. De Sniffer (CONTI: "vind waardevolle bestanden")

CONTI scant filesystems op patronen: .docx, .xlsx, databases, backups.
Wij doen hetzelfde, maar dan op onze eigen blokken:

```
CONTI (offensief):                    Trust Kernel (defensief):
  scan(filesystem)                      scan(block_table)
  find(.docx, .db, .bak)               find(missing_hash, broken_seal, gap)
  prioritize(by_value)                  alert(by_severity)
  encrypt(target)                       quarantine(suspect_block)
```

**Wat de Sniffer bewaakt:**

| Check | Wat | Actie bij anomalie |
|-------|-----|-------------------|
| Block hash mismatch | SHA256 van blok != verwachte hash | QUARANTINE + TIBET incident |
| Missing seal | Ed25519 handtekening ontbreekt | BLOCK + alert |
| Manifest gat | Block N bestaat, N+1 mist, N+2 bestaat | INVESTIGATE + gap fill |
| Onleesbaar blok | Decompressie faalt (corrupt of getampered) | ISOLATE + recovery trigger |
| Onbekend formaat | Block header is geen .tza magic bytes | REJECT + forensic snapshot |
| Dubbele seq | Twee blocks claimen dezelfde sequence | CONFLICT RESOLUTION |
| Timestamp anomalie | Block timestamp in de toekomst of ver verleden | FLAG + manual review |

### 2. De Prioriteerder (CONTI: "belangrijkste eerst")

CONTI versleutelt eerst de meest waardevolle bestanden (databases, backups).
Wij prioriteren MUX verkeer op dezelfde manier:

```
MUX Prioriteit (CONTI-geinspireerd):

  Priority 0: SYSTEM (heartbeat, watchdog, bus control)
    -> Nooit vertragen, nooit filteren
    -> CONTI equivalent: "skip system files to avoid detection"

  Priority 1: VERIFIED (gesignde responses, JIS-cleared tokens)
    -> Voorrang op alles behalve system
    -> CONTI equivalent: "encrypt high-value targets first"

  Priority 2: SUSPECT (gefaalde verificatie, retry na error)
    -> Throttle, extra inspectie
    -> CONTI equivalent: "re-scan files that failed first pass"

  Priority 3: BULK (logging, metrics, background sync)
    -> Laagste prioriteit, mag wachten
    -> CONTI equivalent: "encrypt remaining files last"
```

### 3. De Matroesjka Detector

Dit is de critieke verdediging. Een matroesjka-aanval is:
- Payload A bevat Payload B bevat Payload C
- Elke laag lijkt onschuldig
- Pas als alle lagen uitgepakt zijn, wordt de aanval zichtbaar

CONTI is hier goed in (omgekeerd): het detecteert geneste encryptie om
te voorkomen dat het al-versleutelde data opnieuw versleutelt.

Wij gebruiken dezelfde detectie om geneste aanvallen te vinden:

```
Matroesjka Detectie Pipeline:

  Inkomend blok
    |
    +-- Laag 1: Is het een .tza? Check magic bytes (TBZ)
    |     JA -> verify seal -> decompress -> check inhoud
    |     NEE -> verdacht, maar kan legitimate data zijn
    |
    +-- Laag 2: Bevat de gedecomprimeerde inhoud WEER een .tza?
    |     JA -> MATROESJKA ALERT (nesting depth > 1)
    |           -> Maximale nesting depth = configureerbaar (default: 2)
    |           -> Elke laag MOET eigen geldige seal hebben
    |           -> Missende seal op binnenlaag = QUARANTINE
    |     NEE -> normaal blok, doorlaten
    |
    +-- Laag 3: Entropy analyse
    |     Hoge entropy (>7.5 bits/byte) op gedecomprimeerde data
    |     = mogelijk versleuteld/geobfusceerd
    |     -> FLAG voor handmatige inspectie
    |     -> CONTI technique: entropy scan om encrypted files te skippen
    |
    +-- Laag 4: Bekende patronen
          Zoek naar shellcode signatures, known exploit patterns
          in gedecomprimeerde inhoud
          -> SNAFT poison rules (bestaande 22 regels)
          -> Uitbreiden met binary pattern matching
```

---

## Architectuur: Sniffer Daemon

De Sniffer draait als achtergrond-process naast de Trust Kernel:

```
+-------------------------------------------------------+
|  Trust Kernel (voorproever + archivaris)               |
|    |                                                   |
|    +-- [normaal pad: request -> response]              |
|                                                        |
|  Sniffer Daemon (CONTI-defensief)                      |
|    |                                                   |
|    +-- Block Scanner                                   |
|    |     Continu: loop over block_table                |
|    |     Check: hash, seal, manifest, format           |
|    |     Frequentie: elke N seconden (configureerbaar) |
|    |                                                   |
|    +-- Stream Monitor                                  |
|    |     Inline: kijkt mee op MUX token stream         |
|    |     Check: entropy, nesting, anomalieen           |
|    |     Latency budget: <1us per token (mag niet      |
|    |     vertragen)                                    |
|    |                                                   |
|    +-- Manifest Auditor                                |
|    |     Periodiek: vergelijk manifest met werkelijke  |
|    |     blocks op disk/remote                         |
|    |     Check: gaten, dubbelen, orphans               |
|    |                                                   |
|    +-- Matroesjka Detector                             |
|          Bij elke decompressie: check nesting depth    |
|          Bij hoge entropy: flag voor review            |
|          Bij onbekende inner format: quarantine        |
+-------------------------------------------------------+
```

---

## Modules (te bouwen)

| Module | File | Functie |
|--------|------|---------|
| Block Scanner | `sniffer_blocks.rs` | Continu hash/seal/format verificatie van block table |
| Stream Monitor | `sniffer_stream.rs` | Inline token stream anomalie detectie |
| Manifest Auditor | `sniffer_manifest.rs` | Periodieke manifest vs werkelijkheid check |
| Matroesjka Detector | `sniffer_nesting.rs` | Nesting depth + entropy analyse |
| Quarantine Engine | `quarantine.rs` | Isolatie van verdachte blocks, forensic snapshot |
| Priority Manager | `mux_priority.rs` | CONTI-geinspireerde verkeersprioriteit |

Integratie met bestaand:
- `snaft.rs` -> poison rules uitbreiden met binary patterns
- `watchdog.rs` -> sniffer heartbeat monitoring
- `archivaris.rs` -> quarantine output pad
- `mux.rs` -> priority manager inline
- `config.rs` -> sniffer_enabled, nesting_max_depth, entropy_threshold

---

## Matroesjka Verdedigingsniveaus

```
[profile.paranoid]
sniffer_enabled = true
sniffer_interval_ms = 1000
nesting_max_depth = 1          # Geen nesting toegestaan
entropy_threshold = 7.0        # Streng
block_scan_on_restore = true   # Scan bij elke page-in
stream_monitor_inline = true   # Kijkt mee op elke token

[profile.balanced]
sniffer_enabled = true
sniffer_interval_ms = 5000
nesting_max_depth = 2          # 1 laag nesting OK
entropy_threshold = 7.5
block_scan_on_restore = false  # Alleen periodiek
stream_monitor_inline = true

[profile.fast]
sniffer_enabled = false        # Dev/test: uit
```

---

## De Kern

> Ransomware is het meest geavanceerde bestandssysteem-bewakingsprogramma
> dat ooit geschreven is. Het probleem is alleen dat het voor de verkeerde
> kant werkt. Wij draaien het om.

CONTI's kracht:
- Sniffen naar waardevolle data -> Sniffen naar corrupte/getamperde blocks
- Prioriteren van encryptie -> Prioriteren van MUX verkeer
- Detecteren van backups -> Detecteren van matroesjka-aanvallen
- Vermijden van detectie -> Vermijden van false positives

Trust Kernel + CONTI-defensief = immuunsysteem dat de aanvaller's eigen
technieken tegen hem gebruikt.

---

## Airlock Bifurcatie — Encrypt-by-Default

### Het Inzicht

CONTI versleutelt elk blok en eist betaling voor de sleutel.
Wij doen exact hetzelfde — maar de sleutel is je identiteit.

```
CONTI:          Data → AES-256 encrypt → "Betaal Bitcoin" → decrypt
Trust Kernel:   Data → AES-256 encrypt → "Bewijs wie je bent" → decrypt
```

Zelfde crypto. Andere kant.

### Airlock Bifurcatie

Het **bifurcatiepunt** is de Airlock: het moment waarop data twee
fundamenteel verschillende paden kan nemen op basis van één vraag:
*Heb je een geldige JIS claim?*

```
     Inkomende data
          │
    ┌─────┴─────┐
    │  AIRLOCK   │  ← bifurcatiepunt
    │  (encrypt) │
    └─────┬─────┘
          │
     JIS claim?
      /       \
    JA         NEE
    │           │
 DECRYPT     BLIJFT
    │        ENCRYPTED
    │           │
    ▼           ▼
 Levende     Cryptografisch
 data        dood materiaal
```

### Data at Rest = Altijd Encrypted

Elke .tza block op disk is **standaard versleuteld**:

```
.tza block (data at rest):
  ┌─────────────────────────────────────────────┐
  │ Header: TBZ magic bytes + manifest          │  ← leesbaar (metadata)
  │ Payload: zstd + AES-256-GCM encrypted       │  ← ONLEESBAAR zonder JIS
  │ Seal: Ed25519 signature                     │  ← integriteit bewijs
  │ TIBET token: wie, wanneer, waarom, waarvoor │  ← audit trail
  └─────────────────────────────────────────────┘
```

Zonder JIS claim is dit een waardeloos blok bytes. Net als ransomware.
Maar **by design**, niet by exploit.

### De Identiteit IS de Sleutel

Geen centrale key server. De decryptiesleutel wordt **afgeleid** van
de JIS claim zelf:

```
Sleutelafleiding:

  1. IDD/mens presenteert JIS claim
     (clearance, role, dept, geo, time)

  2. JIS verificatie door Cortex
     → Ed25519 keypair van de IDD/mens

  3. Key agreement
     → Ed25519 → X25519 (Diffie-Hellman)
     → Per-block AES-256-GCM key afgeleid

  4. Decrypt
     → Block payload ontsleuteld
     → zstd decompressie
     → Leesbare data

  5. TIBET token aangemaakt
     → "IDD root_idd opende block 42 om 09:47
        met clearance CONFIDENTIAL voor doel X"
```

### Waarom Dit Werkt

| Eigenschap | Ransomware | Airlock Bifurcatie |
|------------|------------|-------------------|
| Encryptie | AES-256 | AES-256-GCM |
| Sleutel bij | Crimineel (Bitcoin wallet) | Identiteit (JIS claim) |
| Sleutel server | C2 server | Geen — gedistribueerd |
| Verlies sleutel | Data weg | Claim opnieuw, audit trail |
| Audit | Geen | Elk open/dicht = TIBET token |
| Doel | Afpersing | Bescherming by default |

### Wat Dit Betekent voor de Stack

De Archivaris krijgt een nieuwe verantwoordelijkheid:

```
Archivaris (huidige flow):
  receive(block) → verify(seal) → compress(zstd) → store(disk)

Archivaris (met Airlock Bifurcatie):
  receive(block) → verify(seal) → compress(zstd)
    → ENCRYPT(AES-256-GCM, derived_key) → store(disk)

  retrieve(block, jis_claim) → verify(claim) → load(disk)
    → DECRYPT(AES-256-GCM, derived_key) → decompress(zstd) → serve
```

Bestaande componenten die al klaar zijn:
- ✅ Ed25519 — in .tza engine
- ✅ JIS claims — in tibet-cortex
- ✅ Archivaris — append-only opslag
- ✅ TIBET tokens — audit trail
- ✅ zstd compressie — in snapshot engine

Toe te voegen:
- [ ] `archivaris.rs` → encrypt-on-write, decrypt-on-read
- [ ] X25519 key agreement (Ed25519 → Curve25519 conversie)
- [ ] Per-block key derivation (HKDF-SHA256)
- [ ] JIS claim verificatie in hot-path

### De Filosofie

> Data hoort niet onbeschermd op een disk te staan.
> Niet "misschien versleuteld". Niet "als je eraan denkt".
> **Altijd.** Standaard. Zonder uitzondering.
>
> De enige manier om data te lezen is te bewijzen wie je bent.
> Niet een wachtwoord. Niet een token. Jouw cryptografische identiteit.
>
> Ransomware bewees dat encrypt-everything werkt.
> Wij bewijzen dat het ook voor de goede kant kan werken.
>
> — Airlock Bifurcatie, april 2026
