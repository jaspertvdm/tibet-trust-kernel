#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Trust Kernel — Hardware Feature Detection & Activation
# Scant, activeert wat kan, rapporteert wat latent aanwezig is
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TK_PID="${1:-}"  # Optioneel: Trust Kernel PID voor CAT toewijzing

echo "═══════════════════════════════════════════════════════════"
echo "  Trust Kernel — Hardware Feature Scan"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "═══════════════════════════════════════════════════════════"
echo ""

FLAGS=$(grep flags /proc/cpuinfo | head -1)
ACTIVATED=0
LATENT=0
MISSING=0

check_flag() {
    echo "$FLAGS" | grep -qw "$1"
}

status() {
    local name="$1" flag="$2" desc="$3" action="$4"
    if check_flag "$flag"; then
        if [ "$action" = "active" ]; then
            echo -e "  ${GREEN}✅ ACTIEF${NC}  $name — $desc"
            ((ACTIVATED++))
        else
            echo -e "  ${YELLOW}💤 LATENT${NC}  $name — $desc"
            ((LATENT++))
        fi
    else
        echo -e "  ${RED}❌ AFWEZIG${NC} $name — $desc"
        ((MISSING++))
    fi
}

# ── §1: Crypto ──
echo "── Crypto Acceleratie ──"
status "AES-NI" "aes" "AES-256-GCM in hardware (Bifurcatie)" "active"
if check_flag "sha_ni"; then
    status "SHA-NI" "sha_ni" "SHA-256 in hardware" "active"
else
    echo -e "  ${RED}❌ AFWEZIG${NC} SHA-NI — SHA-256 draait in software (nog steeds snel via sha2 crate)"
    ((MISSING++))
fi
echo ""

# ── §2: Random ──
echo "── Random Number Generation ──"
status "RDRAND" "rdrand" "Hardware PRNG voor nonces" "active"
if check_flag "rdseed"; then
    status "RDSEED" "rdseed" "Echte entropy seeds (sterker dan RDRAND)" "latent"
else
    echo -e "  ${RED}❌ AFWEZIG${NC} RDSEED — Gebruikt /dev/urandom als seed bron"
    ((MISSING++))
fi
echo ""

# ── §3: SIMD ──
echo "── SIMD / Parallelle Operaties ──"
status "AVX2" "avx2" "256-bit SIMD (batch hashing, memcpy)" "active"
if check_flag "avx512f"; then
    AVX512_COUNT=$(echo "$FLAGS" | tr ' ' '\n' | grep -c "avx512")
    echo -e "  ${GREEN}✅ ACTIEF${NC}  AVX-512 — ${AVX512_COUNT} extensies (512-bit parallelle crypto)"
    ((ACTIVATED++))
else
    echo -e "  ${RED}❌ AFWEZIG${NC} AVX-512 — Niet beschikbaar, AVX2 wordt gebruikt"
    ((MISSING++))
fi
echo ""

# ── §4: Cache Control ──
echo "── Cache & Memory Control ──"
if check_flag "cat_l3"; then
    echo -e "  ${YELLOW}💤 LATENT${NC}  CAT L3 — Cache Allocation Technology beschikbaar"
    ((LATENT++))

    # Check of resctrl gemount is
    if mountpoint -q /sys/fs/resctrl 2>/dev/null; then
        echo -e "         resctrl: ${GREEN}gemount${NC}"
        CBM=$(cat /sys/fs/resctrl/info/L3/cbm_mask 2>/dev/null || echo "?")
        CLOSIDS=$(cat /sys/fs/resctrl/info/L3/num_closids 2>/dev/null || echo "?")
        echo "         L3 bitmask: $CBM | CLOS IDs: $CLOSIDS"
    else
        echo -e "         resctrl: ${YELLOW}niet gemount${NC}"
        echo "         Activeer: mount -t resctrl resctrl /sys/fs/resctrl"
    fi

    # Activeer als PID meegegeven
    if [ -n "$TK_PID" ]; then
        echo ""
        echo -e "  ${BLUE}→ ACTIVEER${NC} CAT voor PID $TK_PID..."
        if mountpoint -q /sys/fs/resctrl 2>/dev/null; then
            mkdir -p /sys/fs/resctrl/trust-kernel 2>/dev/null || true
            # Reserveer 25% van L3 ways
            FULL_MASK=$(cat /sys/fs/resctrl/info/L3/cbm_mask 2>/dev/null)
            # Neem de onderste kwart van de bits
            echo "L3:0=000f" > /sys/fs/resctrl/trust-kernel/schemata 2>/dev/null && \
                echo "$TK_PID" > /sys/fs/resctrl/trust-kernel/tasks 2>/dev/null && \
                echo -e "  ${GREEN}✅ CAT ACTIEF${NC} — Trust Kernel PID $TK_PID heeft gereserveerde L3 cache" && \
                ((ACTIVATED++)) || \
                echo -e "  ${RED}✗ CAT activatie gefaald${NC}"
        fi
    fi
else
    echo -e "  ${RED}❌ AFWEZIG${NC} CAT L3 — Geen cache partitioning beschikbaar"
    ((MISSING++))
fi

if check_flag "mba"; then
    echo -e "  ${YELLOW}💤 LATENT${NC}  MBA — Memory Bandwidth Allocation (DMA throttling)"
    ((LATENT++))
else
    echo -e "  ${RED}❌ AFWEZIG${NC} MBA — Memory bandwidth niet partitioneerbaar"
    ((MISSING++))
fi
echo ""

# ── §5: Security ──
echo "── Hardware Security ──"
status "SMEP" "smep" "Supervisor Mode Execution Prevention" "active"
status "SMAP" "smap" "Supervisor Mode Access Prevention" "active"

if check_flag "pku"; then
    echo -e "  ${YELLOW}⚠️  AANWEZIG${NC} PKU/WRPKRU — Hackgevoelig! Blokkeer via seccomp (pkey_alloc/free/mprotect)"
else
    echo -e "  ${GREEN}✅ VEILIG${NC}  PKU/WRPKRU — Niet aanwezig op deze CPU = geen risico"
fi

if check_flag "shstk"; then
    status "CET-SS" "shstk" "Shadow Stack (anti-ROP)" "latent"
else
    echo -e "  ${RED}❌ AFWEZIG${NC} CET Shadow Stack — ROP bescherming via software (seccomp+SNAFT)"
    ((MISSING++))
fi
echo ""

# ── §6: Forensics & Monitoring ──
echo "── Forensics & Monitoring ──"
if check_flag "intel_pt"; then
    echo -e "  ${YELLOW}💤 LATENT${NC}  Intel PT — Processor Trace (instructie-level audit)"
    echo "         Activeer: perf record -e intel_pt// -p \$PID"
    ((LATENT++))
else
    echo -e "  ${RED}❌ AFWEZIG${NC} Intel PT — Geen hardware trace beschikbaar"
    ((MISSING++))
fi

# PMU is altijd beschikbaar op x86
echo -e "  ${YELLOW}💤 LATENT${NC}  PMU+NMI — Performance counters voor hardware watchdog"
echo "         Activeer: perf_event_open() met overflow NMI"
((LATENT++))
echo ""

# ── §7: VM Isolatie ──
echo "── VM & Encryptie ──"
if check_flag "tme"; then
    status "TME" "tme" "Total Memory Encryption (RAM altijd encrypted)" "latent"
else
    echo -e "  ${RED}❌ AFWEZIG${NC} TME — RAM niet hardware-encrypted (software Bifurcatie compenseert)"
    ((MISSING++))
fi

if [ -e /dev/sev ]; then
    echo -e "  ${YELLOW}💤 LATENT${NC}  AMD SEV — Secure Encrypted Virtualization"
    ((LATENT++))
else
    echo -e "  ${RED}❌ AFWEZIG${NC} AMD SEV/TDX — VM memory niet hardware-isolated"
    ((MISSING++))
fi
echo ""

# ── Samenvatting ──
echo "═══════════════════════════════════════════════════════════"
echo -e "  ${GREEN}ACTIEF:${NC}  $ACTIVATED features (direct in gebruik)"
echo -e "  ${YELLOW}LATENT:${NC}  $LATENT features (beschikbaar, te activeren)"
echo -e "  ${RED}AFWEZIG:${NC} $MISSING features (niet op deze CPU)"
echo "═══════════════════════════════════════════════════════════"

# ── Aanbevelingen ──
echo ""
echo "── Aanbevelingen ──"

if check_flag "cat_l3" && ! [ -d /sys/fs/resctrl/trust-kernel ]; then
    echo "  1. CAT L3: $0 \$TK_PID  (reserveer L3 cache voor Trust Kernel)"
fi
if check_flag "intel_pt"; then
    echo "  2. Intel PT: perf record -e intel_pt// voor forensische traces"
fi
if check_flag "rdseed"; then
    echo "  3. RDSEED: Activeer in bifurcation.rs voor sterkere nonce seeds"
fi
if check_flag "mba"; then
    echo "  4. MBA: Throttle bulk I/O memory bandwidth voor stabielere latency"
fi
echo "  5. Compile met: RUSTFLAGS=\"-C target-cpu=native\" cargo build --release"
echo ""
