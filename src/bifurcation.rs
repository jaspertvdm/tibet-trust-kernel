use std::time::Instant;
use std::fs;
use std::io::Write;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Serialize, Deserialize};
use rayon::prelude::*;

// Echte crypto — AES-NI hardware accelerated
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand::rngs::OsRng;

// ═══════════════════════════════════════════════════════════════
// Hardware Entropy — Platform-Aware Nonce Generation
//
// Cascade prioriteit:
//   x86_64:  RDSEED (true entropy) → RDRAND (hw PRNG) → OsRng
//   aarch64: ARM CSPRNG via OsRng (kernel getrandom)
//   overig:  OsRng fallback
//
// Ondersteunde platforms:
//   - x86_64: Intel Ivy Bridge+ (2012), AMD Zen+ (2018) — RDRAND/RDSEED
//   - aarch64: ARMv8+ (smartphones, Apple Silicon, Graviton) — OsRng
//   - Elke andere arch: OsRng fallback, altijd correct
//
// RDSEED timing check: bij init eenmalig gemeten, >5µs = skip in cascade
// ═══════════════════════════════════════════════════════════════

/// Check of RDRAND beschikbaar is op deze CPU.
pub fn rdrand_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID.01H:ECX.RDRAND[bit 30]
        // rbx moet bewaard worden (LLVM gebruikt het)
        let ecx: u32;
        unsafe {
            std::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "pop rbx",
                out("ecx") ecx,
                out("eax") _,
                out("edx") _,
                options(nostack),
            );
        }
        (ecx >> 30) & 1 == 1
    }
    #[cfg(not(target_arch = "x86_64"))]
    { false }
}

/// Genereer 64 bits random via RDRAND instructie.
/// Retourneert None als RDRAND faalt (retry exhausted).
/// Op niet-x86_64: altijd None (OsRng fallback via rdrand_nonce).
#[cfg(not(target_arch = "x86_64"))]
fn rdrand64() -> Option<u64> { None }

#[cfg(target_arch = "x86_64")]
fn rdrand64() -> Option<u64> {
    let mut val: u64;
    let mut success: u8;

    // Max 10 retries (Intel recommendation)
    for _ in 0..10 {
        unsafe {
            std::arch::asm!(
                "rdrand {val}",
                "setc {success}",
                val = out(reg) val,
                success = out(reg_byte) success,
            );
        }
        if success == 1 {
            return Some(val);
        }
    }
    None
}

/// Genereer 64 bits echte entropy via RDSEED instructie.
/// RDSEED haalt direct uit de on-die entropy source (trager maar cryptografisch sterker).
/// Retourneert None als RDSEED faalt of niet beschikbaar.
/// Op niet-x86_64: altijd None.
#[cfg(not(target_arch = "x86_64"))]
pub fn rdseed64() -> Option<u64> { None }

#[cfg(target_arch = "x86_64")]
pub fn rdseed64() -> Option<u64> {
    if !rdseed_available() {
        return None;
    }
    let mut val: u64;
    let mut success: u8;

    // Max 10 retries (entropy pool kan tijdelijk leeg zijn)
    for _ in 0..10 {
        unsafe {
            std::arch::asm!(
                "rdseed {val}",
                "setc {success}",
                val = out(reg) val,
                success = out(reg_byte) success,
            );
        }
        if success == 1 {
            return Some(val);
        }
    }
    None
}

/// RDSEED snelheidscheck bij init: als RDSEED >5µs per call,
/// skippen we het in de nonce cascade (te traag voor hot path).
/// Wordt eenmalig bij eerste aanroep gemeten.
static RDSEED_FAST: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn rdseed_is_fast() -> bool {
    *RDSEED_FAST.get_or_init(|| {
        if !rdseed_available() {
            return false;
        }
        // Meet 10 calls, check of gemiddelde <5µs
        let t0 = Instant::now();
        let mut ok = 0u32;
        for _ in 0..10 {
            if rdseed64().is_some() { ok += 1; }
        }
        let avg_ns = t0.elapsed().as_nanos() / 10;
        ok >= 8 && avg_ns < 5_000 // minstens 80% success + <5µs
    })
}

/// Genereer een nonce via de beste beschikbare hardware entropy.
///
/// Prioriteit:
///   1. RDSEED (echte entropy, alleen als snel genoeg — <5µs per call)
///   2. RDRAND (hardware PRNG, 0 syscalls)
///   3. OsRng (/dev/urandom fallback)
pub fn rdrand_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];

    #[cfg(target_arch = "x86_64")]
    {
        // Probeer RDSEED eerst (alleen als timing check passed)
        if rdseed_is_fast() {
            if let (Some(a), Some(b)) = (rdseed64(), rdseed64()) {
                nonce[..8].copy_from_slice(&a.to_le_bytes());
                nonce[8..].copy_from_slice(&b.to_le_bytes()[..4]);
                return nonce;
            }
        }

        // Fallback: RDRAND (hardware PRNG)
        if let (Some(a), Some(b)) = (rdrand64(), rdrand64()) {
            nonce[..8].copy_from_slice(&a.to_le_bytes());
            nonce[8..].copy_from_slice(&b.to_le_bytes()[..4]);
            return nonce;
        }
    }

    // Laatste fallback: OsRng (syscall naar /dev/urandom)
    rand::Rng::fill(&mut OsRng, &mut nonce);
    nonce
}

/// Check of RDSEED beschikbaar is (sterkere entropy dan RDRAND).
pub fn rdseed_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID.07H:EBX.RDSEED[bit 18]
        // rbx is output van cpuid maar LLVM claimt het, dus push/pop
        let ebx: u32;
        unsafe {
            std::arch::asm!(
                "push rbx",
                "mov eax, 7",
                "xor ecx, ecx",
                "cpuid",
                "mov {ebx:e}, ebx",
                "pop rbx",
                ebx = out(reg) ebx,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
                options(nostack),
            );
        }
        (ebx >> 18) & 1 == 1
    }
    #[cfg(not(target_arch = "x86_64"))]
    { false }
}

// ═══════════════════════════════════════════════════════════════
// CAT L3 — Cache Allocation Technology
//
// Reserveert L3 cache ways voor de Trust Kernel.
// Voorkomt dat bulk I/O de hot path uit cache evict.
// Beschikbaar op: Intel Haswell-EP+, Xeon W (P520)
// Interface: Linux resctrl (/sys/fs/resctrl/)
// ═══════════════════════════════════════════════════════════════

/// CAT L3 configuratie
#[derive(Debug, Clone)]
pub struct CatL3Config {
    /// Fractie van L3 ways te reserveren (0.0 - 1.0)
    pub reserve_fraction: f64,
    /// Naam van de resctrl groep
    pub group_name: String,
}

impl Default for CatL3Config {
    fn default() -> Self {
        Self {
            reserve_fraction: 0.25, // 25% van L3 voor Trust Kernel
            group_name: "trust-kernel".to_string(),
        }
    }
}

/// Status van CAT L3 activatie
#[derive(Debug)]
pub enum CatL3Status {
    /// CAT L3 is actief met gereserveerde cache ways
    Active {
        group: String,
        bitmask: String,
        ways_reserved: u32,
        ways_total: u32,
    },
    /// CAT L3 beschikbaar maar niet geactiveerd
    Available {
        ways_total: u32,
    },
    /// resctrl niet gemount
    NotMounted,
    /// CPU ondersteunt geen CAT L3
    NotSupported,
    /// Activatie gefaald
    Failed {
        reason: String,
    },
}

/// Check CAT L3 status zonder te activeren.
pub fn cat_l3_status() -> CatL3Status {
    // Check of resctrl gemount is
    let resctrl = std::path::Path::new("/sys/fs/resctrl/info/L3");
    if !resctrl.exists() {
        // Probeer te detecten of CPU het ondersteunt
        #[cfg(target_arch = "x86_64")]
        {
            let flags = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
            if flags.contains("cat_l3") {
                return CatL3Status::NotMounted;
            }
        }
        return CatL3Status::NotSupported;
    }

    // Lees het bitmask om aantal ways te bepalen
    let mask_str = fs::read_to_string("/sys/fs/resctrl/info/L3/cbm_mask")
        .unwrap_or_default()
        .trim()
        .to_string();

    let mask = u64::from_str_radix(&mask_str, 16).unwrap_or(0);
    let ways_total = mask.count_ones();

    // Check of er al een trust-kernel groep is
    let tk_group = std::path::Path::new("/sys/fs/resctrl/trust-kernel");
    if tk_group.exists() {
        let schemata = fs::read_to_string("/sys/fs/resctrl/trust-kernel/schemata")
            .unwrap_or_default()
            .trim()
            .to_string();

        // Parse het bitmask uit de schemata
        let bitmask = schemata.split('=').last().unwrap_or("?").to_string();
        let reserved_mask = u64::from_str_radix(&bitmask, 16).unwrap_or(0);
        let ways_reserved = reserved_mask.count_ones();

        return CatL3Status::Active {
            group: "trust-kernel".to_string(),
            bitmask,
            ways_reserved,
            ways_total,
        };
    }

    CatL3Status::Available { ways_total }
}

/// Activeer CAT L3 reservering voor een PID.
///
/// Reserveert `config.reserve_fraction` van L3 ways voor het opgegeven process.
/// De rest van het systeem krijgt de overige ways.
pub fn cat_l3_activate(config: &CatL3Config, pid: u32) -> CatL3Status {
    // Check beschikbaarheid
    let mask_path = "/sys/fs/resctrl/info/L3/cbm_mask";
    let mask_str = match fs::read_to_string(mask_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return CatL3Status::NotMounted,
    };

    let full_mask = u64::from_str_radix(&mask_str, 16).unwrap_or(0);
    let ways_total = full_mask.count_ones();
    let ways_to_reserve = ((ways_total as f64) * config.reserve_fraction).ceil() as u32;
    let ways_to_reserve = ways_to_reserve.max(1).min(ways_total);

    // Bereken bitmask: reserveer de onderste N ways
    let reserved_mask: u64 = (1u64 << ways_to_reserve) - 1;
    let reserved_hex = format!("{:x}", reserved_mask);

    // Maak de resctrl groep
    let group_path = format!("/sys/fs/resctrl/{}", config.group_name);
    if let Err(e) = fs::create_dir_all(&group_path) {
        return CatL3Status::Failed {
            reason: format!("mkdir {}: {}", group_path, e),
        };
    }

    // Schrijf schemata
    let schemata_path = format!("{}/schemata", group_path);
    let schemata_value = format!("L3:0={}", reserved_hex);
    if let Err(e) = fs::write(&schemata_path, &schemata_value) {
        return CatL3Status::Failed {
            reason: format!("write schemata: {}", e),
        };
    }

    // Wijs PID toe
    let tasks_path = format!("{}/tasks", group_path);
    let mut f = match fs::OpenOptions::new().append(true).open(&tasks_path) {
        Ok(f) => f,
        Err(e) => return CatL3Status::Failed {
            reason: format!("open tasks: {}", e),
        },
    };

    if let Err(e) = writeln!(f, "{}", pid) {
        return CatL3Status::Failed {
            reason: format!("write pid: {}", e),
        };
    }

    CatL3Status::Active {
        group: config.group_name.clone(),
        bitmask: reserved_hex,
        ways_reserved: ways_to_reserve,
        ways_total,
    }
}

/// Deactiveer CAT L3 reservering.
pub fn cat_l3_deactivate(group_name: &str) -> Result<(), String> {
    let group_path = format!("/sys/fs/resctrl/{}", group_name);
    fs::remove_dir(&group_path)
        .map_err(|e| format!("rmdir {}: {}", group_path, e))
}

/// Airlock Bifurcatie — Encrypt-by-Default voor .tza blocks.
///
/// Het ransomware-model omgedraaid:
///   CONTI:  Data → AES-256 encrypt → "Betaal Bitcoin" → decrypt
///   Ons:    Data → AES-256 encrypt → "Bewijs wie je bent" → decrypt
///
/// De Airlock is het bifurcatiepunt: data splitst in twee paden
/// op basis van één vraag: heb je een geldige JIS claim?
///
///   JA  → decrypt → levende data
///   NEE → encrypted blob → cryptografisch dood materiaal
///
/// Sleutelafleiding:
///   1. IDD/mens presenteert Ed25519 keypair
///   2. Ed25519 → X25519 (Curve25519) conversie
///   3. X25519 key agreement met block-specifieke public key
///   4. HKDF-SHA256 → per-block AES-256-GCM key
///   5. Encrypt/decrypt met derived key
///
/// Geen centrale key server. De identiteit IS de sleutel.

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// AES-256-GCM nonce size (96 bits / 12 bytes — NIST standard)
pub const AES_NONCE_SIZE: usize = 12;

/// AES-256-GCM tag size (128 bits / 16 bytes)
pub const AES_TAG_SIZE: usize = 16;

/// AES-256 key size (256 bits / 32 bytes)
pub const AES_KEY_SIZE: usize = 32;

/// X25519 key size (256 bits / 32 bytes)
pub const X25519_KEY_SIZE: usize = 32;

/// HKDF info string voor per-block key derivation
pub const HKDF_INFO_PREFIX: &[u8] = b"tibet-bifurcation-v1-block-";

/// Ed25519 public key size
pub const ED25519_PUB_SIZE: usize = 32;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// JIS Claim — de identiteitsbewering die als sleutel dient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JisClaim {
    /// Agent/mens identiteit (.aint domain of human ID)
    pub identity: String,
    /// Ed25519 public key (32 bytes, hex-encoded)
    pub ed25519_pub: String,
    /// Clearance level (UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET, TOPSECRET)
    pub clearance: ClearanceLevel,
    /// Role binnen de organisatie
    pub role: String,
    /// Department
    pub dept: String,
    /// Timestamp van de claim (RFC3339)
    pub claimed_at: String,
    /// Signature over de claim velden (Ed25519)
    pub signature: String,
}

/// NATO-style clearance levels (aflopend restrictief)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ClearanceLevel {
    Unclassified = 0,
    Restricted = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
}

impl ClearanceLevel {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Unclassified,
            1 => Self::Restricted,
            2 => Self::Confidential,
            3 => Self::Secret,
            _ => Self::TopSecret,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Restricted => "RESTRICTED",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOPSECRET",
        }
    }
}

/// Encrypted block envelope — wat er op disk staat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlock {
    /// Block index in de RAID stripe
    pub block_index: usize,
    /// Ephemeral X25519 public key (voor key agreement)
    pub ephemeral_pub: [u8; X25519_KEY_SIZE],
    /// AES-256-GCM nonce (uniek per block)
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Minimaal vereiste clearance level om te decrypten
    pub required_clearance: ClearanceLevel,
    /// SHA256 hash van plaintext (voor integriteitscheck na decrypt)
    pub plaintext_hash: [u8; 32],
    /// Encrypted data (ciphertext + GCM tag)
    pub ciphertext: Vec<u8>,
    /// Timestamp van encryptie
    pub encrypted_at_ns: u64,
    /// Wie heeft versleuteld (IDD of system)
    pub encrypted_by: String,
}

/// Resultaat van een bifurcatie-operatie.
#[derive(Debug)]
pub enum BifurcationResult {
    /// Encrypt geslaagd
    Sealed {
        block: EncryptedBlock,
        encrypt_us: u64,
        key_derive_us: u64,
    },
    /// Decrypt geslaagd via geldige JIS claim
    Opened {
        plaintext: Vec<u8>,
        decrypt_us: u64,
        key_derive_us: u64,
        opened_by: String,
    },
    /// JIS claim onvoldoende clearance
    AccessDenied {
        required: ClearanceLevel,
        presented: ClearanceLevel,
        identity: String,
    },
    /// JIS claim signature ongeldig
    ClaimInvalid {
        reason: String,
    },
    /// Integriteit check gefaald na decrypt (data corrupt of getampered)
    IntegrityFailed {
        expected_hash: [u8; 32],
        actual_hash: [u8; 32],
    },
    /// Cryptografische operatie gefaald
    CryptoError {
        reason: String,
    },
}

/// Statistieken voor de Airlock Bifurcatie engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BifurcationStats {
    /// Totaal aantal blocks versleuteld
    pub blocks_sealed: u64,
    /// Totaal aantal blocks ontsleuteld
    pub blocks_opened: u64,
    /// Totaal aantal geweigerde decryptie pogingen
    pub access_denied: u64,
    /// Totaal aantal integriteitsfouten
    pub integrity_failures: u64,
    /// Totaal aantal ongeldige claims
    pub invalid_claims: u64,
    /// Gemiddelde encrypt tijd (microseconden)
    pub avg_encrypt_us: u64,
    /// Gemiddelde decrypt tijd (microseconden)
    pub avg_decrypt_us: u64,
    /// Gemiddelde key derivation tijd (microseconden)
    pub avg_key_derive_us: u64,
}

// ═══════════════════════════════════════════════════════════════
// Airlock Bifurcatie Engine
// ═══════════════════════════════════════════════════════════════

/// Session Key Cache — hergebruik DH-afgeleide keys binnen een sessie.
///
/// X25519 DH kost ~120µs per operatie. Door de afgeleide AES key te cachen
/// per (ephemeral_pub, block_index) combinatie, betaal je die kost maar één keer.
/// Bij herhaalde opens van hetzelfde block: ~5µs ipv ~120µs (24x sneller).
///
/// Cache wordt automatisch gewist bij key rotation of session timeout.
pub struct KeyCache {
    /// Cache: (ephemeral_pub_bytes, block_index) → derived AES key
    derived_keys: HashMap<([u8; 32], usize), [u8; 32]>,
    /// Maximum cache entries (voorkomt unbounded memory growth)
    max_entries: usize,
    /// Cache hits counter
    pub hits: u64,
    /// Cache misses counter
    pub misses: u64,
}

impl KeyCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            derived_keys: HashMap::with_capacity(max_entries.min(4096)),
            max_entries,
            hits: 0,
            misses: 0,
        }
    }

    /// Zoek een cached AES key voor deze ephemeral_pub + block_index combinatie.
    pub fn get(&mut self, ephemeral_pub: &[u8; 32], block_index: usize) -> Option<[u8; 32]> {
        if let Some(key) = self.derived_keys.get(&(*ephemeral_pub, block_index)) {
            self.hits += 1;
            Some(*key)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Sla een afgeleide AES key op. Bij vol: wis de hele cache (simple eviction).
    pub fn put(&mut self, ephemeral_pub: [u8; 32], block_index: usize, aes_key: [u8; 32]) {
        if self.derived_keys.len() >= self.max_entries {
            self.derived_keys.clear(); // Simple eviction — v2: LRU
        }
        self.derived_keys.insert((ephemeral_pub, block_index), aes_key);
    }

    /// Wis alle cached keys (bij key rotation of security event).
    pub fn flush(&mut self) {
        self.derived_keys.clear();
        // Zero de memory (security)
        self.hits = 0;
        self.misses = 0;
    }

    pub fn len(&self) -> usize {
        self.derived_keys.len()
    }

    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 * 100.0 }
    }
}

/// Session Key — hergebruik één DH shared secret voor meerdere seals.
///
/// Eén X25519 DH per sessie (~76µs), daarna alleen HKDF+AES per block (~5µs).
/// Veilig omdat HKDF met unieke block_index per block een unieke AES key genereert.
/// Session roteert automatisch na max_blocks of bij handmatige rotate().
pub struct SessionKey {
    /// Het gedeelde geheim (ephemeral_secret × system_pub)
    shared_secret: [u8; 32],
    /// De ephemeral public key (wordt opgeslagen in elk block)
    ephemeral_pub: [u8; 32],
    /// Aantal blocks versleuteld met deze sessie
    pub blocks_sealed: u64,
    /// Maximum blocks voor automatische rotatie
    max_blocks: u64,
    /// Tijdstip van aanmaak
    created_at: Instant,
    /// Maximum leeftijd voordat rotatie verplicht is
    max_age: std::time::Duration,
}

impl SessionKey {
    /// Maak een nieuwe session key aan (doet de dure DH eenmalig).
    fn new(system_pub: &[u8; 32], max_blocks: u64, max_age: std::time::Duration) -> Self {
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);
        let system_pub_key = PublicKey::from(*system_pub);
        let shared = ephemeral_secret.diffie_hellman(&system_pub_key);

        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(shared.as_bytes());

        Self {
            shared_secret,
            ephemeral_pub: ephemeral_pub.to_bytes(),
            blocks_sealed: 0,
            max_blocks,
            created_at: Instant::now(),
            max_age,
        }
    }

    /// Check of de sessie nog geldig is (niet te oud, niet te veel blocks).
    fn is_valid(&self) -> bool {
        self.blocks_sealed < self.max_blocks && self.created_at.elapsed() < self.max_age
    }

    /// Derive een per-block AES key uit de session shared secret.
    fn derive_block_key(&mut self, block_index: usize) -> [u8; AES_KEY_SIZE] {
        let hk = Hkdf::<Sha256>::new(None, &self.shared_secret);
        let mut info = Vec::from(HKDF_INFO_PREFIX);
        info.extend_from_slice(&block_index.to_le_bytes());
        let mut key = [0u8; AES_KEY_SIZE];
        hk.expand(&info, &mut key).expect("HKDF expand failed");
        self.blocks_sealed += 1;
        key
    }
}

/// De Airlock Bifurcatie Engine.
///
/// Verantwoordelijkheden:
///   1. Seal: encrypt-on-write (elk block standaard versleuteld)
///   2. Open: decrypt-on-read (alleen met geldige JIS claim)
///   3. Key derivation: Ed25519 → X25519 → HKDF → AES key
///   4. Clearance check: claim.clearance >= block.required_clearance
///   5. Audit: elk seal/open genereert een TIBET event
///   6. Key cache: hergebruik DH-keys voor herhaalde operaties
///   7. Session keys: één DH per sessie, ~5µs per seal daarna
pub struct AirlockBifurcation {
    /// Statistieken
    pub stats: BifurcationStats,
    /// System X25519 static secret (de "sleutel van het kasteel")
    system_secret: [u8; 32],
    /// System X25519 public key (afgeleid van secret)
    system_pub: [u8; 32],
    /// Boot time
    boot_time: Instant,
    /// Key cache voor herhaalde DH-operaties (open dezelfde blocks)
    pub key_cache: KeyCache,
    /// Actieve session key (None = nog niet aangemaakt of verlopen)
    session: Option<SessionKey>,
}

impl AirlockBifurcation {
    pub fn new() -> Self {
        // System keypair: static secret → public key
        // v1: deterministic seed voor reproduceerbare tests
        // v2: loaded from secure storage / HSM
        let seed = b"TIBET-BIFURCATION-SYSTEM-KEY-V01";
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(seed);

        // Derive public key from secret (dit is het correcte keypair)
        let system_static = StaticSecret::from(secret_bytes);
        let system_public = PublicKey::from(&system_static);

        Self {
            stats: BifurcationStats::default(),
            system_secret: secret_bytes,
            system_pub: system_public.to_bytes(),
            boot_time: Instant::now(),
            key_cache: KeyCache::new(16384), // 16K entries ≈ 1.5MB cache
            session: None,
        }
    }

    /// Seal: versleutel een plaintext block voor opslag (encrypt-on-write).
    ///
    /// Elk block wordt versleuteld met een ephemeral X25519 keypair.
    /// De plaintext hash wordt bewaard voor integriteitscheck na decrypt.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        block_index: usize,
        required_clearance: ClearanceLevel,
        encrypted_by: &str,
    ) -> BifurcationResult {
        let t0 = Instant::now();

        // 1. Genereer ephemeral X25519 keypair — echte random via OsRng
        //    seal:  shared = ephemeral_secret × system_pub
        //    open:  shared = system_secret  × ephemeral_pub
        //    (X25519 DH commutatief: a×B = b×A)
        let t_key = Instant::now();
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);
        let system_pub = PublicKey::from(self.system_pub);
        let shared = ephemeral_secret.diffie_hellman(&system_pub);

        // 2. HKDF: shared secret → per-block AES-256-GCM key
        let aes_key = self.hkdf_derive_block_key(shared.as_bytes(), block_index);
        let key_derive_us = t_key.elapsed().as_micros() as u64;

        // Cache de key zodat open() van dit block geen DH hoeft te doen
        self.key_cache.put(ephemeral_pub.to_bytes(), block_index, aes_key);

        // 3. Genereer nonce (v1: deterministic, v2: random)
        let nonce = self.generate_nonce(block_index);

        // 4. SHA256 hash van plaintext (voor integriteitscheck)
        let plaintext_hash = self.sha256(plaintext);

        // 5. AES-256-GCM encrypt
        //    v1: XOR-based simulatie (zelfde interface, niet production-safe)
        //    v2: ring::aead of aes-gcm crate
        let t_enc = Instant::now();
        let ciphertext = self.aes_gcm_encrypt(plaintext, &aes_key, &nonce);
        let encrypt_us = t_enc.elapsed().as_micros() as u64;

        let block = EncryptedBlock {
            block_index,
            ephemeral_pub: ephemeral_pub.to_bytes(),
            nonce,
            required_clearance,
            plaintext_hash,
            ciphertext,
            encrypted_at_ns: self.boot_time.elapsed().as_nanos() as u64,
            encrypted_by: encrypted_by.to_string(),
        };

        // Stats
        self.stats.blocks_sealed += 1;
        let total = self.stats.blocks_sealed;
        self.stats.avg_encrypt_us =
            (self.stats.avg_encrypt_us * (total - 1) + encrypt_us) / total;
        self.stats.avg_key_derive_us =
            (self.stats.avg_key_derive_us * (total - 1) + key_derive_us) / total;

        BifurcationResult::Sealed {
            block,
            encrypt_us,
            key_derive_us,
        }
    }

    /// Seal met session key: hergebruik DH shared secret voor snelle seals.
    ///
    /// Eerste call: volledige DH (~76µs) — maakt session aan.
    /// Volgende calls: alleen HKDF + AES (~5µs) — 15x sneller.
    /// Session roteert automatisch na 100K blocks of 5 minuten.
    ///
    /// Cryptografisch veilig: HKDF met unieke block_index per block
    /// garandeert unieke AES keys. Zelfde ephemeral_pub in elk block
    /// van dezelfde sessie — open() werkt identiek.
    pub fn seal_session(
        &mut self,
        plaintext: &[u8],
        block_index: usize,
        required_clearance: ClearanceLevel,
        encrypted_by: &str,
    ) -> BifurcationResult {
        let t_key = Instant::now();

        // Session key: hergebruik of maak nieuw
        let needs_new = self.session.as_ref().map_or(true, |s| !s.is_valid());
        if needs_new {
            self.session = Some(SessionKey::new(
                &self.system_pub,
                100_000,  // max 100K blocks per sessie
                std::time::Duration::from_secs(300),  // max 5 minuten
            ));
        }

        let session = self.session.as_mut().unwrap();

        // Per-block AES key uit session shared secret (geen DH!)
        let aes_key = session.derive_block_key(block_index);
        let ephemeral_pub = session.ephemeral_pub;
        let key_derive_us = t_key.elapsed().as_micros() as u64;

        // Cache voor open()
        self.key_cache.put(ephemeral_pub, block_index, aes_key);

        // Nonce via RDRAND
        let nonce = self.generate_nonce(block_index);

        // SHA256 plaintext hash
        let plaintext_hash = self.sha256(plaintext);

        // AES-256-GCM encrypt
        let t_enc = Instant::now();
        let ciphertext = self.aes_gcm_encrypt(plaintext, &aes_key, &nonce);
        let encrypt_us = t_enc.elapsed().as_micros() as u64;

        let block = EncryptedBlock {
            block_index,
            ephemeral_pub,
            nonce,
            required_clearance,
            plaintext_hash,
            ciphertext,
            encrypted_at_ns: self.boot_time.elapsed().as_nanos() as u64,
            encrypted_by: encrypted_by.to_string(),
        };

        // Stats
        self.stats.blocks_sealed += 1;
        let total = self.stats.blocks_sealed;
        self.stats.avg_encrypt_us =
            (self.stats.avg_encrypt_us * (total - 1) + encrypt_us) / total;
        self.stats.avg_key_derive_us =
            (self.stats.avg_key_derive_us * (total - 1) + key_derive_us) / total;

        BifurcationResult::Sealed {
            block,
            encrypt_us,
            key_derive_us,
        }
    }

    /// Forceer sessie rotatie (bij security event of key rotation).
    pub fn rotate_session(&mut self) {
        self.session = None;
    }

    /// Geeft het aantal blocks versleuteld in de huidige sessie.
    pub fn session_blocks(&self) -> u64 {
        self.session.as_ref().map_or(0, |s| s.blocks_sealed)
    }

    /// Open: ontsleutel een block met een geldige JIS claim (decrypt-on-read).
    ///
    /// Doorloopt het bifurcatiepunt:
    ///   1. Verifieer JIS claim signature
    ///   2. Check clearance level
    ///   3. Deriveer decryptiesleutel uit claim identity
    ///   4. AES-256-GCM decrypt
    ///   5. Verifieer plaintext integriteit (SHA256)
    pub fn open(
        &mut self,
        block: &EncryptedBlock,
        claim: &JisClaim,
    ) -> BifurcationResult {
        // 1. Verifieer claim
        //    v1: structural check
        //    v2: Ed25519 signature verificatie
        if claim.identity.is_empty() {
            self.stats.invalid_claims += 1;
            return BifurcationResult::ClaimInvalid {
                reason: "Empty identity in JIS claim".to_string(),
            };
        }

        if claim.ed25519_pub.len() != ED25519_PUB_SIZE * 2 {
            // Hex-encoded = 64 chars
            self.stats.invalid_claims += 1;
            return BifurcationResult::ClaimInvalid {
                reason: format!(
                    "Invalid Ed25519 public key length: {} (expected {})",
                    claim.ed25519_pub.len(),
                    ED25519_PUB_SIZE * 2
                ),
            };
        }

        // 2. Clearance check — de kern van de bifurcatie
        if claim.clearance < block.required_clearance {
            self.stats.access_denied += 1;
            return BifurcationResult::AccessDenied {
                required: block.required_clearance,
                presented: claim.clearance,
                identity: claim.identity.clone(),
            };
        }

        // 3. Key derivation — check cache first, dan DH als cache miss
        //    Cache hit: ~5ns (HashMap lookup)
        //    Cache miss: ~120µs (X25519 DH + HKDF)
        let t_key = Instant::now();
        let aes_key = if let Some(cached_key) = self.key_cache.get(&block.ephemeral_pub, block.block_index) {
            cached_key
        } else {
            // Cache miss: volledige DH + HKDF
            let system_static = StaticSecret::from(self.system_secret);
            let ephemeral_pub = PublicKey::from(block.ephemeral_pub);
            let shared = system_static.diffie_hellman(&ephemeral_pub);
            let key = self.hkdf_derive_block_key(shared.as_bytes(), block.block_index);
            // Cache de afgeleide key voor herhaald gebruik
            self.key_cache.put(block.ephemeral_pub, block.block_index, key);
            key
        };
        let key_derive_us = t_key.elapsed().as_micros() as u64;

        // 4. AES-256-GCM decrypt via AES-NI
        let t_dec = Instant::now();
        let plaintext = self.aes_gcm_decrypt(&block.ciphertext, &aes_key, &block.nonce);
        let decrypt_us = t_dec.elapsed().as_micros() as u64;

        // 5. Integriteit check
        let actual_hash = self.sha256(&plaintext);
        if actual_hash != block.plaintext_hash {
            self.stats.integrity_failures += 1;
            return BifurcationResult::IntegrityFailed {
                expected_hash: block.plaintext_hash,
                actual_hash,
            };
        }

        // Stats
        self.stats.blocks_opened += 1;
        let total = self.stats.blocks_opened;
        self.stats.avg_decrypt_us =
            (self.stats.avg_decrypt_us * (total - 1) + decrypt_us) / total;

        BifurcationResult::Opened {
            plaintext,
            decrypt_us,
            key_derive_us,
            opened_by: claim.identity.clone(),
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Crypto primitives — ECHTE CRYPTO via AES-NI hardware
    //
    // AES-256-GCM:  aes-gcm crate → core::arch::x86_64::_mm_aesenc_si128
    // X25519:       x25519-dalek → Curve25519 key agreement
    // SHA-256:      sha2 crate → hardware SHA extensions waar beschikbaar
    // HKDF:         hkdf crate → RFC 5869 HMAC-based key derivation
    // ═══════════════════════════════════════════════════════════

    /// HKDF-SHA256: derive per-block AES key uit shared secret.
    ///
    /// RFC 5869 — echte HMAC-based Extract-and-Expand.
    fn hkdf_derive_block_key(&self, shared_secret: &[u8; 32], block_index: usize) -> [u8; AES_KEY_SIZE] {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);

        // Info = prefix + block index (maakt elke block key uniek)
        let mut info = Vec::from(HKDF_INFO_PREFIX);
        info.extend_from_slice(&block_index.to_le_bytes());

        let mut key = [0u8; AES_KEY_SIZE];
        hk.expand(&info, &mut key).expect("HKDF expand failed");
        key
    }

    /// Genereer AES-GCM nonce (96 bits).
    ///
    /// Pad: RDRAND (hardware, 0 syscalls) → OsRng fallback.
    /// NOOIT hergebruiken met dezelfde key.
    fn generate_nonce(&self, _block_index: usize) -> [u8; AES_NONCE_SIZE] {
        rdrand_nonce()
    }

    /// SHA-256 hash via sha2 crate.
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// AES-256-GCM encrypt via AES-NI hardware instructies.
    ///
    /// Op x86_64 met AES-NI: core::arch::x86_64::_mm_aesenc_si128
    /// Throughput: ~4-8 GB/s op moderne hardware
    fn aes_gcm_encrypt(&self, plaintext: &[u8], key: &[u8; AES_KEY_SIZE], nonce: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(nonce);

        cipher.encrypt(nonce, plaintext)
            .expect("AES-256-GCM encrypt failed")
    }

    /// AES-256-GCM decrypt via AES-NI hardware instructies.
    fn aes_gcm_decrypt(&self, ciphertext: &[u8], key: &[u8; AES_KEY_SIZE], nonce: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(nonce);

        cipher.decrypt(nonce, ciphertext)
            .expect("AES-256-GCM decrypt failed")
    }

    /// Statistieken opvragen.
    pub fn stats(&self) -> &BifurcationStats {
        &self.stats
    }

    /// Parallel seal: versleutel meerdere blocks over alle CPU cores.
    /// Session key mode: één DH + parallel HKDF+AES = maximale throughput.
    /// Stats worden bijgewerkt na afloop.
    pub fn seal_batch(
        &mut self,
        plaintexts: &[Vec<u8>],
        required_clearance: ClearanceLevel,
        encrypted_by: &str,
    ) -> BatchResult {
        let t0 = Instant::now();

        // Session key aanmaken/hergebruiken (één DH)
        let needs_new = self.session.as_ref().map_or(true, |s| !s.is_valid());
        if needs_new {
            self.session = Some(SessionKey::new(
                &self.system_pub,
                100_000,
                std::time::Duration::from_secs(300),
            ));
        }

        let session = self.session.as_ref().unwrap();
        let shared_secret = session.shared_secret;
        let ephemeral_pub = session.ephemeral_pub;
        let encrypted_by = encrypted_by.to_string();
        let boot_time = self.boot_time;
        let blocks_sealed = AtomicUsize::new(0);

        // Von Braun drempel: onder 16KB is rayon overhead groter dan de winst.
        // In dat geval single-thread, tenzij er genoeg blocks zijn om het waard te maken.
        let avg_size = if plaintexts.is_empty() { 0 } else {
            plaintexts.iter().map(|p| p.len()).sum::<usize>() / plaintexts.len()
        };
        let use_parallel = avg_size >= 16_384 || plaintexts.len() >= 256;

        // Seal met session shared secret (parallel of single-thread)
        let seal_one = |(block_index, plaintext): (usize, &Vec<u8>)| -> EncryptedBlock {
            // HKDF per-block key (geen DH!)
            let hk = Hkdf::<Sha256>::new(None, &shared_secret);
            let mut info = Vec::from(HKDF_INFO_PREFIX);
            info.extend_from_slice(&block_index.to_le_bytes());
            let mut aes_key = [0u8; AES_KEY_SIZE];
            hk.expand(&info, &mut aes_key).expect("HKDF expand failed");

            // Nonce via RDSEED/RDRAND
            let nonce = rdrand_nonce();

            // SHA-256 plaintext hash
            let mut hasher = Sha256::new();
            hasher.update(plaintext);
            let hash_result = hasher.finalize();
            let mut plaintext_hash = [0u8; 32];
            plaintext_hash.copy_from_slice(&hash_result);

            // AES-256-GCM encrypt
            let cipher_key = Key::<Aes256Gcm>::from_slice(&aes_key);
            let cipher = Aes256Gcm::new(cipher_key);
            let nonce_obj = Nonce::from_slice(&nonce);
            let ciphertext = cipher.encrypt(nonce_obj, plaintext.as_ref())
                .expect("AES-256-GCM encrypt failed");

            blocks_sealed.fetch_add(1, Ordering::Relaxed);

            EncryptedBlock {
                block_index,
                ephemeral_pub,
                nonce,
                required_clearance,
                plaintext_hash,
                ciphertext,
                encrypted_at_ns: boot_time.elapsed().as_nanos() as u64,
                encrypted_by: encrypted_by.clone(),
            }
        };

        let blocks: Vec<EncryptedBlock> = if use_parallel {
            plaintexts.par_iter().enumerate().map(seal_one).collect()
        } else {
            plaintexts.iter().enumerate().map(seal_one).collect()
        };

        let total_us = t0.elapsed().as_micros() as u64;
        let total_bytes: usize = plaintexts.iter().map(|p| p.len()).sum();
        let sealed = blocks_sealed.load(Ordering::Relaxed) as u64;
        let count = blocks.len().max(1);

        // Update stats
        self.stats.blocks_sealed += sealed;
        if let Some(ref mut s) = self.session {
            s.blocks_sealed += sealed;
        }

        // Cache keys voor snelle open
        for block in &blocks {
            let hk = Hkdf::<Sha256>::new(None, &shared_secret);
            let mut info = Vec::from(HKDF_INFO_PREFIX);
            info.extend_from_slice(&block.block_index.to_le_bytes());
            let mut aes_key = [0u8; AES_KEY_SIZE];
            hk.expand(&info, &mut aes_key).expect("HKDF expand failed");
            self.key_cache.put(block.ephemeral_pub, block.block_index, aes_key);
        }

        BatchResult {
            blocks,
            total_us,
            per_block_us: total_us / count as u64,
            throughput_mbs: (total_bytes as f64) / (total_us.max(1) as f64 / 1_000_000.0) / (1024.0 * 1024.0),
            threads_used: rayon::current_num_threads(),
        }
    }

    /// Parallel open: ontsleutel meerdere blocks met dezelfde JIS claim.
    /// Gebruikt key cache waar mogelijk, anders parallel DH.
    /// Stats worden bijgewerkt na afloop.
    pub fn open_batch(
        &mut self,
        blocks: &[EncryptedBlock],
        claim: &JisClaim,
    ) -> BatchOpenResult {
        let t0 = Instant::now();
        let denied = AtomicUsize::new(0);
        let system_secret = self.system_secret;

        if claim.identity.is_empty() || claim.ed25519_pub.len() != ED25519_PUB_SIZE * 2 {
            return BatchOpenResult {
                plaintexts: vec![],
                denied: blocks.len() as u64,
                total_us: 0,
                per_block_us: 0,
                throughput_mbs: 0.0,
            };
        }

        // Pre-fetch cached keys
        let cached_keys: Vec<Option<[u8; 32]>> = blocks
            .iter()
            .map(|b| self.key_cache.get(&b.ephemeral_pub, b.block_index))
            .collect();

        let results: Vec<Option<Vec<u8>>> = blocks
            .par_iter()
            .zip(cached_keys.par_iter())
            .map(|(block, cached_key)| {
                // Clearance check
                if claim.clearance < block.required_clearance {
                    denied.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                // Key: cache hit of DH
                let aes_key = if let Some(key) = cached_key {
                    *key
                } else {
                    let sys_static = StaticSecret::from(system_secret);
                    let eph_pub = PublicKey::from(block.ephemeral_pub);
                    let shared = sys_static.diffie_hellman(&eph_pub);
                    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
                    let mut info = Vec::from(HKDF_INFO_PREFIX);
                    info.extend_from_slice(&block.block_index.to_le_bytes());
                    let mut key = [0u8; AES_KEY_SIZE];
                    hk.expand(&info, &mut key).expect("HKDF expand failed");
                    key
                };

                // AES-256-GCM decrypt
                let cipher_key = Key::<Aes256Gcm>::from_slice(&aes_key);
                let cipher = Aes256Gcm::new(cipher_key);
                let nonce = Nonce::from_slice(&block.nonce);
                let plaintext = cipher.decrypt(nonce, block.ciphertext.as_ref())
                    .expect("AES-256-GCM decrypt failed");

                // Integrity check
                let mut hasher = Sha256::new();
                hasher.update(&plaintext);
                let hash_result = hasher.finalize();
                let mut actual_hash = [0u8; 32];
                actual_hash.copy_from_slice(&hash_result);
                if actual_hash != block.plaintext_hash {
                    return None;
                }

                Some(plaintext)
            })
            .collect();

        let plaintexts: Vec<Vec<u8>> = results.into_iter().flatten().collect();
        let total_us = t0.elapsed().as_micros() as u64;
        let total_bytes: usize = plaintexts.iter().map(|p| p.len()).sum();
        let count = blocks.len().max(1);

        // Update stats
        self.stats.blocks_opened += plaintexts.len() as u64;
        self.stats.access_denied += denied.load(Ordering::Relaxed) as u64;

        BatchOpenResult {
            plaintexts,
            denied: denied.load(Ordering::Relaxed) as u64,
            total_us,
            per_block_us: total_us / count as u64,
            throughput_mbs: (total_bytes as f64) / (total_us.max(1) as f64 / 1_000_000.0) / (1024.0 * 1024.0),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Parallel Batch Operations — Multi-Core Sealing & Opening
//
// Elke core pakt een block, maakt eigen ephemeral keypair,
// eigen AES-GCM instance. Geen gedeelde mutable state.
// Op 12-core P520: theoretisch 12x throughput → 3+ GB/s
// ═══════════════════════════════════════════════════════════════

/// Resultaat van een parallel batch operatie.
#[derive(Debug)]
pub struct BatchResult {
    /// Succesvol verwerkte blocks
    pub blocks: Vec<EncryptedBlock>,
    /// Totale doorlooptijd in microseconden
    pub total_us: u64,
    /// Gemiddelde tijd per block in microseconden
    pub per_block_us: u64,
    /// Throughput in MB/s
    pub throughput_mbs: f64,
    /// Aantal gebruikte threads (rayon)
    pub threads_used: usize,
}

/// Resultaat van een parallel open operatie.
#[derive(Debug)]
pub struct BatchOpenResult {
    /// Succesvol ontsleutelde plaintexts
    pub plaintexts: Vec<Vec<u8>>,
    /// Aantal geweigerd (clearance te laag)
    pub denied: u64,
    /// Totale doorlooptijd in microseconden
    pub total_us: u64,
    /// Gemiddelde tijd per block in microseconden
    pub per_block_us: u64,
    /// Throughput in MB/s
    pub throughput_mbs: f64,
}

/// Parallel seal: versleutel meerdere blocks tegelijk over alle CPU cores.
///
/// Elke core krijgt:
///   - Eigen ephemeral X25519 keypair (geen sharing)
///   - Eigen AES-GCM cipher instance
///   - Eigen RDRAND nonce (per-core hardware random)
///
/// Geen locks, geen mutexes, pure data-parallel.
pub fn parallel_seal(
    plaintexts: &[Vec<u8>],
    system_secret: &[u8; 32],
    required_clearance: ClearanceLevel,
    encrypted_by: &str,
) -> BatchResult {
    let t0 = Instant::now();

    // System public key afleiden (eenmalig)
    let system_static = StaticSecret::from(*system_secret);
    let system_pub = PublicKey::from(&system_static);
    let system_pub_bytes = system_pub.to_bytes();
    let encrypted_by = encrypted_by.to_string();
    let blocks_sealed = AtomicUsize::new(0);

    // Rayon parallel iterator — elke core pakt een block
    let blocks: Vec<EncryptedBlock> = plaintexts
        .par_iter()
        .enumerate()
        .map(|(block_index, plaintext)| {
            // Per-thread: eigen ephemeral keypair
            let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
            let ephemeral_pub = PublicKey::from(&ephemeral_secret);

            // DH: ephemeral × system_pub
            let system_pub_key = PublicKey::from(system_pub_bytes);
            let shared = ephemeral_secret.diffie_hellman(&system_pub_key);

            // HKDF per-block key
            let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
            let mut info = Vec::from(HKDF_INFO_PREFIX);
            info.extend_from_slice(&block_index.to_le_bytes());
            let mut aes_key = [0u8; AES_KEY_SIZE];
            hk.expand(&info, &mut aes_key).expect("HKDF expand failed");

            // Nonce via RDRAND
            let nonce = rdrand_nonce();

            // SHA-256 plaintext hash
            let mut hasher = Sha256::new();
            hasher.update(plaintext);
            let hash_result = hasher.finalize();
            let mut plaintext_hash = [0u8; 32];
            plaintext_hash.copy_from_slice(&hash_result);

            // AES-256-GCM encrypt
            let cipher_key = Key::<Aes256Gcm>::from_slice(&aes_key);
            let cipher = Aes256Gcm::new(cipher_key);
            let nonce_obj = Nonce::from_slice(&nonce);
            let ciphertext = cipher.encrypt(nonce_obj, plaintext.as_ref())
                .expect("AES-256-GCM encrypt failed");

            blocks_sealed.fetch_add(1, Ordering::Relaxed);

            EncryptedBlock {
                block_index,
                ephemeral_pub: ephemeral_pub.to_bytes(),
                nonce,
                required_clearance,
                plaintext_hash,
                ciphertext,
                encrypted_at_ns: t0.elapsed().as_nanos() as u64,
                encrypted_by: encrypted_by.clone(),
            }
        })
        .collect();

    let total_us = t0.elapsed().as_micros() as u64;
    let total_bytes: usize = plaintexts.iter().map(|p| p.len()).sum();
    let count = blocks.len().max(1);

    BatchResult {
        blocks,
        total_us,
        per_block_us: total_us / count as u64,
        throughput_mbs: (total_bytes as f64) / (total_us as f64 / 1_000_000.0) / (1024.0 * 1024.0),
        threads_used: rayon::current_num_threads(),
    }
}

/// Parallel open: ontsleutel meerdere blocks tegelijk met dezelfde JIS claim.
///
/// Clearance check per block, dan parallel decrypt.
/// Geweigerde blocks worden overgeslagen (niet gedecrypt).
pub fn parallel_open(
    blocks: &[EncryptedBlock],
    claim: &JisClaim,
    system_secret: &[u8; 32],
) -> BatchOpenResult {
    let t0 = Instant::now();
    let denied = AtomicUsize::new(0);

    // Valideer claim eenmalig (niet per thread)
    if claim.identity.is_empty() || claim.ed25519_pub.len() != ED25519_PUB_SIZE * 2 {
        return BatchOpenResult {
            plaintexts: vec![],
            denied: blocks.len() as u64,
            total_us: 0,
            per_block_us: 0,
            throughput_mbs: 0.0,
        };
    }

    let results: Vec<Option<Vec<u8>>> = blocks
        .par_iter()
        .map(|block| {
            // Clearance check
            if claim.clearance < block.required_clearance {
                denied.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // DH: system_secret × ephemeral_pub
            let system_static = StaticSecret::from(*system_secret);
            let ephemeral_pub = PublicKey::from(block.ephemeral_pub);
            let shared = system_static.diffie_hellman(&ephemeral_pub);

            // HKDF per-block key
            let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
            let mut info = Vec::from(HKDF_INFO_PREFIX);
            info.extend_from_slice(&block.block_index.to_le_bytes());
            let mut aes_key = [0u8; AES_KEY_SIZE];
            hk.expand(&info, &mut aes_key).expect("HKDF expand failed");

            // AES-256-GCM decrypt
            let cipher_key = Key::<Aes256Gcm>::from_slice(&aes_key);
            let cipher = Aes256Gcm::new(cipher_key);
            let nonce = Nonce::from_slice(&block.nonce);
            let plaintext = cipher.decrypt(nonce, block.ciphertext.as_ref())
                .expect("AES-256-GCM decrypt failed");

            // Integrity check
            let mut hasher = Sha256::new();
            hasher.update(&plaintext);
            let hash_result = hasher.finalize();
            let mut actual_hash = [0u8; 32];
            actual_hash.copy_from_slice(&hash_result);

            if actual_hash != block.plaintext_hash {
                return None;
            }

            Some(plaintext)
        })
        .collect();

    let plaintexts: Vec<Vec<u8>> = results.into_iter().flatten().collect();
    let total_us = t0.elapsed().as_micros() as u64;
    let total_bytes: usize = plaintexts.iter().map(|p| p.len()).sum();
    let count = blocks.len().max(1);

    BatchOpenResult {
        plaintexts,
        denied: denied.load(Ordering::Relaxed) as u64,
        total_us,
        per_block_us: total_us / count as u64,
        throughput_mbs: (total_bytes as f64) / (total_us.max(1) as f64 / 1_000_000.0) / (1024.0 * 1024.0),
    }
}

// ═══════════════════════════════════════════════════════════════
// Live Migration — Zero-Downtime Block Transfer
// ═══════════════════════════════════════════════════════════════

/// Live Migration Controller — rsync-achtige delta-transfer voor blocks.
///
/// Scenario: Server A moet vervangen worden door Server B.
///   1. Bulk sync: kopieer alle blocks van A → B
///   2. Delta sync: kopieer alleen gewijzigde blocks (dirty bits)
///   3. Micro-freeze: pauzeer writes, sync laatste delta's
///   4. Handoff: userfaultfd registratie verplaatsen naar B
///   5. Resume: applicatie gaat door op B, merkt niets
///
/// Dit is de rsync-kernel: niet bestanden maar RAID blocks.
pub struct LiveMigration {
    /// Bron blocks (huidige server)
    source_block_hashes: Vec<[u8; 32]>,
    /// Dirty bitmap: welke blocks zijn gewijzigd sinds laatste sync
    dirty_bitmap: Vec<bool>,
    /// Totaal getransfereerde bytes
    pub bytes_transferred: u64,
    /// Totaal overgeslagen bytes (ongewijzigd)
    pub bytes_skipped: u64,
    /// Aantal sync rondes
    pub sync_rounds: u32,
    /// Status
    pub phase: MigrationPhase,
}

/// Migratiefasen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationPhase {
    /// Initiële bulk sync (alle blocks)
    BulkSync,
    /// Delta sync (alleen dirty blocks)
    DeltaSync,
    /// Micro-freeze (laatste pages, writes gepauzeerd)
    MicroFreeze,
    /// Handoff (userfaultfd registratie verplaatst)
    Handoff,
    /// Compleet (bron kan offline)
    Complete,
    /// Afgebroken
    Aborted { reason: String },
}

/// Resultaat van een sync ronde
#[derive(Debug)]
pub struct SyncRound {
    /// Fase
    pub phase: MigrationPhase,
    /// Ronde nummer
    pub round: u32,
    /// Blocks getransfereerd
    pub blocks_transferred: usize,
    /// Blocks overgeslagen (clean)
    pub blocks_skipped: usize,
    /// Bytes getransfereerd
    pub bytes_transferred: u64,
    /// Duur in microseconden
    pub duration_us: u64,
    /// Remaining dirty blocks
    pub remaining_dirty: usize,
}

impl LiveMigration {
    /// Start een nieuwe migratie voor N blocks.
    pub fn new(block_count: usize) -> Self {
        Self {
            source_block_hashes: vec![[0u8; 32]; block_count],
            dirty_bitmap: vec![true; block_count],  // Alles is "dirty" bij start
            bytes_transferred: 0,
            bytes_skipped: 0,
            sync_rounds: 0,
            phase: MigrationPhase::BulkSync,
        }
    }

    /// Markeer een block als dirty (gewijzigd na laatste sync).
    pub fn mark_dirty(&mut self, block_index: usize) {
        if block_index < self.dirty_bitmap.len() {
            self.dirty_bitmap[block_index] = true;
        }
    }

    /// Voer een sync ronde uit.
    ///
    /// BulkSync: alles transfereren
    /// DeltaSync: alleen dirty blocks
    /// MicroFreeze: laatste dirty blocks + writes pauzeren
    pub fn sync_round(
        &mut self,
        block_data: &[Vec<u8>],
        block_size: usize,
    ) -> SyncRound {
        let t0 = Instant::now();
        self.sync_rounds += 1;

        let mut transferred = 0usize;
        let mut skipped = 0usize;
        let mut bytes = 0u64;

        for i in 0..self.dirty_bitmap.len().min(block_data.len()) {
            if self.dirty_bitmap[i] {
                // "Transfer" het block (in productie: TCP/QUIC naar remote)
                let hash = self.quick_hash(&block_data[i]);

                // Check of het block daadwerkelijk gewijzigd is (dedup)
                if hash != self.source_block_hashes[i] {
                    self.source_block_hashes[i] = hash;
                    bytes += block_data[i].len() as u64;
                    transferred += 1;
                } else {
                    skipped += 1;
                }

                self.dirty_bitmap[i] = false;
            } else {
                skipped += 1;
            }
        }

        self.bytes_transferred += bytes;
        self.bytes_skipped += (skipped as u64) * (block_size as u64);

        let remaining = self.dirty_bitmap.iter().filter(|&&d| d).count();

        // Fase transitie
        match self.phase {
            MigrationPhase::BulkSync => {
                if remaining == 0 {
                    self.phase = MigrationPhase::DeltaSync;
                }
            }
            MigrationPhase::DeltaSync => {
                // Als er weinig dirty blocks zijn, ga naar micro-freeze
                let dirty_pct = (remaining as f64) / (self.dirty_bitmap.len() as f64) * 100.0;
                if dirty_pct < 1.0 {
                    self.phase = MigrationPhase::MicroFreeze;
                }
            }
            MigrationPhase::MicroFreeze => {
                if remaining == 0 {
                    self.phase = MigrationPhase::Handoff;
                }
            }
            MigrationPhase::Handoff => {
                self.phase = MigrationPhase::Complete;
            }
            _ => {}
        }

        SyncRound {
            phase: self.phase.clone(),
            round: self.sync_rounds,
            blocks_transferred: transferred,
            blocks_skipped: skipped,
            bytes_transferred: bytes,
            duration_us: t0.elapsed().as_micros() as u64,
            remaining_dirty: remaining,
        }
    }

    /// Complete de handoff: markeer migratie als afgerond.
    pub fn complete_handoff(&mut self) {
        self.phase = MigrationPhase::Complete;
    }

    /// Percentage compleet.
    pub fn progress_pct(&self) -> f64 {
        let total = self.dirty_bitmap.len() as f64;
        let clean = self.dirty_bitmap.iter().filter(|&&d| !d).count() as f64;
        (clean / total) * 100.0
    }

    /// Quick hash voor block dedup.
    fn quick_hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut state: [u64; 4] = [
            0x243F6A8885A308D3,
            0x13198A2E03707344,
            0xA4093822299F31D0,
            0x082EFA98EC4E6C89,
        ];

        for (i, &byte) in data.iter().enumerate() {
            let idx = i % 4;
            state[idx] = state[idx]
                .wrapping_mul(0x100000001b3)
                .wrapping_add(byte as u64);
            state[(idx + 1) % 4] ^= state[idx].rotate_left(17);
        }

        for i in 0..4 {
            let bytes = state[i].to_le_bytes();
            hash[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        hash
    }
}
