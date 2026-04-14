use std::sync::Arc;
use std::time::Instant;

use crate::bus::{BusPayload, BusResult, VirtualBus};
use crate::config::TrustKernelConfig;
use crate::tibet_token::TibetProvenance;
use crate::mux::TibetMuxFrame;
use crate::bifurcation::{AirlockBifurcation, BifurcationResult, ClearanceLevel, JisClaim, EncryptedBlock};

/// Kernel B — De Archivaris ("De Schone Kluis")
///
/// The Archivaris never touches untrusted input directly.
/// It only receives signed payloads that have passed the Voorproever's gauntlet.
///
/// Responsibilities:
/// 1. Verify the Voorproever's seal on the bus payload
/// 2. JIS access check (clearance, role, geo, time window)
/// 3. Execute the verified action
/// 4. Append-only storage (no overwrites, no deletes)
/// 5. Mint the definitive TIBET provenance token
/// 6. **Airlock Bifurcatie**: encrypt-on-write, decrypt-on-read
///    Data at rest is ALTIJD encrypted. Zonder JIS claim = dood materiaal.
///    Re-encrypt-on-deny: als JIS geen lezen/bewerken toestaat,
///    gaat data terug naar encrypted state ("omgekeerde ransomware").
///
/// The Archivaris is the ONLY component that mints final TIBET tokens.
/// The Voorproever can generate incident tokens (kills), but success tokens
/// are exclusively minted here — ensuring the proof chain is clean.

/// Result of Archivaris processing.
#[derive(Debug)]
pub enum ArchivarisResult {
    /// Successfully processed and archived
    Success {
        token: TibetProvenance,
        execution_us: u64,
        bus_seq: u64,
    },
    /// Bus payload failed verification
    BusVerifyFailed {
        reason: String,
        bus_seq: u64,
    },
    /// JIS access denied
    JisDenied {
        reason: String,
        bus_seq: u64,
    },
    /// Bus is closed (watchdog killed Kernel A)
    BusClosed,
    /// Sequence gap detected (some payloads were lost/blocked)
    SequenceGap {
        expected: u64,
        received: u64,
        /// Processing continues, but this is a TIBET event
        result: Box<ArchivarisResult>,
    },
}

/// Append-only log entry
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub seq: u64,
    pub intent: String,
    pub from_aint: String,
    pub result: String,
    pub tibet_token_type: String,
    pub timestamp_ns: u64,
}

pub struct Archivaris {
    config: TrustKernelConfig,
    bus: Arc<VirtualBus>,
    /// Append-only archive log
    archive: Vec<ArchiveEntry>,
    /// Airlock Bifurcatie engine — encrypt-by-default
    bifurcation: AirlockBifurcation,
    /// Encrypted block vault — data at rest (altijd versleuteld)
    vault: Vec<EncryptedBlock>,
    /// Boot time for relative timestamps
    boot_time: Instant,
}

impl Archivaris {
    pub fn new(config: TrustKernelConfig, bus: Arc<VirtualBus>) -> Self {
        Self {
            config,
            bus,
            archive: Vec::new(),
            bifurcation: AirlockBifurcation::new(),
            vault: Vec::new(),
            boot_time: Instant::now(),
        }
    }

    /// Process a payload from the bus. This is the main entry point.
    pub fn process(&mut self, bus_payload: &BusPayload, original_frame: &TibetMuxFrame) -> ArchivarisResult {
        let t0 = Instant::now();

        // 1. Receive from bus (validates sequence)
        let bus_result = self.bus.receive(bus_payload);

        let (payload, seq_gap) = match bus_result {
            BusResult::Delivered(p) => (p, None),
            BusResult::SequenceGap { expected, received, gap_size: _ } => {
                // Accept but flag — this is a TIBET event
                (bus_payload.clone(), Some((expected, received)))
            }
            BusResult::BusClosed => return ArchivarisResult::BusClosed,
            BusResult::PayloadTooLarge { size, max } => {
                return ArchivarisResult::BusVerifyFailed {
                    reason: format!("Payload {}B exceeds bus max {}B", size, max),
                    bus_seq: bus_payload.seq,
                };
            }
        };

        // 2. Verify Voorproever seal
        if !self.verify_voorproever_seal(&payload) {
            return ArchivarisResult::BusVerifyFailed {
                reason: "Voorproever seal verification failed".to_string(),
                bus_seq: payload.seq,
            };
        }

        // 3. JIS access check
        if self.config.profile.jis_signing_per_action {
            if let Err(reason) = self.jis_check(&payload) {
                return ArchivarisResult::JisDenied {
                    reason,
                    bus_seq: payload.seq,
                };
            }
        }

        // 4. Execute (in Archivaris context, "execute" means: accept and record)
        let result_text = format!(
            "Archived: intent='{}' from='{}' fira={:.2} syscalls={}",
            payload.intent,
            payload.from_aint,
            payload.fira_score,
            payload.observed_syscalls.len()
        );

        // 5. Mint TIBET token (only Archivaris mints success tokens)
        let execution_us = t0.elapsed().as_micros() as u64;
        let execution_ms = execution_us as f64 / 1000.0;

        let token = TibetProvenance::generate_success(
            original_frame,
            result_text.clone(),
            &format!("archivaris_seq{}", payload.seq),
            execution_ms,
            payload.observed_syscalls.clone(),
        );

        // 6. Append to archive (append-only, never overwrite)
        self.archive.push(ArchiveEntry {
            seq: payload.seq,
            intent: payload.intent.clone(),
            from_aint: payload.from_aint.clone(),
            result: result_text,
            tibet_token_type: "SAFE_EXECUTION".to_string(),
            timestamp_ns: self.boot_time.elapsed().as_nanos() as u64,
        });

        // 7. Return result, with sequence gap info if applicable
        let result = ArchivarisResult::Success {
            token,
            execution_us,
            bus_seq: payload.seq,
        };

        if let Some((expected, received)) = seq_gap {
            ArchivarisResult::SequenceGap {
                expected,
                received,
                result: Box::new(result),
            }
        } else {
            result
        }
    }

    /// Verify the Voorproever's cryptographic seal.
    /// In v1: checks seal format. In v2: real Ed25519 verification.
    fn verify_voorproever_seal(&self, payload: &BusPayload) -> bool {
        // v1: structural check — seal must start with "vp_seal_"
        // v2: Ed25519 signature verification against Voorproever's public key
        payload.voorproever_seal.starts_with("vp_seal_seq")
    }

    /// JIS multi-dimensional access check.
    /// Checks clearance, role, department, geo, time window.
    fn jis_check(&self, payload: &BusPayload) -> Result<(), String> {
        // v1: basic checks
        // - Agent must have a .aint identity
        if payload.from_aint.is_empty() {
            return Err("JIS: No agent identity (from_aint is empty)".to_string());
        }

        // - FIR/A score must be above threshold
        let min_fira = 0.3; // Minimum trust score to proceed
        if payload.fira_score < min_fira {
            return Err(format!(
                "JIS: FIR/A score {:.2} below minimum {:.2}",
                payload.fira_score, min_fira
            ));
        }

        // v2: full JisGate.evaluate() with clearance levels, roles, geo, time windows
        Ok(())
    }

    /// Get the archive log (read-only).
    pub fn archive(&self) -> &[ArchiveEntry] {
        &self.archive
    }

    /// Archive size.
    pub fn archive_len(&self) -> usize {
        self.archive.len()
    }

    // ═══════════════════════════════════════════════════════════
    // Airlock Bifurcatie — Encrypt-by-Default
    // ═══════════════════════════════════════════════════════════

    /// Store data in de vault (encrypt-on-write).
    ///
    /// Data gaat NOOIT onversleuteld de disk op.
    /// Dit is het "ransomware" moment — maar dan by design.
    pub fn vault_store(
        &mut self,
        data: &[u8],
        clearance: ClearanceLevel,
        stored_by: &str,
    ) -> VaultStoreResult {
        let block_index = self.vault.len();

        match self.bifurcation.seal(data, block_index, clearance, stored_by) {
            BifurcationResult::Sealed { block, encrypt_us, key_derive_us } => {
                self.vault.push(block);

                // Append-only log
                self.archive.push(ArchiveEntry {
                    seq: self.archive.len() as u64,
                    intent: format!("vault_store_block_{}", block_index),
                    from_aint: stored_by.to_string(),
                    result: format!(
                        "Sealed: block={} clearance={} encrypt={}us",
                        block_index,
                        clearance.as_str(),
                        encrypt_us
                    ),
                    tibet_token_type: "VAULT_SEAL".to_string(),
                    timestamp_ns: self.boot_time.elapsed().as_nanos() as u64,
                });

                VaultStoreResult::Sealed {
                    block_index,
                    encrypt_us,
                    key_derive_us,
                }
            }
            _ => VaultStoreResult::Failed {
                reason: "Bifurcation seal failed".to_string(),
            },
        }
    }

    /// Retrieve data uit de vault (decrypt-on-read).
    ///
    /// Dit is het bifurcatiepunt:
    ///   JIS claim geldig + clearance OK → decrypt → levende data
    ///   JIS claim ongeldig of clearance te laag → GEWEIGERD → dood materiaal
    pub fn vault_retrieve(
        &mut self,
        block_index: usize,
        claim: &JisClaim,
    ) -> VaultRetrieveResult {
        let block = match self.vault.get(block_index) {
            Some(b) => b,
            None => return VaultRetrieveResult::NotFound { block_index },
        };

        match self.bifurcation.open(block, claim) {
            BifurcationResult::Opened { plaintext, decrypt_us, key_derive_us, opened_by } => {
                // Log de opening (TIBET audit trail)
                self.archive.push(ArchiveEntry {
                    seq: self.archive.len() as u64,
                    intent: format!("vault_retrieve_block_{}", block_index),
                    from_aint: opened_by.clone(),
                    result: format!(
                        "Opened: block={} by={} clearance={} decrypt={}us",
                        block_index,
                        opened_by,
                        claim.clearance.as_str(),
                        decrypt_us
                    ),
                    tibet_token_type: "VAULT_OPEN".to_string(),
                    timestamp_ns: self.boot_time.elapsed().as_nanos() as u64,
                });

                VaultRetrieveResult::Opened {
                    plaintext,
                    decrypt_us,
                    key_derive_us,
                }
            }
            BifurcationResult::AccessDenied { required, presented, identity } => {
                // Log de weigering (TIBET audit trail — belangrijk!)
                self.archive.push(ArchiveEntry {
                    seq: self.archive.len() as u64,
                    intent: format!("vault_retrieve_DENIED_block_{}", block_index),
                    from_aint: identity.clone(),
                    result: format!(
                        "ACCESS DENIED: block={} required={} presented={} identity={}",
                        block_index,
                        required.as_str(),
                        presented.as_str(),
                        identity
                    ),
                    tibet_token_type: "VAULT_DENIED".to_string(),
                    timestamp_ns: self.boot_time.elapsed().as_nanos() as u64,
                });

                VaultRetrieveResult::AccessDenied {
                    required,
                    presented,
                    identity,
                }
            }
            BifurcationResult::ClaimInvalid { reason } => {
                VaultRetrieveResult::ClaimInvalid { reason }
            }
            BifurcationResult::IntegrityFailed { .. } => {
                VaultRetrieveResult::IntegrityFailed { block_index }
            }
            _ => VaultRetrieveResult::Failed {
                reason: "Unexpected bifurcation result".to_string(),
            },
        }
    }

    /// Vault grootte (aantal encrypted blocks).
    pub fn vault_len(&self) -> usize {
        self.vault.len()
    }

    /// Bifurcatie statistieken.
    pub fn bifurcation_stats(&self) -> &crate::bifurcation::BifurcationStats {
        self.bifurcation.stats()
    }
}

/// Resultaat van vault_store (encrypt-on-write).
#[derive(Debug)]
pub enum VaultStoreResult {
    Sealed {
        block_index: usize,
        encrypt_us: u64,
        key_derive_us: u64,
    },
    Failed {
        reason: String,
    },
}

/// Resultaat van vault_retrieve (decrypt-on-read).
#[derive(Debug)]
pub enum VaultRetrieveResult {
    Opened {
        plaintext: Vec<u8>,
        decrypt_us: u64,
        key_derive_us: u64,
    },
    AccessDenied {
        required: ClearanceLevel,
        presented: ClearanceLevel,
        identity: String,
    },
    ClaimInvalid {
        reason: String,
    },
    IntegrityFailed {
        block_index: usize,
    },
    NotFound {
        block_index: usize,
    },
    Failed {
        reason: String,
    },
}
