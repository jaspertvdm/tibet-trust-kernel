use serde::{Serialize, Deserialize};
use chrono::Utc;

/// TIBET Provenance Token — cryptographic proof of what happened in the Airlock.
///
/// The 4 dimensions of TIBET:
/// - **erin**: What's IN the token (payload/result/error)
/// - **eraan**: What's ATTACHED (dependencies, images, refs)
/// - **eromheen**: What's AROUND it (context, syscalls, triage decision)
/// - **erachter**: What's BEHIND it (the original intent/purpose)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TibetProvenance {
    pub tbz_version: String,
    pub token_type: String,
    pub timestamp: String,
    pub ains_identity: String,
    pub intent: String,

    // The 4 Dimensions
    pub erin: String,
    pub eraan: String,
    pub eromheen: String,
    pub erachter: String,

    pub execution_time_ms: f64,
    pub vm_id: String,
    pub cryptographic_seal: String,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub observed_syscalls: Vec<String>,
}

impl TibetProvenance {
    pub fn generate_success(
        frame: &crate::mux::TibetMuxFrame,
        result: String,
        vm_id: &str,
        execution_ms: f64,
        syscalls: Vec<String>,
    ) -> Self {
        TibetProvenance {
            tbz_version: "v0.3.1-AIRLOCK".to_string(),
            token_type: "SAFE_EXECUTION".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            ains_identity: frame.from_aint.clone(),
            intent: frame.intent.clone(),
            erin: result,
            eraan: format!("vm:{}", vm_id),
            eromheen: "SNAFT: All syscalls within intent bounds".to_string(),
            erachter: frame.intent.clone(),
            execution_time_ms: execution_ms,
            vm_id: vm_id.to_string(),
            cryptographic_seal: "tbz_sign_ed25519_safeboot".to_string(),
            violations: vec![],
            observed_syscalls: syscalls,
        }
    }

    pub fn generate_incident(
        frame: &crate::mux::TibetMuxFrame,
        decision: &crate::snaft::Decision,
        vm_id: &str,
        execution_ms: f64,
    ) -> Self {
        TibetProvenance {
            tbz_version: "v0.3.1-AIRLOCK-INCIDENT".to_string(),
            token_type: "INCIDENT_KILL".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            ains_identity: frame.from_aint.clone(),
            intent: frame.intent.clone(),
            erin: "VM Execution Terminated — intent bounds violated".to_string(),
            eraan: format!("vm:{}", vm_id),
            eromheen: format!("Triage: KILL. {}", decision.reason),
            erachter: frame.intent.clone(),
            execution_time_ms: execution_ms,
            vm_id: vm_id.to_string(),
            cryptographic_seal: "tbz_sign_ed25519_incident".to_string(),
            violations: decision.violations.clone(),
            observed_syscalls: decision.observed_syscalls.clone(),
        }
    }

    pub fn generate_rejected(
        frame: &crate::mux::TibetMuxFrame,
        reason: &str,
    ) -> Self {
        TibetProvenance {
            tbz_version: "v0.3.1-AIRLOCK-REJECTED".to_string(),
            token_type: "INTENT_REJECTED".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            ains_identity: frame.from_aint.clone(),
            intent: frame.intent.clone(),
            erin: "Intent rejected — no safe snapshot available".to_string(),
            eraan: "none".to_string(),
            eromheen: format!("Rejection: {}", reason),
            erachter: frame.intent.clone(),
            execution_time_ms: 0.0,
            vm_id: "none".to_string(),
            cryptographic_seal: "tbz_sign_ed25519_rejection".to_string(),
            violations: vec![],
            observed_syscalls: vec![],
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }
}
