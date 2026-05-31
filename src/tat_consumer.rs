//! TAT envelope consumer + biometric vehicle dispatcher.
//!
//! Receives TAT envelopes from osapi_adapter (port 18444) and picks the
//! biometric vehicle for fresh re-attestation per the 5-tier ladder
//! (see Jasper memory `project_fresh_assurance_point_of_use_platform_pair`,
//! 31 mei 2026):
//!
//!   Tier 1 — smartphone native (Pixel 10 KIT, TouchID, FaceID)
//!   Tier 2 — laptop native fingerprint (Mac TouchID, Windows Hello, Linux fp)
//!   Tier 3 — delegated: laptop → i-poll → user smartphone .aint → JTm prompt
//!   Tier 4 — external USB token (briefly connected, not shared device)
//!   Tier 5 — passkey + .aint binding (WebAuthn-style + AInternet identity)
//!
//! Floor: never andermans device. Shared/public devices fall outside all tiers.
//!
//! v1.1 implementation is a deterministic stub that picks based on JIS-target
//! shape — production wires this to a device-capability registry that the
//! trust-kernel maintains per operator (cap-bus or AINS resolution).

use serde::{Deserialize, Serialize};

/// What the operator must do to satisfy the re-attestation request,
/// and through which transport the prompt is delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehicleDispatch {
    pub intent: String,
    pub vehicle: String,
    pub tier: u8,
    pub target: String,
    pub transport: String,
    pub prompt: String,
    pub candidate_hash: String,
    pub ttl_seconds: u64,
    pub no_fail_open: bool,
}

/// Decide which biometric vehicle to use for a re-attestation request.
///
/// Heuristic (v1.1 deterministic):
///   - `to` starts with `jis:pixel10:` or `jis:android:`  → Tier 1 native smartphone
///   - `to` starts with `jis:macos:` or `jis:windows:` or `jis:linux:` → Tier 2 native laptop
///   - `to` starts with `jis:laptop:` (no platform-hint) → Tier 3 delegated to smartphone .aint
///   - `to` starts with `jis:usb-token:` → Tier 4 external token
///   - everything else / unknown shape → Tier 5 passkey + .aint binding
///
/// Production wires this to a per-operator device-capability registry; the
/// stub is sufficient for the v1.1 contract (decision is reproducible from
/// envelope alone, no hidden state).
pub fn decide_vehicle(
    intent: &str,
    to: &str,
    candidate_hash: &str,
    ttl_seconds: u64,
) -> VehicleDispatch {
    let (vehicle, tier, transport, prompt) = pick(to);
    VehicleDispatch {
        intent: intent.to_string(),
        vehicle: vehicle.to_string(),
        tier,
        target: to.to_string(),
        transport: transport.to_string(),
        prompt: prompt.to_string(),
        candidate_hash: candidate_hash.to_string(),
        ttl_seconds,
        // no-fail-open: if the vehicle is not reachable or biometric not
        // confirmed within ttl_seconds, the grant MUST stay denied. This
        // is the trust-kernel invariant (Jasper-spec 31 mei).
        no_fail_open: true,
    }
}

fn pick(to: &str) -> (&'static str, u8, &'static str, &'static str) {
    if to.starts_with("jis:pixel10:") || to.starts_with("jis:android:") {
        (
            "smartphone-native",
            1,
            "direct-keystore",
            "Scan fingerprint on phone to re-attest pending grant",
        )
    } else if to.starts_with("jis:macos:")
        || to.starts_with("jis:windows:")
        || to.starts_with("jis:linux:")
    {
        (
            "laptop-native-fp",
            2,
            "direct-platform-auth",
            "Scan fingerprint on laptop sensor to re-attest pending grant",
        )
    } else if to.starts_with("jis:laptop:") {
        (
            "delegated-smartphone",
            3,
            "ainternet-ipoll",
            "Approve the prompt on your phone — laptop has no biometric",
        )
    } else if to.starts_with("jis:usb-token:") {
        (
            "external-usb-token",
            4,
            "usb-cdc",
            "Connect and touch your USB token to re-attest pending grant",
        )
    } else {
        (
            "passkey-aint",
            5,
            "webauthn-aint",
            "Approve the passkey challenge bound to your .aint identity",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_1_for_pixel10_target() {
        let d = decide_vehicle("request_re_attestation", "jis:pixel10:storm", "sha256:x", 300);
        assert_eq!(d.tier, 1);
        assert_eq!(d.vehicle, "smartphone-native");
        assert_eq!(d.transport, "direct-keystore");
        assert!(d.no_fail_open);
    }

    #[test]
    fn tier_2_for_macos_target() {
        let d = decide_vehicle("request_re_attestation", "jis:macos:jasper", "sha256:x", 300);
        assert_eq!(d.tier, 2);
        assert_eq!(d.vehicle, "laptop-native-fp");
    }

    #[test]
    fn tier_3_for_laptop_without_platform() {
        let d = decide_vehicle("request_re_attestation", "jis:laptop:jasper", "sha256:x", 300);
        assert_eq!(d.tier, 3);
        assert_eq!(d.vehicle, "delegated-smartphone");
        assert_eq!(d.transport, "ainternet-ipoll");
    }

    #[test]
    fn tier_4_for_usb_token() {
        let d = decide_vehicle("request_re_attestation", "jis:usb-token:yubi", "sha256:x", 300);
        assert_eq!(d.tier, 4);
        assert_eq!(d.vehicle, "external-usb-token");
    }

    #[test]
    fn tier_5_for_unknown_shape_passkey_fallback() {
        let d = decide_vehicle("request_re_attestation", "jis:humotica:operator", "sha256:x", 300);
        assert_eq!(d.tier, 5);
        assert_eq!(d.vehicle, "passkey-aint");
    }

    #[test]
    fn no_fail_open_always_true() {
        for to in &["jis:pixel10:a", "jis:macos:b", "jis:laptop:c",
                     "jis:usb-token:d", "jis:humotica:e"] {
            let d = decide_vehicle("x", to, "y", 1);
            assert!(d.no_fail_open, "no_fail_open must be true for {}", to);
        }
    }
}
