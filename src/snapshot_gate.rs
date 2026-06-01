//! Snapshot Active Gate (v1.2) — snapshot as a PRECONDITION for risk, not recovery.
//!
//! The immune-system shift (Jasper 28 mei, memory project_active_immune_system_pattern):
//! a destructive action cannot physically run without fresh immune-memory beneath it.
//! The snapshot is not a backup you restore after a fault — it is the T-cell priming
//! that must exist *before* a risky operation is permitted.
//!
//! Canonical rule this enforces:
//! ```yaml
//! rule: destructive-rmrf
//! allow_iff:
//!   - snaft.runtime.running == true
//!   - trust_kernel.snapshot.age_seconds < 60
//!   - jis.identity.verdict == "allowed"
//!   - bifurcation.sandbox_clone.ready == true   # destructive only
//! else: refuse (NOT "log warn") — het mag fysiek niet
//! ```
//!
//! "ACTIVE" gate: when the snapshot is stale but every other precondition holds, the
//! gate may *capture a fresh snapshot as the precondition* and then allow — it primes
//! the immune-memory rather than just rejecting. If that capture fails, the verdict is
//! Denied (no-fail-open). The gate never fails open.

use crate::snapshot::SnapshotEngine;

/// How risky is the operation the caller wants to perform?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    /// Read-only / no state mutation. Always allowed.
    Benign,
    /// Mutates state but reversible. Requires fresh snapshot + identity + snaft.
    Sensitive,
    /// Irreversible / destructive (rm -rf, key-wipe, mass-delete). Above + bifurcation clone.
    Destructive,
}

/// The runtime preconditions the gate evaluates. These mirror snaft's `allow_iff`
/// runtime-state queries (task #15) so a snaft rule and the kernel gate agree.
#[derive(Debug, Clone)]
pub struct GateContext {
    /// snaft.runtime.running
    pub snaft_running: bool,
    /// jis.identity.verdict == "allowed"
    pub identity_allowed: bool,
    /// bifurcation.sandbox_clone.ready (only required for Destructive)
    pub bifurcation_ready: bool,
    /// Max age (seconds) a snapshot may have to count as "fresh immune-memory".
    pub max_snapshot_age_secs: u64,
}

impl Default for GateContext {
    fn default() -> Self {
        Self {
            snaft_running: false,
            identity_allowed: false,
            bifurcation_ready: false,
            max_snapshot_age_secs: 60,
        }
    }
}

/// The gate's decision. Denied is terminal (the op physically may not run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    /// Operation permitted. `fresh_snapshot_id` is the immune-memory anchor it rides on
    /// (None only for Benign, which needs no snapshot).
    Allowed { fresh_snapshot_id: Option<String> },
    /// Operation refused. No-fail-open: this is a hard stop, not a warning.
    Denied { reason: String },
}

impl GateVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateVerdict::Allowed { .. })
    }
}

/// Active snapshot gate. Wraps the SnapshotEngine and tracks the freshest snapshot's
/// capture time so `snapshot_age_seconds()` can answer snaft's runtime-state query.
pub struct SnapshotGate {
    engine: SnapshotEngine,
    /// Unix epoch seconds of the most recent successful snapshot, if any.
    last_snapshot_epoch: Option<i64>,
    last_snapshot_id: Option<String>,
}

impl SnapshotGate {
    pub fn new(engine: SnapshotEngine) -> Self {
        Self { engine, last_snapshot_epoch: None, last_snapshot_id: None }
    }

    /// Current age of the freshest snapshot in seconds, or None if none captured yet.
    /// This is the value a snaft `allow_iff: trust_kernel.snapshot.age_seconds < N` reads.
    pub fn snapshot_age_seconds(&self, now_epoch: i64) -> Option<u64> {
        self.last_snapshot_epoch
            .map(|t| (now_epoch - t).max(0) as u64)
    }

    /// Is there fresh immune-memory (a snapshot younger than max_age)?
    pub fn has_fresh_snapshot(&self, now_epoch: i64, max_age_secs: u64) -> bool {
        matches!(self.snapshot_age_seconds(now_epoch), Some(age) if age < max_age_secs)
    }

    /// Record that a snapshot was just captured (called after engine.capture succeeds).
    pub fn mark_snapshot(&mut self, id: &str, now_epoch: i64) {
        self.last_snapshot_epoch = Some(now_epoch);
        self.last_snapshot_id = Some(id.to_string());
    }

    /// THE GATE. Evaluate whether `risk` may proceed given the runtime context.
    ///
    /// `now_epoch` is the caller-provided current unix-epoch seconds (the daemon passes
    /// chrono::Utc::now().timestamp(); injectable here so the logic is unit-testable).
    ///
    /// `prime_region` is the memory the gate snapshots if it must actively prime fresh
    /// immune-memory (None disables active priming — then a stale snapshot just denies).
    pub fn evaluate(
        &mut self,
        risk: RiskClass,
        ctx: &GateContext,
        now_epoch: i64,
        prime_region: Option<&[u8]>,
        intent: &str,
        from_aint: &str,
    ) -> GateVerdict {
        // Benign: read-only, no immune-memory required.
        if risk == RiskClass::Benign {
            return GateVerdict::Allowed { fresh_snapshot_id: None };
        }

        // Shared preconditions for any risky op (no-fail-open: each missing one = hard deny).
        if !ctx.snaft_running {
            return GateVerdict::Denied {
                reason: "snaft.runtime.running == false — no active immune response".into(),
            };
        }
        if !ctx.identity_allowed {
            return GateVerdict::Denied {
                reason: "jis.identity.verdict != allowed — self-recognition failed".into(),
            };
        }
        // Destructive needs a ready bifurcation sandbox-clone (split-and-watch).
        if risk == RiskClass::Destructive && !ctx.bifurcation_ready {
            return GateVerdict::Denied {
                reason: "bifurcation.sandbox_clone not ready — destructive op needs split-and-watch".into(),
            };
        }

        // Fresh immune-memory check.
        if self.has_fresh_snapshot(now_epoch, ctx.max_snapshot_age_secs) {
            return GateVerdict::Allowed {
                fresh_snapshot_id: self.last_snapshot_id.clone(),
            };
        }

        // Stale (or no) snapshot. ACTIVE step: try to prime fresh immune-memory now.
        match prime_region {
            Some(region) => match self.engine.capture(region, intent, from_aint, 0, false) {
                crate::snapshot::CaptureResult::Success { snapshot, .. } => {
                    self.mark_snapshot(&snapshot.id, now_epoch);
                    GateVerdict::Allowed { fresh_snapshot_id: Some(snapshot.id) }
                }
                crate::snapshot::CaptureResult::Skipped { reason } => GateVerdict::Denied {
                    reason: format!("active snapshot-prime skipped, no immune-memory made (no-fail-open): {}", reason),
                },
                crate::snapshot::CaptureResult::Failed { reason } => GateVerdict::Denied {
                    reason: format!("active snapshot-prime failed (no-fail-open): {}", reason),
                },
            },
            None => GateVerdict::Denied {
                reason: format!(
                    "no fresh snapshot (age >= {}s) and active priming disabled — immune-memory absent",
                    ctx.max_snapshot_age_secs
                ),
            },
        }
    }

    pub fn engine(&self) -> &SnapshotEngine {
        &self.engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> SnapshotEngine {
        SnapshotEngine::new("/tmp/tk-gate-test", false)
    }
    fn good_ctx() -> GateContext {
        GateContext { snaft_running: true, identity_allowed: true, bifurcation_ready: true, max_snapshot_age_secs: 60 }
    }

    #[test]
    fn benign_always_allowed_without_snapshot() {
        let mut g = SnapshotGate::new(engine());
        let v = g.evaluate(RiskClass::Benign, &GateContext::default(), 1000, None, "read", "jis:x");
        assert!(v.is_allowed());
        if let GateVerdict::Allowed { fresh_snapshot_id } = v { assert!(fresh_snapshot_id.is_none()); }
    }

    #[test]
    fn destructive_denied_when_snaft_down() {
        let mut g = SnapshotGate::new(engine());
        let ctx = GateContext { snaft_running: false, ..good_ctx() };
        let v = g.evaluate(RiskClass::Destructive, &ctx, 1000, Some(b"mem"), "rm", "jis:x");
        assert!(matches!(v, GateVerdict::Denied { .. }));
    }

    #[test]
    fn destructive_denied_when_identity_not_allowed() {
        let mut g = SnapshotGate::new(engine());
        let ctx = GateContext { identity_allowed: false, ..good_ctx() };
        let v = g.evaluate(RiskClass::Destructive, &ctx, 1000, Some(b"mem"), "rm", "jis:x");
        assert!(matches!(v, GateVerdict::Denied { .. }));
    }

    #[test]
    fn destructive_denied_when_bifurcation_not_ready() {
        let mut g = SnapshotGate::new(engine());
        let ctx = GateContext { bifurcation_ready: false, ..good_ctx() };
        let v = g.evaluate(RiskClass::Destructive, &ctx, 1000, Some(b"mem"), "rm", "jis:x");
        assert!(matches!(v, GateVerdict::Denied { .. }));
    }

    #[test]
    fn fresh_snapshot_allows_without_repriming() {
        let mut g = SnapshotGate::new(engine());
        g.mark_snapshot("snap_existing", 1000);
        // 30s later, max_age 60 → still fresh, allowed, rides the existing snapshot.
        let v = g.evaluate(RiskClass::Sensitive, &good_ctx(), 1030, None, "write", "jis:x");
        assert_eq!(v, GateVerdict::Allowed { fresh_snapshot_id: Some("snap_existing".into()) });
    }

    #[test]
    fn stale_snapshot_no_priming_denies() {
        let mut g = SnapshotGate::new(engine());
        g.mark_snapshot("snap_old", 1000);
        // 120s later, max_age 60 → stale, priming disabled (None) → deny.
        let v = g.evaluate(RiskClass::Sensitive, &good_ctx(), 1120, None, "write", "jis:x");
        assert!(matches!(v, GateVerdict::Denied { .. }));
    }

    #[test]
    fn active_priming_captures_then_allows() {
        let mut g = SnapshotGate::new(engine());
        // No prior snapshot, but region supplied → gate primes immune-memory then allows.
        let v = g.evaluate(RiskClass::Sensitive, &good_ctx(), 2000, Some(b"region-bytes"), "write", "jis:x");
        match v {
            GateVerdict::Allowed { fresh_snapshot_id } => assert!(fresh_snapshot_id.is_some()),
            other => panic!("expected Allowed after priming, got {:?}", other),
        }
        // and the gate now reports a 0s-age fresh snapshot
        assert_eq!(g.snapshot_age_seconds(2000), Some(0));
    }

    #[test]
    fn active_priming_empty_region_denies_no_fail_open() {
        let mut g = SnapshotGate::new(engine());
        // empty region → engine.capture fails → gate denies (never fails open)
        let v = g.evaluate(RiskClass::Destructive, &good_ctx(), 3000, Some(b""), "rm", "jis:x");
        assert!(matches!(v, GateVerdict::Denied { .. }));
    }

    #[test]
    fn age_query_for_snaft() {
        let mut g = SnapshotGate::new(engine());
        assert_eq!(g.snapshot_age_seconds(1000), None);
        g.mark_snapshot("s", 1000);
        assert_eq!(g.snapshot_age_seconds(1045), Some(45));
        assert!(g.has_fresh_snapshot(1045, 60));
        assert!(!g.has_fresh_snapshot(1061, 60));
    }
}
