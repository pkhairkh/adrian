//! # adrian-policy-executor
//!
//! `PolicyExecutor` trait + 3 platform implementations (Windows, macOS,
//! Linux) for the Adrian framework.
//!
//! Per ADR-024 §Decision and ADR-113 §Decision, the framework's policy model
//! uses a canonical JSON representation (`adrian-policy-core`) that compiles
//! to platform-native formats. This crate defines the `PolicyExecutor` trait
//! and three implementations:
//!
//! - [`WindowsPolicyExecutor`] — emits PReg `Registry.pol` + `GptTmpl.inf` +
//!   `Scripts.ini` + GPP XML + synthetic CSE JSON
//! - [`MacOsPolicyExecutor`] — emits MDM Configuration Profile payloads
//!   (`com.apple.ManagedClient.preferences`, `com.apple.security.firewall`,
//!   `com.apple.passwordpolicy`, `com.apple.configuration.files`)
//! - [`LinuxPolicyExecutor`] — emits `authselect` profile fragments +
//!   `/etc/security/limits.conf.d/` + `/etc/audit/rules.d/` +
//!   `/etc/login.defs.d/` + `firewalld`/`nftables` + atomic `rename(2)`
//!   writes
//!
//! The trait is the seam that lets one canonical JSON policy doc compile to
//! three platform-native formats (per ADR-113 §Decision).
//!
//! ## ADRs
//!
//! - ADR-024: Per-platform policy executors
//! - ADR-025: Transactional policy rollback
//! - ADR-050: `authselect` standard PAM (Linux)
//! - ADR-091: GPP cross-platform compilation
//! - ADR-092: PolicyExecutor trait (synthetic Windows CSE)
//! - ADR-113: GPP cross-platform policy
//! - ADR-118: MCX legacy macOS → MDM DDM migration
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-policy-core`, `adrian-schema-traits`, `adrian-sid`. Each
//! platform implementation is gated by a per-platform feature flag
//! (`windows`, `macos`, `linux`) per finaldraft/04-rust-workspace-design.md
//! §7 — Linux deployments don't need to compile the macOS executor.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_policy_core::{PolicyDoc, PolicyError};
use async_trait::async_trait;
use uuid::Uuid;

/// The `PolicyExecutor` trait (per ADR-092 §Decision).
///
/// Three implementations: [`WindowsPolicyExecutor`],
/// [`MacOsPolicyExecutor`], [`LinuxPolicyExecutor`]. The trait is the seam
/// that lets one canonical JSON policy doc compile to three platform-native
/// formats (per ADR-113 §Decision).
#[async_trait]
pub trait PolicyExecutor: Send + Sync {
    /// Apply a policy document to the target host (per ADR-113 §Decision).
    /// Returns an `ApplyResult` containing the transaction ID (per ADR-025 —
    /// transactional rollback).
    async fn apply(&self, doc: &PolicyDoc, target_host: &str) -> Result<ApplyResult, PolicyError>;

    /// Roll back a previously-applied policy document (per ADR-025 §Decision
    /// — transactional rollback via the transaction ID returned by `apply`).
    async fn rollback(&self, transaction_id: Uuid) -> Result<(), PolicyError>;

    /// Verify that a policy document was applied correctly (per ADR-113
    /// §Decision — read-back verification).
    async fn verify(&self, doc: &PolicyDoc) -> Result<VerifyResult, PolicyError>;
}

/// The result of a `PolicyExecutor::apply` call (per ADR-025 §Decision —
/// transactional rollback).
#[derive(Debug, Clone)]
pub struct ApplyResult {
    /// The transaction ID (per ADR-025 — used by `rollback` to compute the
    /// inverse diff).
    pub transaction_id: Uuid,
    /// The number of policy areas successfully applied.
    pub areas_applied: usize,
    /// The number of policy areas that failed to apply.
    pub areas_failed: usize,
    /// The error messages for failed areas (per ADR-025).
    pub errors: Vec<String>,
}

/// The result of a `PolicyExecutor::verify` call (per ADR-113 §Decision).
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Whether the policy document was applied correctly.
    pub verified: bool,
    /// The areas that did not verify.
    pub failed_areas: Vec<String>,
}

/// Windows policy executor (per ADR-024 §Decision).
///
/// Emits PReg `Registry.pol` + `GptTmpl.inf` + `Scripts.ini` + GPP XML +
/// synthetic CSE JSON. The synthetic CSE JSON is consumed by the framework's
/// Windows client (per ADR-092 §Decision) so that framework-native policy
/// areas (audit, firewall, etc.) are applied via the same GPO mechanism as
/// standard Windows policy.
#[derive(Debug, Default, Clone)]
pub struct WindowsPolicyExecutor;

#[async_trait]
impl PolicyExecutor for WindowsPolicyExecutor {
    async fn apply(
        &self,
        _doc: &PolicyDoc,
        _target_host: &str,
    ) -> Result<ApplyResult, PolicyError> {
        // TODO: implement per ADR-024 / ADR-092 — compile PolicyDoc to
        // PReg Registry.pol + GptTmpl.inf + Scripts.ini + GPP XML + synthetic
        // CSE JSON; copy to SYSVOL via SMB (per ADR-094) or to MDM via
        // WebSocket push (per ADR-028).
        Err(PolicyError::UnsupportedArea(
            "WindowsPolicyExecutor::apply not yet implemented".into(),
        ))
    }

    async fn rollback(&self, _transaction_id: Uuid) -> Result<(), PolicyError> {
        // TODO: implement per ADR-025 — read the transaction's inverse diff
        // and apply it.
        Err(PolicyError::UnsupportedArea(
            "WindowsPolicyExecutor::rollback not yet implemented".into(),
        ))
    }

    async fn verify(&self, _doc: &PolicyDoc) -> Result<VerifyResult, PolicyError> {
        // TODO: implement per ADR-113 — read back PReg / GptTmpl / Scripts /
        // GPP XML and compare.
        Err(PolicyError::UnsupportedArea(
            "WindowsPolicyExecutor::verify not yet implemented".into(),
        ))
    }
}

/// macOS policy executor (per ADR-024 §Decision).
///
/// Emits MDM Configuration Profile payloads:
/// - `com.apple.ManagedClient.preferences` (per ADR-118 — MCX legacy
///   migration)
/// - `com.apple.security.firewall`
/// - `com.apple.passwordpolicy`
/// - `com.apple.configuration.files`
#[derive(Debug, Default, Clone)]
pub struct MacOsPolicyExecutor;

#[async_trait]
impl PolicyExecutor for MacOsPolicyExecutor {
    async fn apply(
        &self,
        _doc: &PolicyDoc,
        _target_host: &str,
    ) -> Result<ApplyResult, PolicyError> {
        // TODO: implement per ADR-024 / ADR-118 — compile PolicyDoc to MDM
        // Configuration Profile payloads; push via MDM protocol (per
        // ADR-028).
        Err(PolicyError::UnsupportedArea(
            "MacOsPolicyExecutor::apply not yet implemented".into(),
        ))
    }

    async fn rollback(&self, _transaction_id: Uuid) -> Result<(), PolicyError> {
        // TODO: implement per ADR-025 — MDM "remove profile" command.
        Err(PolicyError::UnsupportedArea(
            "MacOsPolicyExecutor::rollback not yet implemented".into(),
        ))
    }

    async fn verify(&self, _doc: &PolicyDoc) -> Result<VerifyResult, PolicyError> {
        // TODO: implement per ADR-113 — read back MDM profile via
        // `profiles show -output stdout-xml` on macOS.
        Err(PolicyError::UnsupportedArea(
            "MacOsPolicyExecutor::verify not yet implemented".into(),
        ))
    }
}

/// Linux policy executor (per ADR-024 §Decision / ADR-050).
///
/// Emits `authselect` profile fragments + `/etc/security/limits.conf.d/` +
/// `/etc/audit/rules.d/` + `/etc/login.defs.d/` + `firewalld`/`nftables` +
/// atomic `rename(2)` writes (per ADR-113 §Decision — atomic writes to avoid
/// partial-application state).
#[derive(Debug, Default, Clone)]
pub struct LinuxPolicyExecutor;

#[async_trait]
impl PolicyExecutor for LinuxPolicyExecutor {
    async fn apply(
        &self,
        _doc: &PolicyDoc,
        _target_host: &str,
    ) -> Result<ApplyResult, PolicyError> {
        // TODO: implement per ADR-024 / ADR-050 / ADR-113 — compile PolicyDoc
        // to authselect profile fragments + limits.conf.d + audit.rules.d +
        // login.defs.d + nftables; apply via atomic rename(2) writes.
        Err(PolicyError::UnsupportedArea(
            "LinuxPolicyExecutor::apply not yet implemented".into(),
        ))
    }

    async fn rollback(&self, _transaction_id: Uuid) -> Result<(), PolicyError> {
        // TODO: implement per ADR-025 — restore the previous
        // authselect/limits/audit/login.defs/nftables state from the
        // transaction's snapshot.
        Err(PolicyError::UnsupportedArea(
            "LinuxPolicyExecutor::rollback not yet implemented".into(),
        ))
    }

    async fn verify(&self, _doc: &PolicyDoc) -> Result<VerifyResult, PolicyError> {
        // TODO: implement per ADR-113 — read back authselect/limits/audit/
        // login.defs/nftables and compare.
        Err(PolicyError::UnsupportedArea(
            "LinuxPolicyExecutor::verify not yet implemented".into(),
        ))
    }
}

// TODO: implement PReg Registry.pol writer per ADR-029 (MS-PREG wire format).
// TODO: implement GPP XML writer per ADR-091.
// TODO: implement MDM Configuration Profile plist writer per ADR-118.
// TODO: implement authselect profile fragment writer per ADR-050.
// TODO: implement nftables ruleset writer per ADR-113.
// TODO: implement atomic rename(2) writer per ADR-113 §Decision.

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-policy-executor`. Per the task instructions
    //! these cover type construction, the `PolicyExecutor` trait surface,
    //! loud-stub behaviour, and `ApplyResult` / `VerifyResult` field
    //! propagation — no real network or platform I/O.

    use super::*;
    use adrian_policy_core::{PolicyArea, PolicyDoc, PolicyScope, RegistryPolicy};
    use uuid::Uuid;

    /// Helper: build a minimal valid `PolicyDoc` for driving trait stubs.
    fn sample_doc() -> PolicyDoc {
        PolicyDoc {
            // `Uuid::nil()` is used because the workspace `uuid` crate
            // enables only `v7` + `serde` (no `v4`); the value is
            // irrelevant to the trait-stub coverage here.
            uuid: Uuid::nil(),
            name: "test".into(),
            version: "0.0.1".into(),
            areas: vec![PolicyArea::Registry(RegistryPolicy { values: vec![] })],
            security_descriptor: None,
            scope: PolicyScope {
                principals: vec!["S-1-5-32-544".into()],
                ous: vec![],
                hosts: vec!["host01".into()],
            },
        }
    }

    #[test]
    fn apply_result_carries_fields() {
        let txn = Uuid::nil();
        let r = ApplyResult {
            transaction_id: txn,
            areas_applied: 3,
            areas_failed: 1,
            errors: vec!["audit: boom".into()],
        };
        assert_eq!(r.transaction_id, txn);
        assert_eq!(r.areas_applied, 3);
        assert_eq!(r.areas_failed, 1);
        assert_eq!(r.errors.len(), 1);
    }

    #[test]
    fn verify_result_failed_areas_default_empty() {
        let r = VerifyResult {
            verified: true,
            failed_areas: vec![],
        };
        assert!(r.verified);
        assert!(r.failed_areas.is_empty());
    }

    #[tokio::test]
    async fn windows_executor_stubs_return_unsupported_area() {
        // Loud-stub contract: unimplemented trait methods must surface a
        // typed `PolicyError::UnsupportedArea` rather than `panic!` or
        // `todo!`. This guards the per-platform executors until
        // ADR-024/ADR-092 land.
        let exec = WindowsPolicyExecutor;
        let doc = sample_doc();

        let apply_err = exec.apply(&doc, "host01").await.unwrap_err();
        assert!(matches!(
            apply_err,
            PolicyError::UnsupportedArea(ref m) if m.contains("WindowsPolicyExecutor::apply")
        ));

        let rollback_err = exec.rollback(Uuid::nil()).await.unwrap_err();
        assert!(matches!(
            rollback_err,
            PolicyError::UnsupportedArea(ref m) if m.contains("rollback")
        ));

        let verify_err = exec.verify(&doc).await.unwrap_err();
        assert!(matches!(
            verify_err,
            PolicyError::UnsupportedArea(ref m) if m.contains("verify")
        ));
    }

    #[tokio::test]
    async fn macos_and_linux_executors_surface_unsupported_area() {
        let mac = MacOsPolicyExecutor;
        let linux = LinuxPolicyExecutor;
        let doc = sample_doc();

        let mac_err = mac.apply(&doc, "host01").await.unwrap_err();
        assert!(matches!(
            mac_err,
            PolicyError::UnsupportedArea(ref m) if m.contains("MacOsPolicyExecutor")
        ));

        let linux_err = linux.apply(&doc, "host01").await.unwrap_err();
        assert!(matches!(
            linux_err,
            PolicyError::UnsupportedArea(ref m) if m.contains("LinuxPolicyExecutor")
        ));
    }

    #[test]
    fn cloneable_unit_executor_round_trips_debug() {
        // `#[derive(Clone, Debug)]` on the executor structs must produce
        // equal-by-construction values — this catches regressions if
        // someone adds a field without updating `Clone`/`Debug`.
        // Unit structs should be constructed directly per clippy's
        // `default_constructed_unit_structs` lint.
        let a = WindowsPolicyExecutor;
        let b = a.clone();
        // `WindowsPolicyExecutor` is a unit struct, so any two instances
        // are equal-by-construction; we still assert via `Debug` format
        // to guard the `Debug` derive and catch silent regressions.
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}
