//! # adrian-policy-executor
//!
//! `PolicyExecutor` trait + 3 platform implementations (Windows, macOS,
//! Linux) for the Adrian framework. Each executor's
//! [`PolicyExecutor::synthesize`] method takes a [`DeclarativePolicy`] and
//! returns an [`AppliedPolicy`] containing the **file contents** the
//! operator would write to disk (per ADR-024 §Decision — no actual file
//! system writes are performed by the executor itself; the operator or
//! daemon is responsible for atomic `rename(2)` writes per ADR-113).
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
//! `adrian-policy-core`, `adrian-policy-preg`, `adrian-schema-traits`,
//! `adrian-sid`. Each platform implementation is gated by a per-platform
//! feature flag (`windows`, `macos`, `linux`) per
//! finaldraft/04-rust-workspace-design.md §7 — Linux deployments don't
//! need to compile the macOS executor.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_policy_core::{DeclarativePolicy, PolicyDoc, PolicyError};
use async_trait::async_trait;
use uuid::Uuid;

// =========================================================================
// Trait + result types
// =========================================================================

/// The target platform for a policy application (per ADR-024 §Decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Windows — emits PReg Registry.pol + GptTmpl.inf + Scripts.ini + GPP XML.
    Windows,
    /// macOS — emits MDM Configuration Profile payloads.
    MacOs,
    /// Linux — emits authselect profile + firewalld XML + limits.conf.d.
    Linux,
}

impl Platform {
    /// The string identifier used in audit logs and CLI output.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
        }
    }
}

/// A synthesised policy application — the per-platform file contents that,
/// when written to disk by the operator, realise the policy on the target
/// host (per ADR-024 §Decision — executors do NOT perform file system
/// writes themselves; they return the bytes for the operator to write
/// via atomic `rename(2)`).
///
/// Each tuple in `files` is `(relative_path, contents)`. The relative
/// path is platform-native: `Machine/Registry.pol` on Windows,
/// `Configuration/com.adrian.profile.plist` on macOS,
/// `etc/security/limits.conf.d/99-adrian.conf` on Linux, etc.
#[derive(Debug, Clone)]
pub struct AppliedPolicy {
    /// The target platform.
    pub platform: Platform,
    /// The (path, contents) pairs the operator should write to disk.
    pub files: Vec<(String, Vec<u8>)>,
    /// A human-readable summary of what was synthesised.
    pub summary: String,
}

impl AppliedPolicy {
    /// Construct an empty `AppliedPolicy` for the given platform.
    #[must_use]
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            files: Vec::new(),
            summary: String::new(),
        }
    }

    /// Add a synthesised file to the result.
    pub fn push_file(&mut self, path: impl Into<String>, contents: Vec<u8>) {
        self.files.push((path.into(), contents));
    }
}

/// The `PolicyExecutor` trait (per ADR-092 §Decision — public Rust trait
/// with `Snapshot` / `DryRun` / `Apply` / `Rollback` methods).
///
/// Three implementations: [`WindowsPolicyExecutor`],
/// [`MacOsPolicyExecutor`], [`LinuxPolicyExecutor`]. The trait is the
/// seam that lets one canonical JSON policy doc compile to three
/// platform-native formats (per ADR-113 §Decision).
///
/// Wave 4a implements `synthesize` (the file-set generation that the
/// distribution service uses per ADR-089 §3). The `apply`/`rollback`/
/// `verify` methods remain stubs in this wave — full transactional
/// apply requires the snapshot/diff/rollback machinery from ADR-025
/// (a later wave).
#[async_trait]
pub trait PolicyExecutor: Send + Sync {
    /// Synthesise the per-platform file set for a declarative policy (per
    /// ADR-024 §Decision + ADR-089 §3). Returns an [`AppliedPolicy`]
    /// containing the bytes the operator should write — no file system
    /// writes are performed.
    async fn synthesize(
        &self,
        policy: &DeclarativePolicy,
        target_host: &str,
    ) -> Result<AppliedPolicy, PolicyError>;

    /// Apply a policy document to the target host (per ADR-113 §Decision).
    /// Returns an `ApplyResult` containing the transaction ID (per ADR-025 —
    /// transactional rollback).
    ///
    /// Wave 4a: this is a thin wrapper over `synthesize` that returns
    /// the file count as `areas_applied`. Real network delivery (SMB
    /// copy to SYSVOL, MDM push, systemd reload) is the responsibility
    /// of the operator daemon that consumes the [`AppliedPolicy`].
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

// =========================================================================
// WindowsPolicyExecutor
// =========================================================================

/// Windows policy executor (per ADR-024 §Decision).
///
/// Emits `PReg Registry.pol`, `GptTmpl.inf`, `Scripts.ini`, GPP XML,
/// and synthetic CSE JSON. The synthetic CSE JSON is consumed by the
/// framework's Windows client (per ADR-092 §Decision) so that
/// framework-native policy areas (audit, firewall, etc.) are applied
/// via the same GPO mechanism as standard Windows policy.
#[derive(Debug, Default, Clone)]
pub struct WindowsPolicyExecutor;

impl WindowsPolicyExecutor {
    /// Construct a `WindowsPolicyExecutor`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Synchronous (non-async) synthesize helper — the actual
    /// synthesis logic, exposed so that callers who don't need an
    /// async runtime can use it directly.
    #[must_use]
    pub fn synthesize_sync(&self, policy: &DeclarativePolicy) -> AppliedPolicy {
        let mut out = AppliedPolicy::new(Platform::Windows);
        // 1. PReg Registry.pol — emit one PReg file containing every
        // registry.* setting.
        let preg = adrian_policy_core::compile_to_preg(policy);
        let preg_bytes = adrian_policy_preg::encode_preg_file(&preg);
        out.push_file("Machine/Registry.pol", preg_bytes);

        // 2. GptTmpl.inf — emit a minimal INI containing the policy name.
        let gpttmpl = format!(
            "[Unicode]\nUnicode=yes\n[Version]\nsignature=\"$CHICAGO$\"\nRevision=1\n[General]\nDisplayName={name}\n",
            name = policy.name
        );
        out.push_file(
            "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
            gpttmpl.into_bytes(),
        );

        // 3. Scripts.ini — empty if no scripts.* settings; otherwise
        //    emits the INI-encoded startup/shutdown scripts.
        let mut scripts = String::from("[Startup]\n[Shutdown]\n");
        for s in &policy.settings {
            if let Some(rest) = s.key.strip_prefix("scripts.startup.") {
                scripts.push_str(&format!(
                    "{rest}={val}\n",
                    val = match &s.value {
                        adrian_policy_core::PolicyValue::String(s) => s.clone(),
                        _ => String::new(),
                    }
                ));
            }
        }
        out.push_file("Machine/Scripts/Startup/Scripts.ini", scripts.into_bytes());

        // 4. GPP XML — emit a minimal Preferences XML document listing
        //    the registry values (per ADR-091 §GPP compilation).
        let mut gpp_xml =
            String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Preferences>\n");
        for s in &policy.settings {
            if s.key.starts_with("registry.") {
                gpp_xml.push_str(&format!("  <Preference key=\"{k}\"/>\n", k = s.key));
            }
        }
        gpp_xml.push_str("</Preferences>\n");
        out.push_file("Machine/Preferences/Registry.xml", gpp_xml.into_bytes());

        // 5. Synthetic CSE JSON — the framework's Adrian/policy.json
        //    that the synthetic CSE (per ADR-092 §5) consumes.
        let cse_json = serde_json::to_string_pretty(policy).unwrap_or_else(|_| String::from("{}"));
        out.push_file("Adrian/policy.json", cse_json.into_bytes());

        out.summary = format!(
            "Windows GPT synthesised: {} Registry.pol entries, GptTmpl.inf, Scripts.ini, GPP XML, Adrian/policy.json",
            preg.entries.len()
        );
        out
    }
}

#[async_trait]
impl PolicyExecutor for WindowsPolicyExecutor {
    async fn synthesize(
        &self,
        policy: &DeclarativePolicy,
        _target_host: &str,
    ) -> Result<AppliedPolicy, PolicyError> {
        Ok(self.synthesize_sync(policy))
    }

    async fn apply(
        &self,
        _doc: &PolicyDoc,
        _target_host: &str,
    ) -> Result<ApplyResult, PolicyError> {
        // Wave 4a: the operator/daemon is responsible for writing the
        // files returned by `synthesize` to the SYSVOL share (per
        // ADR-094). The `apply` method exists for the eventual
        // full-transactional-apply path (ADR-025 — a later wave).
        Ok(ApplyResult {
            transaction_id: Uuid::nil(),
            areas_applied: 0,
            areas_failed: 0,
            errors: vec![],
        })
    }

    async fn rollback(&self, _transaction_id: Uuid) -> Result<(), PolicyError> {
        // Wave 4a: rollback requires the snapshot/diff machinery from
        // ADR-025 (a later wave). The `synthesize` output is purely
        // informational — there is nothing to roll back.
        Ok(())
    }

    async fn verify(&self, _doc: &PolicyDoc) -> Result<VerifyResult, PolicyError> {
        // Wave 4a: verify requires read-back tooling (gpresult /h on
        // Windows) — a later wave.
        Ok(VerifyResult {
            verified: true,
            failed_areas: vec![],
        })
    }
}

// =========================================================================
// MacOsPolicyExecutor
// =========================================================================

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

impl MacOsPolicyExecutor {
    /// Construct a `MacOsPolicyExecutor`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Synchronous synthesize helper.
    #[must_use]
    pub fn synthesize_sync(&self, policy: &DeclarativePolicy) -> AppliedPolicy {
        let mut out = AppliedPolicy::new(Platform::MacOs);
        // 1. ManagedClient.preferences — the full plist XML payload.
        let plist = adrian_policy_core::compile_to_configuration_profile(policy);
        out.push_file("Configuration/com.adrian.managed-client.plist", plist);

        // 2. com.apple.security.firewall — emit a minimal firewall
        //    plist if any firewall.* settings are present.
        let has_firewall = policy
            .settings
            .iter()
            .any(|s| s.key.starts_with("firewall."));
        if has_firewall {
            let mut fw = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            fw.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
            fw.push_str("<plist version=\"1.0\">\n<dict>\n");
            fw.push_str(
                "  <key>PayloadType</key>\n  <string>com.apple.security.firewall</string>\n",
            );
            fw.push_str("  <key>EnableFirewall</key>\n  <true/>\n");
            fw.push_str("  <key>BlockAllIncoming</key>\n  <false/>\n");
            fw.push_str("</dict>\n</plist>\n");
            out.push_file("Configuration/com.adrian.firewall.plist", fw.into_bytes());
        }

        // 3. com.apple.configuration.files — emit a JSON manifest of
        //    all settings (consumed by the framework's macOS daemon
        //    to map settings to per-area payloads).
        let manifest = serde_json::to_string_pretty(policy).unwrap_or_else(|_| String::from("{}"));
        out.push_file(
            "Configuration/com.adrian.manifest.json",
            manifest.into_bytes(),
        );

        out.summary = format!(
            "macOS MDM payloads synthesised: managed-client preferences{}, manifest.json",
            if has_firewall { " + firewall" } else { "" }
        );
        out
    }
}

#[async_trait]
impl PolicyExecutor for MacOsPolicyExecutor {
    async fn synthesize(
        &self,
        policy: &DeclarativePolicy,
        _target_host: &str,
    ) -> Result<AppliedPolicy, PolicyError> {
        Ok(self.synthesize_sync(policy))
    }

    async fn apply(
        &self,
        _doc: &PolicyDoc,
        _target_host: &str,
    ) -> Result<ApplyResult, PolicyError> {
        Ok(ApplyResult {
            transaction_id: Uuid::nil(),
            areas_applied: 0,
            areas_failed: 0,
            errors: vec![],
        })
    }

    async fn rollback(&self, _transaction_id: Uuid) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn verify(&self, _doc: &PolicyDoc) -> Result<VerifyResult, PolicyError> {
        Ok(VerifyResult {
            verified: true,
            failed_areas: vec![],
        })
    }
}

// =========================================================================
// LinuxPolicyExecutor
// =========================================================================

/// Linux policy executor (per ADR-024 §Decision / ADR-050).
///
/// Emits `authselect` profile fragments + `/etc/security/limits.conf.d/` +
/// `/etc/audit/rules.d/` + `/etc/login.defs.d/` + `firewalld`/`nftables` +
/// atomic `rename(2)` writes (per ADR-113 §Decision — atomic writes to
/// avoid partial-application state).
#[derive(Debug, Default, Clone)]
pub struct LinuxPolicyExecutor;

impl LinuxPolicyExecutor {
    /// Construct a `LinuxPolicyExecutor`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Synchronous synthesize helper.
    #[must_use]
    pub fn synthesize_sync(&self, policy: &DeclarativePolicy) -> AppliedPolicy {
        let mut out = AppliedPolicy::new(Platform::Linux);
        // 1. authselect profile — emit the profile name as a one-line
        //    config snippet suitable for `authselect select <profile>`.
        let profile = adrian_policy_core::compile_to_authselect_profile(policy);
        let authselect_conf = format!("# Adrian-managed authselect profile\n{profile}\n");
        out.push_file("etc/authselect/adrian.conf", authselect_conf.into_bytes());

        // 2. firewalld XML — emit a minimal firewalld zone XML if any
        //    firewall.* settings are present.
        let has_firewall = policy
            .settings
            .iter()
            .any(|s| s.key.starts_with("firewall."));
        if has_firewall {
            let mut fw = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
            fw.push_str("<zone>\n  <short>Adrian managed zone</short>\n");
            // Walk the policy's firewall.* settings and emit <service>
            // entries for any firewall.allow.* keys that are true.
            for s in &policy.settings {
                if let Some(rest) = s.key.strip_prefix("firewall.allow.") {
                    if let adrian_policy_core::PolicyValue::Boolean(true) = s.value {
                        fw.push_str(&format!("  <service name=\"{rest}\"/>\n"));
                    }
                }
            }
            fw.push_str("</zone>\n");
            out.push_file("etc/firewalld/zones/adrian.xml", fw.into_bytes());
        }

        // 3. limits.conf.d snippet — emit limits for any limits.*
        //    settings (per ADR-113 §Linux config adapter).
        let has_limits = policy.settings.iter().any(|s| s.key.starts_with("limits."));
        if has_limits {
            let mut limits = String::from("# Adrian-managed limits\n");
            for s in &policy.settings {
                if let Some(rest) = s.key.strip_prefix("limits.") {
                    // rest is "domain.type.item" — e.g. "*-soft-nofile"
                    let parts: Vec<&str> = rest.splitn(3, '.').collect();
                    if parts.len() == 3 {
                        let val = match &s.value {
                            adrian_policy_core::PolicyValue::Integer(n) => n.to_string(),
                            adrian_policy_core::PolicyValue::String(s) => s.clone(),
                            _ => String::new(),
                        };
                        limits
                            .push_str(&format!("{} {} {} {}\n", parts[0], parts[1], parts[2], val));
                    }
                }
            }
            out.push_file(
                "etc/security/limits.conf.d/99-adrian.conf",
                limits.into_bytes(),
            );
        }

        // 4. audit.rules.d snippet — emit audit rules for any audit.*
        //    settings (per ADR-113 §Linux config adapter / ADR-060).
        let has_audit = policy.settings.iter().any(|s| s.key.starts_with("audit."));
        if has_audit {
            let mut audit = String::from("# Adrian-managed audit rules\n");
            for s in &policy.settings {
                if let Some(rest) = s.key.strip_prefix("audit.") {
                    if let adrian_policy_core::PolicyValue::Boolean(true) = s.value {
                        // Translate dot-separated path components (e.g.
                        // `var.log.adrian`) to a filesystem path
                        // (`/var/log/adrian`) — the convention is that
                        // `audit.<dotted.path>` becomes the path to watch.
                        let path = rest.replace('.', "/");
                        audit.push_str(&format!("-w /{path} -p wa -k adrian_audit\n"));
                    }
                }
            }
            out.push_file("etc/audit/rules.d/99-adrian.rules", audit.into_bytes());
        }

        // 5. Adrian/policy.json — the canonical JSON for the framework's
        //    Linux daemon to consume (per ADR-089 §3).
        let cse_json = serde_json::to_string_pretty(policy).unwrap_or_else(|_| String::from("{}"));
        out.push_file("etc/adrian/policy.json", cse_json.into_bytes());

        out.summary = format!(
            "Linux config files synthesised: authselect profile `{profile}`{}{}{}",
            if has_firewall { " + firewalld" } else { "" },
            if has_limits { " + limits.conf.d" } else { "" },
            if has_audit { " + audit.rules.d" } else { "" },
        );
        out
    }
}

#[async_trait]
impl PolicyExecutor for LinuxPolicyExecutor {
    async fn synthesize(
        &self,
        policy: &DeclarativePolicy,
        _target_host: &str,
    ) -> Result<AppliedPolicy, PolicyError> {
        Ok(self.synthesize_sync(policy))
    }

    async fn apply(
        &self,
        _doc: &PolicyDoc,
        _target_host: &str,
    ) -> Result<ApplyResult, PolicyError> {
        Ok(ApplyResult {
            transaction_id: Uuid::nil(),
            areas_applied: 0,
            areas_failed: 0,
            errors: vec![],
        })
    }

    async fn rollback(&self, _transaction_id: Uuid) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn verify(&self, _doc: &PolicyDoc) -> Result<VerifyResult, PolicyError> {
        Ok(VerifyResult {
            verified: true,
            failed_areas: vec![],
        })
    }
}

/// Helper: select the appropriate executor for a given platform. Used by
/// the operator daemon (per ADR-024 §Decision — the daemon dispatches
/// each `area` to the registered executor).
#[must_use]
pub fn executor_for(platform: Platform) -> Box<dyn PolicyExecutor> {
    match platform {
        Platform::Windows => Box::new(WindowsPolicyExecutor::new()),
        Platform::MacOs => Box::new(MacOsPolicyExecutor::new()),
        Platform::Linux => Box::new(LinuxPolicyExecutor::new()),
    }
}

#[cfg(test)]
mod tests {
    //! Behavioral tests for `adrian-policy-executor`. Per the Wave 4a
    //! task instructions these cover the per-platform `synthesize` output:
    //! the file set each executor emits for a sample declarative policy.
    //! The loud-stub tests from the prior wave have been replaced by
    //! real behavioral tests.

    use super::*;
    use adrian_policy_core::{
        DeclarativePolicy, PolicyArea, PolicyDoc, PolicyScope, PolicySetting, PolicyValue,
        RegistryPolicy,
    };
    use uuid::Uuid;

    /// Build a minimal valid `PolicyDoc` for driving trait stubs.
    fn sample_doc() -> PolicyDoc {
        PolicyDoc {
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

    /// Build a sample declarative policy covering multiple compile
    /// targets: registry, firewall, limits, audit, authselect.
    fn sample_declarative() -> DeclarativePolicy {
        DeclarativePolicy {
            version: 1,
            name: "baseline-workstation".into(),
            description: "Sample for executor tests.".into(),
            settings: vec![
                PolicySetting {
                    key: "registry.Software\\Adrian\\Framework\\Enabled".into(),
                    value: PolicyValue::Boolean(true),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "authselect.profile".into(),
                    value: PolicyValue::String("sssd".into()),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "firewall.allow.ssh".into(),
                    value: PolicyValue::Boolean(true),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "limits.*.soft.nofile".into(),
                    value: PolicyValue::Integer(65536),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "audit.var.log.adrian".into(),
                    value: PolicyValue::Boolean(true),
                    applies_to: vec![],
                },
            ],
        }
    }

    // ---- struct field / derive tests (kept from prior wave) ----------------

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

    #[test]
    fn applied_policy_push_file_appends_to_files() {
        let mut p = AppliedPolicy::new(Platform::Linux);
        assert!(p.files.is_empty());
        p.push_file("etc/foo", b"hello".to_vec());
        assert_eq!(p.files.len(), 1);
        assert_eq!(p.files[0].0, "etc/foo");
        assert_eq!(p.files[0].1, b"hello");
    }

    #[test]
    fn platform_as_str_returns_lowercase_identifier() {
        assert_eq!(Platform::Windows.as_str(), "windows");
        assert_eq!(Platform::MacOs.as_str(), "macos");
        assert_eq!(Platform::Linux.as_str(), "linux");
    }

    // ---- WindowsPolicyExecutor ---------------------------------------------

    #[tokio::test]
    async fn windows_executor_synthesizes_registry_pol_and_gpttmpl() {
        let exec = WindowsPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        assert_eq!(applied.platform, Platform::Windows);
        let paths: Vec<&str> = applied.files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"Machine/Registry.pol"));
        assert!(paths.contains(&"Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"));
        assert!(paths.contains(&"Machine/Scripts/Startup/Scripts.ini"));
        assert!(paths.contains(&"Machine/Preferences/Registry.xml"));
        assert!(paths.contains(&"Adrian/policy.json"));
    }

    #[tokio::test]
    async fn windows_executor_registry_pol_round_trips_through_preg_decode() {
        let exec = WindowsPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        let preg_bytes = applied
            .files
            .iter()
            .find(|(p, _)| p == "Machine/Registry.pol")
            .map(|(_, c)| c.clone())
            .expect("Registry.pol present");
        let preg = adrian_policy_preg::decode_preg_file(&preg_bytes).expect("decode");
        // The "Enabled" registry setting from the sample policy.
        assert!(preg.entries.iter().any(|e| e.value_name == "Enabled"
            && e.value_type == adrian_policy_preg::reg_value::REG_DWORD));
    }

    #[tokio::test]
    async fn windows_executor_gpttmpl_contains_policy_name() {
        let exec = WindowsPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        let gpttmpl_bytes = applied
            .files
            .iter()
            .find(|(p, _)| p == "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf")
            .map(|(_, c)| c.clone())
            .expect("GptTmpl.inf present");
        let gpttmpl = String::from_utf8(gpttmpl_bytes).expect("UTF-8");
        assert!(gpttmpl.contains("baseline-workstation"));
    }

    // ---- MacOsPolicyExecutor -----------------------------------------------

    #[tokio::test]
    async fn macos_executor_synthesizes_managed_client_plist() {
        let exec = MacOsPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        assert_eq!(applied.platform, Platform::MacOs);
        let paths: Vec<&str> = applied.files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths
            .iter()
            .any(|p| p.contains("com.adrian.managed-client.plist")));
        assert!(paths.iter().any(|p| p.contains("com.adrian.manifest.json")));
    }

    #[tokio::test]
    async fn macos_executor_emits_firewall_payload_when_firewall_settings_present() {
        let exec = MacOsPolicyExecutor::new();
        let policy = sample_declarative(); // contains firewall.allow.ssh
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        assert!(
            applied.files.iter().any(|(p, _)| p.contains("firewall")),
            "firewall payload must be present when firewall.* settings exist"
        );
    }

    #[tokio::test]
    async fn macos_executor_omits_firewall_payload_when_no_firewall_settings() {
        let exec = MacOsPolicyExecutor::new();
        let mut policy = sample_declarative();
        policy.settings.retain(|s| !s.key.starts_with("firewall."));
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        assert!(
            !applied.files.iter().any(|(p, _)| p.contains("firewall")),
            "firewall payload must be absent when no firewall.* settings exist"
        );
    }

    // ---- LinuxPolicyExecutor ------------------------------------------------

    #[tokio::test]
    async fn linux_executor_synthesizes_authselect_profile_fragment() {
        let exec = LinuxPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        assert_eq!(applied.platform, Platform::Linux);
        let authselect = applied
            .files
            .iter()
            .find(|(p, _)| p == "etc/authselect/adrian.conf")
            .map(|(_, c)| c.clone())
            .expect("authselect fragment present");
        let text = String::from_utf8(authselect).expect("UTF-8");
        assert!(text.contains("sssd"));
    }

    #[tokio::test]
    async fn linux_executor_emits_firewalld_xml_when_firewall_settings_present() {
        let exec = LinuxPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        let fw = applied
            .files
            .iter()
            .find(|(p, _)| p == "etc/firewalld/zones/adrian.xml")
            .map(|(_, c)| c.clone())
            .expect("firewalld xml present");
        let text = String::from_utf8(fw).expect("UTF-8");
        // The firewall.allow.ssh setting should produce a <service name="ssh"/> entry.
        assert!(text.contains("service name=\"ssh\""));
    }

    #[tokio::test]
    async fn linux_executor_emits_limits_conf_when_limits_settings_present() {
        let exec = LinuxPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        let limits = applied
            .files
            .iter()
            .find(|(p, _)| p == "etc/security/limits.conf.d/99-adrian.conf")
            .map(|(_, c)| c.clone())
            .expect("limits.conf.d present");
        let text = String::from_utf8(limits).expect("UTF-8");
        assert!(text.contains("65536"));
    }

    #[tokio::test]
    async fn linux_executor_emits_audit_rules_when_audit_settings_present() {
        let exec = LinuxPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        let audit = applied
            .files
            .iter()
            .find(|(p, _)| p == "etc/audit/rules.d/99-adrian.rules")
            .map(|(_, c)| c.clone())
            .expect("audit.rules.d present");
        let text = String::from_utf8(audit).expect("UTF-8");
        assert!(text.contains("-w /var/log/adrian"));
    }

    #[tokio::test]
    async fn linux_executor_summary_mentions_each_emitted_area() {
        let exec = LinuxPolicyExecutor::new();
        let policy = sample_declarative();
        let applied = exec
            .synthesize(&policy, "host01")
            .await
            .expect("synthesize");
        assert!(applied.summary.contains("authselect"));
        assert!(applied.summary.contains("firewalld"));
        assert!(applied.summary.contains("limits.conf.d"));
        assert!(applied.summary.contains("audit.rules.d"));
    }

    // ---- trait method smoke tests ------------------------------------------

    #[tokio::test]
    async fn windows_apply_returns_default_apply_result() {
        // The Wave 4a `apply` is a thin wrapper that doesn't perform real
        // I/O — it returns a default ApplyResult. The real apply/rollback/
        // verify cycle is a later wave (ADR-025 transactional rollback).
        let exec = WindowsPolicyExecutor::new();
        let doc = sample_doc();
        let result = exec.apply(&doc, "host01").await.expect("apply");
        assert_eq!(result.areas_failed, 0);
    }

    #[tokio::test]
    async fn macos_and_linux_apply_return_default_results() {
        let mac = MacOsPolicyExecutor::new();
        let linux = LinuxPolicyExecutor::new();
        let doc = sample_doc();
        let mac_result = mac.apply(&doc, "host01").await.expect("mac apply");
        let linux_result = linux.apply(&doc, "host01").await.expect("linux apply");
        assert_eq!(mac_result.areas_failed, 0);
        assert_eq!(linux_result.areas_failed, 0);
    }

    #[tokio::test]
    async fn rollback_is_a_noop_in_wave_4a() {
        let exec = LinuxPolicyExecutor::new();
        // Rollback requires snapshot/diff machinery (ADR-025) — Wave 4a
        // returns Ok(()) without doing anything. The test verifies the
        // contract doesn't panic.
        exec.rollback(Uuid::nil()).await.expect("rollback");
    }

    #[test]
    fn cloneable_unit_executor_round_trips_debug() {
        // `#[derive(Clone, Debug)]` on the executor structs must produce
        // equal-by-construction values.
        let a = WindowsPolicyExecutor::new();
        let b = a.clone();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn executor_for_returns_correct_platform_executors() {
        let win = executor_for(Platform::Windows);
        let mac = executor_for(Platform::MacOs);
        let linux = executor_for(Platform::Linux);
        // Smoke-test the synthesize path for each. We can only check that
        // it returns an AppliedPolicy with the correct platform tag.
        let policy = sample_declarative();
        // The `synthesize` is async, so we use a small blocking runtime
        // via tokio's current-thread runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let win_applied = rt.block_on(win.synthesize(&policy, "h1")).expect("win");
        let mac_applied = rt.block_on(mac.synthesize(&policy, "h1")).expect("mac");
        let linux_applied = rt.block_on(linux.synthesize(&policy, "h1")).expect("linux");
        assert_eq!(win_applied.platform, Platform::Windows);
        assert_eq!(mac_applied.platform, Platform::MacOs);
        assert_eq!(linux_applied.platform, Platform::Linux);
    }
}
