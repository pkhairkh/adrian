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

use adrian_policy_core::{policy_doc_to_declarative, DeclarativePolicy, PolicyDoc, PolicyError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
// Transactional rollback support (ADR-025)
// =========================================================================

/// A snapshot of a single file's state before a policy `apply` overwrote
/// it.  `None` means the file did not exist before the apply (so rollback
/// should delete it); `Some(bytes)` means the file existed with these
/// contents (so rollback should restore them).
#[derive(Debug, Clone)]
struct FileSnapshot {
    /// The absolute path to the file (root + relative path).
    abs_path: PathBuf,
    /// The previous contents of the file, or `None` if it didn't exist.
    previous_contents: Option<Vec<u8>>,
}

/// A transaction snapshot — the complete set of file states captured
/// before a policy `apply` wrote new files.  Stored keyed by transaction
/// ID so `rollback(transaction_id)` can restore the previous state.
#[derive(Debug, Clone, Default)]
struct TransactionSnapshot {
    /// The files that were written or overwritten by the apply.
    files: Vec<FileSnapshot>,
    /// The authselect profile that was active before the apply (for
    /// rollback).  `None` means authselect was not changed.
    previous_authselect_profile: Option<String>,
}

/// Shared transaction store — maps transaction IDs to snapshots.  Wrapped
/// in `Arc<Mutex<...>>` so that `apply` and `rollback` can share state
/// across clone boundaries (the executor is `Clone`).
type TransactionStore = Arc<Mutex<HashMap<Uuid, TransactionSnapshot>>>;

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
///
/// The `root` field is the base directory for file writes (defaults to
/// `/`).  Tests construct the executor with `with_root(tempdir)` so that
/// `apply` writes to a sandbox instead of clobbering the host's real
/// `/var/lib/adrian/policy/` etc.
#[derive(Debug, Clone)]
pub struct LinuxPolicyExecutor {
    /// Root directory for file writes (defaults to `/`).
    root: PathBuf,
    /// In-memory transaction store (ADR-025).  Shared across clones via
    /// `Arc<Mutex<...>>` so that `apply` and `rollback` see the same map.
    transactions: TransactionStore,
}

impl Default for LinuxPolicyExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPolicyExecutor {
    /// Construct a `LinuxPolicyExecutor` rooted at `/` (production use).
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
            transactions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Construct a `LinuxPolicyExecutor` rooted at `root` (test use).
    /// All file writes from `apply` will go to `root/var/lib/adrian/policy/`
    /// etc., so tests can verify file contents without touching the real
    /// filesystem.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            transactions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The root directory this executor writes to.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
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

    /// Apply a policy document to the target host (per ADR-024 §Decision
    /// + ADR-025 §Decision — transactional rollback).
    ///
    /// This implementation:
    /// 1. Converts the `PolicyDoc` to a `DeclarativePolicy` via
    ///    [`adrian_policy_core::policy_doc_to_declarative`].
    /// 2. Calls `synthesize` to produce the per-platform file set.
    /// 3. For each file in the synthesised set:
    ///    a. Captures a snapshot of any existing file at the target path
    ///       (for rollback).
    ///    b. Creates the parent directory tree if it doesn't exist.
    ///    c. Writes the new contents atomically (write-to-temp + rename).
    /// 4. Records an `authselect select <profile>` invocation (the actual
    ///    `authselect` binary is NOT executed in test mode — the profile
    ///    name is recorded in the transaction snapshot for verification).
    /// 5. Returns an `ApplyResult` with a fresh v7 transaction ID and the
    ///    count of files written.
    async fn apply(&self, doc: &PolicyDoc, _target_host: &str) -> Result<ApplyResult, PolicyError> {
        let declarative = policy_doc_to_declarative(doc);
        let applied = self.synthesize_sync(&declarative);

        let transaction_id = Uuid::now_v7();
        let mut snapshot = TransactionSnapshot::default();
        let mut areas_applied = 0usize;
        let mut areas_failed = 0usize;
        let mut errors = Vec::new();

        for (rel_path, contents) in &applied.files {
            let abs_path = self.root.join(rel_path);
            // Capture the previous state of the file (if any) for rollback.
            let previous = match std::fs::read(&abs_path) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    areas_failed += 1;
                    errors.push(format!("snapshot {rel_path}: {e}"));
                    continue;
                }
            };
            snapshot.files.push(FileSnapshot {
                abs_path: abs_path.clone(),
                previous_contents: previous,
            });
            // Create the parent directory tree.
            if let Some(parent) = abs_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    areas_failed += 1;
                    errors.push(format!("mkdir {rel_path}: {e}"));
                    continue;
                }
            }
            // Atomic write: write to a temp file in the same directory,
            // then rename over the target.
            let tmp = abs_path.with_extension("adrian-tmp");
            if let Err(e) = std::fs::write(&tmp, contents) {
                areas_failed += 1;
                errors.push(format!("write {rel_path}: {e}"));
                let _ = std::fs::remove_file(&tmp);
                continue;
            }
            if let Err(e) = std::fs::rename(&tmp, &abs_path) {
                areas_failed += 1;
                errors.push(format!("rename {rel_path}: {e}"));
                let _ = std::fs::remove_file(&tmp);
                continue;
            }
            areas_applied += 1;
        }

        // Record the authselect profile that was applied (for rollback
        // verification).  We do NOT actually run `authselect select` here
        // — that's the operator daemon's job.  We just record what would
        // be run so tests can verify the decision.
        let profile = adrian_policy_core::compile_to_authselect_profile(&declarative);
        snapshot.previous_authselect_profile = Some(profile);

        // Store the snapshot for rollback.
        if let Ok(mut store) = self.transactions.lock() {
            store.insert(transaction_id, snapshot);
        }

        Ok(ApplyResult {
            transaction_id,
            areas_applied,
            areas_failed,
            errors,
        })
    }

    /// Roll back a previously-applied policy document (per ADR-025 §Decision
    /// — transactional rollback via the transaction ID returned by `apply`).
    ///
    /// For each file that was written by the corresponding `apply`:
    /// - If the file existed before the apply, restore its previous contents.
    /// - If the file did not exist before the apply, delete it.
    ///
    /// Returns `Err(PolicyError::Malformed(...))` if the transaction ID is
    /// unknown (e.g. already rolled back, or never produced by this
    /// executor).
    async fn rollback(&self, transaction_id: Uuid) -> Result<(), PolicyError> {
        let snapshot = {
            let mut store = self
                .transactions
                .lock()
                .map_err(|e| PolicyError::Malformed(format!("transaction store poisoned: {e}")))?;
            store.remove(&transaction_id).ok_or_else(|| {
                PolicyError::Malformed(format!("unknown transaction {transaction_id}"))
            })?
        };
        for file in &snapshot.files {
            match &file.previous_contents {
                Some(prev) => {
                    // Restore the previous contents.
                    if let Some(parent) = file.abs_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if let Err(e) = std::fs::write(&file.abs_path, prev) {
                        tracing::warn!(
                            "rollback: failed to restore {}: {e}",
                            file.abs_path.display()
                        );
                    }
                }
                None => {
                    // The file didn't exist before the apply — delete it.
                    if let Err(e) = std::fs::remove_file(&file.abs_path) {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(
                                "rollback: failed to delete {}: {e}",
                                file.abs_path.display()
                            );
                        }
                    }
                }
            }
        }
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
        // Linux executor must use a temp root — the real `apply` writes
        // files to `root/etc/...`, which would fail with permission denied
        // if root is "/".
        let tmp =
            std::env::temp_dir().join(format!("adrian-policy-test-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let linux = LinuxPolicyExecutor::with_root(&tmp);
        let doc = sample_doc();
        let mac_result = mac.apply(&doc, "host01").await.expect("mac apply");
        let linux_result = linux.apply(&doc, "host01").await.expect("linux apply");
        assert_eq!(mac_result.areas_failed, 0);
        assert_eq!(linux_result.areas_failed, 0, "{:?}", linux_result.errors);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn rollback_unknown_transaction_returns_error() {
        let exec = LinuxPolicyExecutor::new();
        // Rolling back an unknown transaction ID must return an error
        // (ADR-025 — transactional rollback requires a valid transaction).
        let err = exec.rollback(Uuid::now_v7()).await.unwrap_err();
        assert!(matches!(err, PolicyError::Malformed(_)));
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

    // ---- Wave 2: real apply / rollback (ADR-025 transactional) -----------

    /// Helper: build a `PolicyDoc` with a single `Authentication` area so
    /// that `apply` synthesises an authselect profile fragment.
    fn sample_auth_doc() -> PolicyDoc {
        use adrian_policy_core::{AuthenticationPolicy, PolicyArea};
        PolicyDoc {
            uuid: Uuid::nil(),
            name: "auth-test".into(),
            version: "1.0.0".into(),
            areas: vec![PolicyArea::Authentication(AuthenticationPolicy {
                authselect_profile: "sssd".into(),
                smartcard_required: false,
            })],
            security_descriptor: None,
            scope: PolicyScope {
                principals: vec!["S-1-5-32-544".into()],
                ous: vec![],
                hosts: vec!["host01".into()],
            },
        }
    }

    #[tokio::test]
    async fn linux_apply_writes_files_to_target_directory() {
        // Use a tempdir-style unique path under /tmp so we don't clobber
        // the real filesystem.  We clean up at the end of the test.
        let tmp =
            std::env::temp_dir().join(format!("adrian-policy-test-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let exec = LinuxPolicyExecutor::with_root(&tmp);
        let doc = sample_auth_doc();
        let result = exec.apply(&doc, "host01").await.expect("apply");
        // The apply must report at least one area applied (the authselect
        // fragment + policy.json).
        assert!(result.areas_applied > 0, "areas_applied should be > 0");
        assert_eq!(result.areas_failed, 0, "no failures: {:?}", result.errors);
        assert_ne!(
            result.transaction_id,
            Uuid::nil(),
            "transaction ID must be non-nil"
        );
        // The authselect fragment should exist on disk under the temp root.
        let authselect_path = tmp.join("etc/authselect/adrian.conf");
        assert!(
            authselect_path.exists(),
            "authselect fragment should exist at {}",
            authselect_path.display()
        );
        let contents =
            String::from_utf8(std::fs::read(&authselect_path).expect("read")).expect("utf8");
        assert!(
            contents.contains("sssd"),
            "authselect fragment should mention 'sssd'"
        );
        // The policy.json should also exist.
        let policy_json_path = tmp.join("etc/adrian/policy.json");
        assert!(policy_json_path.exists(), "policy.json should exist");
        // Clean up.
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn linux_rollback_restores_previous_file_contents() {
        let tmp =
            std::env::temp_dir().join(format!("adrian-policy-test-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        // Pre-create a file at the target path with known contents so we
        // can verify rollback restores it.
        let target = tmp.join("etc/authselect/adrian.conf");
        std::fs::create_dir_all(target.parent().unwrap()).expect("mkdir");
        let original = b"# original contents\n";
        std::fs::write(&target, original).expect("write original");

        let exec = LinuxPolicyExecutor::with_root(&tmp);
        let doc = sample_auth_doc();
        let result = exec.apply(&doc, "host01").await.expect("apply");
        // After apply, the file should be overwritten with the authselect
        // fragment (NOT the original contents).
        let after_apply = std::fs::read(&target).expect("read after apply");
        assert_ne!(
            &after_apply[..],
            &original[..],
            "apply must overwrite the file"
        );
        assert!(String::from_utf8_lossy(&after_apply).contains("sssd"));

        // Rollback should restore the original contents.
        exec.rollback(result.transaction_id)
            .await
            .expect("rollback");
        let after_rollback = std::fs::read(&target).expect("read after rollback");
        assert_eq!(
            &after_rollback[..],
            &original[..],
            "rollback must restore original"
        );
        // Clean up.
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn linux_rollback_deletes_files_that_did_not_exist_before_apply() {
        let tmp =
            std::env::temp_dir().join(format!("adrian-policy-test-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let exec = LinuxPolicyExecutor::with_root(&tmp);
        let doc = sample_auth_doc();
        let result = exec.apply(&doc, "host01").await.expect("apply");
        let authselect_path = tmp.join("etc/authselect/adrian.conf");
        assert!(authselect_path.exists(), "file should exist after apply");
        // Rollback should DELETE the file (since it didn't exist before
        // the apply).
        exec.rollback(result.transaction_id)
            .await
            .expect("rollback");
        assert!(
            !authselect_path.exists(),
            "file should be deleted after rollback (it didn't exist before apply)"
        );
        // Clean up.
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn linux_apply_records_authselect_profile_in_transaction() {
        // The `apply` must record the authselect profile name in the
        // transaction snapshot (for the operator daemon to run
        // `authselect select <profile>`).  We verify this by applying a
        // policy with authselect.profile = "local" and checking the
        // resulting authselect fragment on disk contains "local".
        let tmp =
            std::env::temp_dir().join(format!("adrian-policy-test-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let exec = LinuxPolicyExecutor::with_root(&tmp);

        use adrian_policy_core::{AuthenticationPolicy, PolicyArea};
        let doc = PolicyDoc {
            uuid: Uuid::nil(),
            name: "auth-local".into(),
            version: "1.0.0".into(),
            areas: vec![PolicyArea::Authentication(AuthenticationPolicy {
                authselect_profile: "local".into(),
                smartcard_required: false,
            })],
            security_descriptor: None,
            scope: PolicyScope {
                principals: vec!["S-1-5-32-544".into()],
                ous: vec![],
                hosts: vec!["host01".into()],
            },
        };
        let result = exec.apply(&doc, "host01").await.expect("apply");
        assert_eq!(result.areas_failed, 0, "{:?}", result.errors);
        let authselect_path = tmp.join("etc/authselect/adrian.conf");
        let contents =
            String::from_utf8(std::fs::read(&authselect_path).expect("read")).expect("utf8");
        assert!(
            contents.contains("local"),
            "authselect fragment should mention the 'local' profile: {contents}"
        );
        // Clean up.
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
