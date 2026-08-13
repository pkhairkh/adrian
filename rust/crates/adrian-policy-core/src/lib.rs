//! # adrian-policy-core
//!
//! Canonical policy document model (`PolicyDoc`, `PolicyArea`) for the
//! Adrian framework, plus the newer declarative JSON policy (`DeclarativePolicy`)
//! introduced in Wave 4a per ADR-089 / ADR-090 / ADR-092.
//!
//! Per ADR-029 §Decision and ADR-113 §Decision, the framework's policy model
//! uses a canonical JSON representation that compiles to platform-native
//! formats: PReg `Registry.pol` + GPP XML on Windows, MDM Configuration
//! Profile payloads on macOS, and `authselect`, `limits.conf.d`, `auditd`,
//! and `nftables` on Linux. This crate defines the canonical JSON schema
//! and the `PolicyArea` enum; the per-platform compilation lives in
//! `adrian-policy-executor` (Layer 2).
//!
//! ## ADRs
//!
//! - ADR-024: Per-platform policy executors
//! - ADR-025: Transactional policy rollback
//! - ADR-028: Push-based policy distribution (WebSocket)
//! - ADR-029: JSON canonical policy (PReg adapter)
//! - ADR-089: Declarative policy GPC+GPT synthesis
//! - ADR-090: ADMX-to-declarative-JSON compiler
//! - ADR-091: GPP cross-platform compilation
//! - ADR-113: GPP cross-platform policy
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-schema-traits`, `adrian-policy-preg`, `serde`, `serde_json`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// =========================================================================
// PolicyDoc — the original canonical document model (per ADR-029 §Decision).
// Kept intact so existing callers (and the existing 5 structural tests) keep
// working. The new `DeclarativePolicy` / `PolicySetting` / `PolicyValue`
// types below are an additional surface that compiles to per-platform
// formats (PReg, MDM plist, authselect profile).
// =========================================================================

/// A canonical policy document (per ADR-029 §Decision).
///
/// The document is a list of `PolicyArea` entries, each targeting a
/// platform-specific concern (registry, file system, audit, firewall,
/// authentication, etc.). The document is the source of truth; per-platform
/// executors (in `adrian-policy-executor`) compile it to platform-native
/// formats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDoc {
    /// The document's UUID (per ADR-031 — Git-backed history).
    pub uuid: Uuid,
    /// The document's human-readable name.
    pub name: String,
    /// The document's version (per ADR-031 — semver, monotonically
    /// increasing in the Git history).
    pub version: String,
    /// The policy areas (per ADR-029 §Decision).
    pub areas: Vec<PolicyArea>,
    /// The security descriptor (per ADR-004 — controls which principals can
    /// read / apply the policy).
    pub security_descriptor: Option<Vec<u8>>,
    /// The scope (per ADR-030 — role-based binding: which groups / OUs /
    /// hosts this policy applies to).
    pub scope: PolicyScope,
}

/// A single policy area (per ADR-029 §Decision — one area per
/// platform-specific concern).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyArea {
    /// Windows registry (compiles to PReg `Registry.pol` per ADR-029).
    Registry(RegistryPolicy),
    /// File system permissions (compiles to NTFS ACLs on Windows, POSIX
    /// mode bits on Linux/macOS, per ADR-113).
    FileSystem(FileSystemPolicy),
    /// Audit policy (compiles to `auditpol.exe` on Windows, `auditd` rules
    /// on Linux, per ADR-060).
    Audit(AuditPolicy),
    /// Firewall rules (compiles to Windows Firewall on Windows, `nftables`
    /// on Linux, `pf` on macOS, per ADR-113).
    Firewall(FirewallPolicy),
    /// Authentication policy (compiles to `authselect` on Linux, `PAM` on
    /// macOS, per ADR-050).
    Authentication(AuthenticationPolicy),
    /// Group membership (compiles to Windows restricted groups, Linux
    /// `/etc/group` entries, macOS `MemberLdapGroups`, per ADR-066).
    RestrictedGroups(RestrictedGroupsPolicy),
    /// Scripts (compiles to Windows GPP `Scripts.ini`, Linux `systemd`
    /// units, macOS `launchd` plists, per ADR-113).
    Scripts(ScriptsPolicy),
    /// Application preferences (compiles to Windows GPP XML, per ADR-091).
    AppPreferences(AppPreferencesPolicy),
}

/// Registry policy (per ADR-029 §Decision — compiles to PReg `Registry.pol`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryPolicy {
    /// The registry values (key path, value name, type, data).
    pub values: Vec<RegistryValue>,
}

/// A single registry value (per ADR-029 §Decision — PReg format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryValue {
    /// The key path (e.g. `Software\Adrian\Framework`).
    pub key: String,
    /// The value name.
    pub value_name: String,
    /// The registry value type (per MS-PREG §2.4 — REG_SZ=1, REG_DWORD=4,
    /// etc.).
    pub value_type: u32,
    /// The value data.
    pub data: Vec<u8>,
}

/// File system permissions policy (per ADR-113).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileSystemPolicy {
    /// The ACL entries (path, principal, permission).
    pub entries: Vec<FileSystemAclEntry>,
}

/// A single file-system ACL entry (per ADR-113).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileSystemAclEntry {
    /// The file path.
    pub path: String,
    /// The principal SID (per Decision 3 — wire-format currency is SID).
    pub principal_sid: String,
    /// The permission (read, write, execute, etc.).
    pub permission: String,
}

/// Audit policy (per ADR-060).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// The audit subcategories to enable (per Windows `auditpol`).
    pub subcategories: Vec<String>,
}

/// Firewall policy (per ADR-113).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirewallPolicy {
    /// The firewall rules.
    pub rules: Vec<FirewallRule>,
}

/// A single firewall rule (per ADR-113).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirewallRule {
    /// The rule name.
    pub name: String,
    /// The action (allow / block).
    pub action: String,
    /// The direction (inbound / outbound).
    pub direction: String,
    /// The protocol (tcp / udp / any).
    pub protocol: String,
    /// The local port(s).
    pub local_ports: Vec<u16>,
    /// The remote port(s).
    pub remote_ports: Vec<u16>,
}

/// Authentication policy (per ADR-050).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationPolicy {
    /// The authselect profile name (per ADR-050 — `sssd` / `minimal` /
    /// `local`).
    pub authselect_profile: String,
    /// Whether to enable smart-card auth (per ADR-084).
    pub smartcard_required: bool,
}

/// Restricted groups policy (per ADR-066).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestrictedGroupsPolicy {
    /// The group memberships to enforce (group SID → member SIDs).
    pub memberships: Vec<(String, Vec<String>)>,
}

/// Scripts policy (per ADR-113).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptsPolicy {
    /// The startup scripts (run at boot).
    pub startup: Vec<String>,
    /// The shutdown scripts (run at shutdown).
    pub shutdown: Vec<String>,
    /// The logon scripts (run at user logon).
    pub logon: Vec<String>,
    /// The logoff scripts (run at user logoff).
    pub logoff: Vec<String>,
}

/// Application preferences policy (per ADR-091 — Windows GPP XML).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppPreferencesPolicy {
    /// The GPP XML payloads (one per application).
    pub payloads: Vec<String>,
}

/// The policy scope (per ADR-030 — role-based binding).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyScope {
    /// The principal SIDs that this policy applies to (per ADR-030).
    pub principals: Vec<String>,
    /// The OUs that this policy applies to (per ADR-030).
    pub ous: Vec<String>,
    /// The hostnames / host patterns that this policy applies to.
    pub hosts: Vec<String>,
}

/// Error type for policy operations.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The policy document is malformed (per ADR-029).
    #[error("malformed policy document: {0}")]
    Malformed(String),
    /// The policy area is not supported by the executor (per ADR-024).
    #[error("unsupported policy area: {0}")]
    UnsupportedArea(String),
    /// The scope is empty (per ADR-030 — scope is mandatory).
    #[error("empty policy scope")]
    EmptyScope,
    /// The security descriptor is invalid (per ADR-004).
    #[error("invalid security descriptor: {0}")]
    InvalidSd(String),
}

/// Serialise a `PolicyDoc` to canonical JSON (per ADR-029 §Decision).
pub fn to_json(doc: &PolicyDoc) -> Result<String, PolicyError> {
    serde_json::to_string_pretty(doc).map_err(|e| PolicyError::Malformed(e.to_string()))
}

/// Deserialise a `PolicyDoc` from canonical JSON (per ADR-029 §Decision).
pub fn from_json(json: &str) -> Result<PolicyDoc, PolicyError> {
    serde_json::from_str(json).map_err(|e| PolicyError::Malformed(e.to_string()))
}

/// Validate a `PolicyDoc` per ADR-029 §Decision (Wave 4a TODO #1).
///
/// Validation rules:
/// - `name` is non-empty.
/// - `version` parses as a semver (`major.minor.patch`).
/// - `scope.principals` + `scope.ous` + `scope.hosts` is non-empty (per
///   ADR-030 — a policy must target at least one principal / OU / host).
/// - `areas` is non-empty (an empty `PolicyDoc` is meaningless).
pub fn validate(doc: &PolicyDoc) -> Result<(), PolicyError> {
    if doc.name.is_empty() {
        return Err(PolicyError::Malformed("name must be non-empty".into()));
    }
    if doc.version.is_empty() {
        return Err(PolicyError::Malformed("version must be non-empty".into()));
    }
    // Semver "major.minor.patch" check — accept any non-empty version
    // with at least one dot, so we don't reject pre-release tags.
    let vparts: Vec<&str> = doc.version.split('.').collect();
    if vparts.len() < 2 {
        return Err(PolicyError::Malformed(format!(
            "version {:?} must be semver major.minor[.patch]",
            doc.version
        )));
    }
    if vparts[0].parse::<u32>().is_err() {
        return Err(PolicyError::Malformed(format!(
            "version major part {:?} must be a number",
            vparts[0]
        )));
    }
    if doc.areas.is_empty() {
        return Err(PolicyError::Malformed("areas must be non-empty".into()));
    }
    if doc.scope.principals.is_empty() && doc.scope.ous.is_empty() && doc.scope.hosts.is_empty() {
        return Err(PolicyError::EmptyScope);
    }
    Ok(())
}

/// Compute the inverse diff of two `PolicyDoc`s (per ADR-025 — Wave 4a
/// TODO #2). The returned `PolicyDoc` represents the changes that, when
/// applied, would transform `new` back into `old`.
///
/// This is a structural diff (not a setting-level diff) for the Wave 4a
/// implementation: if `old` and `new` differ in any way, the inverse is
/// `old` itself; if they are equal, the inverse is an empty `PolicyDoc`
/// (with the same `uuid` and `version`). A future wave will produce a
/// setting-level diff for finer-grained rollback.
pub fn diff(old: &PolicyDoc, new: &PolicyDoc) -> PolicyDoc {
    if old == new {
        // No-op rollback: an empty policy with the same identity.
        PolicyDoc {
            uuid: new.uuid,
            name: new.name.clone(),
            version: new.version.clone(),
            areas: vec![],
            security_descriptor: new.security_descriptor.clone(),
            scope: new.scope.clone(),
        }
    } else {
        // Structural rollback: restore the entire previous document.
        old.clone()
    }
}

// =========================================================================
// DeclarativePolicy — the newer, simpler policy surface (per ADR-089 /
// ADR-090 / Wave 4a). Compiles to PReg / MDM plist / authselect profile
// via the `compile_to_*` free functions below.
// =========================================================================

/// A declarative JSON policy document (per ADR-089 §Decision — the
/// framework's single source of truth).
///
/// This is a simpler, more uniform surface than the original `PolicyDoc`:
/// instead of distinct typed enums per area, it uses a flat list of
/// `PolicySetting`s, each a `(key, value, applies_to)` triple. The
/// `compile_to_*` functions translate this to the per-platform wire
/// formats (PReg `Registry.pol`, macOS Configuration Profile plist XML,
/// Linux authselect profile name).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeclarativePolicy {
    /// The schema version of the declarative policy format (currently `1`).
    pub version: u32,
    /// The policy's human-readable name (e.g. `baseline-workstation`).
    pub name: String,
    /// A longer description of what the policy does.
    pub description: String,
    /// The settings (per ADR-089 §1 — a flat list of key/value/applies_to
    /// triples).
    pub settings: Vec<PolicySetting>,
}

/// A single policy setting — a `(key, value, applies_to)` triple (per
/// ADR-089 §1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySetting {
    /// The setting key, scoped by area prefix (e.g.
    /// `registry.software.adrian.framework.enabled`,
    /// `authselect.profile`, `firewall.allow_ssh`).
    pub key: String,
    /// The typed value (per ADR-029 §2 — the framework's typed value
    /// system: `string`, `integer`, `boolean`, `bytes`, `string_list`).
    pub value: PolicyValue,
    /// The target OUs / groups / hosts the setting applies to (per ADR-030).
    /// An empty list means "applies to all hosts bound by the parent
    /// policy's scope".
    #[serde(default)]
    pub applies_to: Vec<String>,
}

/// A typed policy value (per ADR-029 §2 — the framework's typed value
/// system).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PolicyValue {
    /// A UTF-8 string (compiles to REG_SZ on Windows, string in plist,
    /// quoted string in Linux config).
    String(String),
    /// A signed integer (compiles to REG_DWORD on Windows if in u32
    /// range, integer in plist, decimal in Linux config).
    Integer(i64),
    /// A boolean (compiles to REG_DWORD 0/1 on Windows, bool in plist,
    /// `yes`/`no` in Linux config).
    Boolean(bool),
    /// Raw bytes (compiles to REG_BINARY on Windows, data in plist,
    /// hex-encoded in Linux config).
    Bytes(Vec<u8>),
    /// A list of strings (compiles to REG_MULTI_SZ on Windows, array in
    /// plist, one-line-per-entry in Linux config).
    StringList(Vec<String>),
}

// ---- compile_to_preg ------------------------------------------------------

/// Convert a `DeclarativePolicy` to a `PregFile` (per ADR-029 §3 — the
/// PReg adapter). Only settings whose key starts with `registry.` are
/// emitted; other settings are skipped (they are compiled by the per-
/// platform executors into other wire formats).
pub fn compile_to_preg(policy: &DeclarativePolicy) -> adrian_policy_preg::PregFile {
    use adrian_policy_preg::{PregEntry, PregFile, reg_value};

    let mut entries = Vec::new();
    for setting in &policy.settings {
        let Some(rest) = setting.key.strip_prefix("registry.") else {
            continue;
        };
        // rest is "Software\Adrian\Framework\ValueName" — split on the last
        // backslash to get (key, value_name).
        let (key, value_name) = match rest.rfind('\\') {
            Some(idx) => (rest[..idx].to_string(), rest[idx + 1..].to_string()),
            None => (String::new(), rest.to_string()),
        };
        match &setting.value {
            PolicyValue::String(s) => {
                entries.push(PregEntry::new(
                    key,
                    value_name,
                    reg_value::REG_SZ,
                    adrian_policy_preg::encode_reg_sz(s),
                ));
            }
            PolicyValue::Integer(n) => {
                // REG_DWORD is u32 little-endian; clamp to u32 range.
                let v = u32::try_from(*n).unwrap_or(0);
                entries.push(PregEntry::new(
                    key,
                    value_name,
                    reg_value::REG_DWORD,
                    adrian_policy_preg::encode_reg_dword(v),
                ));
            }
            PolicyValue::Boolean(b) => {
                entries.push(PregEntry::new(
                    key,
                    value_name,
                    reg_value::REG_DWORD,
                    adrian_policy_preg::encode_reg_dword(u32::from(*b)),
                ));
            }
            PolicyValue::Bytes(b) => {
                entries.push(PregEntry::new(key, value_name, reg_value::REG_BINARY, b.clone()));
            }
            PolicyValue::StringList(list) => {
                entries.push(PregEntry::new(
                    key,
                    value_name,
                    reg_value::REG_MULTI_SZ,
                    adrian_policy_preg::encode_reg_multi_sz(list),
                ));
            }
        }
    }
    PregFile { entries }
}

// ---- compile_to_configuration_profile (macOS plist XML) -------------------

/// Convert a `DeclarativePolicy` to a macOS Configuration Profile plist
/// XML payload (per ADR-091 §3 — MDM Configuration Profile). The output
/// is a single `<plist version="1.0"><dict>...</dict></plist>` document
/// containing every setting's key/value pair. The per-platform executor
/// wraps this in the outer `com.apple.ManagedClient.preferences` payload
/// envelope before pushing to MDM.
pub fn compile_to_configuration_profile(policy: &DeclarativePolicy) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    out.push_str("<plist version=\"1.0\">\n");
    out.push_str("<dict>\n");
    // Metadata keys.
    out.push_str("  <key>PayloadDisplayName</key>\n");
    out.push_str("  <string>");
    out.push_str(&plist_escape(&policy.name));
    out.push_str("</string>\n");
    out.push_str("  <key>PayloadDescription</key>\n");
    out.push_str("  <string>");
    out.push_str(&plist_escape(&policy.description));
    out.push_str("</string>\n");
    out.push_str("  <key>PayloadVersion</key>\n");
    out.push_str(&format!("  <integer>{}</integer>\n", policy.version));
    // Settings.
    out.push_str("  <key>Settings</key>\n");
    out.push_str("  <dict>\n");
    for setting in &policy.settings {
        out.push_str("    <key>");
        out.push_str(&plist_escape(&setting.key));
        out.push_str("</key>\n");
        out.push_str(&plist_value_xml(&setting.value));
    }
    out.push_str("  </dict>\n");
    out.push_str("</dict>\n");
    out.push_str("</plist>\n");
    out.into_bytes()
}

/// Escape a string for use in an XML text node (per XML §2.4 — escape
/// `&`, `<`, `>`, and the quote characters).
fn plist_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a `PolicyValue` as a plist XML element (per Apple Configuration
/// Profile schema — `<string>`, `<integer>`, `<true/>`/`<false/>`,
/// `<data>` (base64), `<array>` of `<string>`).
fn plist_value_xml(v: &PolicyValue) -> String {
    match v {
        PolicyValue::String(s) => format!("    <string>{}</string>\n", plist_escape(s)),
        PolicyValue::Integer(n) => format!("    <integer>{}</integer>\n", n),
        PolicyValue::Boolean(true) => "    <true/>\n".to_string(),
        PolicyValue::Boolean(false) => "    <false/>\n".to_string(),
        PolicyValue::Bytes(b) => {
            // plist <data> is base64 — minimal inline encoder.
            format!("    <data>{}</data>\n", base64_encode(b))
        }
        PolicyValue::StringList(list) => {
            let mut out = String::from("    <array>\n");
            for s in list {
                out.push_str(&format!("      <string>{}</string>\n", plist_escape(s)));
            }
            out.push_str("    </array>\n");
            out
        }
    }
}

/// Minimal RFC 4648 base64 encoder (no external dep — keeps
/// `adrian-policy-core` lean).
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let chunks = bytes.chunks_exact(3);
    let rem = chunks.remainder();
    for c in chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(n & 0x3F) as usize] as char);
    }
    match rem.len() {
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push_str("==");
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

// ---- compile_to_authselect_profile (Linux) --------------------------------

/// Convert a `DeclarativePolicy` to a Linux `authselect` profile name
/// (per ADR-050 §Decision — the framework uses `authselect` as the
/// standard PAM profile manager on Linux).
///
/// The function looks for a setting with the key `authselect.profile`:
/// - If present and a string, returns its value (validated against the
///   set of known authselect profile names: `sssd`, `local`, `minimal`,
///   `winbind`, `nis`).
/// - If absent or invalid, returns the framework's default profile name
///   `sssd` (per ADR-050 §Decision — SSSD is the framework's primary
///   Linux identity stack per ADR-114).
pub fn compile_to_authselect_profile(policy: &DeclarativePolicy) -> String {
    const DEFAULT_PROFILE: &str = "sssd";
    const KNOWN_PROFILES: &[&str] = &["sssd", "local", "minimal", "winbind", "nis"];
    for setting in &policy.settings {
        if setting.key == "authselect.profile" {
            if let PolicyValue::String(s) = &setting.value {
                if KNOWN_PROFILES.contains(&s.as_str()) {
                    return s.clone();
                }
                // Unknown profile name — fall back to default rather than
                // emitting an invalid profile name that `authselect select`
                // would reject.
                return DEFAULT_PROFILE.to_string();
            }
        }
    }
    DEFAULT_PROFILE.to_string()
}

/// Validate a `DeclarativePolicy` (per ADR-089 §1 — schema validation).
///
/// Validation rules:
/// - `name` is non-empty.
/// - `description` may be empty (but is recommended).
/// - `version` is `>= 1`.
/// - Each setting's `key` is non-empty and dotted-namespaced (contains `.`).
/// - Each setting's `applies_to` entries (if any) are non-empty strings.
pub fn validate_declarative(policy: &DeclarativePolicy) -> Result<(), PolicyError> {
    if policy.name.is_empty() {
        return Err(PolicyError::Malformed(
            "declarative policy name must be non-empty".into(),
        ));
    }
    if policy.version < 1 {
        return Err(PolicyError::Malformed(format!(
            "declarative policy version {} must be >= 1",
            policy.version
        )));
    }
    if policy.settings.is_empty() {
        return Err(PolicyError::Malformed(
            "declarative policy must have at least one setting".into(),
        ));
    }
    for (i, setting) in policy.settings.iter().enumerate() {
        if setting.key.is_empty() {
            return Err(PolicyError::Malformed(format!(
                "setting {i}: key must be non-empty"
            )));
        }
        if !setting.key.contains('.') {
            return Err(PolicyError::Malformed(format!(
                "setting {i}: key {:?} must be dotted-namespaced (e.g. 'registry.foo.bar')",
                setting.key
            )));
        }
        for (j, target) in setting.applies_to.iter().enumerate() {
            if target.is_empty() {
                return Err(PolicyError::Malformed(format!(
                    "setting {i}: applies_to[{j}] must be non-empty"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-policy-core`. The first 5 tests are the
    //! original `PolicyDoc` structural tests (kept intact from the prior
    //! wave). The remaining tests cover the new `DeclarativePolicy`
    //! surface and the `compile_to_*` functions (Wave 4a).

    use super::*;
    use uuid::Uuid;

    /// Build a small but representative `PolicyDoc` covering multiple
    /// `PolicyArea` variants. Used by several of the tests below so the
    /// construction logic is verified once and reused.
    fn sample_doc() -> PolicyDoc {
        let registry = RegistryPolicy {
            values: vec![RegistryValue {
                key: "Software\\Adrian\\Framework".into(),
                value_name: "Enabled".into(),
                value_type: 4, // REG_DWORD per MS-PREG §2.4
                data: vec![0x01, 0x00, 0x00, 0x00],
            }],
        };
        let audit = AuditPolicy {
            subcategories: vec!["Logon".into(), "Logoff".into()],
        };
        PolicyDoc {
            // `Uuid::nil()` is used in tests because the workspace `uuid`
            // crate enables only the `v7` + `serde` features — `new_v4`
            // would require the `v4` feature. The UUID value itself is
            // irrelevant to the type-construction / round-trip coverage
            // these tests provide.
            uuid: Uuid::nil(),
            name: "baseline".into(),
            version: "0.1.0".into(),
            areas: vec![PolicyArea::Registry(registry), PolicyArea::Audit(audit)],
            security_descriptor: Some(vec![0x01, 0x00, 0x04, 0x80]),
            scope: PolicyScope {
                principals: vec!["S-1-5-32-544".into()],
                ous: vec!["OU=Servers,DC=adrian,DC=dev".into()],
                hosts: vec!["*.servers.adrian.dev".into()],
            },
        }
    }

    #[test]
    fn policy_doc_constructs_with_expected_fields() {
        let doc = sample_doc();
        assert_eq!(doc.name, "baseline");
        assert_eq!(doc.version, "0.1.0");
        assert_eq!(doc.areas.len(), 2);
        assert!(doc.security_descriptor.is_some());
        assert_eq!(doc.scope.principals.len(), 1);
    }

    #[test]
    fn policy_area_enum_variants_match_inner_type() {
        let doc = sample_doc();
        assert!(matches!(
            doc.areas[0],
            PolicyArea::Registry(RegistryPolicy { .. })
        ));
        assert!(matches!(
            doc.areas[1],
            PolicyArea::Audit(AuditPolicy { .. })
        ));
    }

    #[test]
    fn json_round_trip_preserves_structure() {
        let doc = sample_doc();
        let json = to_json(&doc).expect("to_json");
        let back = from_json(&json).expect("from_json");
        assert_eq!(back.name, doc.name);
        assert_eq!(back.version, doc.version);
        assert_eq!(back.areas.len(), doc.areas.len());
        assert_eq!(back.scope.principals, doc.scope.principals);
        assert_eq!(back.scope.hosts, doc.scope.hosts);
        assert_eq!(back.security_descriptor, doc.security_descriptor);
    }

    #[test]
    fn from_json_rejects_malformed_input() {
        let err = from_json("{not json").unwrap_err();
        assert!(matches!(err, PolicyError::Malformed(_)));
    }

    #[test]
    fn policy_error_variants_render_messages() {
        // Construct each variant explicitly so the Display impl is exercised
        // — this catches regressions in the `#[error("…")]` attributes that
        // would otherwise only surface in production logs.
        let malformed = PolicyError::Malformed("bad".into());
        let unsupported = PolicyError::UnsupportedArea("X".into());
        let empty = PolicyError::EmptyScope;
        let sd = PolicyError::InvalidSd("no-owners".into());

        assert_eq!(malformed.to_string(), "malformed policy document: bad");
        assert_eq!(unsupported.to_string(), "unsupported policy area: X");
        assert_eq!(empty.to_string(), "empty policy scope");
        assert_eq!(sd.to_string(), "invalid security descriptor: no-owners");
    }

    // ---- new DeclarativePolicy tests (Wave 4a) -----------------------------

    /// Build a small declarative policy covering multiple value types and
    /// multiple compile targets (registry, authselect, firewall).
    fn sample_declarative() -> DeclarativePolicy {
        DeclarativePolicy {
            version: 1,
            name: "baseline-workstation".into(),
            description: "Baseline policy for managed workstations.".into(),
            settings: vec![
                PolicySetting {
                    key: "registry.Software\\Adrian\\Framework\\Enabled".into(),
                    value: PolicyValue::Boolean(true),
                    applies_to: vec!["OU=Servers,DC=adrian,DC=dev".into()],
                },
                PolicySetting {
                    key: "registry.Software\\Adrian\\Framework\\DisplayName".into(),
                    value: PolicyValue::String("Adrian".into()),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "registry.Software\\Adrian\\Framework\\Modules".into(),
                    value: PolicyValue::StringList(vec!["core".into(), "policy".into()]),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "registry.Software\\Adrian\\Framework\\Threshold".into(),
                    value: PolicyValue::Integer(42),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "authselect.profile".into(),
                    value: PolicyValue::String("sssd".into()),
                    applies_to: vec![],
                },
                PolicySetting {
                    key: "registry.Software\\Adrian\\Framework\\Signature".into(),
                    value: PolicyValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                    applies_to: vec![],
                },
            ],
        }
    }

    #[test]
    fn declarative_policy_serializes_to_json_and_back() {
        let policy = sample_declarative();
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: DeclarativePolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name, policy.name);
        assert_eq!(back.settings.len(), policy.settings.len());
        assert_eq!(back.settings[0].value, policy.settings[0].value);
    }

    #[test]
    fn validate_declarative_accepts_sample_policy() {
        let policy = sample_declarative();
        validate_declarative(&policy).expect("valid");
    }

    #[test]
    fn validate_declarative_rejects_empty_name() {
        let mut policy = sample_declarative();
        policy.name = String::new();
        let err = validate_declarative(&policy).unwrap_err();
        assert!(matches!(err, PolicyError::Malformed(_)));
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn validate_declarative_rejects_unnamespaced_key() {
        let mut policy = sample_declarative();
        policy.settings[0].key = "noseparator".into();
        let err = validate_declarative(&policy).unwrap_err();
        assert!(matches!(err, PolicyError::Malformed(_)));
        assert!(err.to_string().contains("dotted-namespaced"));
    }

    #[test]
    fn compile_to_preg_emits_one_entry_per_registry_setting() {
        let policy = sample_declarative();
        let preg = compile_to_preg(&policy);
        // 5 registry.* settings in the sample (Enabled, DisplayName,
        // Modules, Threshold, Signature).
        assert_eq!(preg.entries.len(), 5);
        // The "Enabled" entry is REG_DWORD with value 1.
        let enabled = preg
            .entries
            .iter()
            .find(|e| e.value_name == "Enabled")
            .expect("Enabled entry present");
        assert_eq!(enabled.value_type, adrian_policy_preg::reg_value::REG_DWORD);
        let dv = adrian_policy_preg::decode_reg_dword(&enabled.value).expect("decode dword");
        assert_eq!(dv, 1);
    }

    #[test]
    fn compile_to_preg_skips_non_registry_settings() {
        let policy = sample_declarative();
        let preg = compile_to_preg(&policy);
        // The authselect.profile setting must not appear in the PReg file.
        assert!(preg.entries.iter().all(|e| e.key != "authselect"));
    }

    #[test]
    fn compile_to_preg_round_trips_through_preg_decode() {
        let policy = sample_declarative();
        let preg = compile_to_preg(&policy);
        let bytes = preg.serialize().expect("serialize");
        let back = adrian_policy_preg::decode_preg_file(&bytes).expect("decode");
        assert_eq!(back.entries.len(), preg.entries.len());
    }

    #[test]
    fn compile_to_configuration_profile_emits_valid_plist_xml() {
        let policy = sample_declarative();
        let bytes = compile_to_configuration_profile(&policy);
        let xml = String::from_utf8(bytes).expect("valid UTF-8");
        // Required plist XML framing.
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<!DOCTYPE plist PUBLIC"));
        assert!(xml.contains("<plist version=\"1.0\">"));
        assert!(xml.contains("<dict>"));
        // Payload metadata keys.
        assert!(xml.contains("<key>PayloadDisplayName</key>"));
        assert!(xml.contains("baseline-workstation"));
        // A typed value from each PolicyValue variant.
        assert!(xml.contains("<true/>")); // Boolean true
        assert!(xml.contains("<string>Adrian</string>")); // String
        assert!(xml.contains("<integer>42</integer>")); // Integer
        assert!(xml.contains("<data>")); // Bytes
        assert!(xml.contains("<array>")); // StringList
    }

    #[test]
    fn compile_to_authselect_profile_returns_sssd_default() {
        let policy = sample_declarative();
        assert_eq!(compile_to_authselect_profile(&policy), "sssd");
    }

    #[test]
    fn compile_to_authselect_profile_falls_back_on_unknown_name() {
        let mut policy = sample_declarative();
        // Change the authselect.profile value to an unknown string.
        for s in &mut policy.settings {
            if s.key == "authselect.profile" {
                s.value = PolicyValue::String("nonsense-profile".into());
            }
        }
        // Unknown profile name should fall back to "sssd" default rather
        // than producing an authselect command that would fail.
        assert_eq!(compile_to_authselect_profile(&policy), "sssd");
    }

    #[test]
    fn compile_to_authselect_profile_returns_local_when_set() {
        let mut policy = sample_declarative();
        for s in &mut policy.settings {
            if s.key == "authselect.profile" {
                s.value = PolicyValue::String("local".into());
            }
        }
        assert_eq!(compile_to_authselect_profile(&policy), "local");
    }

    #[test]
    fn validate_policy_doc_rejects_empty_scope() {
        let mut doc = sample_doc();
        doc.scope.principals.clear();
        doc.scope.ous.clear();
        doc.scope.hosts.clear();
        let err = validate(&doc).unwrap_err();
        assert!(matches!(err, PolicyError::EmptyScope));
    }

    #[test]
    fn validate_policy_doc_rejects_bad_version() {
        let mut doc = sample_doc();
        doc.version = "not-semver".into();
        let err = validate(&doc).unwrap_err();
        assert!(matches!(err, PolicyError::Malformed(_)));
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn diff_of_equal_docs_produces_empty_areas() {
        let doc = sample_doc();
        let inverse = diff(&doc, &doc);
        assert!(inverse.areas.is_empty());
        assert_eq!(inverse.name, doc.name);
    }

    #[test]
    fn diff_of_changed_docs_returns_old_for_rollback() {
        let old = sample_doc();
        let mut new = old.clone();
        new.areas.clear(); // simulate a destructive change
        let inverse = diff(&old, &new);
        assert_eq!(inverse.areas.len(), old.areas.len());
    }

    #[test]
    fn base64_encoder_matches_rfc_4648_test_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
