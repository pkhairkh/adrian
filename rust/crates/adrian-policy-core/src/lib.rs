//! # adrian-policy-core
//!
//! Canonical policy document model (`PolicyDoc`, `PolicyArea`) for the
//! Adrian framework.
//!
//! Per ADR-029 §Decision and ADR-113 §Decision, the framework's policy model
//! uses a canonical JSON representation that compiles to platform-native
//! formats (PReg `Registry.pol` + GPP XML on Windows, MDM Configuration
//! Profile payloads on macOS, `authselect` + `limits.conf.d` + `auditd`
//! + `nftables` on Linux). This crate defines the canonical JSON schema
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
//! `adrian-schema-traits`, `serde`, `serde_json`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A canonical policy document (per ADR-029 §Decision).
///
/// The document is a list of `PolicyArea` entries, each targeting a
/// platform-specific concern (registry, file system, audit, firewall,
/// authentication, etc.). The document is the source of truth; per-platform
/// executors (in `adrian-policy-executor`) compile it to platform-native
/// formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPolicy {
    /// The registry values (key path, value name, type, data).
    pub values: Vec<RegistryValue>,
}

/// A single registry value (per ADR-029 §Decision — PReg format).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemPolicy {
    /// The ACL entries (path, principal, permission).
    pub entries: Vec<FileSystemAclEntry>,
}

/// A single file-system ACL entry (per ADR-113).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemAclEntry {
    /// The file path.
    pub path: String,
    /// The principal SID (per Decision 3 — wire-format currency is SID).
    pub principal_sid: String,
    /// The permission (read, write, execute, etc.).
    pub permission: String,
}

/// Audit policy (per ADR-060).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// The audit subcategories to enable (per Windows `auditpol`).
    pub subcategories: Vec<String>,
}

/// Firewall policy (per ADR-113).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPolicy {
    /// The firewall rules.
    pub rules: Vec<FirewallRule>,
}

/// A single firewall rule (per ADR-113).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPolicy {
    /// The authselect profile name (per ADR-050 — `sssd` / `minimal` /
    /// `local`).
    pub authselect_profile: String,
    /// Whether to enable smart-card auth (per ADR-084).
    pub smartcard_required: bool,
}

/// Restricted groups policy (per ADR-066).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestrictedGroupsPolicy {
    /// The group memberships to enforce (group SID → member SIDs).
    pub memberships: Vec<(String, Vec<String>)>,
}

/// Scripts policy (per ADR-113).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPreferencesPolicy {
    /// The GPP XML payloads (one per application).
    pub payloads: Vec<String>,
}

/// The policy scope (per ADR-030 — role-based binding).
#[derive(Debug, Clone, Serialize, Deserialize)]
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

// TODO: implement PolicyDoc validation per ADR-029.
// TODO: implement PolicyDoc diff (per ADR-025 — transactional rollback uses a diff to compute the inverse).
