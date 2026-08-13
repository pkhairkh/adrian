---
title: "Policy Engine (GPO-equivalent) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Policy Engine
tags: [spec, policy-engine, gpo, admx, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Policy Engine (GPO-equivalent) — Technical Specification

## 1. Overview

The Policy Engine replaces Group Policy Objects (GPO) with a hybrid declarative model: a canonical JSON policy format compiled from ADMX templates, distributed via WebSocket push or Git-backed pull, applied by per-platform `PolicyExecutor` implementations (PReg on Windows, MDM Configuration Profile on macOS, `authselect` + `audit.rules` on Linux), with transactional rollback, role-based binding, and Git-backed history with PR review. The engine eliminates the antipatterns that plague GPO — `cPassword` AES-256 key leakage (MS14-025), DFS-R Windows-only SYSVOL replication, ADMX/ADML macro explosion, no transactional rollback, no `git blame`.

The capability carries 14 ADRs: ADR-024 (per-platform policy executors), ADR-025 (transactional policy rollback), ADR-026 (declarative host facts + WMI filter adapter), ADR-027 (HTTP HEAD slow-link detection), ADR-028 (push-based policy updates via WebSocket), ADR-029 (JSON canonical policy + PReg adapter), ADR-030 (role-based policy binding), ADR-031 (Git-backed policy history), ADR-089 (declarative canonical JSON + INI/Registry.pol AD-interop adapter), ADR-090 (`admx2adrian` Rust compiler), ADR-091 (GPP cross-platform compilation), ADR-092 (`PolicyExecutor` trait with Windows/macOS/Linux implementations), ADR-093 (SSSD GPO access control enhancement), ADR-094 (SYSVOL-equivalent Git-backed replication + SMB read surface). It resolves two blockers (PC-045 GPP cross-platform, PC-055 SYSVOL DFS-R replacement) plus two high-severity problems.

Workshop Decision 7 chose hybrid: declarative JSON is canonical, ADMX is consumed by `admx2adrian` (one-way), and `preg2adrian`/`adrian2preg` adapters preserve Windows interop for the GPT distribution channel. CEL is the default selector language for role-based binding (ADR-030); Rego is opt-in.

The capability is implemented as **nine** Rust crates spanning Layers 2–3: `adrian-policy-core`, `adrian-policy-executor`, `adrian-policy-cel`, `adrian-policy-preg`, `adrian-policy-distribution`, `adrian-policy-daemon`, `adrian-admx-compiler`, `adrian-sssd-gpo` (cdylib). External dependencies include `quick-xml` (ADMX parsing), `serde_json`, `cel` (selector language), `regorus` (optional Rego), `plist` (macOS Configuration Profile), `rustls` (WebSocket mTLS), `tokio`, `git2` (Git-backed history), `tokio-tungstenite` (WebSocket).

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-policy-core` | 2 | `PolicyDoc`, `PolicyArea` enum, `PolicySetting` types, canonical JSON serialization | ADR-029, ADR-089 |
| `adrian-policy-executor` | 2 | `PolicyExecutor` trait + `WindowsPolicyExecutor` (PReg + GptTmpl.inf + synthetic CSE JSON) + `MacOsPolicyExecutor` (Configuration Profile payloads) + `LinuxPolicyExecutor` (`authselect` + `limits.conf.d/` + `audit.rules.d/` + `nftables`/`firewalld` + atomic `rename(2)` writes) | ADR-024, ADR-092 |
| `adrian-policy-cel` | 2 | CEL selector for role-based binding (ADR-030); `Claims.user.department == "Engineering" && Host.facts.os == "linux"` | ADR-030 |
| `adrian-policy-preg` | 2 | PReg adapter — `Registry.pol` reader/writer per MS-GPOL §2.4; `preg2adrian` + `adrian2preg` | ADR-029, ADR-089 |
| `adrian-policy-distribution` | 3 | WebSocket push (mTLS, ADR-028) + Git pull (ADR-031); slow-link detection via HTTP HEAD (ADR-027) | ADR-028, ADR-031, ADR-027 |
| `adrian-policy-daemon` | 3 | `adrian-policyd` binary; runs as SYSTEM/root/launchd; transactional apply with rollback (ADR-025) | ADR-025 |
| `adrian-admx-compiler` | 3 | `admx2adrian` binary; ingests ADMX+ADML, emits canonical JSON `PolicyTemplate` + JSON Schema + category tree + presentation layout; one-way, deterministic, byte-identical output (ADR-090). Gated by `ad-interop`. | ADR-090 |
| `adrian-sssd-gpo` | 3 | cdylib extending SSSD's `ad_gpo_access` to full `Security` PolicyArea via `gpo_access_provider = adrian` (ADR-093) | ADR-093 |
| `adrian-policy-distribution` (cont.) | 3 | SYSVOL-equivalent Git-backed policy repository + SMB read surface per ADR-094 (used by `adrian-smb-server` to serve `\\<domain>\SYSVOL\...` UNC paths) | ADR-094 |

## 3. Key types and traits

```rust
// crates/adrian-policy-core/src/lib.rs

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Canonical policy document. Single source of truth in Git.
/// GPC/GPT views generated for AD-interop (per ADR-089).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyDoc {
    pub id: Uuid,                           // policy UUIDv7
    pub version: u32,                       // monotonic, increments on edit
    pub name: String,
    pub description: String,
    pub area: PolicyArea,
    pub settings: BTreeMap<String, PolicySetting>,  // ordered for byte-identical JSON
    pub scope: PolicyScope,
    pub binding: Option<Binding>,           // CEL expression for role-based binding
    pub parent_version: Option<u32>,        // for diff history
    pub authored_by: String,                // PR author
    pub authored_at: SystemTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "area", rename_all = "snake_case")]
pub enum PolicyArea {
    Security {            // Security Settings; ~85 sub-areas in MS-GPOL §2.3.1
        account_policy: Option<AccountPolicy>,
        local_policies: Option<LocalPolicies>,
        event_log: Option<EventLogPolicy>,
        restricted_groups: BTreeMap<String, Vec<String>>,
        system_services: BTreeMap<String, ServiceConfig>,
        registry: BTreeMap<String, RegistryValue>,
        file_system: BTreeMap<String, FileAcl>,
        // ... 12 more sub-areas
    },
    Preferences {         // GPP — per ADR-091, cross-platform compiled
        files: Vec<FilesPref>,
        drive_maps: Vec<DriveMapPref>,
        local_users_groups: Vec<UserGroupPref>,
        scheduled_tasks: Vec<SchedTaskPref>,
        environment: Vec<EnvVarPref>,
        printers: Vec<PrinterPref>,
    },
    Scripts { startup: Vec<String>, shutdown: Vec<String>,
              logon: Vec<String>, logoff: Vec<String> },
    DeployedApps { msi_packages: Vec<MsiPackage> },  // Windows-only in v1
    EfsRecovery { agents: Vec<String> },
    PublicKeyPolicies { eku_templates: Vec<String> },
    AdminTemplates { registry_keys: BTreeMap<String, RegistryValue> },  // from ADMX
    ScopeOfManagement { mdm_enrollment: Option<String> },  // macOS/Linux
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicySetting {
    Registry { hive: String, path: String, value: String, value_type: RegType },
    Secret { secret_ref: SecretRef },         // ADR-091 — eliminates cPassword
    FileAcl { path: String, sd: String },
    AuditRule { category: String, audit: AuditRule },
    Firewall { rule: FirewallRule },
    PlistPayload { domain: String, key: String, value: PlistValue },  // macOS
    AuthselectProfile { name: String, optional_modules: Vec<String> }, // Linux
    NftablesRule { table: String, chain: String, rule: String },      // Linux
    ShellScript { shell: String, body: String, location: String },
}

/// Secret reference — eliminates the cPassword AES-256 antipattern.
/// Actual secret stored in the framework's secrets service (per-host
/// LAPS rotation per ADR-054, or per-policy encrypted blob).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretRef {
    pub store: SecretStore,                   // "laps" | "kms" | "hsm-blob"
    pub key: String,                          // "laps/<host-fqdn>" | "policy/<uuid>/<setting>"
    pub version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Binding {
    pub selector_language: SelectorLang,     // CEL (default) | Rego (opt-in)
    pub expression: String,                  // CEL expression
}

pub enum SelectorLang { Cel, Rego }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyScope {
    pub hosts: HostFilter,                   // hostname glob | CEL expression
    pub users: UserFilter,                   // user UPN glob | CEL
    pub ou: Option<String>,                  // AD OU distinguished name
    pub wmi_filter: Option<String>,          // WMI query (per ADR-026)
}
```

```rust
// crates/adrian-policy-executor/src/lib.rs (per ADR-024, ADR-092)

#[async_trait]
pub trait PolicyExecutor: Send + Sync {
    async fn apply(
        &self,
        policy: &PolicyDoc,
        target_host: &HostFacts,
    ) -> Result<ApplyResult, PolicyError>;

    async fn rollback(&self, transaction_id: Uuid) -> Result<(), PolicyError>;

    async fn verify(&self, policy: &PolicyDoc) -> Result<VerifyResult, PolicyError>;

    /// Per-host policy_state.db (SQLite) — used for transactional
    /// rollback per ADR-025. BEGIN → apply → COMMIT; failed applies
    /// roll back via shadow-path rename(2).
    fn state_db_path(&self) -> &Path;
}

pub struct ApplyResult {
    pub transaction_id: Uuid,
    pub applied_settings: Vec<String>,
    pub skipped_settings: Vec<String>,       // filtered out by binding
    pub failed_settings: Vec<(String, String)>,
    pub duration: Duration,
}

pub struct WindowsPolicyExecutor { /* PReg + GptTmpl.inf + Scripts.ini + GPP XML + synthetic CSE JSON */ }
pub struct MacOsPolicyExecutor { /* MDM Configuration Profile payloads */ }
pub struct LinuxPolicyExecutor { /* authselect + limits.conf.d/ + audit.rules.d/ + nftables + rename(2) */ }

impl PolicyExecutor for WindowsPolicyExecutor { /* ... */ }
impl PolicyExecutor for MacOsPolicyExecutor { /* ... */ }
impl PolicyExecutor for LinuxPolicyExecutor { /* ... */ }
```

```rust
// crates/adrian-admx-compiler/src/lib.rs (per ADR-090)

/// `admx2adrian` compiler. Ingests ADMX + ADML files, emits
/// canonical JSON PolicyTemplate + JSON Schema + category tree +
/// presentation layout. One-way, deterministic, byte-identical
/// output for reproducible Git diffs.
pub struct AdmxCompiler {
    strict: bool,           // fail on unknown ADMX constructs
    include_presentation: bool,
}

impl AdmxCompiler {
    pub fn compile_dir(&self, admx_dir: &Path, out_dir: &Path)
        -> Result<CompileReport, AdmxError>;
}

pub struct CompileReport {
    pub policies_emitted: u32,        // ~3,500 for Microsoft built-in ADMX
    pub categories_emitted: u32,
    pub schemas_emitted: u32,
    pub unsupported_constructs: Vec<UnsupportedConstruct>,
    pub bytes_written: u64,
}

/// Output file structure per ADMX file:
///   out_dir/<admx_basename>.policy.json    — PolicyTemplate[]
///   out_dir/<admx_basename>.schema.json    — JSON Schema for validation
///   out_dir/<admx_basename>.categories.json — category tree
///   out_dir/<admx_basename>.presentation.json — presentation layout for UI
```

## 4. Data model

```
Policy data model — three storage layers:

1. Git repository (canonical source of truth, per ADR-031)
   repos/adrian-policy.git/
     policies/
       <policy-uuid>.json          — canonical PolicyDoc (per ADR-089)
       <policy-uuid>.history.json   — version history with PR refs
     templates/                     — compiled ADMX output (per ADR-090)
       <admx-file>.policy.json
       <admx-file>.schema.json
     bindings/                      — CEL expression libraries
     hosts/                         — per-host facts (per ADR-026)
       <host-fqdn>.json             — HostFacts (OS, hostname, MAC,
                                       OUs, claims like department)

2. FDB subspace (operational state, snapshot of Git)
   (0x0B, 0x01, policy_uuid)       → serialized PolicyDoc
   (0x0B, 0x02, host_fqdn, policy_uuid) → resolved_policy_for_host
   (0x0B, 0x03, host_fqdn, ts)     → applied_policy_history entry
                                       (transaction_id, version, duration)
   (0x0B, 0x04, transaction_id)    → rollback_state (shadow paths + backups)

3. Per-host state_db (SQLite, per ADR-025)
   /var/lib/adrian/policy_state.db
     CREATE TABLE applied_policies (
       transaction_id TEXT PRIMARY KEY,
       policy_uuid TEXT NOT NULL,
       policy_version INTEGER NOT NULL,
       applied_at INTEGER NOT NULL,
       shadow_paths TEXT NOT NULL,    -- JSON array of backup paths
       status TEXT NOT NULL           -- 'applied' | 'rolled_back'
     );
     CREATE TABLE settings_audit (
       transaction_id TEXT NOT NULL,
       setting_key TEXT NOT NULL,
       old_value TEXT,
       new_value TEXT,
       applied_at INTEGER NOT NULL,
       FOREIGN KEY (transaction_id) REFERENCES applied_policies
     );

4. AD-interop SYSVOL surface (per ADR-094, served via adrian-smb-server)
   \\<domain>\SYSVOL\<domain>\Policies\
     {<policy-guid>}\GPT.INI          — generated from PolicyDoc
     {<policy-guid>}\User\Registry.pol — PReg adapter output
     {<policy-guid>}\Machine\Registry.pol
     {<policy-guid>}\User\Preferences\...  — GPP XML (per ADR-091)
     {<policy-guid>}\Machine\Scripts\...
   Generated on-demand from canonical PolicyDoc; not the source of truth.

5. macOS MDM Configuration Profile (per ADR-092)
   /Library/Managed Preferences/<domain>/<policy-uuid>.mobileconfig
   — plist file generated by MacOsPolicyExecutor

6. Linux per-host config files (per ADR-092)
   /etc/authselect/adrian.conf              — authselect profile
   /etc/security/limits.conf.d/99-adrian.conf
   /etc/audit/rules.d/99-adrian.rules
   /etc/login.defs.d/99-adrian.conf
   /etc/nftables/adrian-{input,forward,output}.nft
   /etc/firewalld/zones/adrian.xml
   — atomic rename(2) writes for rollback

PolicyArea → platform compilation matrix (per ADR-091):
  | Area           | Windows        | macOS              | Linux               |
  |----------------|----------------|--------------------|---------------------|
  | Security.AcctPolicy | Registry.pol   | passwordpolicy plist | login.defs.d      |
  | Security.AuditPolicy | Registry.pol  | audit plist        | audit.rules.d       |
  | Security.UserRights  | GptTmpl.inf    | authselect          | authselect+polkit  |
  | Preferences.Files    | GPP XML        | files plist         | systemd-tmpfiles   |
  | Preferences.DriveMaps| GPP XML        | mount.plist         | systemd-mount      |
  | Preferences.Printers | GPP XML        | printer plist       | cups config        |
  | AdminTemplates.Registry | Registry.pol | ManagedClient    | (skip on Linux)    |
```

## 5. Protocol surface

```
Policy distribution protocol (per ADR-028, ADR-094):

WebSocket push (per ADR-028):
  wss://policy.corp.example.com/v1/events
  mTLS auth (client cert = host enrollment cert per ADR-058)
  Messages (JSON, framed as length-prefixed):
    { "type": "policy_updated", "policy_uuid": "...", "version": 42 }
    { "type": "policy_deleted", "policy_uuid": "..." }
    { "type": "binding_changed", "host_fqdn": "...", "policies": [...] }
    { "type": "refresh_now" }                // operator-triggered refresh
  Server pushes events on Git commit hook (per ADR-031)

HTTP long-poll fallback (per ADR-028):
  GET https://policy.corp.example.com/v1/longpoll?since=<ts>
  90-second timeout; returns when new events exist or timeout

Slow-link detection (per ADR-027):
  GET HEAD https://policy.corp.example.com/v1/probe
  If response time > 500ms, switch from push to pull-on-boot

Git pull (per ADR-031):
  git clone https://policy.corp.example.com/adrian-policy.git
  Pull every 5 minutes; tag-based versioning for atomic updates

SYSVOL read surface (per ADR-094):
  SMB share \\<domain>\SYSVOL\
  Served by adrian-smb-server; honors UNC paths
  Files generated on-demand from canonical PolicyDoc
  Per-DC cached for 60 seconds

REST API (per ADR-061, used by policy management UIs):
  GET    /api/v1/policies                  — list policies
  POST   /api/v1/policies                  — create policy (creates Git PR)
  GET    /api/v1/policies/<uuid>           — get policy
  PUT    /api/v1/policies/<uuid>           — update policy (creates Git PR)
  DELETE /api/v1/policies/<uuid>           — delete policy (creates Git PR)
  GET    /api/v1/policies/<uuid>/history   — version history
  POST   /api/v1/policies/<uuid>/preview   — preview apply on host
  GET    /api/v1/hosts/<fqdn>/applied      — currently-applied policies
  GET    /api/v1/hosts/<fqdn>/drift        — drift report
  POST   /api/v1/hosts/<fqdn>/rollback     — rollback to transaction_id

WMI filter adapter (per ADR-026):
  Outbound: framework host agent evaluates WMI filter on Windows
            hosts only via COM IWbemServices::ExecQuery
  Inbound: framework directory exposes HostFacts as a virtual WMI
           namespace for AD-interop Group Policy Management Console
           compatibility (read-only)
```

## 6. Configuration

```toml
# /etc/adrian/policyd.toml — Policy daemon configuration

[daemon]
listen_addr            = "0.0.0.0:8443"
tls_cert_file          = "/etc/adrian/policyd.crt"
tls_key_file           = "/etc/adrian/policyd.key"
ws_listen_addr         = "0.0.0.0:8444"   # WebSocket push per ADR-028
state_db_path          = "/var/lib/adrian/policy_state.db"
run_as_user            = "root"            # Linux; SYSTEM on Windows; root via launchd on macOS

[canonical]                              # per ADR-089
format                  = "json"
schema_strict           = true
byte_identical_serialization = true       # for reproducible Git diffs

[git]                                    # per ADR-031
repo_url                = "https://policy.corp.example.com/adrian-policy.git"
local_clone             = "/var/lib/adrian/policy-repo"
poll_interval_secs      = 300
ssh_key_file            = "/etc/adrian/policy-git-key"
author_name             = "adrian-policyd"
author_email            = "policyd@corp.example.com"
pr_review_required      = true            # GitOps PR per ADR-031

[push]                                   # per ADR-028
enabled                 = true
mtls_required           = true
longpoll_fallback       = true
longpoll_timeout_secs   = 90
slow_link_threshold_ms  = 500             # per ADR-027

[executor]                               # per ADR-092
platform                = "linux"        # windows | macos | linux (auto-detected)
transactional_rollback  = true           # per ADR-025
shadow_path_root        = "/var/lib/adrian/policy-shadow"
atomic_rename           = true

[selector]                               # per ADR-030
language                = "cel"          # cel | rego
allow_rego_opt_in       = true
cel_max_eval_ms         = 50

[admx_compiler]                          # per ADR-090
strict_mode             = true
include_presentation    = true
microsoft_builtin_admx_dir = "/usr/share/adrian/admx/microsoft"
custom_admx_dir         = "/etc/adrian/admx/custom"
regenerate_on_boot      = false

[ad_interop]                             # per ADR-094
sysvol_share_enabled    = true
gpt_generation          = true
preg_adapter            = true
gpt_ini_path            = "\\<domain>\\SYSVOL\\<domain>\\Policies\\{<guid>}\\GPT.INI"

[sssd_integration]                       # per ADR-093
gpo_access_provider     = "adrian"       # SSSD directive
extended_security_areas = true           # full Security PolicyArea
sudoers_compilation     = true

[audit]
otel_endpoint           = "http://otel-collector:4317"
emit_apply_events       = true
emit_rollback_events    = true
emit_drift_events       = true
emit_binding_eval       = true
```

## 7. Error handling

```rust
// crates/adrian-policy-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy parse error in {file}: {reason}")]
    ParseError { file: String, reason: String },
    #[error("policy schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("setting {setting} unsupported on {platform}")]
    UnsupportedOnPlatform { setting: String, platform: String },
    #[error("CEL binding evaluation failed: {0}")]
    CelEvalFailed(String),
    #[error("Rego binding evaluation failed: {0}")]
    RegoEvalFailed(String),
    #[error("Git operation failed: {0}")]
    GitError(String),
    #[error("transactional apply failed: {settings_count} settings rolled back via shadow path")]
    ApplyFailed { settings_count: u32 },
    #[error("rollback failed for transaction {0}: shadow path missing")]
    RollbackFailed(Uuid),
    #[error("WMI filter evaluation failed: {0}")]
    WmiFilterFailed(String),
    #[error("admx2adrian compile failed: {0}")]
    AdmxCompileFailed(String),
    #[error("PReg write failed: {0}")]
    PregWriteFailed(String),
    #[error("secret store error: {0}")]
    SecretStoreError(String),
    #[error("policy version conflict: expected {expected}, got {actual}")]
    VersionConflict { expected: u32, actual: u32 },
    #[error("storage layer: {0}")]
    Storage(#[from] DirectoryError),
}

// crates/adrian-admx-compiler/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum AdmxError {
    #[error("ADMX parse error: {0}")]
    ParseError(String),
    #[error("unsupported ADMX construct: {construct} in {file}")]
    Unsupported { construct: String, file: String },
    #[error("ADML string missing for id {0}")]
    MissingAdmlString(String),
    #[error("circular policy reference: {0}")]
    CircularRef(String),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}
```

**Error propagation.** Policy errors map to platform-native error surfaces: Windows → Event Log (Application log, source "AdrianPolicy"); macOS → `os_log` with subsystem `com.adrian.policyd`; Linux → journald + structured OTel. Operator surfaces errors via `adrian-cli policy status` and `adrian-cli policy drift`. Failed applies roll back atomically (per ADR-025) and the failure event includes the failing setting's key, the CEL binding result, and the shadow-path rollback trace. Git PRs that fail policy validation (broken CEL, schema mismatch, unsupported setting) are rejected by the Git hook with the error message in the PR comment.

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - PolicyDoc serialization byte-identical round-trips (BTreeMap ordering)
    - PolicyArea enum all-variant serialization
    - SecretRef store dispatch (laps/kms/hsm-blob)
    - CEL binding evaluation (50 expressions, positive + negative)
    - Rego binding evaluation (opt-in path, 20 expressions)
    - PReg read+write round-trips (Registry.pol format)
    - ADMX compiler: 10 sample ADMX files, byte-identical output
    - GPP cross-platform compilation matrix (per ADR-091)
    - WindowsPolicyExecutor: Registry.pol + GptTmpl.inf generation
    - MacOsPolicyExecutor: Configuration Profile generation
    - LinuxPolicyExecutor: authselect + limits.conf.d + audit.rules
    - Transactional rollback: failed apply → shadow path → restore

Integration tests — tests/integration/, real FDB + Git + tokio
  Coverage:
    - Git-backed policy lifecycle: create PR → review → merge →
      WebSocket push → daemon apply → state_db update
    - Transactional apply with intentional failure mid-apply
    - Rollback to previous transaction_id
    - SYSVOL SMB read surface (adrian-smb-server serving generated GPT)
    - WMI filter evaluation on Windows host (interop VM)
    - SSSD gpo_access_provider=adrian end-to-end on Linux host
    - Slow-link detection (network throttle → push→pull switch)

Interop tests — tests/interop/
  Matrix:
    - Windows Server 2022 GPMC reading framework-generated GPT
      (verify GPT.INI + Registry.pol parse correctly)
    - Windows Server 2022 GPMC editing GPO → framework pulls changes
      via `preg2adrian` and updates canonical PolicyDoc
    - macOS MDM profile from MacOsPolicyExecutor via Profile Manager
    - Linux `authselect apply-changes` from LinuxPolicyExecutor output
    - SSSD 2.9 with `gpo_access_provider = adrian` on RHEL 9

Property-based tests — proptest
  Parsers tested:
    - PolicyDoc JSON round-trips
    - PReg Registry.pol round-trips
    - ADMX XML round-trips (quick-xml)
    - Configuration Profile plist round-trips
  Corpus: 100+ property tests across policy crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-029: canonical JSON policy format + PReg adapter
  - ADR-089: declarative canonical + INI/Registry.pol AD-interop
  - ADR-090: admx2adrian compiler for Microsoft built-in ADMX
             (~3,500 policies)
  - ADR-024/092: WindowsPolicyExecutor + LinuxPolicyExecutor
  - ADR-028: WebSocket push distribution
  - ADR-031: Git-backed history with PR review
  - ADR-094: SYSVOL-equivalent Git-backed SMB read surface
  - ADR-026: declarative host facts + WMI filter adapter
  - ADR-027: HTTP HEAD slow-link detection
  - ADR-025: transactional rollback

v1 (Phase 2):
  - MacOsPolicyExecutor (full Configuration Profile coverage)
  - ADR-091: GPP cross-platform compilation
  - preg2adrian reverse adapter (AD-interop GPO ingestion)
  - ADR-030: role-based binding (CEL default, Rego opt-in)
  - ADR-093: SSSD GPO access control enhancement
              (gpo_access_provider = adrian)

v2 (Phase 3):
  - DDM-first authoring for macOS 13+ payloads (per ADR-052)
  - Rego selector opt-in for advanced policy expressions
  - Synthetic CSE for legacy Windows apps that consume custom CSEs
  - Predictive policy drift detection via OTel anomaly scoring
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `quick-xml` | 0.31 | ADMX/ADML XML parsing |
| `serde` / `serde_json` | 1 | PolicyDoc canonical JSON |
| `cel` | 0.2 | CEL selector for role-based binding (ADR-030) |
| `regorus` | 0.2 | Rego selector (opt-in, ADR-030) |
| `plist` | 1.6 | macOS Configuration Profile (.mobileconfig) generation |
| `rust-ini` | 0.21 | INI file parsing (GptTmpl.inf, login.defs.d) |
| `rustls` | 0.23 | TLS for WebSocket + REST |
| `tokio` | 1 | Async runtime |
| `tokio-tungstenite` | 0.21 | WebSocket push (ADR-028) |
| `git2` | 0.18 | Git-backed history (ADR-031) |
| `axum` | 0.7 | REST API server (ADR-061) |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit events |
| `proptest` | 1 | Property-based tests |
| `clap` | 4 | CLI for `admx2adrian` binary |
| `uuid` | 1.10 | Policy UUIDv7 |
| `chrono` | 0.4 | Timestamps in Git history |
| `tempfile` | 3 | Shadow-path atomic writes |
| `rusqlite` | 0.31 | per-host state_db for transactional rollback |
| `adrian-storage-core` | * | DirectoryStore for FDB policy snapshot |

## 11. References

- ADRs: [ADR-024](../adr/ADR-024-per-platform-policy-executors.md), [ADR-025](../adr/ADR-025-transactional-policy-rollback.md), [ADR-026](../adr/ADR-026-declarative-host-facts-wmi-adapter.md), [ADR-027](../adr/ADR-027-http-head-slow-link-detection.md), [ADR-028](../adr/ADR-028-push-based-policy-websocket.md), [ADR-029](../adr/ADR-029-json-canonical-policy-preg-adapter.md), [ADR-030](../adr/ADR-030-role-based-policy-binding.md), [ADR-031](../adr/ADR-031-git-backed-policy-history.md), [ADR-052](../adr/ADR-052-ddm-first-authoring.md), [ADR-054](../adr/ADR-054-per-host-laps-rotation.md), [ADR-089](../adr/ADR-089-declarative-policy-gpc-gpt-synthesis.md), [ADR-090](../adr/ADR-090-admx-to-declarative-json-compiler.md), [ADR-091](../adr/ADR-091-gpp-preferences-cross-platform-compilation.md), [ADR-092](../adr/ADR-092-policy-executor-trait-synthetic-windows-cse.md), [ADR-093](../adr/ADR-093-sssd-gpo-access-control-enhancement.md), [ADR-094](../adr/ADR-094-sysvol-replication-git-backed.md)
- Workshop decisions: [Decision 7 — Policy Format](../workshop/decision-07-policy-format.md)
- KB files: [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md), [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), [docs/04-group-policy/03-admx-templates.md](../docs/04-group-policy/03-admx-templates.md), [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md), [docs/04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md)
- RFCs: RFC 8259 (JSON), RFC 6455 (WebSocket), RFC 7231 (HTTP HEAD)
- MS-* specs: MS-GPOL (Group Policy), MS-GPNP (Group Policy: Preferences Extension), MS-GPDPC (GPO Deployment), MS-ADMX (ADMX schema)
