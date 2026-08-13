---
title: "Migration & Coexistence — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Migration
tags: [spec, migration, coexistence, sidhistory, gpo-translation, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Migration & Coexistence — Technical Specification

## 1. Overview

The Migration capability covers the path from AD to the framework: sIDHistory migration via `DRSAddSidHistory` + time-limited passthrough + ACL rewrite plan, Kerberos cross-realm during parallel-run with per-SPN/per-user/per-host granularity, password hash migration, GPO translation via `admx2adrian` + `preg2adrian` with per-setting review workflow, DNS subdomain strategy, SYSVOL migration to SMB-served Git-backed policy share + HTTPS distribution + DFS-N referral, and auto-generated `capaths` + DNS SRV KDC discovery. The framework's migration story is parallel-run, not big-bang.

During the coexistence window (typically 30–180 days), the framework and AD run side-by-side with cross-realm Kerberos trust (per ADR-128) and LDAP referrals (per ADR-126). sIDHistory passthrough (ADR-126) preserves ACL continuity — the source-domain SID travels in the target user's `sIDHistory`, the source KDC preserves it in the PAC's `ExtraSids` array, and resources with ACLs referencing the source SID continue to grant access. The time-limited passthrough window (default 180 days, matching `tombstoneLifetime`) forces operators to plan ACL rewrites rather than leave sIDHistory as a permanent crutch — `adrian-cli migrate sidhistory audit` reports ACLs still referencing source SIDs as the window closes.

The capability carries 7 ADRs: ADR-068 (subdomain-per-directory DNS strategy), ADR-069 (cross-realm capaths + DNS SRV KDC discovery), ADR-126 (sIDHistory migration via DRSAddSidHistory), ADR-127 (GPO translation via admx2adrian + preg2adrian), ADR-128 (Kerberos cross-realm migration at 3 granularities), ADR-129 (password hash migration via ADMT-equivalent copy), ADR-130 (SYSVOL migration to Git-backed SMB share). It has zero individual blockers but defines the adoption path.

The capability is implemented as **three** Rust crates at Layer 4: `adrian-migrate` (migration tooling — sidhistory, passwords, parallel-run orchestrator), `adrian-gpo-translate` (`admx2adrian` + `preg2adrian` wrapper for GPO migration), `adrian-cli` (migration subcommands). External dependencies include `clap`, `tokio`, `serde`, `serde_json`, `ldap3`, `gss-api`, `reqwest`, `rand`, `tracing`, `quick-xml`, `plist`, `ini`, `tdb`.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-migrate` | 4 | Migration tooling: sidhistory (DRSAddSidHistory), passwords (ADMT-equivalent copy), parallel-run orchestrator, ACL rewrite planner | ADR-126, ADR-128, ADR-129 |
| `adrian-gpo-translate` | 4 | `admx2adrian` + `preg2adrian` wrapper; per-setting review workflow; coverage report | ADR-127 |
| `adrian-cli` (migration subcommands) | 4 | `adrian-cli migrate from-{sssd,winbind,pbis,dsconfigad,enterprise-connect,nomad,jamf-connect,centrify,admitmac,dave}`, `adrian-cli migrate sidhistory audit`, `adrian-cli migrate parallel-run --granularity {per-spn,per-user,per-host}`, `adrian-cli migrate passwords --source <dc>` | ADR-068, ADR-069, ADR-126, ADR-127, ADR-128, ADR-129, ADR-130 |
| `adrian-migrate` (cont.) | 4 | SYSVOL migration orchestrator: Git-backed policy share + HTTPS distribution + DFS-N referral | ADR-130 |
| `adrian-migrate` (cont.) | 4 | DNS subdomain setup: `ad.corp.example.com` for AD, `id.corp.example.com` for framework; auto-generated SRV records | ADR-068 |
| `adrian-migrate` (cont.) | 4 | Cross-realm capaths generation; auto-discover KDCs via DNS SRV | ADR-069 |

## 3. Key types and traits

```rust
// crates/adrian-migrate/src/lib.rs (per ADR-126, ADR-128, ADR-129)

use adrian_sid::Sid;
use uuid::Uuid;

pub struct Migrator {
    source_dc: String,                      // "dc01.ad.corp.example.com"
    target_dc: String,                      // "dc01.id.corp.example.com"
    source_realm: String,                   // "AD.CORP.EXAMPLE.COM"
    target_realm: String,                   // "ID.CORP.EXAMPLE.COM"
    config: MigrateConfig,
}

impl Migrator {
    /// sIDHistory migration via DRSAddSidHistory (per ADR-126).
    /// DRSUAPI opnum 20 — copies source-domain SID into target
    /// user's sIDHistory attribute. Time-limited passthrough window
    /// (default 180 days matching tombstoneLifetime).
    pub async fn migrate_sidhistory(
        &self, source_users: &[Uuid],     // source UUIDs to migrate
        passthrough_window_days: u32,
    ) -> Result<SidHistoryMigrationReport, MigrateError>;

    /// Password hash migration via ADMT-equivalent password copy
    /// (per ADR-129). Requires DCSync-equivalent source access.
    /// Three modes: ADMT copy, password-sync agent, password-reset-at-next-login.
    pub async fn migrate_passwords(
        &self, source_users: &[Uuid],
        mode: PasswordMigrationMode,
    ) -> Result<PasswordMigrationReport, MigrateError>;

    /// Kerberos cross-realm parallel-run orchestrator (per ADR-128).
    /// Three granularities: per-SPN (lowest-risk, slowest),
    /// per-user (medium), per-host (fastest, highest-risk).
    pub async fn parallel_run(
        &self, granularity: ParallelRunGranularity,
        spns: &[String], users: &[Uuid], hosts: &[String],
    ) -> Result<ParallelRunReport, MigrateError>;

    /// ACL rewrite plan generator (per ADR-126).
    /// Scans AD resources for ACLs referencing source-domain SIDs,
    /// produces report + script to rewrite to target SIDs.
    pub async fn plan_acl_rewrite(
        &self, source_sid: &Sid, target_sid: &Sid,
    ) -> Result<AclRewritePlan, MigrateError>;

    /// SYSVOL migration orchestrator (per ADR-130).
    /// Sets up SMB-served Git-backed policy share + HTTPS distribution
    /// + DFS-N referral during coexistence.
    pub async fn migrate_sysvol(
        &self, source_sysvol_path: &str,
    ) -> Result<SysvolMigrationReport, MigrateError>;
}

pub enum PasswordMigrationMode {
    AdmtCopy,                  // requires DCSync-equivalent source access
    PasswordSyncAgent,         // real-time sync during coexistence
    PasswordResetAtNextLogin,  // operationally painful, last resort
}

pub enum ParallelRunGranularity {
    PerSpn,    // lowest-risk, slowest — one SPN at a time
    PerUser,   // medium — one user's SPNs at a time
    PerHost,   // fastest, highest-risk — all SPNs on a host at once
}

pub struct SidHistoryMigrationReport {
    pub migrated_users: u32,
    pub failed_users: Vec<(Uuid, String)>,
    pub passthrough_window_ends: SystemTime,
    pub acl_rewrite_required: u32,           // ACLs still referencing source SIDs
}

pub struct AclRewritePlan {
    pub entries: Vec<AclRewriteEntry>,
    pub script: String,                      // PowerShell for AD, Rust for framework
    pub estimated_duration: Duration,
}

pub struct AclRewriteEntry {
    pub object_dn: String,
    pub source_sid: Sid,
    pub target_sid: Sid,
    pub ace_type: AceType,
    pub access_mask: u32,
}
```

```rust
// crates/adrian-gpo-translate/src/lib.rs (per ADR-127)

use adrian_policy_core::PolicyDoc;

pub struct GpoTranslator {
    admx_compiler: AdmxCompiler,             // from adrian-admx-compiler
    preg_reader: PregReader,                 // from adrian-policy-preg
    config: TranslateConfig,
}

impl GpoTranslator {
    /// Translate AD GPO to framework canonical JSON policy.
    /// Steps:
    ///   1. Parse ADMX/ADML → PolicyTemplate (admx2adrian)
    ///   2. Read Registry.pol → current values (preg2adrian)
    ///   3. Match Registry.pol values to PolicyTemplate settings
    ///   4. Generate PolicyDoc (canonical JSON)
    ///   5. Produce coverage report (per-setting review workflow)
    pub async fn translate_gpo(
        &self, gpo_guid: &str,               // {12345678-1234-...}
    ) -> Result<GpoTranslationResult, MigrateError>;
}

pub struct GpoTranslationResult {
    pub policy_doc: PolicyDoc,
    pub coverage_report: CoverageReport,
    pub unmapped_settings: Vec<UnmappedSetting>,
}

pub struct CoverageReport {
    pub total_settings: u32,
    pub mapped_settings: u32,
    pub unmapped_settings: u32,
    pub coverage_percent: f32,                // typically 75-85% per ADR-127
    pub requires_manual_review: u32,
}

pub struct UnmappedSetting {
    pub registry_path: String,               // HKLM\Software\... 
    pub registry_value: String,
    pub admx_policy_name: Option<String>,
    pub reason: UnmappedReason,
}

pub enum UnmappedReason {
    NoAdmxEntry,                              // not in any ADMX file
    CustomAdmxRequired,                       // ADMX exists but not in our compiler
    PlatformIncompatible,                     // Windows-only setting, no macOS/Linux equiv
    DeprecatedByMicrosoft,                    // ADMX marked deprecated
    RequiresManualTranslation,                // complex setting needing human review
}
```

```rust
// crates/adrian-migrate/src/dns_capaths.rs (per ADR-068, ADR-069)

pub struct DnsCapathsGenerator {
    source_subdomain: String,                // "ad.corp.example.com"
    target_subdomain: String,                // "id.corp.example.com"
}

impl DnsCapathsGenerator {
    /// Generate DNS subdomain records per ADR-068:
    ///   ad.corp.example.com  → SRV records for AD DCs
    ///   id.corp.example.com  → SRV records for framework DCs
    /// Avoids SRV-record collision during coexistence.
    pub fn generate_dns_records(&self) -> DnsRecords;

    /// Generate capaths file per ADR-69:
    ///   [capaths]
    ///   AD.CORP.EXAMPLE.COM = {
    ///       ID.CORP.EXAMPLE.COM = .
    ///   }
    ///   ID.CORP.EXAMPLE.COM = {
    ///       AD.CORP.EXAMPLE.COM = .
    ///   }
    pub fn generate_capaths(&self) -> String;

    /// Auto-discover KDCs via DNS SRV per ADR-069.
    /// _kerberos._tcp.<subdomain> SRV records.
    pub async fn discover_kdcs(&self, subdomain: &str) -> Result<Vec<String>, MigrateError>;
}
```

## 4. Data model

```
Migration data model — minimal FDB usage, mostly transient migration state.

FDB subspaces used (cross-referenced):

  (0x06, 0x01, user_uuid) → user_sid           — primary identity (per ADR-110)
  (0x06, 0x05, user_uuid) → source_sids        — sIDHistory from source domain
  (0x06, 0x06, source_sid) → user_uuid          — reverse lookup for ACL rewrite
  (0x01, dnt(user), ATT_SID_HISTORY, _)         — sIDHistory attribute (per ADR-126)
  (0x08, ts, event_id)                          — migration audit events

Per-migration state (SQLite at operator workstation):

  CREATE TABLE migration_runs (
    run_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    source_realm TEXT NOT NULL,
    target_realm TEXT NOT NULL,
    granularity TEXT,
    status TEXT NOT NULL                        -- 'in_progress' | 'completed' | 'failed'
  );

  CREATE TABLE sidhistory_migrations (
    user_uuid UUID PRIMARY KEY,
    source_sid TEXT NOT NULL,
    target_sid TEXT NOT NULL,
    passthrough_until TIMESTAMPTZ NOT NULL,
    acl_rewrite_status TEXT NOT NULL,           -- 'pending' | 'in_progress' | 'done'
    migrated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE password_migrations (
    user_uuid UUID PRIMARY KEY,
    mode TEXT NOT NULL,                         -- 'admt_copy' | 'sync_agent' | 'reset'
    migrated_at TIMESTAMPTZ NOT NULL,
    source_dc TEXT NOT NULL
  );

  CREATE TABLE parallel_run_state (
    spn TEXT,
    user_uuid UUID,
    host_fqdn TEXT,
    granularity TEXT NOT NULL,
    source_active BOOLEAN NOT NULL,             -- source KDC still authoritative
    target_active BOOLEAN NOT NULL,             -- target KDC authoritative
    cutover_at TIMESTAMPTZ,
    PRIMARY KEY (spn, user_uuid, host_fqdn)
  );

  CREATE TABLE gpo_translations (
    source_gpo_guid TEXT PRIMARY KEY,
    target_policy_uuid UUID NOT NULL,
    coverage_percent REAL NOT NULL,
    unmapped_settings_count INTEGER NOT NULL,
    translated_at TIMESTAMPTZ NOT NULL,
    reviewer TEXT,
    reviewed_at TIMESTAMPTZ
  );

  CREATE TABLE acl_rewrite_plan (
    object_dn TEXT NOT NULL,
    source_sid TEXT NOT NULL,
    target_sid TEXT NOT NULL,
    ace_type TEXT NOT NULL,
    access_mask INTEGER NOT NULL,
    rewrite_status TEXT NOT NULL,               -- 'planned' | 'applied' | 'verified'
    PRIMARY KEY (object_dn, source_sid, ace_type)
  );

DNS subdomain layout (per ADR-068):
  ad.corp.example.com     — AD DCs
    _kerberos._tcp.ad.corp.example.com  SRV 0 100 88 dc01.ad.corp.example.com
    _ldap._tcp.ad.corp.example.com      SRV 0 100 389 dc01.ad.corp.example.com
  id.corp.example.com     — Framework DCs
    _kerberos._tcp.id.corp.example.com  SRV 0 100 88 dc01.id.corp.example.com
    _ldap._tcp.id.corp.example.com      SRV 0 100 389 dc01.id.corp.example.com
  corp.example.com        — neutral zone; either subdomain authoritative
    DNS referral: query for dc01.corp.example.com returns CNAME to either
    ad.corp.example.com or id.corp.example.com depending on cutover state

capaths file (per ADR-069, [capaths] section of krb5.conf):
  [capaths]
    AD.CORP.EXAMPLE.COM = {
        ID.CORP.EXAMPLE.COM = .
    }
    ID.CORP.EXAMPLE.COM = {
        AD.CORP.EXAMPLE.COM = .
    }

  [domain_realm]
    .ad.corp.example.com = AD.CORP.EXAMPLE.COM
    .id.corp.example.com = ID.CORP.EXAMPLE.COM

sIDHistory passthrough (per ADR-126):
  Source AD user:
    CN=alice,DC=ad,DC=corp,DC=example,DC=com
    objectSid: S-1-5-21-<ad-domain>-<alice-rid>
  
  Target framework user (post-migration):
    CN=alice,DC=id,DC=corp,DC=example,DC=com
    objectSid: S-1-5-21-<framework-domain>-<alice-rid>
    sIDHistory: [S-1-5-21-<ad-domain>-<alice-rid>]   # source SID

  Source AD KDC issues TGT with:
    PAC.ExtraSids = [S-1-5-21-<framework-domain>-<alice-rid>]
  Target framework KDC issues TGT with:
    PAC.ExtraSids = [S-1-5-21-<ad-domain>-<alice-rid>]
  
  Resources on AD file server with ACL referencing source SID still grant
  access when target user presents TGT with matching ExtraSid.

  Time-limited passthrough window per ADR-126:
    Default 180 days matching tombstoneLifetime (per ADR-074)
    adrian-cli migrate sidhistory audit reports ACLs still referencing source SIDs
    Window close forces operators to plan ACL rewrite via plan_acl_rewrite()

SYSVOL migration (per ADR-130):
  Coexistence phase:
    \\corp.example.com\SYSVOL      → DFS-N referral to AD SYSVOL
    \\corp.example.com\NEW-SYSVOL  → Framework Git-backed policy share
  Cutover phase (per-OU):
    \\corp.example.com\SYSVOL      → DFS-N referral to framework share
    \\corp.example.com\AD-SYSVOL   → read-only AD SYSVOL (archive)
  HTTPS distribution (greenfield):
    https://policy.corp.example.com/sysvol/<domain>/Policies/...
    Used by framework-enrolled clients without SMB access

Parallel-run state machine (per ADR-128):
  State 1: SOURCE_ACTIVE — source KDC authoritative for SPN
  State 2: DUAL_ISSUE   — both KDCs issue tickets; SPN validates both
  State 3: TARGET_ACTIVE — target KDC authoritative; source KDC refuse
  State 4: SOURCE_DISABLED — source SPN removed

  Granularity controls how many SPNs transition simultaneously:
    per-spn:  one SPN at a time per state transition (safest)
    per-user: all of one user's SPNs at once (medium)
    per-host: all SPNs on one host at once (fastest, highest blast radius)
```

## 5. Protocol surface

```
Migration protocol surface — mostly CLI + DRSUAPI:

DRSUAPI protocol (per ADR-126, used for sIDHistory):
  RPC opnum 20: DRSAddSidHistory
    Input: target_dn, source_domain, source_sid
    Action: copies source_sid into target_dn's sIDHistory attribute
    Requires: DS-Replication-Get-Changes-All extended right on source
    Audited per ADR-122 (DCSync mitigation)
  
  RPC opnum 4: GetNCChanges (used for password hash copy via ADMT-equivalent)
    Action: replicate user object including ATT_UNICODE_PWD
    Requires: DCSync-equivalent access on source AD DC

Cross-realm Kerberos (per ADR-128, RFC 4120 §3.3.3):
  Cross-realm TGT referral:
    Client in AD.CORP requests service ticket for SPN in ID.CORP
    AD KDC returns referral TGT to ID.CORP (encrypted with cross-realm krbtgt key)
    Client presents referral TGT to ID.CORP KDC
    ID.CORP KDC validates cross-realm TGT, returns service ticket
  Transited field validation per RFC 4120 §3.3.3.1
  capaths file controls acceptable transited realms per ADR-069

LDAP referrals (per ADR-126):
  Framework LDAP server returns referral to AD LDAP when:
    - Query targets object in source-domain DN space
    - User authenticating has cross-realm TGT
  AD LDAP server returns referral to framework LDAP when:
    - Query targets object in target-domain DN space
    - User authenticating has cross-realm TGT

SYSVOL SMB protocol (per ADR-130):
  During coexistence:
    \\corp.example.com\SYSVOL      — DFS-N referral
    \\corp.example.com\NEW-SYSVOL  — framework share (adrian-smb-server)
                                       serving Git-backed policies per ADR-094
  During cutover:
    \\corp.example.com\SYSVOL      — framework share (adrian-smb-server)
    \\corp.example.com\AD-SYSVOL   — AD share (read-only archive)

CLI commands (per ADR-063):
  adrian-cli migrate sidhistory --source dc01.ad.corp.example.com \
                                --users @user-list.txt \
                                --passthrough-window-days 180
  adrian-cli migrate sidhistory audit --since-days 30
  adrian-cli migrate passwords --source dc01.ad.corp.example.com \
                              --mode admt-copy
  adrian-cli migrate parallel-run --granularity per-spn \
                                  --spns @spn-list.txt
  adrian-cli migrate parallel-run --granularity per-user \
                                  --users @user-list.txt
  adrian-cli migrate parallel-run --granularity per-host \
                                  --hosts @host-list.txt
  adrian-cli migrate plan-acl-rewrite --source-sid S-1-5-21-...-1234 \
                                      --target-sid S-1-5-21-...-1234
  adrian-cli migrate sysvol --source \\\\corp.example.com\\SYSVOL
  adrian-cli migrate gpo --source-gpo {12345678-...} --review
  adrian-cli migrate dns --source-subdomain ad.corp.example.com \
                         --target-subdomain id.corp.example.com
  adrian-cli migrate capaths --source AD.CORP.EXAMPLE.COM \
                             --target ID.CORP.EXAMPLE.COM \
                             --output /etc/krb5.conf.d/capaths.conf
  adrian-cli trust establish --peer ad --peer-realm AD.CORP.EXAMPLE.COM

GPO translation workflow (per ADR-127):
  1. adrian-cli migrate gpo --source-gpo {guid} --review
     - Parses GPO from source AD SYSVOL
     - Runs admx2adrian compiler on referenced ADMX files
     - Runs preg2adrian on Registry.pol files
     - Produces PolicyDoc + coverage report
  2. Operator reviews unmapped_settings list
     - 15-25% of settings typically unmapped per ADR-127
     - Each unmapped setting has a reason + manual translation guidance
  3. Operator commits PolicyDoc to Git per ADR-031
  4. Framework policy daemon applies per ADR-092
```

## 6. Configuration

```toml
# /etc/adrian/migrate.toml — Migration configuration

[migration]
source_realm            = "AD.CORP.EXAMPLE.COM"
target_realm            = "ID.CORP.EXAMPLE.COM"
source_dc               = "dc01.ad.corp.example.com"
target_dc               = "dc01.id.corp.example.com"
state_db_path           = "/var/lib/adrian/migrate_state.db"
audit_log_path          = "/var/log/adrian/migrate.log"

[sidhistory]                            # ADR-126
passthrough_window_days  = 180          # matches tombstoneLifetime per ADR-074
acl_rewrite_required     = true
audit_remaining_acls     = true
force_window_close       = false        # operator must explicitly close

[passwords]                             # ADR-129
default_mode             = "admt-copy"  # admt-copy | sync-agent | reset
sync_agent_port          = 0            # 0 = disabled, otherwise TCP port for sync agent
weak_password_policy     = "deny"       # deny | allow-with-warning

[parallel_run]                          # ADR-128
default_granularity      = "per-spn"    # per-spn | per-user | per-host
dual_issue_duration_secs = 3600         # how long both KDCs issue
state_transition_confirm = true         # operator confirmation per transition

[gpo_translation]                       # ADR-127
admx_compiler_strict     = true
include_microsoft_builtin_admx = true
custom_admx_dirs         = ["/etc/adrian/admx/custom"]
coverage_threshold_percent = 75         # below this, warn operator
require_manual_review    = true

[sysvol]                                # ADR-130
coexistence_share        = "\\\\corp.example.com\\NEW-SYSVOL"
ad_archive_share         = "\\\\corp.example.com\\AD-SYSVOL"
https_distribution_url   = "https://policy.corp.example.com/sysvol"
git_backed_repo_url      = "https://github.com/corp/adrian-policy.git"

[dns_capaths]                           # ADR-068, ADR-069
source_subdomain         = "ad.corp.example.com"
target_subdomain         = "id.corp.example.com"
capaths_output           = "/etc/krb5.conf.d/adrian-capaths.conf"
dns_server               = "10.0.0.53"
dns_ttl_secs             = 300

[trust]                                 # ADR-126, ADR-128
auto_generate_cross_realm = true
cross_realm_krbtgt_password_file = "/etc/adrian/cross-realm-key.pw"
trust_direction          = "bidirectional"  # bidirectional | inbound | outbound
transitive               = true
sidhistory_filtering     = true         # per ADR-124
selective_auth           = true         # per ADR-125

[audit]
otel_endpoint            = "http://otel-collector:4317"
emit_migration_events    = true
emit_acl_rewrite_events  = true
emit_parallel_run_transitions = true
mitre_attack_mapping     = true
```

## 7. Error handling

```rust
// crates/adrian-migrate/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("source DC {0} unreachable")]
    SourceUnreachable(String),
    #[error("source DRSUAPI bind failed: {0}")]
    DrsuapiBindFailed(String),
    #[error("DRSAddSidHistory failed for user {user}: {reason}")]
    AddSidHistoryFailed { user: Uuid, reason: String },
    #[error("DCSync-equivalent access denied on source DC; requires "
            "DS-Replication-Get-Changes-All extended right")]
    DcsyncAccessDenied,
    #[error("password migration failed for {user}: {reason}")]
    PasswordMigrationFailed { user: Uuid, reason: String },
    #[error("password weak — does not meet framework policy: {0}")]
    WeakPassword(String),
    #[error("parallel-run cutover failed for SPN {0}: source KDC still authoritative")]
    ParallelRunCutoverFailed(String),
    #[error("GPO translation coverage {percent}% below threshold {threshold}%")]
    GpoCoverageBelowThreshold { percent: f32, threshold: f32 },
    #[error("unmapped setting requires manual review: {0}")]
    UnmappedSettingRequiresReview(String),
    #[error("ACL rewrite failed for object {dn}: {reason}")]
    AclRewriteFailed { dn: String, reason: String },
    #[error("sIDHistory passthrough window expired for user {0}; ACL rewrite required")]
    PassthroughWindowExpired(Uuid),
    #[error("cross-realm trust establishment failed: {0}")]
    TrustEstablishmentFailed(String),
    #[error("DNS subdomain setup failed: {0}")]
    DnsSetupFailed(String),
    #[error("SYSVOL migration failed: {0}")]
    SysvolMigrationFailed(String),
    #[error("source GPO {0} not found in source AD")]
    SourceGpoNotFound(String),
    #[error("LDAP: {0}")]
    Ldap(#[from] ldap3::LdapError),
    #[error("storage layer: {0}")]
    Storage(#[from] DirectoryError),
}

// crates/adrian-gpo-translate/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum GpoTranslateError {
    #[error("GPO GUID {0} not found in source SYSVOL")]
    GpoNotFound(String),
    #[error("ADMX file {0} not found")]
    AdmxNotFound(String),
    #[error("Registry.pol parse failed: {0}")]
    PregParseFailed(String),
    #[error("coverage below threshold: {percent}% < {threshold}%")]
    CoverageBelowThreshold { percent: f32, threshold: f32 },
    #[error("admx2adrian: {0}")]
    AdmxCompile(#[from] AdmxError),
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
}
```

**Error propagation.** Migration errors surface via CLI exit codes + structured JSON output for programmatic consumption. Failed migrations are non-destructive — the source AD DC retains the user object until the migration is verified on the target. sIDHistory passthrough window expiration forces operator intervention via `adrian-cli migrate sidhistory audit`. Parallel-run cutover failures auto-rollback to `SOURCE_ACTIVE` state. ACL rewrite failures are logged with the object DN + source SID for manual retry. Every migration step emits OTel audit events with MITRE mapping (`T1078 Valid Accounts` for user migrations, `T1485 Data Destruction` for ACL rewrites).

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - DRSAddSidHistory call construction (mock DRSUAPI client)
    - Password migration: all 3 modes (admt-copy, sync-agent, reset)
    - Parallel-run state machine (SOURCE_ACTIVE → DUAL_ISSUE → TARGET_ACTIVE)
    - ACL rewrite plan generation
    - GPO translation: 10 sample GPOs with varying coverage
    - DNS subdomain record generation
    - capaths file generation
    - SYSVOL migration orchestrator

Integration tests — tests/integration/, real FDB + mock source AD
  Coverage:
    - sIDHistory migration end-to-end (mock source DC)
    - Password hash migration ADMT-copy mode
    - Parallel-run per-SPN granularity full lifecycle
    - GPO translation: real ADMX files from Microsoft built-in set
    - DNS subdomain setup against real DNS server (hickory)
    - capaths generation produces valid krb5.conf
    - Cross-realm trust establishment

Interop tests — tests/interop/
  Matrix:
    - Real Windows Server 2022 AD forest as source
    - Real Samba 4.20 AD as source (alternative)
    - FreeIPA 4.10 cross-realm trust as peer
    - Real AD SYSVOL with customer GPOs (anonymized samples)
    - Real AD DNS zone for subdomain migration
    - Real Windows 10/11 clients parallel-running both AD and framework
    - Real macOS 13+ clients parallel-running both
    - Real Linux RHEL 9 clients parallel-running both
    - mimikatz attack during parallel-run (verify no auth bypass)
    - Impacket DCSync against source AD (audited per ADR-122)

Property-based tests — proptest
  Tested:
    - sIDHistory blob round-trips
    - AclRewritePlan serialization round-trips
    - capaths file round-trips
    - DNS records round-trips
    - PolicyDoc round-trips (already covered in Policy Engine spec)
  Corpus: 40+ property tests across migration crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-126: sIDHistory migration via DRSAddSidHistory with
             time-limited passthrough window (180 days)
  - ADR-128: cross-realm Kerberos trust establishment
  - ADR-129: password hash migration via ADMT-equivalent copy
  - ADR-068: DNS subdomain strategy for migration
  - ADR-069: capaths auto-generation + DNS SRV KDC discovery
  - ADR-127: basic admx2adrian + preg2adrian with coverage report
  - ADR-130: SYSVOL migration (Git-backed + DFS-N referral)

v1 (Phase 2):
  - ADR-128: per-SPN / per-user / per-host parallel-run granularities
              with state machine
  - ADR-127: per-setting review workflow with coverage threshold enforcement
  - ACL rewrite plan generator + apply script
  - adrian-cli migrate from-{sssd,winbind,pbis,dsconfigad,
             enterprise-connect,nomad,jamf-connect,centrify,admitmac,dave}
              (shared with Cross-Platform Parity)
  - SYSVOL HTTPS distribution as greenfield alternative
  - Password-sync agent mode (real-time during coexistence)

v2 (Phase 3):
  - Claims-based migration for Server 2012+ forest functional level
    (replaces sIDHistory entirely for new migrations)
  - Automated cutover orchestration with rollback safety
  - Multi-forest migration topology planner
  - Predictive ACL rewrite prioritization (hot vs cold paths)
  - Migration cost estimator (person-hours, downtime window)
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4 | CLI argument parsing |
| `tokio` | 1 | Async runtime |
| `serde` / `serde_json` | 1 | State DB + report serialization |
| `ldap3` | 0.11 | LDAP client for source AD queries |
| `gss-api` | 0.1 | GSSAPI for cross-realm Kerberos |
| `reqwest` | 0.12 | HTTPS distribution for SYSVOL |
| `rand` | 0.8 | Random cross-realm krbtgt passwords |
| `tracing` | 0.1 | Structured logging |
| `quick-xml` | 0.31 | ADMX/ADML parsing |
| `plist` | 1.6 | macOS plist (legacy agent migration) |
| `rust-ini` | 0.21 | INI parsing (krb5.conf, sssd.conf) |
| `tdb` | 0.1 | TDB parser (Samba legacy config migration) |
| `rusqlite` | 0.31 | Migration state DB |
| `uuid` | 1.10 | UUIDs for users, runs |
| `chrono` | 0.4 | Timestamps |
| `thiserror` | 1 | MigrateError + GpoTranslateError enums |
| `anyhow` | 1 | Top-level error in binary entry points |
| `opentelemetry` | 0.24 | OTel audit events |
| `proptest` | 1 | Property-based tests |
| `adrian-storage-fdb` | * | FDB for cross-references |
| `adrian-identity-fdb` | * | IdentityMapping for sIDHistory storage |
| `adrian-policy-core` | * | PolicyDoc type (GPO translation) |
| `adrian-admx-compiler` | * | admx2adrian compiler |
| `adrian-policy-preg` | * | preg2adrian adapter |
| `adrian-drsuapi` | * | DRSUAPI client (for DRSAddSidHistory, DCSync-equivalent) |
| `adrian-cli` | * | Shared CLI framework |

## 11. References

- ADRs: [ADR-068](../adr/ADR-068-subdomain-dns-strategy.md), [ADR-069](../adr/ADR-069-cross-realm-capaths.md), [ADR-074](../adr/ADR-074-tombstone-lifetime-lingering-objects.md), [ADR-094](../adr/ADR-094-sysvol-replication-git-backed.md), [ADR-110](../adr/ADR-110-sid-to-uid-mapping-uuid-primary.md), [ADR-122](../adr/ADR-122-dcsync-mitigation.md), [ADR-124](../adr/ADR-124-sidhistory-injection-mitigation.md), [ADR-125](../adr/ADR-125-selective-authentication-hbac.md), [ADR-126](../adr/ADR-126-sidhistory-migration.md), [ADR-127](../adr/ADR-127-gpo-translation.md), [ADR-128](../adr/ADR-128-kerberos-cross-realm-migration.md), [ADR-129](../adr/ADR-129-password-hash-migration.md), [ADR-130](../adr/ADR-130-sysvol-migration.md)
- Workshop decisions: [Decision 1 — Replication Protocol](../workshop/decision-01-replication-protocol.md) (parallel-run baseline), [Decision 3 — Identity Model](../workshop/decision-03-identity-model.md) (sIDHistory handling)
- KB files: [catalog/12-migration-and-coexistence.md](../catalog/12-migration-and-coexistence.md), [docs/03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md), [docs/09-linux-equivalents/06-realmd-join-flow.md](../docs/09-linux-equivalents/06-realmd-join-flow.md), [docs/09-linux-equivalents/05-samba-tool-net-ads.md](../docs/09-linux-equivalents/05-samba-tool-net-ads.md), [docs/11-code-examples/05-python-impacket-examples.md](../docs/11-code-examples/05-python-impacket-examples.md)
- RFCs: RFC 4120 (Kerberos), RFC 4120 §3.3.3 (Cross-Realm TGT Referral), RFC 4511 (LDAP, for referrals)
- MS-* specs: MS-DRSR (DRSUAPI — DRSAddSidHistory opnum 20, GetNCChanges opnum 4), MS-ADTS (sIDHistory, trust objects, forest functional levels), MS-GPOL (GPO structure for translation), MS-DFSN (DFS-N referral during SYSVOL migration)
- AD Migration: Microsoft ADMT (Active Directory Migration Tool) documentation, Microsoft "Migrate Active Directory to new domain" guide
