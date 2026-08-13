---
title: "Security & Threat Model — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Security
tags: [spec, security, threat-model, kerberoasting, golden-ticket, dcsync, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Security & Threat Model — Technical Specification

## 1. Overview

The Security capability makes the framework's threat mitigations explicit and on-by-default rather than opt-in via GPO. It covers Kerberoasting mitigation (AES-only migration + detection), golden ticket mitigation (HSM-bound krbtgt + auto-rotation), silver ticket mitigation (mandatory `PAC_BUFFER_TICKET_CHECKSUM`), DCSync mitigation (per-principal audit + HSM-bound break-glass), sIDHistory abuse mitigation (per-trust filtering), AdminSDHolder replacement (declarative RBAC), selective authentication (FreeIPA HBAC-style), and supply-chain security (Sigstore + in-toto). The capability is what differentiates the framework from AD: in AD, every one of these mitigations is a separate GPO that operators forget to enable; in the framework, every one is a structural default.

The capability carries 8 ADRs: ADR-064 (Kerberoasting AES-only migration + detection), ADR-065 (krbtgt HSM + auto-rotation for golden-ticket mitigation), ADR-066 (AdminSDHolder → declarative RBAC), ADR-067 (Sigstore + in-toto supply chain), ADR-122 (DCSync mitigation), ADR-123 (silver ticket mitigation), ADR-124 (sIDHistory injection mitigation), ADR-125 (selective authentication HBAC). It resolves three of the framework's 23 blockers (PC-116 Kerberoasting, PC-117 DCSync, PC-118 golden ticket) plus two high-severity problems.

Native Raft mode (per Decision 1) eliminates DCSync entirely — there is no `EXOP_REPL_SECRETS` opnum to call. AD-interop mode inherits the DCSync attack surface, mitigated by per-principal audit (every `DS-Replication-Get-Changes-All` invocation emits a 4662-equivalent event with the caller's identity, target NC head, and `ulExtendedOp` value) and HSM-bound break-glass (full-sync operations require an HSM-resident quorum key, not just the directory-level extended right). The HSM-bound krbtgt (ADR-065) closes the golden-ticket window — an attacker who exfiltrates the directory cannot forge TGTs because the krbtgt key never leaves the HSM.

The capability is implemented as **three** Rust crates shared across the framework: `adrian-pac-validator` (unified PAC validator), `adrian-monitor` (audit event ingestion + threat detection rules), `adrian-policy-core` (declarative RBAC templates, per ADR-066). External dependencies include `sigstore`, `cosign`, `in-toto`, `ring`, `rasn`, `rasn-kerberos`, `cryptoki`, `tracing`, `opentelemetry`, `prometheus`.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-pac-validator` | 2 | Unified PAC validator (libframework_pac_validator.dylib); local Ed25519 signature verification + legacy RPC fallback; mandatory `PAC_BUFFER_TICKET_CHECKSUM` (0x0E) + `PAC_FULL_CHECKSUM` (0x13) | ADR-064, ADR-065, ADR-082, ADR-083, ADR-123, ADR-117 |
| `adrian-monitor` | 4 | Threat detection rules engine: Kerberoasting detection (etype 0x17 alerting), DCSync detection (4662 audit), golden ticket detection (krbtgt key version mismatch), NTLM usage alerting | ADR-064, ADR-122, ADR-065 |
| `adrian-policy-core` | 2 | Declarative RBAC templates per ADR-066 (replaces AdminSDHolder); role definitions + binding + SDPROP-equivalent enforcement | ADR-066, ADR-125 |
| `adrian-cli` (security subcommands) | 4 | `adrian-cli audit-ntlm`, `adrian-cli threat report`, `adrian-cli sidhistory audit` | ADR-064, ADR-122, ADR-124, ADR-125 |
| Sigstore / in-toto integration | 4 | Build-time cosign sign + in-toto attestation; deploy-time cosign verify | ADR-067 |
| `adrian-hsm` | 2 | Shared with Cert Service; 5 HSM-bound keys: krbtgt, KDS, CA, KRA, token-signing | ADR-015, ADR-020, ADR-065 |

## 3. Key types and traits

```rust
// crates/adrian-pac-validator/src/lib.rs (per ADR-083, ADR-123)

use adrian_sid::Sid;
use rasn_kerberos::KerberosTime;

/// Unified PAC validator. Called by every service that consumes
/// Kerberos tickets: adrian-smb-server, adrian-ldap-server, etc.
#[async_trait]
pub trait PacValidator: Send + Sync {
    async fn validate(
        &self,
        ticket: &ServiceTicket,
        pac: &Pac,
        opts: ValidateOpts,
    ) -> Result<ValidationReport, PacError>;
}

pub struct ValidateOpts {
    pub require_full_checksum: bool,        // ADR-082 0x13 mandatory KDC-side
    pub require_ticket_checksum: bool,      // ADR-123 0x0E mandatory for service tickets
    pub legacy_rpc_fallback: bool,          // false in native mode, true in AD-interop
    pub max_age_secs: u64,                  // reject tickets older than this
    pub check_sidhistory_filtering: bool,   // ADR-124 per-trust filtering
    pub allowed_sidhistory_sids: Vec<Sid>,  // explicit allowlist per trust
}

pub struct ValidationReport {
    pub outcome: ValidationOutcome,
    pub checks: Vec<CheckResult>,
    pub principal_sid: Sid,
    pub detected_sidhistory: Vec<Sid>,
    pub mitre_attack_techniques: Vec<&'static str>,
}

pub enum ValidationOutcome { Valid, Invalid(PacError), Audit }

pub struct CheckResult {
    pub name: &'static str,                  // "server_checksum", "ticket_checksum", etc.
    pub passed: bool,
    pub duration_micros: u64,
    pub detail: Option<String>,
}

pub struct LocalValidator {
    krbtgt_public_key: Ed25519PublicKey,    // HSM-derived; rotated with krbtgt key per ADR-015
    kdc_key_handle: Arc<dyn Signer>,
    config: ValidatorConfig,
}

pub struct LegacyRpcValidator {              // AD-interop fallback per ADR-083
    partner_dcs: Vec<String>,
    timeout: Duration,
}

impl PacValidator for LocalValidator { /* ... */ }
impl PacValidator for LegacyRpcValidator { /* ... */ }
```

```rust
// crates/adrian-monitor/src/threat_detection.rs (per ADR-064, ADR-122, ADR-065)

use adrian_audit::AuditEvent;

/// Threat detection rules engine. Consumes audit events from the
/// audit log + emits alerts when patterns match.
pub struct ThreatDetectionEngine {
    rules: Vec<ThreatRule>,
    alert_sink: Arc<dyn AlertSink>,
    state: DashMap<String, RuleState>,
}

impl ThreatDetectionEngine {
    pub async fn process(&self, event: &AuditEvent) -> Result<(), ThreatError>;
}

pub struct ThreatRule {
    pub name: &'static str,
    pub mitre_technique: &'static str,
    pub description: &'static str,
    pub matcher: ThreatMatcher,
    pub alert_severity: AlertSeverity,
    pub window_secs: u64,                    // for rate-based rules
    pub threshold: u32,
}

pub enum ThreatMatcher {
    /// Kerberoasting — TGS-REQ with etype 0x17 (RC4) per ADR-064
    Kerberoasting { min_etype_17_events: u32, window_secs: u64 },

    /// Golden ticket — TGT with krbtgt key version > current + previous
    /// (per ADR-065 rotation overlap) per ADR-065
    GoldenTicket { krbtgt_current_kvno: u32, krbtgt_previous_kvno: u32 },

    /// DCSync — DS-Replication-Get-Changes-All invocation per ADR-122
    Dcsync { expected_callers: Vec<Sid> },

    /// Silver ticket — service ticket validation failure with
    /// PAC_BUFFER_TICKET_CHECKSUM mismatch per ADR-123
    SilverTicket { failures_threshold: u32, window_secs: u64 },

    /// NTLM relay — unexpected NTLM usage at framework services per ADR-085
    NtlmRelay { allowlist_services: Vec<String> },

    /// sIDHistory injection — service ticket with sIDHistory entry
    /// not in allowed list per ADR-124
    SidHistoryInjection { allowed_sids_per_trust: HashMap<String, Vec<Sid>> },

    /// Pass-the-hash — NTLM auth with hash not in platform-secure
    /// credential store (per ADR-086 layer 3)
    PassTheHash { expected_store: String },

    /// AdminSDHolder drift — RBAC template violation per ADR-066
    AdminSdHolderDrift { rbac_template: String },

    /// LDAP signing bypass — unsigned LDAP bind attempt per ADR-021
    LdapSigningBypass,

    /// LDAP channel binding bypass — missing CB per ADR-021
    LdapChannelBindingBypass,

    /// Pass-the-ticket — ticket used from unusual source IP per ADR-088
    PassTheTicket { geo_baseline: HashMap<String, Vec<IpRange>> },
}

pub enum AlertSeverity { Info, Warning, High, Critical }
```

```rust
// crates/adrian-policy-core/src/rbac.rs (per ADR-066, ADR-125)

use adrian_sid::Sid;

/// Declarative RBAC templates — replaces AdminSDHolder + SDPROP.
/// No 60-minute reset overriding delegated permissions.
pub struct RbacTemplate {
    pub name: String,                        // "Tier-0-Admins", "Tier-1-Server-Admins", etc.
    pub version: u32,
    pub members: Vec<Sid>,                   // protected group members
    pub permitted_sids_on_protected_objects: Vec<Sid>,
    pub denied_sids_on_protected_objects: Vec<Sid>,
    pub protected_containers: Vec<String>,   // CN=AdminSDHolder,CN=System,... equivalents
    pub enforcement_mode: EnforcementMode,
}

pub enum EnforcementMode { Audit, Enforce }

/// Selective authentication (HBAC-style per ADR-125).
/// Per-trust policy: which SIDs from trusted forest may authenticate
/// to which framework hosts.
pub struct SelectiveAuthPolicy {
    pub trust_peer: String,                  // trusted realm
    pub allowed_principals: Vec<HbacRule>,
    pub default_policy: DefaultPolicy,       // Allow | Deny
}

pub struct HbacRule {
    pub principal_pattern: String,           // glob, e.g. "*@IPA.EXAMPLE.COM"
    pub host_pattern: String,                // glob, e.g. "build-*"
    pub service_pattern: String,             // glob, e.g. "ssh-*"
    pub action: HbacAction,                  // Allow | Deny
}

pub enum HbacAction { Allow, Deny }
pub enum DefaultPolicy { Allow, Deny }
```

```rust
// crates/adrian-cli/src/security.rs (per ADR-064, ADR-122, ADR-124)

pub enum SecurityCommand {
    /// Audit NTLM usage in the last N hours
    AuditNtlm { since_hours: u32 },
    /// Generate threat report (Kerberoasting, DCSync, golden ticket, etc.)
    ThreatReport { since_hours: u32, format: ReportFormat },
    /// Audit sIDHistory entries still in use (per ADR-124)
    SidHistoryAudit { since_days: u32 },
    /// Verify supply-chain signatures on framework binaries (per ADR-067)
    VerifySupplyChain { binary_path: PathBuf },
    /// Generate RBAC drift report (per ADR-066)
    RbacDriftReport { template: String },
    /// Show selective auth HBAC evaluation for principal+host (per ADR-125)
    HbacEvaluate { principal: String, host: String, service: String },
}
```

## 4. Data model

```
Security data model:

FDB subspaces used:
  (0x08, ts, event_id) → audit events (per ADR-060)
  (0x0A, artifact_hash[0..32]) → sigstore bundles (per ADR-067)

  (0x01, dnt(user), ATT_KRB_NO_AUTH_DATA_REQUIRED, _)
    → flag: PAC generation skipped for this principal (rare; service accounts)

  (0x01, dnt(user), ATT_MS_DS_ALLOWED_TO_ACT_ON_BEHALF_OF_OTHER_IDENTITY, _)
    → RBCD ACL per ADR-087 (security-sensitive)

  (0x01, dnt(krbtgt), ATT_SUPPLEMENTAL_CREDENTIALS, _)
    → krbtgt key material (HSM-bound, never persisted plaintext)

  (0x01, dnt(trust), ATT_TRUST_ATTRIBUTES, _)
    → trust attributes including FILTER_SIDS flag per ADR-124

  (0x01, dnt(trust), ATT_SECURITY_IDENTIFIER, _)
    → trusted forest's SID for filtering

HSM-bound key registry (in-memory, refreshed from HSM):
  struct HsmBoundKeyRegistry {
    keys: DashMap<KeyLabel, HsmKeyHandle>,
  }
  // 5 HSM-bound keys per ADR-065/037/015/020/067:
  //   - krbtgt           (per ADR-015, 30-day rotation per ADR-065)
  //   - KDS root key      (per ADR-020, gMSA)
  //   - CA signing        (per ADR-037, two-tier CA)
  //   - KRA recovery      (per ADR-032, Shamir M-of-N)
  //   - OCSP signing      (per ADR-033, delegated issuance)
  //   - PEK               (per ADR-086, AD-interop NT hash at-rest encryption)
  //   - token-signing     (per ADR-100, federation shim)

Threat detection rule state (per-rule in-memory):
  Kerberoasting:
    state: { window_start: SystemTime, etype_17_count: u32,
             top_principals: Vec<(String, u32)> }
  GoldenTicket:
    state: { current_kvno: u32, previous_kvno: u32,
             rotation_due: SystemTime }
  DCSync:
    state: { expected_callers: Vec<Sid>, recent_invocations:
             Vec<(SystemTime, Sid, String /*nc_head*/)> }
  SilverTicket:
    state: { window_start: SystemTime, failure_count_per_service:
             HashMap<String, u32> }
  NTLM relay:
    state: { allowlist_services: Vec<String>,
             recent_attempts: Vec<(SystemTime, String, IpAddr)> }
  sIDHistory injection:
    state: { allowed_sids_per_trust: HashMap<String, Vec<Sid>>,
             recent_injections: Vec<(SystemTime, Sid, Sid)> }
  Pass-the-hash:
    state: { recent_hashes: Vec<(SystemTime, String /*upn*/,
             [u8; 16] /*hash*/, String /*store_origin*/)> }
  AdminSDHolder drift:
    state: { rbac_template_version: u32, last_enforcement: SystemTime }

RBAC template storage (per ADR-066):
  GitOps: repos/adrian-rbac.git/
    templates/
      tier-0-admins.yaml
      tier-1-server-admins.yaml
      tier-2-workstation-admins.yaml
      ...
  Operator applies templates; framework enforces via SDPROP-equivalent
  job that runs every 60 seconds (vs AD's 60-minute cycle).

Sigstore / in-toto storage (per ADR-067):
  - Build time: cosign sign --key <kms> adrian-dc:1.0.0
                in-toto attestation with build provenance (SLSA L3)
  - Rekor (transparency log): entries stored at rekor.sigstore.dev
  - Deploy time: operator calls cosign verify --key <kms>
                adrian-dc:1.0.0 before deploying
  - Verify records: stored in FDB (0x0A, artifact_hash) → sigstore_bundle
```

## 5. Protocol surface

```
Security protocol surface — mostly internal API + CLI:

PAC validation API (per ADR-083, ADR-123):
  // Called by every service that consumes Kerberos tickets:
  adrian_pac_validator::validate(ticket, pac, opts) -> ValidationReport
  // Internal, not wire protocol.

  // Legacy RPC fallback (AD-interop):
  NetrLogonSamLogonEx (MS-NRPC opnum 45) — server-side PAC validation
  Called by services that opt in to legacy AD-interop path.

Threat detection API (per ADR-064, ADR-122):
  adrian_monitor::process(event) — async, internal API
  Alert sink emits via OTel log events + Webhook to SOC

CLI security commands (per ADR-063):
  adrian-cli audit-ntlm --since-hours 24
    Output: table of NTLM auth events with principal, source, service
  adrian-cli threat report --since-hours 168 --format json
    Output: JSON report of all threat detections in last 7 days
  adrian-cli sidhistory audit --since-days 30
    Output: sIDHistory entries still referenced in ACLs (per ADR-124)
  adrian-cli verify-supply-chain --binary /usr/bin/adrian-dc
    Output: Sigstore + in-toto verification result
  adrian-cli rbac drift-report --template tier-0-admins
    Output: principals that have drifted from RBAC template
  adrian-cli hbac evaluate --principal alice@CORP --host build-01 --service ssh
    Output: Allow / Deny + matching rule

Audit event emission (per ADR-060):
  OTel log events to OTLP endpoint (gRPC 4317 / HTTP 4318)
  Event attributes include:
    event.id                — Windows-equivalent event ID (4624, 4769, etc.)
    event.outcome           — success | failure | audit | alert
    principal.upn           — the principal involved
    principal.sid
    target.dn               — for directory operations
    target.service          — for TGS-REQ
    auth.logon_type
    auth.etype              — for Kerberos
    source.ip
    source.port
    mitre.attack.technique  — e.g. "T1558.001"
    mitre.attack.tactic     — e.g. "Credential Access"

Supply chain verification (per ADR-067):
  Build time:
    cosign sign --key kms://<key-id> adrian-dc:1.0.0
    in-toto attestation with SLSA L3 provenance
    Rekor entry created at rekor.sigstore.dev
  Deploy time:
    operator calls cosign verify before pulling image
    in-toto attestation verified against policy
    On failure: operator refuses to deploy + alerts

RBAC enforcement (per ADR-066):
  SDPROP-equivalent job runs every 60 seconds (vs AD's 60 minutes):
    1. For each RBAC template, list protected containers
    2. For each protected object, query current SD
    3. Compute expected SD from template (members + permitted_sids)
    4. If current != expected, rewrite SD in FDB transaction
    5. Emit audit event 4719-equivalent (audit policy change)
  Strict mode: enforcement_mode = Enforce (default)
  Audit mode: enforcement_mode = Audit (alerts but no rewrite)

Selective authentication (per ADR-125):
  PAM auth flow (Linux):
    1. pam_adrian.so calls AdrianClient.auth().validate_token()
    2. SDK checks HBAC policy for (principal, host, service)
    3. If no Allow rule matches and default=Deny, reject
    4. Emit audit event 4625-equivalent with reason "hbac_deny"
  LSA auth flow (Windows): adrianlsa.dll calls same SDK
  OpenDirectory auth flow (macOS): AdrianOpenDirectory.bundle calls same SDK
```

## 6. Configuration

```toml
# /etc/adrian/security.toml — Security configuration

[pac_validation]                        # ADR-083, ADR-123
local_validator_enabled = true
legacy_rpc_fallback     = false         # false in native mode
require_full_checksum   = true          # ADR-082 0x13
require_ticket_checksum = true          # ADR-123 0x0E (silver-ticket mitigation)
max_age_secs            = 600

[threat_detection]                      # ADR-064, ADR-122, ADR-065
enabled                 = true
kerberoasting_detection = true
kerberoasting_threshold = 5             # etype 0x17 events in 5 min
kerberoasting_window_secs = 300
golden_ticket_detection = true
dcsync_detection        = true
silver_ticket_detection = true
silver_ticket_failure_threshold = 10
ntlm_relay_detection    = true
sidhistory_injection_detection = true   # ADR-124
pass_the_hash_detection = true
adminsdholder_drift_detection = true    # ADR-066
ldap_signing_bypass_detection = true    # ADR-021
ldap_channel_binding_bypass_detection = true

alert_webhook_url       = "https://soc.corp.example.com/api/alerts"
alert_min_severity      = "warning"

[rbac]                                  # ADR-066
enabled                 = true
templates_repo_url      = "https://github.com/corp/adrian-rbac.git"
enforcement_mode        = "enforce"     # enforce | audit
enforcement_interval_secs = 60          # vs AD's 60 minutes

[selective_auth]                        # ADR-125
enabled                 = true
default_policy          = "deny"        # deny | allow
freeipa_hbac_sync       = false         # set true when FreeIPA peer (ADR-115)

[sidhistory_filtering]                  # ADR-124
within_forest_filtering  = true         # ON by default (vs AD's OFF)
cross_forest_filtering   = true
allowed_sids_per_trust  = "rbac/templates/sidhistory-allowlist.yaml"

[hsm_keys]                              # ADR-015, ADR-020, ADR-032, ADR-037, ADR-065
krbtgt_rotation_days    = 30            # ADR-015
krbtgt_overlap_hours    = 24            # ADR-015
kds_root_rotation_days  = 30
pek_rotation_days       = 90
audit_key_use           = true

[supply_chain]                          # ADR-067
sigstore_signing        = true
in_toto_attestations    = true
verify_at_deploy_time   = true
rekor_transparency_log  = "https://rekor.sigstore.dev"
slsa_level              = 3

[audit]                                 # ADR-060
otel_log_endpoint       = "http://otel-collector:4317"
fdb_hot_tier_days       = 7
mitre_attack_mapping    = true
```

## 7. Error handling

```rust
// crates/adrian-pac-validator/src/error.rs (already in spec 02, repeated here)
#[derive(Debug, thiserror::Error)]
pub enum PacError {
    #[error("PAC server_checksum invalid")]
    ServerChecksumInvalid,
    #[error("PAC kdc_checksum invalid (golden-ticket suspect)")]
    KdcChecksumInvalid,
    #[error("PAC full_checksum invalid (per ADR-082 0x13 buffer)")]
    FullChecksumInvalid,
    #[error("PAC ticket_checksum invalid (silver-ticket suspect, per ADR-123)")]
    TicketChecksumInvalid,
    #[error("PAC requestor field mismatch")]
    RequestorMismatch,
    #[error("PAC expired: issued {issued:?}, max age {max_age_secs}s")]
    Expired { issued: SystemTime, max_age_secs: u64 },
    #[error("PAC logon_info malformed: {0}")]
    LogonInfoMalformed(String),
    #[error("PAC group SID contains sIDHistory entry blocked by trust policy (ADR-124)")]
    BlockedSidHistory,
    #[error("PAC validation RPC to {partner} failed: {reason}")]
    ValidationRpcFailed { partner: String, reason: String },
}

// crates/adrian-monitor/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum ThreatError {
    #[error("alert sink unavailable: {0}")]
    AlertSinkUnavailable(String),
    #[error("rule state corruption: {0}")]
    RuleStateCorrupted(String),
    #[error("audit event malformed: {0}")]
    AuditEventMalformed(String),
    #[error("window state lost for rule {0}; resetting")]
    WindowStateLost(String),
}

// crates/adrian-policy-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("RBAC template {0} not found in Git repo")]
    TemplateNotFound(String),
    #[error("RBAC template version conflict: expected {expected}, got {actual}")]
    TemplateVersionConflict { expected: u32, actual: u32 },
    #[error("RBAC enforcement failed for {object}: {reason}")]
    EnforcementFailed { object: String, reason: String },
    #[error("RBAC drift detected: {count} objects diverge from template {template}")]
    DriftDetected { count: u32, template: String },
}
```

**Error propagation.** PAC validation failures block the auth attempt with `AuthFailed` (mapped to `STATUS_LOGON_FAILURE` on Windows, `PAM_AUTH_ERR` on Linux, OpenDirectory error on macOS). Every PAC validation failure emits an OTel audit event with MITRE mapping (`T1558.001 Golden Ticket`, `T1558.003 Kerberoasting`, `T1558.004 Silver Ticket`). Threat detection alerts propagate via webhook to SOC; Critical-severity alerts page on-call immediately. RBAC drift reports surface via `adrian-cli rbac drift-report` and via OTel audit events. Supply-chain verification failures block deployment with operator error. sIDHistory injection attempts (per ADR-124) are logged with `BlockedSidHistory` and trigger the per-trust filtering alert.

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - Local PAC validator: all 9 buffer types verified
    - Local PAC validator: krbtgt key rotation overlap (current + previous)
    - Local PAC validator: Ed25519 signature verify (mock HSM)
    - Legacy RPC validator: partner failover
    - Threat rules: Kerberoasting detection (5 events in 5 min triggers)
    - Threat rules: Golden ticket detection (kvno > previous)
    - Threat rules: DCSync detection (unexpected caller SID)
    - Threat rules: Silver ticket detection (10 failures/service in 5 min)
    - Threat rules: sIDHistory injection (untrusted SID in PAC)
    - RBAC templates: parse + enforce + drift detection
    - HBAC policy: pattern matching + default policy
    - Sigstore verification (mock cosign binary)
    - in-toto attestation verification (mock attestation file)

Integration tests — tests/integration/, real FDB + HSM mock + tokio
  Coverage:
    - Full PAC validation flow (KDC issues → service validates)
    - krbtgt rotation: TGT issued with current key, validated
      after rotation with previous key (overlap window)
    - PAC_BUFFER_TICKET_CHECKSUM rejection (silver ticket forged
      without 0x0E buffer)
    - sIDHistory filtering (PAC with blocked sIDHistory rejected)
    - Threat detection: synthetic Kerberoasting pattern triggers alert
    - RBAC drift: manually diverge SD, enforcement rewrites it
    - HBAC: deny principal that has no Allow rule, default=Deny
    - Supply chain: cosign verify on signed image passes, on
      tampered image fails

Interop tests — tests/interop/
  Matrix:
    - Real Sigstore + Rekor in test environment
    - Mimikatz golden ticket attack against framework KDC (rejected)
    - Impacket Kerberoasting against framework KDC (audited + alerted)
    - Impacket DCSync against framework DC in AD-interop mode (audited)
    - sIDHistory injection attack from compromised child domain (rejected)
    - Pass-the-hash attack against framework LDAP (rejected, NTLM disabled)
    - Splunk SIEM ingests OTel audit events + alerts trigger
    - Elastic SIEM ingests OTel audit events + alerts trigger

Property-based tests — proptest
  Tested:
    - PAC buffer round-trips (all 9 types)
    - Threat rule matchers round-trips
    - RBAC template YAML round-trips
    - HBAC rule round-trips
  Corpus: 50+ property tests across security crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-011: AES-only default (Kerberoasting structural mitigation)
  - ADR-064: Kerberoasting detection (etype 0x17 alerting)
  - ADR-015: HSM-bound krbtgt with 30-day rotation (golden-ticket structural)
  - ADR-065: golden ticket detection (kvno mismatch alerting)
  - ADR-122: DCSync mitigation — per-principal audit (4662-equivalent)
              + HSM-bound break-glass
  - ADR-123: PAC_BUFFER_TICKET_CHECKSUM mandatory KDC-side +
             default service-side validation (silver-ticket mitigation)
  - ADR-124: sIDHistory filtering default ON within forest trusts
  - ADR-067: Sigstore + in-toto build-time signing
  - ADR-083: PAC validation local path (Ed25519 via HSM-derived krbtgt pubkey)

v1 (Phase 2):
  - Full Kerberoasting detection with service-account migration tracker
  - Silver-ticket default service-side validation (all services opt-in)
  - ADR-066: AdminSDHolder replacement with declarative RBAC templates
  - ADR-125: selective authentication HBAC per-trust policy
  - ADR-067: in-toto attestation verification at deploy time
  - FreeIPA HBAC sync (per ADR-115)
  - sIDHistory injection audit (CLI tooling)

v2 (Phase 3):
  - Predictive threat detection via OTel log anomaly scoring
  - ML-based Pass-the-ticket detection (geo baseline per principal)
  - Quantum-safe Kerberos etypes (per future RFC, gated)
  - RBAC template GitOps with PR-based enforcement review
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `sigstore` | 0.10 | Sigstore client for supply chain (per ADR-067) |
| `cosign` | 0.1 | cosign verify at deploy time |
| `in-toto` | 0.1 | in-toto attestation verification |
| `ring` | 0.17 | Ed25519 signature verification (PAC validation) |
| `rasn` | 0.22 | ASN.1 for PAC structures |
| `rasn-kerberos` | 0.22 | PAC types |
| `cryptoki` | 0.5 | PKCS#11 HSM (krbtgt, KDS, KRA, CA, OCSP, PEK) |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit event emission |
| `prometheus` | 0.13 | Metrics (threat detection alert counts) |
| `tokio` | 1 | Async runtime |
| `thiserror` | 1 | PacError, ThreatError, RbacError enums |
| `serde` / `serde_json` / `serde_yaml` | 1 | RBAC templates, HBAC rules |
| `git2` | 0.18 | RBAC template GitOps (per ADR-066) |
| `clap` | 4 | CLI for security subcommands |
| `proptest` | 1 | Property-based tests |
| `uuid` | 1.10 | UUIDs in events |
| `adrian-auth-core` | * | Principal type |
| `adrian-audit` | * | AuditEvent type |
| `adrian-hsm` | * | Signer trait (HSM-bound keys) |
| `adrian-sid` | * | Sid type |
| `adrian-policy-core` | * | (mutual dependency for RBAC) |

## 11. References

- ADRs: [ADR-011](../adr/ADR-011-rc4-deprecation-aes-default.md), [ADR-015](../adr/ADR-015-krbtgt-hsm-rotation.md), [ADR-021](../adr/ADR-021-ldap-signing-channel-binding.md), [ADR-060](../adr/ADR-060-structured-audit-logs-otel.md), [ADR-064](../adr/ADR-064-kerberoasting-aes-migration.md), [ADR-065](../adr/ADR-065-krbtgt-hsm-rotation.md), [ADR-066](../adr/ADR-066-adminsdholder-declarative-rbac.md), [ADR-067](../adr/ADR-067-sigstore-supply-chain.md), [ADR-082](../adr/ADR-082-ms-kile-pac-generation.md), [ADR-083](../adr/ADR-083-pac-validation-rpc.md), [ADR-085](../adr/ADR-085-ntlm-client-only-rust-crate.md), [ADR-086](../adr/ADR-086-pass-the-hash-defense.md), [ADR-115](../adr/ADR-115-freeipa-alternative-linux-tier.md), [ADR-122](../adr/ADR-122-dcsync-mitigation.md), [ADR-123](../adr/ADR-123-silver-ticket-mitigation.md), [ADR-124](../adr/ADR-124-sidhistory-injection-mitigation.md), [ADR-125](../adr/ADR-125-selective-authentication-hbac.md)
- Workshop decisions: [Decision 5 — KDC Implementation](../workshop/decision-05-kdc-implementation.md), [Decision 6 — NTLM Decision](../workshop/decision-06-ntlm-decision.md)
- KB files: [catalog/11-security-threat-model.md](../catalog/11-security-threat-model.md), [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md)
- RFCs: RFC 4120 (Kerberos), RFC 6806 (FAST), RFC 4556 (PKINIT), RFC 6112 (Anonymous PKINIT)
- MS-* specs: MS-KILE (Kerberos PAC), MS-PAC (PAC), MS-NLMP (NTLM), MS-APDS (Auth Protocol Domain Support), MS-ADTS (AdminSDHolder, sIDHistory)
- MITRE ATT&CK: Enterprise Matrix (attack.mitre.org), specifically T1003 (OS Credential Dumping), T1078 (Valid Accounts), T1136 (Create Account), T1558 (Steal or Forge Kerberos Tickets), T1210 (Exploitation of Remote Services)
- Sigstore: cosign documentation (sigstore.dev), in-toto specification (in-toto.io), SLSA Framework (slsa.dev)
