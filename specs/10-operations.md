---
title: "Operations (deploy / monitor / recover) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Operations
tags: [spec, operations, kubernetes, observability, audit, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Operations (deploy / monitor / recover) — Technical Specification

## 1. Overview

The Operations capability covers deployment (container-native DCs + Kubernetes operator), observability (Prometheus + OpenTelemetry), backup/DR (per-DC backup with PITR + operator-driven runbooks), audit (structured OTel logs + MITRE ATT&CK mapping), API surface (REST for CRUD + gRPC for streaming), trust password auto-rotation, multi-region replication topology, schema-as-code GitOps, functional levels as capability flags, and the unified cross-platform CLI. It is the operability layer that wraps every other capability: without `adrian-operator`, `adrian-monitor`, `adrian-cli`, and `adrian-audit`, the framework's capabilities are APIs without an operator surface.

Container-native deployment is the primary deployment model — bare-metal/VM is documented but not the reference path. The `adrian-operator` (ADR-058) manages the full DC lifecycle via a `DomainController` CRD: `promote` (seeds new DC from existing DIT snapshot via IFM-equivalent path), `demote` (drains replication partners, removes `nTDSDSA` object), `backup` (triggers PVC snapshot or logical export), `restore` (PVC restore + USN-rollback-equivalent detection), `schema-upgrade` (atomic with rollback), `fsmo-transfer` (graceful) or `fsmo-seize` (forcible).

The capability carries 10 ADRs: ADR-057 (Prometheus + OpenTelemetry), ADR-058 (container-native DCs + operator), ADR-059 (PITR backup + DR runbooks), ADR-060 (structured audit logs OTel + MITRE ATT&CK), ADR-061 (REST + gRPC API), ADR-062 (trust password auto-rotation), ADR-063 (unified cross-platform CLI), ADR-119 (schema-as-code GitOps), ADR-120 (multi-region replication topology), ADR-121 (functional levels as capability flags). It has zero individual blockers but defines the operability baseline for every other capability.

The capability is implemented as **six** Rust crates at Layer 4: `adrian-operator` (Kubernetes operator), `adrian-monitor` (Prometheus + OTel), `adrian-audit` (structured OTel audit logs), `adrian-cli` (unified CLI), `adrian-migrate` (migration tooling, shared with Migration capability), `adrian-gpo-translate` (shared with Policy Engine). External dependencies include `kube` (Rust Kubernetes client), `tokio`, `axum` (REST), `tonic` (gRPC), `prometheus`, `opentelemetry`, `opentelemetry-otlp`, `tracing`, `tracing-opentelemetry`, `clap`, `git2`, `serde_yaml`, `reqwest`.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-operator` | 4 | Kubernetes operator; `DomainController` CRD; lifecycle: promote/demote/backup/restore/schema-upgrade/fsmo-transfer/fsmo-seize | ADR-058, ADR-059, ADR-062, ADR-120 |
| `adrian-monitor` | 4 | Prometheus exporter (port 9100) + OTel instrumentation; metrics for LDAP/Kerberos/SMB/replication; tracing for cross-component flow | ADR-057 |
| `adrian-audit` | 4 | Structured OTel audit logs with MITRE ATT&CK mapping; events: 4662-equivalent (repl), 4769-equivalent (TGS-REQ with etype), 4624-equivalent (logon), 4720-equivalent (user create) | ADR-060 |
| `adrian-cli` | 4 | Unified cross-platform CLI with subcommands: join, klist, policy coverage, migrate, audit-ntlm, trust establish, fdb provision, schema rollback | ADR-063 |
| `adrian-operator` (cont.) | 4 | Schema-as-code GitOps: PR-based schema migrations with typed projection regeneration; reversible via `adrian-cli schema rollback` | ADR-119 |
| `adrian-operator` (cont.) | 4 | Functional levels as per-DC capability flags (not forest-wide gates); per-DC advertisement via `msDS-IsParentCapability`-equivalent | ADR-121 |
| `adrian-operator` (cont.) | 4 | REST API for CRUD (`axum`) + gRPC for streaming (replication health, audit tail) via `tonic`; GraphQL deferred | ADR-061 |

## 3. Key types and traits

```rust
// crates/adrian-operator/src/lib.rs (per ADR-058)

use kube::{Client, Api, CustomResource};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// DomainController CRD — Kubernetes custom resource representing
/// a framework Domain Controller. Operator reconciles desired → actual.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "adrian.io",
    version = "v1",
    kind = "DomainController",
    namespaced,
    shortname = "dc",
    status = "DomainControllerStatus",
    names = "domaincontrollers"
)]
pub struct DomainControllerSpec {
    pub realm: String,                       // "corp.example.com"
    pub forest_root: String,
    pub interop_mode: InteropMode,           // ad-interop | native
    pub fdb_cluster_ref: String,             // FdbCluster CR name
    pub pvc_size_gb: u32,
    pub replicas: u32,                       // horizontal scaling
    pub image: String,                       // adrian-dc image
    pub capabilities: Vec<String>,           // ADR-121 capability flags
    pub backup: BackupSpec,
    pub multi_region: Option<MultiRegionSpec>,
}

pub enum InteropMode { AdInterop, Native }

pub struct BackupSpec {
    pub destination: String,                 // s3://bucket/path
    pub schedule: String,                    // cron
    pub pitr_window_days: u32,
}

pub struct MultiRegionSpec {                 // ADR-120
    pub primary_region: String,
    pub secondary_regions: Vec<String>,
    pub sync_replication: bool,
}

pub struct DomainControllerStatus {
    pub phase: DcPhase,                      // Pending|Promoting|Active|Demoting|Backup|Restore|Failed
    pub conditions: Vec<Condition>,
    pub last_backup_at: Option<SystemTime>,
    pub last_restore_at: Option<SystemTime>,
    pub fsmo_held: Vec<String>,              // for AD-interop mode
    pub usn_rollback_detected: bool,
    pub observed_generation: u64,
}

pub enum DcPhase {
    Pending, Promoting, Active, Demoting,
    Backup, Restore, SchemaUpgrade,
    FsmoTransfer, FsmoSeize, Failed,
}

/// Operator implements promote/demote/backup/restore/schema-upgrade/
/// fsmo-transfer/fsmo-seize lifecycle per ADR-058.
pub struct DcOperator {
    kube: Client,
    config: OperatorConfig,
}

impl DcOperator {
    pub async fn reconcile(&self, dc: &DomainController) -> Result<(), OperatorError>;
    pub async fn promote(&self, dc: &DomainController) -> Result<(), OperatorError>;
    pub async fn demote(&self, dc: &DomainController) -> Result<(), OperatorError>;
    pub async fn backup(&self, dc: &DomainController) -> Result<(), OperatorError>;
    pub async fn restore(&self, dc: &DomainController, to: SystemTime) -> Result<(), OperatorError>;
    pub async fn schema_upgrade(&self, dc: &DomainController, pr_url: &str) -> Result<(), OperatorError>;
    pub async fn fsmo_transfer(&self, role: &str, to_dc: &str) -> Result<(), OperatorError>;
    pub async fn fsmo_seize(&self, role: &str) -> Result<(), OperatorError>;
}
```

```rust
// crates/adrian-monitor/src/lib.rs (per ADR-057)

use prometheus::{IntCounter, Histogram, Registry};

pub struct Monitor {
    registry: Registry,
    metrics: Metrics,
    otel_provider: opentelemetry_sdk::trace::Tracer,
}

pub struct Metrics {
    pub ldap_requests_total: IntCounter,             // labeled by op + outcome
    pub ldap_request_duration: Histogram,
    pub kerberos_as_req_total: IntCounter,           // labeled by outcome + etype
    pub kerberos_tgs_req_total: IntCounter,
    pub kerberos_pac_build_duration: Histogram,
    pub smb_connections: IntCounter,
    pub smb_read_bytes: IntCounter,
    pub smb_write_bytes: IntCounter,
    pub replication_lag_secs: Histogram,             // labeled by partner
    pub fdb_storage_lag_secs: Histogram,
    pub fdb_log_server_latency_ms: Histogram,
    pub fdb_cluster_available: IntCounter,
    pub raft_leader_changes: IntCounter,
    pub audit_events_total: IntCounter,              // labeled by event_id
    pub cert_issued_total: IntCounter,
    pub policy_apply_duration: Histogram,
}

impl Monitor {
    pub fn metrics_handler(&self) -> impl Fn() -> String;  // for /metrics endpoint
    pub fn otel_span(&self, name: &str) -> opentelemetry::Span;
}
```

```rust
// crates/adrian-audit/src/lib.rs (per ADR-060)

use opentelemetry::KeyValue;
use std::time::SystemTime;

/// Structured audit events in OTel log format with MITRE ATT&CK mapping.
/// Events include Windows-equivalent IDs for SIEM ingestion compat:
///   4624 (logon), 4625 (failed logon), 4662 (repl priv use),
///   4720 (user create), 4726 (user delete), 4738 (user change),
///   4768 (AS-REQ), 4769 (TGS-REQ), 4771 (Kerberos preauth failed),
///   4776 (NTLM auth), 4719 (audit policy change),
///   5136 (directory object modified), 5141 (directory object deleted)
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub event_id: u32,                       // Windows-equivalent event ID
    pub timestamp: SystemTime,
    pub outcome: AuditOutcome,
    pub principal: Option<String>,
    pub target: Option<String>,
    pub source_addr: Option<IpAddr>,
    pub logon_type: Option<LogonType>,
    pub etype: Option<u32>,
    pub details: Vec<KeyValue>,
    pub mitre_attack: Vec<&'static str>,     // ["T1558.001", "Golden Ticket"]
}

pub enum AuditOutcome { Success, Failure, Audit, Alert }

pub struct AuditLogger {
    otel_log_provider: opentelemetry_sdk::logs::Logger,
    mitre_mapping: DashMap<u32, Vec<&'static str>>,
}

impl AuditLogger {
    pub async fn emit(&self, event: AuditEvent) -> Result<(), AuditError>;

    /// Specific event helpers (typed for type-safety at call sites).
    pub async fn emit_logon(&self, principal: &str, logon_type: LogonType,
                            source_addr: IpAddr, outcome: AuditOutcome) -> Result<(), AuditError>;
    pub async fn emit_kerberos_as_req(&self, principal: &str, etype: u32,
                                       source_addr: IpAddr, outcome: AuditOutcome) -> Result<(), AuditError>;
    pub async fn emit_tgs_req(&self, principal: &str, service: &str, etype: u32,
                              source_addr: IpAddr, outcome: AuditOutcome) -> Result<(), AuditError>;
    pub async fn emit_repl_priv_use(&self, principal: &str, nc_head: &str,
                                    exop: u32, source_addr: IpAddr) -> Result<(), AuditError>;
    pub async fn emit_object_modify(&self, principal: &str, dn: &str,
                                     attrs: &[&str], outcome: AuditOutcome) -> Result<(), AuditError>;
    pub async fn emit_cert_issue(&self, principal: &str, serial: u64,
                                  profile: &str, outcome: AuditOutcome) -> Result<(), AuditError>;
}
```

```rust
// crates/adrian-cli/src/lib.rs (per ADR-063)

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "adrian-cli", version, about = "Adrian Framework CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Join a host to the framework domain
    Join { realm: String, ou: Option<String> },
    /// List Kerberos tickets in the local cache
    Klist,
    /// Show applied policy coverage for this host
    PolicyCoverage,
    /// Audit NTLM usage
    AuditNtlm { since_hours: u32 },
    /// Establish a cross-realm trust
    TrustEstablish { peer: String, peer_realm: String },
    /// Provision an FDB cluster
    FdbProvision { size: u32 },
    /// Roll back a schema migration
    SchemaRollback { pr_url: String },
    /// Migrate from a legacy agent
    Migrate { from: MigrateTarget },
    /// Manage FSMO roles (AD-interop)
    FsmoTransfer { role: String, to: String },
    FsmoSeize { role: String },
    /// Operator subcommands
    Operator(OperatorSubcommand),
    /// Audit log tail (gRPC stream)
    AuditTail { filter: String },
    /// Replication health (gRPC stream)
    ReplHealth,
}

#[derive(Clone)]
pub enum MigrateTarget {
    Sssd, Winbind, Pbis, Dsconfigad,
    EnterpriseConnect, Nomad, JamfConnect,
    Centrify, Admitmac, Dave,
}
```

## 4. Data model

```
Operations data model:

FDB subspaces used:
  (0x08, ts, event_id) → audit event per ADR-060
  (0x0A, artifact_hash[0..32]) → sigstore bundle per ADR-067
  (0x09, 0x01, cert_serial) → CA cert data (cross-ref)
  (0x04, generation) → schema cache (cross-ref, ADR-003/078)

Kubernetes CRDs (per ADR-058):
  adrian.io/v1/DomainController
    spec: { realm, forestRoot, interopMode, fdbClusterRef,
            pvcSizeGb, replicas, image, capabilities, backup, multiRegion }
    status: { phase, conditions, lastBackupAt, lastRestoreAt,
              fsmoHeld, usnRollbackDetected, observedGeneration }
  adrian.io/v1/FdbCluster
    spec: { size, redundancyMode, usableRegions, logServers,
            storageServers, coordinators, backupDestination }
    status: { healthy, availableSize, storageLag, logServerLatency }
  adrian.io/v1/AdrianPolicy
    spec: { gitRepoUrl, branch, syncInterval, websocketPushEnabled }
    status: { lastSyncAt, lastCommit, appliedPolicyCount }
  adrian.io/v1/AdrianCA
    spec: { tier, profile, hsmConfig, ocspUrl }
    status: { healthy, certsIssued, certsRevoked, crlGeneratedAt }

Operator state (CRD status, not FDB):
  Each DomainController CR has status.phase reflecting the lifecycle:
    Pending → Promoting → Active → Demoting → (deleted)
    Active → Backup → Active (scheduled backups)
    Active → Restore → Active (manual restore)
    Active → SchemaUpgrade → Active (per ADR-119)
    Active → FsmoTransfer → Active (AD-interop, graceful)
    Active → FsmoSeize → Active (AD-interop, forcible)
    Active → Failed (USN rollback, FDB unreachable, etc.)

Functional levels (per ADR-121):
  Per-DC capability flags, NOT forest-wide gates. No irreversible
  "raise forest functional level" operation.
  Stored on the DC's nTDSDSA object in FDB:
    (0x01, dnt(nTDSDSA), ATT_MS_DS_IS_PARENT_CAPABILITY, _)
      → bitmap of capabilities
  Capabilities:
    0x0001 — adrian-interop-3.0
    0x0002 — pac-full-checksum
    0x0004 — pac-buffer-ticket-checksum
    0x0008 — fast-required
    0x0010 — pkinit-fido2
    0x0020 — acme-primary
    0x0040 — short-lived-certs
    0x0080 — multi-region-raft
    0x0100 — rbac-v2
    0x0200 — ddm-first
  Clients query capabilities via LDAP search on the DC's nTDSDSA object.

Schema-as-code GitOps (per ADR-119):
  Schema migrations are Git PRs:
    repos/adrian-schema.git/
      migrations/
        0001-initial-schema/
          up.json           — forward migration
          down.json         — reverse migration
          projection.diff   — typed projection diff (auto-generated)
          metadata.toml     — author, date, objectVersion synthesized
      applied/
        0001-initial-schema.applied   — applied-at timestamp + DC UUID
  Operator polls git every 60s; on new PR merged:
    1. Pull migration
    2. Run up.json in FDB transaction
    3. Regenerate SchemaProjection via schema-compiler (≤500ms per ADR-078)
    4. Atomic ArcSwap of projection
    5. Update applied/ marker
  Rollback: adrian-cli schema rollback --pr <url>
    1. Pull down.json from PR
    2. Run in FDB transaction
    3. Regenerate projection
    4. Update applied/ marker
  objectVersion synthesized for AD-interop compatibility.

Audit log storage:
  Hot tier: FDB subspace 0x08 (last 7 days, hot queryable)
  Warm tier: PostgreSQL adrian_audit table (7-90 days, structured query)
  Cold tier: S3 + Athena (90+ days, compliance archive)
  All tiers emit OTel log events to OTLP endpoint in real-time.

MITRE ATT&CK mapping (per ADR-060):
  Event ID → MITRE technique mapping:
    4624 (logon)            → T1078 Valid Accounts
    4625 (failed logon)     → T1110 Brute Force
    4662 (repl priv use)    → T1003 OS Credential Dumping: NTDS
    4720 (user create)      → T1136 Create Account
    4726 (user delete)      → T1531 Account Access Removal
    4768 (AS-REQ)           → T1558 Steal or Forge Kerberos Tickets
    4769 (TGS-REQ)          → T1558.003 Kerberoasting
    4771 (preauth failed)   → T1110 Brute Force
    4776 (NTLM auth)        → T1558.004 NTLM Relay (alert if unexpected)
    5136 (object modify)    → T1485 Data Destruction (if mass delete)
    5141 (object delete)    → T1485 Data Destruction
    4719 (audit policy chg) → T1562 Impair Defenses
```

## 5. Protocol surface

```
Operator API surface (per ADR-058, ADR-061):

REST API (per ADR-061, served by adrian-cli or operator):
  GET    /api/v1/domaincontrollers                  — list DCs
  POST   /api/v1/domaincontrollers                  — create DC (creates CR)
  GET    /api/v1/domaincontrollers/{name}           — get DC
  PUT    /api/v1/domaincontrollers/{name}           — update DC spec
  DELETE /api/v1/domaincontrollers/{name}           — delete DC
  POST   /api/v1/domaincontrollers/{name}/promote   — promote lifecycle
  POST   /api/v1/domaincontrollers/{name}/demote
  POST   /api/v1/domaincontrollers/{name}/backup
  POST   /api/v1/domaincontrollers/{name}/restore   — body: { to: <timestamp> }
  POST   /api/v1/domaincontrollers/{name}/schema-upgrade  — body: { prUrl }
  POST   /api/v1/domaincontrollers/{name}/fsmo-transfer  — body: { role, toDc }
  POST   /api/v1/domaincontrollers/{name}/fsmo-seize      — body: { role }
  GET    /api/v1/fdbclusters/{name}                 — FDB cluster status
  POST   /api/v1/fdbclusters/{name}/scale           — body: { size }
  GET    /api/v1/audit                              — query audit events
  GET    /api/v1/schema/migrations                  — list schema PRs

gRPC streaming (per ADR-061):
  adrian.v1.AuditService/Tail        — server-streaming, filter param
  adrian.v1.ReplicationService/WatchHealth — server-streaming, per-DC
  adrian.v1.BackupService/WatchStatus — server-streaming, per-backup-job
  adrian.v1.OperatorService/WatchEvents — server-streaming, all CR events

Prometheus metrics (per ADR-057):
  GET /metrics on port 9100 of every adrian-* service
  Standard format per Prometheus exposition spec.

OpenTelemetry (per ADR-057, ADR-060):
  OTLP/gRPC on port 4317 of every adrian-* service
  OTLP/HTTP on port 4318
  Traces + metrics + logs all exported to OTLP endpoint

Kubernetes operator protocol (per ADR-058):
  Operator watches DomainController CRs via kube-rs
  Reconcile loop: desired spec → actual state → action
  Events published to Kubernetes Events API (kubectl describe dc/<name>)
  Status updates via CR subresource /status

Backup protocol (per ADR-059):
  Operator triggers FDB backup_agent via subprocess
  Continuous backup: FDB backup_agent --dest s3://... --log
  Restore: FDB fastrestore --from s3://... --to <timestamp>
  Backup status published to CR status + Prometheus metrics

Multi-region replication (per ADR-120):
  FDB usable_regions=2 for cross-region sync replication
  Operator configures FDB regions=2 with primary + secondary
  Per-DC raft leader election scoped to region
  Cross-region failover: operator command, manual trigger

CLI subcommands (per ADR-063):
  adrian-cli join <realm> [--ou <ou>]
  adrian-cli klist
  adrian-cli policy coverage
  adrian-cli audit-ntlm --since-hours 24
  adrian-cli trust establish --peer freeipa --peer-realm IPA.EXAMPLE.COM
  adrian-cli fdb provision --size 3
  adrian-cli schema rollback --pr https://github.com/.../pull/42
  adrian-cli migrate from-jamf-connect
  adrian-cli fsmo transfer --role schema --to dc02
  adrian-cli operator install                    — install CRDs + RBAC
  adrian-cli audit tail --filter 'event_id=4769' — gRPC stream
  adrian-cli repl health                         — gRPC stream
```

## 6. Configuration

```toml
# /etc/adrian/operator.toml — Operator configuration

[operator]
namespace              = "adrian-system"
image_adrian_dc        = "ghcr.io/adrian-framework/adrian-dc:1.0.0"
image_keycloak_shim    = "ghcr.io/adrian-framework/adrian-keycloak-shim:1.0.0"
image_acme_server      = "ghcr.io/adrian-framework/adrian-acme-server:1.0.0"
image_smb_server       = "ghcr.io/adrian-framework/adrian-smb-server:1.0.0"
distroless_images      = true
sigstore_signing       = true                    # ADR-067
max_concurrent_reconciles = 5
leader_election        = true

[backup]                                # ADR-059
destination             = "s3://adrian-backups/corp/"
schedule                = "0 */6 * * *"           # every 6 hours
pitr_window_days        = 30
continuous_backup       = true
backup_retention_days   = 365
encryption_key_kms_ref  = "kms://us-east-1/key/adrian-backup-key"

[multi_region]                          # ADR-120
enabled                 = false
primary_region          = "us-east-1"
secondary_regions       = ["us-west-2", "eu-west-1"]
sync_replication        = true
failover_mode           = "manual"      # manual | automatic

[schema_gitops]                         # ADR-119
repo_url                = "https://github.com/corp/adrian-schema.git"
branch                  = "main"
poll_interval_secs      = 60
ssh_key_secret          = "adrian-schema-deploy-key"
auto_apply_merged_prs   = false         # require operator approval

[functional_levels]                     # ADR-121
mode                    = "per_dc_capability_flags"
forest_wide_gates_disabled = true       # no irreversible raise-FFL
default_capabilities    = [
  "adrian-interop-3.0",
  "pac-full-checksum",
  "fast-required",
  "acme-primary"
]

[api]                                   # ADR-061
rest_listen_addr        = "0.0.0.0:8443"
grpc_listen_addr        = "0.0.0.0:9090"
tls_cert_file           = "/etc/adrian/operator.crt"
tls_key_file            = "/etc/adrian/operator.key"
auth_mode               = "oidc"        # OIDC via Federation Gateway
graphql_enabled         = false         # v2 per ORQ-226/227/228

[monitor]                               # ADR-057
prometheus_port         = 9100
otel_endpoint           = "http://otel-collector:4317"
otel_protocol           = "grpc"        # grpc | http
tracing_enabled         = true
metrics_namespace       = "adrian"

[audit]                                 # ADR-060
otel_log_endpoint       = "http://otel-collector:4317"
fdb_hot_tier_days       = 7
postgres_warm_tier_days = 90
s3_cold_tier_years      = 7
mitre_attack_mapping    = true
alert_on_rc4_etypes     = true
alert_on_ntlm_usage     = true
alert_on_dcsync         = true          # per ADR-122

[trust_password_rotation]               # ADR-062
auto_rotate_days        = 30
auto_reset_on_desync    = true
max_desync_count        = 3
```

## 7. Error handling

```rust
// crates/adrian-operator/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    #[error("Kubernetes API error: {0}")]
    KubeApi(#[from] kube::Error),
    #[error("FDB cluster {0} not found or unhealthy")]
    FdbClusterUnhealthy(String),
    #[error("PVC {0} not found for DC {1}")]
    PvcNotFound(String, String),
    #[error("backup failed for DC {0}: {1}")]
    BackupFailed(String, String),
    #[error("restore failed: PVC restore from {0} returned error: {1}")]
    RestoreFailed(String, String),
    #[error("USN rollback detected on DC {0}; self-quarantining")]
    UsnRollbackDetected(String),
    #[error("schema migration {0} failed: {1}")]
    SchemaMigrationFailed(String, String),
    #[error("FSMO role {0} transfer to {1} failed: {2}")]
    FsmoTransferFailed(String, String, String),
    #[error("FSMO role {0} seize failed: {1}")]
    FsmoSeizeFailed(String, String),
    #[error("multi-region failover failed: {0}")]
    MultiRegionFailoverFailed(String),
    #[error("trust password rotation failed for trust {0}: {1}")]
    TrustPasswordRotationFailed(String, String),
    #[error("reconcile loop timeout after {0:?}")]
    ReconcileTimeout(Duration),
}

// crates/adrian-audit/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("OTel log provider unavailable: {0}")]
    OtelUnavailable(String),
    #[error("FDB audit write failed: {0}")]
    FdbWriteFailed(String),
    #[error("PostgreSQL warm tier write failed: {0}")]
    PostgresWriteFailed(String),
    #[error("S3 cold tier archive failed: {0}")]
    S3ArchiveFailed(String),
    #[error("MITRE ATT&CK mapping missing for event_id {0}")]
    MissingMitreMapping(u32),
}

// crates/adrian-cli/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("not joined to a framework realm; run `adrian-cli join`")]
    NotJoined,
    #[error("operator unreachable: {0}")]
    OperatorUnreachable(String),
    #[error("gRPC stream error: {0}")]
    GrpcStream(String),
    #[error("migration target {0} not installed on this host")]
    MigrationTargetNotInstalled(String),
    #[error("schema rollback requires PR URL; got: {0}")]
    InvalidPrUrl(String),
}
```

**Error propagation.** Operator errors update the DomainController CR status.phase = `Failed` with conditions explaining the failure. Backup/restore failures emit Kubernetes Events visible via `kubectl describe dc/<name>`. Audit write failures fall back to local file logging + alert. CLI errors print user-friendly messages with the next suggested action (`run \`adrian-cli operator install\` first`). Every operator action emits an OTel audit event for traceability.

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - Operator CRD spec/status round-trips (serde + JsonSchema)
    - Reconcile loop state machine (Pending→Promoting→Active→...)
    - Backup/restore command construction
    - Prometheus metrics registration + scrape
    - OTel audit event emission + MITRE mapping
    - CLI argument parsing (clap)
    - All CLI subcommands' happy + error paths
    - Schema GitOps: PR detection, migration apply, projection regen
    - Functional levels: capability flag bit manipulation
    - Trust password rotation scheduling

Integration tests — tests/integration/, real K8s (kind) + tokio
  Coverage:
    - Operator reconcile: create DC CR → wait for Active phase
    - Promote lifecycle: seed new DC from existing
    - Backup + restore round-trip
    - Schema migration apply + rollback
    - FSMO transfer (AD-interop mock)
    - Multi-region failover (mock FDB)
    - Trust password rotation on schedule
    - Audit event emission + FDB + PostgreSQL write
    - gRPC streaming (audit tail, repl health)
    - REST API CRUD for DCs

Interop tests — tests/interop/
  Matrix:
    - kind (Kubernetes in Docker) cluster with operator + CRDs
    - EKS cluster (per-PR test environment)
    - GKE cluster (per-PR test environment)
    - AKS cluster (per-PR test environment)
    - Prometheus + Grafana scraping framework metrics
    - OTel Collector → Jaeger + Loki + Tempo
    - SIEM integration (Splunk, Elastic) via OTel log export
    - Velero backup integration (cluster-level DR)

Property-based tests — proptest
  Tested:
    - CRD spec serialization round-trips
    - Audit event detail map round-trips
    - MITRE mapping table consistency
    - Schema migration up/down round-trips
  Corpus: 50+ property tests across ops crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-058: container-native DC StatefulSet + operator with
             promote/demote/backup/restore lifecycle
  - ADR-057: Prometheus exporter + OTel instrumentation
  - ADR-060: structured audit logs in OTel format + MITRE mapping
  - ADR-059: per-DC backup with PITR + basic DR runbooks
  - ADR-061: REST API for CRUD (axum)
  - ADR-063: unified CLI with core subcommands (join, klist,
             policy coverage, audit-ntlm)
  - ADR-062: trust password auto-rotation
  - ADR-121: functional levels as per-DC capability flags

v1 (Phase 2):
  - Full DR runbooks (operator-driven backup/restore/failover)
  - ADR-119: schema-as-code GitOps with PR review
  - ADR-120: multi-region replication topology
  - gRPC streaming APIs (audit tail, repl health)
  - ADR-063: full CLI with all migration subcommands
  - S3 cold-tier audit archive + Athena query
  - Splunk/Elastic SIEM integration docs

v2 (Phase 3):
  - GraphQL API (per ADR-061 deferral, gated by ORQ-226/227/228)
  - Predictive autoscaling based on auth rate (ML-driven)
  - Multi-cluster federation (operator-of-operators)
  - Predictive threat detection via OTel log anomaly scoring
  - ADR-067: Sigstore + in-toto supply chain integration
              (verify at deploy time, not just build time)
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `kube` | 0.87 | Rust Kubernetes client + operator framework |
| `tokio` | 1 | Async runtime |
| `axum` | 0.7 | REST API server (per ADR-061) |
| `tonic` | 0.11 | gRPC streaming server (per ADR-061) |
| `prometheus` | 0.13 | Metrics exporter |
| `opentelemetry` | 0.24 | OTel SDK |
| `opentelemetry-otlp` | 0.15 | OTLP exporter (gRPC + HTTP) |
| `tracing` | 0.1 | Structured logging |
| `tracing-opentelemetry` | 0.25 | Tracing → OTel bridge |
| `clap` | 4 | CLI argument parsing |
| `git2` | 0.18 | Schema GitOps (per ADR-119) |
| `serde_yaml` | 0.9 | CRD spec + topology YAML |
| `reqwest` | 0.12 | REST client for inter-service calls |
| `aws-sdk-s3` | 1 | S3 backup destination (per ADR-059) |
| `schemars` | 0.8 | JSON Schema for CRDs |
| `serde` / `serde_json` | 1 | CRD serialization |
| `thiserror` | 1 | Error enums |
| `anyhow` | 1 | Top-level error in binary entry points |
| `backon` | 1 | Retry with backoff for reconcile loop |
| `uuid` | 1.10 | UUIDs for events, DCs |
| `chrono` | 0.4 | Timestamps |
| `adrian-storage-fdb` | * | FDB for audit + cluster health |
| `adrian-repl-core` | * | Replicator trait for repl health |
| `adrian-cli` | * | CLI shared with other capabilities |

## 11. References

- ADRs: [ADR-057](../adr/ADR-057-prometheus-otel-observability.md), [ADR-058](../adr/ADR-058-container-native-dcs-operator.md), [ADR-059](../adr/ADR-059-pitr-backup-dr-runbooks.md), [ADR-060](../adr/ADR-060-structured-audit-logs-otel.md), [ADR-061](../adr/ADR-061-rest-grpc-api.md), [ADR-062](../adr/ADR-062-trust-password-auto-rotation.md), [ADR-063](../adr/ADR-063-unified-cross-platform-cli.md), [ADR-067](../adr/ADR-067-sigstore-supply-chain.md), [ADR-119](../adr/ADR-119-schema-as-code-gitops.md), [ADR-120](../adr/ADR-120-multi-region-replication-topology.md), [ADR-121](../adr/ADR-121-functional-levels-capability-flags.md), [ADR-122](../adr/ADR-122-dcsync-mitigation.md)
- Workshop decisions: [Decision 1 — Replication Protocol](../workshop/decision-01-replication-protocol.md), [Decision 2 — Storage Engine](../workshop/decision-02-storage-engine.md)
- KB files: [docs/00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md), [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md)
- RFCs: RFC 5280 (X.509, for backup encryption certs), RFC 7231 (HTTP, REST API), OTLP specification (opentelemetry.io), Prometheus exposition format
- MS-* specs: MS-ADTS (Functional Levels, FSMO roles), MS-DRSR (DRSUAPI, for replication health)
- Kubernetes: Kubernetes API Conventions, Operator Pattern (kubernetes.io/docs), CustomResourceDefinition spec
- MITRE ATT&CK: Enterprise Matrix (attack.mitre.org)
- OpenTelemetry: Semantic Conventions for Logs, Traces, Metrics
