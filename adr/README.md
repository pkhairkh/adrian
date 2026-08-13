---
title: ADR Index — Architecture Decision Records
audience: architects-and-engineers
tags: [adr, decision-records, index, framework-design]
related:
  - ./TRIAGE.md
  - ../catalog/README.md
  - ../catalog/13-open-research-questions.md
  - ../draft/06-roadmap.md
last_updated: 2026-08-13
---

# ADR Index — Architecture Decision Records

This directory contains 130 Architecture Decision Records (ADRs) documenting high-confidence decisions for the Adrian framework. Each ADR resolves a specific problem from the [problem catalog](../catalog/README.md). A further 61 problems are deferred pending Tier-1 architectural ORQ resolution and research spike outcomes — see [TRIAGE.md](./TRIAGE.md) for the deferral rationale.

## How to use this directory

- **New to the ADRs?** Read [TRIAGE.md](./TRIAGE.md) first to understand which problems got ADRs and which were deferred.
- **Looking for a specific decision?** Use the per-capability tables below.
- **Looking for a decision on a specific problem?** Use the PC → ADR mapping table at the bottom.
- **Implementing an ADR?** Read the ADR's "Concrete specification" section — every bullet is testable.

## Statistics

- **Total ADRs**: 130
- **High-confidence (full)**: 83
- **Partial (confident part + deferred part)**: 47
- **Deferred problems (no ADR)**: 61 — gated by 11 Tier-1 ORQs
- **Total words across all ADRs**: ~313,688
- **Average words per ADR**: ~2,412

## ADR format

Every ADR follows this structure:

```markdown
# ADR-NNN: <Title>

## Status      — Accepted (with date)
## Context     — the problem being solved (cites PC-NNN)
## Decision    — the chosen solution, specific and implementable
## Rationale   — why this decision, alternatives rejected
## Consequences — positive, negative, neutral, cost, operational impact
## Alternatives Considered — at least 2 alternatives with rejection rationale
## Open Questions — for PARTIAL ADRs, cites gating ORQ
## Cross-capability impact — how this decision affects other capabilities
## References  — KB files, RFCs, MS-* specs
```

Security ADRs additionally include a **Threat model** section (STRIDE + attack vector + AD mitigations + residual risk).

Migration ADRs additionally include a **Migration state machine** section (source state + target state + coexistence period + cutover trigger + rollback path).

## ADRs by capability

### Core Directory (22 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-001](./ADR-001-linked-value-replication.md) | PC-003 | Linked Value Replication for Multi-Valued Linked Attributes | high | ⚠️ |
| [ADR-002](./ADR-002-memberof-back-link.md) | PC-004 | memberOf Back-Link as DSA-Computed linkID Pair | blocker | ⚠️ |
| [ADR-003](./ADR-003-schema-cache-cow.md) | PC-006 | Copy-on-Write Schema Cache with Monotonic Generation Numbers | medium | ⚠️ |
| [ADR-004](./ADR-004-sd-deduplication.md) | PC-008 | Security Descriptor Deduplication via Content-Hash Indexed Table | medium | ⚠️ |
| [ADR-005](./ADR-005-well-known-container-guids.md) | PC-011 | Reserve and Honor Well-Known Container GUIDs | medium |  |
| [ADR-006](./ADR-006-ad-ldap-controls.md) | PC-012 | AD-Specific LDAP Controls for Client Interop | high |  |
| [ADR-007](./ADR-007-password-change-protocol.md) | PC-013 | kpasswd as Primary Password-Change Protocol; BER-Quote unicodePwd in AD-Compat Mode | medium |  |
| [ADR-008](./ADR-008-declarative-replication-topology.md) | PC-016 | Declarative YAML Replication Topology as Primary Mechanism | medium |  |
| [ADR-009](./ADR-009-constructed-attributes.md) | PC-018 | Constructed Attributes via DSA-Side Computation (PARTIAL) | high | ⚠️ |
| [ADR-010](./ADR-010-backup-restore-snapshots.md) | PC-020 | Storage-Engine-Native Backup and Filesystem Snapshots (PARTIAL) | high | ⚠️ |
| [ADR-070](./ADR-070-drsuapi-replication-protocol.md) | PC-001 | Fresh Rust DRSUAPI Server Implementation for AD-Interop Replication | blocker |  |
| [ADR-071](./ADR-071-replication-model.md) | PC-002 | Hybrid Replication Model — DrSuapiReplicator + RaftReplicator behind Replicator Trait | blocker |  |
| [ADR-072](./ADR-072-global-catalog-strategy.md) | PC-005 | Global Catalog as FDB Projection with AD-Interop PAS Replication | high |  |
| [ADR-073](./ADR-073-storage-engine.md) | PC-007 | FoundationDB as Sole Storage Engine for All DCs | blocker |  |
| [ADR-074](./ADR-074-tombstone-lifetime-lingering-objects.md) | PC-009 | Tombstone Lifetime, Lingering Object Detection, and Raft Log Truncation | high |  |
| [ADR-075](./ADR-075-cross-domain-move.md) | PC-010 | Cross-Domain Move via UUID-Stable Identity with Atomic SID Rewrite | medium |  |
| [ADR-076](./ADR-076-fsmo-role-replacement.md) | PC-014 | FSMO Role Replacement — Raft Consensus for Native Mode, Emulation for AD-Interop | high |  |
| [ADR-077](./ADR-077-foreign-security-principals-rid-pool.md) | PC-015 | RID Pool Allocation, Foreign Security Principals, and sIDHistory Migration | high |  |
| [ADR-078](./ADR-078-schema-model.md) | PC-017 | Hybrid Schema Model — LDAP Schema as Source of Truth with Rust Typed Projection | high |  |
| [ADR-079](./ADR-079-dns-in-directory.md) | PC-019 | AD-Integrated DNS Zones via DRSUAPI Replication with Native-Mode CoreDNS+FDB Plugin | high |  |
| [ADR-080](./ADR-080-instancetype-systemflags-bitmasks.md) | PC-021 | instanceType and systemFlags Bitmasks via Typed Projection with Bitflags Macros | medium |  |
| [ADR-081](./ADR-081-multi-tenancy.md) | PC-022 | Multi-Tenancy via Per-Tenant FDB Keyspaces with Hard Isolation | high |  |

### KDC (13 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-011](./ADR-011-rc4-deprecation-aes-default.md) | PC-024 | AES-256 Default with RC4-HMAC Disabled by Default | blocker |  |
| [ADR-012](./ADR-012-fast-armoring-required.md) | PC-026 | FAST (RFC 6806) Armoring Required by Default | high |  |
| [ADR-013](./ADR-013-cross-realm-tgt-referral.md) | PC-028 | RFC 4120 Cross-Realm TGT Referral and Transited-Field Validation | medium |  |
| [ADR-014](./ADR-014-aes-sha384-etype-0x13.md) | PC-029 | AES-SHA384 (etype 0x13) Support with Preference over 0x12 (PARTIAL) | low | ⚠️ |
| [ADR-015](./ADR-015-krbtgt-hsm-rotation.md) | PC-030 | HSM-Bound krbtgt Key with 30-Day Auto-Rotation and 2-Key Overlap | blocker |  |
| [ADR-016](./ADR-016-spn-uniqueness.md) | PC-031 | SPN Uniqueness via Pre-Commit KDC/DSA Check (PARTIAL) | high | ⚠️ |
| [ADR-017](./ADR-017-upn-uniqueness.md) | PC-032 | Forest-Wide UPN Uniqueness Enforced at Write Time | high | ⚠️ |
| [ADR-018](./ADR-018-kdc-horizontal-scaling.md) | PC-033 | KDC as Horizontally-Scalable Stateless Pool Behind Load Balancer | high | ⚠️ |
| [ADR-019](./ADR-019-kpasswd-password-change.md) | PC-034 | kpasswd (RFC 3244) as Primary Password-Change Protocol with REST Wrapper | medium |  |
| [ADR-020](./ADR-020-gmsa-kds-rotation.md) | PC-035 | gMSA with HSM-Bound KDS Root Key and Automatic 30-Day Rotation | high |  |
| [ADR-082](./ADR-082-ms-kile-pac-generation.md) | PC-023 | MS-KILE-Conformant PAC Generation in Fresh Rust KDC | blocker |  |
| [ADR-083](./ADR-083-pac-validation-rpc.md) | PC-025 | PAC Validation via PAC_BUFFER_TICKET_CHECKSUM (Local) + NetrLogonSamLogonEx (Interop) | high |  |
| [ADR-084](./ADR-084-pkinit-fido2-webauthn-bridge.md) | PC-027 | PKINIT via FIDO2/WebAuthn Bridge (with RFC 4556 Smart-Card Path for Compliance) | high |  |

### Auth Provider (7 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-021](./ADR-021-ldap-signing-channel-binding.md) | PC-037 | LDAP Signing, TLS Channel Binding (RFC 5929), and EPA Mandatory by Default | blocker |  |
| [ADR-022](./ADR-022-ntp-chrony-time-sync.md) | PC-041 | Standard NTP via chrony; Drop MS-SNTP; Alert on Clock Skew | high |  |
| [ADR-023](./ADR-023-kerberos-audit-events.md) | PC-042 | Structured Kerberos Audit Events in OpenTelemetry Log Format | high |  |
| [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md) | PC-036 | Drop NTLM Server-Side; Client-Only NTLM via Rust Crate for Legacy Interop | high |  |
| [ADR-086](./ADR-086-pass-the-hash-defense.md) | PC-038 | Pass-the-Hash Defense via NTLM Server Drop + HSM-Bound PEK + Platform Isolation | blocker |  |
| [ADR-087](./ADR-087-s4u-constrained-delegation.md) | PC-039 | S4U2Self + S4U2Proxy Constrained Delegation (with RBCD) in Framework KDC | high |  |
| [ADR-088](./ADR-088-unified-token-abstraction.md) | PC-040 | Unified Token Abstraction via adrian-sdk AuthModule (Windows LSA / Linux PAM / macOS OpenDirectory) | high |  |

### Policy Engine (14 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-024](./ADR-024-per-platform-policy-executors.md) | PC-047 | Per-platform policy executors (CSE / MDM / SSSD-conf) | high | ⚠️ |
| [ADR-025](./ADR-025-transactional-policy-rollback.md) | PC-048 | Transactional policy application with rollback | medium |  |
| [ADR-026](./ADR-026-declarative-host-facts-wmi-adapter.md) | PC-049 | Declarative host facts; WMI filter adapter for interop | medium |  |
| [ADR-027](./ADR-027-http-head-slow-link-detection.md) | PC-050 | HTTP HEAD probe for slow-link detection | low |  |
| [ADR-028](./ADR-028-push-based-policy-websocket.md) | PC-051 | Push-based policy updates via WebSocket | medium |  |
| [ADR-029](./ADR-029-json-canonical-policy-preg-adapter.md) | PC-052 | JSON canonical policy format; PReg adapter | medium |  |
| [ADR-030](./ADR-030-role-based-policy-binding.md) | PC-054 | Role-based policy binding; deprecate Authenticated Users | medium |  |
| [ADR-031](./ADR-031-git-backed-policy-history.md) | PC-056 | Git-backed policy history with PR review | medium |  |
| [ADR-089](./ADR-089-declarative-policy-gpc-gpt-synthesis.md) | PC-043 | Declarative canonical policy format with INI/Registry.pol AD-interop adapter (resolves PC-043) | high |  |
| [ADR-090](./ADR-090-admx-to-declarative-json-compiler.md) | PC-046 | ADMX-to-declarative-JSON compiler `admx2adrian` (resolves PC-046) | high |  |
| [ADR-091](./ADR-091-gpp-preferences-cross-platform-compilation.md) | PC-045 | Group Policy Preferences cross-platform compilation targets (resolves PC-045) | blocker |  |
| [ADR-092](./ADR-092-policy-executor-trait-synthetic-windows-cse.md) | PC-046 | Per-platform policy executor trait `PolicyExecutor` and synthetic Windows CSE (resolves PC-046) | high |  |
| [ADR-093](./ADR-093-sssd-gpo-access-control-enhancement.md) | PC-053 | SSSD GPO access-control enhancement — full Security area coverage via `adrian-sssd-gpo` (resolves PC-053) | high |  |
| [ADR-094](./ADR-094-sysvol-replication-git-backed.md) | PC-055 | SYSVOL-equivalent replication via Git-backed policy repository + SMB read surface (resolves PC-055) | blocker |  |

### Cert Service (11 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-032](./ADR-032-hsm-bound-kra-shamir.md) | PC-060 | HSM-bound KRA keys; Shamir secret sharing M-of-N | high |  |
| [ADR-033](./ADR-033-ocsp-responder-rfc-6960-nonce-ha.md) | PC-061 | OCSP responder per RFC 6960 with nonce; HA cluster | high |  |
| [ADR-034](./ADR-034-transactional-db-pitr-reject-repair.md) | PC-062 | Transactional DB with PITR; reject repair tools | medium | ⚠️ |
| [ADR-035](./ADR-035-multi-cdp-ocsp-cluster-crl-fallback.md) | PC-063 | Multi-CDP HTTP fallback; HA OCSP cluster; CRL fallback | high |  |
| [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md) | PC-065 | Trust-manager model; cross-cert for interop only | low |  |
| [ADR-037](./ADR-037-two-tier-ca-hsm-root.md) | PC-066 | Two-tier CA with HSM-bound root | medium |  |
| [ADR-095](./ADR-095-acme-primary-mswcce-bridge.md) | PC-057 | ACME-primary cert enrollment with MS-WCCE bridge for Windows `autoenroll.dll` (resolves PC-057) | blocker |  |
| [ADR-096](./ADR-096-cert-profile-yaml-replaces-templates.md) | PC-058 | Declarative `cert-profiles.yaml` replaces AD CS certificate templates (resolves PC-058) | high |  |
| [ADR-097](./ADR-097-cross-platform-autoenroll-acme.md) | PC-059 | Cross-platform autoenrollment via Client SDK ACME client + attestation (resolves PC-059) | high |  |
| [ADR-098](./ADR-098-ndes-scep-replacement-bridge.md) | PC-064 | NDES/SCEP replacement via standalone `adrian-scep-bridge` (resolves PC-064) | medium |  |
| [ADR-099](./ADR-099-ntauthcertificates-pkinit-trust.md) | PC-067 | `NTAuthCertificates` replacement via `LogonAuthorizedCAs` directory attribute + trust-manager (resolves PC-067) | high |  |

### Federation Gateway (10 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-038](./ADR-038-jwks-endpoint-webhook-rollover.md) | PC-070 | JWKS endpoint per RFC 8414; webhook notification; 15-day overlap | medium |  |
| [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md) | PC-071 | OIDC primary; WS-Trust-to-OIDC bridge | medium |  |
| [ADR-040](./ADR-040-saml-replay-clock-skew-policy.md) | PC-072 | SAML replay detection 60-min; per-RP skew policy | low |  |
| [ADR-041](./ADR-041-strict-oidc-default-resource-compat.md) | PC-075 | Strict OIDC by default; resource= compat opt-in | medium | ⚠️ |
| [ADR-042](./ADR-042-rms-out-of-scope-recommend-aip.md) | PC-077 | AD RMS out of scope; recommend AIP | low |  |
| [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md) | PC-068 | Replace AD FS farm (WID/SQL + WAP) with Keycloak StatefulSet + Rust shim sidecar | high |  |
| [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md) | PC-069 | AD FS claim rule language compatibility via Rust PEG-based engine | high |  |
| [ADR-102](./ADR-102-rust-shim-wap-replacement.md) | PC-073 | Rust shim as cross-platform WAP replacement — no MS-ADFSPIP, no Windows Server in DMZ | medium |  |
| [ADR-103](./ADR-103-keycloak-statefulset-no-primary-secondary.md) | PC-074 | PostgreSQL multi-primary replaces AD FS WID primary-secondary farm topology | medium |  |
| [ADR-104](./ADR-104-keycloak-identity-brokering-hrd.md) | PC-076 | Keycloak identity brokering with home realm discovery — per-tenant IdP routing | medium |  |

### File Gateway (7 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-043](./ADR-043-drop-smb1-support.md) | PC-079 | Drop SMB1 Support Entirely | blocker | ⚠️ |
| [ADR-044](./ADR-044-dfs-n-via-dns-srv.md) | PC-080 | DFS-N-Equivalent via DNS SRV | high | ⚠️ |
| [ADR-045](./ADR-045-abe-precomputed-index.md) | PC-082 | Access-Based Enumeration with Pre-computed Per-Share Index | medium | ⚠️ |
| [ADR-046](./ADR-046-drop-msrprn-adopt-ipp-everywhere.md) | PC-083 | Drop MS-RPRN; Adopt IPP Everywhere | blocker | ⚠️ |
| [ADR-047](./ADR-047-offline-files-out-of-scope.md) | PC-084 | Offline Files Out of Scope; Recommend Sync Clients | medium | ⚠️ |
| [ADR-105](./ADR-105-fresh-rust-smb3-server.md) | PC-078 | Fresh Rust SMB 3.1.1 server — SHA-512 preauth integrity, AES-256-GCM, no Samba | blocker |  |
| [ADR-106](./ADR-106-smb-client-persistent-handles-sdk-filemodule.md) | PC-081 | SMB client as Rust SDK FileModule — fresh implementation with persistent-handle reconnect for CA shares | high |  |

### Client SDK (9 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md) | PC-087 | PSSO Extension as Modern macOS Path; Jamf Connect Migration | medium | ⚠️ |
| [ADR-049](./ADR-049-standardize-mit-krb5.md) | PC-090 | Standardize on MIT krb5 on Linux/macOS | medium | ⚠️ |
| [ADR-050](./ADR-050-authselect-standard-pam.md) | PC-092 | Adopt authselect as Standard PAM Profile Mechanism | medium | ⚠️ |
| [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) | PC-093 | KCM on Linux; API: on macOS; Unified Cache Abstraction | medium | ⚠️ |
| [ADR-107](./ADR-107-unified-rust-core-sdk.md) | PC-085 | Unified Rust Core SDK with Platform-Specific Bindings | blocker |  |
| [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) | PC-086 | SSPI-Equivalent Unified Auth Abstraction in adrian-sdk | high |  |
| [ADR-109](./ADR-109-cross-platform-ldap-client.md) | PC-088 | Cross-Platform LDAP Client Library (Wldap32 Equivalent) in adrian-sdk | high |  |
| [ADR-110](./ADR-110-sid-to-uid-mapping-uuid-primary.md) | PC-089 | SID-to-UID Mapping via UUID-Primary Identity + Direct POSIX UID | blocker |  |
| [ADR-111](./ADR-111-unified-ticket-cache-abstraction.md) | PC-091 | Unified Ticket Cache Abstraction — KCM on Linux, API: on macOS, LSA on Windows | medium |  |

### Cross-Platform Parity (12 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-052](./ADR-052-ddm-first-authoring.md) | PC-096 | DDM-First Authoring; Auto-Fallback to Configuration Profile | low |  |
| [ADR-053](./ADR-053-key-escrow-and-nbde.md) | PC-097 | Support Both Per-Computer Key Escrow and NBDE | medium | ⚠️ |
| [ADR-054](./ADR-054-per-host-laps-rotation.md) | PC-098 | Per-Host Local-Admin Password Rotation; LAPS Schema | medium | ⚠️ |
| [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md) | PC-104 | Document Migration Paths; dzdo to sudoers Import | low | ⚠️ |
| [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) | PC-105 | PSSO as Modern macOS Kerberos Path | medium |  |
| [ADR-112](./ADR-112-macos-ntlm-client-rust-crate.md) | PC-094 | macOS NTLM Client Gap Closed by adrian-ntlm-client Rust Crate | high |  |
| [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md) | PC-095 | GPO Preferences and Cross-Platform Policy Compilation | blocker |  |
| [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md) | PC-099 | Linux Identity Stack — SSSD Primary, Winbind Deprecated, PBIS Unsupported | medium |  |
| [ADR-115](./ADR-115-freeipa-alternative-linux-tier.md) | PC-100 | FreeIPA as Supported Alternative Linux Tier via Cross-Realm Trust | medium |  |
| [ADR-116](./ADR-116-legacy-macos-agents-eol.md) | PC-101 | Legacy macOS Agents (NoMAD / Enterprise Connect / Jamf Connect / Centrify / PBIS) EOL | medium |  |
| [ADR-117](./ADR-117-apple-heimdal-fork-staleness-mitigated.md) | PC-102 | Apple Heimdal Fork Staleness Mitigated by Fresh Rust KDC + Unified PAC Validator | medium |  |
| [ADR-118](./ADR-118-mcx-legacy-macos-mdm-ddm-migration.md) | PC-103 | MCX Legacy on macOS — Migrate to MDM Configuration Profiles + DDM | low |  |

### Operations (10 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-057](./ADR-057-prometheus-otel-observability.md) | PC-106 | Prometheus Exporter + OpenTelemetry Instrumentation | high |  |
| [ADR-058](./ADR-058-container-native-dcs-operator.md) | PC-109 | Container-Native DCs + Kubernetes Operator | high | ⚠️ |
| [ADR-059](./ADR-059-pitr-backup-dr-runbooks.md) | PC-110 | Per-DC Backup with PITR + Operator-Driven DR Runbooks | high | ⚠️ |
| [ADR-060](./ADR-060-structured-audit-logs-otel.md) | PC-111 | Structured Audit Logs in OTel Format + MITRE ATT&CK Mapping | high |  |
| [ADR-061](./ADR-061-rest-grpc-api.md) | PC-112 | REST API for CRUD + gRPC for Streaming (GraphQL Deferred) | high | ⚠️ |
| [ADR-062](./ADR-062-trust-password-auto-rotation.md) | PC-114 | Auto-Rotate Trust Passwords + Auto-Reset on Desync | medium | ⚠️ |
| [ADR-063](./ADR-063-unified-cross-platform-cli.md) | PC-115 | Unified Cross-Platform CLI (Implementation Language Deferred) | medium | ⚠️ |
| [ADR-119](./ADR-119-schema-as-code-gitops.md) | PC-107 | Schema-as-Code with GitOps — Reversible Migrations, Typed Projection Regeneration | high | ⚠️ |
| [ADR-120](./ADR-120-multi-region-replication-topology.md) | PC-108 | Multi-Region Replication — Hybrid DRSUAPI + Raft with Locality-Aware Leader Placement | high | ⚠️ |
| [ADR-121](./ADR-121-functional-levels-capability-flags.md) | PC-113 | Replace Functional Levels with Per-Feature Capability Flags + DC Capabilities Exchange | medium | ⚠️ |

### Security (8 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-064](./ADR-064-kerberoasting-aes-migration.md) | PC-116 | Kerberoasting Mitigation — AES-Only Migration + Detection | blocker | ⚠️ |
| [ADR-065](./ADR-065-krbtgt-hsm-rotation.md) | PC-118 | HSM-Bound krbtgt + Auto-Rotation for Golden-Ticket Mitigation | blocker | ⚠️ |
| [ADR-066](./ADR-066-adminsdholder-declarative-rbac.md) | PC-122 | Replace AdminSDHolder with Declarative RBAC | medium | ⚠️ |
| [ADR-067](./ADR-067-sigstore-supply-chain.md) | PC-123 | Sigstore Signing + in-toto Attestations for Supply-Chain Security | medium | ⚠️ |
| [ADR-122](./ADR-122-dcsync-mitigation.md) | PC-117 | DCSync Mitigation — Per-Principal Replication-Get-Changes Audit + HSM-Bound Break-Glass | blocker | ⚠️ |
| [ADR-123](./ADR-123-silver-ticket-mitigation.md) | PC-119 | Silver Ticket Mitigation — Mandatory PAC_BUFFER_TICKET_CHECKSUM + Default Service-Side Validation | high | ⚠️ |
| [ADR-124](./ADR-124-sidhistory-injection-mitigation.md) | PC-120 | sIDHistory Injection Mitigation — Default-On Filtering on All Trusts + Per-Write Audit | high | ⚠️ |
| [ADR-125](./ADR-125-selective-authentication-hbac.md) | PC-121 | Selective Authentication Replaced by HBAC-Equivalent Policy Rules + Per-Host Evaluation | medium | ⚠️ |

### Migration (7 ADRs)

| ADR | Problem | Title | Severity | Partial? |
|-----|---------|-------|----------|----------|
| [ADR-068](./ADR-068-subdomain-dns-strategy.md) | PC-128 | Subdomain-per-Directory DNS Strategy for Migration | medium |  |
| [ADR-069](./ADR-069-cross-realm-capaths.md) | PC-129 | Auto-Generate Kerberos capaths + DNS SRV KDC Discovery | medium | ⚠️ |
| [ADR-126](./ADR-126-sidhistory-migration.md) | PC-124 | sIDHistory Migration — DRSAddSidHistory + Time-Limited Passthrough Window + ACL Re-write Plan | high | ⚠️ |
| [ADR-127](./ADR-127-gpo-translation.md) | PC-125 | GPO Translation — ADMX-to-Canonical-JSON Compiler + Per-Setting Review Workflow | high | ⚠️ |
| [ADR-128](./ADR-128-kerberos-cross-realm-migration.md) | PC-126 | Kerberos Cross-Realm with AD During Migration — Per-SPN/Per-User/Per-Host Granularity | high | ⚠️ |
| [ADR-129](./ADR-129-password-hash-migration.md) | PC-127 | Password Hash Migration — Framework-Side Sync Agent with DRSUAPI Pull + LDAP Modify Push | high | ⚠️ |
| [ADR-130](./ADR-130-sysvol-migration.md) | PC-130 | SYSVOL Migration — SMB-Served Git-Backed Policy Share + HTTPS Distribution + DFS-N Referral | medium | ⚠️ |

⚠️ = PARTIAL ADR (defers a sub-decision to a Tier-1 ORQ; see ADR's "Open Questions")

## PARTIAL ADRs

These ADRs make a confident decision for part of the problem and explicitly defer the rest to a Tier-1 ORQ.

| ADR | Problem | Deferred sub-decision | Gating ORQs |
|-----|---------|----------------------|-------------|
| [ADR-001](./ADR-001-linked-value-replication.md) | PC-003 | Linked Value Replication for Multi-Valued Linked Attributes | ORQ-001, ORQ-032 |
| [ADR-002](./ADR-002-memberof-back-link.md) | PC-004 | memberOf Back-Link as DSA-Computed linkID Pair | ORQ-026 |
| [ADR-003](./ADR-003-schema-cache-cow.md) | PC-006 | Copy-on-Write Schema Cache with Monotonic Generation Numbers | ORQ-001 |
| [ADR-004](./ADR-004-sd-deduplication.md) | PC-008 | Security Descriptor Deduplication via Content-Hash Indexed Table | ORQ-001 |
| [ADR-009](./ADR-009-constructed-attributes.md) | PC-018 | Constructed Attributes via DSA-Side Computation (PARTIAL) | ORQ-032 |
| [ADR-010](./ADR-010-backup-restore-snapshots.md) | PC-020 | Storage-Engine-Native Backup and Filesystem Snapshots (PARTIAL) | ORQ-011 |
| [ADR-014](./ADR-014-aes-sha384-etype-0x13.md) | PC-029 | AES-SHA384 (etype 0x13) Support with Preference over 0x12 (PARTIAL) | ORQ-055, ORQ-056 |
| [ADR-016](./ADR-016-spn-uniqueness.md) | PC-031 | SPN Uniqueness via Pre-Commit KDC/DSA Check (PARTIAL) | ORQ-059, ORQ-060 |
| [ADR-017](./ADR-017-upn-uniqueness.md) | PC-032 | Forest-Wide UPN Uniqueness Enforced at Write Time | ORQ-061, ORQ-062 |
| [ADR-018](./ADR-018-kdc-horizontal-scaling.md) | PC-033 | KDC as Horizontally-Scalable Stateless Pool Behind Load Balancer | ORQ-032 |
| [ADR-024](./ADR-024-per-platform-policy-executors.md) | PC-047 | Per-platform policy executors (CSE / MDM / SSSD-conf) | ORQ-090, ORQ-091 |
| [ADR-034](./ADR-034-transactional-db-pitr-reject-repair.md) | PC-062 | Transactional DB with PITR; reject repair tools | ORQ-120, ORQ-121 |
| [ADR-041](./ADR-041-strict-oidc-default-resource-compat.md) | PC-075 | Strict OIDC by default; resource= compat opt-in | ORQ-132 |
| [ADR-043](./ADR-043-drop-smb1-support.md) | PC-079 | Drop SMB1 Support Entirely | ORQ-154 |
| [ADR-044](./ADR-044-dfs-n-via-dns-srv.md) | PC-080 | DFS-N-Equivalent via DNS SRV | ORQ-001, ORQ-002 |
| [ADR-045](./ADR-045-abe-precomputed-index.md) | PC-082 | Access-Based Enumeration with Pre-computed Per-Share Index | ORQ-154 |
| [ADR-046](./ADR-046-drop-msrprn-adopt-ipp-everywhere.md) | PC-083 | Drop MS-RPRN; Adopt IPP Everywhere | ORQ-154 |
| [ADR-047](./ADR-047-offline-files-out-of-scope.md) | PC-084 | Offline Files Out of Scope; Recommend Sync Clients | ORQ-154 |
| [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md) | PC-087 | PSSO Extension as Modern macOS Path; Jamf Connect Migration | ORQ-169 |
| [ADR-049](./ADR-049-standardize-mit-krb5.md) | PC-090 | Standardize on MIT krb5 on Linux/macOS | ORQ-169 |
| [ADR-050](./ADR-050-authselect-standard-pam.md) | PC-092 | Adopt authselect as Standard PAM Profile Mechanism | ORQ-202 |
| [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) | PC-093 | KCM on Linux; API: on macOS; Unified Cache Abstraction | ORQ-169 |
| [ADR-053](./ADR-053-key-escrow-and-nbde.md) | PC-097 | Support Both Per-Computer Key Escrow and NBDE | ORQ-026 |
| [ADR-054](./ADR-054-per-host-laps-rotation.md) | PC-098 | Per-Host Local-Admin Password Rotation; LAPS Schema | ORQ-026 |
| [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md) | PC-104 | Document Migration Paths; dzdo to sudoers Import | ORQ-169 |
| [ADR-058](./ADR-058-container-native-dcs-operator.md) | PC-109 | Container-Native DCs + Kubernetes Operator | ORQ-011 |
| [ADR-059](./ADR-059-pitr-backup-dr-runbooks.md) | PC-110 | Per-DC Backup with PITR + Operator-Driven DR Runbooks | ORQ-011 |
| [ADR-061](./ADR-061-rest-grpc-api.md) | PC-112 | REST API for CRUD + gRPC for Streaming (GraphQL Deferred) | ORQ-226, ORQ-227, ORQ-228 |
| [ADR-062](./ADR-062-trust-password-auto-rotation.md) | PC-114 | Auto-Rotate Trust Passwords + Auto-Reset on Desync | ORQ-001 |
| [ADR-063](./ADR-063-unified-cross-platform-cli.md) | PC-115 | Unified Cross-Platform CLI (Implementation Language Deferred) | ORQ-169, ORQ-229, ORQ-230, ORQ-231 |
| [ADR-064](./ADR-064-kerberoasting-aes-migration.md) | PC-116 | Kerberoasting Mitigation — AES-Only Migration + Detection | ORQ-042 |
| [ADR-065](./ADR-065-krbtgt-hsm-rotation.md) | PC-118 | HSM-Bound krbtgt + Auto-Rotation for Golden-Ticket Mitigation | ORQ-042 |
| [ADR-066](./ADR-066-adminsdholder-declarative-rbac.md) | PC-122 | Replace AdminSDHolder with Declarative RBAC | ORQ-011 |
| [ADR-067](./ADR-067-sigstore-supply-chain.md) | PC-123 | Sigstore Signing + in-toto Attestations for Supply-Chain Security | ORQ-011 |
| [ADR-069](./ADR-069-cross-realm-capaths.md) | PC-129 | Auto-Generate Kerberos capaths + DNS SRV KDC Discovery | ORQ-042 |
| [ADR-119](./ADR-119-schema-as-code-gitops.md) | PC-107 | Schema-as-Code with GitOps — Reversible Migrations, Typed Projection Regeneration | ORQ-030 |
| [ADR-120](./ADR-120-multi-region-replication-topology.md) | PC-108 | Multi-Region Replication — Hybrid DRSUAPI + Raft with Locality-Aware Leader Placement | ORQ-001 |
| [ADR-121](./ADR-121-functional-levels-capability-flags.md) | PC-113 | Replace Functional Levels with Per-Feature Capability Flags + DC Capabilities Exchange | ORQ-030 |
| [ADR-122](./ADR-122-dcsync-mitigation.md) | PC-117 | DCSync Mitigation — Per-Principal Replication-Get-Changes Audit + HSM-Bound Break-Glass | ORQ-001 |
| [ADR-123](./ADR-123-silver-ticket-mitigation.md) | PC-119 | Silver Ticket Mitigation — Mandatory PAC_BUFFER_TICKET_CHECKSUM + Default Service-Side Validation | ORQ-042 |
| [ADR-124](./ADR-124-sidhistory-injection-mitigation.md) | PC-120 | sIDHistory Injection Mitigation — Default-On Filtering on All Trusts + Per-Write Audit | ORQ-026 |
| [ADR-125](./ADR-125-selective-authentication-hbac.md) | PC-121 | Selective Authentication Replaced by HBAC-Equivalent Policy Rules + Per-Host Evaluation | ORQ-202 |
| [ADR-126](./ADR-126-sidhistory-migration.md) | PC-124 | sIDHistory Migration — DRSAddSidHistory + Time-Limited Passthrough Window + ACL Re-write Plan | ORQ-026 |
| [ADR-127](./ADR-127-gpo-translation.md) | PC-125 | GPO Translation — ADMX-to-Canonical-JSON Compiler + Per-Setting Review Workflow | ORQ-030, ORQ-090 |
| [ADR-128](./ADR-128-kerberos-cross-realm-migration.md) | PC-126 | Kerberos Cross-Realm with AD During Migration — Per-SPN/Per-User/Per-Host Granularity | ORQ-001, ORQ-042 |
| [ADR-129](./ADR-129-password-hash-migration.md) | PC-127 | Password Hash Migration — Framework-Side Sync Agent with DRSUAPI Pull + LDAP Modify Push | ORQ-026 |
| [ADR-130](./ADR-130-sysvol-migration.md) | PC-130 | SYSVOL Migration — SMB-Served Git-Backed Policy Share + HTTPS Distribution + DFS-N Referral | ORQ-001, ORQ-154 |

## Cross-ADR clusters

Several ADRs are tightly coupled and must be implemented together:

- **Kerberos etype cluster**: ADR-011 (AES-256 default), ADR-014 (etype 0x13 partial), ADR-016 (SPN uniqueness), ADR-017 (UPN uniqueness), ADR-018 (KDC horizontal scaling), ADR-020 (gMSA KDS root key)
- **Krbtgt HSM cluster**: ADR-015 (KDC krbtgt HSM rotation), ADR-020 (gMSA KDS root key), ADR-065 (Security golden ticket mitigation)
- **Audit cluster**: ADR-023 (Kerberos audit OTel), ADR-060 (structured audit log OTel), ADR-064 (Kerberoasting detection), ADR-065 (golden ticket detection)
- **Policy cluster**: ADR-024 (per-platform executors), ADR-025 (transactional rollback), ADR-028 (push via WebSocket), ADR-029 (JSON canonical + PReg adapter), ADR-030 (role-based binding), ADR-031 (git-backed history)
- **PKI cluster**: ADR-032 (HSM KRA), ADR-033 (OCSP), ADR-035 (multi-CDP), ADR-036 (trust manager), ADR-037 (two-tier CA)
- **Federation cluster**: ADR-038 (JWKS), ADR-039 (OIDC primary), ADR-040 (SAML replay), ADR-041 (strict OIDC)
- **Time sync cluster**: ADR-022 (NTP chrony), ADR-040 (SAML clock skew)
- **Migration cluster**: ADR-068 (DNS subdomain), ADR-069 (cross-realm capaths)

## Deferred problems

61 problems are deferred pending Tier-1 ORQ resolution. See [TRIAGE.md](./TRIAGE.md) for the full deferral rationale and [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md) for the research spike plan.

## Maintenance

ADRs are immutable once Accepted. To change a decision:

1. Write a new ADR that supersedes the old one (e.g., ADR-070 supersedes ADR-015).
2. Update the old ADR's status to `Superseded by ADR-070`.
3. Update this README's tables.
4. Update the [CHANGELOG](../CHANGELOG.md).

## See also

- [TRIAGE.md](./TRIAGE.md) — the triage document that decided which problems got ADRs
- [catalog/README.md](../catalog/README.md) — the problem catalog
- [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md) — the 262 ORQs gating deferred problems
- [draft/06-roadmap.md](../draft/06-roadmap.md) — the 6-phase roadmap referencing these ADRs
