---
title: Appendices
audience: architects-and-engineers
tags: [final-draft, appendices, adr-index, workshop-decisions, rust-crates, external-dependencies, glossary]
related:
  - ./04-cross-platform-parity.md
  - ./05-security-architecture.md
  - ./06-implementation-roadmap.md
  - ../adr/README.md
  - ../workshop/CONTEXT.md
last_updated: 2026-08-13
---

# Appendices

## Appendix A: ADR index

The definitive PC → ADR mapping. 130 ADRs total, grouped by capability. Severity: **B** = blocker (23), **H** = high (64), **M** = medium (33), **L** = low (10). ADRs marked ⚠️ are PARTIAL (defer a sub-decision to a Tier-1 ORQ; see [`adr/TRIAGE.md`](../adr/TRIAGE.md)).

### Core Directory (25 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-001 | PC-003 | H ⚠️ | Linked Value Replication for Multi-Valued Linked Attributes |
| ADR-002 | PC-004 | B ⚠️ | memberOf Back-Link as DSA-Computed linkID Pair |
| ADR-003 | PC-006 | M ⚠️ | Copy-on-Write Schema Cache with Monotonic Generation Numbers |
| ADR-004 | PC-008 | M ⚠️ | Security Descriptor Deduplication via Content-Hash Indexed Table |
| ADR-005 | PC-011 | M | Reserve and Honor Well-Known Container GUIDs |
| ADR-006 | PC-012 | H | AD-Specific LDAP Controls for Client Interop |
| ADR-007 | PC-013 | M | kpasswd as Primary Password-Change Protocol; BER-Quote unicodePwd in AD-Compat |
| ADR-008 | PC-016 | M | Declarative YAML Replication Topology |
| ADR-009 | PC-018 | H ⚠️ | Constructed Attributes via DSA-Side Computation |
| ADR-010 | PC-020 | H ⚠️ | Storage-Engine-Native Backup and Filesystem Snapshots |
| ADR-070 | PC-001 | B | Fresh Rust DRSUAPI Server for AD-Interop Replication |
| ADR-071 | PC-002 | B | Hybrid Replication Model — DrSuapiReplicator + RaftReplicator |
| ADR-072 | PC-005 | H | Global Catalog as FDB Projection |
| ADR-073 | PC-007 | B | FoundationDB as Sole Storage Engine |
| ADR-074 | PC-009 | H | Tombstone Lifetime, Lingering Object Detection, Raft Log Truncation |
| ADR-075 | PC-010 | M | Cross-Domain Move via UUID-Stable Identity |
| ADR-076 | PC-014 | H | FSMO Role Replacement — Raft for Native, Emulation for AD-Interop |
| ADR-077 | PC-015 | H | RID Pool Allocation, Foreign Security Principals, sIDHistory Migration |
| ADR-078 | PC-017 | H | Hybrid Schema Model — LDAP Schema + Rust Typed Projection |
| ADR-079 | PC-019 | H | AD-Integrated DNS Zones via DRSUAPI; Native CoreDNS+FDB Plugin |
| ADR-080 | PC-021 | M | instanceType and systemFlags Bitmasks via Typed Projection |
| ADR-081 | PC-022 | H | Multi-Tenancy via Per-Tenant FDB Keyspaces |
| ADR-119 | PC-107 | H | Schema-as-Code with GitOps — Reversible Migrations |
| ADR-120 | PC-108 | H | Multi-Region Replication — Hybrid DRSUAPI + Raft with Locality-Aware Leader |
| ADR-121 | PC-113 | M | Replace Functional Levels with Per-Feature Capability Flags |

### KDC (12 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-011 | PC-024 | B | AES-256 Default with RC4-HMAC Disabled by Default |
| ADR-012 | PC-026 | H | FAST (RFC 6806) Armoring Required by Default |
| ADR-013 | PC-028 | M | RFC 4120 Cross-Realm TGT Referral and Transited-Field Validation |
| ADR-014 | PC-029 | L ⚠️ | AES-SHA384 (etype 0x13) Support with Preference over 0x12 |
| ADR-015 | PC-030 | B | HSM-Bound krbtgt Key with 30-Day Auto-Rotation and 2-Key Overlap |
| ADR-016 | PC-031 | H ⚠️ | SPN Uniqueness via Pre-Commit KDC/DSA Check |
| ADR-017 | PC-032 | H | Forest-Wide UPN Uniqueness Enforced at Write Time |
| ADR-018 | PC-033 | H | KDC as Horizontally-Scalable Stateless Pool Behind Load Balancer |
| ADR-019 | PC-034 | M | kpasswd (RFC 3244) with REST Wrapper |
| ADR-020 | PC-035 | H | gMSA with HSM-Bound KDS Root Key and Automatic 30-Day Rotation |
| ADR-082 | PC-023 | B | MS-KILE-Conformant PAC Generation in Fresh Rust KDC |
| ADR-083 | PC-025 | H | PAC Validation via PAC_BUFFER_TICKET_CHECKSUM + NetrLogonSamLogonEx |
| ADR-084 | PC-027 | H | PKINIT via FIDO2/WebAuthn Bridge (+ RFC 4556 Smart-Card Path) |

### Auth Provider (7 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-021 | PC-037 | B | LDAP Signing, TLS Channel Binding (RFC 5929), and EPA Mandatory |
| ADR-022 | PC-041 | H | Standard NTP via chrony; Drop MS-SNTP; Alert on Clock Skew |
| ADR-023 | PC-042 | H | Structured Kerberos Audit Events in OpenTelemetry Log Format |
| ADR-085 | PC-036 | H | Drop NTLM Server-Side; Client-Only NTLM via Rust Crate |
| ADR-086 | PC-038 | B | Pass-the-Hash Defense via NTLM Server Drop + HSM-Bound PEK + Platform Isolation |
| ADR-087 | PC-039 | H | S4U2Self + S4U2Proxy Constrained Delegation (with RBCD) |
| ADR-088 | PC-040 | H | Unified Token Abstraction via adrian-sdk AuthModule |

### Policy Engine (12 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-024 | PC-047 | H ⚠️ | Per-platform policy executors (CSE / MDM / SSSD-conf) |
| ADR-025 | PC-048 | M | Transactional policy application with rollback |
| ADR-026 | PC-049 | M | Declarative host facts; WMI filter adapter for interop |
| ADR-027 | PC-050 | L | HTTP HEAD probe for slow-link detection |
| ADR-028 | PC-051 | M | Push-based policy updates via WebSocket |
| ADR-029 | PC-052 | M | JSON canonical policy format; PReg adapter |
| ADR-030 | PC-054 | M | Role-based policy binding; deprecate Authenticated Users |
| ADR-031 | PC-056 | M | Git-backed policy history with PR review |
| ADR-089 | PC-043 | H | Declarative canonical policy format with INI/Registry.pol AD-interop adapter |
| ADR-090 | PC-046 | H | ADMX-to-declarative-JSON compiler `admx2adrian` |
| ADR-091 | PC-045 | B | Group Policy Preferences cross-platform compilation targets |
| ADR-092 | PC-046 | H | Per-platform policy executor trait `PolicyExecutor` and synthetic Windows CSE |
| ADR-093 | PC-053 | H | SSSD GPO access-control enhancement via `adrian-sssd-gpo` |
| ADR-094 | PC-055 | B | SYSVOL-equivalent replication via Git-backed policy repository + SMB read surface |
| ADR-127 | PC-125 | H | GPO Translation — ADMX-to-Canonical-JSON Compiler + Per-Setting Review Workflow |

### Cert Service (10 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-032 | PC-060 | H | HSM-bound KRA keys; Shamir secret sharing M-of-N |
| ADR-033 | PC-061 | H | OCSP responder per RFC 6960 with nonce; HA cluster |
| ADR-034 | PC-062 | M ⚠️ | Transactional DB with PITR; reject repair tools |
| ADR-035 | PC-063 | H | Multi-CDP HTTP fallback; HA OCSP cluster; CRL fallback |
| ADR-036 | PC-065 | L | Trust-manager model; cross-cert for interop only |
| ADR-037 | PC-066 | M | Two-tier CA with HSM-bound root |
| ADR-095 | PC-057 | B | ACME-primary cert enrollment with MS-WCCE bridge |
| ADR-096 | PC-058 | H | Declarative `cert-profiles.yaml` replaces AD CS certificate templates |
| ADR-097 | PC-059 | H | Cross-platform autoenrollment via Client SDK ACME client + attestation |
| ADR-098 | PC-064 | M | NDES/SCEP replacement via standalone `adrian-scep-bridge` |
| ADR-099 | PC-067 | H | `NTAuthCertificates` replacement via `LogonAuthorizedCAs` directory attribute |

### Federation Gateway (10 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-038 | PC-070 | M | JWKS endpoint per RFC 8414; webhook notification; 15-day overlap |
| ADR-039 | PC-071 | M | OIDC primary; WS-Trust-to-OIDC bridge |
| ADR-040 | PC-072 | L | SAML replay detection 60-min; per-RP skew policy |
| ADR-041 | PC-075 | M ⚠️ | Strict OIDC by default; resource= compat opt-in |
| ADR-042 | PC-077 | L | AD RMS out of scope; recommend AIP |
| ADR-100 | PC-068 | H | Replace AD FS farm (WID/SQL + WAP) with Keycloak StatefulSet + Rust shim |
| ADR-101 | PC-069 | H | AD FS claim rule language compatibility via Rust PEG-based engine |
| ADR-102 | PC-073 | M | Rust shim as cross-platform WAP replacement |
| ADR-103 | PC-074 | M | PostgreSQL multi-primary replaces AD FS WID primary-secondary farm topology |
| ADR-104 | PC-076 | M | Keycloak identity brokering with home realm discovery |

### File Gateway (7 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-043 | PC-079 | B ⚠️ | Drop SMB1 Support Entirely |
| ADR-044 | PC-080 | H ⚠️ | DFS-N-Equivalent via DNS SRV |
| ADR-045 | PC-082 | M ⚠️ | Access-Based Enumeration with Pre-computed Per-Share Index |
| ADR-046 | PC-083 | B ⚠️ | Drop MS-RPRN; Adopt IPP Everywhere |
| ADR-047 | PC-084 | M ⚠️ | Offline Files Out of Scope; Recommend Sync Clients |
| ADR-105 | PC-078 | B | Fresh Rust SMB 3.1.1 server — SHA-512 preauth integrity, AES-256-GCM, no Samba |
| ADR-106 | PC-081 | H | SMB client as Rust SDK FileModule — persistent-handle reconnect for CA shares |
| ADR-130 | PC-130 | M | SYSVOL Migration — SMB-Served Git-Backed Policy Share + DFS-N Referral |

### Client SDK (8 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-048 | PC-087 | M ⚠️ | PSSO Extension as Modern macOS Path; Jamf Connect Migration |
| ADR-049 | PC-090 | M ⚠️ | Standardize on MIT krb5 on Linux/macOS |
| ADR-050 | PC-092 | M ⚠️ | Adopt authselect as Standard PAM Profile Mechanism |
| ADR-051 | PC-093 | M ⚠️ | KCM on Linux; API: on macOS; Unified Cache Abstraction |
| ADR-107 | PC-085 | B | Unified Rust Core SDK with Platform-Specific Bindings |
| ADR-108 | PC-086 | H | SSPI-Equivalent Unified Auth Abstraction in adrian-sdk |
| ADR-109 | PC-088 | H | Cross-Platform LDAP Client Library (Wldap32 Equivalent) |
| ADR-110 | PC-089 | B | SID-to-UID Mapping via UUID-Primary Identity + Direct POSIX UID |
| ADR-111 | PC-091 | M | Unified Ticket Cache Abstraction — KCM/API:/LSA |

### Cross-Platform Parity (10 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-052 | PC-096 | L | DDM-First Authoring; Auto-Fallback to Configuration Profile |
| ADR-053 | PC-097 | M ⚠️ | Support Both Per-Computer Key Escrow and NBDE |
| ADR-054 | PC-098 | M ⚠️ | Per-Host Local-Admin Password Rotation; LAPS Schema |
| ADR-055 | PC-104 | L ⚠️ | Document Migration Paths; dzdo to sudoers Import |
| ADR-056 | PC-105 | M | PSSO as Modern macOS Kerberos Path |
| ADR-112 | PC-094 | H | macOS NTLM Client Gap Closed by adrian-ntlm-client Rust Crate |
| ADR-113 | PC-095 | B | GPO Preferences and Cross-Platform Policy Compilation |
| ADR-114 | PC-099 | M | Linux Identity Stack — SSSD Primary, Winbind Deprecated, PBIS Unsupported |
| ADR-115 | PC-100 | M | FreeIPA as Supported Alternative Linux Tier via Cross-Realm Trust |
| ADR-116 | PC-101 | M | Legacy macOS Agents (NoMAD / Enterprise Connect / Jamf Connect / Centrify / PBIS) EOL |
| ADR-117 | PC-102 | M | Apple Heimdal Fork Staleness Mitigated by Fresh Rust KDC + Unified PAC Validator |
| ADR-118 | PC-103 | L | MCX Legacy on macOS — Migrate to MDM Configuration Profiles + DDM |

### Operations (10 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-057 | PC-106 | H | Prometheus Exporter + OpenTelemetry Instrumentation |
| ADR-058 | PC-109 | H ⚠️ | Container-Native DCs + Kubernetes Operator |
| ADR-059 | PC-110 | H ⚠️ | Per-DC Backup with PITR + Operator-Driven DR Runbooks |
| ADR-060 | PC-111 | H | Structured Audit Logs in OTel Format + MITRE ATT&CK Mapping |
| ADR-061 | PC-112 | H ⚠️ | REST API for CRUD + gRPC for Streaming (GraphQL Deferred) |
| ADR-062 | PC-114 | M ⚠️ | Auto-Rotate Trust Passwords + Auto-Reset on Desync |
| ADR-063 | PC-115 | M ⚠️ | Unified Cross-Platform CLI |

### Security (8 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-064 | PC-116 | B ⚠️ | Kerberoasting Mitigation — AES-Only Migration + Detection |
| ADR-065 | PC-118 | B ⚠️ | HSM-Bound krbtgt + Auto-Rotation for Golden-Ticket Mitigation |
| ADR-066 | PC-122 | M ⚠️ | Replace AdminSDHolder with Declarative RBAC |
| ADR-067 | PC-123 | M ⚠️ | Sigstore Signing + in-toto Attestations for Supply-Chain Security |
| ADR-122 | PC-117 | B | DCSync Mitigation — Per-Principal Replication-Get-Changes Audit + HSM-Bound Break-Glass |
| ADR-123 | PC-119 | H | Silver Ticket Mitigation — Mandatory PAC_BUFFER_TICKET_CHECKSUM + Default Service-Side Validation |
| ADR-124 | PC-120 | H | sIDHistory Injection Mitigation — Default-On Filtering on All Trusts |
| ADR-125 | PC-121 | M | Selective Authentication Replaced by HBAC-Equivalent Policy Rules |

### Migration (7 ADRs)

| ADR | PC | Sev | Title |
|-----|----|----|-------|
| ADR-068 | PC-128 | M | Subdomain-per-Directory DNS Strategy for Migration |
| ADR-069 | PC-129 | M ⚠️ | Auto-Generate Kerberos capaths + DNS SRV KDC Discovery |
| ADR-126 | PC-124 | H | sIDHistory Migration — DRSAddSidHistory + Time-Limited Passthrough Window |
| ADR-127 | PC-125 | H | GPO Translation — ADMX-to-Canonical-JSON Compiler + Per-Setting Review |
| ADR-128 | PC-126 | H | Kerberos Cross-Realm with AD During Migration — Per-SPN/Per-User/Per-Host Granularity |
| ADR-129 | PC-127 | H | Password Hash Migration — Framework-Side Sync Agent with DRSUAPI Pull + LDAP Modify Push |
| ADR-130 | PC-130 | M | SYSVOL Migration — SMB-Served Git-Backed Policy Share + HTTPS Distribution + DFS-N Referral |

## Appendix B: Workshop decisions

The Tier-1 ORQ Resolution Workshop produced 12 decisions ([`workshop/CONTEXT.md`](../workshop/CONTEXT.md)), each resolving one cluster of Open Research Questions and unblocking a set of deferred problems.

| Decision | ORQs resolved | Title (short) | Rust crates | Problems unblocked |
|----------|---------------|---------------|-------------|--------------------|
| Decision 1 | ORQ-001/002/003/004 | Hybrid Replication — Fresh Rust DRSUAPI for AD-Interop, Raft for Native | adrian-drsuapi, adrian-raft, adrian-repl-core, adrian-repl-health, openraft, rasn, rasn-kerberos, tokio, tokio-uring, tracing, opentelemetry | PC-001, PC-002, PC-005, PC-009, PC-014, PC-019, PC-043, PC-044, PC-055, PC-080, PC-102, PC-108, PC-117, PC-126 |
| Decision 2 | ORQ-011/012/013/014 | FoundationDB as Primary Storage Engine for All DCs | adrian-storage-core, adrian-storage-fdb, adrian-storage-fdb-migrations, adrian-storage-testkit, foundationdb, foundationdb-sys, uuid, tokio, tracing | PC-007, PC-008, PC-009, PC-020, PC-062, PC-109, PC-110, PC-117, PC-108 |
| Decision 3 | ORQ-026/027 | UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping | adrian-identity-core, adrian-identity-fdb, adrian-identity-ridpool, adrian-sid, uuid, libc, thiserror, tracing | PC-010, PC-015, PC-022, PC-089, PC-102, PC-120, PC-124, PC-126, PC-127 |
| Decision 4 | ORQ-030/031 | Hybrid Schema Model — LDAP Schema + Typed Rust Projection | adrian-schema, adrian-schema-compiler, adrian-schema-traits, oid, phf, rasn, quick-xml, syn, quote, proc-macro2 | PC-017, PC-021, PC-045, PC-046, PC-095, PC-107, PC-113, PC-125, PC-010 |
| Decision 5 | ORQ-042/043/044 | Fresh Rust KDC (Not MIT, Not Samba Heimdal) | adrian-kdc, adrian-kdc-interop, adrian-pac-validator, rasn, rasn-kerberos, ring, aes, sha1, sha2, hmac, pbkdf2, md4, cryptoki, ldap3, tokio, tokio-uring, tracing, opentelemetry, hickory-server, proptest | PC-023, PC-025, PC-119, PC-027, PC-039 |
| Decision 6 | ORQ-072/074/075 | Drop Server-Side NTLM; Client-Only NTLM for Legacy Services | adrian-ntlm-client, md4, hmac, sha2, rasn, keyring, tokio, tracing, opentelemetry, adrian-kdc | PC-036, PC-038, PC-039, PC-094, PC-040, PC-119 |
| Decision 7 | ORQ-090/091 | Hybrid Declarative JSON Policy + ADMX Compiler + PReg Adapter | adrian-policy-core, adrian-policy-validate, adrian-policy-cel, adrian-policy-preg, adrian-policy-distribution, adrian-policy-daemon, adrian-policy-executor, quick-xml, serde, serde_json, cel, regorus, rust-ini, tokio, axum, tokio-tungstenite, tracing | PC-046, PC-047, PC-048, PC-052, PC-056, PC-095 |
| Decision 8 | ORQ-110/111 | ACME Primary + MS-WCCE Bridge | adrian-acme-server, adrian-wcce-bridge, adrian-ca, adrian-ca-core, adrian-ca-issuing, adrian-cert-agent, adrian-cert-enroll, adrian-certmonger-compat, adrian-est-bridge, adrian-scep, adrian-scep-ra, adrian-trust-manager, picky, x509-cert, ring, rustls, tokio, axum | PC-027, PC-057, PC-058, PC-059, PC-060, PC-061, PC-064, PC-067 |
| Decision 9 | ORQ-132/133/134 | Wrap Keycloak with Rust AD-Claim-Rules Shim | adrian-keycloak, adrian-federation, adrian-federation-shim, adrian-claims-engine, adrian-fed, openidconnect, saml2, reqwest, serde_json, tokio, axum, tracing | PC-068, PC-069, PC-070, PC-071, PC-072, PC-073, PC-074, PC-075, PC-076 |
| Decision 10 | ORQ-154/155 | Fresh Rust SMB 3.1.1 Server | adrian-smb, adrian-smb-core, adrian-smb-server, adrian-smb-auth, adrian-smb-client, adrian-smb-fuse, adrian-smb-macfuse, adrian-smb-winfs, pavao, ring, aes, sha2, tokio, tokio-uring, tracing | PC-078, PC-079, PC-080, PC-081, PC-082, PC-084, PC-130 |
| Decision 11 | ORQ-169/170/175/176 | Unified Rust Core SDK + Platform-Specific Bindings | adrian-sdk, adrian-sdk-c, adrian-sdk-java, adrian-sdk-swift, adrian-sdk-python, adrian-sdk-go, adrian-cli, adrian-client-daemon, adrian-kerberos-renewd, adrian-kerberos-sync, tokio, serde, ldap3, pavao, rustls, openidconnect, saml2, cbindgen, jni, swift-bridge, pyo3, maturin, pam-bindings, libc, windows, objc2, core-foundation, systemd, tracing | PC-040, PC-085, PC-086, PC-088, PC-091, PC-095, PC-100, PC-115 |
| Decision 12 | ORQ-202/203 | SSSD Primary + FreeIPA Alt; Winbind Deprecated; PBIS Unsupported | adrian-sssd-gpo, adrian-authselect-profile, adrian-base-container, adrian-cli, adrian-migrate, clap, tokio, serde, serde_json, ldap3, adrian-sdk, tracing | PC-040, PC-053, PC-088, PC-089, PC-099, PC-101, PC-103, PC-121 |

## Appendix C: Rust crate inventory

The framework's Rust workspace contains ~70 framework crates and ~40 ecosystem crates. Below is the curated inventory of the most-referenced crates across the 130 ADRs and 12 workshop decisions.

### Framework crates (storage + replication + identity + schema)

| Crate | Layer | Dependencies | Description | License |
|-------|-------|--------------|-------------|---------|
| adrian-storage-core | Storage | tokio, thiserror, async-trait | DirectoryStore trait + object model | MIT/Apache-2.0 |
| adrian-storage-fdb | Storage | foundationdb, tokio, tracing | FDB-backed DirectoryStore impl (ADR-073) | MIT/Apache-2.0 |
| adrian-storage-fdb-migrations | Storage | foundationdb, tokio | Schema migrations for FDB subspaces | MIT/Apache-2.0 |
| adrian-identity-core | Identity | uuid, thiserror | UUID-primary identity primitives (Decision 3) | MIT/Apache-2.0 |
| adrian-identity-fdb | Identity | foundationdb, adrian-identity-core | FDB-backed identity store | MIT/Apache-2.0 |
| adrian-identity-ridpool | Identity | adrian-identity-core, rand | RID pool allocation per-DC (ADR-077) | MIT/Apache-2.0 |
| adrian-sid | Identity | thiserror, rasn | SID parsing/encoding (MS-DTYP §2.4.2) | MIT/Apache-2.0 |
| adrian-schema | Schema | adrian-schema-traits, oid | LDAP schema model (Decision 4) | MIT/Apache-2.0 |
| adrian-schema-compiler | Schema | syn, quote, proc-macro2 | Typed-projection compile-time generator | MIT/Apache-2.0 |
| adrian-schema-traits | Schema | phf, oid | Trait definitions for typed projection | MIT/Apache-2.0 |
| adrian-drsuapi | Replication | rasn, rasn-kerberos, tokio, tracing | Fresh Rust DRSUAPI server (ADR-070) | MIT/Apache-2.0 |
| adrian-raft | Replication | openraft, tokio, tracing | RaftReplicator wrapper (ADR-071) | MIT/Apache-2.0 |
| adrian-repl-core | Replication | async-trait, thiserror | Replicator trait (hybrid model) | MIT/Apache-2.0 |
| adrian-repl-health | Replication | adrian-repl-core, tokio, prometheus | Replication health monitoring | MIT/Apache-2.0 |

### Framework crates (KDC + auth + PAC)

| Crate | Layer | Dependencies | Description | License |
|-------|-------|--------------|-------------|---------|
| adrian-kdc | KDC | rasn, rasn-kerberos, ring, aes, sha1, sha2, hmac, pbkdf2, md4, cryptoki, ldap3, tokio, tokio-uring, tracing, opentelemetry, hickory-server, proptest | Fresh Rust KDC ~30K lines (Decision 5) | MIT/Apache-2.0 |
| adrian-kdc-interop | KDC test | rasn-kerberos, tokio, tracing | Wire-compat test suite vs MIT/Heimdal/Windows | MIT/Apache-2.0 |
| adrian-pac-validator | KDC | rasn, ring, md4, cryptoki, thiserror, tracing | Unified PAC validator (libframework_pac_validator) | MIT/Apache-2.0 |
| adrian-ntlm-client | Auth | md4, hmac, sha2, rasn, keyring, tokio, tracing, opentelemetry | NTLMv2 client ~3K lines (ADR-085) | MIT/Apache-2.0 |

### Framework crates (policy + PKI + federation + file)

| Crate | Layer | Dependencies | Description | License |
|-------|-------|--------------|-------------|---------|
| adrian-policy-core | Policy | serde, serde_json, thiserror | Canonical JSON policy model (Decision 7) | MIT/Apache-2.0 |
| adrian-policy-validate | Policy | adrian-policy-core, cel, regorus | CEL selector + Regorus policy eval | MIT/Apache-2.0 |
| adrian-policy-preg | Policy | adrian-policy-core, quick-xml, rust-ini | PReg/Registry.pol adapter (ADR-029) | MIT/Apache-2.0 |
| adrian-policy-executor | Policy | adrian-policy-core, plist, quick-xml, tokio | Per-platform executor (ADR-092) | MIT/Apache-2.0 |
| adrian-policy-daemon | Policy | adrian-policy-executor, tokio, tracing | Daemon running as SYSTEM/root/launchd | MIT/Apache-2.0 |
| adrian-acme-server | PKI | tokio, axum, ring, rustls, x509-cert | ACME RFC 8555 endpoint (ADR-095) | MIT/Apache-2.0 |
| adrian-wcce-bridge | PKI | tokio, rasn, x509-cert | MS-WCCE bridge for Windows autoenroll | MIT/Apache-2.0 |
| adrian-ca | PKI | adrian-ca-core, adrian-ca-issuing, cryptoki, x509-cert, ring | Two-tier CA (ADR-037) | MIT/Apache-2.0 |
| adrian-ocsp-responder | PKI | tokio, axum, ring, x509-cert | OCSP RFC 6960 with nonce (ADR-033) | MIT/Apache-2.0 |
| adrian-trust-manager | PKI | x509-cert, ring, tokio | Trust manager + cross-cert (ADR-036) | MIT/Apache-2.0 |
| adrian-keycloak | Federation | reqwest, tokio, serde_json | Keycloak wrapper (ADR-100) | MIT/Apache-2.0 |
| adrian-claims-engine | Federation | regorus, tokio | ADFS CRL-to-Rego/Cedar translation (ADR-101) | MIT/Apache-2.0 |
| adrian-smb-server | File | adrian-smb-core, adrian-smb-auth, ring, aes, sha2, tokio, tokio-uring | Fresh Rust SMB 3.1.1 (ADR-105) | MIT/Apache-2.0 |
| adrian-smb-client | File | pavao, tokio | SMB client as SDK FileModule (ADR-106) | MIT/Apache-2.0 |

### Framework crates (SDK + operations + migration)

| Crate | Layer | Dependencies | Description | License |
|-------|-------|--------------|-------------|---------|
| adrian-sdk | SDK | tokio, serde, ldap3, pavao, rustls, openidconnect, saml2, adrian-ntlm-client, adrian-sid, tracing, opentelemetry | Unified Rust core SDK (ADR-107) | MIT/Apache-2.0 |
| adrian-sdk-c | SDK FFI | cbindgen, adrian-sdk | C ABI binding | MIT/Apache-2.0 |
| adrian-sdk-swift | SDK FFI | swift-bridge, adrian-sdk | Swift binding (macOS) | MIT/Apache-2.0 |
| adrian-sdk-python | SDK FFI | pyo3, maturin, adrian-sdk | Python binding | MIT/Apache-2.0 |
| adrian-sdk-java | SDK FFI | jni, adrian-sdk | JNI binding | MIT/Apache-2.0 |
| adrian-sdk-go | SDK FFI | cbindgen, adrian-sdk | Go binding via cgo | MIT/Apache-2.0 |
| adrian-cli | Ops | clap, tokio, serde_json, adrian-sdk, adrian-drsuapi, ldap3, tracing | Unified CLI (ADR-063) | MIT/Apache-2.0 |
| adrian-operator | Ops | kube, tokio, serde, tracing | Kubernetes operator (ADR-058) | MIT/Apache-2.0 |
| adrian-observability-sidecar | Ops | opentelemetry, prometheus, tokio, axum | OTLP fan-out sidecar (ADR-057) | MIT/Apache-2.0 |
| adrian-hsm | Ops | cryptoki, tokio, tracing | Unified HsmClient trait | MIT/Apache-2.0 |
| adrian-migrate | Migration | clap, tokio, serde, adrian-sdk, adrian-drsuapi, ldap3, tracing | Migration tooling (ADR-126/127/128/129/130) | MIT/Apache-2.0 |
| adrian-sssd-gpo | Cross-Platform | adrian-policy-core, clap, tokio, serde, ldap3 | SSSD GPO extension cdylib (ADR-093/114) | MIT/Apache-2.0 |
| adrian-dc | Top-level | (workspace) | DC supervisor binary (PID 1, ADR-058) | MIT/Apache-2.0 |
| adrian-dsa | Top-level | adrian-storage-fdb, adrian-identity-fdb, tokio, ldap3 | Directory System Agent (LDAP server) | MIT/Apache-2.0 |

### Ecosystem crates (selected, by category)

| Crate | Category | Version | License | Use |
|-------|----------|---------|---------|-----|
| tokio | Async runtime | 1.40+ | MIT | Async runtime for all framework crates |
| tokio-uring | Async I/O | 0.4+ | MIT | io_uring UDP socket I/O on Linux (Kerberos UDP) |
| tracing | Logging | 0.1+ | MIT | Structured logging |
| opentelemetry | Observability | 0.24+ | MIT | OTel SDK for spans/metrics/logs (ADR-057/060) |
| prometheus | Metrics | 0.13+ | Apache-2.0 | Prometheus text-exposition format |
| serde | Serialization | 1.0+ | MIT/Apache-2.0 | JSON/YAML serialization |
| serde_json | Serialization | 1.0+ | MIT/Apache-2.0 | JSON canonical format |
| clap | CLI | 4.5+ | MIT/Apache-2.0 | `adrian-cli` argument parsing |
| axum | HTTP | 0.7+ | MIT | REST API + ACME endpoint (ADR-061/095) |
| tonic | gRPC | 0.11+ | MIT | gRPC streaming (ADR-061) |
| tokio-tungstenite | WebSocket | 0.21+ | MIT | Push-based policy updates (ADR-028) |
| reqwest | HTTP client | 0.12+ | MIT/Apache-2.0 | Federation + migration HTTP client |
| ldap3 | LDAP | 0.11+ | MIT/Apache-2.0 | LDAP client + server primitives |
| rasn | ASN.1 | 0.10+ | MIT/Apache-2.0 | ASN.1 encoding/decoding (Kerberos, NTLMSSP, X.509) |
| rasn-kerberos | ASN.1 | 0.10+ | MIT/Apache-2.0 | Kerberos-specific ASN.1 types |
| ring | Crypto | 0.17+ | MIT/Apache-2.0 | HMAC, AES, Ed25519, key derivation |
| aes | Crypto | 0.8+ | MIT/Apache-2.0 | AES-CTS for Kerberos etypes (RFC 3962) |
| sha1 | Crypto | 0.10+ | MIT/Apache-2.0 | HMAC-SHA1-96 (etype 0x12) |
| sha2 | Crypto | 0.10+ | MIT/Apache-2.0 | SHA-256 (channel binding), SHA-384 (etype 0x13) |
| hmac | Crypto | 0.12+ | MIT/Apache-2.0 | HMAC primitives |
| pbkdf2 | Crypto | 0.12+ | MIT/Apache-2.0 | RFC 8009 PBKDF2-HMAC-SHA1 (4096 iters) |
| md4 | Crypto | 0.10+ | MIT/Apache-2.0 | NT hash derivation (NTLM client + RC4 audit) |
| rustls | TLS | 0.23+ | MIT/Apache-2.0 | TLS 1.3/1.2 — no OpenSSL |
| x509-cert | PKI | 0.2+ | MIT/Apache-2.0 | X.509 cert parsing/issuance |
| cryptoki | HSM | 0.6+ | MIT/Apache-2.0 | PKCS#11 v3.0 HSM access (ADR-015/020/032/037) |
| zeroize | Memory safety | 1.7+ | MIT/Apache-2.0 | Zeroizing<Vec<u8>> for NT hashes (ADR-086) |
| keyring | Credential store | 3.0+ | MIT/Apache-2.0 | Linux keyctl / macOS Keychain / Windows DPAPI |
| foundationdb | Storage | 0.9+ | MIT/Apache-2.0 | FDB client bindings (Decision 2) |
| openraft | Raft | 0.9+ | MIT/Apache-2.0 | Raft consensus (Decision 1, ADR-071) |
| hickory-server | DNS | 0.8+ | MIT/Apache-2.0 | SRV record publishing (ADR-018) |
| pavao | SMB client | 0.1+ | MIT | SMB client for SDK FileModule (ADR-106) |
| proptest | Testing | 1.4+ | MIT/Apache-2.0 | Property-based PAC bijectivity tests |
| quick-xml | XML | 0.31+ | MIT | ADMX parsing, GPP XML |
| plist | macOS | 1.6+ | MIT | Configuration Profile authoring (macOS) |
| cel | Policy | 0.3+ (cel-rust) | MIT | CEL default selector (Decision 7) |
| regorus | Policy | 0.1+ | Apache-2.0 | Rego/Cedar policy engine (ADR-101) |
| cbindgen | FFI | 0.27+ | MPL-2.0 | C ABI header generation |
| jni | FFI | 0.21+ | MIT/Apache-2.0 | JNI binding for Java SDK |
| swift-bridge | FFI | 0.1+ | MIT/Apache-2.0 | Swift binding (macOS) |
| pyo3 | FFI | 0.20+ | MIT/Apache-2.0 | Python binding |
| windows | Windows API | 0.54+ | MIT/Apache-2.0 | Windows LSA, DPAPI, Event Log |
| objc2 | macOS API | 0.5+ | MIT | macOS Objective-C runtime (PSSO, OpenDirectory) |
| core-foundation | macOS API | 0.9+ | MIT/Apache-2.0 | macOS CoreFoundation types |
| libc | POSIX | 0.2+ | MIT/Apache-2.0 | POSIX syscalls (NSS, PAM) |
| pam-bindings | PAM | 0.1+ | MIT/Apache-2.0 | PAM module bindings (pam_adrian.so) |
| systemd | Linux | 0.10+ | MIT/Apache-2.0 | systemd-creds integration |
| thiserror | Errors | 1.0+ | MIT/Apache-2.0 | Error derive macro |
| uuid | IDs | 1.8+ | MIT/Apache-2.0 | UUIDv7 (Decision 3) |
| rand | Random | 0.8+ | MIT/Apache-2.0 | CSPRNG for krbtgt rotation, gMSA passwords |
| webauthn-rs | FIDO2 | 0.5+ | MIT/Apache-2.0 | FIDO2/WebAuthn for PKINIT bridge (ADR-084) |
| openidconnect | OIDC | 3.4+ | MIT | OIDC client for federation (Decision 9) |
| saml2 | SAML | 0.8+ | MIT | SAML parser for federation |
| kube | Kubernetes | 0.87+ | MIT/Apache-2.0 | Operator SDK (ADR-058) |

## Appendix D: External dependencies

The framework depends on the following external services and ecosystems. Each is the *recommended* deployment; alternatives are documented per-ADR.

**Storage**: FoundationDB 7.3+ (Decision 2, ADR-073). Apple-scale distributed key-value store. The framework's `adrian-storage-fdb` crate wraps the official `foundationdb` Rust bindings. FDB runs as a separate cluster (5+ nodes recommended for production; 3 nodes minimum for development) managed independently from the framework's DCs. The framework's `adrian-operator` does NOT manage FDB lifecycle — FDB has its own operator (`foundationdb-kubernetes-operator`). Backup via FDB's `backup_agent` + `fastrestore` (ADR-010/059).

**Identity provider (federation)**: Keycloak 26+ (Decision 9, ADR-100/103/104). Java application server running on Quarkus, backed by PostgreSQL 16+. The framework's `adrian-keycloak` crate wraps Keycloak's admin REST API. Keycloak runs as a StatefulSet (no primary-secondary — PostgreSQL multi-primary via ADR-103). The framework's Rust shim sidecar (`adrian-federation-shim`) sits in front of Keycloak for ADFS claim rule language compat (ADR-101) and WAP replacement (ADR-102).

**Kerberos (client side, macOS/Linux only)**: MIT krb5 1.21+ (ADR-049). Standardised on Linux and macOS client hosts; bundled with the framework's Client SDK installer. The framework does NOT bundle MIT krb5 on the KDC side — the framework's KDC is fresh Rust (Decision 5). The framework's `libframework_pac_validator.dylib` bypasses macOS system Heimdal's stale PAC parser (ADR-117).

**Container orchestration**: Kubernetes 1.28+ (ADR-058). The framework's DCs run as container images (one DC per Pod) managed by a `StatefulSet` with PVC-backed DIT storage. The `DomainController` CRD is operated by `adrian-operator`. The framework also runs on bare-metal/VM but Kubernetes is the reference deployment. CSI snapshot API required for backup/restore (ADR-059).

**HSM**: PKCS#11 v3.0 compatible HSM (ADR-015/020/032/037). Supported vendors in v1: SoftHSM2 (software, development only), YubiHSM2 (small deployments), Thales Luna Network HSM (enterprise), Entrust nShield (enterprise). The framework's `adrian-hsm` crate uses the `cryptoki` Rust crate for PKCS#11 access. HSM HA clustering is vendor-specific; the framework's `HsmClient` retries across cluster nodes.

**Object storage (backup)**: S3-compatible object storage (ADR-059). WAL archives go to S3, GCS, Azure Blob, or MinIO every 60 seconds. The framework's `adrian-operator` uses the `aws-sdk-s3` Rust crate for S3-compatible APIs; MinIO is the recommended on-prem deployment.

**Observability**: OpenTelemetry Collector (ADR-057/060). The framework's `adrian-observability-sidecar` exports OTLP/gRPC to a downstream collector. Recommended collector: OpenTelemetry Collector 0.95+ with Prometheus exporter, Loki exporter, and Tempo exporter. SIEM integration via JSON Lines file + Windows Event Log forwarder (for AD-interop).

**DNS**: CoreDNS 1.11+ (ADR-079, native mode) OR Microsoft DNS (AD-interop mode). The framework's `adrian-dns-coredns` crate is a CoreDNS plugin that reads DNS zones from FDB. AD-interop mode uses Microsoft DNS via DRSUAPI replication of `dnsNode` objects.

**Time sync**: chrony 4.5+ (ADR-022). The framework's DCs run chrony as the NTP server; client hosts sync from DCs. MS-SNTP is dropped. Alert on clock skew >5 seconds (Kerberos tolerance is 5 minutes).

**PostgreSQL (Keycloak backend)**: PostgreSQL 16+ (ADR-103). Multi-primary via BDR or native logical replication; the framework's `adrian-postgresql` crate wraps PostgreSQL admin operations for the operator.

**Apple PSSO Extension**: macOS 13+ (ADR-056). Required for modern macOS Kerberos path. Apple-controlled; the framework monitors Apple release notes for breaking changes.

**SSSD**: SSSD 2.9+ (ADR-114). The framework's Linux client hosts run SSSD with `id_provider = ad` (framework's AD-equivalent), `krb5_ccname_template = KCM:%u`, `gpo_access_provider = adrian` (the `adrian-sssd-gpo` cdylib).

**FreeIPA**: FreeIPA 4.10+ (ADR-115). Alternative Linux identity tier via cross-realm trust. The framework's `adrian-cli trust establish --peer freeipa` configures the trust.

**Sigstore ecosystem**: cosign 2.2+, Rekor (public instance at `https://rekor.sigstore.dev`), Fulcio (OIDC CA), SLSA L3 build provenance (ADR-067). The framework's CI/CD uses GitHub Actions OIDC tokens for keyless signing.

**Linux distros**: Ubuntu 22.04+ / RHEL 9+ / Amazon Linux 2023 (framework DC host OS); Ubuntu 20.04+ / RHEL 8+ (framework client host OS). The framework's container images are built from `ubuntu:22.04` and `registry.access.redhat.com/ubi9/ubi-minimal`.

**Windows**: Windows Server 2022+ (AD-interop DC); Windows 11 22H2+ (client host). The framework's Windows client runs as an LSA Authentication Package (`adrianlsa.dll`) and a Windows Service (`adrian-client-daemon`).

**macOS**: macOS 13+ (PSSO Extension); macOS 12 and below fall back to Jamf Connect (ADR-048/116). The framework's macOS client runs as a PSSO Extension + OpenDirectory plugin + launchd daemon.

## Appendix E: Glossary

Key terms used throughout the final draft and ADRs.

**ACME** — Automated Certificate Management Environment (RFC 8555). The framework's primary cert enrollment protocol (Decision 8, ADR-095).

**ADMX** — Administrative Template XML format (MS-GPPCF). AD's policy definition format; the framework's `admx2adrian` compiler translates ADMX to canonical JSON (ADR-090).

**ATT&CK (MITRE)** — Adversarial Tactics, Techniques, and Common Knowledge. The framework's audit events map to ATT&CK technique IDs per ADR-060.

**CSE** — Client-Side Extension. AD's per-category GPO processing module; the framework's `PolicyExecutor` trait is the cross-platform equivalent (ADR-024/092).

**DDM** — Declarative Device Management (Apple). The framework's DDM-first authoring strategy on macOS (ADR-052).

**DDM** (also) — Dynamic Data Masking (some contexts). Disambiguated per ADR-052 to Apple DDM.

**DCSync** — Attack extracting all password hashes via DRSUAPI `DRSGetNCChanges` with `EXOP_REPL_SECRETS` (PC-117, MITRE T1003.003). Mitigated in native mode by Raft (no DRSUAPI); in AD-interop by per-call audit + HSM-bound break-glass (ADR-122).

**DRSUAPI** — Directory Replication Service (Remote) API. MS-DRSR protocol used for AD replication. The framework's `adrian-drsuapi` crate is a fresh Rust implementation (ADR-070).

**EXOP_REPL_SECRETS** — DRSUAPI extended operation 0x1 that returns secret attributes (`unicodePwd`, `supplementalCredentials`). The DCSync attack vector (PC-117).

**FAST** — Flexibly Secure Tunneling (RFC 6806). Kerberos armoring; the framework defaults to `fast_mode = "supported"` in MVP, flipping to `"required"` once PKINIT lands (ADR-012).

**FreeIPA** — Open-source Linux identity platform (Red Hat). The framework's alternative Linux tier via cross-realm trust (ADR-115).

**gMSA** — Group Managed Service Account. AD service account type with KDS-managed 240-char random password; the framework's KDS root key is HSM-bound (ADR-020).

**HBAC** — Host-Based Access Control (FreeIPA). Server-side evaluation of (user, host, service) triples; the framework's selective-authentication alternative (ADR-125).

**HSM** — Hardware Security Module. PKCS#11 v3.0 device for key storage; the framework binds krbtgt, KDS root, CA, KRA, and token-signing keys to HSMs (`cryptoki` crate).

**KCM** — Kerberos Credential Manager (RFC 8209, Heimdal/MIT). Linux Kerberos ticket cache API; the framework's unified cache abstraction on Linux (ADR-051).

**KDC** — Key Distribution Center (RFC 4120). Issues Kerberos TGTs and TGS tickets; the framework's KDC is fresh Rust (Decision 5).

**KDS** — Key Distribution Service (MS-KILE). AD service that derives gMSA passwords from a root key; the framework's KDS root key is HSM-bound (ADR-020).

**KRA** — Key Recovery Agent. AD CS role that decrypts archived private keys; the framework's KRA keys are HSM-bound with Shamir M-of-N (ADR-032).

**krbtgt** — The Kerberos account that holds the key used to sign TGTs. HSM-bound in the framework with 30-day rotation (ADR-015/065).

**MS-WCCE** — Windows Client Certificate Enrollment Protocol. The framework's MS-WCCE bridge enables Windows autoenroll against the framework's ACME-primary CA (ADR-095).

**NTLM** — NT LAN Manager (MS-NLMP). Legacy Microsoft authentication protocol; the framework drops server-side NTLM and maintains a client-only Rust crate for legacy services (Decision 6, ADR-085).

**OCSP** — Online Certificate Status Protocol (RFC 6960). Real-time cert revocation checking; the framework's OCSP responder is HA-clustered (ADR-033).

**ORQ** — Open Research Question. The framework's catalog has 262 ORQs; 11 are Tier-1 (workshop-resolved) per [`catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md).

**PAC** — Privilege Attribute Certificate (MS-PAC). Kerberos authorisation data structure embedded in tickets; the framework's fresh Rust KDC emits 9 PAC buffer types (ADR-082).

**PAC_BUFFER_TICKET_CHECKSUM** — PAC buffer type 0x0E (Server 2012+). Signs the entire Ticket.enc-part with krbtgt key; the framework's silver-ticket mitigation (ADR-123).

**PReg** — Policy Registry file format (`Registry.pol`). AD's compiled GPO format; the framework's PReg adapter (ADR-029).

**PIM trust** — Privileged Access Management trust (`TRUST_ATTRIBUTE_PIM_TRUST = 0x200`, Server 2016+). User-level isolation with sIDHistory filtering within-forest.

**PKINIT** — Public Key Cryptography for Initial Authentication (RFC 4556). Kerberos smart-card logon; the framework's PKINIT bridge supports FIDO2/WebAuthn + RFC 4556 (ADR-084).

**PtH** — Pass-the-Hash. Attack reusing stolen NT hashes; the framework eliminates server-side PtH by dropping NTLM acceptor (ADR-085/086).

**RBAC** — Role-Based Access Control. The framework's declarative RBAC replaces AdminSDHolder (ADR-066).

**RBCD** — Resource-Based Constrained Delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`). AD Server 2012+ feature; the framework's KDC implements RBCD per ADR-087.

**sIDHistory** — Multi-valued attribute (`1.2.840.113556.1.4.1369`) carrying SIDs from previous domains. Used for migration; filtered by default on all framework trusts (ADR-124).

**SDPROP** — Security Descriptor Propagator. AD thread that applies AdminSDHolder template to protected groups every 60 min; replaced by declarative RBAC (ADR-066).

**Sigstore** — Open-source software signing ecosystem (cosign + Rekor + Fulcio). The framework's supply-chain security layer (ADR-067).

**SLSA** — Supply-chain Levels for Software Artifacts. Framework targets SLSA L3 (hermetic builds + provenance attestations).

**SPN** — Service Principal Name. Kerberos service identifier (`cifs/file01.example.com@REALM`); uniqueness enforced (ADR-016).

**SSSD** — System Security Services Daemon (Linux). The framework's primary Linux identity stack (ADR-114).

**STRIDE** — Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. Microsoft's threat-model classification used in [`catalog/11-security-threat-model.md`](../catalog/11-security-threat-model.md).

**UTD vector** — Up-To-Dateness vector. AD replication metadata; preserved in AD-interop mode, synthesised from Raft log in native mode (ADR-071).

**WS-Trust** — WS-Trust (OASIS). SOAP-based token exchange protocol; the framework's WS-Trust-to-OIDC bridge supports legacy clients (ADR-039).
