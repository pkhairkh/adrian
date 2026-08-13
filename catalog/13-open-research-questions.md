---
title: Open Research Questions — Cross-Cutting Reference
audience: architects-and-engineers
tags: [open-research-questions, framework-design, cross-cutting, prioritization]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./01-core-directory.md
  - ./02-kdc.md
  - ./03-auth-provider.md
  - ./04-policy-engine.md
  - ./05-cert-service.md
  - ./06-federation-gateway.md
  - ./07-file-gateway.md
  - ./08-client-sdk.md
  - ./09-cross-platform-parity.md
  - ./10-operations.md
  - ./11-security-threat-model.md
  - ./12-migration-and-coexistence.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Open Research Questions

This file consolidates every "Open questions" entry from the 130-problem catalog into a single reference. Each question is numbered (ORQ-001 through ORQ-262), grouped by capability, and tagged with the source problem (PC-NNN). Cross-cutting themes and prioritisation tiers follow the per-capability enumeration.

- **Total open research questions**: 262
- **Source problems**: 130
- **Average ORQs per problem**: ~2.0

Research questions are statements that the framework's design team must answer before implementation can begin. They are not solutions — they are decisions to be made, trade-offs to be evaluated, and experiments to be run. Some are binary (adopt X vs Y); others are open-ended (what is the cost of Z?).

## By capability

### Core Directory

- ORQ-001: Should the framework adopt Samba's DRSUAPI code (GPL) or write a fresh implementation? (from PC-001)
- ORQ-002: Is there a path to CRDT/OT replication that still speaks DRSUAPI on the wire? (from PC-001)
- ORQ-003: Can `PROPERTY_META_DATA_EXT` be expressed as a CRDT tombstone vector? (from PC-002)
- ORQ-004: Does a Raft log naturally subsume UTD vector needs? (from PC-002)
- ORQ-005: Should the framework keep linkID pairs or replace with a graph database (Neo4j-style) for membership? (from PC-003)
- ORQ-006: Is graph storage better than linktable? (from PC-004)
- ORQ-007: What is the cost of computing `memberOf` at read time vs storing it? (from PC-004)
- ORQ-008: Can a single global store replace the PAS replica concept? (from PC-005)
- ORQ-009: If so, what about bandwidth on large forests? (from PC-005)
- ORQ-010: Can copy-on-write schema cache with generation numbers eliminate the lock? (from PC-006)
- ORQ-011: SQLite? (from PC-007)
- ORQ-012: FoundationDB? (from PC-007)
- ORQ-013: Custom? (from PC-007)
- ORQ-014: Each has tradeoffs; pick one and justify? (from PC-007)
- ORQ-015: Modern hashing (BLAKE3) + persistent map vs the existing sdtable design? (from PC-008)
- ORQ-016: Are tombstones needed in a CRDT design? (from PC-009)
- ORQ-017: What about a Raft log truncation strategy? (from PC-009)
- ORQ-018: Is cross-domain move still relevant in a post-domain-forest design? (from PC-010)
- ORQ-019: Should the framework collapse to a single domain? (from PC-010)
- ORQ-020: Replace with REST URL `/api/v1/well-known/Users`? (from PC-011)
- ORQ-021: Document as legacy LDAP-only? (from PC-011)
- ORQ-022: Which controls are essential for greenfield vs migration scenarios? (from PC-012)
- ORQ-023: Allow the BER-quote form only when in AD-compat mode? (from PC-013)
- ORQ-024: Can all FSMO roles be replaced by Raft-based consensus? (from PC-014)
- ORQ-025: Schema "master" via multi-master with version vectors? (from PC-014)
- ORQ-026: Replace SIDs with UUIDs? (from PC-015)
- ORQ-027: Keep SIDs for AD interop, use UUIDs internally? (from PC-015)
- ORQ-028: Replace KCC with declarative YAML topology? (from PC-016)
- ORQ-029: Maintain compatibility with AD's `cn=Sites,cn=Configuration`? (from PC-016)
- ORQ-030: Hybrid (LDAP schema + typed projection)? (from PC-017)
- ORQ-031: Pure typed with LDAP schema as an adapter? (from PC-017)
- ORQ-032: Cache token-groups on write (event-driven) vs compute at read? (from PC-018)
- ORQ-033: Externalize DNS to CoreDNS with a plugin that reads AD? (from PC-019)
- ORQ-034: Keep DNS in-directory for compat? (from PC-019)
- ORQ-035: CRIU for containers? (from PC-020)
- ORQ-036: LVM snapshots? (from PC-020)
- ORQ-037: Storage-engine-native backup? (from PC-020)
- ORQ-038: Replace bitmask with explicit columns/attributes? (from PC-021)
- ORQ-039: Maintain bitmask for compat? (from PC-021)
- ORQ-040: Per-tenant NC heads? (from PC-022)
- ORQ-041: Kubernetes namespace-style isolation? (from PC-022)

### KDC

- ORQ-042: Reuse Samba's Heimdal fork (GPL)? (from PC-023)
- ORQ-043: MIT krb5 + custom PAC plugin (FreeIPA approach)? (from PC-023)
- ORQ-044: Fresh implementation? (from PC-023)
- ORQ-045: Provide a "migration mode" that issues RC4 TGS with audit-log warnings? (from PC-024)
- ORQ-046: Auto-rotate service accounts to AES on next password change? (from PC-024)
- ORQ-047: Always-validate mode with cached krbtgt keys per service? (from PC-025)
- ORQ-048: Token-binding via TLS exporter? (from PC-025)
- ORQ-049: Is FAST-required compatible with all legacy clients (Java, old Python)? (from PC-026)
- ORQ-050: Provide fallback grace period? (from PC-026)
- ORQ-051: Adopt FIDO2 + PKINIT-anonymous for passwordless? (from PC-027)
- ORQ-052: Maintain smart-card path for compliance? (from PC-027)
- ORQ-053: Replace transited-field with signed assertions from each hop? (from PC-028)
- ORQ-054: Trust-on-first-use model? (from PC-028)
- ORQ-055: Adopt 0x13 default with 0x12 fallback grace period? (from PC-029)
- ORQ-056: When to drop 0x12? (from PC-029)
- ORQ-057: HSM-bound krbtgt key? (from PC-030)
- ORQ-058: Automatic rotation every N days? (from PC-030)
- ORQ-059: Per-forest unique index on SPN? (from PC-031)
- ORQ-060: Per-domain with cross-domain conflict detection? (from PC-031)
- ORQ-061: Strict write-time uniqueness vs soft enforcement? (from PC-032)
- ORQ-062: Auto-rename on conflict? (from PC-032)
- ORQ-063: Stateless KDC with shared key in HSM? (from PC-033)
- ORQ-064: Per-realm KDC pool? (from PC-033)
- ORQ-065: Add OAuth2 password-reset endpoint as modern alternative? (from PC-034)
- ORQ-066: HashiCorp Vault integration for service-account secrets? (from PC-035)
- ORQ-067: KDS-equivalent per-forest root key? (from PC-035)

### Auth Provider

- ORQ-068: Provide NTLM-emulation via Kerberos with downgrade-friendly client SDK? (from PC-036)
- ORQ-069: Hard cut-off date? (from PC-036)
- ORQ-070: Disable NTLM by default with audit-mode migration? (from PC-037)
- ORQ-071: Mandate EPA across all protocols? (from PC-037)
- ORQ-072: Drop NTLM entirely (eliminates PtH)? (from PC-038)
- ORQ-073: Use VSM-equivalent on Linux (TEE)? (from PC-038)
- ORQ-074: Replace with OAuth2 client-credentials flow? (from PC-039)
- ORQ-075: Maintain S4U for AD interop? (from PC-039)
- ORQ-076: Adopt WebAuthn-style token-binding as the unified abstraction? (from PC-040)
- ORQ-077: Per-platform adapters? (from PC-040)
- ORQ-078: Drop MS-SNTP entirely? (from PC-041)
- ORQ-079: Mandatory chrony with monitoring alerting on >2 min skew? (from PC-041)
- ORQ-080: Map to MITRE ATT&CK technique IDs in the event metadata? (from PC-042)
- ORQ-081: OTel semantic conventions for Kerberos? (from PC-042)

### Policy Engine

- ORQ-082: Single declarative YAML per GPO in a Git repo? (from PC-043)
- ORQ-083: Per-GPO CRDT? (from PC-043)
- ORQ-084: Declarative policy with explicit `priority: N` per setting? (from PC-044)
- ORQ-085: Keep LSDOU as default? (from PC-044)
- ORQ-086: Adopt OPA-style declarative policy with platform-specific executors? (from PC-045)
- ORQ-087: Per-platform translation layer? (from PC-045)
- ORQ-088: Single policy DSL that compiles to ADMX/MDM/SSSD-conf? (from PC-046)
- ORQ-089: OPA Rego as the unified format? (from PC-046)
- ORQ-090: Generic "policy executor" framework with per-platform plugins? (from PC-047)
- ORQ-091: Declarative policy that compiles to CSE invocations on Windows and shell scripts on Linux? (from PC-047)
- ORQ-092: Per-CSE snapshot before apply? (from PC-048)
- ORQ-093: Git-style revert? (from PC-048)
- ORQ-094: Replace WMI filters with declarative host facts (OS, role, site)? (from PC-049)
- ORQ-095: Keep WMI for Windows-only? (from PC-049)
- ORQ-096: Replace ICMP with HTTP HEAD probe? (from PC-050)
- ORQ-097: Per-CSE slow-link policy? (from PC-050)
- ORQ-098: WebSocket / MQTT push channel for policy updates? (from PC-051)
- ORQ-099: Per-policy TTL? (from PC-051)
- ORQ-100: Single policy format (JSON) with PReg adapter for Windows? (from PC-052)
- ORQ-101: Per-platform native formats? (from PC-052)
- ORQ-102: Adopt FreeIPA HBAC semantics as the cross-platform access-control model? (from PC-053)
- ORQ-103: Map GPO URA to HBAC at compile time? (from PC-053)
- ORQ-104: Replace per-principal ACL with role-based policy binding? (from PC-054)
- ORQ-105: Auto-include computer accounts? (from PC-054)
- ORQ-106: Git-backed SYSVOL with auto-sync to DCs? (from PC-055)
- ORQ-107: Samba-style DRSUAPI SYSVOL? (from PC-055)
- ORQ-108: Git-backed policies with PR-based review? (from PC-056)
- ORQ-109: Auto-tag on apply? (from PC-056)

### Cert Service

- ORQ-110: Adopt ACME (RFC 8555) for new clients + MS-WCCE adapter for Windows? (from PC-057)
- ORQ-111: Implement Dogtag-style REST API? (from PC-057)
- ORQ-112: Single JSON template schema with ACL projection to AD? (from PC-058)
- ORQ-113: Adopt Dogtag profile format? (from PC-058)
- ORQ-114: Single certmonger-style daemon with platform-native key stores (Keychain, KRA, CNG)? (from PC-059)
- ORQ-115: ACME + SCEP dual-protocol? (from PC-059)
- ORQ-116: HSM-backed KRA private keys? (from PC-060)
- ORQ-117: Multi-party KRA recovery (Shamir secret sharing)? (from PC-060)
- ORQ-118: Adopt CRLite (Mozilla) for massive-CRL compression? (from PC-061)
- ORQ-119: Multi-responder OCSP clustering? (from PC-061)
- ORQ-120: Adopt FoundationDB / CockroachDB for CA storage? (from PC-062)
- ORQ-121: SQLite WAL mode? (from PC-062)
- ORQ-122: CRLite for massive forests? (from PC-063)
- ORQ-123: Multi-CDP HTTP fallback? (from PC-063)
- ORQ-124: Single enrollment endpoint that speaks SCEP + EST + ACME? (from PC-064)
- ORQ-125: Per-protocol adapters? (from PC-064)
- ORQ-126: Adopt trust-manager model (like browser CA bundles) instead of cross-cert? (from PC-065)
- ORQ-127: Per-application trust stores? (from PC-065)
- ORQ-128: Default to two-tier with HSM root? (from PC-066)
- ORQ-129: Cloud-based root CA (AWS Private CA, GCP CA Service)? (from PC-066)
- ORQ-130: Replace NTAuthCertificates with per-tenant trust store? (from PC-067)
- ORQ-131: Web-of-trust model? (from PC-067)

### Federation Gateway

- ORQ-132: Adopt Keycloak as the federation layer? (from PC-068)
- ORQ-133: Build native? (from PC-068)
- ORQ-134: Cloud-first (Entra ID)? (from PC-068)
- ORQ-135: Adopt Rego (OPA) as the claims-policy language? (from PC-069)
- ORQ-136: Cedar (AWS)? (from PC-069)
- ORQ-137: Per-IdP plugins? (from PC-069)
- ORQ-138: Auto-notify RPs via webhook on cert rollover? (from PC-070)
- ORQ-139: JWKS rotation API (RFC 8414)? (from PC-070)
- ORQ-140: Drop WS-* entirely? (from PC-071)
- ORQ-141: Provide a WS-Trust-to-OIDC bridge? (from PC-071)
- ORQ-142: Auto-sync clocks via NTP before SAML? (from PC-072)
- ORQ-143: Per-RP skew policy? (from PC-072)
- ORQ-144: Adopt oauth2-proxy as the WAP replacement? (from PC-073)
- ORQ-145: Envoy + ext-authz? (from PC-073)
- ORQ-146: etcd-backed config? (from PC-074)
- ORQ-147: Raft among federation nodes? (from PC-074)
- ORQ-148: Provide `resource=` compat mode for AD FS migration? (from PC-075)
- ORQ-149: Strict OIDC by default? (from PC-075)
- ORQ-150: Adopt Keycloak-style identity brokering? (from PC-076)
- ORQ-151: Per-tenant IdP routing? (from PC-076)
- ORQ-152: Out of scope (recommend AIP)? (from PC-077)
- ORQ-153: Implement minimal RMS-compatible server? (from PC-077)

### File Gateway

- ORQ-154: Adopt Samba's smbd (GPL)? (from PC-078)
- ORQ-155: Write fresh SMB server? (from PC-078)
- ORQ-156: Reuse macOS SMBX kernel ext? (from PC-078)
- ORQ-157: Hard cut? (from PC-079)
- ORQ-158: Provide SMB1-compat shim for legacy NAS? (from PC-079)
- ORQ-159: Adopt Kubernetes-style service discovery (DNS SRV) for share location? (from PC-080)
- ORQ-160: Replicate via Git/syncthing? (from PC-080)
- ORQ-161: CSI + SMB-server-in-container? (from PC-081)
- ORQ-162: CTDB-style clustered Samba? (from PC-081)
- ORQ-163: Pre-computed ABE index? (from PC-082)
- ORQ-164: Per-user view materialization? (from PC-082)
- ORQ-165: Drop MS-RPRN entirely? (from PC-083)
- ORQ-166: Use IPP Everywhere (driverless) for all clients? (from PC-083)
- ORQ-167: Out of scope (recommend Nextcloud client)? (from PC-084)
- ORQ-168: Implement minimal CSC-compatible cache? (from PC-084)

### Client SDK

- ORQ-169: Adopt gRPC-based SDK with platform-native auth adapters? (from PC-085)
- ORQ-170: Per-language bindings (Rust core)? (from PC-085)
- ORQ-171: Provide MDM profile templates for PSSO + Kerberos sub-payload? (from PC-086)
- ORQ-172: Auto-config via framework client SDK? (from PC-086)
- ORQ-173: Auto-migrate Jamf Connect deployments to PSSO? (from PC-087)
- ORQ-174: Provide sync agent for non-MDM Macs? (from PC-087)
- ORQ-175: Extend SSSD or write a new client? (from PC-088)
- ORQ-176: Adopt FreeIPA client as the base? (from PC-088)
- ORQ-177: Drop POSIX UIDs entirely (use UUIDs everywhere)? (from PC-089)
- ORQ-178: Standardize on one algorithm (SSSD slice)? (from PC-089)
- ORQ-179: Standardize on MIT krb5 everywhere? (from PC-090)
- ORQ-180: Contribute macOS Heimdal fork upstream? (from PC-090)
- ORQ-181: Adopt modern device enrollment (Windows Autopilot, Apple DEP, Linux cloud-init style)? (from PC-091)
- ORQ-182: Per-OS adapters? (from PC-091)
- ORQ-183: Provide framework-native PAM module + profile generator? (from PC-092)
- ORQ-184: Adopt `authselect` as the standard? (from PC-092)
- ORQ-185: Adopt KCM as the Linux standard + API: on macOS? (from PC-093)
- ORQ-186: Provide a unified cache abstraction? (from PC-093)

### Cross-Platform Parity

- ORQ-187: Provide NTLM via Samba winbind on macOS? (from PC-094)
- ORQ-188: Document legacy apps as out of scope? (from PC-094)
- ORQ-189: OPA Rego as the unified format? (from PC-095)
- ORQ-190: JSON Schema + per-platform executors? (from PC-095)
- ORQ-191: Per-policy-type DSL? (from PC-095)
- ORQ-192: Adopt DDM-first authoring? (from PC-096)
- ORQ-193: Auto-fallback to Configuration Profile? (from PC-096)
- ORQ-194: Per-computer recovery key in framework directory? (from PC-097)
- ORQ-195: NBDE (Clevis/Tang) for all platforms? (from PC-097)
- ORQ-196: Per-host password in framework directory with ACL-gated read? (from PC-098)
- ORQ-197: Adopt Windows LAPS schema for compat? (from PC-098)
- ORQ-198: Hard-deprecate Winbind for NSS/PAM (keep for SMB only)? (from PC-099)
- ORQ-199: Auto-migrate PBIS to SSSD? (from PC-099)
- ORQ-200: Provide first-party macOS client SDK that fills GPO/DFS-N/ABE gaps? (from PC-100)
- ORQ-201: Document third-party as required? (from PC-100)
- ORQ-202: Adopt FreeIPA as the Linux tier? (from PC-101)
- ORQ-203: Build native IPA-equivalent in the framework? (from PC-101)
- ORQ-204: Kubernetes-style read-replica with no secrets? (from PC-102)
- ORQ-205: Edge-deployed DC with HSM-bound subset? (from PC-102)
- ORQ-206: Document as out of scope? (from PC-103)
- ORQ-207: Provide migration tooling to FreeIPA? (from PC-103)
- ORQ-208: Document migration paths from Centrify/PBIS to PSSO? (from PC-104)
- ORQ-209: Provide import tooling for dzdo rules → sudoers? (from PC-104)
- ORQ-210: Contribute Apple Heimdal fork upstream? (from PC-105)
- ORQ-211: Document PSSO as the only modern path? (from PC-105)

### Operations

- ORQ-212: Adopt OTel semantic conventions for AD/Kerberos? (from PC-106)
- ORQ-213: Per-DC metrics or per-realm aggregation? (from PC-106)
- ORQ-214: Schema-as-code (Git-backed)? (from PC-107)
- ORQ-215: Typed-schema with versioned migrations? (from PC-107)
- ORQ-216: Per-region PDC? (from PC-108)
- ORQ-217: Active-active multi-region with conflict-free replicated data types? (from PC-108)
- ORQ-218: Container image per DC? (from PC-109)
- ORQ-219: Operator for DC lifecycle (promote/demote/backup)? (from PC-109)
- ORQ-220: Per-DC backup with PITR? (from PC-110)
- ORQ-221: Operator-driven DR runbooks? (from PC-110)
- ORQ-222: OTel semantic conventions for AD/Kerberos/GPO? (from PC-111)
- ORQ-223: MITRE ATT&CK technique IDs in event metadata? (from PC-111)
- ORQ-224: REST over directory (CRUD on objects)? (from PC-112)
- ORQ-225: gRPC for streaming (replication status)? (from PC-112)
- ORQ-226: GraphQL for flexible queries? (from PC-112)
- ORQ-227: Drop functional levels entirely (always-latest schema)? (from PC-113)
- ORQ-228: Per-feature flags instead? (from PC-113)
- ORQ-229: Auto-reset on desync detection? (from PC-114)
- ORQ-230: Per-trust rotation policy? (from PC-114)
- ORQ-231: Adopt `samba-tool` as the base? (from PC-115)
- ORQ-232: Write fresh CLI in Go/Rust? (from PC-115)

### Security

- ORQ-233: Auto-detect Kerberoast attempts via 4769 events with etype 0x17? (from PC-116)
- ORQ-234: Force-migrate service accounts to AES on next rotation? (from PC-116)
- ORQ-235: Per-principal `DS-Replication-Get-Changes-All` audit? (from PC-117)
- ORQ-236: Break-glass replication via HSM-bound key? (from PC-117)
- ORQ-237: HSM-bound krbtgt key? (from PC-118)
- ORQ-238: Automatic rotation every N days? (from PC-118)
- ORQ-239: Default-validate by services (perf cost)? (from PC-119)
- ORQ-240: Token-binding alternative? (from PC-119)
- ORQ-241: Drop sIDHistory entirely (use only current SIDs)? (from PC-120)
- ORQ-242: Per-trust filtering policy? (from PC-120)
- ORQ-243: Per-OU selective auth? (from PC-121)
- ORQ-244: FreeIPA HBAC-style server-side evaluation? (from PC-121)
- ORQ-245: Replace AdminSDHolder with declarative RBAC? (from PC-122)
- ORQ-246: Per-protected-group templates? (from PC-122)
- ORQ-247: Sigstore (cosign) for framework binaries? (from PC-123)
- ORQ-248: In-toto attestations? (from PC-123)

### Migration

- ORQ-249: Replace sIDHistory with claims-based migration? (from PC-124)
- ORQ-250: Document ADMT as the only migration path? (from PC-124)
- ORQ-251: Auto-translate known ADMX settings to native? (from PC-125)
- ORQ-252: Per-setting review UI? (from PC-125)
- ORQ-253: Per-SPN migration (move one service at a time)? (from PC-126)
- ORQ-254: Per-user migration (move one user at a time)? (from PC-126)
- ORQ-255: Password-sync agent protocol (proprietary or standard)? (from PC-127)
- ORQ-256: Per-batch migration? (from PC-127)
- ORQ-257: Subdomain per directory (`ad.corp.example.com` + `new.corp.example.com`)? (from PC-128)
- ORQ-258: Per-record migration? (from PC-128)
- ORQ-259: Auto-generate `capaths` from trust graph? (from PC-129)
- ORQ-260: Per-realm KDC discovery via DNS SRV? (from PC-129)
- ORQ-261: Per-domain SYSVOL with DFS-N referral? (from PC-130)
- ORQ-262: Migrate to HTTP-based policy distribution? (from PC-130)

## Cross-cutting research questions

These themes recur across multiple capabilities and must be resolved at the architecture level — they cannot be answered by a single capability team in isolation.

### 1. AD-interop vs. clean-slate (the foundational tension)

Spans: PC-001, PC-002, PC-007, PC-017, PC-023, PC-036, PC-057, PC-068, PC-078, PC-094, PC-099, PC-103, PC-124.

Every protocol-level decision trades interop with existing AD deployments against the freedom to design something better. The framework must pick a lane per protocol: full compat (speak MS-DRSR), compat-with-shim (speak MS-DRSR + extension), or clean-slate (speak Raft/OT). The choice cascades: if DRSUAPI is implemented for interop, the UTD vector model is forced; if a clean-slate CRDT model is chosen, AD-interop is lost. Related ORQs: ORQ-001, ORQ-002, ORQ-030, ORQ-031, ORQ-042, ORQ-043, ORQ-044, ORQ-072, ORQ-110, ORQ-132, ORQ-133, ORQ-154, ORQ-155, ORQ-202, ORQ-203, ORQ-249, ORQ-250.

### 2. Multi-master vs. consensus (the replication tension)

Spans: PC-002, PC-009, PC-014, PC-016, PC-022, PC-043, PC-074, PC-108.

AD is multi-master with last-writer-wins conflict resolution. Modern systems prefer Raft/Paxos for strong consistency. The framework must decide: stay multi-master (compat) or move to consensus (correctness)? If consensus, what is the failure mode when a quorum member is unavailable? Related ORQs: ORQ-003, ORQ-004, ORQ-016, ORQ-017, ORQ-024, ORQ-025, ORQ-083, ORQ-146, ORQ-147, ORQ-216, ORQ-217.

### 3. LDAP schema vs. typed schema (the schema tension)

Spans: PC-017, PC-021, PC-046, PC-058, PC-107, PC-113.

AD's schema is dynamic, attribute-based, LDAP-defined. Modern systems prefer typed schemas (protobuf, SQL DDL, JSON Schema). The framework must choose, and the choice cascades into the directory API, the replication protocol, and the client SDK. Related ORQs: ORQ-030, ORQ-031, ORQ-038, ORQ-039, ORQ-088, ORQ-089, ORQ-112, ORQ-113, ORQ-214, ORQ-215, ORQ-227, ORQ-228.

### 4. SIDs vs. UUIDs (the identity tension)

Spans: PC-015, PC-026, PC-089, PC-124, PC-127.

AD uses SIDs for security principals. Modern systems prefer UUIDs. The framework must decide whether to use SIDs (interop), UUIDs (modern), or both (with mapping). sIDHistory migration (PC-124) is the immediate pressure point. Related ORQs: ORQ-026, ORQ-027, ORQ-177, ORQ-178, ORQ-241, ORQ-249, ORQ-250.

### 5. GPO format vs. declarative policy (the policy tension)

Spans: PC-043 through PC-056, PC-095, PC-125, PC-130.

AD's GPO is INI/registry.pol-based, fragile, no rollback. Modern alternatives (Salt, Ansible, Kubernetes operators) are declarative, versioned, transactional. The framework must decide: keep GPO format (interop), adopt declarative (modern), or hybrid? Related ORQs: ORQ-082, ORQ-083, ORQ-088, ORQ-089, ORQ-090, ORQ-091, ORQ-100, ORQ-101, ORQ-189, ORQ-190, ORQ-191, ORQ-251, ORQ-252, ORQ-261, ORQ-262.

### 6. NTLM: drop or maintain compat (the legacy-auth tension)

Spans: PC-036, PC-037, PC-038, PC-039, PC-094.

NTLM is broken (pass-the-hash, relay). But many legacy apps require it. The framework must decide: drop NTLM entirely (secure), maintain NTLM (compat), or maintain NTLM with hard mitigations (channel binding, EPA, signing). Related ORQs: ORQ-068, ORQ-069, ORQ-070, ORQ-071, ORQ-072, ORQ-074, ORQ-075, ORQ-187, ORQ-188.

### 7. PKI: AD CS protocols vs. ACME/EST (the PKI tension)

Spans: PC-057 through PC-067, PC-123.

AD CS uses MS-WCCE/MS-XCEP for enrollment. Modern PKI uses ACME (RFC 8555) or EST (RFC 7030). The framework must decide: implement MS-WCCE (interop) or adopt ACME (modern)? Related ORQs: ORQ-110, ORQ-111, ORQ-124, ORQ-125, ORQ-126, ORQ-127, ORQ-128, ORQ-129, ORQ-130, ORQ-131, ORQ-247, ORQ-248.

### 8. Federation: AD FS topology vs. modern IdP (the IdP tension)

Spans: PC-068 through PC-077.

AD FS is a separate farm with SQL/WID. Modern IdPs (Keycloak, Authentik, Ory, Zitadel) are lighter and cloud-native. The framework must decide: re-implement AD FS (interop) or wrap a modern IdP? Related ORQs: ORQ-132, ORQ-133, ORQ-134, ORQ-135, ORQ-136, ORQ-137, ORQ-140, ORQ-141, ORQ-148, ORQ-149, ORQ-150, ORQ-151.

### 9. Multi-tenancy: native vs. per-instance (the tenancy tension)

Spans: PC-022, PC-067, PC-076, PC-101, PC-102.

AD has no native multi-tenancy. Cloud-native systems expect multi-tenancy. The framework must decide: support multi-tenancy natively (modern) or document why not (interop with AD's single-tenant model)? Related ORQs: ORQ-040, ORQ-041, ORQ-130, ORQ-131, ORQ-151, ORQ-202, ORQ-203, ORQ-204, ORQ-205.

### 10. Client SDK: per-platform or unified (the SDK tension)

Spans: PC-085 through PC-093, PC-094 through PC-105.

There is no universal AD client SDK today. The framework must decide: provide a unified C/Rust/Go SDK with platform bindings, or wrap existing per-platform libraries (SSSD, OpenDirectory, Wldap32)? Related ORQs: ORQ-169, ORQ-170, ORQ-175, ORQ-176, ORQ-177, ORQ-178, ORQ-179, ORQ-180, ORQ-181, ORQ-182, ORQ-200, ORQ-201.

### 11. HSM binding for high-value keys (the key-management tension)

Spans: PC-035, PC-060, PC-066, PC-117, PC-118, PC-123.

Several capabilities have high-value keys that should never leave an HSM: krbtgt, KDS root key, KRA private keys, CA private keys, framework binary signing keys. The framework must decide whether HSM binding is a hard requirement (Tier 0 feature) or optional (Tier 3 nice-to-have). Related ORQs: ORQ-057, ORQ-063, ORQ-066, ORQ-067, ORQ-116, ORQ-117, ORQ-128, ORQ-236, ORQ-237, ORQ-247.

### 12. Git-backed declarative everything (the GitOps tension)

Spans: PC-043, PC-056, PC-107, PC-115, PC-125.

Multiple capabilities hint at Git-backed declarative configuration: schema (PC-107), GPO (PC-043, PC-056), framework policies (PC-125). The framework must decide whether to standardise on Git as the source of truth for all declarative configuration, with the directory as a materialised view. Related ORQs: ORQ-082, ORQ-106, ORQ-107, ORQ-108, ORQ-214, ORQ-215, ORQ-251, ORQ-252.

## Prioritization

Research questions are tiered by when they must be answered in the framework's design lifecycle. Tier 1 must be answered before design begins (architectural decisions); Tier 2 must be answered before implementation begins (per-capability design); Tier 3 can be answered during implementation (per-feature decisions).

### Tier 1 (must answer before design begins)

These are architectural decisions that cascade across multiple capabilities. Picking wrong is expensive to undo.

- ORQ-001 / ORQ-002 / ORQ-003 / ORQ-004: Replication protocol choice (DRSUAPI vs. CRDT vs. Raft). Affects every Core Directory + Operations + Migration problem.
- ORQ-011 / ORQ-012 / ORQ-013 / ORQ-014: Storage engine choice (ESE vs. SQLite vs. FoundationDB vs. custom). Affects every Core Directory + Operations problem.
- ORQ-026 / ORQ-027: SID vs. UUID for security principals. Affects every Core Directory + KDC + Auth Provider + Migration problem.
- ORQ-030 / ORQ-031: LDAP schema vs. typed schema. Affects every Core Directory + Client SDK + Operations problem.
- ORQ-042 / ORQ-043 / ORQ-044: KDC implementation choice (Samba Heimdal vs. MIT krb5 vs. fresh). Affects every KDC + Auth Provider + Client SDK problem.
- ORQ-072 / ORQ-074 / ORQ-075: NTLM decision (drop vs. maintain). Affects every Auth Provider + Client SDK + Cross-Platform Parity problem.
- ORQ-110 / ORQ-111: PKI enrollment protocol (MS-WCCE vs. ACME). Affects every Cert Service + Client SDK problem.
- ORQ-132 / ORQ-133 / ORQ-134: Federation layer (Keycloak vs. native vs. cloud). Affects every Federation Gateway + Client SDK problem.
- ORQ-154 / ORQ-155: SMB server choice (Samba vs. fresh). Affects every File Gateway + Client SDK problem.
- ORQ-169 / ORQ-170 / ORQ-175 / ORQ-176: Client SDK architecture (gRPC + Rust core vs. extend SSSD vs. adopt FreeIPA client). Affects every Client SDK + Cross-Platform Parity problem.
- ORQ-202 / ORQ-203: Linux tier strategy (adopt FreeIPA vs. build native). Affects every Linux-side problem.

### Tier 2 (must answer before implementation begins)

These are per-capability design decisions that should be locked in before code is written.

- ORQ-024 / ORQ-025: FSMO replacement (Raft vs. multi-master with version vectors).
- ORQ-032: `memberOf` computation strategy (event-driven cache vs. read-time).
- ORQ-057 / ORQ-058: krbtgt key management (HSM-bound vs. file-backed; auto-rotation interval).
- ORQ-059 / ORQ-060: SPN uniqueness scope (per-forest vs. per-domain).
- ORQ-082 / ORQ-083 / ORQ-088 / ORQ-089: Policy format (YAML vs. CRDT vs. Rego vs. DSL).
- ORQ-102 / ORQ-103: HBAC vs. URA for access control.
- ORQ-116 / ORQ-117: KRA key management (HSM + Shamir).
- ORQ-118 / ORQ-122: CRLite adoption for CRL compression.
- ORQ-135 / ORQ-136 / ORQ-137: Claims-policy language (Rego vs. Cedar vs. plugins).
- ORQ-161 / ORQ-162: SMB container strategy (CSI vs. CTDB).
- ORQ-177 / ORQ-178: POSIX UID strategy (drop vs. standardise).
- ORQ-194 / ORQ-195: Disk-encryption key escrow (per-computer in directory vs. NBDE).
- ORQ-214 / ORQ-215: Schema-as-code (Git-backed vs. typed-schema).
- ORQ-218 / ORQ-219: DC containerisation (per-DC image vs. operator).
- ORQ-224 / ORQ-225 / ORQ-226: REST/gRPC/GraphQL API surface for directory.
- ORQ-233 / ORQ-234: Kerberoasting detection (4769 etype 0x17 alerting) and AES migration strategy.
- ORQ-237 / ORQ-238: krbtgt HSM binding + auto-rotation.
- ORQ-241 / ORQ-242: sIDHistory future (drop vs. per-trust filtering policy).
- ORQ-247 / ORQ-248: Supply-chain (Sigstore + in-toto) adoption.
- ORQ-249 / ORQ-250: sIDHistory migration alternative (claims-based vs. ADMT-only).
- ORQ-253 / ORQ-254: Migration granularity (per-SPN vs. per-user).
- ORQ-255 / ORQ-256: Password-sync agent protocol (proprietary vs. standard).

### Tier 3 (can answer during implementation)

These are per-feature decisions that can be made incrementally as code is written.

- ORQ-005: linkID pairs vs. graph database for membership.
- ORQ-006 / ORQ-007: `memberOf` storage strategy details.
- ORQ-008 / ORQ-009: PAS replica alternative.
- ORQ-010: Schema cache lock elimination strategy.
- ORQ-015: sdtable design (BLAKE3 + persistent map).
- ORQ-018 / ORQ-019: Cross-domain move relevance.
- ORQ-020 / ORQ-021: Well-known GUIDs (REST URL vs. legacy LDAP-only).
- ORQ-022: LDAP controls essential for greenfield vs. migration.
- ORQ-023: BER-quote form in AD-compat mode.
- ORQ-028 / ORQ-029: KCC replacement (declarative YAML vs. AD-compat).
- ORQ-033 / ORQ-034: DNS externalisation (CoreDNS plugin vs. in-directory).
- ORQ-035 / ORQ-036 / ORQ-037: Backup mechanism (CRIU vs. LVM vs. storage-engine-native).
- ORQ-038 / ORQ-039: `userAccountControl` bitmask vs. explicit attributes.
- ORQ-045 / ORQ-046: RC4 TGS migration mode.
- ORQ-047 / ORQ-048: PAC always-validate mode vs. token-binding.
- ORQ-049 / ORQ-050: FAST-required compat with legacy clients.
- ORQ-051 / ORQ-052: FIDO2 + PKINIT passwordless path.
- ORQ-053 / ORQ-054: Transited-field replacement.
- ORQ-055 / ORQ-056: etype 0x13 (AES SHA-384) adoption timing.
- ORQ-061 / ORQ-062: SPN uniqueness strictness.
- ORQ-064: Per-realm KDC pool strategy.
- ORQ-065: OAuth2 password-reset endpoint.
- ORQ-066 / ORQ-067: Vault integration for service-account secrets.
- ORQ-068 / ORQ-069: NTLM emulation via Kerberos.
- ORQ-076 / ORQ-077: WebAuthn token-binding abstraction.
- ORQ-078 / ORQ-079: MS-SNTP replacement.
- ORQ-080 / ORQ-081: ATT&CK mapping + OTel semantic conventions for Kerberos.
- ORQ-084 / ORQ-085: Policy conflict resolution strategy.
- ORQ-086 / ORQ-087: OPA-style declarative policy executor model.
- ORQ-090 / ORQ-091: Per-platform policy executor plugins.
- ORQ-092 / ORQ-093: Per-CSE snapshot / Git-style revert.
- ORQ-094 / ORQ-095: WMI filter replacement.
- ORQ-096 / ORQ-097: Slow-link detection alternative.
- ORQ-098 / ORQ-099: Push channel for policy updates.
- ORQ-100 / ORQ-101: Policy payload format.
- ORQ-104 / ORQ-105: Per-principal ACL replacement with RBAC.
- ORQ-106 / ORQ-107: Git-backed SYSVOL strategy.
- ORQ-108 / ORQ-109: Policy audit logging.
- ORQ-112 / ORQ-113: CA template schema.
- ORQ-114 / ORQ-115: Certmonger-style daemon + ACME/SCEP dual-protocol.
- ORQ-119: Multi-responder OCSP clustering.
- ORQ-120 / ORQ-121: CA storage backend.
- ORQ-123: Multi-CDP HTTP fallback.
- ORQ-124 / ORQ-125: Single enrollment endpoint vs. per-protocol adapters.
- ORQ-126 / ORQ-127: Trust-manager model.
- ORQ-129: Cloud-based root CA.
- ORQ-130 / ORQ-131: NTAuthCertificates replacement.
- ORQ-138 / ORQ-139: Token-signing cert rollover notification.
- ORQ-140 / ORQ-141: WS-* support strategy.
- ORQ-142 / ORQ-143: SAML clock skew handling.
- ORQ-144 / ORQ-145: WAP replacement (oauth2-proxy vs. Envoy).
- ORQ-146 / ORQ-147: Federation config storage.
- ORQ-148 / ORQ-149: OIDC `resource=` compat mode.
- ORQ-150 / ORQ-151: Identity brokering + per-tenant routing.
- ORQ-152 / ORQ-153: AD RMS support scope.
- ORQ-156: macOS SMBX kernel ext reuse.
- ORQ-157 / ORQ-158: SMB1 hard cut vs. compat shim.
- ORQ-159 / ORQ-160: DFS-N replacement.
- ORQ-163 / ORQ-164: ABE pre-computed index.
- ORQ-165 / ORQ-166: Print spooler replacement.
- ORQ-167 / ORQ-168: Offline files scope.
- ORQ-171 / ORQ-172: MDM profile templates.
- ORQ-173 / ORQ-174: Jamf Connect migration.
- ORQ-179 / ORQ-180: MIT krb5 standardisation.
- ORQ-181 / ORQ-182: Device enrollment strategy.
- ORQ-183 / ORQ-184: PAM module strategy.
- ORQ-185 / ORQ-186: KCM standardisation.
- ORQ-187 / ORQ-188: macOS NTLM via winbind.
- ORQ-189 / ORQ-190 / ORQ-191: Policy DSL unification.
- ORQ-192 / ORQ-193: DDM-first authoring.
- ORQ-196 / ORQ-197: LAPS schema.
- ORQ-198 / ORQ-199: Winbind deprecation.
- ORQ-200 / ORQ-201: macOS first-party SDK.
- ORQ-204 / ORQ-205: RODC replacement.
- ORQ-206 / ORQ-207: OpenLDAP+MIT scope.
- ORQ-208 / ORQ-209: Centrify/PBIS migration paths.
- ORQ-210 / ORQ-211: Heimdal fork upstreaming.
- ORQ-212 / ORQ-213: OTel semantic conventions.
- ORQ-220 / ORQ-221: DR runbook automation.
- ORQ-222 / ORQ-223: OTel conventions + ATT&CK mapping.
- ORQ-227 / ORQ-228: Functional levels vs. feature flags.
- ORQ-229 / ORQ-230: Trust password rotation automation.
- ORQ-231 / ORQ-232: Unified CLI base (samba-tool vs. fresh Go/Rust).
- ORQ-235: Per-principal DRSRep audit.
- ORQ-239 / ORQ-240: Silver ticket validation default.
- ORQ-243 / ORQ-244: Selective auth alternative.
- ORQ-245 / ORQ-246: AdminSDHolder replacement.
- ORQ-251 / ORQ-252: ADMX auto-translation.
- ORQ-257 / ORQ-258: DNS namespace sharing strategy.
- ORQ-259 / ORQ-260: capaths auto-generation.
- ORQ-261 / ORQ-262: SYSVOL migration strategy.

## How to use this list

- **Architects**: start with Tier 1 — every Tier 1 question must be answered before the design phase begins. Use the cross-cutting themes section to understand dependencies.
- **Capability leads**: walk through your capability's ORQs and propose answers in your design doc. Tier 2 ORQs should be locked before implementation.
- **Engineers**: pick a Tier 3 ORQ relevant to your current work, run a research spike, and document the decision in your PR description.
- **Sponsors**: Tier 1 decisions are the highest-leverage architectural choices. Expect 1-2 week spikes per Tier 1 question.

## References

- Source problems: [01-core-directory.md](./01-core-directory.md) through [12-migration-and-coexistence.md](./12-migration-and-coexistence.md).
- Cross-platform impact: [14-cross-platform-parity-matrix.md](./14-cross-platform-parity-matrix.md).
- Capability taxonomy: [00-framework-capabilities.md](./00-framework-capabilities.md).
