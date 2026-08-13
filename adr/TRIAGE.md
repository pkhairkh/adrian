---
title: ADR Triage — Problem Eligibility Assessment
audience: architects-and-engineers
tags: [adr, triage, decision-records, framework-design]
related:
  - ./README.md
  - ../catalog/README.md
  - ../catalog/13-open-research-questions.md
  - ../draft/04-open-research-questions.md
last_updated: 2026-08-13
---

# ADR Triage

For each of the 130 problems in the catalog, this document records whether a high-confidence ADR (Architecture Decision Record) can be written. Downstream sub-agents use this triage to decide which ADRs to write.

## Triage methodology

Each of the 130 problems was triaged against four criteria (per the triage analyst's task description):

1. **Clear technical answer** — there is a well-established best practice, an obvious modern choice, or a single defensible option.
2. **No Tier-1 ORQ dependency** — the decision does not depend on any of the 11 Tier-1 Open Research Questions listed in [`catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md) §"Tier 1": replication protocol (ORQ-001/002/003/004), storage engine (ORQ-011/012/013/014), SID vs UUID (ORQ-026/027), schema model (ORQ-030/031), KDC implementation (ORQ-042/043/044), NTLM decision (ORQ-072/074/075), PKI enrollment protocol (ORQ-110/111), federation layer (ORQ-132/133/134), SMB server (ORQ-154/155), Client SDK architecture (ORQ-169/170/175/176), Linux tier strategy (ORQ-202/203).
3. **Not reversible by a research spike** — no research spike from [`draft/04-open-research-questions.md`](../draft/04-open-research-questions.md) §6 (7 spikes) would reverse the decision.
4. **Resolves the problem** — the chosen solution fully addresses the problem statement.

Each problem receives one of three labels:

- **ADR-ELIGIBLE** — all four criteria met; high-confidence ADR can be written.
- **DEFERRED** — at least one criterion fails (typically Tier-1 ORQ dependency); do not write an ADR until the gating ORQ is resolved.
- **PARTIAL** — the problem has a clearly confident sub-decision and an uncertain sub-decision; write the ADR for the confident part and explicitly defer the uncertain part to "Open Questions" in the ADR.

## Statistics

- Total problems triaged: 130
- ADR-eligible (high confidence): 60
- Deferred (depends on Tier-1 ORQ or research spike): 61
- Partial (ADR for confident part, defer rest): 9
- Total ADRs to be written: 69 (60 ADR-ELIGIBLE + 9 PARTIAL)

## Per-capability summary

| Capability | Problems | ADR-eligible | Partial | Deferred | ADRs to write |
|-----------|----------|--------------|---------|----------|---------------|
| Core Directory (PC-001..PC-022) | 22 | 8 | 2 | 12 | 10 |
| KDC (PC-023..PC-035) | 13 | 8 | 2 | 3 | 10 |
| Auth Provider (PC-036..PC-042) | 7 | 3 | 0 | 4 | 3 |
| Policy Engine (PC-043..PC-056) | 14 | 7 | 1 | 6 | 8 |
| Cert Service (PC-057..PC-067) | 11 | 5 | 1 | 5 | 6 |
| Federation Gateway (PC-068..PC-077) | 10 | 5 | 0 | 5 | 5 |
| File Gateway (PC-078..PC-084) | 7 | 4 | 1 | 2 | 5 |
| Client SDK (PC-085..PC-093) | 9 | 4 | 0 | 5 | 4 |
| Cross-Platform Parity (PC-094..PC-105) | 12 | 5 | 0 | 7 | 5 |
| Operations (PC-106..PC-115) | 10 | 5 | 2 | 3 | 7 |
| Security (PC-116..PC-123) | 8 | 4 | 0 | 4 | 4 |
| Migration (PC-124..PC-130) | 7 | 2 | 0 | 5 | 2 |
| **Total** | **130** | **60** | **9** | **61** | **69** |

## Triage table

| PC | Title (short) | Capability | Severity | Decision | Reason / seed decision |
|----|---------------|-----------|----------|----------|------------------------|
| PC-001 | DRSUAPI replication protocol | Core Directory | blocker | DEFERRED | Tier-1 ORQ-001/002 (replication protocol choice); also covered by Spike 1 |
| PC-002 | USN/InvocationID/UTD-vector model | Core Directory | blocker | DEFERRED | Tier-1 ORQ-003/004 (UTD vector vs CRDT tombstone vs Raft log); covered by Spike 1 |
| PC-003 | Linked Value Replication (LVR) | Core Directory | high | ADR-ELIGIBLE | Implement per-value metadata for multi-valued linked attributes (LVR-style) regardless of replication protocol — without it, large groups don't scale |
| PC-004 | member/memberOf back-link | Core Directory | blocker | ADR-ELIGIBLE | Implement memberOf as a DSA-computed back-link via linkID pairing; clients cannot write memberOf directly (DSA rejects with unwillingToPerform) |
| PC-005 | Global Catalog PAS replication | Core Directory | high | DEFERRED | Tier-1 ORQ-001/002 (replication protocol determines whether PAS replication, single-global-store, or query-routing is used) |
| PC-006 | Schema cache reload blocks writes | Core Directory | medium | ADR-ELIGIBLE | Implement copy-on-write schema cache with monotonic generation numbers; readers never block writers |
| PC-007 | ESE/JET Blue storage engine | Core Directory | blocker | DEFERRED | Tier-1 ORQ-011/012/013/014 (storage engine choice); covered by Spike 2 |
| PC-008 | Security descriptor dedup (sdtable) | Core Directory | medium | ADR-ELIGIBLE | Implement SD deduplication via content-hash indexed table (sdtable equivalent); hash function and storage layout are Tier-3 implementation details |
| PC-009 | Tombstone lifetime and lingering objects | Core Directory | high | DEFERRED | Tier-1 ORQ-001/002 (replication protocol determines tombstone model: AD tombstones vs CRDT tombstone vectors vs Raft log truncation) |
| PC-010 | Cross-domain move | Core Directory | medium | DEFERRED | Gated by Tier-1 ORQ-026/027 (identity model) and ORQ-030/031 (schema model) — cross-domain move presumes multi-domain forests which depend on the identity/schema architectural choice |
| PC-011 | Well-known container GUIDs | Core Directory | medium | ADR-ELIGIBLE | Reserve and honor the well-known container GUIDs (Users, Computers, Domain Controllers, etc.) as forest-wide constants for AD-interop |
| PC-012 | AD-specific LDAP controls | Core Directory | high | ADR-ELIGIBLE | Implement the core set of AD-specific LDAP controls for client interop (paged results, server-side sort, directory synchronization, cross-domain move, deletion, notification, lazy commit); defer the complete enumerated list to Tier 3 |
| PC-013 | unicodePwd BER-quote trick | Core Directory | medium | ADR-ELIGIBLE | Use kpasswd (RFC 3244) as the primary password-change protocol; support AD's BER-quote unicodePwd LDAP modification form only in AD-compat mode |
| PC-014 | FSMO roles single-master bottleneck | Core Directory | high | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) — if DRSUAPI, FSMO is forced; if Raft, FSMO is replaced; Tier-2 ORQ-024/025 is gated by Tier-1 |
| PC-015 | RID pool allocation bottleneck | Core Directory | high | DEFERRED | Tier-1 ORQ-026/027 (identity model) — RID pool only applies if SIDs are kept; if UUIDs replace SIDs, RID pool is eliminated |
| PC-016 | KCC topology generation scaling | Core Directory | medium | ADR-ELIGIBLE | Use declarative YAML topology configuration as the primary mechanism; provide AD-compat adapter for cn=Sites,cn=Configuration in AD-interop mode |
| PC-017 | LDAP schema vs typed schema | Core Directory | high | DEFERRED | Tier-1 ORQ-030/031 (schema model choice) — directly the Tier-1 question |
| PC-018 | Constructed attributes (memberOf, tokenGroups, canonicalName) | Core Directory | high | PARTIAL | Confident: support constructed attributes via DSA-side computation, marked operational (not returned by default). Deferred (Tier-2 ORQ-032): caching strategy (event-driven write-time cache vs read-time computation) for tokenGroups |
| PC-019 | AD-integrated DNS zones | Core Directory | high | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) — DNS zone replication via DRSUAPI NCs only applies if DRSUAPI is chosen; clean-slate could use CoreDNS plugin |
| PC-020 | NTDS.DIT backup/restore (VSS) | Core Directory | high | PARTIAL | Confident: use storage-engine-native backup APIs (snapshot/checkpoint) and filesystem-level snapshots (LVM/ZFS); eliminate VSS dependency; document restore-from-backup as the canonical recovery. Deferred: specific backup API depends on Tier-1 storage engine choice (ORQ-011/012/013/014) |
| PC-021 | instanceType/systemFlags bitmasks | Core Directory | medium | DEFERRED | Tier-1 ORQ-030/031 (schema model) — bitmask vs explicit-attributes depends on whether typed schema is adopted |
| PC-022 | Multi-tenancy not native to AD | Core Directory | high | DEFERRED | Cross-cutting Tier-1 architectural question (tenancy theme); cascades from identity model ORQ-026/027 |
| PC-023 | MS-KILE profile + PAC generation | KDC | blocker | DEFERRED | Tier-1 ORQ-042/043/044 (KDC implementation choice); covered by Spike 3 |
| PC-024 | RC4-HMAC default (Kerberoasting) | KDC | blocker | ADR-ELIGIBLE | Default to AES-256-CTS-HMAC-SHA1-96 (etype 0x12); disable RC4-HMAC (0x17) by default; provide audit-logged migration mode for legacy service accounts |
| PC-025 | PAC validation RPC roundtrip | KDC | high | DEFERRED | Tier-1 ORQ-042/043/044 (KDC implementation) — PAC validation mechanism (NETLOGON RPC vs PAC_TICKET_CHECKSUM) depends on KDC implementation |
| PC-026 | FAST (RFC 6806) armoring opt-in | KDC | high | ADR-ELIGIBLE | Require FAST (RFC 6806) armoring by default for all Kerberos exchanges; provide audit-only mode and grace-period for legacy client migration |
| PC-027 | PKINIT smart-card logon | KDC | high | DEFERRED | Tier-1 ORQ-110/111 (PKI enrollment protocol) — NTAuthCertificates + Enterprise CA dependency ties PKINIT to the PKI protocol choice |
| PC-028 | Cross-realm TGT referral + transited field | KDC | medium | ADR-ELIGIBLE | Implement RFC 4120 cross-realm TGT referral and transited-field validation correctly per spec; document capaths configuration as the modern mechanism for explicit cross-realm policy |
| PC-029 | AES-SHA384 (etype 0x13) | KDC | low | PARTIAL | Confident: support AES-256-CTS-HMAC-SHA384-192 (etype 0x13); prefer 0x13 over 0x12 when both endpoints support it. Deferred (Tier-3 ORQ-055/056): default-etype-change timeline and 0x12 fallback grace period |
| PC-030 | krbtgt account compromise (golden ticket) | KDC | blocker | ADR-ELIGIBLE | Bind the krbtgt account's key material to an HSM (key never leaves HSM in plaintext); auto-rotate on a 30-day interval with a 2-key overlap window during rollover |
| PC-031 | SPN uniqueness (DRSWriteSPN) | KDC | high | PARTIAL | Confident: enforce SPN uniqueness at the KDC/DC level via pre-commit check (DRSWriteSPN-equivalent). Deferred (Tier-2 ORQ-059/060): uniqueness scope (per-forest vs per-domain with cross-domain conflict detection) |
| PC-032 | UPN uniqueness forest-wide | KDC | high | ADR-ELIGIBLE | Enforce UPN uniqueness strictly at write time (forest-wide); reject conflicting writes with constraint-violation LDAP error |
| PC-033 | KDC throughput at million-object scale | KDC | high | ADR-ELIGIBLE | Deploy KDC as a horizontally-scalable stateless pool behind a load balancer; share krbtgt key material via HSM so any KDC can service any request |
| PC-034 | kpasswd (RFC 3244) | KDC | medium | ADR-ELIGIBLE | Use kpasswd (RFC 3244) as the primary password-change protocol for Kerberos-aware clients; provide a REST API wrapper for modern non-Kerberos clients |
| PC-035 | gMSA (KDS root key + auto-rotation) | KDC | high | ADR-ELIGIBLE | Support group Managed Service Accounts with automatic password rotation (N-day interval); bind the gMSA root key to HSM; defer the root-key distribution mechanism (KDS vs Vault) to Tier 3 |
| PC-036 | NTLM legacy interop | Auth Provider | high | DEFERRED | Tier-1 ORQ-072/074/075 (NTLM decision); covered by Spike 4 |
| PC-037 | NTLM relay attacks (LDAP signing + channel binding + EPA) | Auth Provider | blocker | ADR-ELIGIBLE | Require LDAP signing and TLS channel binding (RFC 5929) on all DC connections; mandate Extended Protection for Authentication (EPA) on all HTTP/LDAP/SMB services; reject clients that don't support these |
| PC-038 | Pass-the-hash (LSASS protection / Credential Guard) | Auth Provider | blocker | DEFERRED | Tier-1 ORQ-072/074/075 (NTLM decision) — PtH defense is fundamentally about NT hash storage; if NTLM is dropped, PtH goes away; if maintained, need LSASS-equivalent protection |
| PC-039 | S4U2Self + S4U2Proxy constrained delegation | Auth Provider | high | DEFERRED | Tier-1 ORQ-072/074/075 (legacy auth decision) — S4U vs OAuth2 client-credentials replacement depends on the NTLM/legacy-auth Tier-1 decision |
| PC-040 | Windows Token vs Linux PAM stack | Auth Provider | high | DEFERRED | Tier-1 ORQ-169/170/175/176 (Client SDK architecture) and ORQ-202/203 (Linux tier strategy) — token construction abstraction depends on both |
| PC-041 | Time sync (W32Time + MS-SNTP) | Auth Provider | high | ADR-ELIGIBLE | Use standard NTP (RFC 5905) via chrony as the time sync protocol on all DCs and clients; drop MS-SNTP; alert on clock skew >2 minutes (Kerberos 5-minute window safety margin) |
| PC-042 | Kerberos audit events (4768/4769/4771) | Auth Provider | high | ADR-ELIGIBLE | Emit structured audit events for all Kerberos operations (TGT-issued, TGS-issued, auth-failed) in OpenTelemetry log format with the equivalent fields of Windows events 4768/4769/4771; defer MITRE ATT&CK technique ID mapping to Tier 3 |
| PC-043 | GPC + GPT split fragile | Policy Engine | high | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) and GitOps cross-cutting theme — GPC/GPT format depends on replication protocol (per-GPO CRDT requires CRDT replication); Tier-2 ORQ-082/083 is gated by Tier-1 |
| PC-044 | LSDOU last-writer-wins | Policy Engine | medium | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) — LWW vs CRDT conflict resolution depends on replication protocol |
| PC-045 | GPO Preferences XML no macOS/Linux equivalent | Policy Engine | blocker | DEFERRED | Tier-1 ORQ-030/031 (schema model) — cross-platform policy data format depends on schema model (typed schema enables JSON Schema; LDAP dynamic constrains the format) |
| PC-046 | ADMX schema Windows-specific | Policy Engine | high | DEFERRED | Tier-1 ORQ-030/031 (schema model) — unified policy DSL depends on schema choice |
| PC-047 | CSE model Windows-only | Policy Engine | high | PARTIAL | Confident: support per-platform policy executors (Windows CSE-equivalent, macOS MDM, Linux SSSD-conf-equivalent). Deferred (Tier-3 ORQ-090/091): the unified executor framework design (generic plugin framework vs per-platform native) |
| PC-048 | GPO no rollback/transactional semantics | Policy Engine | medium | ADR-ELIGIBLE | Implement transactional policy application with per-CSE snapshot before apply; support explicit rollback (Git-style revert) to previous policy version |
| PC-049 | WMI filters client-side + corruption | Policy Engine | medium | ADR-ELIGIBLE | Use declarative host facts (OS, role, site, group membership) as the cross-platform policy targeting mechanism; provide WMI filter adapter for Windows AD-interop only |
| PC-050 | Slow-link detection (ICMP to PDC) | Policy Engine | low | ADR-ELIGIBLE | Use HTTP HEAD probe to a well-known policy endpoint as the slow-link detection mechanism; drop ICMP ping; support per-CSE slow-link policy |
| PC-051 | GPO background refresh too slow | Policy Engine | medium | ADR-ELIGIBLE | Support push-based policy updates via WebSocket for urgent security policies; retain background refresh (90min + jitter) for non-urgent policies; per-policy TTL |
| PC-052 | Registry.pol PReg format | Policy Engine | medium | ADR-ELIGIBLE | Use JSON as the canonical policy format; provide a PReg adapter for Windows AD-interop; document PReg format as legacy |
| PC-053 | SSSD GPO access control limited | Policy Engine | high | DEFERRED | Tier-1 ORQ-202/203 (Linux tier strategy) — HBAC vs URA access-control model depends on Linux tier choice |
| PC-054 | GPO security filtering on Authenticated Users | Policy Engine | medium | ADR-ELIGIBLE | Support role-based policy binding (computer-role + user-role + group) as the primary filter mechanism; auto-include computer accounts for computer-policy; deprecate Authenticated Users as the default filter |
| PC-055 | SYSVOL replication via DFS-R Windows-only | Policy Engine | blocker | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) and GitOps theme — SYSVOL replication mechanism depends on replication protocol |
| PC-056 | No native policy versioning/history | Policy Engine | medium | ADR-ELIGIBLE | Store policy history in a Git repository with PR-based review; auto-tag each applied version; provide CLI/UI revert to any tagged version |
| PC-057 | AD CS Windows-only (no MS-WCCE server) | Cert Service | blocker | DEFERRED | Tier-1 ORQ-110/111 (PKI enrollment protocol choice); covered by Spike 5 |
| PC-058 | Certificate templates (msPKI-*) complex | Cert Service | high | DEFERRED | Tier-1 ORQ-110/111 (PKI enrollment protocol) — template format (msPKI-* vs JSON schema vs Dogtag profile) depends on enrollment protocol |
| PC-059 | Autoenrollment Windows-only | Cert Service | high | DEFERRED | Tier-1 ORQ-110/111 (PKI enrollment protocol) — autoenrollment mechanism (autoenroll.dll CSE vs ACME client vs certmonger) depends on enrollment protocol |
| PC-060 | Key archival (KRA) risk | Cert Service | high | ADR-ELIGIBLE | Bind KRA private keys to HSM (keys never leave HSM in plaintext); use Shamir secret sharing (M-of-N) for multi-party key recovery; document quorum policy |
| PC-061 | OCSP responder scaling | Cert Service | high | ADR-ELIGIBLE | Implement OCSP responder per RFC 6960 with nonce extension support; deploy as a stateless horizontally-scalable cluster; pre-sign frequent responses for cacheability; defer CRLite adoption to Tier 3 |
| PC-062 | CA database corruption recovery | Cert Service | medium | PARTIAL | Confident: use a transactional database (not ESE) for CA storage with point-in-time recovery (PITR); document "restore from backup" as the only corruption recovery procedure; explicitly reject any "repair" tool (eseutil /p equivalent). Deferred (Tier-3 ORQ-120/121): specific DB engine choice (PostgreSQL vs SQLite-WAL vs FoundationDB) |
| PC-063 | Certificate revocation during CA outage | Cert Service | high | ADR-ELIGIBLE | Publish CRLs to multiple HTTP distribution points (multi-CDP) for resilience; deploy OCSP responders as a highly-available cluster; clients must support CRL fallback when OCSP is unreachable |
| PC-064 | NDES (SCEP) fragile + IIS dependency | Cert Service | medium | DEFERRED | Tier-1 ORQ-110/111 (PKI enrollment protocol) — NDES/SCEP/EST support depends on enrollment protocol choice |
| PC-065 | Cross-CA trust (cross-cert) rarely used | Cert Service | low | ADR-ELIGIBLE | Adopt the trust-manager model (per-OS CA bundles, refreshable) as the primary trust mechanism; support cross-cert (CrossCertificatePair) only for explicit AD-interop scenarios |
| PC-066 | Two-tier vs three-tier CA topology | Cert Service | medium | ADR-ELIGIBLE | Default to two-tier CA topology (offline root + online issuing); bind root CA private key to HSM (offline); defer cloud-based root CA option to Tier 2/3 |
| PC-067 | NTAuthCertificates canonical CA list | Cert Service | high | DEFERRED | Tier-1 ORQ-110/111 (PKI enrollment protocol) — NTAuthCertificates model depends on enrollment protocol (ACME doesn't use NTAuthCertificates) |
| PC-068 | AD FS heavy (WID/SQL + WAP) | Federation Gateway | high | DEFERRED | Tier-1 ORQ-132/133/134 (federation layer choice); covered by Spike 6 |
| PC-069 | ADFS claims rule language (CRL) proprietary | Federation Gateway | high | DEFERRED | Tier-1 ORQ-132/133/134 (federation layer) — claims-policy language (Rego vs Cedar vs plugins) depends on IdP choice |
| PC-070 | Token-signing cert rollover | Federation Gateway | medium | ADR-ELIGIBLE | Publish JWKS endpoint per RFC 8414 for automated RP metadata refresh; auto-notify registered RPs via webhook on cert rollover; maintain a 15-day overlap window during rollover |
| PC-071 | WS-Federation/WS-Trust legacy | Federation Gateway | medium | ADR-ELIGIBLE | Adopt OIDC as the primary federation protocol; provide a WS-Trust-to-OIDC bridge for legacy RPs; document WS-Federation and WS-Trust as deprecated |
| PC-072 | SAML replay detection + clock skew | Federation Gateway | low | ADR-ELIGIBLE | Enforce SAML replay detection with a 60-minute window (configurable per-RP); default clock skew tolerance 5 minutes (configurable per-RP); document auto-NTP-sync as the prerequisite |
| PC-073 | AD FS WAP Windows-only | Federation Gateway | medium | DEFERRED | Tier-1 ORQ-132/133/134 (federation layer) — WAP replacement (oauth2-proxy vs Envoy+ext-authz) depends on IdP choice |
| PC-074 | ADFS farm topology fragile | Federation Gateway | medium | DEFERRED | Tier-1 ORQ-132/133/134 (federation layer) — farm topology depends on IdP (Keycloak Infinispan vs custom Raft) |
| PC-075 | ADFS OAuth2/OIDC quirks (resource=, App Groups) | Federation Gateway | medium | ADR-ELIGIBLE | Implement strict OIDC (RFC 6749/7519) by default; provide opt-in resource= parameter compat mode for AD FS migration scenarios; document Application Groups translation |
| PC-076 | External OIDC IdP federation | Federation Gateway | medium | DEFERRED | Tier-1 ORQ-132/133/134 (federation layer) — identity brokering depends on IdP choice (Keycloak has built-in brokering) |
| PC-077 | AD RMS no open-source server | Federation Gateway | low | ADR-ELIGIBLE | Document AD RMS as out-of-scope for the framework; recommend Azure Information Protection (AIP) or an open-source RMS-equivalent as the migration path; do not implement an RMS server |
| PC-078 | SMB 3.1.1 with pre-auth integrity | File Gateway | blocker | DEFERRED | Tier-1 ORQ-154/155 (SMB server choice) |
| PC-079 | SMB1 must be dropped | File Gateway | blocker | ADR-ELIGIBLE | Drop SMB1 support entirely; no modern reason to maintain it; migration is automatic on modern Windows |
| PC-080 | DFS-N + DFS-R Windows-only | File Gateway | high | PARTIAL | Confident: implement DFS-N-equivalent via DNS SRV records for share location. Deferred (Tier-1 ORQ-001/002): DFS-R replacement strategy (Git sync vs storage-engine-native replication) depends on replication protocol choice |
| PC-081 | Continuously Available (CA) shares | File Gateway | high | DEFERRED | Tier-1 ORQ-154/155 (SMB server choice) — CA shares require cluster + persistent handles which depend on server choice (CTDB for Samba vs custom for fresh) |
| PC-082 | Access-Based Enumeration (ABE) | File Gateway | medium | ADR-ELIGIBLE | Support Access-Based Enumeration (ABE) on all shares; pre-compute an ABE index per share for performance; document the CPU cost tradeoff and provide a per-share ABE on/off toggle |
| PC-083 | PrintNightmare (MS-RPRN driver install) | File Gateway | blocker | ADR-ELIGIBLE | Drop MS-RPRN (the PrintNightmare root cause) from the framework; adopt IPP Everywhere (driverless printing) for all clients; document legacy print server support as out-of-scope |
| PC-084 | Offline Files (CSC) Windows-only | File Gateway | medium | ADR-ELIGIBLE | Document Offline Files (CSC) as out-of-scope; recommend modern sync clients (Nextcloud, OneDrive, iCloud Drive) for offline file access; do not implement a CSC-compatible cache |
| PC-085 | No universal AD client SDK | Client SDK | blocker | DEFERRED | Tier-1 ORQ-169/170/175/176 (Client SDK architecture); covered by Spike 7 |
| PC-086 | macOS PSSO Extension Apple-only | Client SDK | high | DEFERRED | Tier-1 ORQ-169/170/175/176 (Client SDK architecture) — PSSO Extension adapter depends on whether framework provides a unified SDK |
| PC-087 | macOS Jamf Connect + ROPG fragile | Client SDK | medium | ADR-ELIGIBLE | Document PSSO Extension (macOS 13+) as the modern macOS SSO path; provide a migration tool from Jamf Connect to PSSO; document Jamf Connect as deprecated |
| PC-088 | SSSD on Linux GPO gaps | Client SDK | high | DEFERRED | Tier-1 ORQ-202/203 (Linux tier strategy) — SSSD vs FreeIPA vs native client depends on Linux tier choice |
| PC-089 | ID mapping (SID ↔ POSIX UID/GID) | Client SDK | blocker | DEFERRED | Tier-1 ORQ-026/027 (identity model) — SID/UID mapping only applies if SIDs are kept; if UUIDs replace SIDs, POSIX UID mapping could be eliminated |
| PC-090 | Heimdal vs MIT Kerberos incompatibilities | Client SDK | medium | ADR-ELIGIBLE | Standardize on MIT krb5 as the framework's Kerberos client on Linux and macOS; document the Apple Heimdal fork as macOS PSSO Extension-specific; defer upstreaming the Heimdal fork to Tier 3 |
| PC-091 | Domain join fragmented | Client SDK | medium | DEFERRED | Tier-1 ORQ-169/170/175/176 (Client SDK architecture) — unified domain-join API depends on SDK architecture |
| PC-092 | PAM stack varies by distro | Client SDK | medium | ADR-ELIGIBLE | Adopt authselect as the standard PAM profile mechanism on Linux; provide a framework-supplied PAM module and authselect profile generator; document per-distro PAM quirks as legacy |
| PC-093 | Kerberos ticket cache type varies | Client SDK | medium | ADR-ELIGIBLE | Adopt KCM as the standard Kerberos ticket cache on Linux; use the Apple API: cache type on macOS; document FILE: and KEYRING: as legacy; provide a unified cache abstraction in the client SDK |
| PC-094 | macOS no native NTLM | Cross-Platform Parity | high | DEFERRED | Tier-1 ORQ-072/074/075 (NTLM decision) — NTLM-on-macOS strategy depends on NTLM decision |
| PC-095 | No unified policy authoring | Cross-Platform Parity | blocker | DEFERRED | Tier-1 ORQ-030/031 (schema model) and ORQ-169/170/175/176 (Client SDK) — unified authoring format depends on both |
| PC-096 | macOS DDM not full-coverage | Cross-Platform Parity | low | ADR-ELIGIBLE | Adopt DDM (Declarative Device Management) as the primary macOS policy authoring format where supported; auto-fallback to Configuration Profile for policies not yet covered by DDM; document the DDM coverage matrix |
| PC-097 | macOS FileVault recovery key escrow | Cross-Platform Parity | medium | ADR-ELIGIBLE | Support two disk-encryption key-escrow mechanisms: (1) per-computer recovery key stored in the framework directory with ACL-gated read access (for AD-interop); (2) NBDE (Clevis/Tang) for cloud-native deployments; deployments choose one or both |
| PC-098 | LAPS no macOS/Linux equivalent | Cross-Platform Parity | medium | ADR-ELIGIBLE | Support per-host local-admin password rotation with passwords stored in the framework directory (per-computer object) with ACL-gated read access; adopt the Windows LAPS (ms-Mcs-AdmPwd) schema for AD-interop; auto-rotate on a 30-day interval |
| PC-099 | SSSD/Winbind/PBIS migration painful | Cross-Platform Parity | medium | DEFERRED | Tier-1 ORQ-202/203 (Linux tier strategy) — stack migration path depends on Linux tier choice |
| PC-100 | macOS OpenDirectory AD plug-in gaps | Cross-Platform Parity | medium | DEFERRED | Tier-1 ORQ-169/170/175/176 (Client SDK architecture) — first-party macOS SDK to fill gaps depends on SDK choice |
| PC-101 | FreeIPA separate Linux identity platform | Cross-Platform Parity | medium | DEFERRED | Tier-1 ORQ-202/203 (Linux tier strategy) — FreeIPA decision is the Tier-1 question |
| PC-102 | RODC no Linux/macOS equivalent | Cross-Platform Parity | medium | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) and ORQ-026/027 (identity model) — RODC requires filtering secrets per-secret which depends on replication + identity model |
| PC-103 | OpenLDAP + MIT Kerberos roll-your-own | Cross-Platform Parity | low | DEFERRED | Tier-1 ORQ-202/203 (Linux tier strategy) — whether to document as out-of-scope or provide migration tooling depends on Linux tier choice |
| PC-104 | Centrify/PBIS/AdmitMac/DAVE legacy | Cross-Platform Parity | low | ADR-ELIGIBLE | Document migration paths from Centrify/PBIS/AdmitMac/DAVE to the framework's first-party clients; provide import tooling for dzdo rules → sudoers; document PBIS as deprecated (deprecated by vendor 2023) |
| PC-105 | Heimdal on macOS fork tracks ~2014 | Cross-Platform Parity | medium | ADR-ELIGIBLE | Document PSSO Extension as the only modern macOS Kerberos path; defer the Apple Heimdal fork upstreaming to Tier 3 |
| PC-106 | No native Prometheus exporter / OTel | Operations | high | ADR-ELIGIBLE | Provide a Prometheus exporter and OpenTelemetry instrumentation for all framework components; per-DC metrics with optional per-realm aggregation layer; adopt OTel semantic conventions for directory/Kerberos/PKI operations |
| PC-107 | Schema upgrades irreversible | Operations | high | DEFERRED | Tier-1 ORQ-030/031 (schema model) — schema-as-code vs typed-schema-with-migrations depends on schema model |
| PC-108 | Multi-region AD replication latency | Operations | high | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) — multi-region model (PDC urgent replication vs active-active CRDT) depends on replication protocol |
| PC-109 | AD no containerization | Operations | high | ADR-ELIGIBLE | Deploy DCs as container images; provide a Kubernetes operator for DC lifecycle (promote/demote/backup/snapshot); document container-native operations as the primary deployment model |
| PC-110 | Disaster recovery manual | Operations | high | ADR-ELIGIBLE | Provide per-DC backup with point-in-time recovery (PITR); operator-driven DR runbooks for automated metadata cleanup and DC recovery; document IFM-equivalent for offline DC promotion |
| PC-111 | AD audit logs Windows-only | Operations | high | ADR-ELIGIBLE | Emit structured audit logs in OpenTelemetry log format for all framework operations; map security-relevant events to MITRE ATT&CK technique IDs; provide a Windows Event Log forwarder for AD-interop |
| PC-112 | AD no REST/gRPC API | Operations | high | PARTIAL | Confident: provide a REST API for CRUD operations on directory objects and gRPC for streaming (replication status, change notifications). Deferred (Tier-2 ORQ-226): GraphQL for flexible queries |
| PC-113 | Functional level upgrades one-way | Operations | medium | DEFERRED | Tier-1 ORQ-030/031 (schema model) — functional levels vs feature flags depends on schema model |
| PC-114 | Trust password rotation desync | Operations | medium | ADR-ELIGIBLE | Auto-rotate trust passwords every 30 days; auto-reset on desync detection (alert + automatic reconciliation); per-trust rotation policy configurable |
| PC-115 | dcdiag/repadmin/ntdsutil Windows-only | Operations | medium | PARTIAL | Confident: provide a unified cross-platform CLI that subsumes dcdiag/repadmin/ntdsutil functionality. Deferred (Tier-3 ORQ-231/232 and Tier-1 ORQ-169/170/175/176): implementation language (Go vs Rust) and base (samba-tool vs fresh) |
| PC-116 | Kerberoasting | Security | blocker | ADR-ELIGIBLE | Auto-detect Kerberoast attempts via Kerberos events with RC4 etype (etype 0x17) and alert; force-migrate service accounts to AES on next password rotation; document RC4 TGS as deprecated |
| PC-117 | DCSync | Security | blocker | DEFERRED | Tier-1 ORQ-001/002 (replication protocol) — DCSync is DRSUAPI-specific (EXOP_REPL_SECRETS); if clean-slate replication is chosen, DCSync doesn't apply |
| PC-118 | Golden ticket (krbtgt hash) | Security | blocker | ADR-ELIGIBLE | Bind the krbtgt account's key material to an HSM (key never leaves HSM in plaintext); auto-rotate on a 30-day interval with a 2-key overlap window during rollover (same decision as PC-030) |
| PC-119 | Silver ticket (service-account hash) | Security | high | DEFERRED | Tier-1 ORQ-042/043/044 (KDC implementation) — PAC_BUFFER_TICKET_CHECKSUM is MS-KILE-specific; mechanism depends on KDC implementation |
| PC-120 | SIDHistory abuse | Security | high | DEFERRED | Tier-1 ORQ-026/027 (identity model) — sIDHistory only makes sense with SIDs; drop vs per-trust filtering depends on identity choice |
| PC-121 | Selective authentication rarely used | Security | medium | DEFERRED | Tier-1 ORQ-202/203 (Linux tier strategy) — selective auth vs HBAC depends on Linux tier choice |
| PC-122 | AdminSDHolder + SDPROP overrides ACLs | Security | medium | ADR-ELIGIBLE | Replace AdminSDHolder + SDPROP with declarative RBAC policy; per-protected-group templates (Tier-0, Tier-1, Tier-2); explicit ACL propagation policy with audit logging |
| PC-123 | Supply-chain risk (WSUS trust) | Security | medium | ADR-ELIGIBLE | Sign all framework binaries with Sigstore (cosign); adopt in-toto attestations for build provenance; verify signatures at install time; document WSUS as out-of-scope |
| PC-124 | sidHistory migration | Migration | high | DEFERRED | Tier-1 ORQ-026/027 (identity model) — sIDHistory migration alternative depends on SID/UUID choice |
| PC-125 | GPO translation manual | Migration | high | DEFERRED | Tier-1 ORQ-030/031 (schema model) — GPO-to-native translation automation depends on schema model |
| PC-126 | Client switchover parallel-run | Migration | high | DEFERRED | Tier-1 ORQ-026/027 (identity model) and ORQ-001/002 (replication protocol) — parallel-run strategy depends on both |
| PC-127 | Password hash migration | Migration | high | DEFERRED | Tier-1 ORQ-026/027 (identity model) — password hash migration depends on identity choice |
| PC-128 | DNS namespace sharing | Migration | medium | ADR-ELIGIBLE | Use a subdomain-per-directory DNS strategy during migration (e.g., ad.corp.example.com for legacy AD, new.corp.example.com for the framework); per-record migration via DNS delegation; document the rollback procedure |
| PC-129 | Kerberos cross-realm capaths + trust | Migration | medium | ADR-ELIGIBLE | Auto-generate Kerberos capaths from the trust graph; per-realm KDC discovery via DNS SRV records; document the cross-realm trust object setup for AD migration |
| PC-130 | SYSVOL migration | Migration | medium | DEFERRED | Tier-1 ORQ-154/155 (SMB server choice) — SYSVOL migration via SMB share compatibility depends on SMB server choice |

## Per-capability deferred-problem detail

For each capability, the list of DEFERRED problems with the specific Tier-1 ORQ that gates each.

### Core Directory (22 problems: 8 ADR, 2 PARTIAL, 12 DEFERRED)

Deferred problems:
- PC-001 — gated by Tier-1 ORQ-001/002 (replication protocol choice); covered by Spike 1
- PC-002 — gated by Tier-1 ORQ-003/004 (UTD vector vs CRDT vs Raft); covered by Spike 1
- PC-005 — gated by Tier-1 ORQ-001/002 (replication protocol)
- PC-007 — gated by Tier-1 ORQ-011/012/013/014 (storage engine choice); covered by Spike 2
- PC-009 — gated by Tier-1 ORQ-001/002 (replication protocol)
- PC-010 — gated by Tier-1 ORQ-026/027 (identity model) + ORQ-030/031 (schema model)
- PC-014 — gated by Tier-1 ORQ-001/002 (replication protocol); Tier-2 ORQ-024/025 cascades from Tier-1
- PC-015 — gated by Tier-1 ORQ-026/027 (identity model)
- PC-017 — gated by Tier-1 ORQ-030/031 (schema model) — this IS the Tier-1 question
- PC-019 — gated by Tier-1 ORQ-001/002 (replication protocol)
- PC-021 — gated by Tier-1 ORQ-030/031 (schema model)
- PC-022 — gated by cross-cutting tenancy architectural question (cascades from ORQ-026/027)

### KDC (13 problems: 8 ADR, 2 PARTIAL, 3 DEFERRED)

Deferred problems:
- PC-023 — gated by Tier-1 ORQ-042/043/044 (KDC implementation choice); covered by Spike 3
- PC-025 — gated by Tier-1 ORQ-042/043/044 (KDC implementation)
- PC-027 — gated by Tier-1 ORQ-110/111 (PKI enrollment protocol)

### Auth Provider (7 problems: 3 ADR, 0 PARTIAL, 4 DEFERRED)

Deferred problems:
- PC-036 — gated by Tier-1 ORQ-072/074/075 (NTLM decision); covered by Spike 4
- PC-038 — gated by Tier-1 ORQ-072/074/075 (NTLM decision)
- PC-039 — gated by Tier-1 ORQ-072/074/075 (NTLM/legacy-auth decision)
- PC-040 — gated by Tier-1 ORQ-169/170/175/176 (Client SDK) + ORQ-202/203 (Linux tier)

### Policy Engine (14 problems: 7 ADR, 1 PARTIAL, 6 DEFERRED)

Deferred problems:
- PC-043 — gated by Tier-1 ORQ-001/002 (replication protocol) + GitOps theme
- PC-044 — gated by Tier-1 ORQ-001/002 (replication protocol)
- PC-045 — gated by Tier-1 ORQ-030/031 (schema model)
- PC-046 — gated by Tier-1 ORQ-030/031 (schema model)
- PC-053 — gated by Tier-1 ORQ-202/203 (Linux tier strategy)
- PC-055 — gated by Tier-1 ORQ-001/002 (replication protocol) + GitOps theme

### Cert Service (11 problems: 5 ADR, 1 PARTIAL, 5 DEFERRED)

Deferred problems:
- PC-057 — gated by Tier-1 ORQ-110/111 (PKI enrollment protocol); covered by Spike 5
- PC-058 — gated by Tier-1 ORQ-110/111 (PKI enrollment protocol)
- PC-059 — gated by Tier-1 ORQ-110/111 (PKI enrollment protocol)
- PC-064 — gated by Tier-1 ORQ-110/111 (PKI enrollment protocol)
- PC-067 — gated by Tier-1 ORQ-110/111 (PKI enrollment protocol)

### Federation Gateway (10 problems: 5 ADR, 0 PARTIAL, 5 DEFERRED)

Deferred problems:
- PC-068 — gated by Tier-1 ORQ-132/133/134 (federation layer); covered by Spike 6
- PC-069 — gated by Tier-1 ORQ-132/133/134 (federation layer)
- PC-073 — gated by Tier-1 ORQ-132/133/134 (federation layer)
- PC-074 — gated by Tier-1 ORQ-132/133/134 (federation layer)
- PC-076 — gated by Tier-1 ORQ-132/133/134 (federation layer)

### File Gateway (7 problems: 4 ADR, 1 PARTIAL, 2 DEFERRED)

Deferred problems:
- PC-078 — gated by Tier-1 ORQ-154/155 (SMB server choice)
- PC-081 — gated by Tier-1 ORQ-154/155 (SMB server choice)

### Client SDK (9 problems: 4 ADR, 0 PARTIAL, 5 DEFERRED)

Deferred problems:
- PC-085 — gated by Tier-1 ORQ-169/170/175/176 (Client SDK architecture); covered by Spike 7
- PC-086 — gated by Tier-1 ORQ-169/170/175/176 (Client SDK architecture)
- PC-088 — gated by Tier-1 ORQ-202/203 (Linux tier strategy)
- PC-089 — gated by Tier-1 ORQ-026/027 (identity model)
- PC-091 — gated by Tier-1 ORQ-169/170/175/176 (Client SDK architecture)

### Cross-Platform Parity (12 problems: 5 ADR, 0 PARTIAL, 7 DEFERRED)

Deferred problems:
- PC-094 — gated by Tier-1 ORQ-072/074/075 (NTLM decision)
- PC-095 — gated by Tier-1 ORQ-030/031 (schema model) + ORQ-169/170/175/176 (Client SDK)
- PC-099 — gated by Tier-1 ORQ-202/203 (Linux tier strategy)
- PC-100 — gated by Tier-1 ORQ-169/170/175/176 (Client SDK architecture)
- PC-101 — gated by Tier-1 ORQ-202/203 (Linux tier strategy) — this IS the Tier-1 question
- PC-102 — gated by Tier-1 ORQ-001/002 (replication protocol) + ORQ-026/027 (identity model)
- PC-103 — gated by Tier-1 ORQ-202/203 (Linux tier strategy)

### Operations (10 problems: 5 ADR, 2 PARTIAL, 3 DEFERRED)

Deferred problems:
- PC-107 — gated by Tier-1 ORQ-030/031 (schema model)
- PC-108 — gated by Tier-1 ORQ-001/002 (replication protocol)
- PC-113 — gated by Tier-1 ORQ-030/031 (schema model)

### Security (8 problems: 4 ADR, 0 PARTIAL, 4 DEFERRED)

Deferred problems:
- PC-117 — gated by Tier-1 ORQ-001/002 (replication protocol)
- PC-119 — gated by Tier-1 ORQ-042/043/044 (KDC implementation)
- PC-120 — gated by Tier-1 ORQ-026/027 (identity model)
- PC-121 — gated by Tier-1 ORQ-202/203 (Linux tier strategy)

### Migration (7 problems: 2 ADR, 0 PARTIAL, 5 DEFERRED)

Deferred problems:
- PC-124 — gated by Tier-1 ORQ-026/027 (identity model)
- PC-125 — gated by Tier-1 ORQ-030/031 (schema model)
- PC-126 — gated by Tier-1 ORQ-026/027 (identity model) + ORQ-001/002 (replication protocol)
- PC-127 — gated by Tier-1 ORQ-026/027 (identity model)
- PC-130 — gated by Tier-1 ORQ-154/155 (SMB server choice)

## Per-capability partial-problem detail

### Core Directory

- PC-018 (Constructed attributes) — Confident: support constructed attributes via DSA-side computation, marked operational. Deferred (Tier-2 ORQ-032): caching strategy (event-driven vs read-time).
- PC-020 (NTDS.DIT backup/restore) — Confident: use storage-engine-native backup; eliminate VSS. Deferred (Tier-1 ORQ-011/012/013/014): specific backup API.

### KDC

- PC-029 (AES-SHA384 etype 0x13) — Confident: support etype 0x13; prefer over 0x12 when both endpoints support. Deferred (Tier-3 ORQ-055/056): default-etype-change timeline.
- PC-031 (SPN uniqueness) — Confident: enforce SPN uniqueness at KDC/DC pre-commit. Deferred (Tier-2 ORQ-059/060): uniqueness scope (per-forest vs per-domain).

### Policy Engine

- PC-047 (CSE model) — Confident: support per-platform policy executors (Windows CSE, macOS MDM, Linux SSSD-conf). Deferred (Tier-3 ORQ-090/091): unified executor framework design.

### Cert Service

- PC-062 (CA database corruption) — Confident: use transactional DB with PITR; reject repair tools. Deferred (Tier-3 ORQ-120/121): specific DB engine choice.

### File Gateway

- PC-080 (DFS-N + DFS-R) — Confident: implement DFS-N-equivalent via DNS SRV. Deferred (Tier-1 ORQ-001/002): DFS-R replacement strategy.

### Operations

- PC-112 (REST/gRPC API) — Confident: provide REST API for CRUD + gRPC for streaming. Deferred (Tier-2 ORQ-226): GraphQL.
- PC-115 (Unified CLI) — Confident: provide a unified cross-platform CLI. Deferred (Tier-3 ORQ-231/232 + Tier-1 ORQ-169/170/175/176): implementation language and base.

## Recommended ADR numbering scheme

ADRs are numbered ADR-001 through ADR-069 in PC-order (per-capability, per-problem in ascending PC-NNN order). The mapping table below shows PC-NNN → ADR-NNN for all 69 ADRs to be written (60 ADR-ELIGIBLE + 9 PARTIAL).

| ADR | PC | Title | Capability | Type |
|-----|----|-------|-----------|------|
| ADR-001 | PC-003 | Linked Value Replication (per-value metadata) | Core Directory | ADR-ELIGIBLE |
| ADR-002 | PC-004 | member/memberOf DSA-computed back-link | Core Directory | ADR-ELIGIBLE |
| ADR-003 | PC-006 | Copy-on-write schema cache with generation numbers | Core Directory | ADR-ELIGIBLE |
| ADR-004 | PC-008 | Security descriptor deduplication via content-hash indexed table | Core Directory | ADR-ELIGIBLE |
| ADR-005 | PC-011 | Honor well-known container GUIDs | Core Directory | ADR-ELIGIBLE |
| ADR-006 | PC-012 | Implement core AD-specific LDAP controls for interop | Core Directory | ADR-ELIGIBLE |
| ADR-007 | PC-013 | kpasswd primary; BER-quote unicodePwd in AD-compat mode | Core Directory | ADR-ELIGIBLE |
| ADR-008 | PC-016 | Declarative YAML topology; AD-compat adapter | Core Directory | ADR-ELIGIBLE |
| ADR-009 | PC-018 | Constructed attributes via DSA-side computation | Core Directory | PARTIAL |
| ADR-010 | PC-020 | Storage-engine-native backup; eliminate VSS | Core Directory | PARTIAL |
| ADR-011 | PC-024 | Default AES-256; disable RC4-HMAC by default | KDC | ADR-ELIGIBLE |
| ADR-012 | PC-026 | Require FAST (RFC 6806) armoring by default | KDC | ADR-ELIGIBLE |
| ADR-013 | PC-028 | RFC 4120 transited field; capaths for cross-realm | KDC | ADR-ELIGIBLE |
| ADR-014 | PC-029 | Support AES-SHA384 (etype 0x13) | KDC | PARTIAL |
| ADR-015 | PC-030 | HSM-bound krbtgt; auto-rotate 30-day with 2-key overlap | KDC | ADR-ELIGIBLE |
| ADR-016 | PC-031 | Enforce SPN uniqueness at KDC/DC pre-commit | KDC | PARTIAL |
| ADR-017 | PC-032 | Enforce UPN uniqueness strictly at write time | KDC | ADR-ELIGIBLE |
| ADR-018 | PC-033 | Horizontally-scalable stateless KDC pool; HSM-shared krbtgt | KDC | ADR-ELIGIBLE |
| ADR-019 | PC-034 | kpasswd (RFC 3244) primary; REST API wrapper | KDC | ADR-ELIGIBLE |
| ADR-020 | PC-035 | gMSA with auto-rotation; HSM-bound root key | KDC | ADR-ELIGIBLE |
| ADR-021 | PC-037 | Require LDAP signing + channel binding + EPA | Auth Provider | ADR-ELIGIBLE |
| ADR-022 | PC-041 | Standard NTP via chrony; drop MS-SNTP | Auth Provider | ADR-ELIGIBLE |
| ADR-023 | PC-042 | Structured Kerberos audit events in OTel log format | Auth Provider | ADR-ELIGIBLE |
| ADR-024 | PC-047 | Per-platform policy executors (CSE/MDM/SSSD-conf) | Policy Engine | PARTIAL |
| ADR-025 | PC-048 | Transactional policy application with rollback | Policy Engine | ADR-ELIGIBLE |
| ADR-026 | PC-049 | Declarative host facts; WMI filter adapter for interop | Policy Engine | ADR-ELIGIBLE |
| ADR-027 | PC-050 | HTTP HEAD probe for slow-link detection | Policy Engine | ADR-ELIGIBLE |
| ADR-028 | PC-051 | Push-based policy updates via WebSocket | Policy Engine | ADR-ELIGIBLE |
| ADR-029 | PC-052 | JSON canonical policy format; PReg adapter | Policy Engine | ADR-ELIGIBLE |
| ADR-030 | PC-054 | Role-based policy binding; deprecate Authenticated Users | Policy Engine | ADR-ELIGIBLE |
| ADR-031 | PC-056 | Git-backed policy history with PR review | Policy Engine | ADR-ELIGIBLE |
| ADR-032 | PC-060 | HSM-bound KRA keys; Shamir secret sharing M-of-N | Cert Service | ADR-ELIGIBLE |
| ADR-033 | PC-061 | OCSP responder per RFC 6960 with nonce; HA cluster | Cert Service | ADR-ELIGIBLE |
| ADR-034 | PC-062 | Transactional DB with PITR; reject repair tools | Cert Service | PARTIAL |
| ADR-035 | PC-063 | Multi-CDP HTTP fallback; HA OCSP cluster; CRL fallback | Cert Service | ADR-ELIGIBLE |
| ADR-036 | PC-065 | Trust-manager model; cross-cert for interop only | Cert Service | ADR-ELIGIBLE |
| ADR-037 | PC-066 | Two-tier CA with HSM-bound root | Cert Service | ADR-ELIGIBLE |
| ADR-038 | PC-070 | JWKS endpoint per RFC 8414; webhook notification; 15-day overlap | Federation Gateway | ADR-ELIGIBLE |
| ADR-039 | PC-071 | OIDC primary; WS-Trust-to-OIDC bridge | Federation Gateway | ADR-ELIGIBLE |
| ADR-040 | PC-072 | SAML replay detection 60-min; per-RP skew policy | Federation Gateway | ADR-ELIGIBLE |
| ADR-041 | PC-075 | Strict OIDC by default; resource= compat opt-in | Federation Gateway | ADR-ELIGIBLE |
| ADR-042 | PC-077 | AD RMS out of scope; recommend AIP | Federation Gateway | ADR-ELIGIBLE |
| ADR-043 | PC-079 | Drop SMB1 support | File Gateway | ADR-ELIGIBLE |
| ADR-044 | PC-080 | DFS-N-equivalent via DNS SRV | File Gateway | PARTIAL |
| ADR-045 | PC-082 | Support ABE; pre-compute per-share index | File Gateway | ADR-ELIGIBLE |
| ADR-046 | PC-083 | Drop MS-RPRN; adopt IPP Everywhere | File Gateway | ADR-ELIGIBLE |
| ADR-047 | PC-084 | Offline Files out of scope; recommend sync clients | File Gateway | ADR-ELIGIBLE |
| ADR-048 | PC-087 | PSSO Extension as modern macOS path; Jamf Connect migration | Client SDK | ADR-ELIGIBLE |
| ADR-049 | PC-090 | Standardize on MIT krb5 on Linux/macOS | Client SDK | ADR-ELIGIBLE |
| ADR-050 | PC-092 | Adopt authselect as standard PAM profile mechanism | Client SDK | ADR-ELIGIBLE |
| ADR-051 | PC-093 | KCM on Linux; API: on macOS; unified cache abstraction | Client SDK | ADR-ELIGIBLE |
| ADR-052 | PC-096 | DDM-first authoring; auto-fallback to Configuration Profile | Cross-Platform Parity | ADR-ELIGIBLE |
| ADR-053 | PC-097 | Support both per-computer key escrow and NBDE | Cross-Platform Parity | ADR-ELIGIBLE |
| ADR-054 | PC-098 | Per-host local-admin password rotation; LAPS schema | Cross-Platform Parity | ADR-ELIGIBLE |
| ADR-055 | PC-104 | Document migration paths; dzdo → sudoers import | Cross-Platform Parity | ADR-ELIGIBLE |
| ADR-056 | PC-105 | PSSO as modern macOS Kerberos path | Cross-Platform Parity | ADR-ELIGIBLE |
| ADR-057 | PC-106 | Prometheus exporter + OTel instrumentation | Operations | ADR-ELIGIBLE |
| ADR-058 | PC-109 | DCs as containers; Kubernetes operator | Operations | ADR-ELIGIBLE |
| ADR-059 | PC-110 | Per-DC backup with PITR; operator-driven DR runbooks | Operations | ADR-ELIGIBLE |
| ADR-060 | PC-111 | Structured audit logs in OTel format; MITRE ATT&CK mapping | Operations | ADR-ELIGIBLE |
| ADR-061 | PC-112 | REST API for CRUD + gRPC for streaming | Operations | PARTIAL |
| ADR-062 | PC-114 | Auto-rotate trust passwords; auto-reset on desync | Operations | ADR-ELIGIBLE |
| ADR-063 | PC-115 | Unified cross-platform CLI | Operations | PARTIAL |
| ADR-064 | PC-116 | Auto-detect Kerberoast; force-migrate to AES | Security | ADR-ELIGIBLE |
| ADR-065 | PC-118 | HSM-bound krbtgt; auto-rotate (same as PC-030) | Security | ADR-ELIGIBLE |
| ADR-066 | PC-122 | Replace AdminSDHolder with declarative RBAC | Security | ADR-ELIGIBLE |
| ADR-067 | PC-123 | Sigstore + in-toto attestations | Security | ADR-ELIGIBLE |
| ADR-068 | PC-128 | Subdomain-per-directory DNS strategy | Migration | ADR-ELIGIBLE |
| ADR-069 | PC-129 | Auto-generate capaths; DNS SRV KDC discovery | Migration | ADR-ELIGIBLE |

## Notes for ADR writers

### Seed decisions

The "Reason / seed decision" column in the triage table above contains the one-sentence seed decision for each ADR-ELIGIBLE and PARTIAL problem. ADR writers should expand this seed into a full ADR (Context, Decision, Consequences, Alternatives, Open Questions per the ADR template).

### PARTIAL ADRs

For PARTIAL problems (9 ADRs), the ADR writer must:
1. Write the full ADR for the confident sub-decision.
2. Add an explicit "Open Questions" section that names the deferred sub-decision and cites the specific ORQ that gates it.
3. Mark the ADR status as "Accepted (partial)" or "Proposed" depending on whether the deferred part would change the implementation.

### Cross-capability ADR consistency

Several ADRs share or cross-reference decisions:
- ADR-015 (PC-030 krbtgt HSM + auto-rotation) and ADR-065 (PC-118 golden ticket mitigation) encode the same decision from different problem framings; ADR writers should cross-reference.
- ADR-019 (PC-034 kpasswd primary) and ADR-007 (PC-013 BER-quote in AD-compat mode) jointly define the framework's password-change story; cross-reference.
- ADR-022 (PC-041 NTP via chrony) underpins the time-sync prerequisite for ADR-040 (PC-072 SAML clock skew) and ADR-013 (PC-028 Kerberos transited field); cross-reference.
- ADR-057 (PC-106 OTel instrumentation), ADR-060 (PC-111 audit logs in OTel format), and ADR-023 (PC-042 Kerberos audit events in OTel) share the OTel semantic conventions; ADR writers should align on the convention.

### Research spike dependencies

The 7 research spikes (per `draft/04-open-research-questions.md` §6) gate 27 of the 61 DEFERRED problems. After each spike completes, the corresponding DEFERRED problems should be re-triaged:
- Spike 1 (DRSUAPI replication) — unblocks PC-001, PC-002, PC-005, PC-009, PC-014, PC-019, PC-043, PC-044, PC-055, PC-108, PC-117, PC-126, PC-130 (DFS-R part)
- Spike 2 (Storage engine) — unblocks PC-007, PC-020 (deferred part)
- Spike 3 (MIT krb5 + PAC plugin) — unblocks PC-023, PC-025, PC-119
- Spike 4 (NTLM compat audit) — unblocks PC-036, PC-038, PC-039, PC-094
- Spike 5 (ACME + Windows autoenroll adapter) — unblocks PC-057, PC-058, PC-059, PC-064, PC-067, PC-027
- Spike 6 (Keycloak as AD FS replacement) — unblocks PC-068, PC-069, PC-073, PC-074, PC-076
- Spike 7 (Rust core SDK) — unblocks PC-085, PC-086, PC-091, PC-100, PC-115 (deferred part)

The remaining DEFERRED problems are gated by Tier-1 architectural questions that are resolved in a 2-day workshop (per `draft/04-open-research-questions.md` §6 closing paragraph): ORQ-026/027 (SID vs UUID) and ORQ-030/031 (schema model). These gate PC-010, PC-015, PC-017, PC-021, PC-022, PC-045, PC-046, PC-053, PC-088, PC-089, PC-095, PC-099, PC-101, PC-102, PC-103, PC-107, PC-113, PC-120, PC-121, PC-124, PC-125, PC-127.

## References

- Problem catalog: [`../catalog/README.md`](../catalog/README.md) and per-capability files `01-core-directory.md` through `12-migration-and-coexistence.md`
- Open research questions (consolidated): [`../catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md)
- Open research questions (synthesis): [`../draft/04-open-research-questions.md`](../draft/04-open-research-questions.md)
- Cross-platform parity matrix: [`../catalog/14-cross-platform-parity-matrix.md`](../catalog/14-cross-platform-parity-matrix.md)
