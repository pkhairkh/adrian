---
title: "ADR-082: MS-KILE-Conformant PAC Generation in Fresh Rust KDC"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: KDC
problem: PC-023
severity: blocker
unblocked_by: Workshop Decision 5 (ORQ-042/043/044)
tags: [adr, kdc, kerberos, ms-kile, ms-pac, pac, fresh-implementation, rust, s4u, silver-ticket]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../workshop/decision-05-kdc-implementation.md
  - ./ADR-011-rc4-deprecation-aes-default.md
  - ./ADR-015-krbtgt-hsm-rotation.md
  - ./ADR-018-kdc-horizontal-scaling.md
  - ./ADR-023-kerberos-audit-events.md
last_updated: 2026-08-14
---

# ADR-082: MS-KILE-Conformant PAC Generation in Fresh Rust KDC

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 5](../workshop/decision-05-kdc-implementation.md) which resolved Tier-1 ORQ-042 (Samba Heimdal fork GPLv3), ORQ-043 (MIT krb5 + custom PAC plugin), and ORQ-044 (fresh implementation) in favor of a fresh Rust KDC in `crates/adrian-kdc`. This ADR translates the workshop decision into a concrete PAC-generation specification: which MS-KILE buffer types the framework emits, the krbtgt-signing rules, the byte-identity invariant against Windows Server 2022+, and the interop-test contract that gates GA.

## Context

AD's KDC (`lsass.exe!kdcsvc.dll`) extends RFC 4120 with MS-KILE: a PAC (Privilege Attribute Certificate) carried inside the `authorization-data` field of every TGT and service ticket. Services (IIS, SQL Server, SMB, COM+, custom Kerberos apps) read group memberships, user RID, `UserAccountControl`, and logon-domain identity directly from the PAC rather than issuing a directory lookup per AP-REQ. Without an MS-KILE-conformant PAC, the framework's TGTs are functionally useless to AD-aware services: they parse but the resulting access token is empty.

The full PAC buffer set per [PC-023](../catalog/02-kdc.md) and [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md):

- `PAC_LOGON_INFO` (0x01) — NDR-encoded `KERB_VALIDATION_INFO` (user SID, primary group, `GroupIds[]`, `ExtraSids[]`, `UserAccountControl`, `LogonServer`, `LogonDomainId`, password timestamps).
- `PAC_CREDENTIAL_TYPE` (0x02) — encrypted credential data for S4U2Proxy delegation; encrypted to the user's long-term key.
- `PAC_SERVER_CHECKSUM` (0x06) — HMAC of the PAC body using the service's long-term key (etype 0xFFFFFF76 for AES, 0xFFFFFF66 for RC4 audit).
- `PAC_PRIVSVR_CHECKSUM` (0x07) — HMAC of `PAC_SERVER_CHECKSUM.SignatureValue` using the krbtgt key; the KDC signature that services re-validate via `NetrLogonSamLogonEx` (PC-025, ADR-083).
- `PAC_CLIENT_INFO_TYPE` (0x0A) — Kerberos name + `ClientId` FILETIME.
- `PAC_UPN_DNS_INFO` (0x0C) — UPN + DNS domain name; `UPN_DNS_INFO_FLAG_EXTENDED` (Server 2019+) adds SAM-Account-Name + SID.
- `PAC_BUFFER_TICKET_CHECKSUM` (0x0E) — Server 2012+; HMAC of `Ticket.enc-part` (post-encryption) using the krbtgt key. Silver-ticket mitigation (PC-119): an attacker with a service's NT hash can forge ticket plaintext but cannot forge this KDC-side signature.
- `PAC_REQUESTOR` (0x12) — Server 2019+; requester SID + machine SID. Detects cross-machine TGT abuse.
- `PAC_FULL_CHECKSUM` (0x13) — Server 2016+; HMAC of the entire PAC (excluding existing signature buffers) using the krbtgt key. Defense against PAC tampering.

AD signs the PAC with the krbtgt account's long-term key (HSM-bound per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)). The PAC byte layout is MS-PAC-compliant: NDR-encoded with 8-byte alignment, deterministic buffer order, signatures populated after the body is finalized. Microsoft does not publish a conformance test suite — the framework must derive correctness from interop.

Constraints from [PC-023](../catalog/02-kdc.md): must generate the full buffer set; must support Server 2012+ ticket signature; must sign with the krbtgt key; must accept `NetrLogonSamLogonEx` PAC validation calls (PC-025, ADR-083); byte layout must be MS-PAC-compliant.

## Decision

The framework's KDC (the fresh Rust implementation specified by [Decision 5](../workshop/decision-05-kdc-implementation.md), module `crates/adrian-kdc/src/pac.rs`) SHALL generate MS-KILE-conformant PACs for every TGT and every service ticket. The PAC builder SHALL be deterministic across KDC instances (per [ADR-018](./ADR-018-kdc-horizontal-scaling.md)): the same principal at the same replication point-in-time produces byte-identical PACs on any KDC instance in the pool. The KDC SHALL emit all nine PAC buffer types listed above for tickets issued to Windows clients; for non-Windows clients (MIT krb5, Heimdal), the KDC SHALL emit a reduced set (LOGON_INFO + SERVER_CHECKSUM + PRIVSVR_CHECKSUM + CLIENT_INFO) when the client signals `KRB5_PADATA_PAC_REQUEST = false` per RFC 4120 §5.2.7 extension (KDC MUST honor the client's PAC request).

The PAC builder SHALL be a pure-Rust module — no FFI to Samba's Heimdal, no FFI to MIT's `lib/krb5/krb/pac.c`, no FFI to FreeIPA's `ipa_kdb_mspac.c`. The PAC builder is `~3K` lines of Rust at v1 maturity, organized as:

- `pac.rs` — top-level PAC construction orchestrator; emits `PAC_INFO_BUFFER` array, marshals buffers in deterministic order.
- `pac/logon_info.rs` — `KERB_VALIDATION_INFO` NDR encoder (uses `rasn` for NDR primitives; manual struct definitions for the 60+ fields of `KERB_VALIDATION_INFO`).
- `pac/credentials.rs` — `PAC_CREDENTIAL_TYPE` encrypt/decrypt (AES-256-CTS-HMAC-SHA1-96 to user long-term key per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md)).
- `pac/signature.rs` — `PAC_SERVER_CHECKSUM`, `PAC_PRIVSVR_CHECKSUM`, `PAC_BUFFER_TICKET_CHECKSUM`, `PAC_FULL_CHECKSUM` computation. Server signature uses the service's long-term key; the three KDC signatures use the krbtgt key (via HSM per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)).
- `pac/client_info.rs`, `pac/upn_dns.rs`, `pac/requestor.rs` — the remaining typed buffer encoders.
- `pac/ndr.rs` — NDR encoding helpers (8-byte alignment, pointer dereferencing, conformant arrays); `rasn` provides the primitives.

The PAC builder SHALL be deterministic on these inputs: principal SID, primary group SID, group memberships (`tokenGroups` recursive expansion), `UserAccountControl`, logon server name, logon domain SID, logon time, password timestamps, UPN, DNS domain name, requester SID (if framework-managed host), and the krbtgt kvno. The builder SHALL NOT depend on KDC instance-specific state (random nonces, per-instance counters); all randomness comes from the krbtgt key and the ticket's `key-version-number`.

The KDC SHALL sign all three krbtgt-keyed signatures (`PAC_PRIVSVR_CHECKSUM`, `PAC_BUFFER_TICKET_CHECKSUM`, `PAC_FULL_CHECKSUM`) via the HSM (per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)). The KDC SHALL NOT hold the krbtgt key in process memory in plaintext; the HSM performs the HMAC operations and returns the signature bytes. The HSM round-trip is ≤5 ms per signature (typical PKCS#11 latency); three signatures per TGT issuance add ≤15 ms to AS-REQ latency, well within the 200 ms p99 target from [Decision 5](../workshop/decision-05-kdc-implementation.md).

**Concrete specification**:

- The KDC SHALL emit all nine MS-KILE PAC buffer types for tickets issued to Windows clients and to services that signal `KRB5_PADATA_PAC_REQUEST = true`.
- The KDC SHALL emit a reduced four-buffer PAC (LOGON_INFO + SERVER_CHECKSUM + PRIVSVR_CHECKSUM + CLIENT_INFO) when the client signals `KRB5_PADATA_PAC_REQUEST = false`. Default: emit the full set.
- The PAC byte layout SHALL be MS-PAC-compliant: NDR-encoded, 8-byte aligned, buffers in the deterministic order (LOGON_INFO → CREDENTIAL_TYPE → SERVER_CHECKSUM → PRIVSVR_CHECKSUM → CLIENT_INFO → UPN_DNS_INFO → TICKET_CHECKSUM → REQUESTOR → FULL_CHECKSUM).
- `PAC_LOGON_INFO` SHALL include all 25+ fields of `KERB_VALIDATION_INFO` (`LogonTime`, `LogoffTime`, `KickOffTime`, `PasswordLastSet`, `PasswordCanChange`, `PasswordMustChange`, `EffectiveName`, `FullName`, `LogonScript`, `ProfilePath`, `HomeDirectory`, `HomeDirectoryDrive`, `LogonCount`, `BadPasswordCount`, `UserId`, `PrimaryGroupId`, `GroupCount`, `GroupIds[]`, `UserFlags`, `UserSessionKey`, `LogonServer`, `LogonDomainId`, `LogonDomainName`, `UserAccountControl`, `SubAuthStatus`, `LastLogonInfo`, `ExtraSids[]`, `ResourceGroupDomainSid`, `ResourceGroupCount`, `ResourceGroupIds[]`).
- `PAC_SERVER_CHECKSUM` SHALL use HMAC-SHA1-96-AES (etype 0xFFFFFF76) for AES principals, or HMAC-MD5-RC4 (etype 0xFFFFFF66) for RC4-audit-mode principals per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md).
- `PAC_PRIVSVR_CHECKSUM` SHALL be HMAC of `PAC_SERVER_CHECKSUM.SignatureValue` using the krbtgt key via HSM.
- `PAC_BUFFER_TICKET_CHECKSUM` SHALL be HMAC of the entire `Ticket.enc-part` (the encrypted blob) using the krbtgt key via HSM. Etype matches the ticket's encryption etype.
- `PAC_FULL_CHECKSUM` SHALL be HMAC of the entire PAC (excluding the bytes of `PAC_SERVER_CHECKSUM`, `PAC_PRIVSVR_CHECKSUM`, `PAC_BUFFER_TICKET_CHECKSUM`) using the krbtgt key via HSM.
- `PAC_REQUESTOR` SHALL be populated when the requester's host is framework-managed (machine SID retrieved from the host object); otherwise omitted.
- The PAC builder SHALL be deterministic: same input → same PAC bytes, modulo the signature buffers (which depend on HSM-side key state). `ExtraSids[]` SHALL be sorted lexicographically by SID byte order before encoding.

**Byte-identity invariant**: For a given principal at a given replication point-in-time, the PAC emitted by the framework's KDC SHALL be byte-identical to the PAC emitted by Windows Server 2022+ for the same principal — with two documented exceptions: (a) `PAC_LOGON_INFO.LogonServer` is the framework KDC's netBIOS name (not a Windows DC's name); (b) `PAC_REQUESTOR` may include the framework's machine SID format. Windows services accept both exceptions; the framework's CI interop test suite confirms this against IIS, SQL Server, and Samba SMB.

**Interop test contract** (mandatory before GA, blocks merge per [Decision 5](../workshop/decision-05-kdc-implementation.md)):

- `crates/adrian-kdc-interop/tests/pac_byte_identity.rs` — framework-issued vs Windows Server 2022+-issued PAC for the same principal; field-by-field comparison; documents the two known divergences.
- `crates/adrian-kdc-interop/tests/pac_windows_accept.rs` — Windows `klist --pac` accepts framework-issued PACs; IIS, SQL Server, Samba SMB extract `KERB_VALIDATION_INFO` and authorize based on group memberships.
- `crates/adrian-kdc-interop/tests/pac_framework_accept.rs` — framework services accept Windows-issued PACs (validate `PAC_PRIVSVR_CHECKSUM` via HSM).
- `crates/adrian-kdc-interop/tests/pac_property.rs` — property-based test (`proptest`): for any principal at any replication point-in-time, two framework KDC instances produce byte-identical PACs (modulo HSM signature bytes).
- `crates/adrian-kdc-interop/tests/silver_ticket.rs` — framework-issued tickets with forged `PAC_BUFFER_TICKET_CHECKSUM` are rejected by framework services (silver-ticket mitigation per PC-119).

## Rationale

Five arguments drive this decision.

**1. Fresh Rust eliminates the C-codebase CVE class.** FreeIPA's `ipa_kdb_mspac.c` (5K+ lines of GPLv3 C) and MIT's `lib/krb5/krb/pac.c` (3K+ lines of MIT-licensed C) both have PAC-validation-bypass CVEs in their history (CVE-2017-11462, CVE-2018-20217, CVE-2020-28196). A fresh Rust implementation eliminates the buffer-overflow / use-after-free CWE class in the KDC's most security-critical code path. Per [Decision 5](../workshop/decision-05-kdc-implementation.md), this is the over-riding reason.

**2. The PAC builder must be deterministic for horizontal scaling.** [ADR-018](./ADR-018-kdc-horizontal-scaling.md) deploys the KDC as a stateless pool behind a load balancer; a client's TGS-REQ may land on a different KDC than its AS-REQ. If the PAC builder is non-deterministic (per-instance random nonces, per-instance counters), the PAC differs across instances and Windows services that cache PACs by hash key (`NetrLogonSamLogonEx` cache) thrash. Determinism is achieved by sourcing all entropy from the krbtgt key and ticket kvno; no per-instance state.

**3. HSM-bound krbtgt key eliminates the LSASS-dump → PAC forgery attack.** AD's `PAC_PRIVSVR_CHECKSUM` is computed by `lsass.exe` with the krbtgt key in LSASS memory; an LSASS dump (mimikatz `lsadump::lsa /patch`) extracts the krbtgt key, enabling PAC forgery. The framework's HSM-bound krbtgt key (per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)) makes the signature computation opaque to the KDC process — an LSASS-equivalent dump of the framework's KDC process yields no krbtgt key material. This closes the PAC-forgery attack class at the protocol level.

**4. `PAC_BUFFER_TICKET_CHECKSUM` is the silver-ticket mitigation and is non-optional.** PC-119 (silver ticket) is a known MS-KILE attack: an attacker with a service's NT hash forges a service ticket (the silver ticket) by encrypting a forged `EncTicketPart` with the service's key. Without `PAC_BUFFER_TICKET_CHECKSUM`, the forged ticket is byte-identical to a real one — only services that re-validate via `NetrLogonSamLogonEx` (PC-025, ADR-083) detect the forgery. With `PAC_BUFFER_TICKET_CHECKSUM`, the forged ticket lacks the correct KDC-side signature; any framework service that validates the ticket signature detects the forgery locally without a DC roundtrip. The framework mandates `PAC_BUFFER_TICKET_CHECKSUM` on every ticket issued.

**5. The reduced four-buffer PAC for non-Windows clients honors RFC 4120 §5.2.7.** MIT krb5 and Heimdal clients may set `KRB5_PADATA_PAC_REQUEST = false` (the `disable-pac-request` krb5.conf option), signaling that the client does not need a PAC. The KDC MUST honor this per RFC 4120 §5.2.7; emitting a full PAC when the client explicitly declined wastes ~3 KB per ticket and breaks the protocol contract.

External evidence: [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) defines the PAC structure; [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) defines the KDC's PAC-generation requirements; [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) document the framework's reference PAC layout. [Samba `source4/kdc/samba_kdc.c`](https://github.com/samba-team/samba) and [FreeIPA `ipa_kdb_mspac.c`](https://github.com/freeipa/freeipa/blob/master/daemons/ipa-kdb/ipa_kdb_mspac.c) are the reference open-source implementations (both GPLv3, rejected per [Decision 5](../workshop/decision-05-kdc-implementation.md)).

## Consequences

**Positive**: AD-aware services (IIS, SQL Server, Samba SMB, custom Kerberos apps) accept framework-issued tickets without modification. Cross-forest trusts work because the trusted forest's KDC produces a PAC that the trusting forest's services accept. Silver-ticket attacks (PC-119) are mitigated by `PAC_BUFFER_TICKET_CHECKSUM`. The deterministic PAC builder enables horizontal scaling (ADR-018) without PAC-cache thrashing. The HSM-bound krbtgt key eliminates LSASS-dump → PAC forgery.

**Negative**: The framework's PAC builder is ~3K lines of fresh Rust with no upstream bug-fix pipeline. The CI interop test suite (`crates/adrian-kdc-interop`) is the primary defense. Microsoft does not publish a PAC conformance test suite; the framework must derive correctness from interop, which is brittle to undocumented Windows behavior changes. Mitigation: the PAC builder is conservative (only emits documented fields); Windows accepts conservative PACs.

**Neutral**: The nine-buffer PAC adds ~3 KB to every ticket. AS-REP size grows from ~1.5 KB to ~4.5 KB; UDP-based AS-REQ may fall back to TCP per RFC 4120 §7.2.2.

**Implementation cost**: 8 person-weeks for the PAC builder module, included in the 36 person-weeks for the full KDC per [Decision 5](../workshop/decision-05-kdc-implementation.md). Breakdown: ~3 pw NDR encoder, ~2 pw signature modules (including HSM integration), ~2 pw extended buffer types, ~1 pw property-based bijectivity test.

## Alternatives Considered

### Alternative 1: Reuse Samba's Heimdal fork PAC builder via FFI

Samba's Heimdal fork in `source4/kdc/samba_kdc.c` is the only open-source server implementation that generates MS-PAC. Rejected per [Decision 5](../workshop/decision-05-kdc-implementation.md): GPLv3 contamination, ~5 years behind upstream Heimdal, Samba-specific defect surface.

### Alternative 2: Reuse FreeIPA's `ipa_kdb_mspac.c` as the PAC plugin for MIT krb5

FreeIPA's MS-PAC plugin for MIT krb5 is the reference for trust-user PAC generation. Rejected per [Decision 5](../workshop/decision-05-kdc-implementation.md): GPLv3 contamination, FreeIPA-specific (depends on 389-DS), emits PAC for trust users only (would need extension to all principals, doubling the C defect surface on the highest-risk KDC path).

### Alternative 3: Emit only the RFC 4120 minimum four-buffer PAC

Emit only `PAC_LOGON_INFO + PAC_SERVER_CHECKSUM + PAC_PRIVSVR_CHECKSUM + PAC_CLIENT_INFO`. Smaller tickets, simpler implementation. Rejected: missing `PAC_BUFFER_TICKET_CHECKSUM` leaves silver-ticket attacks (PC-119) unmitigated; missing `PAC_FULL_CHECKSUM` (Server 2016+) leaves PAC-tampering attacks unmitigated; Windows services that opt into PAC validation via `NetrLogonSamLogonEx` may reject tickets missing the extended buffers. The full nine-buffer set is required for AD-interop parity.

### Alternative 4: Compute the three krbtgt-keyed signatures in process memory (no HSM round-trip)

~15 ms saved per AS-REQ. Rejected: violates [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)'s invariant that the krbtgt key NEVER leaves the HSM in plaintext. LSASS-dump-equivalent attacks on the framework's KDC process would leak the krbtgt key, re-opening the PAC-forgery attack class.

## Open Questions

- For `PAC_REQUESTOR` (Server 2019+): should the framework emit this buffer for non-framework-managed hosts (AD-joined hosts authenticating to framework services)? The conservative approach is to omit `PAC_REQUESTOR` when the requester's host is not framework-managed; Windows services that opt into `PAC_REQUESTOR` validation (rare) may reject such tickets. Defer to interop test results in Phase 2.
- For `PAC_BUFFER_TICKET_CHECKSUM` etype: should this match the ticket's encryption etype, or always use AES-256? Windows uses the ticket's etype. The framework matches Windows.
- Cross-reference [ADR-083](./ADR-083-pac-validation-rpc.md) (PC-025) — the PAC validation RPC path that services use to re-validate the framework's PACs is specified there; the two ADRs are tightly coupled.

## Cross-capability impact

- **Core Directory** (ADR-009 `tokenGroups` cache): the PAC builder consumes `tokenGroups` (recursive group expansion) and the principal's `UserAccountControl`. The principal store (per [Decision 5](../workshop/decision-05-kdc-implementation.md), `src/principal_store.rs`) reads from Core Directory via the typed schema projection (Decision 4) with 60-second TTL caching and event-driven invalidation per ADR-018.
- **Auth Provider** (PC-039 S4U2Self/S4U2Proxy, ADR-087): S4U relies on the PAC to carry the user's identity. The framework's S4U2Self/S4U2Proxy implementation (in `crates/adrian-kdc/src/mskile/s4u.rs` per [Decision 5](../workshop/decision-05-kdc-implementation.md)) consumes the PAC generated by this module.
- **Security** (PC-119 silver ticket, ADR-065 golden ticket): `PAC_BUFFER_TICKET_CHECKSUM` is the silver-ticket mitigation; the HSM-bound krbtgt key is the golden-ticket mitigation (per ADR-015). Both mitigations depend on the PAC builder specified here.
- **Operations** (ADR-018 KDC horizontal scaling): the deterministic PAC builder is the precondition for stateless KDC pooling.
- **Client SDK** (ADR-049 MIT krb5 standardization): framework-managed clients request PACs via `KRB5_PADATA_PAC_REQUEST = true`; non-Windows clients MAY decline per RFC 4120 §5.2.7.
- **Migration** (ADR-069 cross-realm capaths): cross-realm TGTs carry PACs from the originating realm; the framework's KDC validates the origin realm's PAC signature before issuing a referral TGT.

## References

- [PC-023](../catalog/02-kdc.md) — problem statement in the catalog
- [Workshop Decision 5 — Fresh Rust KDC](../workshop/decision-05-kdc-implementation.md) — unblocking decision; specifies `crates/adrian-kdc/src/pac.rs` module
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — MS-KILE profile, PAC buffer types, etype table
- [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) — PAC structure, `PAC_INFO_BUFFER` array, NDR encoding, signature computation
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — `kdcsvc.dll` loading into LSASS, KDC thread pool, krbtgt account storage
- [ADR-011](./ADR-011-rc4-deprecation-aes-default.md) — etype negotiation; `PAC_SERVER_CHECKSUM` etype selection
- [ADR-015](./ADR-015-krbtgt-hsm-rotation.md) — HSM-bound krbtgt key; PAC signature HSM round-trip
- [ADR-018](./ADR-018-kdc-horizontal-scaling.md) — deterministic PAC construction across instances
- [ADR-023](./ADR-023-kerberos-audit-events.md) — PAC-related audit events (PAC validation failure, silver-ticket detection)
- [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) — PAC specification
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) — KDC PAC-generation requirements
- [RFC 4120 §5.2.7](https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7) — `AuthorizationData` and PAC request
- [Samba `source4/kdc/samba_kdc.c`](https://github.com/samba-team/samba) — reference GPLv3 implementation (rejected)
- [FreeIPA `ipa_kdb_mspac.c`](https://github.com/freeipa/freeipa/blob/master/daemons/ipa-kdb/ipa_kdb_mspac.c) — reference GPLv3 implementation (rejected)
