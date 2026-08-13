---
title: "Decision 5 — KDC Implementation: Fresh Rust KDC (Not MIT, Not Samba Heimdal)"
status: accepted
date: 2026-08-13
deciders: adrian-architecture-team
orqs_resolved: [ORQ-042, ORQ-043, ORQ-044]
gates: 3 deferred problems (1 blocker, 2 high) + 3 partial ADR dependents
tags: [workshop, decision, tier-1, kdc, kerberos, rust, ms-kile, pac, fresh-implementation]
related:
  - ./CONTEXT.md
  - ../adr/TRIAGE.md
  - ../adr/ADR-011-rc4-deprecation-aes-default.md
  - ../adr/ADR-012-fast-armoring-required.md
  - ../adr/ADR-013-cross-realm-tgt-referral.md
  - ../adr/ADR-014-aes-sha384-etype-0x13.md
  - ../adr/ADR-015-krbtgt-hsm-rotation.md
  - ../adr/ADR-018-kdc-horizontal-scaling.md
  - ../adr/ADR-023-kerberos-audit-events.md
last_updated: 2026-08-13
---

# Decision 5 — KDC Implementation: Fresh Rust KDC (Not MIT, Not Samba Heimdal)

## Status

Accepted — 2026-08-13. This decision resolves Tier-1 ORQ-042 ("Reuse Samba's Heimdal fork (GPL)?"), ORQ-043 ("MIT krb5 + custom PAC plugin (FreeIPA approach)?"), and ORQ-044 ("Fresh implementation?"). All three ORQs are answered by a single commitment: the framework SHALL implement its KDC from scratch in Rust, with **wire-compatibility to RFC 4120 + MS-KILE validated by interop tests against MIT krb5 1.21+, Heimdal 7.x+, and Windows Server 2022+**. This is Option C of the candidate set in `workshop/CONTEXT.md`. The decision overrides the Spike 3 default recommendation (which favored Option B, MIT+plugin) on grounds detailed in §Rationale. The decision is final for v1 and v2; the only condition under which it would be revisited is a catastrophic MS-KILE interop failure in the first six months of Phase 2 MVP testing, in which case the fallback is Option B (MIT+plugin) as an interim, not a replacement.

## ORQs resolved

- **ORQ-042** — "Reuse Samba's Heimdal fork (GPL)?" → **NO**. GPLv3 is a hard blocker for the framework's commercial-licensing posture; Samba's Heimdal fork is ~5 years behind upstream Heimdal and inherits Samba's Heimdal-specific defect surface. Rejected unconditionally.
- **ORQ-043** — "MIT krb5 + custom PAC plugin (FreeIPA approach)?" → **NO**. MIT krb5 is C; the framework's runtime is Rust. Embedding MIT's `krb5kdc` via FFI creates a hybrid-language operations story (separate crash semantics, separate memory-safety story, separate CVE pipelines) that defeats the framework's "memory-safe end-to-end" claim. FreeIPA's `ipa_kdb_mspac.c` (~5K lines, MS-PAC for trust users only) would need extension to all principals, doubling the defect surface on the highest-risk KDC code path. Rejected for the framework; remains a reasonable path for FreeIPA-derived distributions.
- **ORQ-044** — "Fresh implementation?" → **YES**. The framework SHALL implement its KDC in Rust, RFC 4120-conformant, MS-KILE-conformant, and wire-compatible with MIT krb5, Heimdal, and Windows.

## Decision

The framework SHALL implement its KDC as a fresh Rust codebase in the `crates/adrian-kdc` crate (workspace crate, ~30K lines of Rust at v1 maturity). The KDC SHALL consist of:

1. **AS-REQ / AS-REP path** — `src/as_req.rs`. RFC 4120 §3.1 / §5.4.1 compliant; supports `PA-ENC-TIMESTAMP` pre-auth, `PA-FX-FAST` armoring (per ADR-012), `PA-PK-AS-REQ` PKINIT pre-auth (PC-027 deferred but architecturally provided for), anonymous PKINIT armor TGT (RFC 6112). Enforces `fast_mode = "required"` by default per ADR-012.

2. **TGS-REQ / TGS-REP path** — `src/tgs_req.rs`. RFC 4120 §3.3 / §5.4.2 compliant; supports referral TGTs (per ADR-013), cross-realm `Transited` field validation in `"strict"` / `"disabled"` / `"shortcut-aware"` modes, S4U2Self and S4U2Proxy constrained delegation (PC-039, gated by Decision 6), U2U (user-to-user) for services that need it.

3. **PAC builder** — `src/pac.rs`. MS-KILE-conformant PAC generation. Emits `PAC_LOGON_INFO` (KERB_VALIDATION_INFO), `PAC_CREDENTIAL_TYPE`, `PAC_SERVER_CHECKSUM`, `PAC_PRIVSVR_CHECKSUM`, `PAC_CLIENT_INFO_TYPE`, `PAC_REQUESTOR` (Server 2016+), `PAC_FULL_CHECKSUM` (Server 2016+), `PAC_BUFFER_TICKET_CHECKSUM` (Server 2012+; silver-ticket mitigation per PC-119). PAC signing key is the krbtgt key (per ADR-015); `PAC_PRIVSVR_CHECKSUM` is computed via the HSM-bound krbtgt key. The PAC builder is deterministic across KDC instances (per ADR-018): the same principal at the same replication point-in-time produces byte-identical PACs on any KDC instance.

4. **Etype negotiation** — `src/etype.rs`. RFC 4120 §3.1.3 + RFC 8009. AES-256-CTS-HMAC-SHA1-96 (etype 0x12) default per ADR-011; AES-256-CTS-HMAC-SHA384-192 (etype 0x13) preferred when both endpoints support per ADR-014; RC4-HMAC (etype 0x17) audit-then-enforce per ADR-011; DES unconditionally disabled.

5. **Principal store** — `src/principal_store.rs`. Reads from Core Directory via the typed schema projection (Decision 4). Caches user NT hash, group memberships, SPN-to-account mappings with 60-second TTL and event-driven invalidation (per ADR-018). No per-instance persistent state; any KDC instance can service any request.

6. **KDB backend** — `src/kdb.rs`. A thin Rust adapter over Core Directory; no `kdb5` plugin API (MIT krb5's KDB plugin interface is C and is not used). Exposes `get_principal(name)`, `get_principal_by_sid(sid)`, `get_principal_by_spn(spn)`, `list_group_members(sid)`, all backed by Core Directory LDAP reads.

7. **HSM binding** — `src/hsm.rs`. The krbtgt key is HSM-bound per ADR-015; all krbtgt-key cryptographic operations (TGT signing, TGT validation, `PAC_PRIVSVR_CHECKSUM`) SHALL go through the HSM. The KDC SHALL NOT hold the krbtgt key in process memory in plaintext. The HSM SHALL be PKCS#11 v3.0 compatible (via the `cryptoki` Rust crate).

8. **kpasswd (RFC 3244)** — `src/kpasswd.rs`. Per ADR-019; TCP/UDP 464; KRB-PRIV wrapping; identical password-quality validation across kpasswd, REST, and LDAP password-change paths.

9. **Audit emission** — `src/audit.rs`. Per ADR-023; structured OpenTelemetry log events for every AS-REQ, TGS-REQ, pre-auth failure, TGT renewal, old-key TGT usage, AS-REP-without-preauth, RC4 TGS-REQ. Real-time emission (no batching); local journald + remote OpenTelemetry Collector; Windows Event Log IDs 4768/4769/4771/4770 on Windows for SIEM compat.

**Concrete specification**:

- The KDC SHALL be deployed as a stateless pool behind a load balancer (per ADR-018) with 60-second TTL caching and event-driven invalidation. The krbtgt key is shared via the HSM (per ADR-015); the key never leaves the HSM in plaintext.
- The KDC SHALL produce PACs byte-identical to Windows Server 2022+ for the same principal at the same replication point-in-time. Byte-identity is validated by an interop test capturing Windows-issued and framework-issued PACs for the same principal and comparing them field-by-field.
- The KDC SHALL support FAST-required mode by default (per ADR-012); `fast_mode = "supported"` / `"audit"` / `"grace"` modes available for migration. Anonymous PKINIT armor TGT (RFC 6112) is supported; full PKINIT (PC-027) is deferred to ORQ-110/111 but the protocol path is stubbed in v1.
- The KDC SHALL support etype 0x13 preference over 0x12 per ADR-014; etype 0x17 (RC4) audit-then-enforce per ADR-011.
- The KDC SHALL support RFC 4120 §3.3.3 cross-realm TGT referral and `Transited` field validation per ADR-013 in per-trust modes `"strict"` (default for cross-forest), `"disabled"` (default for intra-forest), `"shortcut-aware"`.
- The KDC SHALL scale to ≥5K AS-REQ/sec per instance; a 10-instance pool SHALL handle ≥50K AS-REQ/sec (per ADR-018). It SHALL expose `GET /health` (HTTP/1.1, port 8080) for load-balancer health checks.
- The KDC SHALL emit audit events per ADR-023 including KDC instance ID, etype, SPN, requester SID, source IP, FAST flag, kvno, and result code.
- The framework SHALL expose `adrian-krb5 kdc-pool scale <N>` / `status`, `adrian-krb5 audit-rc4`, `adrian-krb5 audit-fast`, `adrian-krb5 capaths generate`, `adrian-krb5 trusts list` / `show`, and `adrian-krb5 rotate-krbtgt` CLI commands.

**Wire-compatibility validation** (mandatory before GA): interop test suite (`crates/adrian-kdc-interop`, run in CI on every KDC PR; regression blocks merge) covers (a) MIT krb5 1.21+ — framework-issued TGT accepted by `kvno`/`klist`, MIT-issued TGT accepted by framework KDC; (b) Heimdal 7.x+ — same; (c) Windows Server 2022+ — framework-issued TGT/TGS accepted by Windows `klist`, IIS, SQL Server, and Samba SMB server; Windows-issued TGT/TGS accepted by framework-hosted services; (d) PAC acceptance — framework-issued PAC validated by `kvno --pac`, Windows `klist`, and Samba SMB; (e) S4U2Self/S4U2Proxy — framework-issued S4U tickets accepted by Windows S4U clients.

## Rationale

The decision overrides Spike 3's recommendation (Option B, MIT+plugin) on five grounds:

**1. License posture.** The framework is dual-licensed Apache-2.0 / MIT for the core with a commercial option for enterprise. MIT krb5 itself is MIT-licensed (embedding it does not violate the framework's license), but FreeIPA's `ipa_kdb_mspac.c` reference is GPLv3; using it as the basis for the PAC plugin propagates GPLv3 to the framework's KDC. A clean-room reimplementation of `ipa_kdb_mspac.c` in C is the same effort as a fresh Rust implementation and produces a C codebase the framework must then maintain. Samba's Heimdal fork is GPLv3 (rejected for ORQ-042).

**2. Memory-safety story.** The framework's "memory-safe end-to-end" claim is inoperative if the KDC is C. MIT krb5 has had 60+ CVEs since 2014, ~30 of which are memory-safety bugs (buffer overflows, UAF, double-free); Heimdal's CVE history is similar. A Rust KDC eliminates this entire CWE class in the KDC code path — the second-most-security-critical capability in the framework.

**3. Embedding cost.** MIT's `krb5kdc` is a single-process-per-host daemon with its own `kdb5` plugin API, its own `krb5.conf`, its own logging and signal handling. Embedding it in the framework's `tokio` runtime requires either running it as a subprocess (defeating the unified operations story) or wrapping the C library via FFI (defeating the memory-safety story and creating a hybrid crash model: a segfault in MIT's `krb5kdc` brings down the framework's whole DC process). Neither is acceptable. A fresh Rust KDC integrates natively with `tokio`, with `tracing`/OpenTelemetry, and with the framework's configuration system.

**4. PAC defect surface.** FreeIPA's `ipa_kdb_mspac.c` is the MS-PAC reference but emits MS-PAC for trust users only; extending it to all principals is a 5K-line C extension on top of a 5K-line C reference, in a code path with ~10 CVEs since 2014 (PAC validation bypasses, signature forgeries). The framework's PAC builder in Rust is a fresh ~3K-line implementation in a memory-safe language with a property-based test harness (bijectivity against Windows-issued PACs). The defect surface is smaller in absolute lines and smaller in CWE-class.

**5. Long-term maintenance.** MIT krb5 maintenance is funded by the MIT Kerberos Consortium on a months-to-years cadence; Heimdal by SUSE/Apple on a similar cadence. The framework cannot wait for upstream to fix a security bug. A Rust KDC maintained by the framework team can patch security issues on the framework's own cadence (hours to days). For a security-critical capability, this is decisive.

**Counter-argument acknowledged**: the fresh Rust KDC is a multi-year investment. A ~30K-line Rust KDC written by a 3-engineer team takes ~9 months to MVP. The KDC is NOT in v1 MVP — it is the long pole on the v1 critical path. Mitigation: Phase 2 MVP ships with a "KDC preview" (AS-REQ/TGS-REQ working; PAC validation tested against MIT and Windows but not against IIS/SQL Server; FAST-required enabled; PKINIT stubbed). Phase 3 (~6 months after MVP) ships the full v1 KDC. The workshop accepts this schedule risk because the alternatives (embedding MIT or Samba) are worse on every other dimension.

External evidence: [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) defines Kerberos V5; [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) defines Microsoft's extensions (PAC, FAST-with-armor-key, S4U2Self/S4U2Proxy, U2U); [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) defines the PAC structure. The framework's KDC SHALL be RFC 4120 + MS-KILE + MS-PAC conformant, with PACs byte-identical to Windows Server 2022+ for the same input principal. [MIT krb5 advisories](https://web.mit.edu/kerberos/advisories/) and [Heimdal advisories](https://www.h5l.org/) document the C-language CVE history. [FreeIPA `ipa_kdb_mspac.c`](https://github.com/freeipa/freeipa/blob/master/daemons/ipa-kdb/ipa_kdb_mspac.c) is the reference MS-PAC plugin (5K+ lines of GPLv3 C). The Rust kerberos ecosystem (`krb5-rs`, `rasn-kerberos`) provides protocol-parsing primitives the framework SHALL use where available; the framework SHALL NOT use them for crypto (use `ring` / `aes` directly).

## Trade-offs accepted

- **Schedule risk.** The fresh Rust KDC is the long pole on the v1 critical path (~9 months to MVP). v1 MVP ships with a "KDC preview"; full PAC validation lands in Phase 3. Customers requiring v1-MVP Kerberos must use MIT krb5 in parallel during the preview window.
- **MS-KILE corner-case risk.** Constrained delegation (S4U2Self/S4U2Proxy), compound identity, `PAC_REQUESTOR` / `PAC_FULL_CHECKSUM` (Server 2016+), `PAC_BUFFER_TICKET_CHECKSUM` (silver-ticket mitigation) are MS-KILE-specific corner cases with no RFC equivalent. The fresh Rust implementation may ship with v1 gaps in these corner cases; the CI interop test suite catches them before GA.
- **No upstream bug-fix pipeline.** The framework inherits 0 CVE fixes from MIT or Heimdal; it must find and fix its own. The CI interop test suite and the property-based PAC bijectivity test are the primary defense.
- **Initial implementation cost.** ~9 months × 3 engineers = 27 person-months for v1 MVP; ~12 months × 3 engineers = 36 person-months for full v1. This is the single largest engineering investment in the framework.
- **Rust kerberos ecosystem immaturity.** `krb5-rs` and `rasn-kerberos` are emerging crates with limited production deployments. The framework contributes fixes upstream and maintains a fork of critical crates if necessary. The framework also cannot directly incorporate FreeIPA community fixes; it monitors `ipa_kdb_mspac.c` and ports fixes to Rust.
- **First-mover risk.** The framework is the first non-Microsoft MS-KILE-conformant KDC written in Rust. No prior art exists; the framework's KDC will be the reference for future Rust Kerberos implementations.

## Rust implementation implications

**Crates used**:

- `adrian-kdc` (framework crate, written from scratch — ~30K lines at v1 maturity). The KDC itself: AS-REQ, TGS-REQ, PAC builder, etype negotiation, principal store, KDB backend, HSM binding, kpasswd, audit emission.
- `adrian-kdc-interop` (framework crate). Wire-compatibility test suite; runs against MIT krb5, Heimdal, Windows Server 2022+.
- `rasn` (v0.10+, MIT/Apache-2.0) for ASN.1 encoding/decoding of Kerberos message types (`KDC-REQ`, `KDC-REP`, `EncTicketPart`, `Ticket`, `Authenticator`, `AP-REQ`, `AP-REP`, `KRB-ERROR`, `KRB-PRIV`).
- `rasn-kerberos` (v0.10+, MIT/Apache-2.0) for the Kerberos-specific ASN.1 type definitions. Used where it matches RFC 4120; the framework SHALL NOT use it for MS-KILE-specific extensions (those live in `adrian-kdc::mskile`).
- `ring` (v0.17+), `aes` (v0.8+), `sha1` (v0.10+), `sha2` (v0.10+), `pbkdf2` (v0.12+), `md4` (v0.10+) — all MIT/Apache-2.0 — for low-level crypto primitives: AES-CTS, HMAC-SHA1-96 (etype 0x12), HMAC-SHA384-192 (etype 0x13), PBKDF2-HMAC-SHA1 (4096 iterations per RFC 8009 §1), NT hash (RC4 audit path per ADR-011).
- `cryptoki` (v0.6+, MIT/Apache-2.0) for PKCS#11 v3.0 HSM access (krbtgt key per ADR-015).
- `tokio` (v1.40+, MIT) for async runtime; `tokio-uring` (v0.4+, MIT) for io_uring-based UDP socket I/O on Linux (Kerberos clients prefer UDP for small AS-REQs).
- `ldap3` (v0.11+, MIT/Apache-2.0) for principal-store reads from Core Directory (via the typed projection from Decision 4).
- `tracing` (v0.1+, MIT) + `opentelemetry` (v0.24+, MIT) for audit emission per ADR-023.
- `hickory-server` (v0.8+, MIT/Apache-2.0) for SRV record publishing (`_ldap._tcp.dc._msdcs.<domain>` per ADR-018).

**Crates NOT used**: `krb5-rs` (binding to MIT's libkrb5 — would reintroduce the C dependency; used only for interop tests as a reference client); `kerberos_parser` (superseded by `rasn-kerberos`); `openssl` (rejected as the crypto backend; `ring` + `aes` + `sha1` + `sha2` cover all Kerberos etypes with smaller attack surface; the framework's TLS stack uses `rustls` per ADR-021).

**Module layout** (`crates/adrian-kdc/src/`): `lib.rs` (public API: `Kdc::new(config) -> Kdc; Kdc::run().await`); `as_req.rs` / `tgs_req.rs` (AS-REQ / TGS-REP paths); `pac.rs` (MS-KILE PAC builder); `etype.rs` (etype negotiation); `crypto/{mod,cts,hmac,pbkdf2,rc4}.rs` (AES-CTS, HMAC-SHA1/SHA384, PBKDF2 4096, RC4 audit path); `principal_store.rs` (Core Directory reads via typed projection; 60s TTL cache); `kdb.rs` (KDB backend trait; no kdb5 plugin API); `hsm.rs` (PKCS#11 v3.0 krbtgt binding); `kpasswd.rs` (RFC 3244 on TCP/UDP 464); `audit.rs` (ADR-023 emission); `mskile/{mod,s4u,pac_requestor,pac_full_checksum,ticket_checksum}.rs` (MS-KILE extensions: S4U2Self/S4U2Proxy, Server 2016+ PAC fields, silver-ticket mitigation); `fast.rs` (PA-FX-FAST armoring); `pkinit.rs` (PA-PK-AS-REQ stub); `referral.rs` (RFC 4120 §3.3.3 referral + Transited field validation).

**Performance targets**: AS-REQ throughput ≥5K req/sec per KDC instance on commodity hardware (8 vCPU, 16 GB RAM, 10 GbE); TGS-REQ throughput ≥7K req/sec per instance (TGS is cheaper; no PBKDF2); AS-REQ p99 latency <50 ms (cache hit) / <200 ms (cache miss, Core Directory read); PAC construction <1 ms per PAC (~3KB, ~5 signature operations); krbtgt key HSM round-trip <5 ms per signing operation (typical PKCS#11 latency).

**Testing strategy**: (a) unit tests for every ASN.1 type round-trip (encode → decode → byte-identical); (b) property-based tests (`proptest`) for PAC bijectivity — framework-built PAC → Windows parses it, Windows-built PAC → framework validates it, round-trip framework → framework is byte-identical; (c) interop test suite (`crates/adrian-kdc-interop`) runs against MIT krb5 1.21+, Heimdal 7.x+, Windows Server 2022+ (covers AS-REQ, TGS-REQ, cross-realm referral, S4U2Self, S4U2Proxy, FAST armoring, etype negotiation, PAC validation); (d) fuzzing via `cargo fuzz` targets for the AS-REQ, TGS-REQ, and PAC parsers (minimum 100M iterations in CI nightly).

## Problems unblocked

| PC | Title (short) | Capability | Severity | Pre-gating ORQ | Now unblocked by Decision 5? |
|----|---------------|-----------|----------|----------------|------------------------------|
| PC-023 | MS-KILE profile + PAC generation | KDC | blocker | ORQ-042/043/044 | YES — the fresh Rust KDC implements MS-KILE; PAC generation is `src/pac.rs`; byte-identity to Windows Server 2022+ validated by interop tests |
| PC-025 | PAC validation RPC roundtrip | KDC | high | ORQ-042/043/044 | YES — the fresh KDC supports both `PAC_BUFFER_TICKET_CHECKSUM` (Server 2012+, silver-ticket mitigation) and the older NETLOGON RPC validation path; services can choose either |
| PC-119 | Silver ticket (service-account hash) | Security | high | ORQ-042/043/044 | YES — `PAC_BUFFER_TICKET_CHECKSUM` is implemented in `src/mskile/ticket_checksum.rs`; this is the silver-ticket mitigation per the deferred problem statement |
| PC-027 | PKINIT smart-card logon | KDC | high | ORQ-110/111 (PKI enrollment) | PARTIAL — the KDC's PKINIT protocol path is stubbed (`src/pkinit.rs`); full PKINIT depends on the PKI enrollment decision (Day 2 PM) |
| PC-039 | S4U2Self + S4U2Proxy constrained delegation | Auth Provider | high | ORQ-072/074/075 (NTLM) | PARTIAL — S4U protocol implemented in `src/mskile/s4u.rs`; the S4U-vs-OAuth2 decision depends on Decision 6 (NTLM) |

Plus partial-ADR dependents that can now be promoted from PARTIAL to full:

- **ADR-064** (Kerberoasting AES migration) — was PARTIAL on PAC validation mechanism; `PAC_BUFFER_TICKET_CHECKSUM` is now the chosen mechanism. ADR-064 can be promoted.
- **ADR-065** (krbtgt HSM rotation) — was PARTIAL on KDC integration; the HSM binding is now specified in `src/hsm.rs`. ADR-065 can be promoted.
- **ADR-069** (cross-realm capaths) — was PARTIAL on KDC implementation; the referral logic is in `src/referral.rs`. ADR-069 can be promoted.

## Implementation impact

**Person-week estimates per capability**:

- KDC: 36 person-weeks (full v1: AS-REQ/TGS-REQ 8 pw, PAC builder 8 pw, etype negotiation 3 pw, principal store + KDB 4 pw, HSM binding 3 pw, kpasswd 2 pw, audit emission 3 pw, MS-KILE extensions 5 pw; "KDC preview" for v1 MVP is ~20 pw — AS-REQ, TGS-REQ, PAC builder, etype, HSM, audit; no S4U, no PKINIT, no MS-KILE corner cases).
- Core Directory: 2 pw (principal-store reads via the typed projection; event-driven cache invalidation hook).
- Auth Provider: 1 pw (client-side Kerberos SSPI-equivalent already mostly MIT krb5 via the Client SDK per ADR-049; FAST-required mode integration).
- Operations: 2 pw (KDC pool operator tooling; SRV record publishing; autoscaler config).
- Security: 1 pw (audit-event SIEM queries per ADR-023; Kerberoasting / golden-ticket / AS-REP-roasting alert rules).

**Total: 42 person-weeks** (full v1); ~24 person-weeks (v1 MVP preview). The KDC is on the v1 critical path: the preview blocks Phase 2 MVP signoff; the full KDC blocks Phase 3 GA. Staffing: 3 engineers full-time on the KDC for ~9 months (preview) to ~12 months (full v1).

**Risk items**:

- **MS-KILE corner cases.** S4U2Self/S4U2Proxy, compound identity, `PAC_REQUESTOR`, `PAC_FULL_CHECKSUM` are documented only in MS-KILE and in third-party reverse-engineering (Mimikatz, Rubeus, Impacket). The interop test suite catches gaps; the test suite itself is a deliverable.
- **PKINIT dependency for FAST-required.** ADR-012's anonymous PKINIT armor TGT (RFC 6112) requires PKINIT, deferred to ORQ-110/111. The v1 MVP KDC SHALL ship with `fast_mode = "supported"` (not `"required"`); the flip to `"required"` SHALL occur once PKINIT is implemented (Phase 3). This is a documented schedule risk for ADR-012.
- **PAC byte-identity against Windows.** Microsoft does not publish a PAC conformance test suite. The interop test captures Windows-issued PACs and compares field-by-field; undocumented fields (e.g. reserved bits in `PAC_LOGON_INFO`) may differ. Mitigation: the PAC builder is conservative (only emits documented fields); Windows accepts conservative PACs.
- **Ecosystem immaturity.** `rasn-kerberos` is a young crate; bugs will surface. The framework contributes upstream fixes and maintains a fork if upstream is unresponsive.

## Cross-capability dependencies

- **KDC ↔ Core Directory.** Principal store reads from Core Directory via the typed projection (Decision 4); event-driven cache invalidation per ADR-018. Core Directory publishes invalidation events on password change, group membership change, SPN change.
- **KDC ↔ Auth Provider.** Auth Provider's Kerberos SSPI-equivalent benefits from the KDC pool's horizontal scaling (ADR-018). FAST armoring is enforced by the KDC; the client side MUST support FAST.
- **KDC ↔ Cert Service.** Anonymous PKINIT armor TGT (RFC 6112) requires an Enterprise CA or anonymous-PKINIT-capable cert on the KDC. Gated by PC-027 (PKINIT, deferred to ORQ-110/111). v1 MVP ships without PKINIT; the flip to `fast_mode = "required"` is gated on PKINIT.
- **KDC ↔ Client SDK.** Client SDK MUST support FAST, etype 0x13, and the framework's referral semantics on all platforms. MIT krb5 1.18+ and Heimdal 7.x+ support all of these; the SDK's MIT-krb5-based client per ADR-049 covers it.
- **KDC ↔ Operations.** KDC pool monitoring, autoscaling, SRV record publishing, `adrian-krb5` CLI tooling.
- **KDC ↔ Security.** Audit-event SIEM queries for Kerberoasting / golden-ticket / AS-REP-roasting detection (per ADR-023). `PAC_BUFFER_TICKET_CHECKSUM` mitigates silver-ticket attacks (PC-119).
- **KDC ↔ Migration.** AD-to-framework migration replaces AD's per-DC KDC with the framework's KDC pool. Clients discover KDC instances via SRV records (no client-side change). Existing TGTs issued by AD remain valid until they expire; new TGTs are issued by the framework's KDC.

## References

- [`workshop/CONTEXT.md`](./CONTEXT.md) — §ORQ-042/043/044 candidate analysis; §Decision criteria; §Pre-workshop reading list
- [`adr/TRIAGE.md`](../adr/TRIAGE.md) — DEFERRED problems PC-023/025/119 gated by ORQ-042/043/044
- [`adr/ADR-011-rc4-deprecation-aes-default.md`](../adr/ADR-011-rc4-deprecation-aes-default.md), [`adr/ADR-012-fast-armoring-required.md`](../adr/ADR-012-fast-armoring-required.md), [`adr/ADR-013-cross-realm-tgt-referral.md`](../adr/ADR-013-cross-realm-tgt-referral.md), [`adr/ADR-014-aes-sha384-etype-0x13.md`](../adr/ADR-014-aes-sha384-etype-0x13.md), [`adr/ADR-015-krbtgt-hsm-rotation.md`](../adr/ADR-015-krbtgt-hsm-rotation.md), [`adr/ADR-018-kdc-horizontal-scaling.md`](../adr/ADR-018-kdc-horizontal-scaling.md), [`adr/ADR-023-kerberos-audit-events.md`](../adr/ADR-023-kerberos-audit-events.md) — existing KDC Auth Provider ADRs that the fresh KDC SHALL enforce
- [`docs/02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — MS-KILE profile, PAC buffer types, etype table
- [`docs/02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — PAC structure, `PAC_INFO_BUFFER` array
- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) (Kerberos V5); [RFC 4120 §3.3.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3) (cross-realm operation); [RFC 6112](https://www.rfc-editor.org/rfc/rfc6112) (anonymous PKINIT); [RFC 6806](https://www.rfc-editor.org/rfc/rfc6806) (FAST); [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) (AES-CTS-HMAC etypes)
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/); [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/)
- [MIT krb5 security advisories](https://web.mit.edu/kerberos/advisories/); [Heimdal advisories](https://www.h5l.org/); [FreeIPA `ipa_kdb_mspac.c`](https://github.com/freeipa/freeipa/blob/master/daemons/ipa-kdb/ipa_kdb_mspac.c)
