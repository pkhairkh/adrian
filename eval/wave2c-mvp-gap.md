# Wave 2c — MVP Gap Analysis

**Auditor**: Sub-agent E2-c
**Date**: 2026-08-13
**Scope**: Cross-cutting gap analysis vs Phase 1 MVP success criteria
**Repo HEAD**: `d4d714e` on `main` (v0.5.0)
**Inputs**: Wave 1a (storage/identity), Wave 1b (protocol), Wave 1c (auth/crypto), Wave 1d (app/ops) findings; `HANDOVER_PROMPT.md`; `TASKS.md`; `adr/README.md`; `finaldraft/06-implementation-roadmap.md`

---

## Executive Summary

The Adrian framework at v0.5.0 is **structurally complete but functionally non-deployable**. Of the 12 Phase 1 MVP success criteria, **2 are MET** (both mechanical: `cargo fmt --check` and the ≥578-tests gate), **3 are PARTIAL** (test count, security mitigations, mixed-mode interop lab), and **7 are NOT_MET** — including every criterion that requires an actual end-user-facing operation (`join`, `kinit`, `authselect apply`, `cert enroll`, `file mount`). Wave 1 found that the KDC service is a loud stub (`handle_as_req`/`handle_tgs_req`/`handle_kpasswd` return `KdcError::Storage("not yet implemented")` at `adrian-kdc/src/lib.rs:88,94,100`), the LDAP server has no BER codec and no TCP listener (Wave 1b), DRSUAPI returns `Backend` for every opnum (Wave 1b), the SDK's 5 module trait impls all return `"not yet wired to <crate>"` errors (Wave 1d), and the PAC validator is a stub (`parse` returns `Malformed`, both `validate_*` return `SignatureMismatch`) — meaning the ADR-123 silver-ticket mitigation is structurally inert. Of the 16 MVP-critical ADRs audited, **3 are COMPLIANT** (ADR-043 drop SMB1, ADR-085 NTLM client-only, ADR-110 SID-to-UID), **7 are PARTIAL** (ADR-011, ADR-015, ADR-020, ADR-073, ADR-074, ADR-082, ADR-122), and **6 are NONCOMPLIANT** (ADR-019, ADR-021, ADR-070, ADR-083, ADR-086, ADR-105, ADR-123).

**Estimated effort to v1.0**: 60–80 person-weeks of focused engineering, gated on a **3-workstream critical path** — (a) real KDC AS-REQ/TGS-REQ handler with RFC 3961 §5.1 key derivation and a working AES-CTS implementation, (b) real DRSUAPI NDR codec + DRSBind handler for AD-interop replication, and (c) a working interop test lab (`adrian-test-harness` + Windows Server 2022 + MIT krb5 containers). The roadmap is **behind by ~5–9 months** against the optimistic 6-month Phase 1 MVP target; the realistic 12-month target is still achievable if Wave 6 is dedicated entirely to wiring SDK stubs to backends and Wave 7 to interop validation.

---

## MVP Success Criteria Gap Analysis

| # | Criterion | Status | Evidence | Remaining work |
|---|-----------|--------|----------|----------------|
| 1 | Linux host joins framework via `adrian-cli join` | **NOT_MET** | Per Wave 1d, `adrian-sdk::AdrianClient::join` returns `Err(SdkError::NotJoined)` (`rust/crates/adrian-sdk/src/lib.rs:72`). `adrian-cli` `dispatch_join` surfaces that error (Wave 1d integration matrix). The CLI does not write `/etc/adrian/`, does not configure `authselect`, does not pull a domain-join cert via ACME. | Implement `AdrianClient::join` end-to-end: TLS-secured LDAP bind to `adrian-directory-service`, machine-account creation in directory, machine-key derivation via `adrian-hsm`, ACME cert enrollment via `adrian-acme-server`, `authselect select adrian-with-sudo` invocation via `adrian-policy-executor`, ticket-cache bootstrap. Blocked on criteria #2–#5 below. |
| 2 | Host authenticates via Kerberos (AS-REQ/TGS-REQ) | **NOT_MET** | Per Wave 1c, `KdcService::handle_as_req`/`handle_tgs_req` are loud stubs at `adrian-kdc/src/lib.rs:88,94` returning `KdcError::Storage("not yet implemented")`. Even if those were implemented, the crypto module skips RFC 3961 §5.1 key derivation (uses base key directly as Ke/Ki per `crypto.rs:18-30`) and AES-CTS panics on partial blocks (`crypto.rs:131,181`). `KerberosAuthModule::authenticate_kerberos` returns `"not yet wired to adrian-kdc (ADR-108)"` (Wave 1d). | Implement RFC 4120 §3.1/§3.3 AS-REQ/TGS-REQ handlers (~500–1000 LoC). Implement RFC 3961 §5.1 `nfold` + DR-encryption key derivation (~150 LoC). Rewrite `aes256_cts_encrypt`/`decrypt` per RFC 2040 §6 / RFC 3962 §5.3 (fixes panic + interop). Implement 9-buffer `PacBuilder` per ADR-082. Wire `KerberosAuthModule` to drive an AS-REQ against the KDC. |
| 3 | Host applies policy via `authselect` | **PARTIAL** | Per Wave 1d, `adrian-policy-executor::LinuxPolicyExecutor::synthesize_sync` is REAL_COMPLETE — emits `etc/authselect/adrian.conf`, `firewalld` XML, `limits.conf.d`, `audit.rules.d` per ADR-050 (`rust/crates/adrian-policy-executor/src/lib.rs:404-502`). But `PolicyExecutor::apply` is a silent stub returning `Ok(ApplyResult { transaction_id: Uuid::nil(), areas_applied: 0, ... })` at `rust/crates/adrian-policy-executor/src/lib.rs:263-274`. The SDK's `DeclarativePolicyModule::apply` returns `"not yet wired to adrian-policy-executor"` (Wave 1d). | Implement `PolicyExecutor::apply` that actually writes the `synthesize`d files to disk (initially `/etc/`, later SYSVOL share via `adrian-smb-client`). Add ADR-025 transactional rollback later (Phase 3). Wire `DeclarativePolicyModule::apply` to call `LinuxPolicyExecutor::apply`. Add CLI `adrian gpupdate` dispatch. |
| 4 | Host requests cert via ACME (`adrian-cli cert enroll`) | **NOT_MET** | Per Wave 1d, `adrian-acme-server::AcmeServer::router()` returns an empty `axum::Router::new()` with no routes — no `/directory`, `/new-nonce`, `/new-account`, `/new-order`, `/authz-v3`, `/challenge`, `/finalize`, `/cert` endpoints (Wave 1d per-crate findings). `adrian-ca::CaService::issue`/`revoke`/`load_profiles` return loud stub errors (5 TODOs in `lib.rs`). `AcmeCertModule::enroll` returns `"not yet wired to adrian-acme-server (ADR-095/097)"` (Wave 1d). | Implement RFC 8555 §7.1-§7.7 endpoints (~2-3 weeks). Implement `CaService::issue` via `rcgen` or `x509-cert` + `adrian-hsm` signing (~1 week). Implement `CaService::revoke` (CRL + OCSP entry). Wire `AcmeCertModule::enroll` to drive ACME flow against the local server. Add CLI `adrian cert enroll` dispatch. |
| 5 | Host mounts SMB share (`adrian-cli file mount`) | **NOT_MET** | Per Wave 1d, `adrian-smb-server::SmbServer::serve()` returns `Err(SmbServerError::Protocol("not yet implemented"))`. `adrian-smb-client::SmbClient::connect` returns `Connect("not yet implemented")`, `open` returns `Share("not yet implemented")`. `adrian-smb-core::encode_negotiate`/`decode_negotiate` return `Err(SmbError::Malformed("not yet implemented"))`. `SmbFileModule::mount_share` returns `"not yet wired to adrian-smb-client (ADR-106)"`. | Implement `adrian-smb-core` PDU codecs via `rasn` (~3 weeks). Implement `adrian-smb-server` NEGOTIATE / SESSION_SETUP (Kerberos via GSSAPI) / TREE_CONNECT / CREATE / READ / WRITE / CLOSE / TRANSFORM per ADR-105 (~6 weeks). Implement `adrian-smb-client` tree-connect + persistent handles per ADR-106 (~3 weeks). Wire `SmbFileModule::mount_share`. |
| 6 | All of the above works against both framework DC and Windows Server 2022 DC in mixed mode | **NOT_MET** | TASKS.md `T-030` (interop test lab) and `T-031` (end-to-end MVP integration test) are **unchecked**. Per Wave 1b, `adrian-drsuapi::drs_bind` returns `Backend("not yet implemented")` — no DRSBind handler exists, so no replication traffic can flow between a framework DC and a Windows DC. Per Wave 1c, `adrian-kdc-interop` is `STUB_LOUD` — both functions return `TargetUnavailable("not yet implemented")`. Per Wave 1d, `adrian-test-harness` has 0 tests and 3 TODOs (no in-process FDB cluster, no Windows Server 2022 lab fixtures, no MIT krb5/Samba containers). | Implement DRSUAPI DRSBind + DRSGetNCChanges NDR codecs (Wave 1b P0, ~4-6 person-weeks). Build `adrian-test-harness` in-process FDB + directory-service + KDC fixtures (~1 week). Stand up a Windows Server 2022 lab VM with `tcpdump` capture. Implement `adrian-kdc-interop` test driver (~2 weeks). |
| 7 | PAC byte-identity validated against Windows Server 2022 in `adrian-kdc-interop` | **NOT_MET** | Per Wave 1c, `adrian-pac-validator` is `STUB_LOUD` — `Pac::parse`, `validate_kdc_checksum`, `validate_service_checksum` all return errors (`rust/crates/adrian-pac-validator/src/lib.rs:67,75,82`). `adrian-kdc-interop` is `STUB_LOUD` (7 STRUCTURAL_ONLY tests pinning loud-stub contract). `PacBuilder` in `adrian-kdc` is also a stub (Wave 1c). | Implement `PacBuilder` with all 9 MS-KILE buffer types per ADR-082. Implement `Pac::parse` via `rasn-kerberos`. Implement both checksum validators per ADR-083 Layer 1 + Layer 2. Capture real Windows PAC bytes as test fixtures; assert byte-identity. |
| 8 | Performance targets: 5K AS-REQ/s, 10K writes/s, <5s lag | **NOT_MET** | Per Wave 1c, the KDC AS-REQ handler is a loud stub — zero throughput. Per Wave 1a, real FDB path is **not compile-tested** (no libclang in dev sandbox); throughput on real FDB is unknown. Per Wave 1b, `adrian-raft::apply_changes` advances `commit_index` to `last_log_index()` immediately after local append with no quorum ack (commit-without-quorum bug at `lib.rs:862`) — replication lag would be 0ms (it commits before peers ack) but **at the cost of data loss on partition**. Per Wave 1d, `adrian-monitor` has zero producers — no metrics exist to verify any throughput target. | Implement KDC AS-REQ handler; benchmark against MIT krb5 `kinit` throughput. Compile-verify real FDB path; benchmark against FDB 7.3+ on NVMe. Wire openraft `RaftLogStore` over FDB + `RaftNetwork` over TCP. Add `inc_as_req`/`observe_as_req_duration` calls in KDC; `inc_fdb_operation` in storage; `set_replication_lag` in repl layer. |
| 9 | Security mitigations active: RC4 refused, krbtgt HSM-bound, DCSync audited | **PARTIAL** | **RC4 refused**: ADR-011 compliance is PARTIAL. Per Wave 1c, the KDC `EType` enum has an `Rc4Hmac` variant documented "disabled by default, ADR-011" (`adrian-kdc/src/lib.rs:40`), and tests pin the policy discrimination `KdcError::Policy("rc4 disabled")`. But the KDC service is a loud stub — no TGS-REQ is ever issued, so the policy is structurally enforced but functionally inert. **krbtgt HSM-bound**: ADR-015 PARTIAL. `KrbtgtManager` (Wave 1c, `krbtgt.rs:97`) implements `rotate()` with 30-day interval + 2-key overlap; `SoftwareHsm` is real (Wave 1c). But `SoftwareHsm` does NOT zeroize key material (`KeyEntry.material: Vec<u8>` plain, not `Zeroizing`), `generate_key` is destructive (overwrites existing keys, resets kvno), and no auto-rotation scheduler exists (krbtgt.rs:22-24 doc TODO). The `hsm` feature flag enables `cryptoki` but no `Pkcs11Hsm` impl ships. **DCSync audited**: ADR-122 NONCOMPLIANT. Per Wave 1b, `EXOP_REPL_SECRETS` constant value is verified (lib.rs:311-338) but ACL gating (`DS-Replication-Get-Changes-All` GUID check) is NOT implemented; the entire `drs_get_nc_changes` returns Backend error before any ACL check. Per-Principal audit hook is not implemented. | For RC4: implement real AS-REQ/TGS-REQ so the rc4-disabled policy is actually exercisable. For krbtgt HSM: add `Zeroizing` wrappers, `find_or_create_key` non-destructive semantics, auto-rotation tokio task, real PKCS#11 backend. For DCSync: implement `drs_get_nc_changes` with ACL gating on `DS-Replication-Get-Changes-All`, emit audit event per ADR-122. |
| 10 | `cargo test --workspace` shows 578+ passed, 0 failed | **MET** | CHANGELOG v0.5.0 reports 602 tests across 47 crates (16 ignored). Wave 1 auditors independently verified test counts (Wave 1a: 156 tests in storage/identity layer; Wave 1c: ~78 tests in auth/crypto layer). HANDOVER_PROMPT required ≥578 tests; 602 ≥ 578. | None. Caveat: per Wave 1, most of these tests assert stub contracts (`Err(Backend("not yet implemented"))`), not real protocol behavior. The test count is a process metric, not a quality metric. |
| 11 | `cargo clippy --workspace -- -D warnings` clean | **MET** | Per Wave 1a/1b/1c/1d, all audited crates carry `#![forbid(unsafe_code)]` and Wave 1 reports do not flag clippy warnings as a blocker. HANDOVER_PROMPT return condition #4 lists clippy clean; v0.5.0 ships with clippy passing (per CHANGELOG §v0.5.0). | None. Verify in CI; lint regressions are easily caught. |
| 12 | `cargo fmt --all --check` clean | **MET** | Per Wave 1 audits, no formatting inconsistencies flagged. HANDOVER_PROMPT return condition #5 lists fmt clean; v0.5.0 ships with fmt passing. | None. |

**Summary**: **2/12 MET** (#10, #12), **2/12 PARTIAL** (#3, #9), **8/12 NOT_MET** (#1, #2, #4, #5, #6, #7, #8, #11 is MET — corrected below).

Correction: re-counting — **MET**: #10, #11, #12 (3); **PARTIAL**: #3, #9 (2); **NOT_MET**: #1, #2, #4, #5, #6, #7, #8 (7). Total: **3 MET / 2 PARTIAL / 7 NOT_MET / 0 DEFERRED** out of 12.

---

## Per-ADR Compliance Audit

| ADR | Title | Status | Evidence |
|-----|-------|--------|----------|
| ADR-011 | AES-256 default, RC4 disabled | **PARTIAL** | EType enum has `Rc4Hmac` variant flagged "disabled by default, ADR-011" (Wave 1c, `adrian-kdc/src/lib.rs:40`); policy test `KdcError::Policy("rc4 disabled")` exists (`lib.rs:284-285`). But KDC AS-REQ/TGS-REQ handlers are stubs — no etype negotiation ever happens. No `audit-rc4` / `migrate-rc4` CLI subcommands exist. No `rc4_compat_mode` config knob. Real enforcement requires real AS-REQ handler. |
| ADR-015 | krbtgt HSM rotation | **PARTIAL** | `KrbtgtManager` (`krbtgt.rs:97`) implements `rotate()` with 30-day default interval + current+previous key handles (Wave 1c). `SoftwareHsm` backend is real with AES-256-GCM + HMAC-SHA1-96 (Wave 1c, 8 BEHAVIORAL_REAL tests). Gaps: (1) `KeyEntry.material` is `Vec<u8>` plain, not `Zeroizing` (crypto hygiene defect); (2) `SoftwareHsm::generate_key` is destructive — overwrites existing keys + resets kvno (breaks ADR-015 kvno monotonicity); (3) no auto-rotation tokio task (only manual `rotate()` call); (4) `enterprise-hsm` feature enables `cryptoki` dep but no `Pkcs11Hsm` impl ships — production HSM binding is a forward-declared interface. |
| ADR-019 | kpasswd | **NONCOMPLIANT** | Per Wave 1c, `KdcService::handle_kpasswd` (`lib.rs:99`) is a loud stub. The separate `KpasswdService::handle_kpasswd` (`kpasswd.rs:407`) is real for wire format but: (a) uses simplified length-prefixed binary, NOT RFC 3244 KRB-PRIV ASN.1 — no MIT krb5 interop; (b) sends new password in cleartext over the wire (`kpasswd.rs:138-139` doc — "production code must wrap with KRB-PRIV"); (c) `handle_kpasswd` calls `hsm.generate_key("krbtgt-mac", ...)` on EVERY request, and `SoftwareHsm::generate_key` is destructive — invalidates the pre-seeded MAC key → 3 of 5 ignored tests fail with `bad_integrity`; (d) uses PBKDF2-HMAC-SHA256 (200k iter) instead of bcrypt — defensible but not what ADR-019 specifies; (e) the two `handle_kpasswd` paths (KDC stub vs kpasswd module) are not wired together. |
| ADR-020 | gMSA | **PARTIAL** | Per Wave 1c, `adrian-kdc/src/gmsa.rs` is REAL — 6 BEHAVIORAL_REAL tests, cycle computation (30-day intervals), KDS root key in HSM, deterministic per (root_key, dn, cycle). But: KDS root key is stored in `SoftwareHsm` memory only (no FDB persistence, no rotation schedule), and no wiring exists to actually consume a gMSA password at service-startup time. ADR-020 §Decision says "automatic 30-day rotation" — only the cycle math is implemented, not the rotation scheduler. |
| ADR-021 | LDAP signing + channel binding | **NONCOMPLIANT** | Per Wave 1b, `adrian-directory-service` has no BER codec, no TCP listener, no Bind/Search handler. `Dsa::run` returns `NotImplemented` (`lib.rs:108-117`). The `ldap3` crate is a *client* library mistakenly listed as a server-crate runtime dep (Wave 1b category error). TLS channel binding (RFC 5929) is implemented in `adrian-ntlm-client` (Wave 1c, `lib.rs:398-420`) but is not wired into any LDAP server path. No `rustls` integration in `adrian-directory-service`. Signing/channel-binding policy is unenforceable because no LDAP server exists. |
| ADR-043 | drop SMB1 | **COMPLIANT** | Per Wave 1b/1d, `adrian-smb-core::Dialect` enum defines only SMB 2.0.2 / 2.1 / 3.0 / 3.0.2 / 3.1.1 — no SMB1 variant exists. `adrian-smb-server` per its doc refuses SMB1 negotiation. The ADR's concrete specification ("SMB1 refused entirely, no NetBIOS-over-TCP") is satisfied at the type-system level. Caveat: since `SmbServer::serve()` is a stub, the refusal is not yet runtime-enforced — but the architecture is correct. |
| ADR-070 | DRSUAPI replication | **NONCOMPLIANT** | Per Wave 1b, `adrian-drsuapi` is `STUB_LOUD`. Constants verified (`DrsExtFlag` 8/8, `DrsOption` 12/12, including `EXOP_REPL_SECRETS` 0x100). But `drs_bind` (`lib.rs:214-222`), `drs_get_nc_changes` (`lib.rs:236-245`), and 10 other opnums all return `Backend("not yet implemented")`. No `REPLENTIN_V3` / `REPLVALINF_V3` / `UPTODATE_VECTOR_V1_EXT` NDR encode/decode exists. Doc claim at `lib.rs:131-133` of "byte-identical REPLVALINF_V3" is aspirational, not code. Cannot interop with any Windows DC. |
| ADR-073 | FoundationDB | **PARTIAL** | Per Wave 1a, `adrian-storage-fdb` ships a dual code-path: default build wraps `InMemoryDirectoryStore` from testkit (20 BEHAVIORAL_REAL tests on the fallback path); `#[cfg(feature = "fdb")]` real `foundationdb` code path is **explicitly documented as not compile-tested** (`storage-fdb` line 778: "It is NOT compile-tested in this sandbox (libclang is not available)"). Same pattern for `identity-fdb` and `identity-ridpool`. Tuple-layer key encoding is real (verified by tests on fallback). Real FDB transactions have never been compiled, let alone run. Retry-on-conflict loop documented but absent. Tombstone handling has hardcoded placeholders (`nc_head_dnt = 1`, `when_deleted = 0`). |
| ADR-074 | tombstone lifetime | **PARTIAL** | Per Wave 1a, tombstones are stored in FDB subspace 0x07 (verified). `adrian-repl-core::ReplOperation::TombstoneGC` exists and is correctly NOT replicated (per ADR-074). `resolve_conflict` is implemented (4-tiebreak algorithm: version/timestamp/usn/invocation-id). But: `TombstoneGC` is never invoked by any scheduler; `repl-testkit::get_changes` ignores cursor (Wave 1a, returns all ops); `repl-testkit::apply_changes` skips conflict resolution; lingering-object detection is not implemented; tombstone-lifetime config knob is not exposed; the `TombstoneGC` op is in the enum but no producer emits it. |
| ADR-082 | MS-KILE PAC (9 buffers) | **NONCOMPLIANT** | Per Wave 1c, `PacBuilder` in `adrian-kdc/src/lib.rs:75-132` is `STUB_LOUD` (6 TODOs in lib.rs). `adrian-pac-validator::Pac::parse` returns `Malformed` always (Wave 1c). No code emits any of the 9 MS-KILE buffer types. `PAC_BUFFER_TICKET_CHECKSUM` (the silver-ticket mitigation per ADR-123) is not even defined as a constant. `rasn-kerberos` dep exists but is not consumed by `adrian-pac-validator`. |
| ADR-083 | PAC validation RPC | **NONCOMPLIANT** | Per Wave 1c, `validate_kdc_checksum` and `validate_service_checksum` both return `SignatureMismatch` always (Wave 1c, `adrian-pac-validator/src/lib.rs:75,82`). No `NetrLogonSamLogonEx` (legacy interop RPC) implementation exists. No local Ed25519 signature path. The "expired" error variant exists but is never returned. |
| ADR-085 | NTLM client only | **COMPLIANT** | Per Wave 1c, `adrian-ntlm-client` is REAL — NTLMv2 Type 1/2/3 message construction, NTOWFv1/NTOWFv2, NTProofStr, RFC 5929 channel binding, EPA EPHEMERAL flag, ~18 non-ignored tests + 5 ignored (the byte-level MS-NLMP §4.2 tests are `#[ignore]`'d, possibly stale markers per Wave 1c static analysis). No NTLM server-side code exists in the workspace (per ADR-085 §Decision — server-side dropped). Caveat: 5 ignored tests need runtime verification; `NtlmClient.password` not zeroized; `keyring` dep declared but unused. |
| ADR-086 | PtH defense | **NONCOMPLIANT** | ADR-086 §Decision requires: NTLM server-side drop (COMPLIANT — no server exists, per ADR-085), HSM-bound PEK for AD-interop NT hashes (NOT IMPLEMENTED — `adrian-hsm` has no PEK key type), `Zeroizing<Vec<u8>>` for credential material (PARTIAL — only `adrian-ntlm-client` uses `Zeroizing<[u8; 16]>` for NT hashes; `adrian-kdc` AES keys, `adrian-hsm` `KeyEntry.material`, `adrian-auth-core` `CredentialHandle::NtlmHash/KerberosTgt/OAuth2Token` are all plain `Vec`/`String`/`[u8;N]`), platform isolation (N/A — no platform adapters exist yet per Wave 1d). |
| ADR-105 | SMB 3.1.1 | **NONCOMPLIANT** | Per Wave 1d, `adrian-smb-server::SmbServer::serve()` returns `Protocol("not yet implemented")`. `adrian-smb-core::encode_negotiate`/`decode_negotiate` return `Malformed("not yet implemented")`. No `rasn` dep in `adrian-smb-core/Cargo.toml` despite doc claims (Wave 1d). No SHA-512 preauth integrity, no AES-256-GCM, no signing, no NEGOTIATE_CONTEXT_LIST, no TRANSFORM_HEADER. ADR-105 §Decision concrete specification (dialect list, transport, preauth integrity, encryption, signing, persistent handles) is entirely unimplemented. |
| ADR-110 | SID-to-UID | **COMPLIANT** | Per Wave 1a, `adrian-identity-core::uuid_to_uid` is REAL — implemented as `(uuid_to_u64(uuid) % (2^31 - 65536)) + 65536` per ADR-110 §Decision, with 4 BEHAVIORAL_MINIMAL tests covering determinism, range, distinct-UUID-distinct-UID, and PrincipalType variant matching. The leftover TODO on `uuid_to_uid` (line 184) is misleading — the function is implemented. Caveat: no collision-probability test, no UUID-nil edge case test. |
| ADR-122 | DCSync mitigation | **NONCOMPLIANT** | Per Wave 1b, `EXOP_REPL_SECRETS` constant value (0x100) is verified (`adrian-drsuapi/lib.rs:311-338`). But `drs_get_nc_changes` returns `Backend("not yet implemented")` — the ACL gating on `DS-Replication-Get-Changes-All` GUID (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) is not implemented. Per-Principal replication-audit hook is not implemented. Native Raft mode does not eliminate `EXOP_REPL_SECRETS` because the entire `DrSuapiReplicator` is a stub. ADR-122 §Decision's "per-call audit + HSM-bound break-glass" is not present. |
| ADR-123 | silver ticket | **NONCOMPLIANT** | Per Wave 1c, `Pac::parse` is a stub returning `Malformed` — no caller can ever reach the `validate_*` step. `PAC_BUFFER_TICKET_CHECKSUM` (the mandatory buffer per ADR-123 §Decision) is not defined as a constant, not emitted by `PacBuilder` (which is itself a stub), not validated by `adrian-pac-validator`. ADR-123 §Decision "services validate by default" requires a service-side `validate_service_checksum` call hook in `adrian-smb-server` / `adrian-directory-service` — none exists. ADR-123 is listed as Phase 2 (high-severity) per the roadmap, so NONCOMPLIANT at MVP is expected, but it is also referenced in the MVP-critical ADR list because the PAC_BUFFER_TICKET_CHECKSUM buffer type is supposed to ship in MVP per ADR-082. |

**Summary**: **3/16 COMPLIANT** (ADR-043, ADR-085, ADR-110), **7/16 PARTIAL** (ADR-011, ADR-015, ADR-020, ADR-073, ADR-074, ADR-082, ADR-122), **6/16 NONCOMPLIANT** (ADR-019, ADR-021, ADR-070, ADR-083, ADR-086, ADR-105, ADR-123 — note: 7 NONCOMPLIANT if you count ADR-123 separately from ADR-082). Re-count: 3 COMPLIANT / 6 PARTIAL / 7 NONCOMPLIANT = 16. Final tally: **3 COMPLIANT / 6 PARTIAL / 7 NONCOMPLIANT**.

---

## Roadmap Comparison

Per `finaldraft/06-implementation-roadmap.md`, Phase 1 MVP targets 6–12 months with ~13 engineers. Phase 2 v1 targets 12–18 months with ~28 engineers. Phase 3 v2 targets 12–18 months. Phase 4 v3 targets 6–12 months.

### Phase 1 (MVP) — current target

**Roadmap deliverables** (23 blocker-class ADRs across 8 capabilities):

| Capability | Roadmap ADRs | Delivered at v0.5.0 | Status |
|------------|-------------|---------------------|--------|
| Core Directory | ADR-002, ADR-073, ADR-076, ADR-074, ADR-070 | ADR-002 (linkID pairing in minimal_schema, verified); ADR-073 (PARTIAL — fallback only); ADR-074 (PARTIAL — tombstone storage only); ADR-076 (FSMO roles — NONE implemented; Schema Master / Domain Naming Master / PDC Emulator / RID Master / Infrastructure Master all absent); ADR-070 (NONCOMPLIANT — DRSUAPI stub) | ~25% delivered |
| KDC | ADR-011, ADR-015, ADR-082 | ADR-011 (PARTIAL — policy types only, no enforcement path); ADR-015 (PARTIAL — KrbtgtManager + SoftwareHsm real, but no auto-rotation scheduler, no PKCS#11 backend, no zeroization); ADR-082 (NONCOMPLIANT — PAC builder is a stub, no 9-buffer types) | ~30% delivered |
| Auth Provider | ADR-021, ADR-085/ADR-086 | ADR-021 (NONCOMPLIANT — no LDAP server); ADR-085 (COMPLIANT — NTLM client real); ADR-086 (NONCOMPLIANT — no PEK, no Zeroizing across the board) | ~33% delivered |
| Policy Engine | ADR-029, ADR-094 | ADR-029 (PARTIAL — compile_to_preg/authselect real; apply is silent stub); ADR-094 (NONCOMPLIANT — git-backed SYSVOL replication not implemented) | ~40% delivered |
| Cert Service | ADR-095 | ADR-095 (NONCOMPLIANT — AcmeServer router is empty) | 0% delivered |
| File Gateway | ADR-043, ADR-046, ADR-105 | ADR-043 (COMPLIANT — type-system only); ADR-046 (PARTIAL — IPP constants defined, PrintService router is empty); ADR-105 (NONCOMPLIANT — SmbServer::serve stub) | ~15% delivered |
| Client SDK | ADR-107 | ADR-107 (PARTIAL — SdkBuilder trait surface real, all 5 default impls are loud stubs) | ~25% delivered |
| Cross-Platform Parity | ADR-113 | ADR-113 (PARTIAL — policy format + authselect output is real, no daemon writes them, no `adrian-cli` end-to-end flow) | ~20% delivered |
| Security | ADR-064, ADR-122, ADR-065 | ADR-064 (Kerberoasting — covered transitively by ADR-011 PARTIAL); ADR-122 (NONCOMPLIANT); ADR-065 (golden ticket — covered transitively by ADR-015 PARTIAL) | ~20% delivered |
| Operations | ADR-057, ADR-058, ADR-063 (minimum-viable tooling) | ADR-057 (PARTIAL — MetricsRegistry real but zero producers); ADR-058 (PARTIAL — CRD YAML real, reconcile loop stub); ADR-063 (PARTIAL — clap CLI real, 8/10 subcommands silent Ok) | ~30% delivered |

**Phase 1 aggregate**: roughly **25% delivered** against the roadmap's blocker-class ADR set. The roadmap's optimistic 6-month MVP target is missed by ~3 months at current trajectory (Wave 5 complete, MVP not shippable); the realistic 12-month target is achievable only if Wave 6 dedicates ~8 weeks to SDK↔backend wiring and Wave 7 dedicates ~4 weeks to interop validation against Windows Server 2022.

### Phase 2 (v1) — future

The roadmap's Phase 2 expands to 64 high-severity ADRs across all 8 capabilities plus federation, full PKI, full GPO Preferences, full Client SDK on 3 platforms, monitoring/operations, and security hardening (silver ticket, sIDHistory, AdminSDHolder, supply chain). At v0.5.0, **none** of the Phase 2 ADRs have substantive code beyond what overlaps with Phase 1 (e.g., ADR-082 is listed as Phase 2 promoted but the underlying PAC builder is also required for MVP per ADR-082's MVP scope).

### Phase 3 (v2) and Phase 4 (v3) — future

Migration tools (ADR-126 through ADR-130), advanced federation, advanced PKI (key archival, OCSP, NDES/SCEP), advanced file features (DFS-N, ABE), multi-region — all out of scope. `adrian-migrate` is a stub (Wave 1d). `adrian-federation-shim` is a stub (Wave 1d). No code exists for any Phase 3+ deliverable.

### Roadmap trajectory assessment

**Behind by ~5–9 months** against the optimistic 6-month Phase 1 MVP target. The trajectory is consistent with the roadmap's realistic 12-month Phase 1 target **if and only if** Wave 6 closes the SDK↔backend integration gap (the single largest delivery risk per Wave 1d) and Wave 7 stands up the Windows Server 2022 interop lab (per TASKS.md T-030, currently unchecked). Without those two waves, the framework will stall at "structurally complete but functionally inert" indefinitely.

---

## v1.0 Effort Estimate

| Workstream | Effort (person-weeks) | Critical path? |
|------------|---------------------|----------------|
| KDC AS-REQ/TGS-REQ real impl (RFC 4120 §3.1/§3.3 + §5.4.1/§5.4.2) | 6 | **YES** — gates criterion #2, #6, #7, #8 |
| RFC 3961 §5.1 key derivation (nfold + DR-encrypt for Ke/Ki) | 1.5 | **YES** — gates KDC interop with MIT krb5/Windows |
| AES-256-CTS rewrite (RFC 2040 §6 / RFC 3962 §5.3) — fixes panic + interop | 1 | **YES** — gates KDC interop |
| PAC builder (9 buffers per ADR-082) + `Pac::parse` + `validate_*` per ADR-083 | 4 | **YES** — gates criterion #7, ADR-082, ADR-083, ADR-123 |
| DCE/RPC server endpoint (`DceRpcEndpoint::run`) + SPNEGO auth trailer | 3 | **YES** — gates DRSUAPI + WCCE interop |
| DRSUAPI DRSBind + DRSGetNCChanges + REPLVALINF_V3 NDR codec | 5 | **YES** — gates criterion #6 mixed-mode replication |
| LDAP BER codec + Bind/Search/Modify handlers + TCP listener (389/636) | 4 | **YES** — gates criterion #1 (join via LDAP) |
| Real Schema NC walker in `adrian-schema-compiler` | 2 | NO (Phase 2 OK, but blocks custom-schema validation) |
| openraft wiring: `RaftLogStore` + `RaftStateMachine` + `RaftNetwork` over FDB+TCP | 4 | **YES** — gates criterion #8 (<5s replication lag, no data loss) |
| Compile-verify real FDB path + retry-on-conflict + integration tests | 2 | **YES** — gates criterion #8 (10K writes/sec) |
| `adrian-acme-server` RFC 8555 endpoints (§7.1-§7.7) + `adrian-ca::CaService::issue` | 4 | **YES** — gates criterion #4 |
| `adrian-smb-core` PDU codecs via `rasn` | 3 | **YES** — gates criterion #5 |
| `adrian-smb-server` SMB 3.1.1 NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE/READ/WRITE/CLOSE/TRANSFORM | 6 | **YES** — gates criterion #5 |
| `adrian-smb-client` tree-connect + persistent handles | 3 | **YES** — gates criterion #5 |
| SDK wiring: `KerberosAuthModule`→KDC, `LdapDirectoryModule`→ldap3, `DeclarativePolicyModule`→PolicyExecutor::apply, `SmbFileModule`→SmbClient, `AcmeCertModule`→AcmeServer | 4 | **YES** — gates criteria #1-#5 |
| `PolicyExecutor::apply` real impl (write files to disk) | 1.5 | NO (Phase 2 OK if `synthesize` is enough for MVP demo) |
| `adrian-cli` end-to-end dispatch (convert silent-Ok subcommands to real calls) | 1 | NO (mechanical, parallelizable) |
| `adrian-monitor` producers in KDC + storage + repl + ridpool | 0.5 | NO (mechanical) |
| `adrian-test-harness` in-process FDB + directory-service + KDC fixtures | 1.5 | **YES** — gates every integration test |
| Windows Server 2022 interop lab + capture real wire fixtures (DRSUAPI/LDAP/Kerberos) | 2 | **YES** — gates criterion #6, #7 byte-identity |
| `adrian-kdc-interop` real test driver | 2 | **YES** — gates criterion #7 |
| `adrian-operator::AdrianOperator::run` reconcile loop wired to `kube::Client` | 3 | NO (Phase 2 OK; YAML generation works today) |
| Security hardening: `Zeroizing` everywhere, constant-time HMAC compare, HSM `find_or_create_key` | 1 | NO (security debt, but not on critical path) |
| `adrian-policy-cel` real CEL interpreter + `adrian-claims-engine` AD FS grammar | 3 | NO (Phase 2 — only needed for advanced policy) |
| Documentation: reword aspirational doc comments, ADR compliance matrix update | 0.5 | NO |
| **TOTAL critical-path work** | ~48 person-weeks | |
| **TOTAL including parallelizable non-critical work** | ~62 person-weeks | |
| **TOTAL with 30% buffer for interop surprises** | ~80 person-weeks | |

**With 13 engineers** (roadmap Phase 1 staffing), 80 person-weeks ÷ 13 = ~6 weeks of calendar time at 100% allocation — but the critical-path items are serial (KDC → SDK wiring → CLI → interop lab → integration tests), so the realistic calendar time is **~14–18 weeks (3.5–4.5 months)** to close the MVP gap. Adding Phase 2 v1 scope (64 high-severity ADRs) on top requires the roadmap's growth to ~28 engineers and adds another 12 months.

**Critical path**: KDC AS-REQ/TGS-REQ → PAC builder → SDK `KerberosAuthModule` wiring → CLI `adrian auth/kinit` → `adrian-test-harness` → Windows Server 2022 interop lab → `adrian-kdc-interop` byte-identity validation. Every other workstream can be parallelized against this spine.

---

## "Would I Deploy This?" Assessment

| Subsystem | Deploy to prod today? | Why |
|-----------|----------------------|-----|
| Storage layer | **NO** | Per Wave 1a: real FDB code path is explicitly not compile-tested (`storage-fdb` line 778 — "It is NOT compile-tested in this sandbox"). The dual code-path design (default build wraps `InMemoryDirectoryStore`) means `cargo test` passes without ever exercising the `foundationdb` crate. No retry-on-conflict loop. Tombstone handling has hardcoded placeholders. `identity-testkit` and `repl-testkit` ship with zero tests. **If a customer deployed v0.5.0 today, they would get the in-memory fallback path — data loss on process restart.** |
| Replication layer | **NO** | Per Wave 1b: `adrian-raft` commits entries without quorum (`lib.rs:862` — `apply_changes` advances `commit_index` to `last_log_index()` immediately after local append, no peers acked). Log is in-memory (`Vec<RaftLogEntry>` behind `tokio::sync::RwLock`) — crash = total data loss. `openraft` dependency is declared but never instantiated; a hand-rolled `ManualRaftReplicator` runs instead. `adrian-drsuapi` is `STUB_LOUD` — every opnum returns `Backend("not yet implemented")`. **Multi-node deployment would lose data on any partition or crash.** |
| KDC | **NO** | Per Wave 1c: `KdcService::handle_as_req`/`handle_tgs_req`/`handle_kpasswd` are loud stubs (`lib.rs:88,94,100`). AES-256-CTS panics on non-multiple-of-16 plaintext (`crypto.rs:131,181`). RFC 3961 §5.1 key derivation is skipped (uses base key directly as Ke/Ki — "structurally correct, not byte-compatible"). `PacBuilder` is a stub. Non-constant-time HMAC compare (`crypto.rs:230`). Key material not zeroized. **Cannot issue a TGT that MIT krb5 or Windows would accept.** |
| Policy engine | **NO** (for apply), **YES** (for synthesize-only use cases like generating PReg files offline) | Per Wave 1d: `synthesize` is REAL for Windows/macOS/Linux (PReg + GptTmpl.inf + Scripts.ini + GPP XML + MDM plist + authselect + firewalld + limits.conf.d). `adrian-policy-preg` is 5/5 production-ready (the most production-ready crate in the framework per Wave 1d). But `apply`/`rollback`/`verify` are silent stubs returning `Ok(... Uuid::nil() ...)`. No daemon writes the synthesised bytes to disk or SYSVOL. **An operator could use `adrian-policy-preg` as a standalone `Registry.pol` parser today; they cannot use the full policy pipeline.** |
| SDK + CLI | **NO** | Per Wave 1d: all 5 SDK default module impls (`KerberosAuthModule`, `LdapDirectoryModule`, `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`) return loud-stub errors. `AdrianClient::join` returns `Err(SdkError::NotJoined)`. CLI's 8 of 10 subcommands silently `Ok(())` after parsing args (only `join` and `policy apply` surface SDK errors). The SDK declares `ldap3`/`rustls`/`adrian-smb-client`/`adrian-auth-core` as deps but never uses them — dead deps. The FFI bindings (C/JNI/Swift/Python) compile but invoke only loud-stub methods. **A customer running `adrian join --domain adrian.dev` gets `Error: not joined` and exits non-zero.** |
| Operator (deployment) | **NO** (as an operator), **YES** (as a YAML generator) | Per Wave 1d: `crd_definition()` / `generate_statefulset()` / `generate_helm_chart()` produce valid JSON/YAML (12 BEHAVIORAL_REAL tests). But `AdrianOperator::run()` returns `Err(Reconcile("not yet implemented"))` without ever constructing a `kube::Client`. The `kube` + `k8s-openapi` deps are dead weight. The generated StatefulSet references `ghcr.io/adrian/dc:0.1.0` which does not exist. **An operator could `helm template` the chart today for documentation purposes; they cannot run a working controller.** |

---

## Recommendations for v0.6.0

Prioritized to close the MVP gap with minimum effort and maximum leverage:

### P0 — Critical-path items (must land in v0.6.0 to ship MVP)

1. **Implement KDC AS-REQ/TGS-REQ handlers** (RFC 4120 §3.1/§3.3 + §5.4.1/§5.4.2). ~6 person-weeks. **Single highest-leverage item** — unblocks criteria #2, #6, #7, #8.
2. **Implement RFC 3961 §5.1 key derivation** (`nfold` + DR-encrypt for Ke/Ki). ~1.5 person-weeks. Without this, no MIT krb5/Windows interop even if AS-REQ is implemented.
3. **Rewrite AES-256-CTS** against RFC 2040 §6 / RFC 3962 §5.3. ~1 person-week. Fixes both the panic and the interop failure. Add RFC 3962 §5.3 official test vectors.
4. **Implement `PacBuilder` (9 buffers per ADR-082) + `Pac::parse` + `validate_kdc_checksum`/`validate_service_checksum`** in `adrian-pac-validator`. ~4 person-weeks. Unblocks ADR-082, ADR-083, ADR-123 and criterion #7.
5. **Implement DCE/RPC server endpoint (`DceRpcEndpoint::run`)** — `tokio::net::TcpListener` + accept loop + Bind/Request dispatch. ~1.5 person-weeks. Unblocks all DRSUAPI/SAMR/LSARPC/Netlogon/WCCE interop.
6. **Implement LDAP BER codec + Bind/Search handlers + TCP listener on 389/636.** ~4 person-weeks. Move `ldap3` from runtime to dev-deps; add `rasn`-based BER codec. Unblocks criterion #1 (join via LDAP).
7. **Implement DRSUAPI DRSBind + DRSGetNCChanges + REPLVALINF_V3 NDR codec.** ~5 person-weeks. Unblocks criterion #6 (mixed-mode replication).
8. **Wire openraft `RaftLogStore` over FDB + `RaftStateMachine` + `RaftNetwork` over TCP; replace `ManualRaftReplicator`.** ~4 person-weeks. Fixes commit-without-quorum bug + in-memory-log data-loss risk.
9. **Compile-verify real FDB code path** (`cargo check --features fdb` with libclang in CI). ~1 person-week (assuming few compile errors). Fixes the single highest-risk item per Wave 1a.
10. **Wire `adrian-sdk` default module impls to real backends** — KerberosAuthModule→KDC, LdapDirectoryModule→ldap3→directory-service, DeclarativePolicyModule→PolicyExecutor::apply, SmbFileModule→SmbClient, AcmeCertModule→AcmeServer. ~4 person-weeks. Unblocks criteria #1-#5.
11. **Build `adrian-test-harness`** — in-process FDB cluster + directory-service + KDC fixtures. ~1.5 person-weeks. Prerequisite for every integration test.
12. **Stand up Windows Server 2022 interop lab + capture wire fixtures** (DRSUAPI/LDAP/Kerberos byte captures as test fixtures). ~2 person-weeks. Unblocks criterion #6, #7.
13. **Implement `adrian-kdc-interop` real test driver** — container-based, byte-identity PAC comparison, AS-REQ/TGS-REQ wire-format comparison. ~2 person-weeks. Unblocks criterion #7.
14. **Implement `adrian-acme-server` RFC 8555 endpoints + `adrian-ca::CaService::issue`.** ~4 person-weeks. Unblocks criterion #4.
15. **Implement `adrian-smb-core` PDU codecs + `adrian-smb-server` SMB 3.1.1 + `adrian-smb-client`.** ~12 person-weeks total. Unblocks criterion #5. Long pole — start early.

### P1 — Should land in v0.6.0 but parallelizable

16. **Implement `PolicyExecutor::apply`** that writes synthesised files to disk. ~1.5 person-weeks.
17. **Convert 8 silent-Ok CLI subcommands to real dispatch** (or at least loud-stub errors). ~0.5 person-week.
18. **Wire `adrian-monitor` producers** into KDC, storage-fdb, repl-core, ridpool. ~0.5 person-week.
19. **Security hardening**: wrap all key material in `Zeroizing<...>` (KDC AES keys, HSM `KeyEntry.material`, auth-core `CredentialHandle` fields, NTLM `NtlmClient.password`); replace `expected_tag != tag` with `subtle::ConstantTimeEq`; add `Hsm::find_or_create_key` non-destructive method. ~1 person-week.
20. **Implement `adrian-operator::AdrianOperator::run` reconcile loop** OR split the crate into `adrian-operator-crds` (YAML generation, usable today) + `adrian-operator-controller` (reconcile loop, deferred). ~0.5 person-week for the split, ~3 person-weeks for the real loop.

### P2 — Defer to v0.7.0+ (Phase 2)

21. Real Schema NC walker (`adrian-schema-compiler::compile_from_directory`).
22. `adrian-policy-cel` real CEL interpreter.
23. `adrian-claims-engine` AD FS claim rule grammar.
24. `adrian-federation-shim` real Keycloak integration.
25. `adrian-migrate` real migration tooling.
26. `adrian-print-service` real IPP.
27. Auto-rotation scheduler for krbtgt (tokio task).
28. Real PKCS#11 HSM backend (`Pkcs11Hsm` impl).
29. RFC 3244 KRB-PRIV wrapping for kpasswd (currently sends password in cleartext).
30. Wire-capture regression test fixtures for all PDUs.

### P3 — Doc hygiene (low effort, high value)

31. Reword aspirational doc comments that overstate implementation status (per Wave 1b: `drsuapi` REPLVALINF_V3 claim, `directory-service` RFC 4510-4519 server claim, `raft` "openraft-based" claim).
32. Update TASKS.md — T-001 through T-029 are marked `[x]` but Wave 1 found the underlying crates are loud stubs. Either re-open these tasks with a "stub-only" annotation, or add new tasks T-001a through T-029a for the real implementations.
33. Update CHANGELOG.md to v0.6.0 once P0 items 1-13 land.

### Staffing recommendation

With 13 engineers (roadmap Phase 1 staffing) and ~80 person-weeks of P0+P1 work, the calendar time to v0.6.0 MVP is **~14–18 weeks (3.5–4.5 months)** assuming:
- 3 engineers on KDC (AS-REQ/TGS-REQ + key derivation + AES-CTS + PAC builder) — the long pole.
- 2 engineers on DRSUAPI + DCE/RPC server endpoint + LDAP BER codec.
- 2 engineers on openraft wiring + FDB compile-verify.
- 2 engineers on SMB (server + client + core codecs).
- 1 engineer on ACME + CA.
- 1 engineer on SDK wiring + CLI dispatch.
- 1 engineer on test-harness + interop lab + kdc-interop.
- 1 engineer on monitor producers + security hardening + doc hygiene.

If staffing is below 13, the critical path stretches proportionally. If only 5 engineers are available, v0.6.0 MVP slips to ~9-10 months — close to the roadmap's realistic 12-month Phase 1 target.

---

**Audit complete.** 12 MVP criteria assessed, 16 MVP-critical ADRs audited, 4 phases compared against roadmap, 6 subsystems assessed for production-readiness, ~80 person-weeks of remaining work estimated. No code modified. All findings cross-referenced to Wave 1a/1b/1c/1d by name.
