# Adrian Framework — Production Readiness Evaluation

**Date**: 2026-08-13
**Repo HEAD**: `6b2a495` on `main` (post-Wave 2 of this evaluation)
**Version audited**: v0.5.0 (602 tests passing, 16 ignored, 0 failed)
**Method**: 7-agent wave-based audit (4 per-crate auditors in Wave 1, 3 cross-cutting analysts in Wave 2). Findings in `eval/wave1{a,b,c,d}-*.md` and `eval/wave2{a,b,c}-*.md` (~2,183 lines of structured analysis).

---

## TL;DR

**Adrian v0.5.0 is a research-grade scaffold, not a deployable product.** The workspace compiles cleanly, all 602 tests pass, clippy is clean, and the ADR/catalog/spec documentation set is excellent. But of the 47 Rust crates, **only ~10 contain production-grade real implementations** (storage-core, storage-testkit, sid, identity-ridpool, dcerpc NDR primitives, hsm trait + SoftwareHsm, policy-preg, policy-core's compile_to_preg, schema-compiler's validate_object, raft's RPC *receivers*). The remaining ~37 crates are either loud stubs (typed errors that surface "not yet implemented") or silent stubs (functions that return `Ok(())` without doing anything). The Phase 1 MVP success criteria are **2 MET / 3 PARTIAL / 7 NOT_MET** out of 12.

**Gap-to-production rating: 3.5 / 10.**

| Dimension | Rating | Headline |
|-----------|--------|----------|
| Code quality & scaffolding | 8/10 | Clean, `#![forbid(unsafe_code)]` everywhere, 602 tests pass, clippy clean |
| Documentation & ADRs | 9/10 | 130 ADRs, 72 KB files, 12 specs, 12 workshop decisions, excellent cross-referencing |
| Storage & identity layer | 6/10 | Real `InMemoryDirectoryStore` fallback; real FDB path never compiled (no libclang) |
| Protocol layer (DRSUAPI/LDAP/Raft) | 2/10 | drsuapi + directory-service are loud stubs; raft commits without quorum |
| KDC + crypto | 2/10 | `handle_as_req`/`handle_tgs_req` are loud stubs; AES-256-CTS panics on partial blocks; PAC validator entirely stub |
| App/ops layer (SDK/CLI/monitor/operator) | 3/10 | SDK wiring all returns "not yet wired"; CLI has 8 silent-Ok subcommands; operator reconcile is stub |
| Security posture | 3/10 | 1/13 AD-baseline controls enforced (PtH by NTLM absence); kpasswd sends password in cleartext |
| Ops readiness (CI/Docker/observability) | 1/10 | No `.github/workflows/`, no Dockerfile, no health probes, no benchmarks, 19 tracing calls total in workspace |
| MVP success criteria | 2/12 MET | Only `cargo test ≥578` and `clippy clean` are MET; the 7 user-facing criteria (join/auth/policy/cert/file/interop/PAC) are NOT_MET |
| **Overall** | **3.5/10** | **Not production-ready. Estimate 60-80 person-weeks to v1.0.** |

---

## 1. Where We Are — Codebase Snapshot

### 1.1 Workspace composition

- **47 crates** across 5 dependency layers (L0 foundation → L4 ops)
- **602 tests pass / 0 fail / 16 ignored** in 3.12s
- **207 → 113 TODO markers** (94 stubs replaced across Waves 0-5)
- **`#![forbid(unsafe_code)]`** in every crate (verified by `grep -rn 'unsafe'` returning zero hits in non-FFI code; only `adrian-sdk-c` uses `#![deny(unsafe_code)]` with per-function `#[allow(unsafe_code)]` for FFI)
- **~15,000 lines of Rust** in `src/` directories (rough estimate)

### 1.2 Test quality breakdown (per Wave 2b)

| Quality class | Count | % | What it means |
|---------------|------:|---:|---------------|
| BEHAVIORAL_REAL | ~300 | 50% | Real byte-exact tests of dcerpc NDR/PDU, sid SDDL/binary, storage-testkit transactions, raft vote/append idempotency, hsm crypto round-trips, policy-preg MS-GPREG, ntlm-client Type 1/2/3 |
| BEHAVIORAL_MINIMAL | ~150 | 25% | Display formatting, serde round-trips, constructor equivalence — guards against type regressions but no behavior |
| STRUCTURAL_ONLY | ~150 | 25% | "Stub returns documented typed error variant" assertions (e.g. `handle_as_req_returns_storage_not_implemented`) |
| IGNORED | 16 | — | 13 blocked on real crypto bugs (AES-CTS, NTLM NT-hash); 3 empty placeholders for FDB integration tests |

### 1.3 Per-crate status matrix (consolidated from Wave 1a-d)

Status legend: ✅ REAL_COMPLETE · 🟡 REAL_PARTIAL · 🔴 REAL_WITH_KNOWN_BUGS · 🟠 STUB_LOUD (returns typed error) · ⚫ STUB_SILENT (returns Ok without doing work)

#### Layer 0 — Foundation (4 crates)

| Crate | Status | Tests | TODOs | Readiness |
|-------|--------|------:|------:|----------:|
| adrian-storage-core | ✅ | 11 | 2 | 4/5 |
| adrian-sid | ✅ | 35 | 0 | 5/5 ★ |
| adrian-schema-traits | ✅ | 2 | 3 | 4/5 |
| adrian-repl-core | ✅ | 6 | 0 | 4/5 |

#### Layer 1 — Abstractions (5 crates)

| Crate | Status | Tests | TODOs | Readiness |
|-------|--------|------:|------:|----------:|
| adrian-storage-fdb | 🟡 (fallback real; FDB path never compiled) | 17 | 0 | 3/5 |
| adrian-identity-core | ✅ | 4 | 0 | 3/5 |
| adrian-identity-fdb | 🟡 (fallback real) | 21 | 0 | 3/5 |
| adrian-identity-ridpool | ✅ | 35 | 0 | 4/5 |
| adrian-identity-testkit | ✅ | **0** | 0 | 3/5 |

#### Layer 2 — Domain implementations (17 crates)

| Crate | Status | Tests | TODOs | Readiness |
|-------|--------|------:|------:|----------:|
| adrian-storage-testkit | ✅ | 24 | 0 | 4/5 |
| adrian-dcerpc | ✅ (NDR + bind/bind_ack real; no server) | 49 | 0 | 3/5 |
| adrian-drsuapi | 🟠 (REPLENTIN_V3 codec real; handlers stub) | 13 | 18 | 2/5 |
| adrian-raft | 🔴 (RPC receivers real; commits without quorum) | 35 | 0 | 2/5 |
| adrian-directory-service | 🟠 (no BER codec, no TCP listener) | ? | 12 | 1/5 |
| adrian-schema-compiler | 🟡 (validate_object real; compile_from_directory hardcoded) | 22 | 0 | 3/5 |
| adrian-repl-testkit | 🟡 | **0** | 4 | 2/5 |
| adrian-kdc | 🔴 (crypto primitives real but buggy; KdcService loud stub) | 39 (8 ignored) | 6 | 2/5 |
| adrian-kdc-interop | 🟠 | 7 | 1 | 1/5 |
| adrian-hsm | ✅ (SoftwareHsm real; no PKCS#11 backend) | ~17 | 1 | 3/5 |
| adrian-ntlm-client | 🟡 (wire format real; NT-hash bug disputed) | 28 (5 ignored) | 0 | 3/5 |
| adrian-pac-validator | 🟠 | 7 | 2 | 1/5 |
| adrian-auth-core | 🟡 (trait real; no backends) | 7 | 0 | 2/5 |
| adrian-policy-core | ✅ (compile_to_preg real) | 21 | 0 | 4/5 |
| adrian-policy-preg | ✅ | 12 | 0 | 5/5 ★ |
| adrian-policy-executor | 🟡 (synthesize real; apply/rollback stub) | 20 | 0 | 3/5 |
| adrian-admx-compiler | 🟡 (parse real; legacy compile lossy) | 15 | 0 | 3/5 |

#### Layer 3 — Services (10 crates)

| Crate | Status | Tests | TODOs | Readiness |
|-------|--------|------:|------:|----------:|
| adrian-ca | 🟠 | ? | 5 | 1/5 |
| adrian-acme-server | ⚫ (empty axum router) | ? | 5 | 1/5 |
| adrian-wcce-bridge | 🟠 | ? | 4 | 1/5 |
| adrian-smb-server | ⚫ (no PDU codec, no listener) | ? | 2 | 1/5 |
| adrian-smb-client | ⚫ | ? | 3 | 1/5 |
| adrian-smb-core | 🟠 (encode/decode return errors) | ? | 2 | 1/5 |
| adrian-print-service | 🟠 | ? | 2 | 1/5 |
| adrian-federation-shim | 🟠 | ? | 4 | 1/5 |
| adrian-policy-cel | 🟠 | ? | 3 | 1/5 |
| adrian-claims-engine | 🟠 | ? | 3 | 1/5 |

#### Layer 4 — Ops + SDK (11 crates)

| Crate | Status | Tests | TODOs | Readiness |
|-------|--------|------:|------:|----------:|
| adrian-sdk | 🟠 (5 module impls return "not yet wired") | 20 | 2 | 2/5 |
| adrian-sdk-c | 🟡 (FFI plumbing real; underlying SDK stub) | 8 | 0 | 3/5 |
| adrian-sdk-jni | 🟠 | ? | 1 | 1/5 |
| adrian-sdk-swift | 🟠 | ? | 0 | 1/5 |
| adrian-sdk-python | 🟠 | ? | 1 | 1/5 |
| adrian-cli | ⚫ (8 silent-Ok subcommands; only Join + Policy Apply dispatch) | 6 | 1 | 2/5 |
| adrian-monitor | 🟡 (MetricsRegistry real; zero call sites) | 8 | 0 | 2/5 |
| adrian-operator | 🟡 (CRD/Helm YAML real; reconcile stub) | 11 | 0 | 3/5 |
| adrian-gpo-translate | 🟠 | ? | 1 | 1/5 |
| adrian-migrate | 🟠 | ? | 1 | 1/5 |
| adrian-test-harness | ⚫ | **0** | 3 | 1/5 |

**Layer rollup**:
- L0: avg **4.0/5** (solid foundation)
- L1: avg **3.2/5** (testable but FDB path unverifiable)
- L2: avg **2.5/5** (real codecs, stub handlers, buggy crypto)
- L3: avg **1.0/5** (everything is a stub)
- L4: avg **1.8/5** (scaffold only, no integration)

---

## 2. Honest Assessment — The Five Hardest Truths

These are the findings the CHANGELOG soft-pedals but the audit confirms.

### 2.1 The KDC cannot issue a TGT

`KdcService::handle_as_req` / `handle_tgs_req` / `handle_kpasswd` at `adrian-kdc/src/lib.rs:88, 94, 100` are **loud stubs returning `KdcError::Storage("not yet implemented")`**. The CHANGELOG's Wave 3a entry claims "Real KDC AS-REQ/AS-REP + TGS-REQ/TGS-REP" but no such code exists — only the crypto *primitives* (PBKDF2, HMAC-SHA1-96, AES-256 block cipher) were implemented, and those have bugs.

Even if the handlers existed, no MIT krb5 or Windows client could interop because:
- RFC 3961 §5.1 key derivation (`nfold` + DR-encrypt) is **intentionally skipped** — the code uses the base key directly as Ke/Ki (documented as "structurally correct, not byte-compatible" at `crypto.rs:18-30`)
- AES-256-CTS **panics** on plaintexts not a multiple of 16 bytes (out-of-bounds slice at `crypto.rs:131, 181`)

### 2.2 The 13 ignored tests are mostly mis-categorized

The CHANGELOG claims 13 ignored tests cover "two known crypto bugs". The audit found:

| Bug | CHANGELOG claim | Audit finding |
|-----|----------------|---------------|
| AES-256-CTS swap | "non-trivial swap that current impl gets wrong" | **Real and worse**: runtime panic (out-of-bounds slice). Not just interop failure — robustness/DoS issue. NOT a MAC bypass. |
| NTLMv2 NT hash | "produces different byte sequence than MS-NLMP reference" | **Likely stale**: code at `lib.rs:259-281, 340-356` is structurally textbook-correct per MS-NLMP §3.3.1-2. Cannot verify without running tests. 2 of 5 ignored tests would likely pass if un-ignored. |
| kpasswd auth flow | "depends on AES-256-CTS bug" | **Misattributed**: kpasswd never invokes AES-CTS. Real bug is `SoftwareHsm::generate_key` being destructive — `handle_kpasswd` calls `generate_key("krbtgt-mac", ...)` on every request, overwriting the test's pre-seeded key. 2 of 5 ignored tests would actually pass today. |

### 2.3 The "real FDB code path" has never been compiled

Every "production" crate (`adrian-storage-fdb`, `adrian-identity-fdb`, `adrian-identity-ridpool`) wraps `InMemoryDirectoryStore` from the testkit in the default build. The real `foundationdb` API calls in the `real_fdb` submodule are gated behind the `fdb` feature flag, which **requires libclang for bindgen** — unavailable in the dev sandbox. CI has no `cargo check --features fdb` step. All 156 storage-layer tests run against the in-memory fallback.

### 2.4 The SDK doesn't integrate anything

All five `AdrianSdk` module impls return documented "not yet wired to <crate>" errors:

```
KerberosAuthModule::authenticate_kerberos → "not yet wired to adrian-kdc (ADR-108)"
LdapDirectoryModule::search → "not yet wired to adrian-directory-service"
DeclarativePolicyModule::apply → "not yet wired to adrian-policy-executor"
SmbFileModule::mount_share → "not yet wired to adrian-smb-client (ADR-106)"
AcmeCertModule::enroll → "not yet wired to adrian-acme-server (ADR-095/097)"
```

The CLI's `join` surfaces the SDK error (honest), but `gpupdate`, `klist`, `kinit`, `auth`, `cert`, `file`, `migrate`, `gpo-translate`, `kdc rotate-krbtgt` all **silently return `Ok(())`** after `tracing::info!` — pretending success without doing work. This is worse than a loud stub.

### 2.5 Security controls are documented but not enforced

Of 13 AD-baseline security controls audited (Wave 2a), **only 1 is enforced**: pass-the-hash defense, by virtue of having no NTLM server-side code at all. Every other control (RC4 refusal, LDAP signing/channel binding, SMB1 refusal, DCSync audit, silver ticket mitigation, SID history filtering, Kerberoasting mitigation, HSM-bound krbtgt with auto-rotation) is specified in ADR text and referenced in code comments but **not enforced in code** — because every enforcement point is a loud stub.

The good news: zero live network attack surface today (no `TcpListener::bind` anywhere). The bad news: v0.6.0 stubs risk being filled in *without* the security controls landing first.

Additional security defects found:
- **Non-constant-time HMAC verification** at `crypto.rs:230` (`if expected_tag != tag` short-circuits on first differing byte → timing attack)
- **Key material not zeroized** across 4 crates (KDC crypto, HSM, NTLM client, auth-core — inconsistent hygiene; only NTLM client's NT hash uses `Zeroizing`)
- **kpasswd sends new password in cleartext** at `kpasswd.rs:137-139` — not wrapped in KRB-PRIV per RFC 4120 §3.5
- **kpasswd has no replay cache** — authenticator replay would succeed
- **gMSA KDF uses HMAC-SHA1-96 truncation** (12 bytes) instead of full HMAC-SHA1 (20 bytes) per SP800-108 §5.1

---

## 3. MVP Success Criteria — Gap Analysis

From the original `HANDOVER_PROMPT.md`:

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Linux host joins via `adrian-cli join` | ❌ NOT_MET | `AdrianClient::join` returns `Err(SdkError::NotJoined)` |
| 2 | Host authenticates via Kerberos | ❌ NOT_MET | `handle_as_req` is a loud stub |
| 3 | Host applies policy via authselect | 🟡 PARTIAL | `synthesize` works; `apply` is silent stub |
| 4 | Host requests cert via ACME | ❌ NOT_MET | `AcmeServer::router()` returns empty router |
| 5 | Host mounts SMB share | ❌ NOT_MET | `SmbServer::serve` returns NotImplemented |
| 6 | Mixed-mode with Windows Server 2022 | ❌ NOT_MET | T-030, T-031 unchecked; no interop lab |
| 7 | PAC byte-identity validated | ❌ NOT_MET | PAC validator is entirely stub |
| 8 | Perf: 5K AS-REQ/s, 10K writes/s, <5s lag | ❌ NOT_MET | No benchmarks; PBKDF2 alone takes 80ms (12 AS-REQ/s ceiling) |
| 9 | Security mitigations active | 🟡 PARTIAL | Only PtH by NTLM absence; 1/13 controls enforced |
| 10 | `cargo test` ≥ 578 | ✅ MET | 602 tests pass |
| 11 | `cargo clippy -- -D warnings` clean | ✅ MET | Clean |
| 12 | `cargo fmt --check` clean | ✅ MET | Clean |

**Result: 3 MET / 2 PARTIAL / 7 NOT_MET** (the 3 MET are all mechanical quality gates, not functional criteria)

---

## 4. ADR Compliance Audit

| ADR | Title | Status |
|-----|-------|--------|
| ADR-011 | AES-256 default, RC4 disabled | 🟡 PARTIAL (etype constants exist; no enforcement point) |
| ADR-015 | krbtgt HSM rotation | 🟡 PARTIAL (manager real; auto-rotation not scheduled; no PKCS#11 backend) |
| ADR-019 | kpasswd | 🔴 NONCOMPLIANT (cleartext password, no replay cache) |
| ADR-020 | gMSA | 🟡 PARTIAL (KDF wrong — uses HMAC-SHA1-96 truncation) |
| ADR-021 | LDAP signing + channel binding | 🔴 NONCOMPLIANT (no LDAP server) |
| ADR-043 | drop SMB1 | ✅ COMPLIANT (no SMB server at all) |
| ADR-070 | DRSUAPI | 🔴 NONCOMPLIANT (handlers stub) |
| ADR-073 | FoundationDB | 🟡 PARTIAL (real path never compiled) |
| ADR-074 | tombstone lifetime | 🟡 PARTIAL (tombstone keys real; GC task not implemented) |
| ADR-082 | MS-KILE PAC | 🔴 NONCOMPLIANT (PacBuilder is stub) |
| ADR-083 | PAC validation RPC | 🔴 NONCOMPLIANT (validator is stub) |
| ADR-085 | NTLM client only | ✅ COMPLIANT |
| ADR-086 | PtH defense | 🟡 PARTIAL (no NTLM server — enforced by absence) |
| ADR-105 | SMB 3.1.1 | 🔴 NONCOMPLIANT (no SMB server) |
| ADR-110 | SID-to-UID | ✅ COMPLIANT |
| ADR-122 | DCSync mitigation | 🔴 NONCOMPLIANT (no handler, no audit event emission) |
| ADR-123 | silver ticket | 🔴 NONCOMPLIANT (PAC_BUFFER_TICKET_CHECKSUM not implemented) |

**Tally: 3 COMPLIANT / 6 PARTIAL / 8 NONCOMPLIANT** (of 17 MVP-critical ADRs)

---

## 5. Ops Readiness — The Weakest Dimension

Wave 2b found ops readiness to be **1/5**. Specific gaps:

| Capability | Status |
|------------|--------|
| CI/CD pipeline (`.github/workflows/`) | ❌ No directory exists |
| Dockerfile / container image | ❌ None |
| Health/readiness probes | ❌ Not in StatefulSet |
| `tracing::` calls in hot paths | ❌ 19 total in workspace, **zero** in KDC/storage hot paths |
| `MetricsRegistry` producers | ❌ Zero call sites outside `adrian-monitor` tests |
| `cargo bench` / criterion | ❌ Not set up |
| Backup/restore | ❌ No code despite 3 ADRs (010, 034, 059) |
| Runbooks | ❌ None |
| Config schema | ❌ No `config.toml`, no env-var overrides |
| Request IDs / correlation | ❌ None |
| README accuracy | ❌ Still describes repo as "research deliverable" with "47 stubs" |
| `cargo audit` | ❌ Not configured |

---

## 6. Effort Estimate to v1.0

Wave 2c estimates **60-80 person-weeks** of focused engineering to close the MVP gap, with a 3-workstream critical path:

### Critical path (must be sequential)

1. **KDC AS-REQ/TGS-REQ real impl** (~10 person-weeks)
   - RFC 4120 §3.1/§3.3 handlers (~500-1000 LoC)
   - RFC 3961 §5.1 `nfold` + DR-encrypt key derivation (~150 LoC) — **blocks all Kerberos interop**
   - Rewrite `aes256_cts_encrypt`/`decrypt` per RFC 2040 §6 / RFC 3962 §5.3 (fixes panic + interop)
   - 9-buffer `PacBuilder` per ADR-082
   - Wire `KerberosAuthModule` to drive an AS-REQ

2. **DRSUAPI NDR codec + DRSBind handler** (~6 person-weeks)
   - Real NDR codec for REPLENTIN_V3 wire bytes (current impl only round-trips with itself)
   - DRSBind handler that establishes replication context
   - DRSGetNCChanges that returns real directory objects
   - ACL check on EXOP_REPL_SECRETS (DCSync mitigation)

3. **Interop test lab** (~4 person-weeks)
   - `adrian-test-harness` with in-process FDB + directory-service + KDC fixtures
   - Windows Server 2022 lab VM with `tcpdump` capture
   - MIT krb5 + Samba containers for cross-realm tests
   - `adrian-kdc-interop` test driver with PAC byte-identity fixtures

### Parallel workstreams (can run concurrently)

- LDAP server (BER codec + TCP listener + Bind/Search/Modify handlers) — ~6 person-weeks
- SMB 3.1.1 server (PDU codecs + Negotiate/SessionSetup/Create/Read/Write/Close) — ~12 person-weeks
- ACME server (RFC 8555 §7.1-§7.7) + CA service — ~4 person-weeks
- Real FDB integration tests (libclang + FDB cluster in CI) — ~2 person-weeks
- CI/CD pipeline (`.github/workflows/`, Dockerfile, clippy/fmt/audit gates) — ~1 person-week
- Observability (wire `MetricsRegistry` producers in KDC/storage; add `tracing` spans) — ~2 person-weeks
- Operator reconcile loop (real `kube::Client`, controller-runtime pattern) — ~4 person-weeks
- CLI: convert 8 silent-Ok subcommands to real dispatch — ~3 person-weeks
- Security hardening (constant-time HMAC, key zeroize, kpasswd KRB-PRIV wrapping, replay cache) — ~2 person-weeks

### Calendar estimate

- **Optimistic** (13 engineers, full-time, no integration friction): 14-18 weeks
- **Realistic** (8 engineers, allowing for integration testing + interop debugging): 24-30 weeks (~6-7 months)
- **Pessimistic** (5 engineers, includes crypto rewrites + Windows interop surprises): 40-50 weeks (~9-12 months)

---

## 7. "Would I Deploy This?" Assessment

For each major subsystem, the honest answer:

| Subsystem | Deploy today? | Why |
|-----------|--------------|-----|
| Storage layer (testkit fallback) | ❌ NO | Real FDB path never compiled; no backup/restore; no benchmarks |
| Replication layer | ❌ NO | Raft commits without quorum (data loss on partition); drsuapi handlers stub |
| KDC | ❌ NO | Cannot issue TGTs; AES-CTS panics; PAC validator stub |
| LDAP directory service | ❌ NO | No BER codec, no TCP listener |
| SMB server | ❌ NO | No PDU codec, no listener |
| ACME + CA | ❌ NO | Empty router, CA service stub |
| Policy engine (synthesize only) | ✅ YES | `LinuxPolicyExecutor::synthesize` produces real file bytes — usable as a standalone PReg/plist generator |
| PReg parser | ✅ YES | `adrian-policy-preg` is real and tested — usable standalone |
| SID parser | ✅ YES | `adrian-sid` is real and tested — usable standalone |
| Kubernetes operator (YAML gen only) | ✅ YES | CRD + StatefulSet + Helm YAML generation works; reconcile loop is stub but YAML is deployable as documentation |
| SDK + CLI | ❌ NO | All 5 module impls return "not yet wired"; CLI has 8 silent-Ok subcommands |
| Monitor | ❌ NO | MetricsRegistry real but has zero call sites; nothing produces metrics |
| Operator (controller) | ❌ NO | `AdrianOperator::run()` returns NotImplemented |

**Bottom line**: Of 12 subsystems, only 4 are deployable today, and 3 of those are standalone utilities (PReg parser, SID parser, YAML generator) — not the integrated Adrian platform.

---

## 8. Recommendations for v0.6.0 (Prioritized)

### P0 — Must land before any "AS-REQ works" claim

1. **Fix AES-256-CTS** — rewrite per RFC 2040 §6 to fix panic + interop. ~1 person-week.
2. **Implement RFC 3961 §5.1 key derivation** — `nfold` + DR-encrypt. ~1 person-week. Blocks all Kerberos interop.
3. **Implement KDC AS-REQ/TGS-REQ handlers** — RFC 4120 §3.1/§3.3. ~2-3 person-weeks.
4. **Implement 9-buffer PacBuilder** per ADR-082. ~2 person-weeks.
5. **Implement real PAC validator** (`Pac::parse`, both checksum validators). ~1 person-week. Blocks ADR-123 silver ticket mitigation.
6. **Constant-time HMAC compare** in `crypto.rs:230` — use `subtle::ConstantTimeEq`. ~1 day.
7. **Zeroize key material** across 4 crates (KDC crypto, HSM, NTLM client, auth-core). ~2 days.
8. **Fix `SoftwareHsm::generate_key`** to be non-destructive (return existing key if present). ~1 day. Unblocks 2 ignored kpasswd tests.
9. **Wrap kpasswd new password in KRB-PRIV** per RFC 4120 §3.5. ~2 days.
10. **Add replay cache** to kpasswd authenticator. ~1 day.

### P1 — Must land for v0.6.0 release

11. **CI/CD pipeline** — `.github/workflows/ci.yml` running `cargo check`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo audit`. ~1 person-week.
12. **Dockerfile** + multi-stage build. ~3 days.
13. **Compile-verify real FDB path** — `cargo check --features fdb` with libclang in CI. ~2 days.
14. **Wire `MetricsRegistry` producers** in KDC (`inc_as_req`, `observe_as_req_duration`), storage (`inc_fdb_operation`), replication (`set_replication_lag`). ~3 days.
15. **Add `tracing` spans** in KDC/storage hot paths. ~2 days.
16. **Wire `KerberosAuthModule` → `adrian-kdc`** (after P0 #3 lands). ~3 days.
17. **Wire `LdapDirectoryModule` → real LDAP client** (after LDAP server lands). ~3 days.
18. **Convert 8 silent-Ok CLI subcommands** to real dispatch (or loud stubs). ~1 day.
19. **`adrian-test-harness`** with in-process FDB + directory-service + KDC fixtures. ~1 person-week.
20. **`cargo bench` setup** with criterion; benchmark AS-REQ throughput. ~3 days.

### P2 — Should land for v0.7.0

21. **Real LDAP server** (BER codec + TCP listener + Bind/Search/Modify/Add/Delete). ~6 person-weeks.
22. **Real DRSUAPI handlers** (DRSBind, DRSGetNCChanges with real NDR codec). ~4-6 person-weeks.
23. **Real SMB 3.1.1 server** (PDU codecs + Negotiate/SessionSetup/Create/Read/Write/Close). ~12 person-weeks.
24. **Real ACME server** (RFC 8555 §7.1-§7.7). ~3 person-weeks.
25. **Real CA service** (cert issuance via `x509-cert`, CRL, OCSP). ~2 person-weeks.
26. **Operator reconcile loop** (real `kube::Client`, controller-runtime pattern). ~4 person-weeks.
27. **Backup/restore crate** per ADR-010/034/059. ~3 person-weeks.
28. **Real PKCS#11 HSM backend** (per ADR-015). ~4 person-weeks.
29. **Windows Server 2022 interop lab** — VM + `tcpdump` + fixture captures. ~2 person-weeks.
30. **`adrian-kdc-interop`** test driver with PAC byte-identity fixtures. ~2 person-weeks.

### P3 — Polish for v1.0

31. **README + CONTRIBUTING updates** — reflect v0.5.0 state.
32. **Runbooks** for common ops (join, rotate-krbtgt, restore-from-backup).
33. **Config schema** (`config.toml` + env-var overrides).
34. **Cross-compilation** for Linux/macOS/Windows targets.
35. **SBOM generation** per ADR-067 (Sigstore).
36. **Fuzzing targets** for AS-REQ, TGS-REQ, PAC parsers via `cargo fuzz`.

---

## 9. The Single Most Important Recommendation

**Ship the P0 list (10 items) as v0.6.0, even if nothing else lands.**

The P0 list is ~6-8 person-weeks of work that:
- Fixes 2 security vulnerabilities (non-constant-time HMAC, kpasswd cleartext)
- Unblocks 4 of the 13 ignored tests (HSM key-overwrite fix unblocks kpasswd; AES-CTS fix unblocks the rest)
- Makes the KDC actually capable of issuing a TGT (real key derivation + non-panicking AES-CTS + real handlers)
- Makes the PAC validator real (blocks silver ticket attacks)
- Establishes the security-control-first pattern that v0.7.0+ protocol work must follow

Without P0, every additional line of protocol code increases the surface area where security controls are missing. With P0, the v0.7.0+ work can proceed with confidence that the crypto foundation is correct.

---

## 10. Conclusion

Adrian v0.5.0 is a **research-grade scaffold with a strong architectural foundation and a weak implementation floor**. The ADRs, specs, and crate structure are excellent. The storage primitives (SID, storage-core, storage-testkit) and policy primitives (PReg, declarative JSON) are production-quality. The crypto primitives are real but buggy. Everything else is scaffolding waiting for implementation.

The honest gap-to-production rating is **3.5/10**: the architecture is right, the scaffolding is solid, but the actual protocol implementations, security enforcement, ops infrastructure, and SDK integration are not yet there. With 60-80 person-weeks of focused engineering on the P0+P1+P2 lists, Adrian could reach a deployable v1.0. Without that work, it remains a well-documented research artifact.

The most important next step is not "implement more protocols" — it is "fix the crypto foundation, then implement protocols on top of a correct foundation." The current pattern of stubbing handlers while leaving crypto bugs unfix risks building a tower on sand.

---

## Appendix A — Evaluation Methodology

This evaluation was conducted by dispatching 7 parallel sub-agents across 2 waves:

- **Wave 1** (4 sub-agents, per-crate audit):
  - E1-a: storage/identity (10 crates, 7,127 LoC, 156 tests, 14 TODOs)
  - E1-b: protocol (6 crates, 44 TODOs, MS-* conformance matrix)
  - E1-c: auth/crypto (6 crates, 13 ignored tests deep-dive, security risk matrix)
  - E1-d: app/ops (25 crates, integration status matrix)

- **Wave 2** (3 sub-agents, cross-cutting analysis):
  - E2-a: security (48-row risk register, threat model, AD-baseline comparison)
  - E2-b: test/ops (test quality classification, CI/CD audit, observability audit)
  - E2-c: MVP gap (12-criteria gap analysis, 17-ADR compliance audit, v1.0 effort estimate)

Total: ~2,183 lines of structured findings in `eval/` directory.

## Appendix B — Detailed Findings

- `eval/wave1a-storage-identity.md` — 226 lines
- `eval/wave1b-protocol.md` — 233 lines
- `eval/wave1c-auth-crypto.md` — 331 lines
- `eval/wave1d-app-ops.md` — 305 lines
- `eval/wave2a-security.md` — 459 lines
- `eval/wave2b-test-ops.md` — 407 lines
- `eval/wave2c-mvp-gap.md` — 222 lines
