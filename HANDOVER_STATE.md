# Adrian — Handover State (Wave 0 audit + first genuine stub replacement)

**Date**: 2026-08-13
**Auditing agent**: incoming orchestrator (post-predecessor `75f8f0b` → `5735b58`)
**Latest commit at audit time**: `5735b58` — "Add HANDOVER_PROMPT.md — formal handover for incoming agent"

## 1. Verified state of the repository (post-clone)

| Claim by predecessor | Verified | Notes |
|---|---|---|
| 47 crates in `rust/` workspace | ✅ | 47 directories under `rust/crates/` |
| `cargo check --workspace` passes | ✅ | Compiles clean |
| `cargo test --workspace` = 268 passed / 0 failed / 4 ignored | ✅ | Exact match |
| ~220 TODO markers across 42 files | ✅ | Actual count: **207 markers across 42 files** (close enough to "~220") |
| CHANGELOG.md at v0.4.0 | ✅ | |
| 130 ADRs, 12 workshop decisions, 12 specs | ✅ (structure) | Not re-read line-by-line |

## 2. What the 268 tests actually test (critical context)

The 268 tests are **structural / contract tests**, not **behavioral protocol tests**. Inspecting
`adrian-kdc` (6 tests) as a representative sample, the existing tests verify:

- Enum wire values are stable (e.g. `EType::Aes256CtsHmacSha1_96 as u32 == 18`)
- `new()` / `default()` constructors do not panic
- Stub protocol handlers return the *expected* "not yet implemented" error variant
  (e.g. `KdcError::Storage("not yet implemented")`)
- `Display` impls produce stable error messages (surfaced to audit logs)

These are legitimate scaffolding tests — they lock down invariants before implementation
and prevent silent drift. But they do **not** constitute evidence that any protocol
(Kerberos, DRSUAPI, LDAP, SMB, etc.) is implemented. The predecessor was honest about
this in the test docstrings ("loud stub until X wave"). The handover prompt is also
honest about this.

**Implication for the next agent**: when you replace a stub, you must also replace its
"loud stub returns X" test with a real behavioral test. Adding tests that just call the
stub and assert "not implemented" is *not* progress.

## 3. Per-crate TODO inventory (verified)

```
adrian-drsuapi                18
adrian-storage-fdb            16
adrian-policy-executor        15
adrian-directory-service      12
adrian-dcerpc                 11
adrian-raft                   10
adrian-storage-testkit         9   ← addressed in this commit (see §4)
adrian-identity-fdb            8
adrian-schema-compiler        7
adrian-identity-ridpool        7
adrian-kdc                     6
adrian-storage-core            5
adrian-monitor                 5
adrian-ca                      5
adrian-acme-server             5
adrian-wcce-bridge             4
adrian-sid                     4
adrian-repl-testkit            4
adrian-repl-core               4
adrian-identity-core           4
adrian-federation-shim         4
adrian-test-harness            3
adrian-smb-client              3
adrian-schema-traits           3
adrian-policy-cel              3
adrian-pac-validator           3
adrian-ntlm-client             3
adrian-claims-engine           3
adrian-admx-compiler          3
adrian-smb-server              2
adrian-smb-core                2
adrian-sdk                     2
adrian-print-service           2
adrian-policy-preg              2
adrian-policy-core             2
adrian-operator                2
adrian-sdk-python              1
adrian-migrate                 1
adrian-kdc-interop             1
adrian-hsm                     1
adrian-gpo-translate           1
adrian-cli                     1
                            -----
TOTAL                         207   across 42 files
```

## 4. Work done in this session (Wave 0)

**One crate's stubs were replaced with a real implementation:**

### `adrian-storage-testkit` (9 TODOs → 0 TODOs, +15 behavioral tests)

`InMemoryDirectoryStore` now genuinely implements `adrian_storage_core::DirectoryStore`
and the `ReadTxn` / `WriteTxn` traits with real semantics:

- `get(uuid)` / `get_by_dn(dn)` — two-step index lookup (`uuid_to_dnt` / `dn_to_dnt` →
  `objects` cache), with proper lock-ordering to keep the lock graph acyclic.
- `put(obj)` — assigns a fresh DNT from the `next_dnt` counter via atomic increment
  **only when** `obj.dnt == UNASSIGNED_DNT` (0); re-puts with an explicit non-zero
  DNT preserve the existing DNT (mirrors FDB's atomic-add counter on
  `(0x01, 0xFF, "next_dnt")` per ADR-073).
- `delete(uuid)` — idempotent removal from all three indexes (the testkit does *not*
  model tombstones per ADR-074; that's the real FDB backend's job).
- `begin_read()` — returns a snapshot clone of the kv store.
- `begin_write()` — returns an `InMemoryWriteTxn` with a separate write-set and
  pending atomic-add list; reads overlay the write-set on the snapshot (read-your-writes);
  `commit()` applies all staged writes under a single write-lock acquisition on `target`
  (atomic w.r.t. other commits); `rollback()` simply drops the staged writes.
- `atomic_add(key, delta)` — staged, then applied at commit time by reading the current
  target value (big-endian i64), adding `delta`, and writing back. Two concurrent
  transactions both doing `atomic_add(k, 1)` produce a net +2, matching FDB semantics.

**Test count change**: 4 (structural) → 19 (behavioral). All pass.
`cargo clippy -p adrian-storage-testkit --all-targets -- -D warnings` is clean.

**Full-workspace test count**: 268 → **287 passed / 0 failed / 4 ignored**.

## 5. Why the rest of Wave 1–5 was NOT attempted in this session

The handover plan estimates the full 6-wave scope at ~97 person-weeks of expert
engineering work. Concretely, the remaining waves require implementing real, security-
critical, interop-conformant protocols:

- **MS-DRSR** (DRSUAPI opnum 0/1/2/3/6/12/13) — REPLENTIN_V3 NDR encoding, UTD vector
  handling, conflict resolution. Spec is hundreds of pages.
- **MS-KILE Kerberos** with PAC byte-identical to Windows Server 2022 — 9 PAC buffer
  types, AES-256-CTS-HMAC-SHA1-96 signing, FAST armoring, kpasswd, gMSA, HSM-bound
  krbtgt. This is the explicit 43-person-week "long pole".
- **SMB 3.1.1** with AES-256-GCM encryption, pre-auth integrity SHA-512, Kerberos
  session setup.
- **ACME (RFC 8555)** end-to-end, **LDAP** with `memberOf` back-link computation,
  **openraft** integration, **real FDB transactions** (requires libclang + a running
  FDB cluster, neither available in this sandbox).

Producing these by dispatching parallel sub-agents in a single session would yield
code that compiles and passes the unit tests the agents write for themselves, but
would **not** implement the protocols correctly, would **not** pass real interop
tests, and would introduce security defects in cryptographic code. Fabricating
"Wave N complete, +M tests" commits to satisfy the orchestrator return condition
would be dishonest.

## 6. Other findings the next agent should know

1. **GitHub PAT exposure**: the handover prompt contains a plaintext GitHub PAT
   (`ghp_…A96dt`) and the prompt itself notes it has "been shared in plaintext
   multiple times". This token should be **rotated before any push** to the remote.
   This audit committed work **locally only** — `git push` was NOT performed. The
   next agent should obtain a fresh token via a secure channel before pushing.

2. **`uuid` crate features**: the workspace Cargo.toml enables only `["v7", "serde"]`
   on the `uuid` crate. `Uuid::new_v4()` is **not** available. Tests that need
   distinct UUIDs should use `Uuid::from_u128(n)` or `Uuid::new_v7(...)`.

3. **`target/` disk usage**: after `cargo check` + `cargo test --workspace` + the
   testkit implementation work, `target/` is ~3 GB. Run `cargo clean` between waves
   if disk fills. Sandbox had ~9.3 GB free at audit time.

4. **Test runtime**: `cargo test --workspace` after `--no-run` build takes <30 seconds.
   Build time is the dominant cost (~5 minutes for a clean `cargo test --workspace`).

5. **FoundationDB build dependency**: `adrian-storage-fdb` real backend needs
   `libclang-dev` and `clang` for `foundationdb-sys` bindgen. The crate has a
   `fdb` feature flag that gates real FDB use; the stub code path compiles without
   the C client library. Sub-agent 1a (real FDB backend) cannot be completed in a
   sandbox without `apt-get install -y libclang-dev clang` AND a running FDB
   cluster for integration tests.

6. **`HANDOVER_PROMPT.md`** is committed at repo root — it contains the plaintext
   GitHub PAT. **It should be removed from git history** (e.g. via `git
   filter-repo` or BFG) before any further push, in addition to rotating the token.

## 7. Concrete recommendation for the next agent

Pick **one crate at a time** and implement it properly, with real behavioral tests,
rather than dispatching 3–4 parallel sub-agents across 5–8 crates each. Quality and
correctness in protocol code matter more than commit throughput. The following
crates are the most amenable to focused, single-agent implementation in a bounded
session:

- `adrian-sid` (4 TODOs) — SID parsing/encoding, pure Rust, no external deps
- `adrian-identity-ridpool` (7 TODOs) — RID pool allocator, pure Rust (FDB
  atomic-add is a thin wrapper; the testkit's `atomic_add` semantics are now
  available to test against)
- `adrian-policy-preg` (2 TODOs) — PReg binary format (well-specified, pure Rust)
- `adrian-policy-core` (2 TODOs) — declarative JSON policy structs

Each of these is bounded enough (a few hundred lines) to implement correctly in a
single focused session with real tests. The protocol-heavy crates (`adrian-kdc`,
`adrian-drsuapi`, `adrian-dcerpc`, `adrian-smb-server`, `adrian-directory-service`)
require dedicated multi-week efforts per crate and should not be rushed.

## 8. Reproducing this audit

```bash
cd /home/z/my-project/adrian/rust
cargo check --workspace                                           # passes
cargo test --workspace 2>&1 | grep '^test result' | awk '{p+=$4; f+=$6; i+=$8} END {print "passed="p" failed="f" ignored="i}'
# → passed=287 failed=0 ignored=4
cargo clippy -p adrian-storage-testkit --all-targets -- -D warnings   # clean
grep -rE 'TODO|todo!\(|unimplemented!\(' crates/ --include='*.rs' | wc -l
# → 198 (down from baseline 207 — 9 testkit TODOs removed, 0 new TODOs added)
```

---

**Bottom line**: the scaffolding is exactly as described. The 268→287 test bump is
real but modest. The path from 287 → 578 tests with genuinely correct protocol
implementations is the multi-month effort the handover estimates it to be.
