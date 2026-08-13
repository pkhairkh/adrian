# TASKLIST 07 — SMB & File Services

**Domain**: SMB 3.1.1 server + client + core PDU codecs + print service
**Branch**: `domain-07-smb-file`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-smb-server/src/lib.rs`
- `rust/crates/adrian-smb-server/Cargo.toml`
- `rust/crates/adrian-smb-core/src/lib.rs`
- `rust/crates/adrian-smb-core/Cargo.toml`
- `rust/crates/adrian-smb-client/src/lib.rs`
- `rust/crates/adrian-smb-client/Cargo.toml`
- `rust/crates/adrian-print-service/src/lib.rs`
- `rust/crates/adrian-print-service/Cargo.toml`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `adrian-smb-core` (3113 lines): PDU codecs for Negotiate, SessionSetup, TreeConnect, Create, Read, Write, Close, Logoff, Echo. SMB2 header encode/decode. 37 tests.
- `adrian-smb-server` (1186 lines): Async TCP server on port 445. Negotiate + SessionSetup + TreeConnect + Create/Read/Write/Close handlers. 17 tests.
- `adrian-smb-client` (525 lines): Minimal client — Negotiate, SessionSetup, TreeConnect, Create/Read/Write/Close. 9 tests.
- `adrian-print-service` (125 lines): STUB — IPP axum router is lazily wired, returns NotImplemented. 2 TODOs.

## Known Gaps

1. **No AES-256-GCM encryption** — SMB 3.1.1 §3.2.4.3 requires AES-256-GCM for encrypted PDUs but it's not implemented (only pre-auth integrity SHA-512 is real).
2. **No Kerberos session setup** — SessionSetup uses a stub auth (accepts any credentials). Real GSS-API Kerberos is not wired.
3. **No persistent handles (ADR-106)** — handles are per-session; no durable open that survives reconnection.
4. **No DFS-N (ADR-044)** — Distributed File System Namespace not supported; `\\server\share\path` doesn't follow DFS referrals.
5. **No SMB Direct (RDMA)** — not in scope for v0.8.0 but documented.
6. **No directory change notify** — `SMB2_CHANGE_NOTIFY` command not implemented.
7. **No oplock support** — opportunistic locks not implemented.
8. **Print service is a stub** — no real IPP server.

---

## Wave 1: AES-256-GCM encryption

**DoD**: SMB 3.1.1 encrypted PDUs (SMB2_TRANSFORM_HEADER) work with AES-256-GCM. Client and server can negotiate encryption.

### Tasks

- T-101: Implement `SmbEncryptionKey` derivation from the session key (per SMB 3.1.1 §3.2.5.1).
- T-102: Implement `encrypt_pdu(key, plaintext) -> Vec<u8>` — AES-256-GCM with 12-byte nonce, 16-byte tag.
- T-103: Implement `decrypt_pdu(key, ciphertext) -> Vec<u8>` — inverse.
- T-104: Implement `SMB2_TRANSFORM_HEADER` encode/decode (per SMB 3.1.1 §2.2.41).
- T-105: Wire encryption negotiation into `NegotiateResponse` (set `SMB2_GLOBAL_CAP_ENCRYPTION` flag).
- T-106: Add 5 tests (encrypt/decrypt round-trip, tampered ciphertext rejected, wrong key rejected, transform header round-trip, negotiation flag set).
- T-107: Commit `Wave 1: SMB 3.1.1 AES-256-GCM encryption (+5 tests)`

## Wave 2: Kerberos session setup (GSS-API)

**DoD**: SMB SessionSetup uses real Kerberos via GSS-API (SPNEGO). Client authenticates with a TGT.

### Tasks

- T-201: Implement `GssApi::accept_sec_context(token) -> Result<ResponseToken>` — server-side SPNEGO acceptor.
- T-202: Implement `GssApi::init_sec_context(target_spn) -> Result<Token>` — client-side SPNEGO initiator.
- T-203: Wire SessionSetup to use GSS-API — the SessionSetup request carries a SPNEGO token, the server validates it via the KDC.
- T-204: Add 4 tests (Kerberos session setup succeeds, NTLM fallback refused per ADR-085, anonymous refused, session key derivation from Kerberos).
- T-205: Commit `Wave 2: SMB Kerberos session setup via GSS-API (+4 tests)`

## Wave 3: Persistent handles (ADR-106) + change notify

**DoD**: Handles survive reconnection (durable open). Directory change notify works.

### Tasks

- T-101: Implement `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` + `SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2` (per SMB 3.1.1 §2.2.31).
- T-302: Implement `DurableHandleTable` — maps `{persistent_id, session_id}` to open file handle. Survives disconnect.
- T-303: Implement `SMB2_CHANGE_NOTIFY` command (per SMB 3.1.1 §2.2.35) — directory change notifications.
- T-304: Implement `SMB2_OPLOCK_BREAK` (per SMB 3.1.1 §2.2.23) — opportunistic lock break.
- T-305: Add 6 tests (durable open create, durable open reconnect after disconnect, change notify on directory create, change notify on file modify, oplock break on conflicting open, oplock acknowledgment).
- T-306: Commit `Wave 3: Persistent handles + change notify + oplocks (ADR-106) (+6 tests)`

## Wave 4: DFS-N + print service

**DoD**: DFS namespace referrals work. Print service has a real IPP server.

### Tasks

- T-401: Implement `SMB2_GET_DFS_REFERRAL` command (per MS-DFSN) — returns DFS referral list.
- T-402: Implement DFS referral following in `adrian-smb-client` — client follows referrals transparently.
- T-403: Implement IPP server in `adrian-print-service` per RFC 8011 — `Print-Job`, `Create-Job`, `Send-Document`, `Get-Job-Attributes`, `Get-Printer-Attributes`.
- T-404: Wire print service to a spool directory (files written to disk for printing).
- T-405: Add 6 tests (DFS referral response, DFS referral following, IPP Print-Job, IPP Get-Printer-Attributes, IPP Create-Job + Send-Document, IPP error responses).
- T-406: Commit `Wave 4: DFS-N referrals + IPP print service (+6 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-smb-server -p adrian-smb-core -p adrian-smb-client -p adrian-print-service` — all tests pass
- `cargo clippy` clean for all 4 crates
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
