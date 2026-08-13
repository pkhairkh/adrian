# TASKLIST 03 — Directory Service (LDAP)

**Domain**: RFC 4511 LDAP server — BER codec, TCP listener, handlers, AD-interop controls
**Branch**: `domain-03-directory-service`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-directory-service/src/lib.rs`
- `rust/crates/adrian-directory-service/src/ber.rs`
- `rust/crates/adrian-directory-service/src/filter.rs`
- `rust/crates/adrian-directory-service/src/handler.rs`
- `rust/crates/adrian-directory-service/src/server.rs`
- `rust/crates/adrian-directory-service/src/types.rs`
- `rust/crates/adrian-directory-service/Cargo.toml`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- Real RFC 4511 BER codec: `ber.rs` (encode/decode for LdapMessage, BindRequest, SearchRequest, etc.)
- Filter parsing: `filter.rs` (AND, OR, NOT, equality, present)
- Handlers: `handler.rs` (Bind, Search, Modify, Add, Delete, RootDSE)
- TCP listener: `server.rs` (async tokio TCP on port 389)
- 104 tests pass, **4 ignored** (TCP listener tests hang due to timeout issues)

## Known Gaps

1. **4 TCP listener tests are `#[ignore]`'d** — `serve_search_root_dse_round_trip`, `serve_search_finds_inserted_user`, `serve_real_tcp_listener_accepts_connection`, `dsa_run_serves_real_connection`. These hang because the server task doesn't have a timeout and the test deadlocks waiting for a response.
2. **No AD-interop LDAP controls (ADR-006)** — `LDAP_SERVER_PAGED_RESULT_OID`, `LDAP_SERVER_SORT_OID`, `LDAP_SERVER_SD_FLAGS_OID`, `LDAP_SERVER_SHOW_DELETED_OID`, `LDAP_SERVER_EXTENDED_DN_OID`, `LDAP_SERVER_ASQ_OID`, `LDAP_SERVER_DIRSYNC_OID`, etc. are not implemented.
3. **No `schemaModifyRequest` extended operation (ADR-078)** — schema modifications via LDAP extended op not supported.
4. **No Global Catalog listener (ADR-072)** — GC should listen on port 3268.
5. **No LDAP signing/channel binding (ADR-021)** — security control not enforced.
6. **No LDAPS (TLS) support** — only plaintext port 389.
7. **Filter parsing incomplete** — no `>=`, `<=`, `~=` (approximate), substring (`*`) filters.

---

## Wave 1: Fix TCP listener test timeouts

**DoD**: All 4 currently-ignored TCP listener tests pass (un-ignored). No test hangs > 10 seconds.

### Tasks

- T-101: Add `tokio::time::timeout` wrapper around all `recv_msg` calls in tests.
- T-102: Fix the server's `serve_connection` to properly handle EOF and partial reads (the hang is likely due to the server waiting for more bytes after the client has sent the full message).
- T-103: Add a `LdapServer::serve_with_timeout(stream, dsa, timeout)` variant.
- T-104: Un-ignore the 4 TCP listener tests and verify they pass.
- T-105: Commit `Wave 1: Fix LDAP TCP listener test timeouts (+4 tests un-ignored)`

## Wave 2: AD-interop LDAP controls (ADR-006)

**DoD**: At least 4 AD-specific LDAP controls implemented: paged results, sort, SD flags, extended DN.

### Tasks

- T-201: Implement `LDAP_SERVER_PAGED_RESULT_OID` (1.2.840.113556.1.4.319) — paged search results with cookie.
- T-202: Implement `LDAP_SERVER_SORT_OID` (1.2.840.113556.1.4.473) — server-side sorting.
- T-203: Implement `LDAP_SERVER_SD_FLAGS_OID` (1.2.840.113556.1.4.801) — security descriptor flag control.
- T-204: Implement `LDAP_SERVER_EXTENDED_DN_OID` (1.2.840.113556.1.4.529) — extended DN with GUID/SID.
- T-205: Add 8 tests (2 per control: request parsing + response generation).
- T-206: Commit `Wave 2: AD-interop LDAP controls — paged/sort/SD-flags/extended-DN (+8 tests)`

## Wave 3: Global Catalog + LDAPS + schemaModifyRequest

**DoD**: GC listener on port 3268. LDAPS (TLS) on port 636. `schemaModifyRequest` extended operation works.

### Tasks

- T-301: Add `Dsa::gc_bind_addr` field and a second TCP listener on port 3268 for Global Catalog.
- T-302: Implement GC search (searches all naming contexts, not just the default).
- T-303: Add LDAPS support using `tokio-rustls` (TLS listener on port 636).
- T-304: Implement `schemaModifyRequest` extended operation (RFC 4512 §4.1.2) — calls `adrian-schema-compiler` to regenerate the typed projection.
- T-305: Add 6 tests (GC search, LDAPS handshake, schemaModify add attribute, schemaModify modify, schemaModify delete, schemaModify rollback on error).
- T-306: Commit `Wave 3: Global Catalog + LDAPS + schemaModifyRequest (+6 tests)`

## Wave 4: LDAP signing/channel binding + filter completeness

**DoD**: LDAP signing (channel binding token verification) enforced per ADR-021. All RFC 4515 filter types supported.

### Tasks

- T-401: Implement LDAP signing — verify the bind channel binding token (CBT) when the client connects over TLS.
- T-402: Add `>=`, `<=`, `~=` (approximate match) filter types.
- T-403: Add substring filter (`cn=al*`) — initial, any, final components.
- T-404: Add extensible match filter (`cn:caseExactMatch:=alice`).
- T-405: Add 7 tests (signing enforced, channel binding rejected if missing, each filter type round-trip, complex nested filter).
- T-406: Commit `Wave 4: LDAP signing/channel binding + complete filter parsing (+7 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-directory-service` — all tests pass, 0 ignored
- `cargo clippy -p adrian-directory-service -- -D warnings` clean
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
