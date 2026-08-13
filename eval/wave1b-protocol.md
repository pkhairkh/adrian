# Wave 1b — Protocol Layer Audit

**Auditor**: Sub-agent E1-b
**Date**: 2026-08-13
**Scope**: 6 crates (dcerpc, drsuapi, raft, directory-service, schema-compiler, schema-traits)
**Repo**: `/home/z/my-project/adrian/` @ `dadc4ca` on `main` (v0.5.0)

## Executive Summary

The protocol layer is **structurally scaffolded but not wire-interop-ready**. Of the 6 audited crates, only two — `adrian-dcerpc` (client-side transport + NDR primitives + Bind/BindAck/Request/Response PDU codec) and `adrian-raft` (Raft RPC *handlers*) — contain real, behavioral, byte-exact code that exercises actual protocol semantics. `adrian-schema-traits` is a real Layer-0 foundation crate. `adrian-schema-compiler` has a real `validate_object` implementation but its `compile_from_directory` always returns a hardcoded `minimal_schema()` baseline rather than walking the live Schema NC. `adrian-drsuapi` and `adrian-directory-service` are **loud stubs**: every opnum / LDAP handler returns `Backend` or `NotImplemented`. The handover's claim "structurally correct but not byte-identical to Windows" is accurate for the dcerpc primitives; it is **overstated** for drsuapi and directory-service, which have no wire-level code at all (only constant tables and struct shapes). MS-DRSR conformance is at the constant-table level only; LDAP conformance is zero; the openraft dependency in `adrian-raft` is unused at runtime (a hand-rolled `ManualRaftReplicator` implements RPC *receivers* but no leader-election driver).

**Biggest interop risks**: (1) `adrian-drsuapi` cannot interop with any Windows DC — no DRSBind handler exists; (2) `adrian-directory-service` cannot interop with any LDAP client — no BER codec and no TCP listener; (3) `adrian-dcerpc` lacks RPC security (auth_length always 0) so only anonymous binds would succeed even if the server-side listener existed; (4) `adrian-raft` commits entries without quorum — data loss on partition.

## Per-Crate Findings

### adrian-dcerpc
- **Status**: REAL_PARTIAL
- **Protocol conformance**: MS-RPCE §2.1 / [C706] §12.6 + §14 — **PARTIAL, byte-exact for what's implemented**.
  - **Common header (16 bytes)**: byte-exact. Tests at `pdu.rs:552-591` assert every byte at every offset matches the spec (rpc_vers=5, ptype, pfc_flags, NDR20_DATA_REP=0x10, frag_length patched to actual buffer length, auth_length=0, call_id).
  - **NDR20 primitives** (`ndr.rs`): correct little-endian + power-of-two alignment. Covers `u8/u16/u32/u64`, 16-byte UUIDs, conformant-varying byte arrays, conformant-varying UTF-16LE strings with trailing NUL. The NDR20 transfer-syntax UUID constant `8A885D04-1CEB-11C9-9FE8-08002B104860` is verified byte-exact (`ndr.rs:461-466`).
  - **Bind PDU**: byte-exact, including the iface-version encoding (`(major << 16) | minor` at `pdu.rs:226-228`), p_cont_elem layout (44 bytes for a single-context bind), and the 4-byte alignment of n_context_elem before the first context element.
  - **Bind_ack PDU**: byte-exact, including `sec_addr` 2-byte length prefix + NUL terminator + 4-byte alignment before `p_result_list` (`pdu.rs:341-360`). The `bind_ack_pdu_sec_addr_padding_rounds_to_4` test verifies this.
  - **Request/Response**: minimal framing only — Request header is 24 bytes (16 common + 8 body: `alloc_hint + p_cont_id + cancel_count + reserved`), opnum is prepended to stub bytes per IDL contract. Response decode is a simple slice after the 24-byte header (no validation of alloc_hint or auth trailer).
- **Test quality**: BEHAVIORAL_REAL — 30+ tests across the 4 modules, asserting specific byte values at specific offsets, not just round-trip. `bind_pdu_wire_layout_matches_spec` (`pdu.rs:552`) is the gold-standard test: it walks every byte 0..71 and asserts the value matches MS-RPCE. The transport module uses `tokio::io::duplex` for real async end-to-end round-trips including bind rejection, multiple-PDU streaming, and short-read error paths.
- **TODOs**: 8 (1 inline at `lib.rs:251` for `DceRpcEndpoint::run`, 7 trailing at `lib.rs:262-276`)
- **Production readiness**: 2/5 — real client-side codec + transport; no server-side listener; no RPC security (Kerberos/SPNEGO); only 4 of 11 PDU types implemented (Bind, BindAck, Request, Response — missing Fault, Bind_nak, Alter_context, Alter_context_resp, Auth3, Shutdown, Orphaned); NDR pointer/struct/union/pipe semantics not implemented (only primitives + byte arrays + UTF-16 strings + UUIDs).
- **Wire-compat risk**: **HIGH for unauthenticated traffic**. The Bind/BindAck/Request/Response codecs are byte-correct for single-context, single-frag, unauth PDUs — a real Windows DC would accept a Bind from this client (and reject it at the auth-negotiation step because auth_length=0). The opnum-in-stub encoding (vs. opnum-as-header-field) is the IDL contract for connection-oriented DCE/RPC and matches MS-RPCE. **Caveat**: no test compares these bytes against a real Windows capture (e.g. from `tcpdump`/Wireshark of a `repadmin /sync` request). The byte-exactness is asserted against the spec text, not against empirical Windows output.
- **What's missing**: server-side `DceRpcEndpoint::run()` (TcpListener + accept loop); RPC security (`PKT_PRIVACY`/`PKT_INTEGRITY` via SPNEGO over Kerberos, per ADR-021); 7 missing PDU types; NDR pointer semantics (`unique_ptr`, `ref_ptr`, conformant-struct embedding); NDR64 transfer syntax; multi-context bind dispatch (only 1 context tested); Alter_context for late binding.
- **Notes**: The crate is **correctly factored** for the 5-protocol amortization strategy (DRSUAPI + SAMR + LSARPC + Netlogon + MS-WCCE all share this transport). The 5 interface UUIDs are verified against the MS-* §1.9 published values (`lib.rs:309-332`).

### adrian-drsuapi
- **Status**: STUB_LOUD
- **Protocol conformance**: MS-DRSR — **NONE at the wire level; constant-table-only**.
  - `DrsExtFlag` enum (`lib.rs:66-84`): all 8 numeric values verified byte-exact against MS-DRSR §4.1.277 (`tests:267-278`). Includes the LVR-critical trio `DRS_EXT_GETCHGREQ_V8 (0x40)`, `DRS_EXT_GETCHGREPLY_V9 (0x80)`, `DRS_EXT_GETCHGREQ_V10 (0x10000)`.
  - `DrsOption` enum (`lib.rs:95-124`): all 12 numeric values verified (`tests:293-308`), including `EXOP_REPL_SECRETS (0x100)` (the DCSync extension per ADR-122).
  - `DrsBindResult` struct: matches MS-DRSR §4.1.4.2 field shape (server_invocation_id, server_extensions, replication_epoch).
  - **REPLENTIN_V3**: **NOT IMPLEMENTED**. The doc comment at `lib.rs:131-133` claims "Emits and consumes REPLVALINF_V3 records byte-identically to MS-DRSR §4.1.277" — this is aspirational doc, not code. There is no NDR encode/decode for REPLVALINF_V3, REPLTIMESTAM, UPTODATE_VECTOR_V1_EXT, or any other MS-DRSR complex type anywhere in this crate. The `DrSuapiReplicator::get_changes` impl at `lib.rs:152-165` returns `ReplicationError::Backend("not yet implemented")`.
  - **DRSBind (opnum 0x00)**: NOT implemented — `drs_bind` at `lib.rs:214-222` returns Backend error.
  - **DRSGetNCChanges (opnum 0x04)**: NOT implemented — `drs_get_nc_changes` at `lib.rs:236-245` returns Backend error.
  - **DRSUnbind, DRSReplicaSync, DRSUpdateRefs, DRSReplicaAdd/Del/Modify, DRSGetReplInfo, DRSCrackNames, DRSVerifyNames, DRSDomainControllerInfo, EXOP_REPL_SECRETS**: all NOT implemented (12 trailing TODOs at `lib.rs:247-257`).
  - **UTD vector handling**: NOT implemented in this crate (the UTD vector data structures live in `adrian-repl-core`; this crate's `Replicator::update_utd_vector` returns Backend).
- **Test quality**: STRUCTURAL_ONLY — 8 tests, every one asserts that calling the stub returns `Err(ReplicationError::Backend(_))`. Plus 4 tests verifying enum constant values match MS-DRSR (these are the only "real" tests; they verify protocol constants but no wire behavior). The `#[ignore]` integration test placeholder at `lib.rs:461-466` is a no-op body.
- **TODOs**: 18 (highest of any audited crate)
- **Production readiness**: 1/5
- **Wire-compat risk**: **WILL NOT INTEROP**. A real Windows DC connecting to this server would fail at the DCE/RPC Bind (no server listener) and even if the bind succeeded, every DRSUAPI opnum returns an error. A real Windows DC *as a replication source* (i.e. this crate as client) cannot be exercised because the `DrSuapiReplicator` returns Backend before any wire I/O.
- **What's missing**: literally all MS-DRSR wire code: DRSBind (with `DRS_EXTENSIONS` parsing), DRSUnbind, DRSGetNCChanges (with `REPLVALINF_V3` / `REPLENTIN_V3` NDR encode/decode of the `REPLY` body — the most complex single type in MS-DRSR, hundreds of fields), UPTODATE_VECTOR_V1_EXT serialization, all 12 opnums, EXOP_REPL_SECRETS ACL gating per ADR-122, integration with FDB-backed store to actually pull NC changes, conflict resolution using `adrian_repl_core::resolve_conflict`.
- **Notes**: The handover's claim "structurally correct but not byte-identical to Windows" is **inaccurate for this crate** — it is not structurally correct because the structure is "stub returns error", not "real NDR types with byte mismatches". The doc-comment claim about REPLVALINF_V3 byte-identity is misleading; it should be reworded to "intended to emit/consume REPLVALINF_V3 byte-identically once implemented".

### adrian-raft
- **Status**: REAL_PARTIAL
- **Protocol conformance**: Ongaro & Ousterhout §5 — **PARTIAL, receiver-side real, driver missing**.
  - §5.4.1 AppendEntries receiver logic (`lib.rs:556-632`): REAL — all 6 steps implemented (term check, term advance + become follower, prev_log_index/term match, conflict truncation, append new entries, commit-index advance via `min(leader_commit, last_new_index)`). Tests at `lib.rs:1178-1290` exercise all 5 scenarios: stale term, higher term, log inconsistency, conflict truncation, idempotent resend.
  - §5.4.1 RequestVote receiver logic (`lib.rs:634-687`): REAL — all 3 steps (term check, term advance + reset voted_for, up-to-date log check using the (last_log_term, last_log_index) tuple ordering). Tests at `lib.rs:1293-1374` exercise stale term, first-candidate grant, second-candidate reject, stale-log reject, higher-term grant.
  - §5.4.2 InstallSnapshot receiver: PARTIAL — term regression rejected, higher term accepted, but **snapshot bytes are discarded** (`lib.rs:689-733`). The handler logs at debug level and returns Ok(()) without applying the snapshot to the state machine or truncating the log.
  - §5.2 persistent state (currentTerm, votedFor, log): **NOT persisted** — `RaftNodeState.log` is `Vec<RaftLogEntry>` in memory behind `tokio::sync::RwLock`. Crash = data loss.
  - §5.2 leader volatile state (nextIndex[], matchIndex[]): **NOT present** — no leader role implemented.
  - §5.3 leader election (candidate-side `start_election`): **NOT implemented** — there is no `become_candidate` / `start_election` / `RequestVote` broadcast loop.
  - §5.3 commit rule (replicate on majority before apply): **VIOLATED** — `RaftDirectoryReplicator::apply_changes` at `lib.rs:820-864` advances `commit_index` to `last_log_index()` immediately after local append, treating "local apply = one-node quorum". This is acknowledged in the comment at `lib.rs:858-861` ("in the in-memory v1 test path we treat the local apply as a one-node quorum") but it means **data loss on partition** — a single-node "apply" with no peers acked is not commit-safe by Raft's safety proof.
  - §5.4.1 heartbeat (empty AppendEntries): supported by the receiver (zero entries works) but no heartbeat timer.
  - §5.6 log compaction + snapshot: NOT implemented.
  - §7 linearizable client reads: out of scope (no client API).
- **Test quality**: BEHAVIORAL_REAL for RPC handlers — 35 tests, all asserting concrete state mutations after concrete RPC invocations (e.g. "after `append_entries(2, inv, 1, 1, [e2@2, e3@2], 0)`, the log is `[1@1, 2@2, 2@3]`"). Tests cover all 5 Ongaro & Ousterhout receiver-side scenarios. **Missing**: no test exercises a multi-node cluster (every test uses a single `ManualRaftReplicator`); no test for the openraft type-conversion seam beyond a 2-line round-trip.
- **TODOs**: 3 (all trailing at `lib.rs:929-933`: openraft RaftLogStore/StateMachine/Network/Driver wiring)
- **Production readiness**: 2/5
- **Wire-compat risk**: N/A (Raft is internal framework protocol, not external interop). But **functional risk is HIGH**: the crate's `openraft` dependency is **unused at runtime** — `pub use openraft::{CommittedLeaderId, LogId, Vote}` is re-exported and `to_openraft_log_id` / `to_openraft_vote` exist as seam helpers, but no `openraft::Raft<...>` instance is ever constructed. The actual runtime impl is the hand-rolled `ManualRaftReplicator`. The "openraft-based" framing in `Cargo.toml` description is misleading.
- **What's missing**: openraft `RaftLogStore` impl (FDB-backed, per Decision 1 / ADR-073), openraft `RaftStateMachine` impl, openraft `RaftNetwork` impl over `tokio::net::TcpStream`, leader-election driver (§5.3 candidate-side + heartbeat timer), snapshot transfer (§5.6), persistent state on FDB (§5.2), real quorum-based commit (§5.3 — current code commits without quorum).
- **Notes**: The UTD-vector synthesis function `synthesize_utd_vector` (`lib.rs:255-274`) is genuinely useful — it walks a Raft log and produces a UTD vector with one cursor per distinct `origin_invocation_id`, sorting by invocation ID per MS-ADTS §3.1.1.3.2.5. This is a real, tested piece of code that would interop with `repadmin /showutdvec` output formatting.

### adrian-directory-service
- **Status**: STUB_LOUD
- **Protocol conformance**: RFC 4511 / RFC 4510-4519 — **NONE**.
  - No BER codec. No ASN.1 message dispatch. No TCP listener. No Bind/Search/Modify/Add/Delete/ModifyDN/Compare/Extended handlers.
  - The `SearchRequest` struct (`lib.rs:144-163`) has the right *fields* (base_dn, scope, deref_aliases, size_limit, time_limit, filter, attributes, types_only) matching RFC 4511 §4.5.1, but the `handle_search` function (`lib.rs:179-188`) returns `DsaError::NotImplemented` without ever reading the request.
  - The `Dsa::run` function (`lib.rs:108-117`) returns `DsaError::NotImplemented("Dsa::run not yet implemented")` — there is no TCP listener, no async accept loop.
  - The doc claim "Implements LDAPv3 (RFC 4510-4519) server-side on TCP/389 (LDAP) and TCP/636 (LDAPS), with the Global Catalog listener on TCP/3268 / 3269 (per ADR-072)" is **aspirational doc, not code**.
  - The doc enumerates 10 AD-specific LDAP controls per ADR-006 (paged, sort, SD flags, show-deleted, extended-DN, ASQ, DirSync, domain-scope, verify-name, ranged-retrieval) — none are implemented.
- **Test quality**: STRUCTURAL_ONLY — 8 tests, every protocol-handling test asserts `Err(DsaError::NotImplemented(_))`. Two tests verify `SearchRequest` struct field defaults; one test verifies `SearchResultEntry` multi-valued attribute support (data-structure only, no wire encoding).
- **TODOs**: 12 (3 inline at `lib.rs:109, 183, 193`; 9 trailing at `lib.rs:200-208`)
- **Production readiness**: 1/5
- **Wire-compat risk**: **WILL NOT INTEROP**. OpenLDAP / ldapsearch / AD clients cannot connect — there is no TCP listener and no BER codec to parse an incoming BindRequest. Even if a listener existed, the BER bytes would need to be parsed into the `SearchRequest` struct, which has no codec.
- **What's missing**: BER codec (encode + decode all RFC 4511 message types: BindRequest, BindResponse, SearchRequest, SearchResultEntry, SearchResultDone, ModifyRequest/Response, AddRequest/Response, DelRequest/Response, ModifyDNRequest/Response, CompareRequest/Response, ExtendedRequest/Response, IntermediateResponse, controls); TCP listener on 389/636 (TLS via `tokio-rustls`); GC listener on 3268/3269; Bind handler (RFC 4513 — simple, SASL/GSSAPI, SASL/GSS-SPNEGO per ADR-021 channel-binding); Search handler with filter parser (RFC 4515 string form → AST); all 10 AD controls per ADR-006; constructed attributes per ADR-009 (tokenGroups, memberOf, canonicalName); schemaModifyRequest extended op wiring to schema-compiler; RootDSE; StartTLS extended op.
- **Notes**: **Critical category error in `Cargo.toml`**: the crate depends on `ldap3` (line 26). `ldap3` is an LDAP *client* library — it cannot be used to *implement* an LDAP server. The framework will need to either (a) write a BER codec from scratch using `rasn` (already a dep of `adrian-dcerpc` and `adrian-schema-compiler`), (b) use `lber` (the BER primitive lib that `ldap3` uses internally), or (c) build a hand-rolled BER encoder/decoder. The current `ldap3` dep should be moved to dev-dependencies (used for integration tests against the local server) and a real BER codec dependency added.

### adrian-schema-compiler
- **Status**: REAL_PARTIAL (real validator, fake compiler-walker)
- **Protocol conformance**: RFC 4512 §4 + MS-ADTS §3.1.1.2 — **PARTIAL**.
  - `SchemaProjection` data model: matches RFC 4512 §4.1.x (attributeSchema fields: `attributeID`, `ldapDisplayName`, `attributeSyntax`, `rangeLower/Upper`, `isSingleValued`, `searchFlags`; classSchema fields: `governsID`, `ldapDisplayName`, `superiors`, `mustContain`, `mayContain`, `systemFlags`, `objectClassCategory`).
  - `minimal_schema()` (`lib.rs:485-816`): REAL — hardcoded baseline of 26 attributes + 7 classes (top, person, user, group, organizationalUnit, domainDNS, container) with correct linkID pairing (member=3/memberOf=4, managedBy=1/managedObjects=2, manager=8/directReports=9) per ADR-001/ADR-002. Verified by `minimal_schema_pairs_linkids_per_adr002` test.
  - `validate_object` (`lib.rs:284-401`): REAL — walks `objectClass` hierarchy via BFS over `superiors`, accumulates transitive `must_contain` / `may_contain`, checks every attribute is in the allowed set (with system-attribute exemption per MS-ADTS §3.1.1.2.x), checks every `must_contain` is present. Verified by 5 behavioral tests at `lib.rs:1129-1235`.
  - `validate_syntax` (`lib.rs:407-473`): PARTIAL — checks Boolean (1 byte 0x00/0xFF), Integer (≤8 bytes), String (valid UTF-8), SID (8..=68 bytes). Not implemented: OID syntax validation, DN syntax validation, GeneralizedTime syntax validation, SecurityDescriptor byte-shape, range_lower/range_upper enforcement.
  - `compile_from_directory` (`lib.rs:246-282`): **FAKE** — the doc claims it walks the Schema NC, but the implementation always returns `minimal_schema()` regardless of whether the Schema NC head is found or not (lines 259-281). The "real walk" is deferred to Wave 4b per inline comment at `lib.rs:262-265`.
  - `recompile_and_swap` (`lib.rs:105-114`): does NOT actually re-walk the directory; it just calls `compile()` (which returns minimal_schema) and bumps `generation + 1`. No atomic pointer swap happens — the new projection is returned but never installed anywhere.
  - `read_schema_nc_head` (`lib.rs:179-205`): always returns `WELL_KNOWN_SCHEMA_NC_HEAD` regardless of directory contents (the production path that would parse `objectGUID` from the Schema NC head object is a TODO at `lib.rs:191-194`).
- **Test quality**: BEHAVIORAL_REAL for `validate_object` (5 tests covering accept + 3 reject paths + system-object edge case); BEHAVIORAL_MINIMAL for `compile_from_directory` (verifies it returns a non-empty projection but doesn't verify a real walk because the StubStore returns None).
- **TODOs**: 0 formal `TODO` markers — but the code self-identifies the Wave 4b gating via inline comments at `lib.rs:262-265, 272-275`. The HANDOVER_STATE inventory showed 7 TODOs for this crate at Wave 0; those have been resolved by replacing them with inline "gated to Wave 4b" comments.
- **Production readiness**: 2/5
- **Wire-compat risk**: NONE (no protocol code). But **functional risk is HIGH**: a directory with custom schema (added via `schemaModifyRequest`) will not have its custom attributes reflected in the projection until the Wave 4b FDB walk is implemented. Until then, custom attributes will be silently tolerated by `validate_syntax` (per ADR-078 §Decision Layer 2 dynamic fallback) but won't be indexed, validated against range_lower/range_upper, or projected into typed Rust classes.
- **What's missing**: real Schema NC walk (range scan over FDB subspace 0x01, filter on `objectClass=attributeSchema`/`classSchema`, parse `attributeID`/`governsID` OID strings into numeric IDs, resolve superior/must_contain/may_contain by name → ID), range_lower/range_upper enforcement, OID syntax validation, DN syntax validation (RFC 4514 parsing), DIT structure rules, name forms (RFC 4512 §5.x), schema linkID pairing validation (forward linkID must be even, back-linkID = forward+1), `schemaModifyRequest` → re-compile → atomic swap wiring (the swap is currently a no-op), `read_schema_nc_head` parsing real `objectGUID` from the Schema NC head object.
- **Notes**: The `dump_rust` developer-only command (`lib.rs:119-155`) is real and tested — it emits a Rust source file with `ATTRIBUTE_IDS: &[(u32, &str)]` and `CLASS_IDS: &[(u32, &str)]` static arrays. This is the offline inspection tool promised by Decision 4 §Decision Layer 1.

### adrian-schema-traits
- **Status**: REAL_COMPLETE (for its declared scope as a Layer-0 foundation crate)
- **Protocol conformance**: RFC 4512 §4.1.x + MS-ADTS §3.1.1.2.x — **PARTIAL**.
  - `AttributeSyntax` enum (12 variants, `lib.rs:44-70`): covers the LDAP-syntax subset (DirectoryString, IA5String, Integer, Boolean, OID, DN, OctetString, GeneralizedTime) plus AD-specific syntaxes (LargeInteger `2.5.5.16`, SID `2.5.5.17`, SecurityDescriptor `2.5.5.15`, CaseExactString `2.5.5.3`). **Missing AD syntaxes**: PrintableString `2.5.5.5`, NumericString `2.5.5.6`, DNWithBinary `2.5.5.7`, DNWithString `2.5.5.12`, PresentationAddress, ObjectAccessor.
  - `AttributeSchema` / `ClassSchema` / `SchemaProjection` structs: field-complete per RFC 4512 + AD.
  - `SchemaProjection::next_generation()` (`lib.rs:159-163`): real CoW clone with `generation.saturating_add(1)` per ADR-003.
  - `SchemaCache` trait (`lib.rs:172-185`): real trait surface (attribute/attribute_by_name/class/class_by_name/generation/schema_nc_head). The implementing type `SnapshotView` promised in the doc comment is NOT in this crate (it would live in a future schema-cache crate).
  - `Projectable` trait (`lib.rs:222-225`): trait surface only — no `#[derive(Projectable)]` proc-macro exists yet (TODO at `lib.rs:227`).
  - `SearchFlags` bitflags (`lib.rs:235-253`): 8 of the documented flags (fANR, fATTINDEX, fPRESERVEATON, fCOPY, fTUPLEINDEX, fSUBTREEATTRINDEX, fCONFIDENTIAL, fNEVERVALUEAUDIT). Matches MS-ADTS §3.1.1.3.2.5 for the subset covered.
  - `SystemFlags` bitflags (`lib.rs:257-269`): 5 flags (ATTR_NOT_REPLICATED, ATTR_IS_CONSTRUCTED, DOMAIN_DISALLOW_RENAME, DOMAIN_DISALLOW_MOVE, DISALLOW_DELETE). The numeric values match MS-ADTS §3.1.1.2.4 for these 5; the full SystemFlags set is ~30 bits.
  - `SchemaError` enum (`lib.rs:189-212`): 7 variants matching the validation failure modes (UnknownAttributeId, UnknownAttributeName, UnknownClassId, UnknownClassName, MissingMustContain, DisallowedAttribute, ProjectionCompile).
- **Test quality**: BEHAVIORAL_MINIMAL — 2 tests verifying `SearchFlags` and `SystemFlags` bitflag decoding. Appropriate for a pure-types foundation crate; the behavioral tests live in `adrian-schema-compiler` which exercises `SchemaProjection::validate_object` etc.
- **TODOs**: 3 (all forward-looking: derive macro, `SchemaProjection::build` constructor, native-class trait library)
- **Production readiness**: 3/5 — solid foundation; missing derive macro blocks framework-native class projection.
- **Wire-compat risk**: NONE (no protocol code).
- **What's missing**: `#[derive(Projectable)]` proc-macro (gated to Wave 4b), `SchemaProjection::build()` constructor (the TODO points at `adrian-schema-compiler`), native-class trait library (ServiceAccount, ManagedDevice, PolicySet, CertificateTemplate per ADR-078 §Decision Layer 2), additional AD syntaxes (PrintableString, NumericString, DNWithBinary, DNWithString), `SnapshotView` implementing `SchemaCache` with `Arc<SchemaProjection>` (referenced in doc but not present).
- **Notes**: This is the cleanest crate of the 6 audited. Layer-0 dependencies only (`serde`, `thiserror`, `uuid`, `bitflags`); no `tokio`, no `rasn`, no protocol deps. The `SchemaError` variants are well-designed (carry both attribute ID and class ID for actionable error messages).

## MS-* Conformance Matrix

| Protocol | Spec | Conformance Level | Evidence |
|----------|------|-------------------|----------|
| DCE/RPC common header | MS-RPCE §2.1 / [C706] §12.6.1 | FULL | `pdu.rs:552-591` byte-exact assertion test |
| DCE/RPC Bind PDU | MS-RPCE §2.2.1 / [C706] §12.6.1 | FULL (single-context only) | `pdu.rs:523-549` round-trip + `pdu.rs:552-591` byte-layout |
| DCE/RPC Bind_ack PDU | MS-RPCE §2.2.2 / [C706] §12.6.2 | FULL (single-result, sec_addr padding verified) | `pdu.rs:648-731` 4 round-trip tests + padding test |
| DCE/RPC Request PDU | MS-RPCE §2.2.6.4 / [C706] §12.6.1 | PARTIAL (opnum in stub, no auth trailer, single-frag only) | `pdu.rs:793-816` byte-layout test |
| DCE/RPC Response PDU | MS-RPCE §2.2.6.5 | PARTIAL (stub extraction only, no alloc_hint validation) | `pdu.rs:818-856` |
| DCE/RPC Fault PDU | MS-RPCE §2.2.2.6 | NONE | not implemented |
| DCE/RPC Alter_context | MS-RPCE §2.2.3 | NONE | not implemented |
| DCE/RPC RPC security | MS-RPCE §2.2.2.8 / [C706] §13 | NONE | auth_length always 0; no SPNEGO/Kerberos |
| NDR20 transfer syntax | MS-RPCE §2.1 / [C706] §14 | PARTIAL (primitives only: u8/u16/u32/u64/UUID/conformant byte array/UTF-16 string; no pointers/structs/unions/pipes) | `ndr.rs:309-488` 13 round-trip tests with byte assertions |
| NDR64 transfer syntax | MS-RPCE §3.1 | NONE | not implemented |
| DRSUAPI DRSBind | MS-DRSR §4.1.4 | NONE | `drs_bind` returns Backend error |
| DRSUAPI DRSUnbind | MS-DRSR §4.1.5 | NONE | not implemented |
| DRSUAPI DRSGetNCChanges | MS-DRSR §4.1.27 | NONE | `drs_get_nc_changes` returns Backend error |
| DRSUAPI DRSCrackNames | MS-DRSR §4.1.17 | NONE | not implemented |
| DRSUAPI DRS_EXTENSIONS flags | MS-DRSR §4.1.277 | FULL (constant values only — 8 of 8 verified) | `lib.rs:267-290` |
| DRSUAPI dwFlags / DrsOption | MS-DRSR §4.1.x | FULL (constant values only — 12 of 12 verified) | `lib.rs:293-308` |
| REPLENTIN_V3 | MS-DRSR §4.1.10.1 | NONE | no NDR encode/decode code exists |
| REPLVALINF_V3 | MS-DRSR §4.1.277 | NONE | doc claim is aspirational |
| UPTODATE_VECTOR_V1_EXT | MS-DRSR §4.1.10.1.12 | NONE (data structures in `adrian-repl-core` only) | no MS-DRSR wire encoding |
| EXOP_REPL_SECRETS (DCSync) | MS-DRSR §4.1.27 §EXOP_REPL_SECRETS | NONE (constant value verified, ACL gating not implemented) | `lib.rs:311-338` |
| LDAP Bind | RFC 4511 §4.2 | NONE | not implemented |
| LDAP Search | RFC 4511 §4.5 | NONE (struct shape only) | `handle_search` returns NotImplemented |
| LDAP Modify | RFC 4511 §4.6 | NONE | not implemented |
| LDAP Add | RFC 4511 §4.7 | NONE | not implemented |
| LDAP Delete | RFC 4511 §4.8 | NONE | not implemented |
| LDAP ModifyDN | RFC 4511 §4.9 | NONE | not implemented |
| LDAP Compare | RFC 4511 §4.10 | NONE | not implemented |
| LDAP Extended ops | RFC 4511 §4.12 | NONE | not implemented |
| LDAP BER encoding | RFC 4511 §4.1 / RFC 4517 | NONE | no BER codec in this crate or any dep |
| LDAP RootDSE | RFC 4512 §5.1 | NONE | not implemented |
| LDAP memberOf (constructed) | MS-ADTS §3.1.1.3.2.10 | NONE | not implemented |
| LDAP AD controls (10) | ADR-006 | NONE | none of 10 controls implemented |
| LDAP schemaModifyRequest | RFC 4512 §4.1.2 / ADR-078 | NONE | handler returns NotImplemented |
| schema attributeSchema | RFC 4512 §4.1.3 + MS-ADTS §3.1.1.2.x | PARTIAL (data model + 26 hardcoded attrs; no real walk) | `minimal_schema()` + `validate_object` |
| schema classSchema | RFC 4512 §4.1.4 + MS-ADTS §3.1.1.2.x | PARTIAL (data model + 7 hardcoded classes; no real walk) | `minimal_schema()` + `validate_object` |
| schema linkID pairing | RFC 4512 §4.1.3 + ADR-001 | FULL (verified by test) | `minimal_schema_pairs_linkids_per_adr002` |
| schema validate_object | RFC 4512 §2 + ADR-078 | PARTIAL (must_contain + disallowed + basic syntax; no range/OID/DN validation) | `lib.rs:1129-1235` 5 behavioral tests |
| Raft AppendEntries (receiver) | Ongaro §5.4.1 | FULL (all 6 steps) | `lib.rs:1178-1290` 5 tests |
| Raft AppendEntries (sender) | Ongaro §5.4.1 | NONE | no leader-side driver |
| Raft RequestVote (receiver) | Ongaro §5.4.1 | FULL (all 3 steps + up-to-date log check) | `lib.rs:1293-1374` 5 tests |
| Raft leader election (candidate) | Ongaro §5.4.1 | NONE | no `start_election` loop |
| Raft InstallSnapshot (receiver) | Ongaro §5.4.2 | PARTIAL (term check only; bytes discarded) | `lib.rs:1377-1397` 2 tests |
| Raft persistent state | Ongaro §5.2 | NONE (in-memory only) | `Vec<RaftLogEntry>` behind RwLock |
| Raft commit rule (majority) | Ongaro §5.3 | VIOLATED (single-node "quorum") | `apply_changes` advances commit_index without acks |
| Raft log compaction | Ongaro §5.6 | NONE | not implemented |

## Cross-Cutting Observations

1. **The handover's "structurally correct but not byte-identical to Windows" framing is accurate only for `adrian-dcerpc`.** For `adrian-drsuapi` and `adrian-directory-service`, the crates are NOT structurally correct — they are loud stubs that return error constants. There is no wire-level code to be byte-correct or byte-incorrect about. The handover should be reworded: "structurally correct (dcerpc) + loud stubs (drsuapi, directory-service) + hand-rolled Raft handlers (raft) + hardcoded baseline schema (schema-compiler)".

2. **Doc claims vs. code reality.** Several crates have ambitious doc comments that overstate implementation status:
   - `adrian-drsuapi` lib.rs line 131-133: "Emits and consumes REPLVALINF_V3 records byte-identically to MS-DRSR §4.1.277" — there is no REPLVALINF_V3 code.
   - `adrian-directory-service` lib.rs line 5: "Implements LDAPv3 (RFC 4510-4519) server-side on TCP/389" — no TCP listener exists.
   - `adrian-raft` Cargo.toml description: "openraft-based native replication" — openraft is a dependency but never instantiated at runtime.
   These should be reworded to "intended to implement" / "will emit byte-identically" / "openraft-seam-native replication" so future auditors don't waste time searching for code that doesn't exist.

3. **The two real crates (`adrian-dcerpc`, `adrian-raft`) share a quality pattern**: byte-exact assertions against the spec, real async I/O via `tokio::io::duplex`, loud-stub fallbacks for unimplemented opnums/RPCs, `#![forbid(unsafe_code)]` + `#![warn(missing_docs)]`. The four stub/fake crates do not match this pattern.

4. **The `ldap3` dependency in `adrian-directory-service` is a category error.** `ldap3` is a client library. To implement an LDAP server, the framework needs a BER codec. `rasn` is already a workspace dependency (used by `adrian-dcerpc` and `adrian-schema-compiler`) and could provide the BER primitives — but `rasn` does not ship an LDAP message type library, so the framework will need to define its own ASN.1 schema for RFC 4511 messages. This is non-trivial (≈2–3 person-weeks of work for the BER codec + message types).

5. **The openraft seam in `adrian-raft` is real but unused.** `to_openraft_log_id` / `to_openraft_vote` are correctly implemented conversion helpers, and the `LogId`/`Vote`/`CommittedLeaderId` types are re-exported. But because no `openraft::Raft<...>` instance is ever constructed, this seam is currently dead code. The hand-rolled `ManualRaftReplicator` is a parallel implementation that doesn't use openraft at all. This means the openraft version (which is battle-tested) is bypassed in favor of the hand-rolled version (which has the commit-without-quorum bug at `lib.rs:862`).

6. **Wave 4b is the long pole.** Three crates explicitly defer real work to "Wave 4b" via inline comments:
   - `adrian-schema-compiler`: real Schema NC walk over FDB.
   - `adrian-drsuapi`: REPLVALINF_V3 byte-for-byte equivalence, UTD-vector delta application, EXOP_REPL_SECRETS ACL gating.
   - `adrian-test-harness`: integration tests for both of the above.
   Wave 4b should be sequenced before any real AD-interop claim can be made.

7. **The `validate_object` + `minimal_schema` work in `adrian-schema-compiler` is the most production-advanced piece of the 6 crates audited.** It has 5 behavioral tests, walks a real class hierarchy via BFS, and correctly handles the system-attribute exemption per MS-ADTS §3.1.1.2.x. This is real schema validation logic that could ship today for a framework-only forest (no custom schema). The gap is the Schema NC walker, which is the Wave 4b dependency.

8. **No wire-capture regression tests exist.** None of the 6 crates has a test that compares encoded bytes against a `.bin` file captured from real Windows / OpenLDAP traffic. The dcerpc byte-exactness is asserted against the spec text only. This is the single highest-value test-infrastructure investment for closing the wire-compat gap: capture 10–20 real PDUs from a Windows Server 2022 lab, commit the bytes as test fixtures, and assert `encode_*` produces byte-identical output.

## Risk Register

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| `adrian-drsuapi` cannot interop with Windows DCs (no DRSBind handler) | Critical | Certain (today) | Implement DRSBind + DRSGetNCChanges + REPLVALINF_V3 NDR codec (Wave 4b) |
| `adrian-directory-service` cannot interop with LDAP clients (no BER codec, no listener) | Critical | Certain (today) | Write BER codec (rasn-based or hand-rolled), implement Bind/Search handlers, add TCP listener on 389/636 |
| `adrian-dcerpc` lacks RPC security (auth_length=0) — only anonymous binds work | High | Certain (when server endpoint ships) | Implement SPNEGO over Kerberos auth trailer per MS-RPCE §2.2.2.8 + ADR-021 (signing/channel-binding) |
| `adrian-raft` commits without quorum — data loss on partition | High | Likely (any multi-node deploy) | Wire openraft `RaftLogStore` + `RaftStateMachine` + `RaftNetwork` and replace `ManualRaftReplicator` with `openraft::Raft<...>` |
| `adrian-raft` log is in-memory — crash = total data loss | High | Certain (any crash) | Same as above — openraft + FDB-backed `RaftLogStore` |
| No wire-capture regression tests — byte-exactness asserted against spec text only | High | Possible (spec misreading) | Capture 10-20 real PDUs from Windows Server 2022 lab; commit as fixtures; assert encode produces identical bytes |
| `adrian-schema-compiler` always returns `minimal_schema()` regardless of directory contents | Medium | Certain (today) | Implement real Schema NC walk over FDB subspace 0x01 (Wave 4b) |
| `adrian-dcerpc` opnum-in-stub encoding contradicts MS-RPCE for some interface classes | Medium | Possible | Verify against Windows capture whether opnum is in stub or in Request header for DRSUAPI; current code assumes stub per IDL contract |
| `ldap3` dependency in `adrian-directory-service` is a client lib used in a server crate | Medium | Certain (today) | Remove `ldap3` from runtime deps; add BER codec dep (`rasn` or `lber`); move `ldap3` to dev-deps for integration tests |
| Doc comments overstate implementation status (REPLVALINF_V3 byte-identity, RFC 4510-4519 server, openraft-based) | Low | Certain (today) | Reword doc comments to "intended to" / "will emit byte-identically once implemented" |
| `SchemaProjection::compile_from_directory` does not walk real Schema NC | Medium | Certain (today) | Wave 4b FDB walk; until then, custom attributes silently tolerated via ADR-078 dynamic fallback |

## Recommendations for v0.6.0

Prioritized by wire-compat gap closure:

1. **(P0) Implement the DCE/RPC server endpoint (`DceRpcEndpoint::run`).** The transport primitives are real and tested — this is a thin `tokio::net::TcpListener` + accept loop that reads Bind PDUs, sends BindAck via `pdu::encode_bind_ack_pdu`, dispatches Request PDUs to registered `DceRpcServer` impls. Estimated 1–2 person-weeks. Unblocks any DRSUAPI/SAMR/LSARPC/Netlogon/WCCE interop testing.

2. **(P0) Write a BER codec for LDAP.** Either extend the `rasn` usage or write a hand-rolled BER encoder/decoder covering RFC 4511 message types. Without this, `adrian-directory-service` cannot accept a single LDAP BindRequest. Estimated 2–3 person-weeks for codec + message type library. Remove `ldap3` from runtime deps of `adrian-directory-service`; move to dev-deps.

3. **(P0) Capture real wire fixtures.** Spin up a Windows Server 2022 lab DC + a Samba AD DC + an OpenLDAP server. Use `tcpdump`/Wireshark to capture: (a) DRSUAPI Bind/BindAck/DRSBind/DRSGetNCChanges sequence, (b) LDAP Bind/Search/Add/Modify sequence, (c) Kerberos AS-REQ/AS-REP/TGS-REQ/TGS-REP. Commit the `.bin` fixtures and write byte-comparison tests. This is the single highest-leverage investment for closing the wire-compat gap — it converts "byte-exact against the spec text" into "byte-exact against real Windows". Estimated 1 person-week.

4. **(P1) Replace `ManualRaftReplicator` with `openraft::Raft<...>`.** The openraft seam types exist (`to_openraft_log_id`, `to_openraft_vote`). Implement `RaftLogStore` over FDB subspace 0x05, `RaftStateMachine` over the directory store, `RaftNetwork` over `tokio::net::TcpStream`. This eliminates the commit-without-quorum bug and the in-memory-log data-loss risk in one stroke. Estimated 3–4 person-weeks.

5. **(P1) Implement DRSBind + DRSGetNCChanges stubs that actually decode/encode NDR.** Even if the FDB-backed `get_changes` is not yet wired, having the NDR types for `DRS_EXTENSIONS`, `DRS_BIND_RESULT`, `REPLENTIN_V3`, `REPLVALINF_V3` defined and round-trip tested against captured bytes is the foundation for all DRSUAPI work. Estimated 4–6 person-weeks (REPLVALINF_V3 alone is hundreds of fields).

6. **(P1) Implement the real Schema NC walker in `adrian-schema-compiler`.** Replace the `minimal_schema()` fallback with a real range scan over FDB subspace 0x01 filtering on `objectClass=attributeSchema`/`classSchema`. Parse `attributeID`/`governsID` OID strings into the numeric `AttributeId`/`ClassId`. Resolve superior/must_contain/may_contain by name → ID. Estimated 2 person-weeks.

7. **(P2) Implement RPC security (SPNEGO over Kerberos) in `adrian-dcerpc`.** Auth trailer encoding/decoding per MS-RPCE §2.2.2.8; auth_level negotiation (none/connect/call/pkt_integrity/pkt_privacy); integrate with `adrian-kdc` for the Kerberos side. Required for any AD-interop beyond anonymous binds. Estimated 3–4 person-weeks.

8. **(P2) Implement the missing 7 DCE/RPC PDU types** (Fault, Bind_nak, Alter_context, Alter_context_resp, Auth3, Shutdown, Orphaned). Each is small (10–50 lines) but needed for robust interop. Estimated 1 person-week.

9. **(P2) Reword aspirational doc comments.** Replace "Emits REPLVALINF_V3 byte-identically" with "Intended to emit REPLVALINF_V3 byte-identically once implemented (Wave 4b)". Replace "Implements LDAPv3 server-side on TCP/389" with "Will implement LDAPv3 server-side on TCP/389 once the BER codec and TCP listener are wired". Replace "openraft-based native replication" with "openraft-seam native replication (openraft driver wiring is Wave 4b)". Estimated 2 hours.

10. **(P3) Add `SearchFlags`/`SystemFlags` validation to `validate_object`.** Check that constructed attributes (fATTR_IS_CONSTRUCTED) are not written by clients; check that `fCONFIDENTIAL` attributes require `CONTROL_ACCESS` right. Estimated 1 person-week.
