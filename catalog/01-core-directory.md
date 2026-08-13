---
title: Core Directory Service — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, core-directory, framework-design, gap-analysis]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./02-kdc.md
  - ./03-auth-provider.md
  - ./04-policy-engine.md
  - ./13-open-research-questions.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Core Directory Service — Problem Catalog

**Capability definition**: Stores identity, configuration, and policy objects in a replicated, multi-master directory. Exposes query/modify via LDAP. Exposes replication via DRSUAPI (if AD-interop) or a new protocol (if clean-slate). Inherits from AD DS (`ntdsa.dll` DSA + ESE database + DRSUAPI replication + LDAP server + GC). Consumed by KDC, Auth Provider, Policy Engine, Cert Service, Federation Gateway, File Gateway, and the Client SDK. Foundation capability — every other subsystem depends on this one.

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-001 | DRSUAPI replication protocol must be implemented in the framework's DC | blocker | cross-platform |
| PC-002 | USN / InvocationID / UTD-vector replication model is unique to AD; alternatives must preserve rollback semantics | blocker | cross-platform |
| PC-003 | Linked Value Replication (LVR) required for groups larger than ~5,000 members | high | cross-platform |
| PC-004 | `member` / `memberOf` back-link requires linkID pairing and DSA-computed construction | blocker | cross-platform |
| PC-005 | Global Catalog partial-attribute-set replication must be implemented | high | cross-platform |
| PC-006 | Schema cache reload blocks LDAP writes for 5–30 seconds | medium | Windows |
| PC-007 | ESE / JET Blue database is Windows-only; framework must pick a new storage engine | blocker | cross-platform |
| PC-008 | Security descriptor deduplication (`sdtable`) required for large directories | medium | cross-platform |
| PC-009 | Tombstone lifetime and lingering-object cleanup must be designed | high | cross-platform |
| PC-010 | Cross-domain move requires `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` and PDC + RID coordination | medium | cross-platform |
| PC-011 | Well-known container GUIDs are forest-wide constants | medium | cross-platform |
| PC-012 | AD-specific LDAP controls required for client interop | high | cross-platform |
| PC-013 | `unicodePwd` BER-quote trick for password changes is AD-specific | medium | cross-platform |
| PC-014 | FSMO roles are single-master bottlenecks; seizure is destructive | high | Windows, cross-platform |
| PC-015 | RID pool allocation is a 500-RID batch bottleneck | high | cross-platform |
| PC-016 | KCC topology generation every 15 minutes has scaling limits | medium | cross-platform |
| PC-017 | Schema is LDAP-schema with OIDs; typed-schema alternative requires migration tooling | high | cross-platform |
| PC-018 | Constructed attributes (`memberOf`, `tokenGroups`, `canonicalName`) require DSA-side computation | high | cross-platform |
| PC-019 | AD-integrated DNS zones replicate via DRSUAPI in DomainDnsZones / ForestDnsZones NCs | high | cross-platform |
| PC-020 | `NTDS.DIT` backup / restore requires VSS-aware snapshots | high | cross-platform |
| PC-021 | `instanceType` and `systemFlags` are complex bitmasks gating object behavior | medium | cross-platform |
| PC-022 | Multi-tenancy is not native to AD; framework must decide whether to support it | high | cross-platform |

---

## Detailed problem entries

### PC-001 — DRSUAPI replication protocol must be implemented in the framework's DC

**Capability**: Core Directory
**Severity**: blocker
**Cross-platform**: Windows / Linux / cross-platform

**Problem statement**:

AD replication is implemented by DRSUAPI (`[uuid(E3514235-8B63-11D0-A26C-00A0C92B955C), version(4.0)]`), a DCE/RPC interface whose IDL is published in MS-DRSR §4. The replication workhorse is `DRSGetNCChanges` (opnum 3), a state-based pull protocol: a destination DC issues a request carrying its UTD vector and high-watermark cursor for a given NC, and the source DC responds with an NDR-encoded `DRS_MSG_GETCHGREPLY_V11` containing `REPLENTIN` / `ENTINF` / `PROPENT` chains, optionally LZ-compressed (the `DRS_EXT_GETCHG_DEFLATE` capability flag negotiated in `DRSBind`'s `DRS_EXTENSIONS_INT.dwFlags`). The interface also includes 23 other methods (`DRSReplicaSync`, `DRSCrackNames`, `DRSWriteSPN`, `DRSAddEntry`, `DRSExecuteKCC`, `DRSGetReplInfo`, `DRSAddSidHistory`, etc.) that are exercised by `ntdsutil`, `repadmin`, `kcc`, `movetree`, and dcpromo per the analysis in [02-protocols/06-rpc-dcerpc-ms-drsr.md](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md).

Samba 4's `source4/rpc_server/drsuapi/` (in particular `getncchanges.c`, `addentry.c`, `uptodateness_vector.c`) is the only open-source server implementation that speaks the wire protocol and survives the bidirectional interop tests with Windows DCs. FreeIPA uses 389-DS Multi-Master Replication over LDAP, which is not wire-compatible with MS-DRSR — FreeIPA ↔ AD integration works only via forest trust + cross-realm Kerberos, not via replication. OpenLDAP uses SYNCREPL (RFC 4533), also incompatible. MIT krb5 / Heimdal do not implement DRSUAPI at all per the comparison in [10-comparison-matrices/02-protocol-implementation-matrix.md](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md).

A framework that wants to peer-replicate with an existing AD forest (the AD-interop scenario) must either (a) implement DRSUAPI server-side from MS-DRSR §4, including the full `DRS_EXTENSIONS_INT` capability negotiation (BASE, ASYNCREPL, GETCHG_DEFLATE, GETCHG_REQ_V6/V8/V10/V11, CRYPTO_BIND, STRONG_ENCRYPTION, RECYCLE_BIN), (b) reuse Samba's implementation under GPLv3, or (c) design a clean-slate replication protocol (Raft, CRDT, operation-based push) and accept loss of AD interop. Each `REPLENTIN` packet also carries a `PROPERTY_META_DATA_EXT` blob per attribute (`dwVersion`, `uuidLastOriginatingDsa`, `usnOriginatingChange`, `ftimeLastOriginatingChange`), and the framework must round-trip this metadata exactly — AD's conflict-resolution logic depends on per-attribute version vectors, not last-writer-wins on the object per [03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

**Impact**:

Breaks AD interop entirely. Without a DRSUAPI server, the framework cannot be a peer DC in an existing forest — Windows DCs will refuse to replicate with it (`ERROR_DS_DRA_BAD_DN` / `RPC_S_PROTOCOL_ERROR`). Cross-vendor multi-master replication is impossible; only forest-trust + Kerberos cross-realm (the FreeIPA model) is available, which loses: schema unification, GC, universal-group membership, fine-grained password policy inheritance, and bidirectional SID history. DCSync-style tooling (`impacket/secretsdump.py`) that reads directory secrets via `DRSGetNCChanges` will not work against the framework's DCs.

**Constraints**:

- Must remain NDR-wire-compatible with MS-DRSR §4 for AD-interop scenarios, including the LZ-Express compression algorithm (`lzxpress.c` in Samba, `MDSCompressionUncompress` in `ntdsa.dll`).
- Must handle `REPLENTIN_V3`/`V6`/`V8`/`V10`/`V11` version skew — Windows DCs negotiate the highest mutually-supported version in `DRS_EXTENSIONS_INT.dwFlags`.
- Must support PKT_PRIVACY auth (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6`) via SPNEGO (Kerberos preferred, NTLM legacy).
- Must register the `E3514235-8B63-11D0-A26C-00A0C92B955C` interface on the endpoint mapper (TCP 135) and optionally `\pipe\drsuapi` over SMB.

**Cross-platform considerations**:

- **Windows**: Native — `ntdsa.dll` exports the server stub; `ntdsapi.dll` ships the client stub. RPCSS registers the dynamic port. No third-party code needed.
- **macOS**: Apple has no native DCE/RPC. Samba built via Homebrew provides `rpcclient` and `samba-tool` but no DC mode. The framework's macOS DC role would need a fresh DCE/RPC stack.
- **Linux**: Samba 4's `source4/rpc_server/drsuapi/` is the reference open-source implementation, but it's GPLv3 — incompatible with a proprietary framework. MIT krb5's `libgssrpc` provides only the RPC runtime, not a DRSUAPI server. Impacket (`impacket/dcerpc/v5/drsuapi.py`) is a Python client only.
- **Cross-platform consistency**: Wire-level interop is achievable; the question is whether to ship a server stack on every DC or only on DCs that need AD interop.

**KB references**:

- [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI interface specification, NDR encoding, opnum table, `DRS_EXTENSIONS_INT` capability flags.
- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — USN/UTD vector mechanics, `PROPERTY_META_DATA_EXT`, LVR, strict consistency.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — DSA process model, `DRS_EXTENSIONS` boot negotiation, `DRSCrackNames` formats.
- [`10-comparison-matrices/02-protocol-implementation-matrix.md`](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md) — Cross-vendor implementation status.

**Open questions**:

- Should the framework adopt Samba's DRSUAPI code under GPLv3 (forcing the framework to GPL) or write a fresh implementation under a permissive license?
- Is there a path to CRDT/OT replication that still speaks DRSUAPI on the wire — i.e. a DRSUAPI adapter over a CRDT store?
- What is the minimum viable interop scenario: full peer DC, RODC-equivalent (inbound-replication-only), or member-only (no replication at all)?
- Can the framework ship DRSUAPI as an optional sidecar module, loaded only when AD-interop mode is enabled?

**Cross-capability impact**:

- Affects: PC-030 (krbtgt rotation) — replication of the krbtgt account's `unicodePwd` must be atomic and urgent.
- Affects: PC-031 (SPN uniqueness) — `DRSWriteSPN` opnum 13 is the wire-level enforcement point.
- Affected by: PC-007 (storage engine) — replication depends on storage transaction semantics for atomic NC writes.

---

### PC-002 — USN / InvocationID / UTD-vector replication model is unique to AD; alternatives must preserve rollback semantics

**Capability**: Core Directory
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

AD's replication correctness rests on a four-tuple: per-DC `usnChanged` (monotonic 64-bit counter allocated inside the ESE transaction in `ntdsa.dll!DBUpdateRecUsn`, persisted at `DBHEADER.usnLast` offset 0x118 of `ntds.dit`), per-DC `invocationId` (UUID regenerated on USN-rollback detection or by `repadmin /kcc -resetinvocationid`, persisted on the NTDS Settings object as OID `1.2.840.113556.1.4.124`), per-NC up-to-dateness (UTD) vector (set of `{InvocationID, USN}` tuples encoding the highest-seen USN per originating DSA), and per-NC high-watermark cursor (the `{InvocationID, USN}` pair last pulled from each partner). Together these implement idempotent replication with rollback protection per the analysis in [03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

Rollback detection is the subtle part. When a partner DC's `invocationId` differs from what the source remembers, the source discards all state about that partner and re-initializes the UTD vector (treating the partner as a fresh replica). When a partner's advertised high-watermark is *lower* than the stored cursor (`D_usn_current < D_usnHighPropUpdate`), `ntdsa.dll!CheckUsnRollback` quarantines the partner and logs event 2095. Recovery requires demote + metadata cleanup + re-promote, or `repadmin /kcc -resetinvocationid` as a last resort per [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md).

Any new replication protocol (CRDT, OT, Raft) must preserve all three properties: (a) rollback detection — restored DCs must not silently resume from a stale USN; (b) idempotency — re-replication of the same change must be a no-op; (c) per-attribute `PROPERTY_META_DATA_EXT` with `dwVersion` (incremented per originating write), `uuidLastOriginatingDsa` (the originator's `invocationId`), `usnOriginatingChange`, and `ftimeLastOriginatingChange`. Existing alternatives do not provide all three: Raft's log truncation gives consistency but loses per-attribute originating metadata; 389-DS MMR uses a vector clock but without per-attribute versioning; OpenLDAP SYNCREPL uses a state cookie without rollback detection.

**Impact**:

Silent data divergence if any of the three is lost. A restored DC that advertises its old `invocationId` will be treated as up-to-date by partners and will silently fail to receive any new changes — the classic "USN rollback" scenario. Without per-attribute metadata, conflict resolution degenerates to last-writer-wins on the entire object, which loses attribute-level intent (e.g. an admin setting `description` while a replication partner sets `telephoneNumber` — both should win).

**Constraints**:

- Must interop with AD DCs — preserve `invocationId` semantics on the wire (the `DRS_MSG_GETCHGREQ_V11.uuidInvocIdSrc` and `uuidDsaObjDest` fields).
- Must preserve per-attribute `PROPERTY_META_DATA_EXT` for AD-aware conflict resolution. AD's resolver picks the higher `dwVersion` wins; equal versions → higher `usnOriginatingChange` wins; equal USN → higher `ftimeLastOriginatingChange` wins.
- Must support strict replication consistency (`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Strict Replication Consistency = 1`) — quarantine stale partners rather than re-seed.

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll!CheckUsnRollback` implements detection; `repadmin /showutdvec` exposes the UTD vector per NC.
- **macOS**: No equivalent; OpenDirectory has no multi-master replication and no rollback detection. The framework's macOS DC would need to implement the algorithm from scratch.
- **Linux**: Samba 4 reimplements the algorithm in `source4/rpc_server/drsuapi/uptodateness_vector.c` and `source4/dsdb/repl/replicated_object.c`. FreeIPA / 389-DS use a vector clock but no `invocationId` reset on rollback.
- **Cross-platform consistency**: The wire format (UTD vector in `DRSGetNCChanges` request) must be byte-identical for AD interop; the in-memory representation is implementation-specific.

**KB references**:

- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — Full UTD vector IDL, USN rollback detection algorithm, strict consistency registry.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `DBHEADER.usnLast`, `DBUpdateRecUsn`, transaction commit path.

**Open questions**:

- Can `PROPERTY_META_DATA_EXT` be expressed as a CRDT tombstone vector? The four fields map roughly to `(originator_id, op_seq, logical_time, version)` — the question is whether CRDT merge semantics subsume the AD resolver's tiebreak rules.
- Does a Raft log naturally subsume the UTD vector? The Raft log gives a total order per term, but AD's vector is per-attribute-per-originator — much finer-grained.
- If the framework moves to a consensus-based model, what is the analog of `invocationId` reset? Is it the leader's term number, or a separate "node generation" counter?

**Cross-capability impact**:

- Affects: PC-009 (tombstone lifetime) — UTD vector entries must be GC'd when their originator's tombstone expires.
- Affects: PC-020 (VSS-aware backup) — restore must reset `invocationId` or partners will quarantine.
- Affected by: PC-007 (storage engine) — the storage layer must expose transaction-bound USN allocation.

---

### PC-003 — Linked Value Replication (LVR) required for groups larger than ~5,000 members

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

Before Server 2003 SP1, a single value add to a multi-valued linked attribute (e.g. adding one user to a 10,000-member group) caused the *entire* attribute set to replicate on the wire — 10,000 `member` values per change. The practical ceiling for group size was ~5,000 members because each modification saturated replication links. LVR (Linked Value Replication), introduced in Server 2003 SP1 (schema `objectVersion` 31+), splits multi-valued linked attributes into per-value `REPLVALINF_V3` records: each add or delete is one record carrying the value DN, the add/delete flag, and the per-value `PROPERTY_META_DATA_EXT` per [03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

The wire format is the `REPLVALINF_V3` structure inside `REPLENTIN_V3.pValues`. Each entry contains `pNameObject` (the object whose attribute is changing), `attrVal` (the value DN), `fIsPresent` (TRUE = add, FALSE = delete), and `MetaData` (originating DC + USN + version). The DSA at the destination applies each entry independently to its `linktable` (in AD's ESE store) or equivalent linked-value store per [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md).

LVR eligibility is gated by two schema conditions: the attribute's `linkID` must be non-zero (forward links are even, backlinks are forward+1) AND `systemFlags` must have `FLAG_ATTR_IS_LINKED` (bit 8, mask 0x100). Pre-LVR forests (schema < 31) cannot use LVR even if the DCs are modern. A new framework that supports large groups must replicate LVR-equivalent semantics or accept the same ~5,000-member ceiling per [03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

**Impact**:

Large-group operations become a replication bottleneck without LVR. Adding one user to a 50,000-member group (common for `Domain Users` variants in big enterprises, or for distribution lists) replicates 50,000 values instead of one — a 10 MB replication payload instead of 200 bytes. Back-link construction (`memberOf` for the added user) is also slow without per-value replication because the destination must recompute the entire back-link set. At scale, the practical ceiling is ~5,000 members per group; beyond that, replication latency and `linktable` bloat dominate.

**Constraints**:

- `linkID` pairing in schema (forward = even, backlink = forward+1) must be preserved — `member` (linkID=3) → `memberOf` (linkID=4), `managedBy` (linkID=1) → `managedObjects` (linkID=2), etc.
- Back-link is computed, never directly writable. LDAP clients that write `memberOf` get `unwillingToPerform` (53).
- `REPLVALINF_V3` version is negotiated via `DRS_EXT_GETCHGREQ_V8` (0x40) in `DRS_EXTENSIONS_INT.dwFlags`.
- For AD interop, the framework must accept and produce `REPLVALINF_V3` records on the wire.

**Cross-platform considerations**:

- **Windows**: Native since Server 2003 SP1. `ntdsa.dll` writes per-value records to `linktable`; `DRSGetNCChanges` serializes them as `REPLVALINF_V3`.
- **macOS**: OpenDirectory has no LVR-equivalent; group membership is single-valued per replica.
- **Linux**: Samba 4 implements LVR in `source4/dsdb/samdb/ldb_modules/repl_meta_data.c` and is interoperable with AD. 389-DS / FreeIPA replicate per-value natively (their own MMR protocol). OpenLDAP with back-`mdb` stores multi-valued attributes as separate rows but has no LVR-equivalent replication.
- **Cross-platform consistency**: Wire-level `REPLVALINF_V3` must be byte-identical for AD interop; the in-memory representation can differ.

**KB references**:

- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — `REPLVALINF_V3` IDL, `PROPERTY_META_DATA_EXT`, LVR schema-version gate.
- [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md) — `linkID` pairing, `FLAG_ATTR_IS_LINKED`, `systemFlags` bitmask.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `linktable` schema, `backlinkDNT` reverse index.

**Open questions**:

- Should the framework keep the `linkID` pair model or replace it with a graph database (Neo4j-style) for membership? Graph storage would let group expansion be O(log n) instead of O(m) where m = group size.
- Is the 5,000-member ceiling still relevant for clean-slate deployments? Modern LDAP servers (389-DS, OpenLDAP) handle 100K-member groups natively.
- Can LVR be expressed as a CRDT OR-set (add-only / remove-only / add-wins)?

**Cross-capability impact**:

- Affects: PC-018 (`tokenGroups` constructed attribute) — recursive group expansion reads `linktable`; without LVR the read path is O(group size).
- Affected by: PC-007 (storage engine) — `linktable` is a separate table in ESE; the framework's storage must support an equivalent indexed linked-value store.

---

### PC-004 — `member` / `memberOf` back-link requires linkID pairing and DSA-computed construction

**Capability**: Core Directory
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

`member` is a forward link (`linkID=3`) on the group object; `memberOf` is the back-link (`linkID=4`) on the user object. The DSA computes `memberOf` at write time — when a client adds a user DN to a group's `member` attribute, `ntdsa.dll` writes one row to `linktable` (`linkDNT` = group DNT, `backlinkDNT` = user DNT) and the `memberOf` value for the user is materialized either at read time (constructed attribute, `FLAG_ATTR_IS_CONSTRUCTED`) or pre-computed in `linktable`'s reverse index per [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md). Clients cannot write `memberOf` directly; the DSA rejects with `unwillingToPerform (53)`. The linkID pairing is hardcoded in the schema: `CN=member,CN=Schema,...,linkID=3` and `CN=memberOf,...,linkID=4` per [03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

This bidirectional link is fundamental to AD's identity model. Every AD-aware application that asks "what groups is this user in?" reads `memberOf`. Exchange, SharePoint, ADUC, every custom LDAP app, and the Kerberos PAC's `GroupIds` / `ExtraSids` fields all depend on it. The Kerberos KDC's PAC builder walks `memberOf` recursively to compute `tokenGroups` for the user's ticket per [03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md). A framework that wants typed/SQL-backed schema must still implement this bidirectional link or break every AD application.

The mechanics of the computation are non-trivial: the DSA must update the back-link atomically with the forward-link write (within the same ESE transaction), the back-link must be replicated alongside the forward-link as part of LVR (`REPLVALINF_V3` for both sides), and the back-link must be invalidated when the forward-link is deleted (which can happen via tombstone of the group, tombstone of the user, or direct `member` value removal).

**Impact**:

Every AD-aware application breaks without `memberOf`. Exchange cannot route mail to distribution groups; SharePoint cannot resolve site-collection permissions; ADUC shows users as members of zero groups; custom LDAP apps that filter `(memberOf=CN=Admins,...)` return zero results. The Kerberos KDC cannot build a correct PAC (no `GroupIds`, no `ExtraSids`), so authorization decisions based on group membership fail silently — users appear to be in no groups.

**Constraints**:

- `memberOf` must be transparent to LDAP clients reading it — they must see it as a multi-valued DN-syntax attribute populated by the DSA.
- Must support both constructed-at-read-time (low storage cost, high read cost) and stored-materialized (high storage cost, low read cost) forms. AD uses stored for `memberOf` and constructed for `tokenGroups`.
- Back-link must be transactionally consistent with forward-link — no window where `member` is set but `memberOf` is not.
- For AD interop, the schema must define `member` (`attributeID` `1.2.840.113556.1.4.138`? — actually `member` is `2.5.4.31`) and `memberOf` (`2.5.4.35`) with `linkID` 3 and 4 respectively.

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll` writes to `linktable`; `ntdsa.dll!ABSearch` resolves back-links at query time.
- **macOS**: OpenDirectory has no `memberOf` equivalent; apps must walk group membership explicitly. The framework's macOS DC must synthesize `memberOf` for AD-aware clients.
- **Linux**: Samba 4 implements `memberOf` in `source4/dsdb/samdb/ldb_modules/memberof.c`. OpenLDAP has the `memberOf` overlay (`slapd-memberof`) that materializes back-links at write time — a possible reference implementation. 389-DS has the same via the `memberOf` plugin.
- **Cross-platform consistency**: LDAP wire format must be identical for AD interop. Internal representation can differ.

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `linktable` schema, `linkDNT` / `backlinkDNT` columns, `linkbase` encoding.
- [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md) — `linkID` pairing table (member/memberOf=3/4, managedBy/managedObjects=1/2, directReports/manager=8/9).

**Open questions**:

- Is graph storage (Neo4j, Dgraph, JanusGraph) better than `linktable` for back-link materialization? Graph stores handle transitive closure in O(log n) vs AD's O(group count × group size).
- What is the cost of computing `memberOf` at read time vs storing it? At scale (1M users × avg 50 group memberships), the stored form costs ~50M `linktable` rows; the constructed form costs ~50ms per query.
- Should the framework generalize `linkID` to N-ary links (e.g. for resource-based constrained delegation `msDS-AllowedToActOnBehalfOfOtherIdentity`, which is linkID-paired but conceptually different)?

**Cross-capability impact**:

- Affects: PC-018 (`tokenGroups` constructed attribute) — depends on `memberOf` walk.
- Affects: KDC's PAC generation (PC-023) — `GroupIds` and `ExtraSids` in `KERB_VALIDATION_INFO` come from the `memberOf` transitive closure.

---

### PC-005 — Global Catalog partial-attribute-set replication must be implemented

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

The Global Catalog (GC) is a partial-attribute read-only replica of every naming context in the forest, hosted on a designated DC where the NTDS Settings object has `msDS-IsGlobalCatalogReady=TRUE`, listening on TCP/3268 (LDAP) and TCP/3269 (LDAPS) per [03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md). The partial attribute set (PAS) is defined per-attributeSchema by `isMemberOfPartialAttributeSet=TRUE` (OID `1.2.840.113556.1.4.1427`). Base-schema attributes in the PAS include `objectClass`, `cn`, `sAMAccountName`, `userPrincipalName`, `displayName`, `mail`, `proxyAddresses`, `memberOf`, `objectGUID`, `objectSid`, `sIDHistory`, `primaryGroupID`. GCs are required for cross-domain searches: UPN lookup, GAL (Global Address List), recursive group membership expansion, and Kerberos PAC `ExtraSids` for cross-domain resource groups.

GC promotion is a multi-step process: set `options |= 0x1` (`NTDSSETTINGS_OPT_IS_GC`) on the NTDS Settings object; KCC (`ntdskcc.dll!KRCCGCVerifyGCs`) computes missing partial NC replicas; DSA pulls each missing NC via `DRSGetNCChanges` with `ulFlags = DRS_GET_NC_SIZE | DRS_SYNC_REPL` and the partial-NC flag, which causes the source's `REPLENTIN` filter (`ntdsa.dll!FilterReplAttr`) to drop non-PAS attributes on the wire; DSA verifies all PAS-bearing NCs are fully synchronized; DSA sets `msDS-IsGlobalCatalogReady=TRUE`; publishes `_ldap._tcp.gc._msdcs.<forest>` SRV records; registers `GC/<host>` and `GC/<host>/<forest-root-dns>` SPNs on the computer account per [03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md).

The framework needs a GC-equivalent for cross-domain searches (UPN lookup, GAL, recursive group membership) and for the Kerberos KDC's PAC `ExtraSids` construction. Without it, cross-domain queries (`ldap://dc:3268`) fail; universal-group membership expansion breaks; the framework cannot serve as the KDC's source for cross-domain group SIDs.

**Impact**:

Cross-domain queries against port 3268 fail (`operationsError`). Universal group membership expansion breaks — users in domain A who are members of a universal group in domain B do not get the group's SID in their PAC. UPN-based lookups (the most common form of cross-domain identity resolution) require a full-forest LDAP walk instead of a single GC query. Exchange address book queries (`GAL`) require per-domain LDAP queries. Universal Group Caching (UDC) is the partial alternative but only works for already-authenticated users in a known site.

**Constraints**:

- Must support PAS filter on `DRSGetNCChanges` — the wire-level `ulFlags` must include `DRS_FULL_SYNC_PARTIAL` and the source's `FilterReplAttr` must honor `isMemberOfPartialAttributeSet`.
- Must support `_ldap._tcp.gc._msdcs.<forest>` and `_ldap._tcp.<site>._sites.gc._msdcs.<forest>` SRV records.
- Must register `GC/<host>` SPN for Kerberos clients to authenticate to the GC service.
- For AD interop, the PAS membership must be identical to AD's default PAS, including the `msExch*` attributes Exchange adds.

**Cross-platform considerations**:

- **Windows**: Native — `ntdsa.dll` plus `netlogon.dll` SRV registration plus `ntdskcc.dll` topology.
- **macOS**: No GC concept. The framework's macOS DC role would need to implement port 3268 listener and the GC promotion lifecycle.
- **Linux**: Samba 4 implements GC in `source4/dsdb/samdb/ldb_modules/global_catalog.c`. SSSD's `ad_provider` queries the GC for cross-domain group memberships (`ad_gc.py`) — set `ad_enable_gc = True` (default) in `sssd.conf`.
- **Cross-platform consistency**: The wire-level PAS filter on `DRSGetNCChanges` must be byte-identical for AD interop.

**KB references**:

- [`03-directory-schema/03-global-catalog.md`](../docs/03-directory-schema/03-global-catalog.md) — PAS membership table, GC promotion lifecycle, SRV record format, UDC alternative.
- [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md) — Forest topology, cross-domain query patterns.

**Open questions**:

- Can a single global store (e.g. a per-forest CockroachDB / FoundationDB / Spanner cluster) replace the PAS replica concept entirely? If so, what about bandwidth on large forests — a 100-domain forest with 1M users per domain is 100M objects, and a global query fan-out may be more expensive than the current GC.
- If the framework moves to a single-domain-forest model (collapsing the forest/domain distinction), is the GC still needed?
- Should UDC replace the GC for branch-office scenarios, with the framework's GC-equivalent living only in hub sites?

**Cross-capability impact**:

- Affects: KDC PC-023 — KDC's PAC `ExtraSids` construction reads the GC for cross-domain universal groups.
- Affects: KDC PC-028 — cross-realm TGT referral chains depend on GC for realm lookup.
- Affected by: PC-001 (DRSUAPI) — GC content replicates via DRSUAPI; partial-NC flag is the wire-level gate.

---

### PC-006 — Schema cache reload blocks LDAP writes for 5–30 seconds

**Capability**: Core Directory
**Severity**: medium
**Cross-platform**: Windows

**Problem statement**:

`ntdsa.dll` keeps the schema in an in-memory `g_SchemaCache` hash table (`THashTable<SchemaClass>` keyed by `governsID`). The cache is loaded at boot from `CN=Schema,CN=Configuration,<forest-root-dn>` and refreshed whenever the operational attribute `schemaUpdateNow` (write to `CN=Aggregate,CN=Schema,...`) is invoked. The reload is single-threaded: `ntdsa.dll!SCCacheRefresh` acquires the schema cache lock, walks the entire Schema NC, rebuilds the hash table, swaps it in, and releases the lock. In-flight LDAP requests continue using the previous cache snapshot; new requests block until the reload completes per [00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) and [03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

On a mid-size forest (~2,000 schema attributes, ~500 classes), the reload takes 5–30 seconds. During this window, all LDAP writes block (reads continue using the cached schema). Schema extensions during maintenance windows cause noticeable write outages. CI/CD-style schema operations — e.g. an application deployment that adds a new attribute — are unworkable in their natural cadence because each schema modify triggers a reload.

A new framework should design schema reload to be lock-free (copy-on-write with atomic pointer swap, generation-numbered caches, MVCC) or use a more granular invalidation scheme (per-class or per-attribute invalidation rather than full reload). The trade-off is complexity: a partial-invalidation scheme must handle schema graph changes (e.g. adding a `mustContain` to a base class affects every subclass).

**Impact**:

Schema extensions during maintenance windows cause noticeable write outages. CI/CD-style schema ops are unworkable — a deployment pipeline that adds 5 new attributes would block writes for ~30 seconds per attribute × 5 = 2.5 minutes. Production AD deployments rarely extend schema more than once per quarter precisely because of this cost. For the framework's own schema evolution (each new feature adds attributes), the same cost applies unless the reload is redesigned.

**Constraints**:

- Schema cache must be transactionally consistent — in-flight writes must not see partial schema.
- Schema cache must support concurrent reads during reload (writes may block, reads must not).
- For AD interop, the framework must accept `schemaUpdateNow` writes and trigger a reload, but the reload mechanism itself is implementation-specific (not on the wire).

**Cross-platform considerations**:

- **Windows**: The blocker is `ntdsa.dll!SCCacheRefresh` — single-threaded, full-reload. No workaround in AD; the only mitigation is "do schema changes during maintenance windows."
- **macOS**: OpenDirectory's `slapd` has a similar reload pattern (less frequent, smaller schema). The framework's macOS DC can do better — copy-on-write schema cache with generation numbers is straightforward.
- **Linux**: 389-DS / OpenLDAP with `cn=config` backend supports online schema changes without blocking writes (per-attribute invalidation). Samba 4 has a similar issue to AD — `source4/dsdb/schema/schema_set.c` reloads the entire schema.
- **Cross-platform consistency**: The user-visible behavior (LDAP write returns `unwillingToPerform` during reload, or blocks) must be consistent across DCs.

**KB references**:

- [`00-overview/02-ad-architecture.md`](../docs/00-overview/02-ad-architecture.md) — Schema cache reload behavior, single-threaded `gSchemaCache` rebuild.
- [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md) — `schemaUpdateNow` operational attribute, `SCCacheRefresh` internals.

**Open questions**:

- Can copy-on-write schema cache with generation numbers eliminate the lock? The cost is doubled memory during the swap window (~50 MB for a 5,000-attribute schema).
- Can the framework invalidate only the affected schema subgraph (e.g. just the modified class and its subclasses) instead of the entire cache?
- Should the framework support "hot" schema changes via a transactional schema-update protocol (atomic attribute-add + class-add + instance migration in one transaction)?

**Cross-capability impact**:

- Affects: PC-017 (schema design) — the schema-reload cost influences whether the framework can ship frequent schema updates.
- Affected by: PC-007 (storage engine) — copy-on-write schema cache benefits from storage-engine-level MVCC.

---

### PC-007 — ESE / JET Blue database is Windows-only; framework must pick a new storage engine

**Capability**: Core Directory
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

AD stores the DIT in `ntds.dit`, an ESE (Extensible Storage Engine, "Jet Blue") database with 32 KB page size (Server 2012+; previously 8 KB then 16 KB), implemented by `esent.dll`. ESE provides ISAM-style transactional access via `JetInit3`, `JetAttachDatabase`, `JetBeginTransaction`, `JetPrepareUpdate`, `JetSetColumn`, `JetUpdate`, `JetCommitTransaction`. The DIT contains ~50 tables: `datatable` (one row per AD object), `linktable` (linked-value attributes), `sdtable` (security descriptor dedup cache), `cursor` (per-NC UTD vector), `msysobjects` (ESE catalog) per [00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) and [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md). Page-level checksums are SHA-1 (post-Server 2012). Online backup is via VSS writer `{5425FD7A-0D43-4C59-AA61-D3D2D9E2B9D7}`.

Open-source alternatives: Samba uses TDB (Trivial Database, a hash-file store) and LDB (LDAP-over-TDB layer); FreeIPA / 389-DS uses BerkeleyDB-derived `libdb`; OpenLDAP uses LMDB (Lightning Memory DB, an mmap'd B+tree). None of these is identical to ESE in transactional semantics, page-level checksums, SD dedup, or replication integration. Each has different performance characteristics: TDB is single-file, no transactions, fine for small directories; BerkeleyDB is robust but slow on modern hardware; LMDB is fast but single-writer; modern LSM-tree stores (RocksDB, LevelDB, Cassandra) are fast for writes but require compaction tuning.

The framework must pick a storage engine that supports: (a) transactional writes with `BEGIN/COMMIT/ROLLBACK` and `WAL` (write-ahead log); (b) per-attribute metadata storage (`PROPERTY_META_DATA_EXT` per attribute per object); (c) SD deduplication (two objects with identical SDs share one row in `sdtable`, reference count `sdrefcount`); (d) page-level checksums for corruption detection; (e) online backup (snapshot the storage engine while it's running); (f) crash recovery (replay WAL on boot). SQLite (with WAL mode) provides (a), (e), (f) but not (c) or (d). FoundationDB provides (a), (b), (e), (f) and is horizontally scalable but introduces a dependency on an FDB cluster. RocksDB provides (a), (d), (e) but not (c) directly.

**Impact**:

Storage choice determines replication, backup, and recovery story. The wrong choice locks the framework into a scalability ceiling (TDB's ~1M-object limit) or a single-writer bottleneck (LMDB). Storage-engine-level page corruption (`JET_errDbTimeCorrupted`, ESE -1018 / -1022 errors) is the most common cause of AD DC death; the framework's storage must have equivalent corruption detection. Without SD dedup, every object lookup pays an SD hash compare — at 1M objects with unique SDs, that's 1M SD comparisons per query that does an SD eval.

**Constraints**:

- Must support VSS-equivalent snapshot for consistent backup — either storage-engine-native (RocksDB checkpoint, SQLite backup API, FoundationDB snapshot) or filesystem-level (LVM, ZFS, Btrfs snapshots).
- Must support page-level checksums for corruption detection — most modern engines do (LMDB, RocksDB, SQLite); TDB does not.
- Must support transactional USN allocation (PC-002) — the storage must expose a monotonic counter allocated inside the transaction.
- Must support `linktable`-equivalent indexed linked-value storage (PC-003, PC-004).
- Must support `sdtable`-equivalent SD dedup (PC-008) — either via storage-engine-level dedup or application-level.
- Must scale to 10M objects minimum for enterprise deployments; 100M+ for cloud-scale.

**Cross-platform considerations**:

- **Windows**: ESE is Windows-only (`esent.dll`); the framework cannot reuse it on macOS / Linux. There is an open-source ESE reader (`libesedb` by Joachim Metz) but no writer.
- **macOS**: SQLite ships system-wide; LMDB and RocksDB build cleanly. FoundationDB requires a separate cluster.
- **Linux**: All major engines (SQLite, LMDB, RocksDB, FoundationDB, CockroachDB, PostgreSQL) work. Samba 4 uses TDB+LDB; FreeIPA uses BerkeleyDB; OpenLDAP uses LMDB.
- **Cross-platform consistency**: The storage engine must work identically on all three platforms — same on-disk format, same transactional semantics, same backup API. Otherwise cross-DC backup/restore across OSes breaks.

**KB references**:

- [`00-overview/02-ad-architecture.md`](../docs/00-overview/02-ad-architecture.md) — `NTDS.DIT` internal layout, ESE page size, VSS writer GUID.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — ESE table schema (`datatable`, `linktable`, `sdtable`, `cursor`, `msysobjects`), transaction commit path, USN allocation.

**Open questions**:

- SQLite (simple, portable, WAL) vs FoundationDB (distributed, transactional, requires cluster) vs custom LSM-tree (RocksDB + custom dedup layer)? Each has trade-offs; pick one and justify.
- Can the framework support multiple storage engines (pluggable backends) like OpenLDAP does (`back-mdb`, `back-bdb`, `back-sql`)? Or is the storage-engine choice too tightly coupled to replication?
- For cloud-native deployments, is a distributed SQL store (CockroachDB, Spanner, TiDB) the right choice? The trade-off is latency — CockroachDB's p99 latency is 10–50ms vs ESE's <1ms.

**Cross-capability impact**:

- Affects: PC-001 (DRSUAPI) — replication depends on storage transaction semantics for atomic NC writes.
- Affects: PC-002 (UTD vector) — `cursor` table needs transactional updates.
- Affects: PC-008 (SD dedup) — needs `sdtable`-equivalent.
- Affects: PC-020 (backup/restore) — needs snapshot support.

---

### PC-008 — Security descriptor deduplication (`sdtable`) required for large directories

**Capability**: Core Directory
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD deduplicates security descriptors (SDs) across objects: two objects with identical `nTSecurityDescriptor` share one row in `sdtable`, with the reference count in `sdrefcount`. The DSA computes a 32-bit Murmur hash of the self-relative SD, looks up the hash in `sdtable`, and either reuses the existing row or allocates a new one. Lookup happens in `ntdsa.dll!SCGetSDFromCache` before falling through to allocation per [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md). The `sdtable` columns are `sdID` (PK), `sd` (binary self-relative SD), `sdHash` (32-bit Murmur), `sdrefcount` (number of objects referencing this SD).

Script-generated OUs with explicit per-OU ACEs bloat `sdtable` past 1M rows and slow SD evaluation. At 10M objects with mostly unique SDs, `sdtable` would be 10M rows × ~2 KB SD = 20 GB. SD evaluation is a hot path in authorization — every LDAP query that returns `nTSecurityDescriptor` (or filters on it) walks the SD's DACL. Without dedup, every object lookup pays an SD hash compare against the in-memory SD cache (typically ~1M entries), then falls through to disk.

A new framework should preserve SD dedup or accept the perf cost; either is a deliberate design choice. Modern hashing (BLAKE3) + a persistent hash-indexed map (e.g. RocksDB prefix-bloom-filter) would give O(1) dedup at the cost of an extra index. The trade-off is write complexity — every SD write must hash, look up, insert-or-increment-refcount, decrement-old-refcount, all within one transaction.

**Impact**:

SD evaluation is a hot path in authorization. Without dedup, every object lookup pays an SD hash compare. At 10M objects with unique SDs, the SD cache miss rate approaches 100%, and every lookup does a disk read. Scripted OU creation with explicit per-OU ACEs (common in some shops) creates 100K+ unique SDs; the framework's SD cache thrashes and authorization latency jumps from ~1ms to ~50ms.

**Constraints**:

- Must support `nTSecurityDescriptor` self-relative SD storage (the binary format defined in MS-DTYP §2.4.6).
- SD hash collision must be detected — two SDs with the same hash must compare byte-for-byte before dedup.
- Reference count must be transactionally consistent — an SD with `sdrefcount = 0` must be GC'd; an SD with `sdrefcount > 0` must not be GC'd.
- For AD interop, the SD on the wire must be byte-identical (so AD-aware tools that compare SDs work).

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll!SCGetSDFromCache` with 32-bit Murmur hash. `sdtable` is in `ntds.dit`.
- **macOS**: No equivalent in OpenDirectory. The framework's macOS DC would need to implement SD dedup.
- **Linux**: 389-DS / OpenLDAP / Samba 4 do not dedup SDs — every object stores its own SD. The framework's Linux DC would need to implement dedup if it wants AD-scale performance.
- **Cross-platform consistency**: The dedup algorithm is internal — the wire format is always the full SD.

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `sdtable` columns, `SCGetSDFromCache` lookup path, `sdrefcount` reference counting.
- [`00-overview/02-ad-architecture.md`](../docs/00-overview/02-ad-architecture.md) — `NTDS.DIT` table inventory, `sdtable` row in table list.

**Open questions**:

- Modern hashing (BLAKE3, CityHash64) vs the existing 32-bit Murmur? 32-bit Murmur has noticeable collision rate at 10M+ SDs; BLAKE3 with 256-bit output has effectively zero.
- Persistent hash-indexed map (RocksDB prefix-bloom-filter) vs in-memory hash table? Persistent map survives restart; in-memory requires warmup.
- Should the framework also dedup partial SD components (owner, group, SACL, DACL) separately? AD does not — the entire SD is dedup'd as one unit.

**Cross-capability impact**:

- Affects: PC-007 (storage engine) — `sdtable` is a separate table; the storage engine must support it.
- Affects: Policy Engine (PC-043) — GPO SDs benefit from the same dedup.

---

### PC-009 — Tombstone lifetime and lingering object cleanup must be designed

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD tombstones objects instead of deleting them outright: when an object is deleted, the DSA sets `isDeleted=TRUE`, moves the object to `CN=Deleted Objects,<NC>` (a normally-hidden container), preserves a minimal attribute set (`objectGUID`, `objectSid`, `sIDHistory`, `lastKnownParent`, `member` for tombstoned groups), and strips all other attributes. The tombstone persists for `tombstoneLifetime` days (default 180 days since Server 2003 SP1; older forests defaulted to 60). After `tombstoneLifetime`, the tombstone is garbage-collected (`ntdsa.dll!GarbageCollection` task) per [03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

If a partner DC is offline longer than `tombstoneLifetime`, strict replication consistency refuses to re-sync (event 2042 — "The DC has been offline for too long to be brought up-to-date"). The admin must run `repadmin /removelingeringobjects <src-dc> <dst-dc> <nc-dn> /advisory` to scan for stale objects, then run without `/advisory` to actually remove them. Without strict consistency, the stale DC could reintroduce deleted objects (a "lingering object" — an object deleted on one DC but still present on the stale DC, which then replicates it back to the rest of the forest). Lingering objects are subtle: they may have stale group memberships, stale SPNs, stale passwords — all of which cause intermittent auth failures and security risks.

A new framework needs an equivalent design or accepts eventual-consistency risks. CRDT-based replication handles tombstones natively (tombstones are explicit delete-tokens in the operation log); Raft-based replication uses log truncation (the log entry containing the delete is the tombstone, and it can be GC'd after a configurable retention period). Both approaches must answer: how long to retain tombstones? how to detect a partner that's been offline longer than the retention period? how to clean up lingering objects?

**Impact**:

Long-offline DCs can reintroduce deleted objects. Strict consistency quarantines them (event 2042) — the admin must manually intervene. Lingering objects cause: stale group memberships (user appears to be in a group that was deleted), stale SPNs (KDC issues tickets for a deleted service), stale passwords (user can log in with an old password). At scale (100+ DCs), lingering-object cleanup is a quarterly maintenance task; without tooling, it's a multi-day operation.

**Constraints**:

- Must support `tombstoneLifetime` configuration (per-NC, default 180 days).
- Must support lingering-object detection (compare UTD vectors; if a partner's vector is older than `tombstoneLifetime`, quarantine).
- Must support `repadmin /removelingeringobjects`-equivalent API for cleanup.
- For AD interop, the framework must produce tombstones on delete (the wire format includes `isDeleted`, `lastKnownParent`, and the preserved attribute set).
- Must support the Recycle Bin feature (Server 2008 R2+) — recycled objects go through two stages (deleted → recycled → physically deleted), allowing restore from either stage.

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll!GarbageCollection` runs every 12 hours by default; tombstone lifetime configurable via `CN=Directory Service,CN=Windows NT,CN=Services,...` `tombstoneLifetime` attribute.
- **macOS**: OpenDirectory has no tombstone concept; deleted objects are gone immediately. The framework's macOS DC must implement tombstones.
- **Linux**: 389-DS has tombstones (`nsTombstone` objectclass); OpenLDAP has no tombstone concept in core but `accesslog` overlay provides similar functionality. Samba 4 implements AD-compatible tombstones.
- **Cross-platform consistency**: Tombstone wire format must be AD-compatible for interop.

**KB references**:

- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — Tombstone lifetime, lingering object detection, event 2042, `repadmin /removelingeringobjects`.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `GarbageCollection` task, tombstone attribute preservation.

**Open questions**:

- Are tombstones needed in a CRDT design? CRDTs use operation logs with explicit delete-tokens; the question is how long to retain the log.
- What about a Raft log truncation strategy? The log entry containing the delete is the tombstone; GC happens after snapshot.
- Should the framework support the AD Recycle Bin (two-stage delete) for AD interop, or replace it with a different design (e.g. time-travel queries via MVCC)?

**Cross-capability impact**:

- Affects: PC-002 (UTD vector) — vector entries must be GC'd when their originator's tombstone expires.
- Affects: PC-020 (backup/restore) — restore must respect tombstone lifetime (restoring a backup older than `tombstoneLifetime` causes quarantine).

---

### PC-010 — Cross-domain move requires `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` and PDC + RID master coordination

**Capability**: Core Directory
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Moving an object within an NC is a standard LDAP ModifyDN operation (RFC 4511 §4.9). Moving an object *across* NCs (e.g. user from `corp.example.com` to `child.corp.example.com`) requires the `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` control (`1.2.840.113556.1.4.521`), carrying the target DC's NTDS Settings DN. The source DC reads the object's `nTSecurityDescriptor`, `sIDHistory`, group memberships, then calls DRSUAPI `DRSAddEntry` (opnum 17) against the target DC's `invocationId` to create the object in the target NC. The source DC then writes a tombstone with `lastKnownParent` set to the original parent DN per [03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md).

Cross-domain move has hard prerequisites: (1) domain functional level ≥ Windows 2000 native (no mixed mode); (2) PDC emulator reachable in both domains — the PDC performs urgent replication of the password; (3) RID master reachable in the target domain — the target DC needs a fresh RID for the moved object's `objectSid`? Actually, the SID is preserved across the move (the source domain's RID is kept in `sIDHistory`, and a new RID is allocated in the target domain). (4) Admin privilege on both source and target OUs. (5) SPN attribute values must be cleared first (`servicePrincipalName` is domain-scoped; cross-domain SPN causes duplicate-SPN conflicts per [03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md)). (6) Group memberships across NC boundaries are rewritten as foreign-SID references in `sIDHistory`.

A framework that supports multi-domain forests must implement cross-NC move semantics or document the limitation. In a single-domain forest (the modern recommended topology), cross-domain move is irrelevant. The framework should consider whether multi-domain support is a v1 requirement or a future capability.

**Impact**:

Multi-domain migration workflows (common in large enterprises) break. The `movetree.exe` tool, `Move-ADObject -TargetServer`, and any custom LDAP script using the cross-domain control all fail with `unwillingToPerform`. Group memberships across domains are lost in transit (the user's old memberships become foreign-SID references, which require explicit `sIDHistory` population).

**Constraints**:

- Must preserve SID across move (the user's RID stays the same; the domain prefix changes).
- Must rewrite cross-domain group memberships as foreign-SID references (the user appears in the target domain's group as `S-1-5-21-<old-domain>-<rid>` instead of a local DN).
- Must clear SPNs before move and re-add after move (or implement cross-domain SPN uniqueness check).
- Must coordinate with PDC emulator (urgent password replication) and RID master (RID allocation).

**Cross-platform considerations**:

- **Windows**: `movetree.exe` and `Move-ADObject -TargetServer` use the cross-domain control. `ntdsa.dll!SampModifyCrossDomainMove` implements the source-side logic.
- **macOS**: No equivalent in OpenDirectory. The framework's macOS DC would need to implement cross-NC move.
- **Linux**: Samba 4 implements cross-domain move (`samba-tool domain move`); 389-DS / FreeIPA have no cross-domain move concept (FreeIPA domains are independent).
- **Cross-platform consistency**: Wire format must be AD-compatible for interop.

**KB references**:

- [`03-directory-schema/02-ous-containers.md`](../docs/03-directory-schema/02-ous-containers.md) — `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` control format, move prerequisites, SPN-clear requirement.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `DRSAddEntry` opnum 17, `lastKnownParent` tombstone attribute.

**Open questions**:

- Is cross-domain move still relevant in a post-domain-forest design? Modern AD deployments increasingly consolidate into a single domain per forest.
- Should the framework collapse to a single domain (eliminating cross-domain move entirely) or support multi-domain for legacy interop?
- If multi-domain is supported, should `sIDHistory` be retained across moves, or replaced with a different cross-domain identity mechanism?

**Cross-capability impact**:

- Affects: PC-014 (FSMO roles) — cross-domain move requires PDC + RID master reachable.
- Affects: KDC PC-031 (SPN uniqueness) — SPNs must be cleared before move to avoid forest-wide duplicates.

---

### PC-011 — Well-known container GUIDs are forest-wide constants

**Capability**: Core Directory
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD binds a fixed set of well-known containers to NC heads via the `wellKnownObjects` and `msDS-WellKnownObjects` multi-valued attributes (both on the NC head object). Each entry is `B:32:<WKGUID>:<DN>`. The GUIDs are published in MS-ADTS §6.1.1 and are identical across all forests: `CN=Users` = `aa312825-683f-11d2-8d6c-001999999999`; `CN=Computers` = `a361b2bf-661b-4092-a59c-6e8ab9b9d919`; `CN=Deleted Objects` = `18e2ea80-84f1-11d2-9d4b-00c04f79f889`; `CN=System` = `30000000-66d7-4b81-bb2c-8e9b98f7d3f0`; `CN=LostAndFound` = `e458b0b0-ff42-4718-aa9b-df6e7c7a9a9a`; `CN=ForeignSecurityPrincipals` = `221ac1a7-6f24-4c89-8e68-26d2bf7822bb`; `CN=Infrastructure` = `2fbac1870ade11d297c400c04fd8d5cd`; `CN=Program Data` = `4bdf36c0-92f1-11d2-aee2-00c04f8e3c7f`; `CN=NTDS Quotas` = `a8d7a478-9f6b-4ea2-8d20-3a51e9f7a7e5`; `CN=Managed Service Accounts` = `1eb93889-e40c-46aa-bb97-fa32b925c1e0` per [03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md).

AD-aware clients use `<WKGUID=<guid>,<NC-dn>>` LDAP URLs to locate these containers portably without hardcoding the DN. Example: `ldap://dc01/<WKGUID=aa312825-683f-11d2-8d6c-001999999999,DC=corp,DC=example,DC=com>` resolves to `CN=Users,DC=corp,DC=example,DC=com`. This indirection matters because admins can rename `CN=Users` (technically possible, though rarely done) and the WKGUID binding still works.

A framework should preserve these GUIDs or document the incompatibility. Replacement with REST URLs (`/api/v1/well-known/Users`) is cleaner for greenfield deployments but breaks every AD-aware tool. A hybrid approach (LDAP WKGUID lookup translated to an internal REST URL) preserves interop at the cost of dual API surface.

**Impact**:

Tools that use WKGUID bindings break. This includes: `dsquery`, ADUC, `redirusr` / `redircmp` (which redirect default user/computer creation containers by manipulating `wellKnownObjects`), Exchange System Manager, and many third-party tools that locate `CN=System` for service-connection-point lookups. Without WKGUID support, these tools fall back to hardcoded DN guesses (`CN=Users,DC=...`), which fail when the admin has restructured the tree.

**Constraints**:

- WKGUID lookup must be supported at the DSA level — the LDAP server must resolve `<WKGUID=...,<NC-dn>>` to the actual DN before search.
- The `wellKnownObjects` and `msDS-WellKnownObjects` attributes must be writable by admins (to allow container redirection).
- For AD interop, the GUIDs must be the MS-ADTS §6.1.1 published values.

**Cross-platform considerations**:

- **Windows**: Native — `ntdsa.dll` resolves WKGUID in LDAP bind path.
- **macOS**: No equivalent. The framework's macOS DC must implement WKGUID resolution if it serves LDAP.
- **Linux**: Samba 4 implements WKGUID; 389-DS / OpenLDAP do not natively (would need an overlay).
- **Cross-platform consistency**: Wire format must be AD-compatible for interop.

**KB references**:

- [`03-directory-schema/02-ous-containers.md`](../docs/03-directory-schema/02-ous-containers.md) — Full WKGUID table, `wellKnownObjects` / `msDS-WellKnownObjects` attribute format, WKGUID binding syntax.

**Open questions**:

- Replace with REST URL `/api/v1/well-known/Users` for the framework's native API, with WKGUID as an LDAP-compat shim?
- Document as legacy LDAP-only — new clients use the REST API; AD-aware clients use WKGUID over LDAP?
- Should the framework support WKGUID redirection (admin can move `CN=Users` to `OU=Corp Users` and update `wellKnownObjects`)?

**Cross-capability impact**:

- Affects: Client SDK (PC-082, not in this catalog) — client API must expose well-known container lookup.
- Affects: Cert Service — `NTAuthCertificates` lives under `CN=Public Key Services,CN=Services,CN=Configuration,...`, located via WKGUID.

---

### PC-012 — AD-specific LDAP controls required for client interop

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD implements 25+ LDAP controls not part of RFC 4511, including: `LDAP_SERVER_TREE_DELETE_OID` (`1.2.840.113556.1.4.805`, atomic subtree delete), `LDAP_SERVER_DIRSYNC_OID` (`1.2.840.113556.1.4.841`, directory synchronization with cookie-based cursor), `LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.528`, control which SD parts are returned), `LDAP_SERVER_ASQ_OID` (`1.2.840.113556.1.4.1504`, attribute-scoped query), `LDAP_SERVER_RANGE_RETRIEVAL_OID` (`1.2.840.113556.1.4.802`, range retrieval for large multi-valued attributes), `LDAP_SERVER_NOTIFICATION_OID` (`1.2.840.113556.1.4.528`, persistent search), `LDAP_SERVER_GET_STATS_OID` (`1.2.840.113556.1.4.1338`, query statistics), `LDAP_SERVER_FORCE_UPDATE_OID`, `LDAP_SERVER_DOMAIN_SCOPE_OID`, `LDAP_SERVER_SEARCH_OPTIONS_OID`, `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` (`1.2.840.113556.1.4.521`, cross-domain move), `LDAP_SERVER_VERIFY_NAME_OID`, `LDAP_SERVER_SHOW_DELETED_OID`, `LDAP_SERVER_SHOW_RECYCLED_OID`, `LDAP_SERVER_PERMISSIVE_MODIFY_OID`, `LDAP_SERVER_QUOTA_CONTROL_OID`, `LDAP_SERVER_SHUTDOWN_NOTIFY_OID`, etc. per [02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md).

OpenLDAP and 389-DS do not implement most of these. Only AD and Samba-AD-DC implement the full set. A new framework must either implement these controls or document which AD features break: DirSync-based sync (used by Azure AD Connect), range-retrieval for large groups (used by every AD-aware app reading a >1,500-member group), subtree delete (used by `Remove-ADObject -Recursive`), notification (used by event-driven AD monitoring tools), permissive modify (used by Exchange to avoid read-modify-write races on multi-valued attributes).

The most impactful is DirSync — Azure AD Connect uses it to read incremental changes from on-prem AD. Without DirSync, the framework cannot be the source for Azure AD Connect sync. Range-retrieval is the second most impactful — without it, reading a 10,000-member group requires 7 paged queries of 1,500 values each (the default range cap). Permissive modify is third — without it, an `ldap_modify` that adds a value already present fails with `attributeOrValueExists (19)`, breaking Exchange's mailbox-provisioning scripts.

**Impact**:

Azure AD Connect sync breaks (no DirSync). Large-group enumeration breaks (no range-retrieval; client must do 7+ paged queries). Subtree deletes break (no TREE_DELETE; client must walk the subtree and delete leaf-first). Event-driven monitoring breaks (no NOTIFICATION; client must poll). Exchange mailbox provisioning breaks (no PERMISSIVE_MODIFY; concurrent modifications to the same multi-valued attribute race).

**Constraints**:

- Must remain BER-wire-compatible with the control OIDs (e.g. `1.2.840.113556.1.4.528` for SD_FLAGS).
- Control response values must follow MS-ADTS §3.1.1.3 byte layout.
- For DirSync, the cookie format must be opaque to the client but stable across server restarts (the cookie contains a USN cursor + a per-DC marker).

**Cross-platform considerations**:

- **Windows**: Native — `dsamain.dll` implements all 25+ controls.
- **macOS**: OpenDirectory's `slapd` implements RFC 4511 controls only. The framework's macOS DC must implement the AD controls.
- **Linux**: Samba 4 implements most AD controls; 389-DS / OpenLDAP implement a subset (typically DirSync-equivalent via syncrepl, range-retrieval natively).
- **Cross-platform consistency**: Wire format must be AD-compatible for interop.

**KB references**:

- [`02-protocols/02-ldap-protocol.md`](../docs/02-protocols/02-ldap-protocol.md) — AD-specific LDAP controls list, BER encoding of control values, DirSync cookie format.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — DSA control dispatch, range-retrieval implementation, paged query limit.

**Open questions**:

- Which controls are essential for greenfield deployments vs migration scenarios? DirSync is migration-only; range-retrieval is essential for any large-group use.
- Can the framework replace DirSync with a server-sent-events / WebSocket stream (modern equivalent) for new clients, while keeping DirSync for AD-interop?
- What is the minimum control set for "Azure AD Connect compatible"? (Likely DirSync + ranged-retrieval + paged results.)

**Cross-capability impact**:

- Affects: Migration (PC-068, not in this catalog) — Azure AD Connect sync depends on DirSync.
- Affects: Client SDK (PC-080, not in this catalog) — client LDAP wrapper must expose control API.

---

### PC-013 — `unicodePwd` BER-quote trick for password changes is AD-specific

**Capability**: Core Directory
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD password change via LDAP modify on `unicodePwd` requires the value to be the UTF-16LE bytes of a *quoted* password: `"P@ssw0rd!"` becomes 24 bytes including the opening and closing `0x22 0x00` quote characters in UTF-16LE. The quotes are not optional — the DSA rejects unquoted values with `constraintViolation (19)`. TLS is mandatory (the modify must be over LDAPS or after StartTLS); cleartext password modify is rejected. RFC 3062 PasswordModify extended operation is NOT supported by AD — only the modify-on-`unicodePwd` form works per [02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md).

This BER-quote trick is unique to AD. OpenLDAP / 389-DS / Samba 4 accept RFC 3062 PasswordModify and also accept unquoted `userPassword`. Existing AD-automation scripts (ldap3 Python library, impacket, custom PowerShell using `System.DirectoryServices.Protocols`, the `Set-ADAccountPassword` cmdlet) all use the BER-quote trick. Switching to RFC 3062 breaks them.

The `unicodePwd` attribute stores the NT hash (MD4 of the UTF-16LE password) — there is no derivation step. The KDC and NTLM SSP both consume the same 16-byte value as the long-term key per [11-code-examples/05-python-impacket-examples.md](../docs/11-code-examples/05-python-impacket-examples.md). A password change is implemented by the DSA computing MD4 of the new UTF-16LE password and storing the result in `unicodePwd`, plus updating `pwdLastSet`, plus urgent-replicating the change to the PDC emulator.

**Impact**:

Existing AD-automation scripts that use the BER-quote trick fail against a framework that only supports RFC 3062. Switching from BER-quote to RFC 3062 is a deliberate breaking change that requires migrating every script. The migration cost is non-trivial — large enterprises have thousands of password-rotation scripts that use the BER-quote form.

**Constraints**:

- Must support both forms if AD interop is required: BER-quote on `unicodePwd` AND RFC 3062 PasswordModify extended op.
- TLS mandatory in both forms.
- For AD interop, the `unicodePwd` attribute must exist and store the NT hash (so Kerberos / NTLM can use it).
- Must implement urgent replication to PDC emulator on password change (the PDC is the authoritative source for "did the password just change?" lookups).

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll` implements the BER-quote validation; `kdcsvc.dll` and `msv1_0.dll` consume the stored NT hash.
- **macOS**: OpenDirectory uses a different password attribute (`authAuthority`). The framework's macOS DC must implement the `unicodePwd` BER-quote for AD interop.
- **Linux**: Samba 4 implements the BER-quote; 389-DS / OpenLDAP use RFC 3062 natively.
- **Cross-platform consistency**: Wire format must be AD-compatible for interop.

**KB references**:

- [`02-protocols/02-ldap-protocol.md`](../docs/02-protocols/02-ldap-protocol.md) — `unicodePwd` modify semantics, BER-quote requirement, TLS enforcement.
- [`11-code-examples/05-python-impacket-examples.md`](../docs/11-code-examples/05-python-impacket-examples.md) — Python examples using `ldap3` and impacket for password change.

**Open questions**:

- Allow the BER-quote form only when in AD-compat mode, and require RFC 3062 for native mode?
- Provide a transitional API that accepts both forms during migration?
- Should the framework support password-quality validation at the DSA (currently AD delegates this to the LSA filter `pwdmon.dll`)?

**Cross-capability impact**:

- Affects: KDC (PC-023) — KDC's long-term key for the user is the NT hash stored in `unicodePwd`.
- Affects: Auth Provider (PC-038) — NTLM's NT hash is the same value.

---

### PC-014 — FSMO roles are single-master bottlenecks; seizure is destructive

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: Windows, cross-platform

**Problem statement**:

AD is multi-master for ordinary writes but designates exactly one DC per forest or per domain for five single-master operations: Schema Master (sole writer of the Schema NC), Domain Naming Master (sole arbiter of new domain / application partition creation), PDC Emulator (default preferred DC for password changes; trusted DC for downlevel clients; time master; urgent-replication hub), RID Master (allocates 500-RID batches to other DCs; ensures RID uniqueness), Infrastructure Master (updates cross-domain references when objects are renamed or moved). The role holder is recorded in the `fSMORoleOwner` attribute on the Schema NC head, the Partitions container, the domain NC head, the RID Manager object, and the Infrastructure object per [00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md).

Transfer is graceful (the current holder demotes itself; the new holder is promoted; the role owner writes its own `fSMORoleOwner` and the change replicates normally). Seizure is forceful (`ntdsutil roles seize <role>` or `Move-ADDirectoryServerOperationMasterRole -Force`) — the current holder is offline or unrecoverable. The original holder **must never come back online** as a DC afterwards; if it does, it will believe it still holds the role, leading to a "torn-write" situation that replicates as a conflict and may corrupt the schema. After seizing the schema master from a DC that came back online, the only safe operation on the original holder is demotion (`dcpromo /forceremoval`).

A framework should consider whether FSMO roles are needed at all. Consensus-based RID allocation (e.g. Raft per-domain for RID pool allocation) replaces the RID master. Schema-version vector (multi-master schema with version-vector conflict resolution) replaces the schema master. Time-master-via-chrony (or NTP-with-MS-SNTP) replaces the PDC emulator's time-master role. The Infrastructure Master is largely obsolete in forests with GCs on every DC (the IM's cross-domain reference update is redundant when every DC has a GC). The Domain Naming Master is needed only when adding/removing domains — a rare operation that can use a brief consensus round.

**Impact**:

Operational fragility. Losing a DC with FSMO roles is a manual recovery procedure (`ntdsutil seize` or `Move-ADDirectoryServerOperationMasterRole -Force`) that requires careful sequencing. The most consequential role is the PDC emulator — losing it stops urgent password replication (concurrent logons may fail until regular replication catches up) and stops time sync (forest drifts away from external time). The RID master is the second most consequential — losing it causes new-account creation to fail after pool exhaustion. The schema master is rarely lost but its seizure is the most destructive (the original holder must never come back).

**Constraints**:

- Schema Master is required for any LDAP-based schema modify (the DSA on non-holders rejects with `ERROR_DS_DSA_MUST_BE_INT_MASTER` 8438).
- RID Master is required for SID uniqueness (each DC's local pool is finite; exhaustion = no new security principals).
- PDC Emulator is required for password-change urgent replication and for downlevel-client compatibility.
- For AD interop, the FSMO role holders must be discoverable via `fSMORoleOwner` attribute on the standard objects.

**Cross-platform considerations**:

- **Windows**: `netdom query fsmo`, `Get-ADForest | Select SchemaMaster, DomainNamingMaster`, `Get-ADDomain | Select PDCEmulator, RIDMaster, InfrastructureMaster`. `ntdsutil` for seize.
- **macOS**: No equivalent. The framework's macOS DC must implement FSMO or a replacement.
- **Linux**: Samba 4 implements FSMO roles (`samba-tool fsmo show`, `samba-tool fsmo seize`). FreeIPA uses a different model (single-master per replication topology with leader election).
- **Cross-platform consistency**: FSMO discovery must be LDAP-based (`fSMORoleOwner` attribute) for AD-interop.

**KB references**:

- [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) — Full FSMO role table, transfer vs seizure semantics, `fSMORoleOwner` attribute locations, per-role detail.

**Open questions**:

- Can all FSMO roles be replaced by Raft-based consensus? Schema Master via multi-master with version vectors; RID Master via Raft-per-domain; PDC Emulator via chrony + urgent-replication-per-DC; Infrastructure Master obsolete with GCs everywhere; Domain Naming Master via Raft-per-forest on add-domain operation.
- Schema "master" via multi-master with version vectors — what is the conflict resolution? Higher version wins? Last-writer-wins?
- Time master via chrony: does chrony support authenticated NTP (RFC 5906) for the equivalent of MS-SNTP?

**Cross-capability impact**:

- Affects: PC-015 (RID pool) — RID Master is the bottleneck.
- Affects: PC-010 (cross-domain move) — requires PDC + RID Master reachable.
- Affects: KDC PC-030 (krbtgt rotation) — krbtgt password change uses urgent replication via PDC.

---

### PC-015 — RID pool allocation is a 500-RID batch bottleneck

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

Each DC requests RIDs from the RID Master in batches of 500 (default `msDS-RIDPoolSize`). When the local pool drops below 50% (alert threshold, event 16656), the DC requests a new pool; when the local pool drops below ~20%, the DC alerts urgently. When the pool is exhausted, no new security principals can be created (event 16645). The RID Master itself maintains a forest-wide `rIDAvailablePool` (a 64-bit counter, low 31 bits = next RID, high 33 bits = reserved) on the `CN=RID Manager$,CN=System,<domain-dn>` object per [00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md) and [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md).

The RID space per domain is bounded by the 32-bit RID component of the SID (`S-1-5-21-<domain>-<rid>`), giving a theoretical max of 2^30 RIDs (~1 billion) per domain. In practice, RID conservation policies limit consumption. If the RID Master is offline, DCs continue from their local pool until exhaustion — typically hours to days depending on account-creation rate.

RID pool collision is a real risk: if a DC is restored from snapshot (USN rollback), its local pool may overlap with RIDs already issued by the restored DC before the snapshot. AD detects this via the `rIDPreviousAllocationPool` / `rIDAllocationPool` attributes and the RID Master's "RID pool cleanup" mechanism. Without detection, two DCs could issue the same RID to different objects — a catastrophic identity collision.

A framework could use a consensus-based RID allocator (Raft per-domain, with the leader issuing RID batches) or a globally-unique UUID-based scheme (eliminate RIDs entirely). The trade-off: SIDs are deeply embedded in AD's authorization model (ACLs reference SIDs; PAC carries SIDs; cross-forest trusts use SIDs). Replacing SIDs with UUIDs requires rethinking the entire authorization stack.

**Impact**:

RID Master outage causes new-account creation to fail after pool exhaustion — typically within hours in a busy domain. RID space can collide if DCs are restored from snapshots without proper USN-rollback detection (the recovered DC re-issues RIDs from its stale pool). At 1 billion RIDs per domain, the practical lifetime is ~10 years for a 100K-user domain with normal turnover, but the conservative allocation (500 RIDs at a time) means a single DC can stall the whole domain if it hoards RIDs.

**Constraints**:

- Must preserve SID uniqueness forest-wide (SIDs are referenced in ACLs, PACs, sIDHistory, cross-forest trusts).
- Must support `RIDAvailablePool` and `rIDAllocationPool` for AD interop (Windows tools query these).
- Must detect RID pool collision on USN rollback (the `rIDPreviousAllocationPool` mechanism).
- Must handle RID Master outage gracefully (DCs continue from local pool until exhaustion).

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll` RID allocator; `ridmgr.dll` RID Master logic; `Get-ADDomain | Select RIDMaster, RIDAvailablePool`.
- **macOS**: No equivalent. The framework's macOS DC must implement RID allocation.
- **Linux**: Samba 4 implements RID allocation (`source4/dsdb/common/util.c` `ridalloc` module); 389-DS / FreeIPA use UUIDs for unique IDs but still allocate SIDs for AD interop.
- **Cross-platform consistency**: Wire format (RID pool allocation via DRSUAPI `DRSGetDomainControllerInfo`) must be AD-compatible for interop.

**KB references**:

- [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) — RID Master role, pool allocation algorithm, `rIDAvailablePool` / `rIDAllocationPool` / `rIDPreviousAllocationPool` attributes.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — RID allocation in ESE, RID pool collision detection.

**Open questions**:

- Replace SIDs with UUIDs for clean-slate deployments? SIDs are deeply embedded; the cost is high but the benefit is no RID exhaustion ever.
- Keep SIDs for AD interop, use UUIDs internally? The mapping table adds complexity.
- Consensus-based RID allocator (Raft per-domain) — what is the latency cost? Raft consensus is ~10ms per write; RID pool allocation is currently ~50ms per pool (network round-trip to RID Master).

**Cross-capability impact**:

- Affects: PC-014 (FSMO) — RID Master is one of the five roles.
- Affects: Migration (PC-069, not in this catalog) — `sIDHistory` migration depends on RID allocation in the target domain.

---

### PC-016 — KCC topology generation every 15 minutes has scaling limits

**Capability**: Core Directory
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

The Knowledge Consistency Checker (`ntdskcc.dll!KCCDoTask`) runs every 15 minutes by default on every DC, computes a least-cost spanning tree for intra-site replication, and the Inter-Site Topology Generator (ISTG) for each site computes inter-site topology. The KCC walks the sites/subnets/site-links cost matrix in `CN=Sites,CN=Configuration,...` and updates `repsFrom` / `repsTo` on each NC head per [00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) and [00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md).

At 100+ sites, KCC execution time grows non-linearly (the spanning-tree computation is O(sites × links), and the ISTG bridgehead selection is O(bridgeheads × sites)). At 200+ sites, KCC becomes a bottleneck — single-threaded execution blocks replication topology updates for minutes. ISTG bridgehead selection can fail when sites have asymmetric link costs (the algorithm picks the wrong bridgehead, causing replication to flow over a high-cost link). KCC failures are silent — the topology just doesn't update, and replication continues with stale `repsFrom`.

A framework should consider a centralized or declarative topology (Kubernetes-style) instead of auto-computed KCC. Declarative topology (YAML describing sites, subnets, site-links, bridgeheads) is human-reviewable, version-controllable, and avoids the KCC's auto-computation pitfalls. The trade-off is loss of self-healing — when a DC fails, the KCC automatically re-routes; a declarative topology requires manual intervention or a separate health-monitor + topology-updater service.

**Impact**:

Large-forest deployments hit KCC scaling ceilings around 200 sites. KCC execution time exceeds 15 minutes, causing the next KCC run to start before the previous one finishes — a backpressure spiral. ISTG bridgehead mis-selection causes replication to flow over high-cost links (e.g. a branch office in Tokyo replicating through New York instead of through Tokyo's local bridgehead). The silent failure mode (topology doesn't update) is the worst — admins assume replication is healthy because no errors are logged, but the topology is stale.

**Constraints**:

- Must support site-link cost matrix (`CN=Sites,CN=Configuration,...` `CN=IP,CN=Inter-Site Transports,...` siteLink objects with `cost`, `replInterval`, `schedule`).
- Must support ISTG failover (if the ISTG for a site fails, another DC takes over).
- For AD interop, the KCC must run and update `repsFrom` / `repsTo` on schedule (Windows DCs assume the partner's KCC is healthy).

**Cross-platform considerations**:

- **Windows**: `ntdskcc.dll` native; `repadmin /kcc` forces a run; `Get-ADReplicationSite`, `Get-ADReplicationSiteLink`, `Get-ADReplicationSubnet` for inspection.
- **macOS**: No equivalent. The framework's macOS DC must implement KCC or accept declarative topology.
- **Linux**: Samba 4 implements KCC (`source4/dsdb/kcc/`); 389-DS / FreeIPA use a different topology model (admin-defined replication agreements, no auto-computation).
- **Cross-platform consistency**: The KCC must produce identical `repsFrom` / `repsTo` on Windows and non-Windows DCs for interop.

**KB references**:

- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — KCC role in replication topology, ISTG concept.
- [`00-overview/02-ad-architecture.md`](../docs/00-overview/02-ad-architecture.md) — Sites, subnets, site-links, KCC execution model.

**Open questions**:

- Replace KCC with declarative YAML topology (Kubernetes-style)? Sites, subnets, site-links, bridgeheads defined in YAML; applied via `kubectl apply`-equivalent.
- Maintain compatibility with AD's `cn=Sites,cn=Configuration`? The framework's DC could read AD-style site objects and translate to internal topology.
- Hybrid: declarative topology for inter-site, auto-KCC for intra-site?

**Cross-capability impact**:

- Affects: PC-001 (DRSUAPI) — replication topology drives `repsFrom` / `repsTo`.
- Affects: Operations (PC-094, not in this catalog) — KCC monitoring, topology visualization.

---

### PC-017 — Schema is LDAP-schema with OIDs; typed-schema alternative requires migration tooling

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD schema uses `attributeSchema` (governsID `1.2.840.113556.1.5.18`) and `classSchema` (governsID `1.2.840.113556.1.5.4`) LDAP objects in `CN=Schema,CN=Configuration,<forest-root-dn>`. Each attribute has an X.500 OID from the Microsoft arc `1.2.840.113556.1.x` (or from a private enterprise arc `1.3.6.1.4.1.<PEN>` for custom attributes), an `attributeSyntax` (X.500 abstract syntax like `2.5.5.12` DirectoryString), an `oMSyntax` (X.520 concrete syntax like 64 caseExactString), a `searchFlags` bitmask (indexing, ANR, confidential, RODC-filtered), `linkID` pairing (forward + backlink), `isMemberOfPartialAttributeSet` (GC membership), `isSingleValued`, `systemOnly`, `rangeLower` / `rangeUpper`. Each class has `subClassOf`, `systemMayContain` / `systemMustContain`, `mayContain` / `mustContain`, `possSuperiors` / `systemPossSuperiors`, `defaultSecurityDescriptor`, `schemaIDGUID` per [03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

OpenLDAP and 389-DS use RFC 4512 `attributeType` / `objectClass` definitions in `cn=schema`. The schema is still LDAP-schema with OIDs, just a slightly different representation. A typed-schema alternative (protobuf, SQL DDL, JSON Schema, Cap'n Proto) would require a complete migration path from LDAP schema, plus runtime translation for AD-aware clients that read schema via LDAP. The benefit of typed schema is compile-time type checking, code generation, and structured access; the cost is loss of LDAP-schema compatibility and a non-trivial migration.

The schema choice cascades into the directory API (LDAP queries vs typed queries), the replication protocol (LDAP-schema attributes replicate as BER-encoded values; typed schema would replicate differently), and the client SDK (LDAP wrapper vs typed client). A hybrid approach (LDAP schema + typed projection) is possible but doubles the maintenance surface.

**Impact**:

Typed-schema alternative breaks every AD-aware application that reads schema via LDAP. ADUC, ADSI Edit, Exchange System Manager, every custom LDAP app, every third-party AD tool, Azure AD Connect — all assume LDAP-schema. A pure typed-schema framework cannot serve as an AD drop-in replacement. A hybrid (LDAP schema with typed projection) preserves interop at the cost of dual maintenance.

**Constraints**:

- Must support LDAP schema reads for AD interop (clients query `CN=Schema,CN=Configuration,...` with `(objectClass=attributeSchema)` filters).
- Can layer typed schema on top — the LDAP schema is the source of truth, and typed views are projections.
- Schema modify must support the `schemaUpdateNow` operational attribute to trigger cache reload.

**Cross-platform considerations**:

- **Windows**: AD schema as described.
- **macOS**: OpenDirectory uses `slapd`-based schema (RFC 4512 `attributeType` / `objectClass`). The framework's macOS DC must serve AD-style schema for interop.
- **Linux**: 389-DS / OpenLDAP use RFC 4512 schema; Samba 4 implements AD-style schema.
- **Cross-platform consistency**: Wire format (LDAP-schema with OIDs) must be AD-compatible for interop.

**KB references**:

- [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md) — `attributeSchema` / `classSchema` attribute tables, OID allocation, `searchFlags` bitmask, `schemaUpdateNow`.
- [`10-comparison-matrices/02-protocol-implementation-matrix.md`](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md) — Cross-vendor schema implementation comparison.

**Open questions**:

- Hybrid (LDAP schema + typed projection)? Pure typed with LDAP schema as an adapter? Or pure LDAP-schema for v1?
- If typed, which DSL: protobuf, Cap'n Proto, JSON Schema, SQL DDL, or a custom DSL?
- Can the framework auto-generate LDAP-schema from typed schema (for AD-interop mode)?

**Cross-capability impact**:

- Affects: PC-006 (schema cache reload) — typed schema has different cache semantics.
- Affects: Client SDK (PC-080, not in this catalog) — typed client API requires typed schema.

---

### PC-018 — Constructed attributes (`memberOf`, `tokenGroups`, `canonicalName`) require DSA-side computation

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD marks certain attributes as constructed (`FLAG_ATTR_IS_CONSTRUCTED` bit 1, mask 0x02 in `systemFlags`). They are not stored; the DSA computes them at read time from underlying data. Examples: `memberOf` (walks `linktable` back-links for the user's group memberships), `tokenGroups` (recursive group expansion including universal groups across domains, returns SIDs), `tokenGroupsGlobalAndUniversal` (subset for GC-style queries), `canonicalName` (DN-to-domain-path translation, e.g. `CN=jdoe,CN=Users,DC=corp,DC=example,DC=com` → `corp.example.com/Users/jdoe`), `msDS-NCReplCursors` (UTD vector as XML), `msDS-NCReplInboundNeighbors` (inbound partners as XML), `parentGUID` (parent object's GUID), `allowedChildClassesEffective` / `allowedAttributesEffective` (computed from the caller's permissions) per [03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md) and [03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md).

Constructed attributes are also marked `FLAG_ATTR_IS_OPERATIONAL` (bit 2, mask 0x04) — they are not returned by default in LDAP searches; the client must explicitly request them in the `attributes` list. This is why a default `ldapsearch (objectClass=user)` does not return `memberOf` — the client must request `attributes=['memberOf', 'tokenGroups']`.

A framework must preserve constructed-attribute semantics or break LDAP clients. The expensive one is `tokenGroups` — recursive group expansion is O(group count × group size) and can take 100ms+ for users with deep nested memberships. AD caches `tokenGroups` on the user object (`msDS-CachedActiveGroupMembership`?) — actually no, AD computes it at read time. The Kerberos KDC's PAC builder computes the equivalent (`GroupIds` and `ExtraSids` in `KERB_VALIDATION_INFO`) on every TGT issuance, which is why KDC CPU is the bottleneck at million-user scale per [03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md).

**Impact**:

Token-groups-based authorization (Kerberos PAC, ADUC's "Member Of" tab, every custom LDAP app that filters on `memberOf` or reads `tokenGroups`) breaks without constructed attributes. The KDC cannot build a correct PAC (no `GroupIds`, no `ExtraSids`), so authorization decisions based on group membership fail silently — users appear to be in no groups. ADUC cannot display the user's group memberships, breaking admin workflows. The `canonicalName` attribute is the foundation of every UI that displays a user-friendly path (`corp.example.com/Users/jdoe`) instead of a DN — without it, UIs show raw DNs.

**Constraints**:

- Must support `FLAG_ATTR_IS_CONSTRUCTED` and `FLAG_ATTR_IS_OPERATIONAL` semantics.
- Clients must explicitly request operational attrs in the LDAP search `attributes` list; default search must not return them.
- `tokenGroups` must include universal groups across domains (requires GC lookup or equivalent).
- `memberOf` must be the same set as what the `linktable` back-link walk would produce (no divergence between constructed and stored).

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll` computes constructed attributes at search-result-build time.
- **macOS**: OpenDirectory has a few constructed attrs (`dsAttrTypeStandard:AppleMetaNodePath`); not the same set. The framework's macOS DC must implement AD-style constructed attrs.
- **Linux**: Samba 4 implements `memberOf` and `tokenGroups` via LDB modules; 389-DS implements via the `roles` plugin and `mbr` plugin; OpenLDAP uses the `memberof` overlay.
- **Cross-platform consistency**: Wire format must be AD-compatible for interop.

**KB references**:

- [`03-directory-schema/02-ous-containers.md`](../docs/03-directory-schema/02-ous-containers.md) — `systemFlags` bitmask, `FLAG_ATTR_IS_CONSTRUCTED` / `FLAG_ATTR_IS_OPERATIONAL`.
- [`03-directory-schema/03-global-catalog.md`](../docs/03-directory-schema/03-global-catalog.md) — `tokenGroups` recursive expansion via GC, `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`).

**Open questions**:

- Cache `tokenGroups` on write (event-driven, invalidate on group membership change) vs compute at read? Write-time caching trades storage for read latency; the cache invalidation graph is complex (a group rename invalidates every member's cache).
- Can the framework precompute `tokenGroups` for the KDC's PAC builder (avoiding the per-AS-REQ computation)? This is the KDC throughput bottleneck at million-user scale.
- Should `memberOf` be stored (materialized) or computed? AD computes; OpenLDAP with `memberof` overlay stores. Stored is faster read but slower write.

**Cross-capability impact**:

- Affects: KDC PC-023 — KDC's PAC builder computes the equivalent of `tokenGroups` on every TGT issuance.
- Affects: PC-004 (member/memberOf back-link) — `memberOf` constructed attribute depends on `linktable` walk.

---

### PC-019 — AD-integrated DNS zones replicate via DRSUAPI in DomainDnsZones / ForestDnsZones NCs

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD-integrated DNS stores zones as `dnsNode` objects in two application partitions (NDNCs — Naming Context Definition Naming Contexts): `DomainDnsZones.<domain>` (per-domain DNS data, replicates to all DCs in the domain) and `ForestDnsZones.<forest>` (forest-wide DNS data, replicates to all DCs in the forest). Each `dnsNode` object's `dnsRecord` attribute is a multi-valued binary blob, where each value is a `DNS_RECORD` structure (type, TTL, data) per the DNS wire format. The zones replicate via the same DRSUAPI `DRSGetNCChanges` mechanism as Domain NCs per [02-protocols/05-dns-dynamic-updates.md](../docs/02-protocols/05-dns-dynamic-updates.md) and [00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md).

AD-integrated DNS features: per-DC DNS (each DC serves its own copy of the zone, accepting dynamic updates), secure DDNS via GSS-TSIG keyed to machine accounts (the machine account's password is the GSS-TSIG key), scavenging (aging-based record cleanup), and forest-wide single source of truth for `_msdcs.<forest>` records (DC locator SRV records). The alternative — file-based DNS zones (BIND, PowerDNS, CoreDNS) — lacks directory replication (each server has its own copy) and lacks secure DDNS tied to machine accounts (would need a separate key distribution mechanism).

BIND with the `dlz_bind` Samba plugin is the closest open-source analog: BIND reads zone data from Samba's LDB store, which replicates via DRSUAPI. FreeIPA stores DNS in 389-DS (its own LDAP), replicating via 389-DS's MMR — not DRSUAPI-compatible. A framework must decide whether to keep DNS in the directory (AD-interop) or externalize (BIND/PowerDNS/CoreDNS) and lose AD DNS features (scavenging, secure DDNS via GSS-TSIG keyed to machine accounts).

**Impact**:

AD-integrated DNS features (per-DC DNS, secure DDNS, scavenging, _msdcs forest-wide) break without directory-stored DNS. The DC locator mechanism (`_ldap._tcp.dc._msdcs.<domain>` SRV records) depends on directory-replicated DNS — without it, clients cannot reliably discover DCs. Secure DDNS (machine accounts updating their own A/AAAA records) is critical for DHCP environments where IP addresses change frequently. Scavenging prevents stale records from accumulating.

**Constraints**:

- Must support `dnsNode` / `dnsZone` AD schema for interop (`objectClass = dnsNode`, `dnsRecord` attribute with binary `DNS_RECORD` values).
- Must support GSS-TSIG dynamic updates (RFC 3645) keyed to machine accounts.
- Must support the `_msdcs.<forest>` forest-wide NDNC.
- For AD interop, the framework must accept `dnsNode` replication via DRSUAPI.

**Cross-platform considerations**:

- **Windows**: `dnsrv.dll` loaded into LSASS on DCs with DNS Server role; `dnsmgmt.msc` for management; `Resolve-DnsName` for queries.
- **macOS**: macOS has its own mDNS responder, not AD-integrated DNS. The framework's macOS DC must run a DNS server (BIND, CoreDNS, or custom) that reads from the directory.
- **Linux**: BIND with `dlz_bind` Samba plugin reads from LDB; FreeIPA uses BIND reading from 389-DS; CoreDNS is a popular modern alternative but has no native AD-DNS integration.
- **Cross-platform consistency**: Wire format must be AD-compatible for interop.

**KB references**:

- [`02-protocols/05-dns-dynamic-updates.md`](../docs/02-protocols/05-dns-dynamic-updates.md) — GSS-TSIG dynamic updates, `dnsNode` schema, secure DDNS.
- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — AD-integrated DNS role, `_msdcs` zone, DC locator.

**Open questions**:

- Externalize DNS to CoreDNS with a plugin that reads AD? Or keep DNS in-directory for compat?
- If externalized, how to handle GSS-TSIG keyed to machine accounts? The machine account password is in the directory; CoreDNS would need to query the directory for the key.
- For greenfield, is AD-integrated DNS still the right model? Modern DNS best practice (Anycast, DNSSEC, DoH/DoT) is easier with external DNS.

**Cross-capability impact**:

- Affects: PC-001 (DRSUAPI) — DNS NCs replicate via DRSUAPI.
- Affects: KDC PC-023 — KDC discovery via `_ldap._tcp.dc._msdcs.<domain>` SRV records.

---

### PC-020 — `NTDS.DIT` backup / restore requires VSS-aware snapshots

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD backup uses VSS (Volume Shadow Copy Service) writer `{5425FD7A-0D43-4C59-AA61-D3D2D9E2B9D7}` to capture a transactionally-consistent DIT snapshot. The VSS writer freezes ESE writes, snapshots the volume, thaws writes — the snapshot is point-in-time consistent. Non-VSS-aware snapshots (VMware/Hyper-V without integration services, manual file copy of `ntds.dit`) cause USN rollback detection on next boot: the DC advertises a stale `invocationId` and `usnLast`, partners quarantine it, event 2095 fires per [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) and [03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

The restore procedure is equally critical: after restoring a VSS-aware backup, the DC must reset its `invocationId` (so partners re-seed) or perform an authoritative restore (mark specific objects as authoritative, overriding partners' versions). The `ntdsutil ifm` (install-from-media) feature creates a VSS-aware snapshot suitable for offline DC provisioning — the new DC copies the IFM media and starts replication from the IFM's USN, avoiding a full forest-wide sync.

A framework needs: (a) online backup API (snapshot the storage engine while it's running, transactionally consistent); (b) restore procedure that detects and resets `invocationId` (or equivalent); (c) feature-parity with `ntdsutil ifm` for install-from-media; (d) snapshot retention and rotation. For container-native deployments, the equivalent is CRIU (Checkpoint/Restore In Userspace) for process-level snapshots, or LVM/ZFS/Btrfs snapshots for filesystem-level snapshots.

**Impact**:

Non-VSS-aware backups cause silent USN rollback → strict-consistency quarantine. The DC appears healthy but stops replicating; partners log event 2095; admin must demote + metadata cleanup + re-promote. Without IFM, provisioning a new DC in a remote site requires a full forest-wide sync (potentially terabytes of data over a slow WAN). Without snapshot retention, backup rotation is manual.

**Constraints**:

- Must support point-in-time-consistent snapshot (storage-engine-native or filesystem-level).
- Must support IFM (install-from-media) for offline DC provisioning.
- Must support `invocationId` reset on restore (or equivalent for the framework's replication model).
- Must support authoritative restore (mark specific objects as authoritative).
- For AD interop, the VSS writer must be invokable by Windows Backup (and the equivalent on macOS / Linux must be invokable by `tar` / `rsync` / `zfs send`).

**Cross-platform considerations**:

- **Windows**: VSS writer, `wbadmin start systemstatebackup`, `ntdsutil ifm`. The framework must register a VSS writer for Windows DCs.
- **macOS**: Time Machine is the closest equivalent (file-level snapshots). The framework's macOS DC must use Time Machine or a custom snapshot mechanism.
- **Linux**: LVM snapshots, ZFS snapshots, Btrfs snapshots, or storage-engine-native (RocksDB checkpoint, SQLite backup API, FoundationDB snapshot). CRIU for process-level snapshots in containers.
- **Cross-platform consistency**: The backup format must be cross-platform (a backup taken on a Windows DC must be restorable on a Linux DC).

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — VSS writer GUID, ESE database files, `ntdsutil ifm` procedure.
- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — USN rollback detection on restore, event 2095, `repadmin /kcc -resetinvocationid`.

**Open questions**:

- CRIU for container-native DC snapshots? CRIU captures process state; restoring a DC from CRIU would skip the boot sequence (which is needed to re-register RPC endpoints, re-publish SRV records, etc.).
- LVM snapshots vs ZFS snapshots vs storage-engine-native? LVM is filesystem-agnostic; ZFS is end-to-end; storage-engine-native is most portable.
- For cloud-native deployments, is snapshot-based backup the right model? Object-store-based backup (e.g. S3 with versioning) might be more durable.

**Cross-capability impact**:

- Affects: PC-002 (UTD vector) — restore must reset `invocationId`.
- Affects: PC-009 (tombstone) — restoring a backup older than `tombstoneLifetime` causes quarantine.
- Affects: Operations (PC-096, not in this catalog) — backup/restore is a core ops task.

---

### PC-021 — `instanceType` and `systemFlags` are complex bitmasks that gate object behavior

**Capability**: Core Directory
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD uses two interlocking bitmasks to gate object behavior: `instanceType` (32-bit, OID `2.5.21.1`, written by the DSA on create, `systemOnly`) and `systemFlags` (32-bit, OID `1.2.840.113556.1.4.378`). `instanceType` bits: `IT_WRITE` (0x01, object is writable on this DC; FALSE on RODC copies), `IT_NC_ABOVE` (0x02, NC head is above this object; i.e. this object is NOT the NC head), `IT_NC` (0x04, object IS the NC head), `IT_NC_BASE` (0x08, base of an NDNC). Common values: 0x03 (writable object below NC head — most user/computer/group objects), 0x04 (NC head replica, NOT writable — GC partial replica), 0x05 (writable NC head — domain NC on a DC in that domain), 0x07 (writable NC head with IT_NC_BASE — NDNC heads on home server) per [03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md).

`systemFlags` bits include: `FLAG_ATTR_NOT_REPLICATED` (0x01, attribute value not replicated; e.g. `badPwdCount`, `lastLogon` — per-DC), `FLAG_ATTR_IS_CONSTRUCTED` (0x02), `FLAG_ATTR_IS_OPERATIONAL` (0x04), `FLAG_SCHEMA_BASE_OBJECT` (0x08), `FLAG_ATTR_IS_RDN` (0x10), `FLAG_DOMAIN_DISALLOW_MOVE` (0x100, set on `CN=Builtin`, `CN=Users`, `CN=Computers`, `CN=System`), `FLAG_DOMAIN_DISALLOW_MOVE_ON_DOMAIN` (0x200), `FLAG_DOMAIN_DISALLOW_RENAME` (0x400), `FLAG_DOMAIN_DISALLOW_DELETE` (0x800), and config-NC variants (`FLAG_CONFIG_ALLOW_MOVE` 0x01000000, `FLAG_CONFIG_ALLOW_RENAME` 0x02000000, etc.). Well-known containers have `systemFlags = 0x00080000` (DISALLOW_MOVE | DISALLOW_RENAME | DISALLOW_DELETE).

Direct LDAP clients that filter on these flags (e.g. `(systemFlags:1.2.840.113556.1.4.803:=256)` to find non-movable objects) break if the framework replaces the bitmask with explicit attributes. The trade-off: bitmasks are compact (one attribute) but opaque (no schema enforcement, no indexing on individual bits); explicit attributes are clear (`is_nc_head BOOLEAN`, `is_replicated BOOLEAN`, `is_movable BOOLEAN`) but verbose (one attribute per flag).

**Impact**:

Direct LDAP clients that filter on `instanceType` or `systemFlags` break. Examples: `Find unreplicated attributes` (`(systemFlags:1.2.840.113556.1.4.803:=1)`), `find NC heads` (`(instanceType=*)` with bit-2 set), `find non-movable containers` (`(systemFlags:1.2.840.113556.1.4.803:=256)`). These filters are used by AD management tools, security scanners, and migration scripts.

**Constraints**:

- Must preserve AD-compat values for interop scenarios (`instanceType` 0x03 for ordinary objects, 0x05 for writable NC heads, etc.).
- Must support `LDAP_MATCHING_RULE_BIT_AND` (`1.2.840.113556.1.4.803`) and `LDAP_MATCHING_RULE_BIT_OR` (`1.2.840.113556.1.4.804`) on both bitmasks.
- For AD interop, the bitmask values must be byte-identical.

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll` enforces `instanceType` and `systemFlags` at write time.
- **macOS**: No equivalent. The framework's macOS DC must implement the bitmasks.
- **Linux**: Samba 4 implements both; 389-DS / OpenLDAP do not have `instanceType` / `systemFlags` equivalents.
- **Cross-platform consistency**: Wire format must be AD-compatible for interop.

**KB references**:

- [`03-directory-schema/02-ous-containers.md`](../docs/03-directory-schema/02-ous-containers.md) — `instanceType` flag table, `systemFlags` bitmask table, well-known container `systemFlags` values.

**Open questions**:

- Replace bitmask with explicit columns/attributes (`is_nc_head BOOLEAN`, `is_replicated BOOLEAN`, `is_movable BOOLEAN`) for native mode? Maintain bitmask for compat mode?
- Hybrid: bitmask on the wire (LDAP), explicit attributes internally (storage)? Translation at the LDAP layer.

**Cross-capability impact**:

- Affects: PC-012 (LDAP controls) — `LDAP_MATCHING_RULE_BIT_AND` / `BIT_OR` rules must work on these bitmasks.

---

### PC-022 — Multi-tenancy is not native to AD; framework should decide whether to support it

**Capability**: Core Directory
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD has no native multi-tenancy. Each tenant needs either a separate forest (heavy — separate schema, separate KDC, separate GC, separate replication topology, separate admin team) or a separate OU within a shared forest (light — same KDC, same GC, same schema, same replication topology, no hard isolation between tenants). The OU-based approach has weak isolation: a Domain Admin in tenant A can read tenant B's user objects; a compromised KDC in tenant A issues tickets for tenant B's users; a schema extension by tenant A affects tenant B per [00-overview/03-domains-forests-trees.md](../docs/00-overview/03-domains-forests-trees.md) and [00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md).

The framework should either (a) support per-tenant NCs with hard isolation (separate KDC keys per tenant, separate GC per tenant, separate schema per tenant — or at least separate schema extensions per tenant, separate replication topology per tenant, separate audit logs per tenant), or (b) document why multi-tenancy is out of scope and recommend separate framework instances per tenant. Option (b) is simpler but operationally expensive at scale (one deployment per tenant × 1000 tenants = 1000 deployments). Option (a) is complex but matches cloud-native expectations (Kubernetes-style namespace isolation).

Hard isolation requires: separate `krbtgt` keys per tenant (otherwise one tenant's admin can forge tickets for another tenant); separate GC per tenant (otherwise one tenant's admin can enumerate another tenant's users); separate schema extensions per tenant (otherwise one tenant's schema change affects another); separate audit logs per tenant (otherwise one tenant's admin can read another tenant's auth events); separate replication topology per tenant (otherwise a slow tenant blocks replication for all).

**Impact**:

SaaS-style AD offerings (Azure AD DS, Managed AD) need multi-tenancy; without it, each tenant requires a separate deployment — operationally expensive at scale. On-prem enterprises with multiple business units (acquisitions, joint ventures, regulated subsidiaries) also need multi-tenancy. Without hard isolation, a single compromised admin or a single compromised DC compromises all tenants.

**Constraints**:

- If supported, must isolate KDC keys, GC, schema, replication, audit logs per tenant.
- Must support per-tenant admin role (no super-admin who can see all tenants).
- For AD interop, multi-tenancy is out of scope (AD is single-tenant per forest).
- Must support per-tenant backup/restore (a tenant's data can be restored without affecting other tenants).

**Cross-platform considerations**:

- **Windows**: AD is single-tenant per forest. Azure AD DS emulates multi-tenancy via separate deployments per customer.
- **macOS**: OpenDirectory is single-tenant. Profile Manager emulates multi-tenancy via separate OD masters.
- **Linux**: 389-DS / FreeIPA are single-tenant per deployment. Samba 4 is single-tenant per domain.
- **Cross-platform consistency**: Multi-tenancy must work identically across all DC OSes.

**KB references**:

- [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md) — Forest as the security boundary, OU-based weak isolation.
- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — AD deployment models, multi-forest vs single-forest.

**Open questions**:

- Per-tenant NC heads? Each tenant gets its own NC under a shared forest root (similar to how DNS zones work in AD).
- Kubernetes namespace-style isolation? Each tenant is a "namespace" with its own KDC, GC, schema, replication.
- Hybrid: separate framework instances per tenant for hard isolation, with a federation layer (SAML / OIDC) for cross-tenant SSO?
- Is multi-tenancy a v1 requirement or a v2 capability?

**Cross-capability impact**:

- Affects: KDC PC-023 — KDC must support per-tenant `krbtgt` keys.
- Affects: KDC PC-030 — krbtgt rotation must be per-tenant.
- Affects: Operations (PC-096, not in this catalog) — backup/restore must be per-tenant.
- Affects: Migration (PC-068, not in this catalog) — multi-tenant migration requires per-tenant sIDHistory.

---

## Cross-capability impact

Problems in this capability affect and are affected by problems in other capabilities:

- **KDC** depends on Core Directory for principal data, krbtgt account, service principals. PC-023 (KDC MS-KILE) is blocked if Core Directory cannot store `unicodePwd` (PC-013), `servicePrincipalName` (PC-031 uniqueness check), or `userPrincipalName` (PC-032 uniqueness check). PC-030 (krbtgt rotation) requires atomic replication of the krbtgt account's `unicodePwd` — a Core Directory replication concern (PC-001, PC-002).
- **Auth Provider** depends on Core Directory for account lookup. PC-038 (pass-the-hash defense) requires Core Directory to store `unicodePwd` securely (encrypted at rest, never logged). PC-039 (S4U2Self/S4U2Proxy) requires Core Directory to store `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity` (linked attributes, depends on PC-004 linkID pairing).
- **Policy Engine** depends on Core Directory for storing GPO objects (`groupPolicyContainer` class). PC-043 (GPO architecture) requires atomic replication of GPC + GPT — a Core Directory concern (PC-001 replication, PC-020 backup).
- **Cert Service** depends on Core Directory for publishing certs, templates, CRLs. The `NTAuthCertificates` object (under `CN=Public Key Services,CN=Services,CN=Configuration,...`) is located via WKGUID (PC-011). Cert publication uses `userCertificate` attribute (multi-valued, linked).
- **Federation Gateway** depends on Core Directory for user/group data. Claim issuance reads `tokenGroups` (PC-018 constructed attribute).
- **File Gateway** depends on Core Directory for ACLs (SD on file objects, depends on PC-008 SD dedup).
- **Client SDK** depends on Core Directory for LDAP query/modify (PC-012 AD-specific controls, PC-013 password change).
- **Operations** depends on Core Directory for backup/restore (PC-020), monitoring (replication health, USN rollback detection).
- **Migration & Coexistence** depends on Core Directory for sidHistory migration (PC-015 RID allocation in target domain), GPO translation (PC-017 schema), and replication coexistence (PC-001 DRSUAPI interop).

## Open research questions specific to this capability

1. **DRSUAPI server-side implementation strategy**: Adopt Samba's GPLv3 code (forcing framework to GPL), write a fresh implementation under a permissive license, or design a clean-slate replication protocol that loses AD interop? The choice has cascading consequences for every other capability that depends on AD interop (KDC, Auth Provider, Policy Engine, Migration).

2. **Replication model**: Multi-master with UTD vectors (AD-compatible, last-writer-wins per attribute), Raft consensus (strong consistency, leader bottleneck), CRDT (eventual consistency, conflict-free), or hybrid (multi-master for ordinary objects, Raft for schema)? Each has trade-offs in correctness, performance, and AD interop.

3. **Storage engine**: SQLite (simple, portable, single-writer), FoundationDB (distributed, transactional, requires cluster), RocksDB (LSM-tree, fast writes, custom dedup), CockroachDB (distributed SQL, strong consistency, high latency), or custom? The choice must support transactional USN allocation, `linktable`-equivalent, `sdtable`-equivalent, and online backup.

4. **Schema model**: LDAP-schema with OIDs (AD-compatible), typed schema with code generation (modern, breaks AD interop), or hybrid (LDAP schema as source of truth, typed views as projection)? The choice cascades into the directory API, replication, and client SDK.

5. **FSMO roles**: Replace with consensus-based alternatives (Raft per-domain for RID allocation, multi-master schema with version vectors, chrony for time master), keep FSMO for AD interop, or hybrid (FSMO on the wire, consensus internally)?

6. **Multi-tenancy**: Native per-tenant NCs with hard isolation, separate framework instances per tenant, or hybrid (federation layer for cross-tenant SSO)? Hard isolation requires per-tenant KDC, GC, schema, replication, audit — significant complexity.

7. **SIDs vs UUIDs**: Keep SIDs for AD interop (with RID allocation bottleneck), use UUIDs internally (eliminating RID exhaustion), or hybrid (UUIDs internally, SIDs as projection for AD interop)? The choice affects every ACL, PAC, and trust relationship.

8. **DNS in-directory vs externalized**: Keep DNS in-directory (AD-interop, GSS-TSIG to machine accounts), externalize to CoreDNS/BIND/PowerDNS (modern, loses secure DDNS), or hybrid (CoreDNS with directory-reading plugin)?

9. **Cross-domain move relevance**: Is cross-domain move still needed in a post-domain-forest design? Modern AD deployments consolidate into single-domain forests; the framework could collapse to a single domain and eliminate PC-010 entirely.

10. **Backup format**: Cross-platform backup format (a Windows-taken backup restorable on Linux DCs), per-platform format (simpler but no cross-restore), or storage-engine-native (depends on PC-007 storage choice)?
