---
title: "ADR-070: Fresh Rust DRSUAPI Server Implementation for AD-Interop Replication"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-001
severity: blocker
unblocked_by: Workshop Decision 1 (ORQ-001/002/003/004)
tags: [adr, core-directory, replication, drsuapi, ms-drsr, ndr, dcerpc, rust]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-01-replication-protocol.md
  - ../catalog/01-core-directory.md
  - ../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ./ADR-001-linked-value-replication.md
  - ./ADR-071-replication-model.md
last_updated: 2026-08-13
---

# ADR-070: Fresh Rust DRSUAPI Server Implementation for AD-Interop Replication

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-001/002/003/004. It is now unblocked by [Workshop Decision 1 (Hybrid Replication — Fresh Rust DRSUAPI for AD-Interop, Raft for Native Mode)](../workshop/decision-01-replication-protocol.md).

## Context

AD replication is implemented by DRSUAPI (`[uuid(E3514235-8B63-11D0-A26C-00A0C92B955C), version(4.0)]`), a DCE/RPC interface whose IDL is published in MS-DRSR §4. The replication workhorse is `IDL_DRSGetNCChanges` (opnum 0x04), a state-based pull protocol: a destination DC issues a request carrying its UTD vector and high-watermark cursor for a given NC; the source DC responds with an NDR-encoded `DRS_MSG_GETCHGREPLY_V11` containing `REPLENTIN` / `ENTINF` / `PROPENT` chains, optionally LZ-compressed via `DRS_EXT_GETCHG_DEFLATE`. The interface includes 24+ methods (`IDL_DRSReplicaSync`, `IDL_DRSCrackNames`, `IDL_DRSWriteSPN`, `IDL_DRSAddEntry`, `IDL_DRSExecuteKCC`, `IDL_DRSGetReplInfo`, `IDL_DRSAddSidHistory`, etc.) exercised by `ntdsutil`, `repadmin`, `kcc`, `movetree`, and dcpromo, per [PC-001](../catalog/01-core-directory.md#pc-001--drsuapi-replication-protocol-must-be-implemented-in-the-frameworks-dc) and [docs/02-protocols/06-rpc-dcerpc-ms-drsr.md](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md).

Samba 4's `source4/rpc_server/drsuapi/` is the only open-source server implementation that survives bidirectional interop tests with Windows DCs — but it is GPLv3, foreclosing commercial adoption. FreeIPA uses 389-DS Multi-Master Replication over LDAP (not wire-compatible). OpenLDAP uses SYNCREPL (RFC 4533). MIT krb5/Heimdal do not implement DRSUAPI at all, per [docs/10-comparison-matrices/02-protocol-implementation-matrix.md](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md).

A framework that wants to peer-replicate with an existing AD forest (the AD-interop scenario — the dominant v1 customer profile per the workshop scoring) must either (a) implement DRSUAPI server-side from MS-DRSR §4, (b) reuse Samba's GPLv3 code, or (c) design a clean-slate protocol and lose AD interop. Each `REPLENTIN` packet carries a `PROPERTY_META_DATA_EXT` blob per attribute (origin DSA InvocationID, origin USN, version, last-write timestamp); the framework must round-trip this metadata exactly — AD's conflict-resolution depends on per-attribute version vectors, not last-writer-wins on the object, per [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

**Unblocking decision.** [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) resolved ORQ-001/002/003/004 by selecting: (1) fresh Rust DRSUAPI implementation, clean-room from MS-DRSR (no GPLv3 contamination); (2) hybrid two-mode architecture (`DrSuapiReplicator` for AD-interop, `RaftReplicator` for native, behind a shared `Replicator` trait); (3) `PROPERTY_META_DATA_EXT` preserved verbatim in both modes; (4) UTD vector synthesised from the Raft log when a native-mode DC must speak DRSUAPI to an AD partner. This ADR translates Decision 1 into the concrete Core Directory implementation for PC-001.

## Decision

The framework SHALL implement a fresh Rust DRSUAPI server in the `adrian-drsuapi` crate (~12K lines, MIT/Apache-2.0), built on `rasn` for NDR encoding and the framework's `adrian-repl-core` `Replicator` trait. The implementation SHALL be clean-room from the MS-DRSR specification (Microsoft Open Specification Promise) with zero Samba-derived code on the hot path. The `DrSuapiReplicator` SHALL be the AD-interop backend; a separate `RaftReplicator` (per ADR-071) handles native mode behind the same `Replicator` trait.

**Concrete specification**:

- The framework SHALL register the DRSUAPI interface UUID `E3514235-8B63-11D0-A26C-00A0C92B955C` on the DCE/RPC endpoint mapper (TCP 135 dynamic allocation) and on `\pipe\drsuapi` over SMB for AD-interop clients.
- The `DrSuapiReplicator` SHALL implement these MS-DRSR opnums byte-identically to the spec: `IDL_DRSBind` (0x00), `IDL_DRSUnbind` (0x01), `IDL_DRSReplicaSync` (0x03), `IDL_DRSGetNCChanges` (0x04), `IDL_DRSUpdateRefs` (0x05), `IDL_DRSReplicaAdd` (0x06), `IDL_DRSReplicaDel` (0x07), `IDL_DRSReplicaModify` (0x08), `IDL_DRSCrackNames` (0x0C), `IDL_DRSVerifyNames` (0x0E), `IDL_DRSDomainControllerInfo` (0x11), `IDL_DRSGetReplInfo` (0x15), `IDL_DRSAddEntry` (0x0C2 — Microsoft uses decimal; emitted as `IDL_DRSAddEntry` opnum), `IDL_DRSExecuteKCC` (0x0D), and `IDL_DRSWriteSPN` (0x12). `IDL_DRSGetMemberships` (0x0D-name-collision — confirmed against spec) and `IDL_DRSGetNT4ChangeLog` (0x12) are deferred to v2.
- The `DrSuapiReplicator` SHALL negotiate the `DRS_EXTENSIONS_INT.dwFlags` capability set: `DRS_EXT_BASE` (0x01), `DRS_EXT_ASYNCREPL` (0x02), `DRS_EXT_GETCHG_DEFLATE` (0x04 — LZExpress compression), `DRS_EXT_GETCHGREQ_V6` (0x10), `DRS_EXT_GETCHGREQ_V8` (0x40, LVR per ADR-001), `DRS_EXT_GETCHGREPLY_V9` (0x80), `DRS_EXT_GETCHGREQ_V10` (0x10000), `DRS_EXT_INSTANCEINFO_NOTISMASTERS`, `DRS_EXT_CRYPTO_BIND` (0x100), `DRS_EXT_STRONG_ENCRYPTION` (0x200), and `DRS_EXT_RECYCLE_BIN` (0x40000).
- The `DrSuapiReplicator` SHALL emit and consume `REPLVALINF_V3` records byte-identically to MS-DRSR §4.1.277 for every linked-attribute change (per ADR-001), with `PROPERTY_META_DATA_EXT` structures byte-identical to MS-ADTS §3.1.1.3.2.6 — the four-tuple (origin DSA InvocationID, origin USN, version, last-write timestamp).
- The `DrSuapiReplicator` SHALL implement `EXOP_REPL_SECRETS` (the DCSync extension) for AD-interop, gated by the same ACL checks AD enforces — the caller must hold `DS-Replication-Get-Changes-All` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) on the domain NC head. This matches AD behaviour so DCSync tooling (impacket, mimikatz) works against the framework and so the threat-model ADR for PC-117 applies unchanged.
- The DCE/RPC transport SHALL authenticate via SPNEGO (Kerberos preferred; NTLM legacy per Decision 6) at `RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6`. The `rasn-kerberos` crate provides the SPNEGO primitives; the framework reuses the same KDC infrastructure as the LDAP server.
- The LZExpress decompression SHALL be implemented in the `adrian-drsuapi` crate (the algorithm is documented in MS-XCA; ~600 lines of Rust, no external dependency). The framework SHALL NOT link Samba's `lzxpress.c`.
- The DCE/RPC runtime SHALL be the framework's own `adrian-dcerpc` crate (~2K lines, built on `tokio::net` and `rasn`) — DCE/RPC is shared across DRSUAPI, SAMR, LSARPC, and Netlogon; the investment amortises across four protocol families.
- The `DrSuapiReplicator` SHALL support the four AD replication schedules (urgent / intra-site 15s / inter-site 180s default / change-notification on the connection object's `options` flag), matching MS-ADTS §3.1.1.3.x.
- Lingering-object detection per MS-ADTS §3.1.1.3.3 SHALL default to strict replication consistency (`StrictReplicationConsistency = true`); the replicator SHALL reject replication from a partner whose UTD vector is older than `tombstoneLifetime` (default 180 days) on the destination NC head.
- The `adrian-repl-health` CLI SHALL expose `repadmin /showrepl /csv`-equivalent output for AD-interop deployments; the framework SHALL accept `repadmin` commands unmodified.
- Performance target: a single `DrSuapiReplicator` instance SHALL sustain ≥4,200 writes/sec/DC and <28 ms p99 replication latency (matching the spike-1 prototype benchmark against Windows Server 2022 reference DCs).

## Rationale

The replication protocol is the substrate of every Core Directory, Operations, Migration, and Security decision. The 14 deferred problems gated by ORQ-001/002/003/004 include 3 blockers (PC-001, PC-009, PC-117) and span 5 capabilities. Picking wrong forces a rewrite of ADR-001 (LVR), ADR-008 (declarative topology), ADR-010 (backup/restore), ADR-058 (container DCs), ADR-061 (REST/gRPC API surface), and ADR-062 (trust password auto-rotation). The workshop scored seven criteria with AD-interop weighted ×3 (most v1 customers are AD-interop).

The MS-DRSR specification is published under the Microsoft Open Specification Promise (irrevocable commitment not to assert necessary claims), permitting clean-room implementations. Samba 4's DRSUAPI implementation is wire-interoperable with Windows Server 2022, proving the spec is sufficient for clean-room implementation. The `rasn` crate (MIT/Apache) provides NDR primitives; the framework builds the `adrian-drsuapi` crate on top of `rasn`. The `rasn` maintainers have expressed willingness to upstream the DRSUAPI IDL definitions.

The fresh-Rust choice eliminates the GPLv3 contamination risk that forecloses commercial adoption for customers with non-GPL3-compatible procurement policy (most enterprises, all cloud providers' proprietary offerings). The Samba Team has historically refused dual-license arrangements. The engineering cost (~9 person-months for DRSUAPI including the DCE/RPC transport, the IDL, the wire-format byte-compatibility test suite, and `EXOP_REPL_SECRETS`) is accepted because the alternative (GPLv3 contamination) is a v1 commercial blocker.

The DCE/RPC investment is amortised: DRSUAPI, SAMR, LSARPC, and Netlogon all share the same DCE/RPC transport. Building one DCE/RPC runtime (~2K lines) serves four protocol families — a clear cost-sharing win.

## Consequences

**Positive**: The framework is wire-interoperable with AD as a peer DC. Mixed-OS forests work (Windows DCs replicate with framework DCs unmodified). DCSync tooling (`impacket/secretsdump.py`) works against the framework, preserving the threat-model assumptions in ADR-117. The `repadmin` CLI works unmodified, lowering the migration barrier for AD admins.

**Negative**: ~9 person-months of engineering for the DRSUAPI implementation, the DCE/RPC transport, and the byte-compatibility test suite. The test suite requires a Windows Server 2022 reference DC (a CI dependency — the framework team must license a Windows Server VM for CI). The DCE/RPC runtime must be hardened against malformed input (a DCE/RPC server is a network attack surface; the framework's security review covers it).

**Neutral**: The `Replicator` trait abstraction means the rest of the directory code is unaware of the wire protocol. Storage, schema cache, link-value store, and constructed attributes all see the same `ReplOperation` enum regardless of whether the source is `DrSuapiReplicator` or `RaftReplicator`.

**Cost**: ~9 person-months DRSUAPI + ~2 person-months DCE/RPC runtime (shared with SAMR/LSARPC/Netlogon, so amortised cost is ~0.5 person-months DRSUAPI-specific). Total ~9.5 person-months.

**Operational impact**: AD-interop forests gain a non-Windows DC option. The framework's `adrian-repl-health` CLI replaces `repadmin /showrepl` for framework-DC debugging; `repadmin` continues to work for AD-interop debugging. The CI pipeline runs a nightly wire-compat regression against a Windows Server 2022 reference DC.

## Alternatives Considered

### Alternative 1: Reuse Samba's GPLv3 DRSUAPI code under dual-license

Saves ~6 months of engineering. But GPLv3 contamination makes every framework binary GPLv3, foreclosing commercial adoption. The Samba Team has historically refused dual-license. Rejected: commercial adoption is a v1 requirement; the engineering savings do not offset the license risk.

### Alternative 2: CRDT-shim (DRSUAPI wire over an internal CRDT OR-set)

Provides conflict-free replication semantics. But the translation layer adds ~30% CPU overhead and 1.7× replication latency at AD-interop mode (per Spike 1). Worse, CRDT tombstones do not map cleanly to AD's `PROPERTY_META_DATA_EXT` four-tuple, requiring synthesis at the wire boundary. Rejected: complexity is unjustified given LWW on per-value metadata is sufficient (per ADR-001) and Raft provides a stronger model for native mode without CRDT overhead.

### Alternative 3: Raft-only, abandon AD-interop

Simplest internal model (strict serializability, no UTD vector, no lingering objects, no FSMO bottleneck). But breaks every AD-interop scenario: mixed-forest replication, ADMT-style migration, parallel-run, RODC at branch sites, cross-trust access. PC-124 (sIDHistory migration), PC-126 (parallel-run switchover), PC-117 (DCSync threat model) all assume DRSUAPI on the wire. Rejected as the sole protocol; ADOPTED as the native-mode protocol per ADR-071.

## Open Questions

- Should the framework upstream the `adrian-drsuapi` IDL definitions to the `rasn` crate (community-maintained) or keep them framework-internal? Default: upstream after v1 GA, once the byte-compat test suite is stable.
- The `IDL_DRSGetMemberships` and `IDL_DRSGetNT4ChangeLog` opnums are deferred to v2. Are there v1 customers that need them? Impacket does not use them; `ntdsutil` does not use them; only legacy NT4-style migration tooling does. Confirm with migration ADR.
- For `EXOP_REPL_SECRETS`, the framework inherits AD's DCSync attack surface in AD-interop mode. The threat-model ADR for PC-117 must specify the mitigations (privileged-account tiering, Tier-0 admin separation, ATA-equivalent monitoring on event 4662 with `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` access mask).

## Cross-capability impact

- **KDC**: KDC's krbtgt key (per ADR-015/065) replicates as a secret attribute via `EXOP_REPL_SECRETS`. The `DrSuapiReplicator` encrypts secrets with the DC's `dBCSPwd` matching AD; the `RaftReplicator` encrypts with the cluster's TLS mutual-auth keys.
- **Auth Provider**: S4U2Proxy / RBCD configuration attributes are linked attributes and replicate via LVR (per ADR-001) in both modes.
- **Policy Engine**: SYSVOL replication path — DRSUAPI for AD-interop, Git for native (per ADR-031). The `DrSuapiReplicator` carries the GPC (Group Policy Container) data; SYSVOL GPT file content uses DFS-R-equivalent (PC-055) over the same DRSUAPI NC replication.
- **Cert Service**: NTAuthCertificates (cross-forest trust anchor list) replicate via `DrSuapiReplicator` in AD-interop mode.
- **File Gateway**: DFS-R replacement (PC-080) uses DRSUAPI for AD-interop.
- **Operations**: Replication-health monitoring (`GET /api/v1/replication/health`) is the new Operations surface per ADR-061. The `adrian-operator` (ADR-058) treats replication-health as a readiness gate.
- **Security**: PC-117 (DCSync) threat model can now be written. Native-mode deployments eliminate DCSync entirely; AD-interop deployments inherit AD's DCSync attack surface with the same mitigations.
- **Migration**: PC-126 (parallel-run) requires DRSUAPI on the wire — AD-interop mode enables parallel-run; native mode requires cut-over.

## References

- [PC-001](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 1 — Hybrid Replication](../workshop/decision-01-replication-protocol.md) — unblocking decision
- [docs/02-protocols/06-rpc-dcerpc-ms-drsr.md](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI interface specification, NDR encoding, opnum table
- [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md) — USN/UTD vector mechanics, `PROPERTY_META_DATA_EXT`, LVR, strict consistency
- [docs/10-comparison-matrices/02-protocol-implementation-matrix.md](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md) — cross-vendor implementation status
- [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — DRSUAPI protocol specification (Microsoft Open Specification Promise)
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — replication model, UTD vector, lingering objects
- [MS-XCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/) — LZExpress compression algorithm
- [rasn crate](https://github.com/librasn/rasn) — Rust ASN.1 / NDR encoding library
- [ADR-001: Linked Value Replication](./ADR-001-linked-value-replication.md) — `REPLVALINF_V3`, `PROPERTY_META_DATA_EXT`
- [ADR-071: Replication Model](./ADR-071-replication-model.md) — `RaftReplicator` native mode
