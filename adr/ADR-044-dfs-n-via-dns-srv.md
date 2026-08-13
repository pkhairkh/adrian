---
title: "ADR-044: DFS-N-Equivalent via DNS SRV"
status: Accepted (partial)
date: 2026-08-13
deciders: adrian-architecture-team
capability: File Gateway
problem: PC-080
severity: high
tags: [adr, file-gateway, dfs-n, dfs-r, dns-srv, sysvol, partial]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/07-file-gateway.md
  - ../docs/07-file-print/02-dfs-n-dfs-r.md
  - ../docs/07-file-print/01-smb-shares-internals.md
  - ./ADR-043-drop-smb1-support.md
last_updated: 2026-08-13
---

# ADR-044: DFS-N-Equivalent via DNS SRV

## Status

Accepted (partial) — 2026-08-13. The DFS-N-equivalent referral resolution is accepted. The DFS-R-equivalent content replication strategy is deferred pending resolution of Tier-1 ORQ-001/002 (replication protocol choice).

## Context

DFS Namesspaces (DFS-N) is the `dfssvc.exe` service that resolves a UNC path of the form `\\corp.example.com\Public\Engineering\docs\file.txt` into a per-site target referral. AD stores the namespace authoritatively as `msDFS-NamespaceRoot` and `msDFS-Link` objects under `CN=Dfs-Configuration,CN=System,DC=...`. The referral is returned via the NETDFS RPC interface `[uuid(4FC742E0-4A10-11CF-8273-00AA004AE673)]` opnum 0/1/2, with site-costing computed against `CN=Subnets,CN=Sites,CN=Configuration,...` so a client in the `HQ` site gets redirected to a target in `HQ` first, per the analysis in [docs/07-file-print/02-dfs-n-dfs-r.md](../docs/07-file-print/02-dfs-n-dfs-r.md). DFS-R is `dfsr.exe`, a multi-master file replication protocol that uses RDC (Remote Differential Compression, `rdparty.dll`) and the NTFS USN journal (`FSCTL_READ_USN_JOURNAL`) for change detection; the wire protocol is MS-DFSR `[uuid(91b7b931-c75a-4530-8258-1b3eb578c5d8)]`.

The framework inherits two distinct gaps from [PC-080](../catalog/07-file-gateway.md#pc-080--dfs-n-namespace--dfs-r-replication-are-windows-only-no-linux-equivalent). DFS-N is a referral protocol: the framework can implement MS-DFSC client referral resolution and serve referrals from its Core Directory's `msDFS-*` objects without implementing a DFS-N server in the Windows sense. DFS-R is a content replication protocol: replacing it requires either (a) reusing DFS-R for interop with Windows DCs (DFS-R replicates SYSVOL on Server 2008 R2+), (b) adopting an alternative like `syncthing` for non-SYSVOL replication plus an AD-interop shim for SYSVOL, or (c) reusing Samba 4's MS-DRSR-based SYSVOL replication (single-master per attribute, not multi-master). The DFS-N half has a clear technical answer; the DFS-R half depends on the Tier-1 replication-protocol decision (ORQ-001/002) and cannot be finalized until that decision is made.

The DFS-N problem is forced by operational reality. DFS-N is widely used for share abstraction — hard-coded `\\server\share` UNC paths in scripts, shortcuts, and applications break when servers are renamed or migrated. Without DFS-N, every share move requires DNS CNAME updates and client-side remapping, which is operationally unacceptable in any enterprise with >1000 users. The framework must support `\\domain\share\path` UNC resolution for client compat. The constraints from [PC-080](../catalog/07-file-gateway.md#pc-080--dfs-n-namespace--dfs-r-replication-are-windows-only-no-linux-equivalent) require MS-DFSC referral (NETDFS opnum 0/1/2) returning `DFS_REFERRAL_V3` / `V4` structures, site-aware referrals using `CN=Subnets,CN=Sites,CN=Configuration,...`, and Samba-as-leaf-target behavior preserved so framework-hosted shares can be referenced by Windows-hosted DFS namespaces.

The DFS-R problem is forced by SYSVOL replication specifically. Every framework DC must serve SYSVOL consistently, and interop with Windows DCs requires either DFS-R (Windows-native) or Samba 4's DRSUAPI-on-SYSVOL approach (Samba interop). For non-SYSVOL replication (user shares, profile shares), the framework has more flexibility: `syncthing`, `rsync`, or a fresh content-replication engine all work. But the SYSVOL choice cannot be made without first deciding the framework's AD-replication protocol (ORQ-001/002), because the SYSVOL replication strategy is logically parallel to the directory-partition replication strategy — they share change-detection primitives (USN journals or equivalent) and may share transport. The [TRIAGE.md](./TRIAGE.md) gating cites ORQ-001/002 as the deferral trigger, which is correct.

## Decision

The framework's File Gateway will implement DFS-N-equivalent referral resolution via DNS SRV records as the primary share-location mechanism, with a thin MS-DFSC referral-compatibility layer for legacy Windows clients. The framework will not implement a Windows-style `dfssvc.exe`-equivalent DFS-N server (no `msDFS-NamespaceRoot` write path); instead, the framework's Policy Engine and a DNS SRV publisher will collaborate to publish share locations as `_smb._tcp.<site>._sites.<domain>` SRV records, and the framework's client SDK will resolve share locations via DNS SRV queries in site-aware order. For Windows-client compat, the framework will implement MS-DFSC referral read (NETDFS opnum 0/1/2 read-only) returning `DFS_REFERRAL_V4` structures synthesized from the DNS SRV data, so that Windows clients with hard-coded `\\domain\share` UNC paths continue to work.

The DFS-R content-replication strategy is deferred. The framework will document SYSVOL replication as TBD pending the Tier-1 replication-protocol decision (ORQ-001/002). For non-SYSVOL replication, the framework will recommend `syncthing` (multi-master, conflict-resolving, mature) as the v1 default, with a documentation note that the framework's eventual DFS-R-equivalent strategy will be defined once the Tier-1 replication decision is made.

**Concrete specification**:

- The framework's DNS publisher MUST publish, for every framework-hosted share, a DNS SRV record of the form `_smb._tcp.<site>._sites.<share-name>.<domain> IN SRV 0 <weight> <port> <host>` for every site in which the share is hosted.
- The framework's client SDK MUST implement a share-location resolver that performs DNS SRV queries against `_smb._tcp.<site>._sites.<share-name>.<domain>` in site-aware order (local site first, then site-cost-sorted remote sites) and returns the first reachable target. The resolver MUST fall back to the `Domain` site-link cost from `CN=SiteLink,CN=Sites,CN=Configuration,...` when a site-specific SRV record is absent.
- The framework's MS-DFSC referral-compat layer MUST respond to NETDFS opnum 0 (`NetrDfsAdd`), opnum 1 (`NetrDfsRemove`), opnum 2 (`NetrDfsEnum`), opnum 19 (`NetrDfsGetReferral`) with read-only `DFS_REFERRAL_V4` structures synthesized from the DNS SRV data. Write opnums (NetrDfsAdd, NetrDfsRemove, NetrDfsMove, NetrDfsRename) MUST return `STATUS_ACCESS_DENIED` (0xC0000022) with a logged warning referencing this ADR.
- The framework's Core Directory MUST support the `msDFS-NamespaceRoot`, `msDFS-Link`, `msDFS-Target` object classes for read-only interop with Windows DFS namespaces. The framework's Policy Engine MUST NOT create or modify these objects; they exist solely so that Windows DFS-N clients can query the framework directory and resolve namespace paths.
- The framework's Samba-as-leaf-target behavior MUST be preserved: framework-hosted shares MUST set the `SMB2_SHAREFLAG_DFS` (0x0001) flag in `TreeConnect.GetResponse` only when the share is genuinely a DFS leaf target, and `SMB2_SHAREFLAG_DFS_ROOT` (0x0002) only when the share is the root of a DFS namespace. These flags are inspected by DFS-N clients per [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md).
- The framework's documentation MUST include a "DFS-N migration playbook" for customers migrating from Windows-hosted DFS-N: (1) inventory existing `msDFS-*` objects via `dfsutil /root:\\<domain>\<namespace> /view`, (2) for each namespace link, create a corresponding DNS SRV record set, (3) reconfigure client UNC paths from `\\domain\namespace\link` to the framework's `\\<site-resolved-host>\<share>` form (or keep `\\domain\namespace\link` and rely on the MS-DFSC compat layer), (4) decommission the Windows DFS-N servers.
- The framework's SYSVOL replication documentation MUST explicitly mark the strategy as deferred pending Tier-1 ORQ-001/002, with a placeholder recommendation: "v1 deployments should use a single-DC SYSVOL or accept manual rsync-based SYSVOL synchronization between framework DCs until the replication decision is finalized."
- The framework's non-SYSVOL replication recommendation MUST be `syncthing` (multi-master, conflict-resolving) for v1, with the documentation noting that this is a placeholder until the framework's DFS-R-equivalent strategy is defined.

## Rationale

The DFS-N half of the decision is forced by operational economics. DNS SRV is the framework's existing service-discovery primitive (it already publishes `_ldap._tcp`, `_kerberos._tcp`, `_kpasswd._tcp`, `_gc._tcp` per the Core Directory's AD-compat layer). Extending this primitive to share location is a natural fit: the framework already has a DNS server (BIND or integrated DNS), it already has site-aware resolution logic, and it already has a client SDK that performs DNS SRV queries. A DFS-N implementation layered on top of DNS SRV reuses ~95% of the framework's existing infrastructure, versus a fresh MS-DFSC server implementation which would require a new RPC interface, a new AD object-management surface, and a new client-side referral cache. The DNS SRV approach also avoids the Windows-DFS-N's "one namespace per domain" limitation: the framework can publish unlimited namespaces as DNS SRV record sets without the AD-object overhead.

The MS-DFSC referral-compat layer is included because the operational reality is that enterprises have thousands of hard-coded `\\domain\share` UNC paths in scripts, shortcuts, registry values, and application configuration files. The framework cannot migrate those by hand; it must accept them. The MS-DFSC compat layer is a read-only shim that synthesizes `DFS_REFERRAL_V4` responses from DNS SRV data; it does not implement the full DFS-N write surface (which is rarely used — most enterprises create DFS namespaces once and never modify them). The compat layer's cost is ~2000 lines of code (RPC server + NETDFS dispatch + referral-cache), versus ~25,000 lines for a full DFS-N reimplementation. The compat layer's wire-compat is verifiable against Microsoft's `dfsutil /view` and against the Windows SMB client's built-in DFS-N referral consumer.

The DFS-R half is deferred because the choice is genuinely gated by Tier-1 ORQ-001/002. The framework's AD-replication protocol determines whether SYSVOL replication can share transport with directory replication (DRSUAPI-style), whether it must use a separate protocol (DFS-R-equivalent), or whether SYSVOL can be replicated via a clean-slate mechanism (Git-based, content-addressed). The choice also determines the framework's change-detection primitive (USN journals if DRSUAPI-style; CRDT vectors if Raft-style; git commit hashes if Git-based), which in turn determines what the DFS-R-equivalent must implement. Deferring the DFS-R half to post-ORQ-001/002 avoids a premature commitment that would have to be unwound.

The non-SYSVOL `syncthing` recommendation is conservative. `syncthing` is mature, multi-master, conflict-resolving, and has no AD integration to break. It is not a long-term answer (the framework should eventually ship its own replication engine tied to the directory replication choice), but it is a safe v1 default that lets customers deploy multi-site non-SYSVOL shares without waiting for the Tier-1 decision. The recommendation can be replaced without breaking deployed customers; `syncthing` continues to run alongside the framework's eventual native replication engine.

## Consequences

**Positive**. The framework gains DFS-N-equivalent share abstraction without inheriting the full MS-DFSC server complexity. The framework reuses its DNS infrastructure for share discovery, eliminating a parallel discovery protocol. The framework's MS-DFSC compat layer preserves hard-coded `\\domain\share` UNC paths from existing customer environments, enabling migration. The framework's documentation can offer a clear migration playbook.

**Negative**. The framework's DFS-N story is "DNS SRV + MS-DFSC read-only compat," not "drop-in DFS-N replacement." Customers who depend on the DFS-N write surface (`dfsutil /add`, `/remove`, `/move`) will need to migrate to the framework's DNS-based publication model. The framework's referral cache is per-client (no server-side cache), so referral latency may be higher than Windows DFS-N's server-side cached referrals for chatty workloads. The Samba-as-leaf-target behavior is preserved but not extended: framework-hosted shares cannot be Windows-DFS-N namespace roots, only leaf targets.

**Neutral**. The MS-DFSC compat layer is invisible to most clients (Windows clients treat it as a DFS-N server). The DNS SRV publication model is invisible to non-Windows clients (Linux `cifs.ko` and macOS SMBX both resolve DNS SRV for share discovery where supported, falling back to direct host names where not).

**Implementation cost**. DFS-N half: medium (~8-12 engineer-weeks for DNS SRV publisher + client SDK resolver + MS-DFSC compat layer + tests + documentation). DFS-R half: deferred; estimated 6-12 engineer-months once the Tier-1 replication decision is made.

**Operational impact**. Operations teams gain a single share-discovery protocol (DNS SRV) for both framework-hosted and Windows-hosted shares (the framework's DNS publisher can be configured to mirror Windows DFS-N data into DNS SRV records for cross-platform access). Operations teams lose the Windows DFS-N management surface (`dfsutil`, `dfsmig`); the framework provides a CLI equivalent for managing DNS SRV publication. The deferred DFS-R strategy creates an operational gap for multi-DC SYSVOL deployments in v1; the documentation must be clear that multi-DC v1 deployments should either use single-DC SYSVOL or accept manual rsync-based synchronization.

## Alternatives Considered

**Alternative 1: Full MS-DFSC server reimplementation.** The framework implements a complete `dfssvc.exe`-equivalent: NETDFS RPC server with full write opnum support, `msDFS-NamespaceRoot` / `msDFS-Link` AD object management, pKT cache, site-costing. **Rejection rationale**: This is ~25,000 lines of code for a feature that is largely read-only in practice. The write surface (`NetrDfsAdd`, `NetrDfsRemove`, `NetrDfsMove`) is rarely used after initial namespace setup; the read surface (`NetrDfsGetReferral`) is what clients hit continuously. The DNS SRV + read-only MS-DFSC compat approach captures 95% of the value at 10% of the cost.

**Alternative 2: Adopt Samba 4's partial DFS-N server.** Samba 4 has a partial DFS-N server implementation (`source3/modules/vfs_default.c` and `source3/rpc_server/dfs/srv_dfs_ctls.c`). The framework could extend Samba's DFS-N support to full coverage. **Rejection rationale**: Samba's DFS-N server is incomplete (no full write surface, no site-costing on the read surface), and depending on it ties the framework's DFS-N story to Samba's release cycle. The framework's DNS SRV approach is implementation-independent: it works whether the framework's SMB server is Samba, a fresh Rust/Go implementation, or platform-native SMBX.

**Alternative 3 (for DFS-R): Reuse MS-DFSR wire protocol.** The framework implements MS-DFSR (the Windows DFS-R wire protocol `[uuid(91b7b931-...)]`) for full SYSVOL interop with Windows DCs. **Rejection rationale (deferral)**: This is the right answer if the framework's Tier-1 replication choice lands on DRSUAPI-style (USN journals, multi-master). But if the framework's Tier-1 choice lands on Raft-based or CRDT-based replication, MS-DFSR's USN-journal change detection is incompatible, and the framework would have to maintain a parallel USN-journal layer just for DFS-R. Deferring until ORQ-001/002 is resolved avoids this premature commitment.

## Open Questions

The DFS-R half of this ADR is gated by Tier-1 ORQ-001/002 (replication protocol choice). Specifically:

- **ORQ-001**: Should the framework adopt DRSUAPI-style replication, Raft-based replication, CRDT-based replication, or a hybrid? (Gates the SYSVOL replication choice: DRSUAPI-style implies DFS-R can share transport; Raft/CRDT implies a parallel SYSVOL replication mechanism.)
- **ORQ-002**: If DRSUAPI-style, what is the change-detection primitive (USN journals, vector clocks, hash chains)? (Gates whether the framework's DFS-R-equivalent can reuse the same change-detection code path.)

Once these ORQs are resolved, the deferred DFS-R sub-decision will be finalized in a follow-up ADR (estimated ADR-070+). Until then, v1 deployments MUST use single-DC SYSVOL or accept manual rsync-based SYSVOL synchronization.

## Cross-capability impact

- **Core Directory** ([PC-001](../catalog/01-core-directory.md)): The DFS-R sub-decision is logically parallel to the Core Directory replication decision; the two share change-detection primitives.
- **Policy Engine** ([PC-050](../catalog/04-policy-engine.md)): Policy Engine's SYSVOL-equivalent distribution depends on this ADR's DFS-R resolution for multi-DC deployments.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): Client SDK implements the DNS SRV share-location resolver; the SDK's SMB client wrapper consumes the resolver's output.
- **Migration** ([PC-128](../catalog/12-migration-and-coexistence.md)): Migration runbook includes the DFS-N migration playbook (Windows DFS-N → DNS SRV publication).

## References

- [PC-080](../catalog/07-file-gateway.md) — problem statement
- [docs/07-file-print/02-dfs-n-dfs-r.md](../docs/07-file-print/02-dfs-n-dfs-r.md) — `dfssvc.exe` and `dfsr.exe` architecture, NETDFS opnum table, RDC algorithm
- [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md) — `SMB2_SHAREFLAG_DFS` and `SMB2_SHAREFLAG_DFS_ROOT` flags
- [MS-DFSC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc) — Distributed File System: Naming Context (DFS-N) protocol
- [MS-DFSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsr) — Distributed File System: Replication (DFS-R) protocol
- [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782) — DNS SRV resource record
