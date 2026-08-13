---
title: File Gateway — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, file-gateway, framework-design, gap-analysis, smb, dfs, print, offline-files]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./06-federation-gateway.md
  - ./08-client-sdk.md
  - ./09-cross-platform-parity.md
  - ./14-cross-platform-parity-matrix.md
  - ./13-open-research-questions.md
last_updated: 2026-08-13
---

# File Gateway — Problem Catalog

## Capability definition

File and print services. SMB shares, DFS-N, DFS-R-equivalent, print spooler-equivalent, offline-files-equivalent. Inherits from AD's `lanmanserver` (`srv2.sys` + `srv.sys` + `srvnet.sys`), DFS-N (`dfssvc.exe`), DFS-R (`dfsr.exe`), Print Spooler (`spoolsv.exe`), and Offline Files (`cscsvc.dll` + `csc.sys`). Depends on Core Directory (publishes shares, printers, DFS topology) and Auth Provider (SMB auth). Consumed by the Client SDK (file/print client) and the Policy Engine (uses SYSVOL-equivalent for policy distribution).

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-078 | SMB 3.1.1 with pre-auth integrity + AES-GCM is required for modern Windows interop | blocker | Windows / macOS / Linux |
| PC-079 | SMB1 must be dropped (security liability); migration is automatic on modern Windows | blocker | Windows / macOS / Linux |
| PC-080 | DFS-N (namespace) + DFS-R (replication) are Windows-only; no Linux equivalent | high | Windows / Linux |
| PC-081 | Continuously Available (CA) shares require cluster + persistent handles | high | cross-platform |
| PC-082 | Access-Based Enumeration (ABE) post-filters directory listings; CPU cost | medium | cross-platform |
| PC-083 | PrintNightmare (CVE-2021-34527) exposed MS-RPRN driver install as SYSTEM | blocker | Windows / cross-platform |
| PC-084 | Offline Files (CSC) is Windows-only; no macOS/Linux equivalent | medium | Windows / macOS / Linux |

## Detailed problem entries

### PC-078 — SMB 3.1.1 with pre-auth integrity + AES-GCM is required for modern Windows interop

**Capability**: File Gateway
**Severity**: blocker
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

SMB 3.1.1 (dialect `0x0311`, introduced with Server 2016 / Windows 10) layers three security primitives onto the SMB session that earlier dialects lack: SHA-512 pre-auth integrity, AES-GCM (and AES-GMAC) as the encryption and signing cipher, and a `NegotiateContextList` that binds the entire Negotiate exchange into the session-key derivation. The pre-auth integrity hash (Negotiate Context type `0x0001`, `SMB2_PREAUTH_INTEGRITY_CAPABILITIES`) is computed over the entire Negotiate request and response per MS-SMB2 §3.2.5.1, and is then mixed into the HKDF-SHA512 key-derivation labeled `"SMBSigningKey\x00" / "ServerIn\x00" / "ServerOut\x00"`. Without pre-auth integrity, a MITM can downgrade dialect negotiation between a 3.1.1-capable client and an SMB 2.1 server, defeating the AES-GCM signing that 3.1.1 enables. AES-128-GCM and AES-256-GCM are advertised via Negotiate Context type `0x0002` (`SMB2_ENCRYPTION_CAPABILITIES`) and the cipher selection appears in the `SMB2_TRANSFORM_HEADER` (`EncryptionAlgorithm` field at offset `0x14`, values `0x0002`/`0x0004`). Signing via AES-GMAC is advertised via the `SMB2_SIGNING_CAPABILITIES` context (type `0x0008`), per the analysis in [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md).

The open-source stacks trail Microsoft at different paces. Samba added SMB 3.1.1 dialect support in 4.3 (2015), with AES-GCM encryption added in 4.4 and pre-auth integrity in 4.4; production stability arrived with Samba 4.7. Apple's SMBX kernel extension (`smbx.kext` replacing the earlier `smbfs.kext`) gained SMB 3.0.2 in macOS 10.13 and SMB 3.1.1 client support in macOS 11 Big Sur; server-side SMB 3.1.1 came later. The Linux CIFS kernel module (`cifs.ko`) supports SMB 3.1.1 with `vers=3.1.1,seal` mount options since kernel 5.x. The Windows reference implementation is `srv2.sys` (server) and `mrxsmb20.sys` (client), with the per-share `EncryptData` flag and the per-server `RequireSecuritySignature` registry key under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` controlling the security posture, per [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md).

A new framework cannot ship an SMB server that negotiates below SMB 3.0.2 for production use against Windows 10 1709+ clients; Windows refuses SMB 2.x to non-domain-joined servers under several GPO-enforced configurations (e.g. `EnableInsecureGuestLogons = 0`, Microsoft network client: Digitally sign communications policy). The dialect gap is not just "encryption"; without 3.1.1 the framework cannot offer downgrade-resistant session key derivation, and clients using AES-GMAC signing for performance (the AES-NI accelerated path in modern x86/ARM cores) fall back to AES-CMAC-128 in 3.0/3.0.2.

**Impact**:

Without SMB 3.1.1 the framework is unable to interoperate with Windows 10 1709+ and Windows Server 2019+ clients in their default hardened posture. The guest-mode and SMB1 fallbacks Microsoft has been disabling for five years leave no migration path. Quantitatively, Microsoft telemetry as of 2024 shows >95% of file-server traffic in enterprise AD deployments uses SMB 3.x dialects, with SMB 3.1.1 the majority dialect on Windows 11 + Server 2022.

**Constraints**:

- Must support dialect range SMB 2.0.2 (`0x0202`) → 3.1.1 (`0x0311`); lower bound is set by Samba-joined appliances and macOS SMBX in domain-joined mode.
- Must implement AES-128-GCM, AES-256-GCM, AES-128-CCM, AES-256-CCM cipher negotiation per MS-SMB2 `SMB2_ENCRYPTION_CAPABILITIES`.
- Must implement SHA-512 pre-auth integrity (`SMB2_PREAUTH_INTEGRITY_CAPABILITIES`), binding Negotiate into session-key derivation.
- Must support per-share `EncryptData = 1` and per-server `RequireSecuritySignature = 1` registry equivalents.
- Must remain wire-compatible with MS-SMB2; the framework cannot invent dialect extensions that Windows clients would refuse.

**Cross-platform considerations**:

- **Windows**: Reference is `srv2.sys` + `srvnet.sys`; pre-auth integrity is mandatory for SMB 3.1.1 negotiation, optional for 3.0.2. Windows 11 22H2+ refuses downgrade below 3.0 by default on domain-joined clients.
- **macOS**: SMBX in macOS 11+ ships 3.1.1 client; server-side SMB 3.1.1 came in macOS 13. Apple's implementation has known quirks with multichannel and persistent handles — see [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) cross-platform section.
- **Linux**: Samba 4.7+ has full 3.1.1; the kernel `cifs.ko` client supports 3.1.1 since 5.x. Older distros (RHEL 7, Debian 9) ship Samba 4.4-4.5 which cannot negotiate 3.1.1 — out of scope for greenfield.
- **Cross-platform consistency**: A framework SMB server must produce identical Negotiate responses and dialect selection on every platform. The AES-GCM performance profile (AES-NI) is uniform on x86_64 and Apple Silicon but absent on older ARMv7 edge devices — cipher selection must be a runtime negotiation, not a build-time default.

**KB references**:

- [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) — SMB 3.1.1 Negotiate context list, AES-GCM transform header, signing algorithm table per dialect.
- [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md) — `srv2.sys` driver architecture, per-share `EncryptData` / `ContinuouslyAvailable` registry flags, signing algorithm progression from HMAC-MD5 (SMB1) to AES-GMAC (SMB 3.1.1).

**Open questions**:

- Adopt Samba's `smbd` (GPLv3, full MS-SMB2 coverage, 25 years of bug-fix tail) or write a fresh SMB server in the framework's implementation language (Rust/Go) trading time-to-market for license clarity?
- Reuse macOS SMBX kernel extension on Apple platforms and Samba `smbd` elsewhere — accepting divergent code paths and feature drift?
- Implement SMB Direct (RDMA) in v1, or defer to a follow-up release given RDMA NIC heterogeneity on Linux (Mellanox vs Broadcom vs Chelsio) and absence on macOS?

**Cross-capability impact**:

- Affects: PC-079 (SMB1 removal), PC-081 (CA shares — persistent handles require SMB 3.0+), PC-022 (KDC FAST — SMB 3.1.1 encryption is the transport layer parallel for SMB auth hardening).
- Affected by: PC-083 (PrintNightmare — MS-RPRN rides over SMB named pipes; the SMB 3.1.1 posture constrains spooler RPC auth).

---

### PC-079 — SMB1 must be dropped (security liability); migration is automatic on modern Windows

**Capability**: File Gateway
**Severity**: blocker
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

SMB1 ("`NT LM 0.12`", dialect string `PC NETWORK PROGRAM 1.0` and successors) is the original 1985-era SMB dialect. Microsoft deprecated SMB1 server-side with Windows Server 2019 (default off, `EnableSMB1Protocol = 0` in `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`) and disabled the client by default on Windows 10 1709. Samba 4.5 (2016) made `server min protocol = SMB2_02` the default. The proximate cause was EternalBlue (MS17-010, CVE-2017-0144), which exploited a bug in `srvnet.sys!SrvNetWskReceiveComplete` reachable via SMB1 transaction commands; the broader cause is SMB1's structural unsoundness — 1985 design without integrity protection, MD4/MD5 MACs, oplock semantics incompatible with modern clustering, and the dialect-wide reliance on NetBIOS-over-TCP (port 139) alongside direct-hosted TCP/445, per [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) and the EternalBlue reference in [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md).

Apple shipped an SMB1-capable `smbfs.kext` until macOS 10.14 (when SMBX fully replaced it) and Samba-on-macOS via Homebrew retains SMB1 disabled by default. Linux `cifs.ko` can still mount SMB1 shares (the `vers=1.0` mount option) when talking to legacy NAS appliances (NetApp ONTAP 7-mode, old Synology DSM, Buffalo LinkStation), but distros increasingly ship with `vers=3.0` as the minimum in `/etc/modprobe.d/cifs.conf`. The Windows registry `EnableSMB1Protocol` and the Samba `server min protocol` directive are the two levers; both default to "off" in modern builds.

The framework must not negotiate SMB1 in any configuration. The cost of supporting SMB1 includes: (a) maintaining the SMB1 server-side dispatch in `srv.sys`-equivalent code (or Samba `source3/smbd/server.c`), (b) keeping the NetBIOS session service (TCP/139, UDP/137/138) for legacy client discovery, (c) preserving the broken oplock-v1 semantics that interfere with CA share failover, and (d) accepting the security exposure surface that EternalBlue-class bugs demonstrate. Microsoft's telemetry shows <0.1% of enterprise file-server traffic was SMB1 by 2023 — there is no operational reason to keep it.

**Impact**:

SMB1 is a recurring source of wormable vulnerabilities (EternalBlue, SMBGhost-adjacent). Including it in the framework ships a known-bad dialect with 2017-era exploit tooling that is still in active red-team circulation. The migration cost on modern Windows is zero (Microsoft auto-disables); the migration cost on Linux is one Samba config line and a distro upgrade; on macOS it is automatic. The cost of retaining SMB1 vastly exceeds the cost of dropping it.

**Constraints**:

- Must NOT negotiate SMB1; `server min protocol = SMB2_02` (or higher) at all times.
- Must NOT enable NetBIOS name/datagram services (UDP/137, UDP/138) or NetBIOS session service (TCP/139) in v1.
- Must document explicitly that legacy NAS appliances (NetApp ONTAP 7-mode, pre-DSM-7 Synology, Samba 3.x on old Linux) are out of scope; users must upgrade the appliance or run a Samba-3.x proxy.
- Must not break SYSVOL replication scenarios that depend on SMB1 fallback (Windows AD moved off this in Server 2008 R2 with DFSR-migrated SYSVOL — see [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md)).

**Cross-platform considerations**:

- **Windows**: `Set-SmbServerConfiguration -EnableSMB1Protocol $false` is the supported posture; the registry equivalent is `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\EnableSMB1Protocol = 0`. Server 2019+ ships this by default.
- **macOS**: SMBX has SMB1 disabled since macOS 10.14. Homebrew Samba follows upstream Samba defaults.
- **Linux**: Samba 4.5+ ships with `server min protocol = SMB2_02`. RHEL 8+, Ubuntu 18.04+ inherit this. Older distros must be hardened manually.
- **Cross-platform consistency**: A framework SMB server on every platform must refuse SMB1 Negotiate, returning `STATUS_INVALID_PARAMETER` (0xC000000D) on the Negotiate response when the client lists only `0x00FF` / `PC NETWORK PROGRAM 1.0` as supported dialects.

**KB references**:

- [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) — dialect history table (PC NETWORK PROGRAM 1.0 through SMB 3.1.1), MS17-010 / EternalBlue context, Samba `server min protocol` defaults.
- [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md) — `srv.sys` legacy SMB1 driver, `EnableSMB1Protocol` registry key, `srvnet.sys!SrvNetWskReceiveComplete` as the EternalBlue site.

**Open questions**:

- Hard cut with documentation, or provide an SMB1-compat shim as an out-of-tree module for the long tail of regulated customers with embedded appliances that cannot be upgraded?
- Document SMB1-only NAS appliances as out of scope and recommend a Samba 4.7+ proxy appliance in front, or refuse to support those customers entirely?

**Cross-capability impact**:

- Affects: PC-078 (SMB 3.1.1 floor — dropping SMB1 makes 3.0.2 the operational floor).
- Affected by: PC-080 (DFS-N leaf targets — legacy SMB1-only NAS appliances cannot host DFS-N targets).

---

### PC-080 — DFS-N (namespace) + DFS-R (replication) are Windows-only; no Linux equivalent

**Capability**: File Gateway
**Severity**: high
**Cross-platform**: Windows / Linux

**Problem statement**:

DFS Namesspaces (DFS-N) is the `dfssvc.exe` service that resolves a UNC path of the form `\\corp.example.com\Public\Engineering\docs\file.txt` into a per-site target referral using a Path Knowledge Table (pKT) cached in registry `HKLM\SOFTWARE\Microsoft\Dfs\Roots\Domain\<domain>\<namespace>` and stored authoritatively as `msDFS-NamespaceRoot` / `msDFS-Link` AD objects under `CN=Dfs-Configuration,CN=System,DC=...`. The referral is returned via the NETDFS RPC interface `[uuid(4FC742E0-4A10-11CF-8273-00AA004AE673)]` opnum 0/1/2, with site-costing computed against `CN=Subnets,CN=Sites,CN=Configuration,...` so a client in the `HQ` site gets redirected to a target in `HQ` first, per the analysis in [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md). DFS-R is the `dfsr.exe` service that multi-master replicates folder contents using RDC (Remote Differential Compression, an rsync-like rolling-hash algorithm in `rdparty.dll`) and the NTFS USN journal (`$Extend\$UsnJrnl:$J`, read via `FSCTL_READ_USN_JOURNAL`) for change detection. DFS-R's wire protocol is MS-DFSR `[uuid(91b7b931-c75a-4530-8258-1b3eb578c5d8)]`.

Samba's role is limited: it can act as a DFS-N leaf target (i.e., a share pointed to by a DFS-N namespace hosted on Windows) but cannot host a domain-based DFS namespace. There is no open-source DFS-R implementation. The Linux alternatives — `rsync`, `syncthing`, `lsyncd` — are point-to-point or simple tree-sync; they lack multi-master conflict resolution, USN-journal change tracking, and AD-integrated topology. `librsync` ships the RDC algorithm but is not integrated into any replication manager. macOS has neither DFS-N server nor DFS-R; its SMBX client can resolve DFS-N referrals for `mount_smbfs` access to Windows-hosted namespaces.

The implication for the framework is that DFS-N and DFS-R are two distinct gaps. DFS-N is a referral protocol — the framework can implement MS-DFSC client referral resolution without implementing a DFS-N server, by serving referrals from the Core Directory's `msDFS-*` objects. DFS-R is a content replication protocol — replacing it requires either (a) reusing DFS-R for interop with Windows DCs (DFS-R replicates SYSVOL on Server 2008 R2+; see [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md)), (b) adopting an alternative like `syncthing` for non-SYSVOL replication and an AD-interop shim for SYSVOL, or (c) reusing Samba 4's MS-DRSR-based SYSVOL replication (which is single-master per attribute, not multi-master).

**Impact**:

DFS-N is widely used for share abstraction — hard-coded `\\server\share` UNC paths in scripts, shortcuts, and applications break when servers are renamed or migrated. Without DFS-N, every share move requires DNS CNAME updates and client-side remapping. DFS-R is the only multi-master file replication protocol integrated with AD; without it, multi-site file shares require either manual rsync/syncthing glue or a SAN/NAS layer that externalizes replication. SYSVOL replication specifically is a hard dependency: every framework DC must serve SYSVOL consistently, and interop with Windows DCs requires either DFS-R (Windows-native) or Samba 4's DRSUAPI-on-SYSVOL approach.

**Constraints**:

- Must support `\\domain\share\path` UNC resolution for client compat — implement MS-DFSC referral (NETDFS opnum 0/1/2) returning `DFS_REFERRAL_V3` / `V4` structures.
- Must produce site-aware referrals using `CN=Subnets,CN=Sites,CN=Configuration,...` — site-costing identical to Windows.
- Must NOT implement DFS-R wire protocol unless SYSVOL interop with Windows DCs is a v1 requirement; otherwise externalize replication.
- Must preserve Samba-as-leaf-target behavior so framework-hosted shares can be referenced by Windows-hosted DFS namespaces.
- For SYSVOL replication specifically, must pick one: MS-DFSR (Windows interop), Samba-style DRSUAPI-on-SYSVOL (Samba interop), or clean-slate (no interop with either).

**Cross-platform considerations**:

- **Windows**: DFS-N and DFS-R are full Windows Server roles (`FS-DFS-Namespace`, `FS-DFS-Replication`). Managed via `New-DfsnRoot`, `New-DfsReplicationGroup`, `dfsrdiag`, `dfsutil`.
- **macOS**: SMBX client resolves DFS-N referrals via `mount_smbfs`. No DFS-N server, no DFS-R. See [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) cross-platform section.
- **Linux**: `cifs.ko` kernel module resolves DFS-N referrals for `mount -t cifs //domain/share`. Samba can be a leaf target. No DFS-N server, no DFS-R. `lsyncd` / `rsync` / `syncthing` are point-to-point alternatives.
- **Cross-platform consistency**: Framework-hosted DFS namespaces must produce identical referral responses from any framework DC, regardless of host OS. Site-costing tables must be shared via the Core Directory's `CN=Subnets` and `CN=SiteLink` objects, not stored per-host.

**KB references**:

- [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md) — `dfssvc.exe` and `dfsr.exe` architecture, pKT cache, `msDFS-Link` AD object schema, NETDFS `[uuid(4FC742E0-...)]` opnum table, USN journal `FSCTL_READ_USN_JOURNAL`, RDC algorithm, `dfsmig.exe` SYSVOL migration flow.
- [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md) — `lanmanserver` share flags including `SMB2_SHAREFLAG_DFS` and `SMB2_SHAREFLAG_DFS_ROOT` returned in `TreeConnect.GetResponse`, which DFS-N clients inspect to confirm namespace hosting.

**Open questions**:

- Adopt Kubernetes-style service discovery (DNS SRV records per service) for share location instead of DFS-N, accepting that Windows clients with hard-coded `\\domain\share` UNC paths will need migration tooling?
- Replicate SYSVOL via Git (pull-only per-DC, fast-forward only) for clean-slate framework deployments, with a DFS-R shim for interop with Windows DCs during migration?
- Reuse `librsync` for a content-replication engine that mimics DFS-R's RDC behavior without implementing the MS-DFSR wire protocol?

**Cross-capability impact**:

- Affects: PC-084 (Offline Files — CSC cache works against DFS-N targets; without DFS-N, CSC must resolve direct share paths).
- Affected by: PC-001 (Core Directory replication — DFS-R for SYSVOL is parallel to DRSUAPI for AD partition replication; the two share change-detection primitives like USN journals but are otherwise independent).

---

### PC-081 — Continuously Available (CA) shares require cluster + persistent handles

**Capability**: File Gateway
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

A Continuously Available (CA) share in Windows is one whose `TreeConnect.GetResponse` returns the `SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE` (0x0002) capability bit, signaling that the share is backed by a Failover Cluster role on top of a Cluster Shared Volume (CSV) and that the server will honor persistent handle create contexts (`DH2Q` — Durable Handle v2 Request, `0x44483251`; and `DH2C` — Durable Handle v2 Reconnect, `0x44483243`). When the cluster node hosting the SMB server role fails, the CSV moves to another node and the SMB client reconnects via `DH2C`, presenting its original `ClientGuid` (negotiated in the SMB2 Negotiate response at offset `0x0C`), the durable handle's `PersistentFileId`, and the session's `SessionId`. The client observes a brief TCP retransmit (typically 1-3 seconds) and then resumes I/O without losing open file handles, oplock state, or SMB leases, per the analysis in [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) and [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md).

The cluster requirement is the hard part. Samba's clustered mode (`CTDB` — Clustered Trivial Database) provides multi-node `smbd` with shared TDB state, but it does not implement transparent failover — when a CTDB node fails, the client's SMB session is torn down and the client must reconnect and re-open files. CTDB has no equivalent of `DH2Q`/`DH2C` reconnect semantics; Samba's `durable handles` (SMB 2.0+ `DH1Q` context) and `resilient handles` (SMB 2.1) survive network glitches but not server process death. There is no macOS equivalent — Apple's SMBX is single-node and cannot participate in a cluster. The Linux CSI (Container Storage Interface) + Kubernetes StatefulSet pattern approximates CA by wrapping `smbd` in a Pod with leader election, but the SMB client still experiences full session teardown on Pod failover.

The framework cannot achieve CA without solving three coupled problems: (a) shared storage accessible to every node in the cluster (CSV equivalent — typically a distributed block device like Ceph RBD or a shared NFS mount), (b) cluster quorum (Windows Failover Cluster uses a node majority + witness share; Kubernetes uses `lease` objects in etcd), and (c) persistent handle state stored in the shared storage so the new owner node can resume the session (Windows stores per-session state in CSV; the framework would need to write handle/oplock state to a shared key-value store). The Windows implementation lives in `srv2.sys`'s `Smb2CreateContextList` parser, with the `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` structure carrying the `CreateGuid`, `Flags` (bit `0x02` = `DH2Q_FLAG_PERSISTENT`), and `Timeout` fields.

**Impact**:

CA is required for production file-server HA. Without it, every cluster-node maintenance event (patching, reboot, upgrade) disconnects every SMB client with open handles to that node. For SQL Server over SMB, Hyper-V over SMB, and continuous-build CI workloads, every disconnect means a transaction abort or build failure. Quantified: a 1000-user file server with weekly patching loses ~3-5 minutes of productive work per user per patch cycle without CA, which is why Microsoft made CA the default for SOFS (Scale-Out File Server) deployments in Server 2012 R2+.

**Constraints**:

- Must support persistent handles (`DH2Q`/`DH2C` create contexts) per MS-SMB2 §2.2.31 and §3.3.5.9.
- Must support cluster quorum — either Windows Failover Cluster equivalent or Kubernetes leader election.
- Must store persistent-handle state (open files, leases, oplocks, session keys) in shared storage accessible to every cluster node.
- Must implement `SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE` advertisement in `TreeConnect.GetResponse` only when the share is genuinely backed by cluster storage.
- Failover time must be ≤ 30 seconds (Windows default is 5-15s); longer breaks client-side reconnect timeouts.

**Cross-platform considerations**:

- **Windows**: Reference is CSV + SOFS + Failover Cluster. `Set-SmbShare -ContinuouslyAvailable $true` requires the share to live on a CSV-backed clustered file server role.
- **macOS**: SMBX has no cluster mode. The framework cannot offer CA on macOS without writing a clustered SMBX equivalent.
- **Linux**: Samba CTDB is the only mature clustered SMB server, but lacks transparent failover. The framework would need to either extend CTDB with persistent-handle reconnect or build a fresh clustered SMB server on top of a shared key-value store (etcd, FoundationDB) for handle state.
- **Cross-platform consistency**: A framework CA share must behave identically regardless of host OS. This is the hardest cross-platform requirement in the File Gateway — cluster quorum, shared storage, and persistent-handle state are all platform-divergent primitives.

**KB references**:

- [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md) — `ContinuouslyAvailable` registry flag, `SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE` bit in `TreeConnect.GetResponse`, CSV/SOFS prerequisite, persistent handle `DH2Q`/`DH2C` create contexts.
- [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) — `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` structure, `CreateGuid` field, `DH2Q_FLAG_PERSISTENT` bit, lease break behavior during failover, the Samba CTDB limitation noted in the cross-platform section.

**Open questions**:

- Build a clustered SMB server in a container (CSI + PVC + leader election) and accept that failover requires SMB session re-establishment, or invest in true persistent-handle support by storing handle state in a shared etcd/FDB cluster?
- Reuse CTDB-style clustered Samba for the Linux tier and document macOS as non-CA, accepting platform-divergent file-server HA posture?
- Adopt a new wire-compatible CA protocol extension (e.g. `DH3Q`) that lets the framework store handle state in a content-addressable store rather than CSV, trading wire-compat for implementation simplicity?

**Cross-capability impact**:

- Affects: PC-078 (SMB 3.1.1 — persistent handles require SMB 3.0+; the floor is set here).
- Affected by: PC-001 (Core Directory replication — the cluster quorum service could be the same Raft consensus used for AD replication).

---

### PC-082 — Access-Based Enumeration (ABE) post-filters directory listings; CPU cost

**Capability**: File Gateway
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Access-Based Enumeration (ABE) is enabled per-share via the `AccessBasedEnumeration = 1` REG_DWORD under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\<ShareName>`. When enabled, `srv2.sys!SrvSmbQueryDirectoryInformation` post-filters `FILE_DIRECTORY_INFORMATION` / `FILE_BOTH_DIR_INFORMATION` / `FILE_NAMES_INFORMATION` responses to only return entries the caller has `FILE_ListDirectory` (read) access to via NTFS ACL. The check happens after the underlying file system returns the full directory listing — `srv2.sys` walks each entry, evaluates the NTFS ACL against the caller's token, and removes inaccessible entries from the response buffer before returning it to the client. There is no pre-filtering at the NTFS layer, no index, no caching across calls. The PowerShell cmdlet `Set-SmbShare -FolderEnumerationMode AccessBased` exposes the same flag, per [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md).

Samba implements the equivalent via `hide unreadable = yes` in `smb.conf`, processed by `smbd/dir.c:OpenDir` + `smbd/dir.c:SeekDir` — same post-filter model. Linux can also use POSIX ACLs with the `cifs.ko` `cifsacl` mount option, but ABE is server-side; the client never sees filtered entries. macOS SMBX has no documented ABE support; MDM-deployed shares rely on the underlying Windows/Samba server for ABE. The performance characteristic is universal: ABE cost is O(n) per directory enumeration where n is the entry count, and the per-entry ACL evaluation walks the SD's DACL (typically 3-10 ACEs per file in a domain-joined share).

The Windows performance guidance for ABE is to disable it on shares with >10,000 entries per directory, or to subdivide directories so no single listing exceeds ~1,000 entries. The framework inherits this constraint: any cross-platform ABE implementation must post-filter at the SMB response layer, walking NTFS ACLs per entry. Pre-computed ABE indexes (per-user materialized views of accessible entries) are a research direction Microsoft has not shipped; Samba has not implemented them either. The framework could innovate here, but the design tension is between stale-views (acceptable staleness, low CPU) and live-evaluation (correct, expensive).

**Impact**:

Without ABE, users see filenames they cannot open — usability regression. With ABE, large directories become slow on every `ls` / `dir` / `FindFirstFile` call. In practice, ABE is a non-negotiable feature for any share exposed to non-admin users (Home directories, Department shares); the question is performance, not whether to implement it. Quantified: a directory with 50,000 entries takes ~3-5 seconds to enumerate with ABE on a stock Windows file server, versus <500ms without.

**Constraints**:

- Must support per-share ABE toggle (Windows registry equivalent `AccessBasedEnumeration = 0|1`).
- Must support NTFS ACL evaluation; POSIX ACLs are insufficient (no `OWNER_RIGHTS` / `CREATOR OWNER` semantics).
- Must preserve ABE behavior on `FindFirstFile`/`FindNextFile` chained calls — the filter state must persist across multiple SMB `QUERY_DIRECTORY` requests within one create-handle.
- Must produce identical enumeration results across Windows, macOS, and Linux clients connecting to the same framework-hosted share.

**Cross-platform considerations**:

- **Windows**: `srv2.sys` post-filter, registry flag per share. `Set-SmbShare -FolderEnumerationMode AccessBased`.
- **macOS**: SMBX has no first-party ABE. Framework-hosted shares on macOS must implement ABE in the framework's SMB server, not delegate to SMBX.
- **Linux**: Samba `hide unreadable = yes` is the equivalent. The framework can reuse Samba's post-filter if Samba is the underlying SMB server.
- **Cross-platform consistency**: ABE evaluation must produce identical results regardless of caller's OS. This requires the framework's NTFS ACL evaluator to be authoritative, not the host OS's permission model.

**KB references**:

- [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md) — `AccessBasedEnumeration` per-share registry flag, `srv2.sys!SrvSmbQueryDirectoryInformation` post-filter implementation, `Set-SmbShare -FolderEnumerationMode AccessBased` cmdlet, troubleshooting note about ABE CPU overhead.
- [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) — `FILE_DIRECTORY_INFORMATION` and `FILE_BOTH_DIR_INFORMATION` response structures that ABE filters, `QUERY_DIRECTORY` (SMB2 cmd `0x0E`) request/response semantics, Samba `hide unreadable = yes` cross-platform equivalent.

**Open questions**:

- Pre-compute ABE indexes (per-user materialized views of accessible entries, refreshed on ACL change) to amortize the per-call cost, accepting stale views of up to N seconds?
- Use the framework's Core Directory to store share ACLs as `nTSecurityDescriptor` on `msDFS-Link` / `share` AD objects, so ABE evaluation can leverage the directory's existing SD cache (`sdtable` in AD's ESE) rather than walking per-file ACLs?

**Cross-capability impact**:

- Affects: PC-013 (Core Directory ACL evaluation — share ACLs and NTFS ACLs share the same SD evaluation engine).
- Affected by: PC-078 (SMB 3.1.1 — `QUERY_DIRECTORY` responses can be encrypted via SMB 3.1.1 transform headers, which interacts with ABE filtering because the filter runs before encryption).

---

### PC-083 — PrintNightmare (CVE-2021-34527) exposed MS-RPRN driver install as SYSTEM

**Capability**: File Gateway
**Severity**: blocker
**Cross-platform**: Windows / cross-platform

**Problem statement**:

CVE-2021-34527 ("PrintNightmare") and its sibling CVE-2021-36958 exploited MS-RPRN's `RpcAddPrinterDriverEx` (opnum 109 on the Print System Remote Protocol interface `[uuid(0F30C728-D1DA-11D2-AE4F-00A0C92B955C)]`) to achieve SYSTEM code execution on any print server reachable over MS-RPRN RPC. The vector: a caller with `LoadDriver` privilege (or in some pre-patch configurations, any authenticated user) supplies a `DRIVER_CONTAINER` structure pointing to a UNC path containing an attacker-controlled DLL. The spooler service (`spoolsv.exe`, running as `NT AUTHORITY\NetworkService` but with a `LoadLibrary`-capable subsystem) copies the DLL to `C:\Windows\System32\spool\drivers\x64\3\` as SYSTEM and then loads it via `LoadLibrary`, achieving SYSTEM code execution in the spooler process. The fix (KB5004945) added path validation to `localspl.dll!SplAddPrinterDriver` that rejects UNC paths and verifies the requesting user can read the file directly, per [`07-file-print/03-print-services.md`](../docs/07-file-print/03-print-services.md).

The deeper architectural problem is that MS-RPRN's Type 3 driver model loads third-party code (driver DLLs, renderers, port monitors) into the spooler process. Microsoft's mitigation in Server 2012+ was Type 4 drivers (`PrinterDriverClass=v4` in the INF), which use the spooler's built-in XPS render pipeline and don't load third-party code. Type 4 + `PrintIsolationHost.exe` (driver isolation in a separate low-integrity process since Server 2008 R2) is the only safe Windows print architecture. The framework's print subsystem must not implement the MS-RPRN driver-install code path; it should expose printing via IPP Everywhere (RFC 8011, driverless) and CUPS-style filters (which run as a low-privilege `lp` user, not as root/SYSTEM), per the cross-platform comparison in [`07-file-print/03-print-services.md`](../docs/07-file-print/03-print-services.md).

Samba's `cups` backend (`source3/printing/print_cups.c`) hands print jobs to CUPS via the IPP protocol; Samba itself does not load driver DLLs into a SYSTEM-equivalent process on Linux. macOS uses CUPS as its entire print stack (Apple acquired CUPS in 2007), exposing IPP on TCP 631 with driver filters stored in `/Library/Printers/` running as the `lp` user. Linux CUPS is identical. The cross-platform print security posture is therefore already aligned with the PrintNightmare-safe architecture — the framework must simply refuse to implement MS-RPRN driver install and document IPP Everywhere as the only supported client-printer protocol.

**Impact**:

PrintNightmare-class vulnerabilities are systemic. MS-RPRN driver install was the source of at least four CVEs in 2021-2022 (CVE-2021-34527, CVE-2021-36958, CVE-2021-34483, CVE-2021-26878). Any framework that implements the MS-RPRN driver install path inherits this attack surface. Conversely, dropping MS-RPRN entirely and standardizing on IPP Everywhere means Windows clients must use Type 4 driverless printing (supported since Windows 10 21H2 with the IPP driver class) or a CUPS-compatible driver model. Print queue AD publication (`printQueue` objects under `CN=<server>,CN=PrintQueues,...`) can still be supported for discovery without supporting the MS-RPRN driver-install code path.

**Constraints**:

- Must NOT implement `RpcAddPrinterDriverEx` (opnum 109) or `RpcAddPrinterDriver` (opnum 17) in any form.
- Must NOT load third-party driver code into the print spooler process — Type 4 (driverless) or CUPS filters only.
- Must enforce `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (auth level 6) on all MS-RPRN RPC calls if any subset of MS-RPRN is implemented for legacy compat (e.g. `RpcEnumPrinters` opnum 3 for printer discovery).
- Must enforce `RestrictDriverInstallationToAdministrators = 1` registry equivalent and `RestrictAnonymousShareAccess = 1` for `\\server\print$` SMB share if driver distribution via `print$` is supported.
- Must support `printQueue` AD object publication for printer discovery without supporting driver-install over RPC.

**Cross-platform considerations**:

- **Windows**: Type 4 driverless printing + `PrintIsolationHost.exe` is the safe path. The framework's Windows client should use the IPP class driver (Windows 10 21H2+), not legacy Type 3 drivers.
- **macOS**: CUPS already runs filters as `lp` user. Framework-hosted print queues should advertise via Bonjour `_ipp._tcp` mDNS for macOS discovery, not MS-RPRN.
- **Linux**: CUPS is identical to macOS. Framework-hosted queues should advertise via Avahi mDNS or be discovered via LDAP query against `printQueue` AD objects.
- **Cross-platform consistency**: IPP Everywhere (RFC 8011 + PWG 5100.18) is the universal driverless print protocol supported by Windows 10 21H2+, macOS 11+, and Linux CUPS 1.5+. Standardizing on IPP Everywhere eliminates the platform-divergent driver distribution problem entirely.

**KB references**:

- [`07-file-print/03-print-services.md`](../docs/07-file-print/03-print-services.md) — `spoolsv.exe` service architecture, MS-RPRN `[uuid(0F30C728-...)]` opnum table (including opnum 109 `RpcAddPrinterDriverEx`), Type 2/3/4 driver model, `PrintIsolationHost.exe` isolation, `RestrictDriverInstallationToAdministrators` registry mitigation, KB5004945 patch details.
- [`02-protocols/03-smb-cifs-protocol.md`](../docs/02-protocols/03-smb-cifs-protocol.md) — MS-RPRN rides over SMB named pipe `\PIPE\SPOOLSS`; the SMB 3.1.1 encryption and signing posture constrains the RPC auth level that MS-RPRN can negotiate.

**Open questions**:

- Drop MS-RPRN entirely (including `RpcEnumPrinters` for discovery) and use LDAP queries against `printQueue` AD objects + Bonjour/Avahi mDNS for printer discovery, or implement a read-only MS-RPRN subset for legacy Windows clients that expect `\\server` enumeration?
- Provide a CUPS-compatible print server in the framework (reusing CUPS or writing a fresh IPP server), or expose printer shares via Samba's `cups` backend on Linux/macOS and document Windows clients as needing IPP driver class?

**Cross-capability impact**:

- Affects: PC-078 (SMB 3.1.1 — MS-RPRN over `\PIPE\SPOOLSS` inherits the SMB session's encryption posture).
- Affected by: PC-013 (Core Directory — `printQueue` object publication requires AD schema extension).

---

### PC-084 — Offline Files (CSC) is Windows-only; no macOS/Linux equivalent

**Capability**: File Gateway
**Severity**: medium
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

Offline Files (Client-Side Cache, CSC) is implemented on Windows by `cscsvc.dll` (the user-mode service) + `csc.sys` (the kernel mini-redirector that intercepts SMB Create/Read/Write when offline) + `cscdll.dll` (the Win32 API) + `cscapi.dll` (UI helpers) + `SyncHost.dll` (the background sync agent), backed by an encrypted proprietary-format cache at `%SystemRoot%\CSC\v2.0.6\` (CSC v2 since Server 2012 — 256-bit AES via DPAPI machine key, sparse-file-optimized format). Sync triggers fire at logon/logoff (via `winlogon.exe` calling `SyncServiceProvider.LogonSync`/`LogoffSync`), on a Task Scheduler job (`\Microsoft\Windows\OfflineFiles\BackgroundSync`, default 120 minutes), on network change events (via `INetworkListManagerEvents`), and on slow-link transitions (via `cscsvc.dll!SlowLinkDetector` measuring 16-KB block round-trip against `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache\SlowLinkSpeed`, default 64000 bps), per [`07-file-print/04-offline-files.md`](../docs/07-file-print/04-offline-files.md). Conflict resolution is configurable per-share via `NetCache\Shares\<ShareName>\ConflictResolution` (0=ask, 1=server-wins, 2=client-wins).

macOS has no native equivalent. The closest third-party options (ExpanDrive, Mountain Duck) cache remote SMB/WebDAV shares locally and sync on reconnect, but lack integration with Apple's SMBX client and have no MDM-managed conflict-resolution policy. Apple's "always online" assumption (mobile accounts + portable home directories, deprecated) used rsync-based sync but is not actively developed. Linux has no native Offline Files feature either: `ccachefs` and `OfflineFS` are experimental FUSE filesystems, unmaintained. `cifs.ko` with `cache=loose` provides page-cache only, not offline access. The closest Linux pattern is Syncthing or Nextcloud client for full offline support — but neither integrates with SMB semantics (no `FILE_DIRECTORY_INFORMATION` filtering, no lease preservation across offline periods, no `DH2Q`/`DH2C` reconnect after offline-to-online transition).

The framework faces a scoping question. CSC is a Windows-specific technology with deep kernel integration (`csc.sys` is a mini-redirector layered under `rdbss.sys`, intercepting IRP_MJ_CREATE/READ/WRITE for UNC paths). Reimplementing it cross-platform requires a kernel-mode or FUSE component on every platform. The minimum viable alternative is a userspace sync agent that materializes offline copies on local disk and synchronizes via SMB on reconnect — losing transparent offline access (apps must use the local cache path, not the UNC) but gaining cross-platform portability. Apple's PSSO Extension model suggests the framework could ship a userspace agent that runs as a LaunchAgent (macOS), systemd user service (Linux), and Win32 service (Windows) with platform-specific file-watch mechanisms (`fs_events` on macOS, `inotify`/`fanotify` on Linux, `ReadDirectoryChangesW` on Windows).

**Impact**:

Mobile users on Windows depend on CSC for offline access to network shares — losing it forces them to use VPN for every file access. macOS and Linux users have no equivalent today; they rely on SyncThing/Nextcloud client or accept online-only access. The framework's value-add is unified behavior: same offline cache format, same conflict-resolution policies, same MDM-managed configuration on every platform. Quantified: ~30-40% of enterprise laptops use offline files regularly (per Microsoft usage telemetry), making this a v1 must-have for any framework targeting Windows replacement.

**Constraints**:

- If in scope, must support conflict resolution (server-wins / client-wins / ask-user) per-share, configurable via policy.
- Must support transparent cache (apps use UNC path, not local cache path) — requires kernel-mode integration on Windows and FUSE on Linux/macOS.
- Must support sync triggers at logon/logoff, scheduled, network-change, and slow-link transition.
- Must support cache encryption (AES-256 minimum, keyed to platform's key store — DPAPI on Windows, Keychain on macOS, kernel keyring on Linux).
- If out of scope, must document the gap and recommend Nextcloud client or Syncthing as the supported alternative.

**Cross-platform considerations**:

- **Windows**: Reference implementation is `cscsvc.dll` + `csc.sys`. The framework should preserve CSC behavior on Windows by reusing the OS stack where possible.
- **macOS**: No native equivalent. Framework must ship a userspace sync agent or document the gap.
- **Linux**: No native equivalent. Framework must ship a userspace sync agent (possibly via FUSE) or document the gap.
- **Cross-platform consistency**: If the framework ships an offline-files agent, the cache format, conflict-resolution semantics, and sync trigger model must be identical across platforms. The cache encryption key store is platform-divergent (DPAPI / Keychain / kernel keyring) — the framework must abstract this.

**KB references**:

- [`07-file-print/04-offline-files.md`](../docs/07-file-print/04-offline-files.md) — `cscsvc.dll` + `csc.sys` architecture, CSC v2 cache format at `%SystemRoot%\CSC\v2.0.6\`, slow-link detection at 64 Kbps default, conflict resolution registry keys, `Win32_OfflineFilesCache` WMI provider, transparent caching vs Always Offline mode, cross-platform gap analysis (no macOS/Linux equivalents).
- [`07-file-print/01-smb-shares-internals.md`](../docs/07-file-print/01-smb-shares-internals.md) — `CacheFlags` per-share registry value (0x00 manual, 0x10 automatic documents, 0x20 automatic programs, 0x40 no caching default, 0x30 branchcache), `SHARE_INFO_1005` `CSCFlags` field semantics, the share-level caching policy that CSC reads at TreeConnect time.

**Open questions**:

- Out of scope (recommend Nextcloud client or Syncthing as the supported alternative), or implement minimal CSC-compatible cache?
- If implementing, use FUSE on Linux/macOS for transparent cache (apps see UNC, not local path) at the cost of kernel-mode complexity, or use a userspace agent that exposes a separate `~/OfflineCache/` directory and rely on app cooperation?
- Reuse the existing CSC v2 cache format on Windows (interop with native CSC) and a new format on macOS/Linux, accepting format divergence?

**Cross-capability impact**:

- Affects: PC-080 (DFS-N — CSC cache works against DFS-N targets; the framework's offline agent must resolve DFS-N referrals before caching).
- Affected by: PC-078 (SMB 3.1.1 — CSC sync uses the same SMB session as online access; the encryption posture applies to both).

---

## Cross-capability impact

The File Gateway's seven problems cluster around three architectural tensions:

1. **SMB dialect floor** (PC-078, PC-079, PC-081): The framework must commit to SMB 3.1.1 as the production floor, dropping SMB1 entirely and requiring persistent handles for CA shares. This affects the Client SDK (PC-085) which must produce SMB 3.1.1 clients, and the Auth Provider (PC-029, NTLM relay mitigation) which inherits the SMB signing/encryption posture.

2. **DFS replication strategy** (PC-080, PC-084): DFS-R has no open-source equivalent; the framework must either re-implement DFS-R for SYSVOL interop, adopt Samba 4's DRSUAPI-on-SYSVOL approach, or externalize replication entirely. The Offline Files gap (PC-084) compounds this — a cross-platform sync agent must work against DFS-N targets, which requires implementing MS-DFSC referral resolution in the Client SDK (PC-085).

3. **Print security model** (PC-083): The framework must refuse MS-RPRN driver install and standardize on IPP Everywhere. This affects the Client SDK (PC-085) which must produce IPP clients, and the Policy Engine (PC-050) which distributes printer-configuration policy via MDM Configuration Profiles (macOS) or Group Policy Preferences (Windows).

Cross-capability impacts that flow into File Gateway from other capabilities:

- From **KDC** (PC-023, MS-KILE profile): SMB session setup uses Kerberos via GSS-SPNEGO; the KDC's PAC contents (group SIDs) flow through to share ACL evaluation in ABE (PC-082).
- From **Auth Provider** (PC-029, NTLM relay mitigation): SMB signing mandatory (PC-078's `RequireSecuritySignature`) is the primary NTLM relay defense on the SMB transport.
- From **Core Directory** (PC-013, SD evaluation engine): ABE (PC-082) and share ACL evaluation depend on the same `nTSecurityDescriptor` evaluation code path that the Core Directory uses for AD object ACLs.
- From **Operations** (PC-106, observability): SMB server health, DFS-R backlog, spooler queue depth, and CSC sync state must be exposed as Prometheus metrics and OpenTelemetry traces.

## Open research questions specific to this capability

1. **SMB server implementation choice** — Adopt Samba's `smbd` (GPLv3, mature, MS-SMB2 complete), write a fresh Rust/Go SMB server (license-clear, but ~5 years to MS-SMB2 completeness), or wrap platform-native SMB stacks (SMBX on macOS, Samba on Linux, srv2.sys-equivalent on Windows) accepting divergent feature surfaces?

2. **CA share architecture** — Build a clustered SMB server with shared persistent-handle state (etcd/FDB-backed), or accept that CA shares are a Windows-only feature and document macOS/Linux as non-CA? If the former, what is the cross-platform cluster quorum story (Kubernetes leases, etcd, or a custom Raft)?

3. **DFS replication** — Re-implement MS-DFSR for SYSVOL interop with Windows DCs, adopt Samba's DRSUAPI-on-SYSVOL approach (clean-slate but breaks interop with Windows DCs in mixed environments), or externalize replication entirely (Git for SYSVOL, Syncthing for non-SYSVOL)? What are the implications for migration scenarios (PC-122+) where the framework must coexist with Windows DCs?

4. **Print driver model** — Drop MS-RPRN entirely and standardize on IPP Everywhere (RFC 8011 + PWG 5100.18), or implement a read-only MS-RPRN subset for legacy Windows client discovery? If the former, what is the migration path for customers with existing Type 3 driver deployments?

5. **Offline files** — Implement a cross-platform userspace sync agent (Nextcloud-client-like) with transparent FUSE-based cache on Linux/macOS, or document offline files as out of scope and recommend third-party solutions? If implementing, how does the framework handle conflict resolution when the same file is modified offline on two devices?

6. **ABE performance** — Pre-compute per-user ABE indexes (materialized views of accessible entries, refreshed on ACL change) or accept the O(n) per-call cost? If pre-computing, what is the staleness tolerance, and how does the index update propagate across cluster nodes?

7. **Cross-platform CA semantics** — If the framework ships a clustered SMB server with persistent handles, what is the minimum cluster size (2 nodes for HA, 3 nodes for quorum), and how does this interact with the framework's AD-equivalent multi-master replication topology (typically 3+ DCs)?
