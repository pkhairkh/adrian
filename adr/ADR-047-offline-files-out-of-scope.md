---
title: "ADR-047: Offline Files Out of Scope; Recommend Sync Clients"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: File Gateway
problem: PC-084
severity: medium
tags: [adr, file-gateway, offline-files, csc, sync-clients, out-of-scope]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/07-file-gateway.md
  - ../docs/07-file-print/04-offline-files.md
  - ../docs/07-file-print/01-smb-shares-internals.md
last_updated: 2026-08-13
---

# ADR-047: Offline Files Out of Scope; Recommend Sync Clients

## Status

Accepted — 2026-08-13

## Context

Offline Files (Client-Side Cache, CSC) is implemented on Windows by `cscsvc.dll` (the user-mode service) + `csc.sys` (the kernel mini-redirector that intercepts SMB Create/Read/Write when offline) + `cscdll.dll` (the Win32 API) + `cscapi.dll` (UI helpers) + `SyncHost.dll` (the background sync agent), backed by an encrypted proprietary-format cache at `%SystemRoot%\CSC\v2.0.6\` (CSC v2 since Server 2012 — 256-bit AES via DPAPI machine key, sparse-file-optimized format), per [docs/07-file-print/04-offline-files.md](../docs/07-file-print/04-offline-files.md). Sync triggers fire at logon/logoff (via `winlogon.exe` calling `SyncServiceProvider.LogonSync`/`LogoffSync`), on a Task Scheduler job (`\Microsoft\Windows\OfflineFiles\BackgroundSync`, default 120 minutes), on network change events (via `INetworkListManagerEvents`), and on slow-link transitions (via `cscsvc.dll!SlowLinkDetector` measuring 16-KB block round-trip against `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache\SlowLinkSpeed`, default 64000 bps). Conflict resolution is configurable per-share via `NetCache\Shares\<ShareName>\ConflictResolution` (0=ask, 1=server-wins, 2=client-wins).

CSC is structurally a Windows-specific technology with deep kernel integration (`csc.sys` is a mini-redirector layered under `rdbss.sys`, intercepting `IRP_MJ_CREATE`/`IRP_MJ_READ`/`IRP_MJ_WRITE` for UNC paths). macOS has no native equivalent: the closest third-party options (ExpanDrive, Mountain Duck) cache remote SMB/WebDAV shares locally and sync on reconnect, but lack integration with Apple's SMBX client and have no MDM-managed conflict-resolution policy. Apple's "always online" assumption (mobile accounts + portable home directories, deprecated) used rsync-based sync but is not actively developed. Linux has no native Offline Files feature either: `ccachefs` and `OfflineFS` are experimental FUSE filesystems, unmaintained. `cifs.ko` with `cache=loose` provides page-cache only, not offline access. The closest Linux pattern is Syncthing or Nextcloud client for full offline support — but neither integrates with SMB semantics (no `FILE_DIRECTORY_INFORMATION` filtering, no lease preservation across offline periods, no `DH2Q`/`DH2C` reconnect after offline-to-online transition).

The framework faces a scoping question. Reimplementing CSC cross-platform requires a kernel-mode or FUSE component on every platform. The minimum viable alternative is a userspace sync agent that materializes offline copies on local disk and synchronizes via SMB on reconnect — losing transparent offline access (apps must use the local cache path, not the UNC) but gaining cross-platform portability. Per [PC-084](../catalog/07-file-gateway.md#pc-084--offline-files-csc-is-windows-only-no-macoslinux-equivalent)'s impact analysis, ~30-40% of enterprise laptops use offline files regularly, making this a v1 must-have for any framework targeting Windows replacement. But the must-have framing is misleading: those users do not need CSC specifically; they need offline access to network shares. Sync clients (Nextcloud, OneDrive, iCloud Drive) provide that, with cross-platform support, MDM-managed configuration, and active development.

The constraints from [PC-084](../catalog/07-file-gateway.md#pc-084--offline-files-csc-is-windows-only-no-macoslinux-equivalent) are explicit: if in scope, the framework must support conflict resolution per-share (server-wins / client-wins / ask-user) configurable via policy; transparent cache (apps use UNC path, not local cache path) requiring kernel-mode integration on Windows and FUSE on Linux/macOS; sync triggers at logon/logoff, scheduled, network-change, and slow-link transition; cache encryption (AES-256 minimum, keyed to platform's key store — DPAPI on Windows, Keychain on macOS, kernel keyring on Linux). If out of scope, the framework must document the gap and recommend Nextcloud client or Syncthing as the supported alternative. The "if in scope" path is a multi-year engineering effort; the "if out of scope" path is documentation and integration testing. The decision is forced by the framework's v1 timeline and the maturity of the third-party sync-client ecosystem.

## Decision

The framework's File Gateway will not implement Offline Files (CSC) or a CSC-compatible cache. The framework will document Offline Files as out of scope for v1 and recommend Nextcloud client (cross-platform, mature, MDM-managed) as the primary supported alternative, with Syncthing (cross-platform, P2P, no central server) as the secondary alternative for customers who prefer a serverless model. The framework will provide integration documentation for both clients, including MDM-managed configuration templates (macOS), Group Policy templates (Windows), and Ansible roles (Linux) that pre-configure the sync client to mount framework-hosted shares via SMB and synchronize to a local cache directory.

**Concrete specification**:

- The framework's File Gateway MUST NOT implement Offline Files (CSC), `csc.sys`-equivalent kernel mini-redirector, `cscsvc.dll`-equivalent user-mode service, or any CSC v2 cache-format reader/writer.
- The framework's documentation MUST include an "Offline Files (CSC) — out of scope" section in the File Gateway capability overview, citing this ADR and directing users to the recommended alternatives.
- The framework's documentation MUST include integration guides for two recommended sync clients:
  - **Nextcloud client** (primary recommendation): cross-platform (Windows, macOS, Linux), MIT-licensed, supports selective sync, conflict resolution (ask-user default), MDM-managed configuration via `Nextcloud.cfg` plist/JSON. The guide MUST include: macOS MDM Configuration Profile (`com.nextcloud.desktopclient` payload), Windows Group Policy template (`nextcloud.admx`), Linux Ansible role (deploy `~/.config/Nextcloud/nextcloud.cfg` with share mount point = `\\<server>\<share>` and local cache = `~/Nextcloud/<share>`).
  - **Syncthing** (secondary recommendation): cross-platform, MPL-2.0-licensed, P2P (no central server), supports versioning for conflict resolution. The guide MUST include: macOS LaunchDaemon plist, Windows service configuration, Linux systemd unit, and a "share folder" configuration that points at the framework-hosted SMB share via `mount_smbfs` (macOS) / `mount -t cifs` (Linux) / `New-SmbMapping` (Windows) on startup.
- The framework's Client SDK MUST provide a `framework-share mount` CLI that mounts a framework-hosted share via SMB and exposes a stable local mount path (e.g. `/run/framework/shares/<share-name>` on Linux, `/Volumes/<share-name>` on macOS, `Z:\<share-name>` on Windows). The sync client is configured against this stable mount path, decoupling sync-client configuration from underlying share server identity.
- The framework's Policy Engine MUST ship a "sync client deployment" policy template (Windows GPO + macOS Configuration Profile + Linux Ansible role) that auto-installs Nextcloud client (or Syncthing) and pre-configures it to sync the user's home share. The policy template MUST be optional (the framework does not require sync-client deployment for basic file access).
- The framework's documentation MUST include a migration guide for customers moving from Windows CSC to Nextcloud/Syncthing: (1) inventory existing CSC-enabled shares via `OfflineFiles` GPO and per-share `CSCFlags` registry, (2) for each share, deploy the sync-client policy, (3) on first sync, the client downloads the user's home share contents to local cache, (4) verify with the user that the local cache contains the expected files, (5) disable CSC on the share (`Set-SmbShare -CachingMode None`).
- The framework's documentation MUST explicitly call out the transparent-cache limitation: apps must use the sync client's local cache path, not the UNC path, when offline. Apps that hard-require UNC path access when offline (rare — typically legacy MS Access databases over UNC) are documented as out of scope and require either an always-online posture (VPN, DirectAccess-equivalent) or a per-app migration to a sync-friendly storage model.
- The framework's automated test suite MUST include a sync-client integration test: deploy Nextcloud client against a test framework-hosted share, verify file synchronization in both directions, verify conflict detection on simultaneous edit, verify offline access (disconnect network, edit local, reconnect, verify sync completes). The test MUST run on Windows, macOS, and Linux.
- The framework's Prometheus exporter MUST expose share-mount metrics (`smb_share_mount_seconds{share="<name>"}`, `smb_share_mount_active{share="<name>"}`) so operations teams can monitor whether sync clients are successfully mounting framework-hosted shares.

## Rationale

The decision to scope out CSC is forced by v1 economics. Implementing CSC cross-platform is a multi-year engineering effort: a kernel mini-redirector on Windows, a FUSE filesystem on Linux and macOS, a CSC v2-compatible cache format on Windows (for interop with existing CSC-enabled shares), a new cache format on Linux/macOS, conflict resolution policies, sync triggers, cache encryption across three platform key stores, and integration with the framework's SMB session lifecycle. The framework's v1 timeline cannot absorb this work; the framework's v1 value proposition (modern, secure, cross-platform AD replacement) does not require it. The third-party sync-client ecosystem (Nextcloud, Syncthing, OneDrive, iCloud Drive) is mature, cross-platform, MDM-managed, and actively developed — the framework cannot compete with these projects' engineering investment, and it should not try.

The decision is also forced by the shift in user expectations. Windows CSC was designed for the 2005-era "domain-joined laptop + DFS-N share" model; modern users expect cloud-style sync (selective sync, cross-device, file-versioning, web UI) that CSC does not provide. Nextcloud client and OneDrive client deliver this; CSC does not. The framework's recommendation aligns with user expectations rather than fighting them.

The decision preserves cross-platform parity by recommending sync clients that work identically on Windows, macOS, and Linux. CSC is Windows-only; Nextcloud and Syncthing are cross-platform. The framework's "same sync behavior on every OS" commitment is met by the recommendation, not by a fresh CSC reimplementation.

The decision to ship integration guides (rather than just documentation pointers) is forced by the framework's operational-deployment commitment. Customers deploying the framework need a working offline-files solution on day one; the integration guide provides that, with MDM-configuration templates, Ansible roles, and a tested sync-client configuration. The framework's value-add is the integration, not the sync client itself.

The decision to ship the `framework-share mount` CLI is forced by the need to decouple sync-client configuration from share-server identity. Sync clients are configured against a stable local mount path; the framework's CLI mounts the share via SMB and exposes the stable path. When the framework migrates a share to a different server (server rename, capacity migration, site failover), the sync client does not need reconfiguration — the framework's CLI re-resolves the share location via DNS SRV (per ADR-044) and re-mounts to the same stable path.

## Consequences

**Positive**. The framework's v1 scope shrinks by a multi-year engineering effort, freeing resources for core capabilities (Core Directory, KDC, Policy Engine). The framework's cross-platform parity commitment is preserved by recommending cross-platform sync clients. The framework's documentation provides a working offline-files solution on day one via tested integration guides. The framework's `framework-share mount` CLI provides a stable mount-path abstraction that survives share migrations.

**Negative**. Framework customers who depend on Windows CSC's transparent-cache behavior (apps use UNC path even when offline) must adapt to the sync-client model (apps use the local cache path). Most apps tolerate this — they read/write files via the local cache, and the sync client propagates changes when online. A small class of apps (legacy MS Access databases over UNC, certain LOB apps that hard-code UNC paths) cannot tolerate the switch; these are documented as out of scope. The framework's recommendation is also a deployment dependency: customers must install and operate Nextcloud or Syncthing alongside the framework, which adds operational surface.

**Neutral**. The framework's File Gateway capability remains wire-compatible with MS-SMB2; the sync clients connect via SMB and are transparent to the framework's SMB server. The framework's `framework-share mount` CLI is also useful for non-sync-client use cases (interactive shell users who want a stable mount path).

**Implementation cost**. Low. Estimated 4-6 engineer-weeks for the `framework-share mount` CLI, the Nextcloud and Syncthing integration guides, the MDM/Ansible policy templates, the migration guide, the sync-client integration test, and the out-of-scope documentation. The framework's v1 timeline absorbs this easily.

**Operational impact**. Operations teams gain a cross-platform offline-files story (Nextcloud or Syncthing) at the cost of operating an additional service (Nextcloud server, if chosen — Syncthing is P2P and has no central server). The framework's runbook must include a "sync client deployment" section. The framework's Prometheus metrics for share mounts let operations teams detect sync-client mount failures. The framework's support team must be trained to triage sync-client issues (Nextcloud/Syncthing configuration, conflict resolution, offline-edit edge cases) — this is a new skill, but a well-documented one.

## Alternatives Considered

**Alternative 1: Implement a cross-platform userspace sync agent in the framework.** The framework ships its own sync agent (LaunchAgent on macOS, systemd user service on Linux, Win32 service on Windows) that materializes offline copies on local disk and synchronizes via SMB on reconnect. **Rejection rationale**: This duplicates Nextcloud/Syncthing functionality with less maturity. Nextcloud client has 10+ years of development, millions of users, and a large contributor base; Syncthing has 8+ years of development and a strong P2P architecture. The framework cannot match this investment in v1, and the result would be a worse sync client than what already exists for free. The framework's value is the directory, the SMB server, and the policy engine — not a fourth sync client.

**Alternative 2: Implement a FUSE-based transparent cache on Linux/macOS only, document Windows as out of scope (use Windows CSC).** The framework ships a FUSE filesystem on Linux/macOS that intercepts file access and synchronizes via SMB on reconnect, preserving the UNC-path-transparent model. Windows customers continue to use Windows CSC against framework-hosted shares. **Rejection rationale**: This is platform-divergent (Windows uses CSC, Linux/macOS use FUSE), which violates the framework's cross-platform parity commitment. The FUSE implementation is also significant engineering effort (multi-month) with ongoing maintenance burden (FUSE kernel API changes, macOS kext-equivalent auth, Linux DAX/cache coherency issues). The recommendation to use Nextcloud/Syncthing achieves the same offline outcome with less framework code.

**Alternative 3: Implement CSC v2 cache-format compatibility on Windows only, reuse Windows CSC.** The framework ships a CSC v2-compatible cache reader/writer on Windows, allowing Windows CSC to work against framework-hosted shares without modification. Linux/macOS are documented as out of scope (use Nextcloud/Syncthing). **Rejection rationale**: CSC v2's cache format is proprietary and undocumented; reverse-engineering it is a multi-month effort with ongoing Microsoft-format-change risk (the format changed in Server 2012 from v1 to v2; a future Windows version could change it again). The format is also tied to Windows-specific kernel integration (`csc.sys` mini-redirector) that the framework cannot easily replicate. The cost-benefit is unfavorable: Windows customers get a fragile CSC compat layer, Linux/macOS customers get nothing from this alternative.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the SMB server implementation choice (Samba vs fresh vs platform-native, per ORQ-154/155), but the offline-files scope-out is independent of the SMB server choice — sync clients connect via SMB regardless of underlying server implementation.

## Cross-capability impact

- **File Gateway** ([PC-080](../catalog/07-file-gateway.md)): The `framework-share mount` CLI resolves share location via DNS SRV (per ADR-044) before mounting; the CLI's share-resolution logic is shared with the Client SDK's share-location resolver.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): Client SDK's SMB client wrapper is used by the `framework-share mount` CLI; the SDK does not implement CSC.
- **Policy Engine** ([PC-050](../catalog/04-policy-engine.md)): Policy Engine ships a "sync client deployment" policy template (GPO + Configuration Profile + Ansible role).
- **Migration** ([PC-128](../catalog/12-migration-and-coexistence.md)): Migration runbook includes the Windows CSC → Nextcloud/Syncthing migration guide.

## References

- [PC-084](../catalog/07-file-gateway.md) — problem statement
- [docs/07-file-print/04-offline-files.md](../docs/07-file-print/04-offline-files.md) — `cscsvc.dll` + `csc.sys` architecture, CSC v2 cache format, slow-link detection, conflict resolution
- [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md) — `CacheFlags` per-share registry value, `SHARE_INFO_1005` `CSCFlags` field semantics
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2) — SMB2 protocol (the framework's SMB server, against which sync clients connect)
- [Nextcloud Client Documentation](https://docs.nextcloud.com/desktop/) — primary recommended sync client
- [Syncthing Documentation](https://docs.syncthing.net/) — secondary recommended sync client
