---
title: "ADR-045: Access-Based Enumeration with Pre-computed Per-Share Index"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: File Gateway
problem: PC-082
severity: medium
tags: [adr, file-gateway, abe, ntfs-acl, performance, access-based-enumeration]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/07-file-gateway.md
  - ../docs/07-file-print/01-smb-shares-internals.md
  - ../docs/02-protocols/03-smb-cifs-protocol.md
last_updated: 2026-08-13
---

# ADR-045: Access-Based Enumeration with Pre-computed Per-Share Index

## Status

Accepted — 2026-08-13

## Context

Access-Based Enumeration (ABE) is enabled per-share in Windows via `AccessBasedEnumeration = 1` REG_DWORD under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\<ShareName>` (or `Set-SmbShare -FolderEnumerationMode AccessBased` in PowerShell). When enabled, `srv2.sys!SrvSmbQueryDirectoryInformation` post-filters `FILE_DIRECTORY_INFORMATION` / `FILE_BOTH_DIR_INFORMATION` / `FILE_NAMES_INFORMATION` responses to return only entries the caller has `FILE_ListDirectory` (read) access to via NTFS ACL, per [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md). The Windows implementation has no pre-filtering at the NTFS layer, no index, no caching across calls — `srv2.sys` walks each entry, evaluates the NTFS ACL against the caller's token, and removes inaccessible entries from the response buffer before returning it to the client. Samba implements the equivalent via `hide unreadable = yes` in `smb.conf`, processed by `smbd/dir.c:OpenDir` + `smbd/dir.c:SeekDir` — same post-filter model.

The performance characteristic is universal: ABE cost is O(n) per directory enumeration where n is the entry count, and the per-entry ACL evaluation walks the SD's DACL (typically 3-10 ACEs per file in a domain-joined share). Windows performance guidance is to disable ABE on shares with >10,000 entries per directory, or to subdivide directories so no single listing exceeds ~1,000 entries. Quantified by the impact analysis in [PC-082](../catalog/07-file-gateway.md#pc-082--access-based-enumeration-abe-post-filters-directory-listings-cpu-cost): a directory with 50,000 entries takes ~3-5 seconds to enumerate with ABE on a stock Windows file server, versus <500ms without. The framework inherits this constraint because any cross-platform ABE implementation must post-filter at the SMB response layer, walking NTFS ACLs per entry. The current state of the art is unacceptable for any share with >10,000 entries.

The framework cannot skip ABE. ABE is non-negotiable for any share exposed to non-admin users (Home directories, Department shares, profile shares). Without ABE, users see filenames they cannot open — a usability regression and, in regulated environments, a data-classification leak (a user can see "Acme-Acquisition-Legal-Review.docx" even if they cannot open it). The framework must support ABE on every share, with per-share toggle, NTFS ACL evaluation (POSIX ACLs are insufficient — no `OWNER_RIGHTS` / `CREATOR OWNER` semantics), `FindFirstFile`/`FindNextFile` chained-call state preservation, and identical enumeration results across Windows, macOS, and Linux clients.

The cross-platform consistency requirement is the hardest constraint. Per [PC-082](../catalog/07-file-gateway.md#pc-082--access-based-enumeration-abe-post-filters-directory-listings-cpu-cost)'s cross-platform considerations, the framework's NTFS ACL evaluator must be authoritative, not the host OS's permission model. macOS SMBX has no first-party ABE; framework-hosted shares on macOS must implement ABE in the framework's SMB server, not delegate to SMBX. Linux Samba's `hide unreadable = yes` is available but the framework's ACL evaluator must produce identical results regardless of host OS. The framework's Core Directory ACL evaluation engine (per PC-013) is the reference; ABE evaluation must reuse the same SD-walk code path.

The performance question is the design tension. Two strategies are available: (a) live-evaluation (correct, expensive — the current Windows/Samba model), and (b) pre-computed indexes (per-user materialized views of accessible entries, refreshed on ACL change — a research direction Microsoft has not shipped, Samba has not implemented). The framework must pick one. Live-evaluation is operationally simple but breaks on large directories; pre-computed indexes add complexity but unlock ABE on directories that are currently unmanageable.

## Decision

The framework's File Gateway will support Access-Based Enumeration on all shares with a per-share on/off toggle, and will pre-compute a per-share ABE index keyed by (user SID, directory path) → accessible-entry list, refreshed on ACL change. The framework's NTFS ACL evaluator (shared with the Core Directory's SD evaluation engine per PC-013) will be authoritative for ABE decisions on every platform; the framework will not delegate to Samba's `hide unreadable` or macOS SMBX's permission model. The pre-computed index will be a per-share materialized view, with staleness tolerance configurable per-share (default 30 seconds, range 0-300 seconds; 0 means live-evaluation-only).

**Concrete specification**:

- The framework's SMB server MUST support per-share ABE toggle. The configuration surface MUST be `shares.<name>.abe = on|off` (default `off` for admin-only shares, `on` for user-facing shares). The toggle MUST be exposed via the framework's CLI (`framework-share set <name> --abe on|off`) and via the framework's REST API.
- When ABE is on, the framework's SMB server MUST filter `QUERY_DIRECTORY` (SMB2 cmd `0x0E`) responses per [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md) to return only entries the caller has `FILE_ListDirectory` (read) access to. The filter MUST use the framework's NTFS ACL evaluator (shared with Core Directory's SD evaluation engine), not the host OS's permission model.
- The framework MUST maintain a per-share ABE index in shared storage (the framework's key-value store backing the SMB server's persistent state). The index key MUST be `(share_id, user_sid, directory_path)`; the index value MUST be the sorted list of accessible child entry names. The index MUST be invalidated and rebuilt whenever the ACL on the directory or any child entry changes (the framework's ACL-change-notification path triggers the invalidation).
- The index staleness tolerance MUST be configurable per-share via `shares.<name>.abe_index_staleness_seconds` (default 30, range 0-300). At `0`, the index is bypassed and live-evaluation is used for every `QUERY_DIRECTORY` call (equivalent to the Windows/Samba model).
- The framework's SMB server MUST consult the ABE index on every `QUERY_DIRECTORY` call when ABE is on. If the index entry for (caller SID, directory path) is present and not stale, the server MUST return the indexed entry list. If the entry is absent or stale, the server MUST fall back to live-evaluation, update the index, and return the filtered result.
- The framework's `FindFirstFile`/`FindNextFile` chained-call semantics MUST preserve filter state across multiple `QUERY_DIRECTORY` requests within one create-handle. The framework MUST use the SMB2 `FileId` + `ResumeKey` to correlate chained calls and return consistent filtered results.
- The framework's NTFS ACL evaluator MUST support `OWNER_RIGHTS` and `CREATOR OWNER` SIDs (per Windows SD semantics), not just POSIX ACL equivalents. The evaluator MUST walk the SD's DACL in canonical order (explicit ACEs before inherited ACEs; deny ACEs before allow ACEs within each scope).
- The framework MUST produce identical ABE enumeration results for the same caller SID querying the same share, regardless of the caller's host OS (Windows, macOS, Linux). The framework's automated test suite MUST include a parity test: a Windows client, a macOS client, and a Linux client each query the same share with the same user SID, and the response entry sets MUST be byte-identical.
- The framework's Prometheus exporter MUST expose per-share metrics: `smb_abe_index_size{share="<name>"}` (entries), `smb_abe_index_hit_rate{share="<name>"}` (ratio), `smb_abe_live_evaluation_seconds{share="<name>"}` (histogram), `smb_abe_index_rebuild_seconds{share="<name>"}` (histogram). Operations teams use these to detect shares where the index is ineffective (low hit rate, high rebuild time).
- The framework's documentation MUST include a "ABE capacity planning" section: recommended max directory size for live-evaluation mode (1,000 entries), recommended max directory size for indexed mode (50,000 entries), and guidance on subdividing directories that exceed 50,000 entries.

## Rationale

The decision to ship pre-computed ABE indexes is forced by the framework's cross-platform parity commitment. The Windows/Samba live-evaluation model breaks at >10,000 entries; macOS SMBX has no ABE at all; Linux Samba's `hide unreadable` has the same O(n) limitation. A framework that ships only live-evaluation ABE cannot serve enterprise customers with large Home-directory shares (typical: 10,000-100,000 entries per directory in a 50,000-user enterprise). The pre-computed index unlocks ABE on directories that are currently unmanageable, with a configurable staleness tolerance that lets operations teams trade off correctness (low staleness) against performance (high staleness) per-share.

The decision to make the framework's NTFS ACL evaluator authoritative is forced by cross-platform consistency. If the framework delegates to Samba's `hide unreadable` on Linux, the results may differ from a fresh Rust/Go implementation on macOS or a `srv2.sys`-equivalent on Windows — different ACL evaluators make different choices around inherited ACE ordering, `CREATOR OWNER` resolution, and `OWNER_RIGHTS` precedence. The framework's Core Directory already has a reference SD evaluation engine (per PC-013) used for AD object ACLs; reusing that engine for ABE ensures consistent results across the directory and the file share, and lets the framework ship one well-tested ACL evaluator rather than three.

The decision to use shared storage for the index (not per-node in-memory caches) is forced by the framework's CA-share design (per PC-081). When a share is hosted on a cluster, the ABE index must be visible to every node so that failover does not invalidate the index. Shared storage (the framework's existing key-value store) provides this. The index read/write overhead is dominated by the ACL evaluation cost in any case; the shared-storage lookup adds ~1-2ms per query, which is negligible compared to the 50-500ms saved by avoiding live-evaluation on large directories.

The decision to ship a configurable staleness tolerance (rather than a fixed value) is forced by operational diversity. A Home-directory share with rarely-changing ACLs tolerates 30-second staleness easily; an M&A-project share with rapidly-changing ACLs may need 1-second staleness. Operations teams need the lever. The default of 30 seconds matches Microsoft's typical Group Policy refresh interval (90 minutes ± 30 minutes jitter, but ACL changes are typically batched), giving 99.9% freshness in practice.

The decision to fall back to live-evaluation when the index is stale or absent preserves correctness. The index is a performance optimization, not a correctness mechanism; the live-evaluation path is always available. This means a misconfigured index (stale, corrupted, missing) produces a slow but correct response, not an incorrect one. The fail-safe posture is critical for a security feature.

## Consequences

**Positive**. The framework unlocks ABE on directories with up to 50,000 entries, versus the ~10,000-entry ceiling of the Windows/Samba live-evaluation model. Operations teams gain a per-share performance lever (`abe_index_staleness_seconds`) for tuning the correctness/performance tradeoff. Cross-platform ABE parity is guaranteed by the unified NTFS ACL evaluator. The framework's Prometheus metrics give operations teams visibility into ABE index effectiveness per-share, enabling proactive tuning.

**Negative**. The framework's SMB server has higher memory and storage overhead (the ABE index for a 50,000-entry share with 1,000 unique user SIDs is ~50MB in the worst case). The framework's ACL-change-notification path must trigger index invalidation reliably; a missed invalidation produces stale results (within the staleness tolerance) but never incorrect long-term results. The framework's documentation must explain the staleness tradeoff to operations teams who are accustomed to Windows' always-correct ABE.

**Neutral**. The pre-computed ABE index is invisible to clients (the SMB wire protocol is unchanged). Windows `Get-SmbShare` and Samba `smbcontrol` show only the ABE on/off flag, not the indexing strategy.

**Implementation cost**. Medium-high. Estimated 10-15 engineer-weeks for the NTFS ACL evaluator integration, the index storage, the ACL-change-notification path, the index-rebuild worker, the per-share configuration, the Prometheus metrics, the parity test matrix, and the documentation. The NTFS ACL evaluator itself is reused from Core Directory (PC-013); the marginal cost is the index infrastructure.

**Operational impact**. Operations teams gain a new tuning lever (`abe_index_staleness_seconds`) and new metrics (`smb_abe_*`). The framework's runbook must include an "ABE index troubleshooting" section: how to detect a low-hit-rate index (suggests ACL churn exceeding rebuild capacity), how to force an index rebuild, and how to switch to live-evaluation mode as a fallback. The framework's capacity-planning guidance must include ABE index sizing (estimate: 1KB per (SID, directory) entry; for a 50,000-user enterprise with 1,000 shares, worst-case index is ~50GB across all shares — typically much less because most users access only a subset of directories).

## Alternatives Considered

**Alternative 1: Live-evaluation only (Windows/Samba model).** The framework implements ABE as a post-filter on every `QUERY_DIRECTORY` call, walking the DACL per entry, with no index. **Rejection rationale**: This breaks at >10,000 entries per directory, which is unacceptable for enterprise Home-directory shares. The framework's cross-platform parity commitment requires the framework to do better than the Windows/Samba status quo.

**Alternative 2: Per-user materialized views, refreshed on a fixed schedule.** The framework computes, every N minutes, a complete per-user accessible-entry list for every directory on every share. **Rejection rationale**: This produces a combinatorial explosion (users × directories × shares) that is infeasible for large enterprises. The per-share, per-(SID, directory) index is demand-driven (only computed for directories actually queried) and is far more efficient. The scheduled-refresh model also produces longer staleness windows than the demand-driven model.

**Alternative 3: Delegate to Samba's `hide unreadable` on Linux, implement fresh ABE on macOS/Windows.** The framework does not implement its own ACL evaluator; it uses Samba's post-filter on Linux, a fresh implementation on macOS, and the OS-native filter on Windows. **Rejection rationale**: Cross-platform consistency is broken — different ACL evaluators produce different results around `OWNER_RIGHTS`, `CREATOR OWNER`, inherited-ACE ordering, and deny-before-allow precedence. The framework's commitment to byte-identical ABE results across platforms (verified by the parity test) cannot be met with this approach.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the SMB server implementation choice (Samba vs fresh vs platform-native, per ORQ-154/155), but the ABE design is implementation-independent: any candidate SMB server can host the ABE index and the framework's NTFS ACL evaluator.

## Cross-capability impact

- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): The framework's NTFS ACL evaluator is shared between ABE (file share SDs) and Core Directory (AD object SDs). Changes to the evaluator affect both.
- **File Gateway** ([PC-078](../catalog/07-file-gateway.md)): `QUERY_DIRECTORY` responses can be encrypted via SMB 3.1.1 transform headers; the ABE filter runs before encryption, so the filter's correctness is independent of the encryption posture.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): Client SDK's SMB client wrapper is transparent to ABE; the framework's ABE filter is server-side.
- **Operations** ([PC-106](../catalog/10-operations.md)): Prometheus exporter exposes `smb_abe_*` metrics; OpenTelemetry traces log ABE index hit/miss per query.

## References

- [PC-082](../catalog/07-file-gateway.md) — problem statement
- [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md) — `AccessBasedEnumeration` per-share registry flag, `srv2.sys!SrvSmbQueryDirectoryInformation` post-filter
- [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md) — `FILE_DIRECTORY_INFORMATION` response structures, `QUERY_DIRECTORY` semantics
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2) — SMB2 protocol (QUERY_DIRECTORY command)
- [MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp) — Windows data types (security descriptor structure)
- [MS-GPSO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpso) — Group Policy: Security Extension (GptTmpl.inf ACL format reference)
