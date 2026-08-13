---
title: "ADR-110: SID-to-UID Mapping via UUID-Primary Identity + Direct POSIX UID"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-089
severity: blocker
unblocked_by: [workshop-decision-03, workshop-decision-11]
tags: [adr, client-sdk, sid, uid, gid, posix, uuid, id-mapping, sssd, winbind, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-002-memberof-back-link.md
  - ./ADR-053-key-escrow-and-nbde.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ../catalog/08-client-sdk.md
  - ../workshop/decision-03-identity-model.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/09-linux-equivalents/02-sssd-id-mapping.md
  - ../docs/09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-14
---

# ADR-110: SID-to-UID Mapping via UUID-Primary Identity + Direct POSIX UID

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 3](../workshop/decision-03-identity-model.md) (UUID-primary + SID-as-attribute + bidirectional mapping table) and [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK). Resolves the blocker problem [PC-089](../catalog/08-client-sdk.md) (ID mapping is non-deterministic across hosts without coordination). Implements the POSIX UID/GID mapping service referenced in Decision 3 §POSIX UID/GID mapping.

## Context

POSIX UIDs and GIDs are 32-bit integers that the Linux kernel and macOS BSD layer use to identify file owners and process credentials. AD uses SIDs (`S-1-5-21-<domain-authority>-<rid>` per MS-DTYP §2.4.2) to identify security principals. The mapping between SIDs and POSIX IDs is not stored authoritatively in AD (the RFC 2307 `uidNumber`/`gidNumber` attributes exist but are rarely populated in greenfield AD deployments). Instead, each Linux/macOS client computes the mapping algorithmically, and the algorithms differ between stacks.

SSSD's `ldap_id_mapping = true` (default) computes: (1) take the binary form of the domain SID, (2) SHA-1 hash it, (3) take the first 8 bytes as a big-endian uint64, modulo 10,000 (the default slice count), (4) `slice_offset = slice_index * range_size` (default 200,000), (5) `UID = range_min + slice_offset + RID` — implemented in `src/lib/idmap/sss_idmap.c:gen_slice`, per [docs/09-linux-equivalents/02-sssd-id-mapping.md](../docs/09-linux-equivalents/02-sssd-id-mapping.md). Winbind's `idmap_rid` uses the simpler `UID = range_min + RID` (no hashing, requires the domain's range to be specified manually). Winbind's `idmap_autorid` uses hashing similar to SSSD but with a different collision-resolution strategy. PBIS uses `RangeMin`/`RangeMax`/`RangeSize` registry keys with an algorithm similar to `idmap_rid`. The collision risk: SSSD's default range is 200,000 to 2,000,200,000 (a 2-billion-wide allocation table), sliced into 10,000 slices of 200,000 each. With 10,000 slices and N trusted domains, the birthday-paradox collision probability is roughly N²/20,000. For N=10 trusted domains, collision probability is ~0.5%; for N=100, ~38%. macOS uses a completely different model: OpenDirectory uses the user's `GeneratedUID` (a UUID stored in AD as `objectGUID`) and does not perform SID-to-UID hashing — POSIX UIDs on macOS are local-only (assigned sequentially at user creation, stored in `/var/db/dslocal/nodes/Default/users/<user>.plist` as `dsAttrTypeStandard:UniqueID`).

Per [PC-089](../catalog/08-client-sdk.md) and [docs/09-linux-equivalents/04-winbind-internals.md](../docs/09-linux-equivalents/04-winbind-internals.md), the cross-host problem: two Linux hosts running SSSD with identical `ldap_id_mapping = true` config will produce the same UID for the same AD user, but a Linux host running SSSD and a Linux host running Winbind with `idmap_rid` will produce different UIDs for the same AD user. A Linux host running SSSD and a macOS host bound via `dsconfigad` will produce different UIDs (SSSD algorithmic vs macOS local-assigned). If a file is shared via NFS or copied via scp between these hosts, file ownership breaks: `ls -l` shows the wrong owner, `chown` to a UID on one host produces a different user on another host. ~5-10% of users in mixed SSSD + Winbind deployments are affected, requiring `chown -R --from=<olduid> <newuid>` sweeps over `/home` and shared filesystems.

Workshop Decision 3 ([workshop/decision-03-identity-model.md](../workshop/decision-03-identity-model.md)) resolved the gating ORQs ORQ-026/027 in favor of: UUIDv7 as the internal primary key for every security principal, with SID as a first-class attribute; a bidirectional mapping table in FDB subspace `0x0D` providing O(1) lookup in both directions; and a specific POSIX UID/GID mapping model: "The framework's POSIX UID/GID mapping service (Client SDK, per PC-089) SHALL use the mapping table to map SIDs to POSIX UIDs. The mapping is configurable (algorithmic mapping via `author = "rfc2307"` or `algorithmic = "adrian-default"`; or directory-stored via the `uidNumber`/`gidNumber` attributes). The framework's default algorithmic mapping is `uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536`." This ADR locks the SDK-side implementation of that mapping service.

## Decision

The `adrian-sdk` Rust core ships a cross-platform POSIX UID/GID mapping service in its `DirectoryModule`, built on the framework's bidirectional UUID↔SID mapping table (per Decision 3 §`principal_identities` FDB subspace `0x0D`). The service replaces SSSD's `ldap_id_mapping` algorithmic slice mapping, Winbind's `idmap_rid`/`idmap_autorid`, PBIS's range-based mapping, and macOS's local-assignment model with a single deterministic algorithm based on the framework's UUIDv7 primary key. Existing SSSD/Winbind/PBIS deployments migrate to the framework's mapping via the SDK's `adrian-cli migrate from-{sssd,winbind,pbis}` commands, which preserve existing UID/GID assignments by writing the existing `uidNumber`/`gidNumber` to the framework's directory.

**Concrete specification**:

- The `DirectoryModule` exposes a `IdMapper` struct:
  ```rust
  impl DirectoryModule {
      pub fn id_mapper(&self) -> &IdMapper;
  }
  pub struct IdMapper { /* config + cache */ }
  impl IdMapper {
      pub async fn sid_to_uid(&self, sid: &Sid) -> Result<u32, IdMapError>;
      pub async fn sid_to_gid(&self, sid: &Sid) -> Result<u32, IdMapError>;
      pub async fn uid_to_sid(&self, uid: u32) -> Result<Sid, IdMapError>;
      pub async fn gid_to_sid(&self, gid: u32) -> Result<Sid, IdMapError>;
      pub async fn uuid_to_uid(&self, uuid: Uuid) -> Result<u32, IdMapError>;
      pub async fn uuid_to_gid(&self, uuid: Uuid) -> Result<u32, IdMapError>;
      pub async fn uid_to_uuid(&self, uid: u32) -> Result<Uuid, IdMapError>;
      pub async fn gid_to_uuid(&self, gid: u32) -> Result<Uuid, IdMapError>;
  }
  ```
  The `IdMapper` is the sole entry point for SID↔UID and UUID↔UID translation in the framework's SDK. The platform's NSS module (`nss_adrian.so.2` per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §PAM/NSS provider) calls `IdMapper::sid_to_uid()` during `getpwnam`/`getpwuid`; the platform's PAM module (`pam_adrian.so` per [ADR-107](./ADR-107-unified-rust-core-sdk.md)) calls `IdMapper::uid_to_sid()` during `pam_sm_acct_mgmt` to translate the calling UID back to a SID for access-control decisions.

- The default algorithmic mapping is `uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536`, giving a stable POSIX UID range of 65536..2^31-1 (the same range as Linux `useradd` defaults, per Decision 3 §POSIX UID/GID mapping). The `uuid_to_u64` function takes the first 8 bytes of the UUID's binary representation as a big-endian uint64 (UUIDv7's first 48 bits are a timestamp; the remaining 74 bits are random — this gives sufficient entropy for the modulo operation). The same algorithm is used for `uuid_to_gid`. The algorithm is deterministic given the UUID — the same UUID produces the same UID on every framework-managed host, regardless of host OS.

- The directory-stored mapping mode (`IdMapper::Mode::Directory`) reads the `uidNumber`/`gidNumber` attributes from the framework's directory (RFC 2307) instead of computing algorithmically. This mode is used for: (a) migrated AD deployments where the AD DC already has `uidNumber`/`gidNumber` populated and the framework preserves these values during migration; (b) deployments that need specific UID/GID ranges (e.g., to match an existing NFS server's `exports` file). The directory-stored mode is the default for migrated deployments; the algorithmic mode is the default for greenfield deployments. The mode is selected per-domain via `ClientConfig::id_map_mode`.

- The collision-handling policy: if the algorithmic `uuid_to_uid` produces a UID that is already in use by a different UUID (a 2^-31 collision probability per pair, negligible in practice), the framework's directory detects the collision at principal-creation time and assigns the principal a directory-stored `uidNumber` instead (using the FDB atomic-add counter at `(0x06, 0x03, "uid_counter")` per Decision 3 §RID-pool allocator). The collision is logged and the framework's `adrian-cli idmap audit` command lists all directory-stored overrides.

- The `IdMapper` caches SID↔UID and UUID↔UID mappings in-memory per `AdrianClient` instance: an LRU cache (default 100K entries, configurable via `ClientConfig::id_map_cache_size`) with 60-second TTL. Cache invalidation is event-driven via the framework's WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)) when a principal is created, deleted, or has its `uidNumber`/`gidNumber` modified. The cache hit rate target is 99%+ for typical deployments (the working set of principal references is much smaller than the total principal count, per Decision 3 §Rationale).

- The framework's NSS module (`nss_adrian.so.2`) calls `IdMapper::sid_to_uid()` for `getpwnam`/`getpwuid`/`getgrnam`/`getgrgid`/`getspnam`. The NSS module's `getpwnam("alice@corp.example.com")` flow: (1) LDAP search the directory for `userPrincipalName = "alice@corp.example.com"` (or `sAMAccountName = "alice"` per the framework's name-resolution config); (2) extract the principal's `objectSid` and `uuid` (objectGUID); (3) call `IdMapper::sid_to_uid(objectSid)` (or `IdMapper::uuid_to_uid(uuid)`); (4) return the `passwd` struct with `pw_uid = mapped_uid`, `pw_gid = mapped_gid` (from the primary group SID), `pw_name = "alice"`, `pw_dir = "/home/alice"`, `pw_shell = "/bin/bash"`.

- The framework's `adrian-cli migrate from-{sssd,winbind,pbis}` commands read the existing UID/GID assignments from the legacy stack's local state (SSSD's `/var/lib/sss/db/cache_<domain>.ldb`, Winbind's `/var/lib/samba/winbindd_idmap.tdb`, PBIS's `/opt/pbis/config/reg.dat`) and write them to the framework's directory as `uidNumber`/`gidNumber` attributes on the corresponding user/group objects. The migrated deployments use `IdMapper::Mode::Directory` to preserve the existing UID/GID assignments without re-mapping.

- The framework's macOS OpenDirectory plugin (`AdrianOpenDirectory.bundle` per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §PAM/NSS provider) uses the same `IdMapper` algorithm as the Linux NSS module. macOS's OpenDirectory previously used the user's `GeneratedUID` (UUID) and did not perform SID-to-UID hashing — POSIX UIDs on macOS were local-only. The framework's OpenDirectory plugin replaces the local-assignment model with the framework's algorithmic (or directory-stored) mapping, ensuring that the same AD user has the same UID on macOS and Linux. This is a breaking change for existing macOS `dsconfigad`-bound Macs (their local-assigned UIDs differ from the framework's algorithmic UIDs); the framework's migration tooling handles the UID remapping via `chown -R --from=<olduid> <newuid>` over `/home` and shared filesystems.

- The framework's Windows client does not need `IdMapper` (Windows uses SIDs natively; no UID/GID concept). The framework's Windows client exposes `IdMapper` only for framework-native applications that interoperate with Linux/macOS NFS exports and need to translate UIDs to SIDs.

- The C ABI exposes the `IdMapper` as opaque-handle functions:
  ```c
  typedef struct AdrianIdMapper AdrianIdMapper;
  int32_t adrian_idmap_sid_to_uid(AdrianIdMapper*, const uint8_t* sid_bytes, size_t sid_len, uint32_t* out_uid);
  int32_t adrian_idmap_sid_to_gid(AdrianIdMapper*, const uint8_t* sid_bytes, size_t sid_len, uint32_t* out_gid);
  int32_t adrian_idmap_uid_to_sid(AdrianIdMapper*, uint32_t uid, uint8_t** out_sid, size_t* out_len);
  int32_t adrian_idmap_gid_to_sid(AdrianIdMapper*, uint32_t gid, uint8_t** out_sid, size_t* out_len);
  int32_t adrian_idmap_uuid_to_uid(AdrianIdMapper*, const uint8_t uuid[16], uint32_t* out_uid);
  int32_t adrian_idmap_uid_to_uuid(AdrianIdMapper*, uint32_t uid, uint8_t out_uuid[16]);
  /* ... and so on for gid/uuid pairs */
  ```
  The C ABI is the foundation for the NSS module's C calls (`nss_adrian.so.2` is a C shared library that calls the C ABI).

## Rationale

The choice to use the framework's UUIDv7 primary key as the input to the UID-mapping algorithm is forced by Decision 3's UUID-primary identity model. SIDs are kept as wire-format currency for AD-interop, but the framework's internal primary key is the UUID. The mapping table (per Decision 3 §`principal_identities` FDB subspace `0x0D`) provides the authoritative SID↔UUID correspondence; the `IdMapper` uses the UUID as the algorithmic input. This eliminates the SID-collision problem (multiple domains with SIDs that hash to the same SSSD slice) and the SID-collision problem (different domains producing the same UID via `idmap_rid` when `range_min` overlaps).

The choice to use `uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536` as the default algorithmic mapping is forced by three considerations. First, the range 65536..2^31-1 is the same range as Linux `useradd` defaults, matching existing POSIX conventions. Second, the modulo operation over 2^31 - 65536 gives a uniform distribution over the range (UUIDv7's first 48 bits are a timestamp, but the remaining 74 bits are random — the modulo operation over 2^31 - 65536 is well-mixed). Third, the algorithm is deterministic given the UUID — the same UUID produces the same UID on every framework-managed host, regardless of host OS, eliminating the cross-host problem documented in [PC-089](../catalog/08-client-sdk.md). The collision probability per pair is 1/(2^31 - 65536) ≈ 5×10^-10; for a 10M-principal forest, the expected number of collisions is ~10M × 10M × 5×10^-10 / 2 ≈ 25 — non-zero but rare, and the collision-handling policy (directory-stored override) handles it gracefully.

The choice to support both algorithmic and directory-stored mapping modes is forced by the migration requirement. Greenfield deployments use the algorithmic mode (no need to populate `uidNumber`/`gidNumber` in the directory). Migrated AD deployments with existing `uidNumber`/`gidNumber` use the directory-stored mode to preserve existing UID/GID assignments (avoiding `chown` sweeps over `/home` and shared filesystems). Migrated SSSD-with-`ldap_id_mapping`-true deployments use the algorithmic mode but with a different algorithm — the framework's `adrian-cli migrate from-sssd` command computes the existing SSSD-mapped UIDs and writes them to the framework's directory as `uidNumber` overrides, so the directory-stored mode preserves them.

The choice to invalidate the `IdMapper` cache via the framework's WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)) is forced by the requirement that UID/GID mappings be consistent across all framework-managed hosts. If a principal is created on DC-A and the `IdMapper` cache on DC-B is not invalidated, DC-B may return a stale UID for the new principal (or no UID at all). The WebSocket push ensures that the cache is invalidated within ~100ms of the principal-creation event on DC-A, which is fast enough for typical NSS workloads (a `getpwnam` for a just-created user is rare; the user typically waits a few seconds after creation before logging in).

The choice to make the macOS OpenDirectory plugin use the same `IdMapper` algorithm as the Linux NSS module is forced by the cross-platform-parity requirement. macOS's local-assignment model (`GeneratedUUID` → sequential local UID) produces UIDs that differ from Linux's SSSD-mapped UIDs for the same AD user; this breaks NFS home shares and SMB share ACLs in mixed Linux + macOS deployments (per [PC-089](../catalog/08-client-sdk.md) §Impact). The framework's OpenDirectory plugin replaces the local-assignment model with the framework's algorithmic (or directory-stored) mapping, ensuring that the same AD user has the same UID on macOS and Linux. The breaking change for existing macOS `dsconfigad`-bound Macs is handled by the framework's migration tooling (`adrian-cli migrate from-dsconfigad`).

## Consequences

**Positive**. The framework gains a single deterministic SID↔UID mapping across all platforms (Linux, macOS, Windows-as-client), eliminating the cross-host file-ownership problem documented in [PC-089](../catalog/08-client-sdk.md). The framework's algorithmic mapping has a negligible collision probability (~25 collisions in a 10M-principal forest) and graceful collision handling (directory-stored override). The directory-stored mode preserves existing UID/GID assignments during migration, avoiding `chown` sweeps. The framework's macOS OpenDirectory plugin finally matches Linux's UID assignments for the same AD user, enabling NFS home shares and SMB share ACLs in mixed Linux + macOS deployments. The `IdMapper` cache's 99%+ hit rate keeps the lookup cost at <100µs per call (per Decision 3 §Rationale).

**Negative**. The framework's macOS OpenDirectory plugin is a breaking change for existing macOS `dsconfigad`-bound Macs (their local-assigned UIDs differ from the framework's algorithmic UIDs); the migration tooling handles the UID remapping via `chown -R --from=<olduid> <newuid>`, which is a slow operation on large home directories (~10 minutes for a 100GB home directory). The framework's algorithmic mapping produces UIDs that differ from SSSD's `ldap_id_mapping` algorithm — migrated SSSD deployments must use the directory-stored mode (with `adrian-cli migrate from-sssd` populating the overrides) to preserve existing UIDs. The `IdMapper` cache's 60-second TTL means that a UID/GID change takes up to 60 seconds to propagate to all framework-managed hosts (acceptable for typical operations; rapid UID/GID changes are rare).

**Neutral**. The framework's Windows client does not use `IdMapper` (Windows uses SIDs natively); the `IdMapper` is invisible on Windows. The framework's algorithmic mapping is invisible to end users (they see their username, not their UID). The framework's directory-stored mode is invisible to end users (they see their UID, whether algorithmic or directory-stored).

**Implementation cost**. ~6 person-weeks. Breakdown: `IdMapper` Rust core + algorithmic mapping (1 pw), directory-stored mode (1 pw), cache layer with WebSocket invalidation (1 pw), NSS module integration (`nss_adrian.so.2` calls) (1 pw), macOS OpenDirectory plugin integration (1 pw), migration tooling (`adrian-cli migrate from-{sssd,winbind,pbis,dsconfigad}`) (1 pw).

**Operational impact**. Operations teams gain a single UID/GID mapping across all platforms (verifiable via `adrian-cli idmap audit` listing all directory-stored overrides). Operations teams gain metrics for cache hit rate (`adrian_idmap_cache_hits_total{platform}` / `adrian_idmap_cache_misses_total{platform}`) and lookup latency (`adrian_idmap_lookup_duration_seconds{platform}`). Operations teams must understand the migration tooling for existing SSSD/Winbind/PBIS/dsconfigad deployments (the runbook includes a "UID/GID migration" section).

## Alternatives Considered

**Alternative 1: Adopt SSSD's slice algorithm across all platforms.** The framework uses SSSD's `ldap_id_mapping` algorithm (SHA-1 hash of domain SID → slice index → `UID = range_min + slice*range_size + RID`) on Linux, macOS, and Windows-as-client. **Rejection rationale**: SSSD's slice algorithm has the documented collision problem (~0.5% for 10 trusted domains, ~38% for 100); the framework cannot accept this collision rate. SSSD's slice algorithm also requires per-domain `range_min`/`range_size` configuration, which is operationally complex for customers with many trusted domains. The framework's UUID-based algorithm has a negligible collision probability and requires no per-domain configuration.

**Alternative 2: Adopt RFC 2307 as the default (`uidNumber`/`gidNumber` in the directory).** The framework requires `uidNumber`/`gidNumber` on every principal at creation time; the framework's directory allocates UIDs from a sequential counter (the FDB atomic-add counter at `(0x06, 0x03, "uid_counter")` per Decision 3). **Rejection rationale**: This forces every principal to have a directory-stored UID, which is operationally heavier than the algorithmic mapping (the directory must be queried for every UID lookup). The framework's algorithmic mapping is the default; the directory-stored mode is available for migrated deployments. The hybrid model (algorithmic default + directory-stored override) gives the framework the best of both worlds.

**Alternative 3: Drop POSIX UIDs entirely (use UUIDs everywhere).** The framework uses UUIDs for all identity references, including `chown` by UUID (via a new `chownbyuuid` syscall) and NFSv4 with `sec=krb5p` and `nfsmapid`-equivalent. **Rejection rationale**: This requires re-architecting every POSIX tool that assumes UID/GID integers (the Linux kernel, every shell, every `ls`/`chown`/`chmod` invocation, every NFS client and server). The framework cannot justify this re-architecture effort; the framework's UUID-based algorithmic mapping preserves the POSIX UID/GID abstraction while giving the framework the benefits of UUID-primary identity internally.

## Open Questions

None. The decision is fully specified by Decision 3 §POSIX UID/GID mapping and Decision 11 §`DirectoryModule`. The implementation details (migration tooling for legacy stacks, macOS OpenDirectory plugin) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): The `IdMapper` reads the `principal_identities` FDB subspace `0x0D` mapping table (per Decision 3); the directory's `uidNumber`/`gidNumber` attributes are used in directory-stored mode.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The `IdMapper` is the ID-mapping surface of the unified SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)).
- **Client SDK** ([PC-088](../catalog/08-client-sdk.md)): The `nss_adrian.so.2` NSS module uses `IdMapper` for `getpwnam`/`getpwuid` translation, replacing SSSD's NSS module in the framework's SSSD-primary path (per Decision 12).
- **Cross-Platform Parity** ([PC-099](../catalog/09-cross-platform-parity.md)): The migration tooling (`adrian-cli migrate from-{sssd,winbind,pbis,dsconfigad}`) is part of the Linux tier migration (per Decision 12).
- **File Gateway** (Decision 10): The `IdMapper` is used by the framework's SMB client and NFS client to translate SIDs (from Kerberos PAC) to UIDs for file-ownership assignment.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): The migration tooling preserves existing UID/GID assignments during AD→framework and SSSD/Winbind/PBIS→framework migration.

## References

- [PC-089](../catalog/08-client-sdk.md) — problem statement
- [Workshop Decision 3 — Identity Model](../workshop/decision-03-identity-model.md) — UUID-primary + SID-as-attribute + bidirectional mapping table
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings
- [docs/09-linux-equivalents/02-sssd-id-mapping.md](../docs/09-linux-equivalents/02-sssd-id-mapping.md) — SSSD `sss_idmap.c:gen_slice` algorithm, collision mitigation, RFC 2307 attribute OIDs
- [docs/09-linux-equivalents/04-winbind-internals.md](../docs/09-linux-equivalents/04-winbind-internals.md) — `idmap_rid`, `idmap_autorid`, `idmap_ad`, `idmap_tdb2` backends
- [ADR-002](./ADR-002-memberof-back-link.md) — memberOf back-link (group-membership resolution)
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution (cache invalidation channel)
- [ADR-053](./ADR-053-key-escrow-and-nbde.md) — key escrow (cross-platform disk-encryption recovery, related directory-stored attribute)
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [RFC 2307](https://www.rfc-editor.org/rfc/rfc2307) — An Approach for Using LDAP as a Network Information Service
- [MS-DTYP §2.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp) — SID binary format
- [uuid Rust crate](https://docs.rs/uuid) — UUIDv7 (RFC 9562) support
- [adrian-sid crate](https://github.com/adrian/adrian) — framework's pure-Rust SID parser (per Decision 3)
