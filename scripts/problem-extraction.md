# Problem Extraction — Working Document

> **Purpose.** Consolidated inventory of problems, gaps, and design tensions
> extracted from the 72-file AD KB (`/home/z/my-project/download/ad-kb/`).
> Each entry is intended to feed the per-capability catalog files that other
> writing subagents will produce. Stay terse; the catalog files will polish.
>
> **Coverage.** All 72 KB files were read in full. 130 problems extracted
> across 13 capabilities. Severity: 23 blocker / 64 high / 33 medium / 10 low.
>
> **Conventions.**
> - **Capability** is the framework's primary subsystem this problem belongs to.
>   Secondary capabilities are mentioned in the description when relevant.
> - **Severity** ranks impact-on-framework if unsolved:
>   - `blocker` — without solving, the framework cannot ship a usable AD-equivalent.
>   - `high` — significant functional gap or security risk; needs explicit design.
>   - `medium` — workaround exists but the gap should be acknowledged.
>   - `low` — nuisance or future-compatible item.
> - KB references use paths relative to `download/ad-kb/`.

## Statistics

- Total files read: 72
- Total problems extracted: 130
- By capability:
  - Core Directory: 22
  - KDC: 13
  - Auth Provider: 7
  - Policy Engine: 14
  - Cert Service: 11
  - Federation Gateway: 10
  - File Gateway: 7
  - Client SDK: 9
  - Cross-Platform Parity: 12
  - Operations: 10
  - Security: 8
  - Migration: 7
- By severity:
  - Blocker: 23
  - High: 64
  - Medium: 33
  - Low: 10

---

## Problem Inventory

### Core Directory

#### PC-001
- **Capability**: Core Directory
- **Title**: DRSUAPI replication protocol must be implemented in the framework's DC
- **Description**: AD replication hinges on `DRSGetNCChanges` (opnum 3 on interface `E3514235-...`), which is a state-based pull protocol with USN vectors, UTD vectors, invocation-ID rollback detection, and LZ-compressed REPLENTIN packets. Samba's `source4/rpc_server/drsuapi/` is the only open-source server implementation; FreeIPA uses an entirely different replication protocol (389-DS MMR) that is not wire-compatible with AD. A new framework that aims to support AD features must either (a) implement DRSUAPI server-side for AD interop, (b) reuse Samba's implementation, or (c) design a new replication protocol and lose interop.
- **Impact**: AD-DC compatibility breaks entirely without a DRSUAPI server. Cross-vendor replication is impossible.
- **Severity**: blocker
- **Constraints**: Must remain NDR-wire-compatible with MS-DRSR §4 for any AD-interop scenario. Must handle REPLENTIN_V3/V6/V8/V10/V11 version skew.
- **KB references**: `02-protocols/06-rpc-dcerpc-ms-drsr.md`, `03-directory-schema/05-replication-internals.md`, `01-ad-core/01-ad-ds-internals.md`, `10-comparison-matrices/02-protocol-implementation-matrix.md`
- **Cross-platform**: Windows, Linux, cross-platform (any DC implementation)
- **Open questions**: Should the framework adopt Samba's DRSUAPI code (GPL) or write a fresh implementation? Is there a path to CRDT/OT replication that still speaks DRSUAPI on the wire?

#### PC-002
- **Capability**: Core Directory
- **Title**: USN/InvocationID/UTD-vector replication model is unique to AD; alternatives must preserve rollback semantics
- **Description**: AD's `usnChanged`/`usnCreated` per-DC monotonic counters, `invocationId` (regenerated on USN rollback detection), UTD vector (`{InvocationID,USN}` per originator), and high-watermark cursors together implement idempotent replication with rollback protection. Any new replication protocol (CRDT, OT, or Raft) must preserve (a) rollback detection (restored DCs must not silently resume from a stale USN), (b) idempotency (re-replication must be a no-op), (c) per-attribute `PROPERTY_META_DATA_EXT` (version, originating DSA, originating USN, time). Existing alternatives (Raft, 389-DS MMR, OpenLDAP syncrepl) do not provide all three.
- **Impact**: Silent data divergence if any of the three is lost.
- **Severity**: blocker
- **Constraints**: Must interop with AD DCs (preserve `invocationId` semantics on the wire); must preserve per-attribute metadata for AD-aware conflict resolution.
- **KB references**: `03-directory-schema/05-replication-internals.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Can `PROPERTY_META_DATA_EXT` be expressed as a CRDT tombstone vector? Does a Raft log naturally subsume UTD vector needs?

#### PC-003
- **Capability**: Core Directory
- **Title**: Linked Value Replication (LVR) is required for groups larger than ~5,000 members
- **Description**: Pre-LVR (Server 2003 SP1), a single group-member add replicates the entire `member` attribute. LVR splits `member`/`memberOf`/`managedBy`/etc. into per-value `REPLVALINF_V3` records so only the delta replicates. A new framework must replicate the LVR semantics (or design an alternative) — otherwise large-group operations (common in enterprise AD) saturate replication links.
- **Impact**: Large-group operations become a replication bottleneck; back-link construction (`memberOf`) is slow without LVR.
- **Severity**: high
- **Constraints**: `linkID` pairing in schema (forward = even, backlink = +1) must be preserved; back-link is computed, never directly writable.
- **KB references**: `03-directory-schema/05-replication-internals.md`, `03-directory-schema/01-schema-attributes.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Should the framework keep linkID pairs or replace with a graph database (Neo4j-style) for membership?

#### PC-004
- **Capability**: Core Directory
- **Title**: `member`/`memberOf` back-link requires linkID pairing and DSA-computed construction
- **Description**: `member` is a forward link (linkID=3), `memberOf` is the back-link (linkID=4). The DSA computes `memberOf` on write and stores it in `linktable` (`backlinkDNT`). Clients cannot write `memberOf` directly; the DSA rejects. Back-link enumeration is read-time. A new framework that wants typed/SQL-backed schema must still implement this bidirectional link or break every AD application that queries `memberOf`.
- **Impact**: Every AD-aware application (Exchange, SharePoint, ADUC, custom LDAP apps) breaks without `memberOf`.
- **Severity**: blocker
- **Constraints**: Must be transparent to LDAP clients reading `memberOf`; must support both constructed and stored forms.
- **KB references**: `01-ad-core/01-ad-ds-internals.md`, `03-directory-schema/01-schema-attributes.md`
- **Cross-platform**: cross-platform
- **Open questions**: Is graph storage better than linktable? What is the cost of computing `memberOf` at read time vs storing it?

#### PC-005
- **Capability**: Core Directory
- **Title**: Global Catalog (GC) partial attribute set replication must be implemented
- **Description**: The GC is a partial-attribute read-only replica of every NC in the forest. PAS membership is per-attributeSchema (`isMemberOfPartialAttributeSet=TRUE`). GC promotion is multi-step: set `options |= 0x1`, KCC computes missing partial NC replicas, DSA pulls via `DRSGetNCChanges` with partial-NC flag, DSA flips `msDS-IsGlobalCatalogReady=TRUE`, publishes SRV records, registers `GC/<host>` SPN. A new framework needs GC-equivalent for cross-domain searches (UPN lookup, GAL, recursive group membership).
- **Impact**: Cross-domain queries (`ldap://dc:3268`) fail; universal group membership expansion breaks.
- **Severity**: high
- **Constraints**: Must support PAS filter on `DRSGetNCChanges`; must support `_ldap._tcp.gc._msdcs.<forest>` SRV records; Universal Group Caching (UDC) is the partial alternative.
- **KB references**: `03-directory-schema/03-global-catalog.md`, `00-overview/03-domains-forests-trees.md`
- **Cross-platform**: cross-platform
- **Open questions**: Can a single global store replace the PAS replica concept? If so, what about bandwidth on large forests?

#### PC-006
- **Capability**: Core Directory
- **Title**: Schema cache reload blocks LDAP writes for 5–30 seconds
- **Description**: `schemaUpdateNow` triggers `ntdsa.dll!SCCacheRefresh` which single-threaded reloads `g_SchemaCache`. In-flight LDAP requests use the previous cache; new requests block until the reload completes. On a mid-size forest, this is 5–30 seconds of write-blocking. A new framework should design schema reload to be lock-free or use MVCC.
- **Impact**: Schema extensions during maintenance windows cause noticeable write outages; CI/CD-style schema ops are unworkable.
- **Severity**: medium
- **Constraints**: Schema cache must be transactionally consistent; in-flight writes must not see partial schema.
- **KB references**: `00-overview/02-ad-architecture.md`, `03-directory-schema/01-schema-attributes.md`
- **Cross-platform**: Windows
- **Open questions**: Can copy-on-write schema cache with generation numbers eliminate the lock?

#### PC-007
- **Capability**: Core Directory
- **Title**: ESE/JET Blue database is Windows-only; framework must pick a new storage engine
- **Description**: AD stores the DIT in `ntds.dit`, an ESE (JET Blue) database with 32 KB page size, 16 KB+ pages, sdtable SD dedup, linktable for linked values, and `msysobjects` catalog. Samba uses TDB/LDB; FreeIPA uses 389-DS's BerkeleyDB-derived store; OpenLDAP uses MDB. Each has different performance characteristics, transactional semantics, and replication integration. The framework must pick a storage engine that supports: (a) transactional writes, (b) per-attribute metadata, (c) SD deduplication, (d) page-level checksums, (e) online backup.
- **Impact**: Storage choice determines replication, backup, and recovery story.
- **Severity**: blocker
- **Constraints**: Must support VSS-equivalent snapshot for consistent backup; must support page checksums for corruption detection.
- **KB references**: `00-overview/02-ad-architecture.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: SQLite? FoundationDB? Custom? Each has tradeoffs; pick one and justify.

#### PC-008
- **Capability**: Core Directory
- **Title**: Security descriptor deduplication (`sdtable`) is required for large directories
- **Description**: Two objects with identical SDs share one row in `sdtable`; reference count is `sdrefcount`. Script-generated OUs with explicit per-OU ACEs bloat `sdtable` past 1M rows and slow SD evaluation. A new framework should preserve SD dedup or accept the perf cost; either is a deliberate design choice.
- **Impact**: SD evaluation is a hot path in authorization; without dedup, every object lookup pays an SD hash compare.
- **Severity**: medium
- **Constraints**: Must support `nTSecurityDescriptor` self-relative SD storage; SD hash collision must be detected.
- **KB references**: `01-ad-core/01-ad-ds-internals.md`, `00-overview/02-ad-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Modern hashing (BLAKE3) + persistent map vs the existing sdtable design?

#### PC-009
- **Capability**: Core Directory
- **Title**: Tombstone lifetime and lingering object cleanup must be designed
- **Description**: AD tombstones objects (set `isDeleted=TRUE`, move to `CN=Deleted Objects`) for `tombstoneLifetime` (default 180 days). After that, the tombstone is garbage-collected. If a partner DC is offline longer than `tombstoneLifetime`, strict consistency refuses to re-sync (event 2042); admin must run `repadmin /removelingeringobjects`. A new framework needs an equivalent design or accepts eventual-consistency risks.
- **Impact**: Long-offline DCs can reintroduce deleted objects; strict consistency quarantines them.
- **Severity**: high
- **Constraints**: Must support `tombstoneLifetime` configuration; must support lingering-object detection.
- **KB references**: `03-directory-schema/05-replication-internals.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Are tombstones needed in a CRDT design? What about a Raft log truncation strategy?

#### PC-010
- **Capability**: Core Directory
- **Title**: Cross-domain move requires `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` and PDC + RID master coordination
- **Description**: Moving an object between NCs requires the source DC to call DRSUAPI `DRSAddEntry` against the target DC's `invocationId`, transfer the SD/SID/group memberships, then write a tombstone with `lastKnownParent`. SPNs must be cleared first (domain-scoped). PDC emulator + RID master must be reachable. A new framework that supports multi-domain forests must implement cross-NC move semantics or document the limitation.
- **Impact**: Multi-domain migration workflows (common in large enterprises) break.
- **Severity**: medium
- **Constraints**: Must preserve SID, must rewrite cross-domain group memberships as foreign-SID refs.
- **KB references**: `03-directory-schema/02-ous-containers.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Is cross-domain move still relevant in a post-domain-forest design? Should the framework collapse to a single domain?

#### PC-011
- **Capability**: Core Directory
- **Title**: Well-known container GUIDs are forest-wide constants
- **Description**: `CN=Users` (`aa312825-683f-11d2-8d6c-001999999999`), `CN=Computers` (`a361b2bf-...`), `CN=Deleted Objects` (`18e2ea80-...`), `CN=System`, `CN=Builtin`, `CN=Managed Service Accounts`, etc. are bound to NC heads via `wellKnownObjects`/`msDS-WellKnownObjects`. AD-aware clients use `<WKGUID=...,DC=corp,DC=com>` LDAP URLs to locate them portably. A new framework should preserve these or document the incompatibility.
- **Impact**: Tools that use WKGUID bindings break.
- **Severity**: medium
- **Constraints**: WKGUID lookup must be supported at the DSA level.
- **KB references**: `03-directory-schema/02-ous-containers.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace with REST URL `/api/v1/well-known/Users`? Document as legacy LDAP-only?

#### PC-012
- **Capability**: Core Directory
- **Title**: AD-specific LDAP controls are required for client interop
- **Description**: 25+ AD-specific LDAP controls (TREE_DELETE, DIRSYNC, SD_FLAGS, ASQ, RANGE_RETRIEVAL, NOTIFICATION, GET_STATS, etc.) are not part of RFC 4511. OpenLDAP and 389-DS do not implement them; only AD and Samba-AD-DC do. A new framework must either implement these controls or document which AD features break (DirSync-based sync, Azure AD Connect, range-retrieval for large groups).
- **Impact**: Azure AD Connect sync, large-group enumeration, subtree deletes — all break without the controls.
- **Severity**: high
- **Constraints**: Must remain BER-wire-compatible with the control OIDs (e.g. `1.2.840.113556.1.4.528` for SD_FLAGS).
- **KB references**: `02-protocols/02-ldap-protocol.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Which controls are essential for greenfield vs migration scenarios?

#### PC-013
- **Capability**: Core Directory
- **Title**: `unicodePwd` BER-quote trick for password changes is AD-specific
- **Description**: AD password change via LDAP modify on `unicodePwd` requires the value be the UTF-16LE bytes of a *quoted* password (`"P@ssw0rd!"` → 24 bytes including the quotes). RFC 3062 PasswordModify extended op is NOT supported. A new framework should standardize on RFC 3062 (more portable) but preserve the BER-quote trick for AD interop.
- **Impact**: Existing AD-automation scripts (ldap3, impacket, custom PowerShell) use the BER-quote trick; switching breaks them.
- **Severity**: medium
- **Constraints**: Must support both forms if AD interop is required; TLS mandatory in both.
- **KB references**: `02-protocols/02-ldap-protocol.md`, `11-code-examples/05-python-impacket-examples.md`
- **Cross-platform**: cross-platform
- **Open questions**: Allow the BER-quote form only when in AD-compat mode?

#### PC-014
- **Capability**: Core Directory
- **Title**: FSMO roles are single-master bottlenecks; seizure is destructive
- **Description**: Five FSMO roles (Schema Master, Domain Naming Master, PDC, RID, Infrastructure) are single-master. If the holder dies permanently, seizure is required; the original holder must never come back online (torn-write risk). Seizure is manual via `ntdsutil` or `Move-ADDirectoryServerOperationMasterRole -Force`. A new framework should consider whether FSMO roles are needed at all (consensus-based RID allocation, schema-version vector, time-master-via-chrony).
- **Impact**: Operational fragility — losing a DC with FSMO roles is a manual recovery procedure.
- **Severity**: high
- **Constraints**: Schema master is required for any LDAP-based schema; RID master for SID uniqueness; PDC for password-change urgent replication.
- **KB references**: `00-overview/04-fsmo-roles.md`
- **Cross-platform**: Windows, cross-platform
- **Open questions**: Can all FSMO roles be replaced by Raft-based consensus? Schema "master" via multi-master with version vectors?

#### PC-015
- **Capability**: Core Directory
- **Title**: RID pool allocation is a 500-RID batch bottleneck
- **Description**: Each DC requests RIDs from the RID Master in batches of 500. When the pool drops below 50%, alert; when exhausted, no new security principals. RID Master offline → DCs continue from their pool until exhaustion. A new framework could use a consensus-based RID allocator (e.g. Raft per-domain) or a globally-unique UUID-based scheme.
- **Impact**: RID Master outage causes new-account creation to fail after pool exhaustion; RID space can collide if DCs are restored from snapshots.
- **Severity**: high
- **Constraints**: Must preserve SID uniqueness forest-wide; must support `RIDAvailablePool` and `rIDAllocationPool` for AD interop.
- **KB references**: `00-overview/04-fsmo-roles.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace SIDs with UUIDs? Keep SIDs for AD interop, use UUIDs internally?

#### PC-016
- **Capability**: Core Directory
- **Title**: KCC topology generation every 15 minutes has scaling limits
- **Description**: KCC (`ntdskcc.dll!KCCDoTask`) runs every 15 minutes by default on every DC, computes a least-cost spanning tree, and ISTG computes inter-site topology. At 100+ sites this becomes a bottleneck. ISTG bridgehead selection can fail when sites have asymmetric link costs. A new framework should consider a centralized or declarative topology (Kubernetes-style) instead of auto-computed KCC.
- **Impact**: Large-forest deployments hit KCC scaling ceilings around 200 sites.
- **Severity**: medium
- **Constraints**: Must support site-link cost matrix; must support ISTG failover.
- **KB references**: `00-overview/01-active-directory-overview.md`, `00-overview/02-ad-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace KCC with declarative YAML topology? Maintain compatibility with AD's `cn=Sites,cn=Configuration`?

#### PC-017
- **Capability**: Core Directory
- **Title**: Schema is LDAP-schema with OIDs; typed-schema alternative requires migration tooling
- **Description**: AD schema uses `attributeSchema`/`classSchema` LDAP objects with X.500 OIDs (Microsoft arc `1.2.840.113556.1.x`), `attributeSyntax`/`oMSyntax`, `searchFlags` bitmask, `linkID` pairing, and `isMemberOfPartialAttributeSet`. OpenLDAP/389-DS use RFC 4512 `attributeType`/`objectClass`. A typed-schema alternative (protobuf/SQL/JSON Schema) would require a complete migration path from LDAP schema, plus runtime translation for AD-aware clients.
- **Impact**: Typed-schema alternative breaks every AD-aware application that reads schema via LDAP.
- **Severity**: high
- **Constraints**: Must support LDAP schema reads for AD interop; can layer typed schema on top.
- **KB references**: `03-directory-schema/01-schema-attributes.md`, `10-comparison-matrices/02-protocol-implementation-matrix.md`
- **Cross-platform**: cross-platform
- **Open questions**: Hybrid (LDAP schema + typed projection)? Pure typed with LDAP schema as an adapter?

#### PC-018
- **Capability**: Core Directory
- **Title**: Constructed attributes (`memberOf`, `tokenGroups`, `canonicalName`) require DSA-side computation
- **Description**: AD marks certain attributes as constructed (`FLAG_ATTR_IS_CONSTRUCTED` in `systemFlags`). They are not stored; the DSA computes them at read time from underlying data. Examples: `memberOf` (walks `linktable` back-links), `tokenGroups` (recursive group expansion), `canonicalName` (DN-to-domain-path translation), `msDS-NCReplCursors` (UTD vector as XML). A new framework must preserve constructed-attribute semantics or break LDAP clients.
- **Impact**: Token-groups-based authorization (Kerberos PAC, ADUC) breaks without `tokenGroups`.
- **Severity**: high
- **Constraints**: Must support `FLAG_ATTR_IS_CONSTRUCTED` and `FLAG_ATTR_IS_OPERATIONAL` semantics; clients must explicitly request operational attrs.
- **KB references**: `03-directory-schema/02-ous-containers.md`, `03-directory-schema/03-global-catalog.md`
- **Cross-platform**: cross-platform
- **Open questions**: Cache token-groups on write (event-driven) vs compute at read?

#### PC-019
- **Capability**: Core Directory
- **Title**: AD-integrated DNS zones replicate via DRSUAPI in DomainDnsZones/ForestDnsZones NCs
- **Description**: AD-integrated DNS stores zones as `dnsNode` objects in `DomainDnsZones.<domain>` and `ForestDnsZones.<forest>` application partitions. They replicate via the same DRSUAPI as Domain NCs. BIND with `dlz_bind` Samba plugin is the closest open-source analog; FreeIPA stores DNS in 389DS. A new framework must decide whether to keep DNS in the directory (AD-interop) or externalize (BIND/PowerDNS/CoreDNS) and lose AD DNS features (scavenging, secure DDNS via GSS-TSIG keyed to machine accounts).
- **Impact**: AD-integrated DNS features (per-DC DNS, secure DDNS, scavenging) break without directory-stored DNS.
- **Severity**: high
- **Constraints**: Must support `dnsNode`/`dnsZone` AD schema for interop; must support GSS-TSIG dynamic updates.
- **KB references**: `02-protocols/05-dns-dynamic-updates.md`, `00-overview/01-active-directory-overview.md`
- **Cross-platform**: cross-platform
- **Open questions**: Externalize DNS to CoreDNS with a plugin that reads AD? Keep DNS in-directory for compat?

#### PC-020
- **Capability**: Core Directory
- **Title**: `NTDS.DIT` backup/restore requires VSS-aware snapshots
- **Description**: AD backup uses VSS writer `{5425FD7A-0D43-4C59-AA61-D3D2D9E2B9D7}` to capture a transactionally-consistent DIT. Non-VSS-aware snapshots (VMware/Hyper-V without integration) cause USN rollback detection on next boot. A new framework needs (a) online backup API (snapshot the storage engine), (b) restore procedure that detects and resets `invocationId`, (c) ifeature-parity with `ntdsutil ifm` for install-from-media.
- **Impact**: Non-VSS-aware backups cause silent USN rollback → strict-consistency quarantine.
- **Severity**: high
- **Constraints**: Must support point-in-time-consistent snapshot; must support IFM (install-from-media) for offline DC provisioning.
- **KB references**: `01-ad-core/01-ad-ds-internals.md`, `03-directory-schema/05-replication-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: CRIU for containers? LVM snapshots? Storage-engine-native backup?

#### PC-021
- **Capability**: Core Directory
- **Title**: `instanceType` and `systemFlags` are complex bitmasks that gate object behavior
- **Description**: `instanceType` (IT_WRITE, IT_NC_ABOVE, IT_NC, IT_NC_BASE) marks NC head vs ordinary object. `systemFlags` (FLAG_ATTR_NOT_REPLICATED, FLAG_ATTR_IS_CONSTRUCTED, FLAG_ATTR_IS_OPERATIONAL, FLAG_SCHEMA_BASE_OBJECT, FLAG_DOMAIN_DISALLOW_MOVE/RENAME/DELETE, FLAG_CONFIG_ALLOW_*) gates object behavior. A new framework should preserve these for AD interop or replace with explicit attributes (`is_nc_head BOOLEAN`, `is_replicated BOOLEAN`, etc.).
- **Impact**: Direct LDAP clients that filter on these flags break.
- **Severity**: medium
- **Constraints**: Must preserve AD-compat values for interop scenarios.
- **KB references**: `03-directory-schema/02-ous-containers.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace bitmask with explicit columns/attributes? Maintain bitmask for compat?

#### PC-022
- **Capability**: Core Directory
- **Title**: Multi-tenancy is not native to AD; framework should decide whether to support it
- **Description**: AD has no native multi-tenancy. Each tenant needs a separate forest (heavy) or a separate OU within a shared forest (light, but no hard isolation — same KDC, same GC, same schema, same replication topology). The framework should either (a) support per-tenant NCs with hard isolation (separate KDC, separate GC, separate schema), or (b) document why multi-tenancy is out of scope and recommend separate framework instances per tenant.
- **Impact**: SaaS-style AD offerings (Azure AD DS, Managed AD) need multi-tenancy; without it, each tenant requires a separate deployment.
- **Severity**: high
- **Constraints**: If supported, must isolate KDC keys, GC, schema, replication, audit logs per tenant.
- **KB references**: `00-overview/03-domains-forests-trees.md`, `00-overview/01-active-directory-overview.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-tenant NC heads? Kubernetes namespace-style isolation?

### KDC

#### PC-023
- **Capability**: KDC
- **Title**: KDC must implement MS-KILE profile of RFC 4120 with PAC generation and signing
- **Description**: AD's KDC (`kdcsvc.dll`) extends RFC 4120 with MS-KILE: PAC buffer generation in TGT (PAC_LOGON_INFO, PAC_SIGNATURE_DATA x2, PAC_UPN_DNS_INFO, PAC_CLIENT_INFO, Server 2016+ PAC_BUFFER_TICKET_CHECKSUM and PAC_FULL_CHECKSUM, Server 2019+ PAC_REQUESTER). KDC signs PAC with krbtgt long-term key. Samba's Heimdal fork in `source4/kdc/` is the only open-source server implementation. MIT krb5 KDC does NOT generate PACs by default (only verifies). FreeIPA's `ipa_kdb` plugin generates MS-PAC for cross-forest trust users.
- **Impact**: Without MS-KILE-compliant KDC, AD-aware services cannot validate PACs; cross-forest trusts break.
- **Severity**: blocker
- **Constraints**: Must generate PAC with full buffer set; must support Server 2016+ ticket signature for silver-ticket defense.
- **KB references**: `02-protocols/01-kerberos-internals.md`, `02-protocols/08-spn-upn-pac.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Reuse Samba's Heimdal fork (GPL)? MIT krb5 + custom PAC plugin (FreeIPA approach)? Fresh implementation?

#### PC-024
- **Capability**: KDC
- **Title**: RC4-HMAC default for backwards compat is a security liability
- **Description**: RC4-HMAC (etype 0x17) is still default for accounts without `msDS-SupportedEncryptionTypes` set. RC4 keys are derived from MD4 of the password (NT hash), making TGS tickets offline-brute-forceable (Kerberoasting). Server 2022 disables RC4 by default for new accounts but legacy service accounts remain. A new framework should default to AES-only (etype 0x12 + 0x11) and provide explicit RC4-compat mode for migration.
- **Impact**: Kerberoasting remains the most common AD attack vector.
- **Severity**: blocker
- **Constraints**: Must support RC4 as opt-in for migration; AES-only default must not break service-account logon for legacy apps.
- **KB references**: `02-protocols/01-kerberos-internals.md`, `00-overview/01-active-directory-overview.md`
- **Cross-platform**: cross-platform
- **Open questions**: Provide a "migration mode" that issues RC4 TGS with audit-log warnings? Auto-rotate service accounts to AES on next password change?

#### PC-025
- **Capability**: KDC
- **Title**: PAC validation RPC requires service-to-DC roundtrip
- **Description**: Services that need PAC validation (IIS, SQL Server, COM+) call `NetrLogonSamLogonEx` over Netlogon to the DC, passing the ticket + PAC. The DC validates the KDC signature with the krbtgt key. This is a per-AP-REQ roundtrip for high-security services. Most services skip PAC validation (perf), relying on KDC-time signing only. Server 2016+ ticket signature mitigates silver-ticket attacks but only services that opt in to PAC validation benefit. A new framework could push PAC validation to the KDC at TGS time (always-validate) or implement a token-binding approach.
- **Impact**: Silver-ticket attacks succeed against services that skip PAC validation.
- **Severity**: high
- **Constraints**: Must not introduce per-request DC roundtrip for non-validating services; must support `VerifyPacAuthenticators` registry toggle for opt-in.
- **KB references**: `02-protocols/08-spn-upn-pac.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: Windows
- **Open questions**: Always-validate mode with cached krbtgt keys per service? Token-binding via TLS exporter?

#### PC-026
- **Capability**: KDC
- **Title**: FAST (RFC 6806) armoring is opt-in via GPO; rarely enforced
- **Description**: FAST wraps pre-auth in a TGT-armored tunnel, defeating AS-REP roasting. Supported Server 2012+ KDC and Windows 8+ client. GPO `Configure FAST policy = Supported|Required`. Most deployments leave it at "Supported" (off). A new framework should default to FAST-required and document the migration path.
- **Impact**: AS-REP roasting remains viable for accounts with `DO_NOT_REQUIRE_PREAUTH`.
- **Severity**: high
- **Constraints**: Must support anonymous PKINIT armor TGT (RFC 6112) for first-logon FAST.
- **KB references**: `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Is FAST-required compatible with all legacy clients (Java, old Python)? Provide fallback grace period?

#### PC-027
- **Capability**: KDC
- **Title**: PKINIT smart-card logon requires NTAuthCertificates AD object + Enterprise CA
- **Description**: PKINIT (RFC 4556) requires the user cert to chain to a CA in `NTAuthCertificates` AD object (`CN=NTAuthCertificates,CN=Public Key Services,...`). User cert SAN must contain UPN or map via `altSecurityIdentities`. A new framework needs equivalent PKI integration or design a modern passwordless alternative (FIDO2, WebAuthn, Windows Hello for Business).
- **Impact**: Smart-card logon (PIV/CAC) depends on this integration; government/defense deployments require it.
- **Severity**: high
- **Constraints**: Must support NTAuthCertificates for AD interop; consider FIDO2 as modern alternative.
- **KB references**: `02-protocols/01-kerberos-internals.md`, `05-pki-certs/02-certificate-templates.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt FIDO2 + PKINIT-anonymous for passwordless? Maintain smart-card path for compliance?

#### PC-028
- **Capability**: KDC
- **Title**: Cross-realm TGT referral chain is rigid; transited field validation is fragile
- **Description**: When a user in domain A requests a service ticket for a service in domain B, the KDCs walk the trust graph via referral TGTs. The `Transited` field of the resulting ticket encodes the realm chain; the target KDC validates it against the trust graph. In forests with many domains and shortcut trusts, the chain can be non-trivial. A new framework should consider a flatter trust model (any-to-any via forest root) or document the chain semantics.
- **Impact**: Cross-domain auth latency in multi-domain forests; trust-graph misconfig breaks auth.
- **Severity**: medium
- **Constraints**: Must preserve RFC 4120 §3.3.3 referral semantics for AD interop.
- **KB references**: `00-overview/03-domains-forests-trees.md`, `02-protocols/01-kerberos-internals.md`, `03-directory-schema/04-trusts-topology.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace transited-field with signed assertions from each hop? Trust-on-first-use model?

#### PC-029
- **Capability**: KDC
- **Title**: AES-SHA384 (etype 0x13) support requires Server 2022+ KDC and clients
- **Description**: RFC 8009 adds `aes256-cts-hmac-sha384-192` (etype 0x13) with stronger HMAC. Server 2022+ supports; older DCs/clients fall back to 0x12. PBKDF2 iteration count stays at 4096 for compatibility. A new framework should default to 0x13 with fallback to 0x12 for legacy clients.
- **Impact**: Stronger ticket integrity for modern deployments.
- **Severity**: low
- **Constraints**: Must support both 0x12 and 0x13; PBKDF2 4096 iterations for compatibility.
- **KB references**: `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt 0x13 default with 0x12 fallback grace period? When to drop 0x12?

#### PC-030
- **Capability**: KDC
- **Title**: `krbtgt` account compromise = golden ticket; rotation is operationally painful
- **Description**: Anyone with the krbtgt account hash can forge TGTs (golden ticket). krbtgt password rotation is recommended but operationally painful (must do twice within TGT lifetime to invalidate old tickets). Microsoft's krbtgt rotation guidance is a multi-step procedure. A new framework should (a) make krbtgt rotation a one-click operation, (b) support dual-krbtgt mode (overlap window), (c) monitor for tickets signed by old keys post-rotation.
- **Impact**: Compromised krbtgt = full forest compromise; rotation rarely done.
- **Severity**: blocker
- **Constraints**: Must support dual-krbtgt (Server 2012+ feature); must log old-key TGT usage as a security signal.
- **KB references**: `00-overview/01-active-directory-overview.md`, `02-protocols/08-spn-upn-pac.md`
- **Cross-platform**: cross-platform
- **Open questions**: HSM-bound krbtgt key? Automatic rotation every N days?

#### PC-031
- **Capability**: KDC
- **Title**: SPN uniqueness requires KDC-side `DRSWriteSPN` pre-commit check
- **Description**: AD enforces SPN uniqueness forest-wide via `DRSWriteSPN` (opnum 13 on DRSUAPI). The KDC, when registering an SPN, calls DRSWriteSPN with duplicate-detection. `setspn -X` finds duplicates post-hoc. Duplicate SPNs cause KDC to issue tickets encrypted to the wrong account (`KRB_AP_ERR_MODIFIED`). A new framework must implement SPN uniqueness at write time.
- **Impact**: Duplicate SPNs cause intermittent auth failures (`KRB_AP_ERR_MODIFIED`) that are difficult to diagnose.
- **Severity**: high
- **Constraints**: Uniqueness scope is forest-wide (across all domains). Must support GC-based uniqueness check.
- **KB references**: `02-protocols/08-spn-upn-pac.md`, `02-protocols/06-rpc-dcerpc-ms-drsr.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-forest unique index on SPN? Per-domain with cross-domain conflict detection?

#### PC-032
- **Capability**: KDC
- **Title**: UPN uniqueness is forest-wide but enforced inconsistently
- **Description**: UPN (`userPrincipalName`) must be unique within the forest. AD enforces this at the KDC during AS-REQ (the KDC picks one of the duplicates). Suffix list (`uPNSuffixes` on `CN=Partitions`) restricts which suffixes are valid. UPN duplicates cause intermittent login failures. A new framework must enforce UPN uniqueness at write time and validate suffix.
- **Impact**: UPN-duplicate users get intermittent login failures depending on which DC handles the AS-REQ.
- **Severity**: high
- **Constraints**: Must support `uPNSuffixes` and `msDS-UPNSuffixes` for custom suffixes; uniqueness scope is forest.
- **KB references**: `02-protocols/08-spn-upn-pac.md`, `00-overview/03-domains-forests-trees.md`
- **Cross-platform**: cross-platform
- **Open questions**: Strict write-time uniqueness vs soft enforcement? Auto-rename on conflict?

#### PC-033
- **Capability**: KDC
- **Title**: KDC throughput at million-object scale is a known bottleneck
- **Description**: AD KDC (`kdcsvc.dll`) runs in LSASS thread pool; per-DC throughput is bounded by LSASS CPU. Million-user forests often require dedicated KDC DCs (without GC, without RID master). The 5-minute Kerberos skew window and PAC signing cost per AS-REQ/TGS-REQ add overhead. A new framework should horizontally scale the KDC (stateless, share krbtgt key across N KDCs) and benchmark at scale.
- **Impact**: Large enterprises need dedicated KDC DCs; auth latency in worst-case scenarios.
- **Severity**: high
- **Constraints**: KDC must share krbtgt key across instances; must share service-account long-term keys via directory.
- **KB references**: `00-overview/02-ad-architecture.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Stateless KDC with shared key in HSM? Per-realm KDC pool?

#### PC-034
- **Capability**: KDC
- **Title**: `kpasswd` (RFC 3244) is the only standardized password-change protocol; UI integration varies
- **Description**: AD uses kpasswd on TCP/UDP 464 for password changes. The protocol uses KRB-PRIV wrapping. All major clients (Windows, macOS Heimdal, Linux MIT) support it. UI integration varies: Windows uses Ctrl+Alt+Del → Change Password; macOS uses System Settings; Linux uses `passwd` via PAM. A new framework must support kpasswd and consider modern alternatives (self-service portal, OAuth-backed password reset).
- **Impact**: Standard kpasswd is required for client interop.
- **Severity**: medium
- **Constraints**: Must support TCP/UDP 464; KRB-PRIV wrapping; returns `KRB5KDC_ERR_KEY_EXPIRED` for must-change.
- **KB references**: `02-protocols/01-kerberos-internals.md`, `02-protocols/07-ntp-time-sync.md`
- **Cross-platform**: cross-platform
- **Open questions**: Add OAuth2 password-reset endpoint as modern alternative?

#### PC-035
- **Capability**: KDC
- **Title**: Group Managed Service Accounts (gMSA) require KDS root key + automatic password rotation
- **Description**: gMSAs (`msDS-GroupMSAMembership` ACL) have automatic 30-day password rotation computed by KDS (Key Distribution Service) using a forest-wide root key (`Add-KdsRootKey`). The KDS root key must be created 10+ hours before use (effective time trick). Service hosts fetch the gMSA password via `NetrServerAuthenticate3` + `NetrServerRetrieveBaseDelta` or via `Get-ADServiceAccount`. A new framework must implement KDS-equivalent or use a different mechanism (Vault-backed service-account secrets).
- **Impact**: Without gMSA-equivalent, service-account passwords are static (Kerberoast risk) or operator-managed (ops burden).
- **Severity**: high
- **Constraints**: Must support automatic rotation; must support host ACL (`msDS-GroupMSAMembership`).
- **KB references**: `01-ad-core/01-ad-ds-internals.md`, `00-overview/04-fsmo-roles.md`
- **Cross-platform**: cross-platform
- **Open questions**: HashiCorp Vault integration for service-account secrets? KDS-equivalent per-forest root key?

### Auth Provider

#### PC-036
- **Capability**: Auth Provider
- **Title**: NTLM must be supported for legacy interop; deprecation is operationally difficult
- **Description**: NTLM (MS-NLMP) is deprecated but widely deployed. Apps that hard-require NTLM (legacy SQL drivers, old IIS-integrated apps, third-party appliances) fail when NTLM is blocked. Microsoft's "Restrict NTLM" GPOs allow audit→enforce migration but most shops stay in audit mode indefinitely. A new framework should (a) support NTLM as opt-in for compat, (b) default to Kerberos-only, (c) provide migration tooling.
- **Impact**: Legacy app compat blocks NTLM removal in most enterprises.
- **Severity**: high
- **Constraints**: Must support NTLMv2 (NTLMv1 disabled by default); must support channel binding (RFC 5929) for relay defense.
- **KB references**: `02-protocols/04-ntlm-internals.md`, `10-comparison-matrices/01-feature-os-matrix.md`
- **Cross-platform**: Windows, Linux (via Samba), cross-platform
- **Open questions**: Provide NTLM-emulation via Kerberos with downgrade-friendly client SDK? Hard cut-off date?

#### PC-037
- **Capability**: Auth Provider
- **Title**: NTLM relay attacks require LDAP signing + channel binding + EPA enforcement
- **Description**: NTLM relay places an attacker in the middle; the attacker forwards the Type 1/2/3 messages to a target service. Mitigations: SMB signing required, LDAP signing + channel binding (EPA), `Restrict NTLM` GPOs. AD CS LDAP endpoint was a famous relay target (PetitPotam, ShadowCoerce). A new framework should default to LDAP signing required + channel binding required and document the EPA posture.
- **Impact**: NTLM relay is a common lateral-movement vector.
- **Severity**: blocker
- **Constraints**: Must support `MsvAvChannelBindings` (SHA-256 of TLS channel bindings); must support `EPHEMERAL` flag for non-delegatable sessions.
- **KB references**: `02-protocols/04-ntlm-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Disable NTLM by default with audit-mode migration? Mandate EPA across all protocols?

#### PC-038
- **Capability**: Auth Provider
- **Title**: Pass-the-hash (PtH) defense requires LSASS protection / Credential Guard
- **Description**: NTLM hash is the entire secret; an attacker with the hash can construct valid NTLMv2 responses without the password. LSASS memory dumps (mimikatz) harvest hashes. Microsoft's defenses: LSA Protected Mode (`RunAsPPL`), Credential Guard (virtualization-based LSASS isolation), LAPS for local admin rotation. A new framework on Windows needs LSASS protection; on Linux/macOS the equivalent is SSSD's krb5_child setuid isolation.
- **Impact**: PtH is the dominant lateral-movement technique.
- **Severity**: blocker
- **Constraints**: Must not store NT hash in process memory accessible to administrators; must support LAPS-equivalent for local accounts.
- **KB references**: `02-protocols/04-ntlm-internals.md`, `00-overview/01-active-directory-overview.md`
- **Cross-platform**: Windows, cross-platform
- **Open questions**: Drop NTLM entirely (eliminates PtH)? Use VSM-equivalent on Linux (TEE)?

#### PC-039
- **Capability**: Auth Provider
- **Title**: S4U2Self + S4U2Proxy constrained delegation semantics are complex
- **Description**: S4U2Self (PA-FOR-USER) lets a service obtain a TGS for itself on behalf of a user (no user password needed). S4U2Proxy lets the service exchange that TGS for a TGS to a backend service, constrained by `msDS-AllowedToDelegateTo` on the service account. Resource-based constrained delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`) flips the ACL to the target. A new framework must implement all three or document the delegation limitations.
- **Impact**: Constrained delegation is widely used for service-to-service auth (IIS → SQL, etc.).
- **Severity**: high
- **Constraints**: Must support `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit; must support `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- **KB references**: `02-protocols/08-spn-upn-pac.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace with OAuth2 client-credentials flow? Maintain S4U for AD interop?

#### PC-040
- **Capability**: Auth Provider
- **Title**: Windows Token construction (LSASS-side) vs Linux PAM stack are architecturally different
- **Description**: Windows builds a token (user SID + group SIDs + privileges) in LSASS via `LsaLogonUser`; the token is a kernel object passed to processes. Linux uses PAM (auth/account/password/session phases) + NSS (passwd/group lookups) with no kernel token. macOS uses PAM + OpenDirectory. A new framework needs a unified auth API that abstracts these differences (SSPI on Windows, GSSAPI + PAM on Linux, Authorization Framework on macOS).
- **Impact**: Cross-platform client SDK requires per-OS auth abstraction.
- **Severity**: high
- **Constraints**: Must support Kerberos + NTLM + cert auth; must expose token/group info to apps.
- **KB references**: `10-comparison-matrices/04-auth-flow-comparison.md`, `09-linux-equivalents/10-pam-nss-stack.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt WebAuthn-style token-binding as the unified abstraction? Per-platform adapters?

#### PC-041
- **Capability**: Auth Provider
- **Title**: Time sync (W32Time + MS-SNTP) is fragile; 5-minute Kerberos skew window breaks auth
- **Description**: Kerberos requires clocks within 5 minutes (`clockskew`); PA-ENC-TIMESTAMP pre-auth fails with `KRB_AP_ERR_SKEW` if outside. AD uses W32Time + MS-SNTP authentication (Netlogon secure channel key signs NTP responses). chrony/ntpd do not support MS-SNTP. VM time drift via Hyper-V/VMware integration services is a common cause. A new framework should default to chrony (no MS-SNTP), rely on KDC skew enforcement, and provide monitoring for skew.
- **Impact**: Time skew is the most common cause of Kerberos auth failures in mixed environments.
- **Severity**: high
- **Constraints**: Must support RFC 5905 NTP; consider MS-SNTP only for legacy AD interop.
- **KB references**: `02-protocols/07-ntp-time-sync.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Drop MS-SNTP entirely? Mandatory chrony with monitoring alerting on >2 min skew?

#### PC-042
- **Capability**: Auth Provider
- **Title**: Kerberos audit events (4768/4769/4771) need equivalent in framework
- **Description**: AD logs Kerberos events to Windows Event Log: 4768 (TGT issued), 4769 (TGS issued), 4771 (pre-auth failed), 4768/4769 with `Ticket Encryption Type: 0x17` is the Kerberoasting signal. A new framework should emit equivalent structured events (JSON/CEF) to OpenTelemetry / SIEM, including etype, SPN, requester SID, source IP.
- **Impact**: Kerberoasting/DCSync detection depends on these events; SIEM queries assume Windows event IDs.
- **Severity**: high
- **Constraints**: Must include etype, SPN, requester SID, source IP, request ID for correlation.
- **KB references**: `11-code-examples/05-python-impacket-examples.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Map to MITRE ATT&CK technique IDs in the event metadata? OTel semantic conventions for Kerberos?

### Policy Engine

#### PC-043
- **Capability**: Policy Engine
- **Title**: GPO architecture (GPC + GPT split) is fragile; version mismatch is common
- **Description**: GPO is split: GPC (groupPolicyContainer AD object) and GPT (SYSVOL folder). `versionNumber` on GPC must match `Version` in `GPT.INI`. DFS-R replicates GPT; DRSUAPI replicates GPC. Mismatches happen when DFS-R lags or when admins edit GPT directly. A new framework should use a single source of truth (e.g. signed Git repo replicated to all DCs) and abandon the GPC/GPT split.
- **Impact**: GPO version mismatch causes clients to skip policy or apply stale.
- **Severity**: high
- **Constraints**: Must support atomic GPO updates; must support `gPLink`/`gPOptions` for LSDOU processing.
- **KB references**: `04-group-policy/01-gpo-architecture.md`, `04-group-policy/05-gpt-gpc-structure.md`
- **Cross-platform**: Windows, cross-platform
- **Open questions**: Single declarative YAML per GPO in a Git repo? Per-GPO CRDT?

#### PC-044
- **Capability**: Policy Engine
- **Title**: LSDOU processing order is last-writer-wins; no conflict resolution beyond Enforced/Block
- **Description**: GPO processing order is LSDOU (Local, Site, Domain, OU parent-to-child), `gPLink` left-to-right, last-applied-wins. Modifiers: `gPOptions=1` (block inheritance), `gPLink Options=0x2` (Enforced). No semantic conflict resolution (e.g. "Registry X wins over Registry Y"). A new framework should support declarative policy with explicit precedence rules.
- **Impact**: Policy conflicts are resolved by accident (whichever GPO is last in LSDOU); debugging is hard.
- **Severity**: medium
- **Constraints**: Must preserve LSDOU + Enforced for AD interop; consider declarative precedence as enhancement.
- **KB references**: `04-group-policy/02-gpo-processing-order.md`
- **Cross-platform**: cross-platform
- **Open questions**: Declarative policy with explicit `priority: N` per setting? Keep LSDOU as default?

#### PC-045
- **Capability**: Policy Engine
- **Title**: GPO Preferences (XML files) have no macOS/Linux equivalent
- **Description**: GPO Preferences (`Drive Maps`, `Files`, `Folders`, `Ini Files`, `Local Users and Groups`, `Printers`, `Scheduled Tasks`, `Services`, `Shortcuts`, `Environment`, `Registry`, `Internet Settings`) are 14+ XML files in `Machine\Preferences\` and `User\Preferences\`. SSSD reads only `GptTmpl.inf` (security CSE); no Preferences XML. macOS MDM profiles cover a subset. A new framework needs a unified declarative policy format that maps to all platforms.
- **Impact**: Preferences are the most-used GPO feature; cross-platform parity is poor.
- **Severity**: blocker
- **Constraints**: Must support drive maps, file deployment, scheduled tasks, local users/groups, registry/plist, environment variables.
- **KB references**: `04-group-policy/05-gpt-gpc-structure.md`, `04-group-policy/04-cse-client-side-extensions.md`, `10-comparison-matrices/05-gpo-equivalents-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt OPA-style declarative policy with platform-specific executors? Per-platform translation layer?

#### PC-046
- **Capability**: Policy Engine
- **Title**: ADMX schema is Windows-specific; cross-platform equivalent is fragmented
- **Description**: ADMX (XML) + ADML (localized strings) define registry policy settings. Central Store at `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\`. macOS MDM uses per-payload schemas (no unified ADMX equivalent). Linux SSSD has no ADMX parser. A new framework should adopt a unified policy-definition format (JSON Schema? OPA?) that compiles to platform-native forms.
- **Impact**: Cross-platform policy authoring requires per-OS translation today.
- **Severity**: high
- **Constraints**: Must support ADMX for Windows interop; must support MDM payload schema for macOS.
- **KB references**: `04-group-policy/03-admx-templates.md`, `10-comparison-matrices/05-gpo-equivalents-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Single policy DSL that compiles to ADMX/MDM/SSSD-conf? OPA Rego as the unified format?

#### PC-047
- **Capability**: Policy Engine
- **Title**: CSE (Client-Side Extension) model is Windows-only; per-CSE GUIDs
- **Description**: 16+ CSEs (Registry `{35378EAC-...}`, Security `{827D319E-...}`, Scripts `{42B5FAAE-...}`, Folder Redir `{426031c0-...}`, AppLocker `{16be69fa-...}`, Software Install `{c6dc5466-...}`, etc.) are Windows DLLs registered under `HKLM\...\Group Policy\CSEs\{GUID}`. Each exports `ProcessGroupPolicy`. macOS/Linux have no equivalent — SSSD implements only the Security CSE subset. A new framework needs per-platform CSE-equivalents.
- **Impact**: Cross-platform policy enforcement is partial.
- **Severity**: high
- **Constraints**: Must support Windows CSE GUIDs for interop; must define platform-native equivalents.
- **KB references**: `04-group-policy/04-cse-client-side-extensions.md`, `10-comparison-matrices/05-gpo-equivalents-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Generic "policy executor" framework with per-platform plugins? Declarative policy that compiles to CSE invocations on Windows and shell scripts on Linux?

#### PC-048
- **Capability**: Policy Engine
- **Title**: GPO has no native rollback or transactional semantics
- **Description**: GPO apply is best-effort; failed CSEs log Event 1090 but processing continues. No atomic rollback (unlike Ansible's `--check` mode). Registry.pol writes are immediate; reverting requires restoring from backup. A new framework should support transactional policy apply with rollback on failure.
- **Impact**: Bad GPO deployments can break hosts with no easy revert.
- **Severity**: medium
- **Constraints**: Must support per-CSE rollback; must support dry-run / preview.
- **KB references**: `04-group-policy/02-gpo-processing-order.md`, `04-group-policy/04-cse-client-side-extensions.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-CSE snapshot before apply? Git-style revert?

#### PC-049
- **Capability**: Policy Engine
- **Title**: WMI filters are evaluated client-side; WMI repository corruption fails GPOs
- **Description**: GPO WMI filters (`msFTSI` objects under `CN=SOM,CN=WMIPolicy,CN=System,...`) are WQL queries evaluated on the client. If WMI service is unavailable, the GPO is **not applied** (fail-closed). WMI repository corruption is common on Windows. A new framework should consider declarative host-filters (Ansible-style facts) instead of WMI.
- **Impact**: WMI repository corruption silently drops GPOs.
- **Severity**: medium
- **Constraints**: Must preserve WMI filter eval for AD interop; consider OS-fact-based filters as modern alternative.
- **KB references**: `04-group-policy/02-gpo-processing-order.md`
- **Cross-platform**: Windows
- **Open questions**: Replace WMI filters with declarative host facts (OS, role, site)? Keep WMI for Windows-only?

#### PC-050
- **Capability**: Policy Engine
- **Title**: Slow-link detection (ICMP ping to PDC) is unreliable
- **Description**: `gpsvc.dll!DetectSlowLink` pings the PDC 3 times with a 64 KB packet, estimates link speed. ICMP is often blocked; result is "fast" by default. Slow-link triggers skip Folder Redir, Software Install, Scripts, and most Preferences. A new framework should use TCP RTT or HTTP-based detection instead.
- **Impact**: Slow-link detection is unreliable; either always-fires or never-fires.
- **Severity**: low
- **Constraints**: Must support slow-link policy processing semantics for compat.
- **KB references**: `04-group-policy/02-gpo-processing-order.md`
- **Cross-platform**: Windows
- **Open questions**: Replace ICMP with HTTP HEAD probe? Per-CSE slow-link policy?

#### PC-051
- **Capability**: Policy Engine
- **Title**: GPO background refresh interval (90 min + jitter) is too slow for security policies
- **Description**: Default GPO refresh is 90 minutes + 0–30 minute jitter. Security-sensitive policies (LAPS rotation, account lockout) need faster propagation. Manual `gpupdate /force` is the workaround. A new framework should support push-based policy distribution (webhook to clients) and per-policy priority.
- **Impact**: Security policies propagate slowly; urgent changes require manual gpupdate.
- **Severity**: medium
- **Constraints**: Must support push-based refresh; must support per-policy priority.
- **KB references**: `04-group-policy/02-gpo-processing-order.md`
- **Cross-platform**: cross-platform
- **Open questions**: WebSocket / MQTT push channel for policy updates? Per-policy TTL?

#### PC-052
- **Capability**: Policy Engine
- **Title**: Registry.pol PReg format is binary/UTF-16; needs explicit parser
- **Description**: `Registry.pol` is a binary file with `PReg\0` signature followed by UTF-16LE `[key;value;type;size;data;]` records. Each record is hex-encoded. SSSD's `samba-gpupdate` parses this for a fixed set of known policy keys. macOS MDM has no PReg concept. A new framework should adopt a portable format (JSON/YAML) for new policies and provide a PReg compat reader.
- **Impact**: Registry.pol is opaque to non-Windows clients.
- **Severity**: medium
- **Constraints**: Must support PReg for Windows interop; new policies should use JSON/YAML.
- **KB references**: `04-group-policy/05-gpt-gpc-structure.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Single policy format (JSON) with PReg adapter for Windows? Per-platform native formats?

#### PC-053
- **Capability**: Policy Engine
- **Title**: SSSD GPO access control only enforces `[Privilege Rights]` logon rights
- **Description**: SSSD's `ad_gpo_access_control` parses `GptTmpl.inf` `[Privilege Rights]` section for 5 logon rights (SeInteractiveLogonRight, SeRemoteInteractiveLogonRight, SeNetworkLogonRight, SeBatchLogonRight, SeServiceLogonRight). All other GPO settings (Registry.pol, Preferences, Scripts) are ignored on Linux. macOS MDM covers a different subset. A new framework needs a unified access-control policy that maps to all platforms.
- **Impact**: GPO access control on Linux is ~1/50th of Windows scope.
- **Severity**: high
- **Constraints**: Must support the 5 logon rights on Linux for AD interop; consider FreeIPA HBAC as modern alternative.
- **KB references**: `09-linux-equivalents/03-sssd-gpo-access.md`, `10-comparison-matrices/05-gpo-equivalents-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt FreeIPA HBAC semantics as the cross-platform access-control model? Map GPO URA to HBAC at compile time?

#### PC-054
- **Capability**: Policy Engine
- **Title**: GPO security filtering on `Authenticated Users` is fragile
- **Description**: Default GPOs are ACLed for `Authenticated Users` (Read + Apply). Removing Authenticated Users from a GPO is a common breakage: computer accounts need Read at boot. Workaround is to add `Domain Computers` explicitly. A new framework should default to "all authenticated + computer accounts" and document the security-filter model.
- **Impact**: Removing Authenticated Users silently breaks computer policy.
- **Severity**: medium
- **Constraints**: Must support per-principal ACL on policy objects; must include computer accounts by default.
- **KB references**: `04-group-policy/02-gpo-processing-order.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace per-principal ACL with role-based policy binding? Auto-include computer accounts?

#### PC-055
- **Capability**: Policy Engine
- **Title**: SYSVOL replication via DFS-R is Windows-only; FRS is removed
- **Description**: SYSVOL replicates via DFS-R (`dfsr.exe`) using version vectors + RDC. Server 2019 removed FRS entirely. Samba AD-DC replicates SYSVOL via DRSUAPI on the SysVol directory (single-master per attribute) — different mechanism. A new framework must pick: DFS-R-equivalent (write it), DRSUAPI-based SYSVOL (Samba-style), or externalize to Git/sync.
- **Impact**: SYSVOL is the GPO + logon-script distribution channel; without it, GPO breaks.
- **Severity**: blocker
- **Constraints**: Must support GPO + script distribution to all clients via SMB (`\\<domain>\SYSVOL\...`).
- **KB references**: `07-file-print/02-dfs-n-dfs-r.md`, `04-group-policy/01-gpo-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Git-backed SYSVOL with auto-sync to DCs? Samba-style DRSUAPI SYSVOL?

#### PC-056
- **Capability**: Policy Engine
- **Title**: No native policy versioning / history; reverting requires backup restore
- **Description**: GPO has only `versionNumber` (incrementing counter). No history of past versions. Reverting to a previous GPO state requires restoring from a `Backup-GPO` archive. A new framework should version policies in Git with full history and support atomic rollback.
- **Impact**: GPO change management is manual; revert is fragile.
- **Severity**: medium
- **Constraints**: Must support policy version history; must support atomic rollback.
- **KB references**: `04-group-policy/01-gpo-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Git-backed policies with PR-based review? Auto-tag on apply?

### Cert Service

#### PC-057
- **Capability**: Cert Service
- **Title**: AD CS (certsvc.exe + ESE CA DB) is Windows-only; no open-source MS-WCCE server
- **Description**: AD CS uses `certsvc.exe` with ESE-backed CA database. MS-WCCE (ICertPassage RPC UUID `91b9b93a-...`) is the cert enrollment protocol. MS-XCEP (CEP HTTP) + MS-WSTEP (CES HTTP) are modern SOAP-based enrollment. Samba does not implement MS-WCCE server. FreeIPA's Dogtag uses a different RA protocol. A new framework must either implement MS-WCCE for AD interop or adopt a modern protocol (EST, ACME) and lose AD CS client interop.
- **Impact**: Windows autoenrollment breaks without MS-WCCE; certmonger cannot enroll against AD CS.
- **Severity**: blocker
- **Constraints**: Must support MS-WCCE/MS-XCEP/MS-WSTEP for Windows interop; consider ACME as modern alternative.
- **KB references**: `01-ad-core/02-ad-cs-cert-services.md`, `05-pki-certs/01-ad-cs-architecture.md`, `10-comparison-matrices/02-protocol-implementation-matrix.md`
- **Cross-platform**: Windows, Linux
- **Open questions**: Adopt ACME (RFC 8555) for new clients + MS-WCCE adapter for Windows? Implement Dogtag-style REST API?

#### PC-058
- **Capability**: Cert Service
- **Title**: Certificate templates (v1/v2/v3) with `msPKI-*` attributes are complex
- **Description**: AD CS templates are `pKICertificateTemplate` AD objects with `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, `pKIKeyUsage`, `pKIExtendedKeyUsage`, `pKIMaxIssuingDepth`, `pKIExpirationPeriod`, `pKIOverlapPeriod`, `nTSecurityDescriptor` (Enroll/Autoenroll ACEs). v1 (NT4) → v2 (Win2003, ACL) → v3 (Win2008, CNG). A new framework needs an equivalent template model or simplifies (single JSON template schema).
- **Impact**: Template authoring is expert-only; ACL model is fragile.
- **Severity**: high
- **Constraints**: Must support per-template ACL (Enroll, Autoenroll, Write, Read); must support EKU enforcement.
- **KB references**: `05-pki-certs/02-certificate-templates.md`
- **Cross-platform**: cross-platform
- **Open questions**: Single JSON template schema with ACL projection to AD? Adopt Dogtag profile format?

#### PC-059
- **Capability**: Cert Service
- **Title**: Autoenrollment via `autoenroll.dll` CSE + GPO is Windows-only
- **Description**: Autoenroll CSE `{71587597-1207-11D2-8250-00A0C903A8CB}` runs at GP refresh, calls CEP for policy + CES/WCCE for issuance. macOS has no equivalent (MDM SCEP profile is per-device). Linux uses `certmonger` with `cepces` plugin (CEP/CES client). A new framework needs a unified autoenroll daemon (cross-platform) that pulls policy from a unified endpoint.
- **Impact**: Cross-platform autoenroll requires per-OS agents today.
- **Severity**: high
- **Constraints**: Must support key-based renewal (MS-WSTEP) for unattended hosts; must support key archival.
- **KB references**: `05-pki-certs/03-autoenrollment.md`, `04-group-policy/04-cse-client-side-extensions.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Single certmonger-style daemon with platform-native key stores (Keychain, KRA, CNG)? ACME + SCEP dual-protocol?

#### PC-060
- **Capability**: Cert Service
- **Title**: Key archival (KRA) is risky; losing KRA keys loses all archived keys
- **Description**: When `msPKI-Private-Key-Flag.REQUIRE_PRIVATE_KEY_ARCHIVAL` is set, the CSR is wrapped with the CA's KRA cert (CMS EnvelopedData, AES-256 content key + RSA-OAEP wrap). CA stores the wrapped key in `KeyRecoveryTable`. KRA certs are published to AD `CN=KRAContainer,...`. If KRA private keys are lost, all archived keys are unrecoverable. A new framework should consider HSM-backed KRA + multi-KRA quorum.
- **Impact**: KRA key loss = unrecoverable user keys (a break-glass scenario).
- **Severity**: high
- **Constraints**: Must support multiple KRAs with quorum (N-of-M); must support KRA cert rotation.
- **KB references**: `05-pki-certs/03-autoenrollment.md`, `01-ad-core/02-ad-cs-cert-services.md`
- **Cross-platform**: cross-platform
- **Open questions**: HSM-backed KRA private keys? Multi-party KRA recovery (Shamir secret sharing)?

#### PC-061
- **Capability**: Cert Service
- **Title**: OCSP responder scaling; CA database corruption during outage
- **Description**: AD CS Online Responder (`OCSPResp.exe` under `svchost -k NetworkService`) signs `BasicOCSPResponse` blobs using an OCSP signing cert (`ID-PKIX-OCSP-NoCheck` extension). The responder reads the CA's CRL from `CRLTable`. CRL generation can fail (`0x80070020` file lock from IIS). During CA downtime, OCSP responses can become stale. A new framework should support clustered OCSP responders + CRL pre-publication.
- **Impact**: OCSP responder is a single point of failure during CA outage.
- **Severity**: high
- **Constraints**: Must support `ID-PKIX-OCSP-NoCheck`; must support pre-cached CRL; must support nonce.
- **KB references**: `05-pki-certs/04-ocsp-crl.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt CRLite (Mozilla) for massive-CRL compression? Multi-responder OCSP clustering?

#### PC-062
- **Capability**: Cert Service
- **Title**: CA database corruption recovery is "restore from backup, do not eseutil /p"
- **Description**: CA ESE database (`*.edb`) corruption is detected via `JET_errDbTimeTooNew`/`JET_errDbTimeCorrupted`. Recovery is "restore from backup" — running `eseutil /p` on a CA DB is explicitly discouraged (breaks cert serial continuity). A new framework should support online CA DB repair + point-in-time recovery.
- **Impact**: CA DB corruption is a multi-hour outage.
- **Severity**: medium
- **Constraints**: Must support WAL/transaction-log replay; must support point-in-time recovery.
- **KB references**: `01-ad-core/02-ad-cs-cert-services.md`, `05-pki-certs/01-ad-cs-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt FoundationDB / CockroachDB for CA storage? SQLite WAL mode?

#### PC-063
- **Capability**: Cert Service
- **Title**: Certificate revocation during CA outage (CRL/OCSP unreachable) breaks TLS
- **Description**: If CRL/OCSP is unreachable from a client, the client either fails-closed (TLS reject) or fails-open (skip revocation check). AD CS publishes CRLs to AD (`certificateRevocationList` attribute) and HTTP. During CA/AD outage, clients cannot fetch CRLs. A new framework should support cached CRL + OCSP stapling + backup CRL distribution points.
- **Impact**: TLS outages cascade during CA/AD outage.
- **Severity**: high
- **Constraints**: Must support CRL caching on client; must support multiple CDP URLs; must support OCSP stapling.
- **KB references**: `05-pki-certs/04-ocsp-crl.md`
- **Cross-platform**: cross-platform
- **Open questions**: CRLite for massive forests? Multi-CDP HTTP fallback?

#### PC-064
- **Capability**: Cert Service
- **Title**: NDES (SCEP for network devices) is fragile; IIS dependency
- **Description**: NDES (`SCEP.exe` service) provides SCEP enrollment for routers/switches/IoT. Requires IIS + ASP.NET + dynamic RPC. Configuration is multi-step and brittle. A new framework should provide a modern SCEP/EST/ACME endpoint without IIS dependency.
- **Impact**: NDES is the only AD-native SCEP; alternative is third-party (Gatekeeper, certNanny).
- **Severity**: medium
- **Constraints**: Must support SCEP (RFC 8894) for network devices; consider EST (RFC 7030) and ACME (RFC 8555).
- **KB references**: `01-ad-core/02-ad-cs-cert-services.md`, `05-pki-certs/03-autoenrollment.md`
- **Cross-platform**: cross-platform
- **Open questions**: Single enrollment endpoint that speaks SCEP + EST + ACME? Per-protocol adapters?

#### PC-065
- **Capability**: Cert Service
- **Title**: Cross-CA trust (cross-cert) via `CrossCertificatePair` is rarely used
- **Description**: Cross-certification (root A signs root B's cert) creates a bridge. AD stores cross-certs in `NTAuthCertificates` `CrossCertificatePair` attribute. Rarely deployed due to path-validation complexity. A new framework should support cross-cert for partner PKI but document the path-validation implications.
- **Impact**: Cross-org PKI trust is operationally complex.
- **Severity**: low
- **Constraints**: Must support `CrossCertificatePair` attribute; must support pathLenConstraint in BasicConstraints.
- **KB references**: `05-pki-certs/02-certificate-templates.md`, `01-ad-core/02-ad-cs-cert-services.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt trust-manager model (like browser CA bundles) instead of cross-cert? Per-application trust stores?

#### PC-066
- **Capability**: Cert Service
- **Title**: Two-tier vs three-tier CA topology is a greenfield design decision
- **Description**: Two-tier (offline root + online issuing) is most common. Three-tier adds a policy CA for high-assurance (NameConstraints, PolicyConstraints). Offline root has long CRL lifetime (6–12 months). A new framework should default to two-tier with HSM-protected root; document three-tier for high-assurance.
- **Impact**: CA topology choice affects security posture and operational complexity.
- **Severity**: medium
- **Constraints**: Must support offline root; must support HSM-protected CA keys (CNG/KSP).
- **KB references**: `05-pki-certs/01-ad-cs-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Default to two-tier with HSM root? Cloud-based root CA (AWS Private CA, GCP CA Service)?

#### PC-067
- **Capability**: Cert Service
- **Title**: `NTAuthCertificates` AD object is the canonical list of logon-authorized CAs
- **Description**: AD publishes the `NTAuthCertificates` object (`CN=NTAuthCertificates,CN=Public Key Services,...`) listing CAs allowed to issue logon certs. PKINIT KDC validates user certs against this list. `certutil -dspublish NTAuthCA` publishes. A new framework needs equivalent PKI-trust distribution or document the limitation.
- **Impact**: Smart-card logon depends on NTAuthCertificates.
- **Severity**: high
- **Constraints**: Must support NTAuthCertificates for AD interop; consider per-application trust stores.
- **KB references**: `05-pki-certs/01-ad-cs-architecture.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace NTAuthCertificates with per-tenant trust store? Web-of-trust model?

### Federation Gateway

#### PC-068
- **Capability**: Federation Gateway
- **Title**: AD FS is heavy (WID/SQL config DB, separate farm, WAP proxy)
- **Description**: AD FS uses `Microsoft.IdentityServer.ServiceHost.exe` with config in WID or SQL Server. WAP (`WAPService.exe`) is the perimeter proxy using MS-ADFSPIP. WID is primary-DC-style replication (max 5 nodes); SQL farm allows multi-primary. A new framework should adopt a lighter federation layer (Keycloak, Authentik, Ory) with AD integration, not the heavy AD FS topology.
- **Impact**: AD FS deployment is operationally complex; most orgs would prefer cloud IdP.
- **Severity**: high
- **Constraints**: Must support SAML 2.0, OIDC, OAuth2; must support AD as claims provider.
- **KB references**: `01-ad-core/03-ad-fs-federation.md`, `06-federation-sso/01-adfs-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt Keycloak as the federation layer? Build native? Cloud-first (Entra ID)?

#### PC-069
- **Capability**: Federation Gateway
- **Title**: ADFS claims rule language (CRL) is proprietary DSL; migration to standard policy is painful
- **Description**: CRL syntax: `c:[Type == "...", Value == "..."] => issue(Type = "...", Value = c.Value);`. 5 phases (Acceptance Transform, Issuance Authorization, Issuance Transform, Delegation, Token Serialization). Attribute stores (AD, LDAP, SQL, custom .NET). Keycloak has "mappers" (no DSL); Authentik has expression policies (Python). A new framework should adopt a standard policy language (Rego/OPA, Cedar, XACML).
- **Impact**: CRL rules do not port to other IdPs; migration requires manual translation.
- **Severity**: high
- **Constraints**: Must support AD-as-attribute-store; must support custom attribute stores.
- **KB references**: `06-federation-sso/03-claims-rules.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt Rego (OPA) as the claims-policy language? Cedar (AWS)? Per-IdP plugins?

#### PC-070
- **Capability**: Federation Gateway
- **Title**: Token-signing cert rollover requires RP metadata refresh; 15-day overlap window
- **Description**: AD FS auto-rolls token-signing cert (Server 2012 R2+): new cert published alongside old for 5–15 days, then promoted to primary. RPs that cache metadata fail until they refresh. AD FS publishes both certs in federation metadata. A new framework should automate cert rollover + RP notification.
- **Impact**: Cert rollover causes intermittent RP failures.
- **Severity**: medium
- **Constraints**: Must publish both old + new certs in metadata; must support `validUntil` for cert transition.
- **KB references**: `06-federation-sso/01-adfs-architecture.md`, `06-federation-sso/02-saml-ws-fed.md`
- **Cross-platform**: cross-platform
- **Open questions**: Auto-notify RPs via webhook on cert rollover? JWKS rotation API (RFC 8414)?

#### PC-071
- **Capability**: Federation Gateway
- **Title**: WS-Federation and WS-Trust are legacy; OIDC is the modern path
- **Description**: AD FS supports WS-Federation (passive) + WS-Trust (active) + SAML 2.0 + OIDC (2016+). WS-* is SOAP-based, declining. Modern clients (SPAs, mobile) use OIDC. A new framework should support OIDC natively, SAML 2.0 for legacy RPs, and deprecate WS-* (or provide a compat shim).
- **Impact**: WS-* migration is a multi-year project for enterprises.
- **Severity**: medium
- **Constraints**: Must support OIDC (RFC 6749, 8252 PKCE, 7636); must support SAML 2.0 (OASIS).
- **KB references**: `06-federation-sso/04-oidc-oauth.md`, `06-federation-sso/02-saml-ws-fed.md`
- **Cross-platform**: cross-platform
- **Open questions**: Drop WS-* entirely? Provide a WS-Trust-to-OIDC bridge?

#### PC-072
- **Capability**: Federation Gateway
- **Title**: SAML replay detection window (60 min) and clock skew (5 min) need tuning
- **Description**: AD FS SAML replay detection caches assertion IDs for 60 min. Clock skew tolerance is 5 min either side. `IssueInstant` outside `NotBefore`/`NotOnOrAfter` window → `MSIS7042`. A new framework should make these configurable and document the security/availability tradeoff.
- **Impact**: SAML auth failures on clock-skewed SPs.
- **Severity**: low
- **Constraints**: Must support per-RP skew override (`NotBeforeSkew`).
- **KB references**: `06-federation-sso/02-saml-ws-fed.md`
- **Cross-platform**: cross-platform
- **Open questions**: Auto-sync clocks via NTP before SAML? Per-RP skew policy?

#### PC-073
- **Capability**: Federation Gateway
- **Title**: AD FS Web Application Proxy (WAP) is Windows-only; modern alternatives exist
- **Description**: WAP (`WAPService.exe`) is the perimeter reverse proxy that pre-auths via AD FS using MS-ADFSPIP. Modern alternatives: nginx + oauth2-proxy, Traefik + forward-auth, Caddy + auth portal. A new framework should adopt a cloud-native reverse proxy with OIDC pre-auth.
- **Impact**: WAP is a Windows-only dependency; alternatives are lighter.
- **Severity**: medium
- **Constraints**: Must support OIDC pre-auth; must support header injection for backend.
- **KB references**: `01-ad-core/03-ad-fs-federation.md`, `06-federation-sso/01-adfs-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt oauth2-proxy as the WAP replacement? Envoy + ext-authz?

#### PC-074
- **Capability**: Federation Gateway
- **Title**: ADFS farm topology (primary + secondaries in WID mode) is operationally fragile
- **Description**: WID-mode AD FS has one primary node (writes) + N secondaries (read-only, sync every 5 min). All admin cmdlets must hit the primary. If primary dies, manual promotion required. SQL-mode adds HA at the SQL tier. A new framework should use consensus-based config (Raft) for the federation layer.
- **Impact**: WID primary failure is a manual failover.
- **Severity**: medium
- **Constraints**: Must support multi-primary config; must support config DB HA.
- **KB references**: `06-federation-sso/01-adfs-architecture.md`
- **Cross-platform**: cross-platform
- **Open questions**: etcd-backed config? Raft among federation nodes?

#### PC-075
- **Capability**: Federation Gateway
- **Title**: ADFS as OAuth2/OIDC provider has quirks (resource= parameter, Application Groups)
- **Description**: AD FS 2016+ OIDC has quirks: `resource=` parameter (not standard OAuth2), Application Groups (Server 2016+), `allatclaims` scope for full AD claim pass-through, refresh token rotation (Server 2019+ opt-in). Standard OIDC clients (oauth2-proxy, AppAuth) need adaptation. A new framework should be RFC 6749/8252 strict and document AD FS quirks for migration.
- **Impact**: AD FS OIDC is not strictly RFC-conformant; clients need adaptation.
- **Severity**: medium
- **Constraints**: Must support RFC 6749, 8252 (PKCE), 7636; must support OIDC Discovery (RFC 8414).
- **KB references**: `06-federation-sso/04-oidc-oauth.md`
- **Cross-platform**: cross-platform
- **Open questions**: Provide `resource=` compat mode for AD FS migration? Strict OIDC by default?

#### PC-076
- **Capability**: Federation Gateway
- **Title**: External OIDC IdP federation (ADFS-as-RP) needs explicit CPT configuration
- **Description**: ADFS 2019+ can federate to external OIDC IdPs (Entra ID, Okta). Requires `Add-AdfsClaimsProviderTrust -OIDCUrl -ClientID -ClientSecret -MetadataUrl`. ADFS becomes the RP; user picks CPT at the home realm discovery page. A new framework should support IdP brokering natively (Keycloak-style).
- **Impact**: Multi-IdP federation is manual per-IdP configuration.
- **Severity**: medium
- **Constraints**: Must support OIDC + SAML IdP brokering; must support home realm discovery.
- **KB references**: `06-federation-sso/04-oidc-oauth.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt Keycloak-style identity brokering? Per-tenant IdP routing?

#### PC-077
- **Capability**: Federation Gateway
- **Title**: AD RMS (DRM/IRM) has no open-source server; AIP is the migration path
- **Description**: AD RMS (`rmssvc.exe`) issues use licenses for protected content. SLC private key compromise = all issued ILs compromised. Microsoft's Azure Information Protection (AIP) is the cloud migration target. MIP SDK exists for Linux/macOS clients. No open-source RMS server. A new framework should document whether IRM is in scope (likely no) and recommend AIP or alternative.
- **Impact**: IRM-dependent orgs (legal, finance) have no open-source alternative.
- **Severity**: low
- **Constraints**: If in scope, must support use-license issuance + content key encryption.
- **KB references**: `01-ad-core/05-ad-rms-rights.md`
- **Cross-platform**: cross-platform
- **Open questions**: Out of scope (recommend AIP)? Implement minimal RMS-compatible server?

### File Gateway

#### PC-078
- **Capability**: File Gateway
- **Title**: SMB 3.1.1 with pre-auth integrity + AES-GCM is required for modern Windows interop
- **Description**: SMB 3.1.1 (Server 2016+) adds SHA-512 pre-auth integrity (binds Negotiate to session key derivation) + AES-GCM encryption + AES-GMAC signing. Samba added 3.1.1 in 4.3 (2015); macOS SMBX gained 3.1.1 client in macOS 11. A new framework's SMB server must support 3.1.1 dialect or fail interop with Win10+ clients.
- **Impact**: Win10 1709+ clients refuse SMB 2.x to non-domain-joined servers in some configs.
- **Severity**: blocker
- **Constraints**: Must support SMB 2.0.2 → 3.1.1 dialect range; must support AES-128/256-GCM.
- **KB references**: `02-protocols/03-smb-cifs-protocol.md`, `07-file-print/01-smb-shares-internals.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt Samba's smbd (GPL)? Write fresh SMB server? Reuse macOS SMBX kernel ext?

#### PC-079
- **Capability**: File Gateway
- **Title**: SMB1 must be dropped (security liability); migration is automatic on modern Windows
- **Description**: SMB1 (`NT LM 0.12`) is deprecated, disabled by default Server 2019+ / Win10 1709+. EternalBlue (MS17-010) was the SMB1 vulnerability. Samba 4.5+ disables SMB1 by default. A new framework should drop SMB1 entirely.
- **Impact**: SMB1 is a security liability.
- **Severity**: blocker
- **Constraints**: Must not negotiate SMB1; must document legacy NAS appliances as out of scope.
- **KB references**: `02-protocols/03-smb-cifs-protocol.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Hard cut? Provide SMB1-compat shim for legacy NAS?

#### PC-080
- **Capability**: File Gateway
- **Title**: DFS-N (namespace) + DFS-R (replication) are Windows-only; no Linux equivalent
- **Description**: DFS-N (`dfssvc.exe`) resolves `\\domain\share\path` via pKT cache + AD-stored `msDFS-Link` objects. DFS-R (`dfsr.exe`) multi-master replicates folder contents using RDC (rsync-like) + USN journal. Samba can act as DFS-N leaf target but not host namespaces. No DFS-R equivalent on Linux (rsync/syncthing are point-to-point). A new framework must decide: replicate DFS-N/R for compat or externalize (Kubernetes-style).
- **Impact**: DFS-N is widely used for share abstraction; without it, hard-coded UNC paths are required.
- **Severity**: high
- **Constraints**: Must support `\\domain\share\path` UNC resolution for client compat; consider externalizing replication.
- **KB references**: `07-file-print/02-dfs-n-dfs-r.md`
- **Cross-platform**: Windows, Linux
- **Open questions**: Adopt Kubernetes-style service discovery (DNS SRV) for share location? Replicate via Git/syncthing?

#### PC-081
- **Capability**: File Gateway
- **Title**: Continuously Available (CA) shares require cluster + persistent handles
- **Description**: CA shares (`ContinuouslyAvailable=1`) require CSV-backed SOFS cluster + persistent handles (`DH2Q`/`DH2C` create contexts). Transparent failover: client sees brief TCP retransmit during failover. Samba's CTDB cluster is limited (no transparent failover). A new framework should support CA via Kubernetes-style stateful workloads (CSI + PVC + leader election).
- **Impact**: CA is required for production file-server HA.
- **Severity**: high
- **Constraints**: Must support persistent handles; must support cluster quorum.
- **KB references**: `07-file-print/01-smb-shares-internals.md`, `02-protocols/03-smb-cifs-protocol.md`
- **Cross-platform**: cross-platform
- **Open questions**: CSI + SMB-server-in-container? CTDB-style clustered Samba?

#### PC-082
- **Capability**: File Gateway
- **Title**: Access-Based Enumeration (ABE) post-filters directory listings; CPU cost
- **Description**: ABE (`AccessBasedEnumeration=1` per share) filters `FILE_DIRECTORY_INFORMATION` responses to entries the caller has `FILE_ListDirectory` on. `srv2.sys` post-filters. CPU cost on large directories. Samba supports via `hide unreadable = yes`. A new framework should preserve ABE and consider indexing for performance.
- **Impact**: ABE is a usability feature; without it, users see files they cannot open.
- **Severity**: medium
- **Constraints**: Must support per-share ABE toggle; must support NTFS ACL evaluation.
- **KB references**: `07-file-print/01-smb-shares-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Pre-computed ABE index? Per-user view materialization?

#### PC-083
- **Capability**: File Gateway
- **Title**: PrintNightmare (CVE-2021-34527) exposed MS-RPRN driver install as SYSTEM
- **Description**: `RpcAddPrinterDriverEx` (opnum 109 on MS-RPRN) allowed user-supplied driver DLL to be loaded by spoolsv.exe (SYSTEM). Mitigations: `RestrictDriverInstallationToAdministrators=1`, `RpcPacketPrivacy` enforcement, Type 4 drivers (no third-party code in spooler). A new framework should not implement MS-RPRN driver install; use Type 4 (IPP Everywhere) or CUPS-style filters.
- **Impact**: PrintNightmare-class vulns are a systemic risk.
- **Severity**: blocker
- **Constraints**: Must not load third-party code into print spooler; must enforce PKT_PRIVACY RPC.
- **KB references**: `07-file-print/03-print-services.md`
- **Cross-platform**: Windows, cross-platform
- **Open questions**: Drop MS-RPRN entirely? Use IPP Everywhere (driverless) for all clients?

#### PC-084
- **Capability**: File Gateway
- **Title**: Offline Files (CSC) is Windows-only; no macOS/Linux equivalent
- **Description**: CSC (`cscsvc.dll` + `csc.sys` mini-redirector) caches SMB shares locally for offline access. Encrypted cache at `%SystemRoot%\CSC\v2.0.6\`. Sync at logon/logoff/scheduled. Conflict resolution (server-wins/client-wins/ask). No macOS/Linux equivalent — SSSD provides offline Kerberos ticket cache but not file cache. A new framework should consider whether offline file access is in scope (likely yes for mobile users) and what mechanism (Syncthing, Nextcloud client, rsync).
- **Impact**: Mobile users on Windows depend on CSC; macOS/Linux users have no equivalent.
- **Severity**: medium
- **Constraints**: If in scope, must support conflict resolution + transparent cache.
- **KB references**: `07-file-print/04-offline-files.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Out of scope (recommend Nextcloud client)? Implement minimal CSC-compatible cache?

### Client SDK

#### PC-085
- **Capability**: Client SDK
- **Title**: No universal "AD client SDK"; Windows uses SSPI+Wldap32, macOS uses OpenDirectory, Linux uses SSSD/Winbind/PAM/NSS
- **Description**: Windows apps use SSPI (secur32.dll) for auth + Wldap32 for LDAP + Netapi32 for joins. macOS apps use OpenDirectory framework + Authorization framework. Linux apps use SSSD/Winbind (NSS+PAM) + OpenLDAP client libs. No unified SDK. A new framework should provide a unified cross-platform SDK (Rust/Go/Python) that abstracts auth + directory + policy.
- **Impact**: Cross-platform AD client development requires per-OS expertise.
- **Severity**: blocker
- **Constraints**: Must support Windows, macOS, Linux; must expose auth, directory, policy, cert APIs.
- **KB references**: `10-comparison-matrices/04-auth-flow-comparison.md`, `09-linux-equivalents/10-pam-nss-stack.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt gRPC-based SDK with platform-native auth adapters? Per-language bindings (Rust core)?

#### PC-086
- **Capability**: Client SDK
- **Title**: macOS PSSO Extension (macOS 13+) replaces Enterprise Connect + NoMAD but is Apple-only
- **Description**: PSSO (`Authentication_SSO.appex`) runs in `securityd`'s `authentication-extension` XPC child. Uses SEP-bound ECDSA P-256 key (Hardware_Bound) or password-derived key. MDM payload `com.apple.configuration-ext.platform-sso` configures. Sub-payload `com.apple.KerberosSSO` for Kerberos. Replaces Enterprise Connect (deprecated) + NoMAD (EOL, Jamf-acquired). A new framework should adopt PSSO for macOS client integration.
- **Impact**: macOS client auth requires PSSO Extension for passwordless + Kerberos.
- **Severity**: high
- **Constraints**: Must support PSSO Extension via MDM profile; must support SEP-bound keys.
- **KB references**: `08-macos-equivalents/04-platform-sso-extension.md`, `08-macos-equivalents/05-kerberos-sso-extension.md`
- **Cross-platform**: macOS
- **Open questions**: Provide MDM profile templates for PSSO + Kerberos sub-payload? Auto-config via framework client SDK?

#### PC-087
- **Capability**: Client SDK
- **Title**: macOS Jamf Connect + ROPG password sync is fragile during IdP password change
- **Description**: Jamf Connect uses OIDC ROPG (Resource Owner Password Grant) to validate the local password against the IdP. On IdP password change, the sync agent detects divergence (ROPG fails) and prompts user. FileVault unlock uses the OLD password until sync completes. A new framework should adopt PSSO Hardware_Bound mode (no password sync needed) and document the migration path from Jamf Connect.
- **Impact**: Password sync failures leave users locked out of FileVault.
- **Severity**: medium
- **Constraints**: Must support PSSO Hardware_Bound; must support password-derived fallback for Intel Macs.
- **KB references**: `08-macos-equivalents/03-jamf-connect-pro.md`, `08-macos-equivalents/06-enterprise-connect-nomad.md`
- **Cross-platform**: macOS
- **Open questions**: Auto-migrate Jamf Connect deployments to PSSO? Provide sync agent for non-MDM Macs?

#### PC-088
- **Capability**: Client SDK
- **Title**: SSSD on Linux has GPO access control + ID mapping but no full GPO CSE support
- **Description**: SSSD provides: `ad` provider (LDAP+Kerberos), `ad_gpo_access_control` (5 logon rights only), `ldap_id_mapping` (algorithmic SID→UID), `cache_credentials` (offline auth), `dyndns_update` (GSS-TSIG DDNS). Missing: full GPO CSE support (Registry.pol, Preferences, Scripts), DFS-N client (uses cifs.ko instead), ABE on SMB mounts. A new framework should provide a unified Linux client that fills these gaps.
- **Impact**: Linux client integration is partial; admins compensate with Ansible/Puppet.
- **Severity**: high
- **Constraints**: Must preserve SSSD's strengths (caching, GPO access, ID mapping); add full GPO + DFS-N + ABE.
- **KB references**: `09-linux-equivalents/01-sssd-ad-provider.md`, `09-linux-equivalents/03-sssd-gpo-access.md`
- **Cross-platform**: Linux
- **Open questions**: Extend SSSD or write a new client? Adopt FreeIPA client as the base?

#### PC-089
- **Capability**: Client SDK
- **Title**: ID mapping (SID ↔ POSIX UID/GID) is non-deterministic across hosts without coordination
- **Description**: SSSD `ldap_id_mapping=true` uses SHA-1 hash of domain SID → slice → UID = `range_min + slice*range_size + RID`. Collisions possible (10K slices, 2B range). Samba `idmap_rid`/`idmap_autorid` similar but different algorithm. PBIS uses `RangeMin`/`RangeMax`/`RangeSize`. Two hosts with different algorithms = same user has different UIDs = file ownership breaks. A new framework should standardize on UUID-based identity or document the ID-mapping contract.
- **Impact**: Cross-host file ownership breaks if ID mapping differs.
- **Severity**: blocker
- **Constraints**: Must produce stable UIDs across hosts; must support RFC 2307 (uidNumber in AD) as alternative.
- **KB references**: `09-linux-equivalents/02-sssd-id-mapping.md`, `09-linux-equivalents/04-winbind-internals.md`
- **Cross-platform**: Linux, macOS
- **Open questions**: Drop POSIX UIDs entirely (use UUIDs everywhere)? Standardize on one algorithm (SSSD slice)?

#### PC-090
- **Capability**: Client SDK
- **Title**: Heimdal vs MIT Kerberos on Linux/macOS have subtle incompatibilities
- **Description**: Samba bundles Heimdal; SSSD uses MIT krb5; macOS ships Heimdal fork (hasn't tracked upstream since ~2014). Apple's `libMITKerberosShim.dylib` redirects MIT-style GSSAPI calls to Heimdal. PAC parsing in Heimdal `lib/krb5/pac.c` vs MIT `lib/krb5/krb/pac.c` have minor ordering differences. A new framework should standardize on MIT krb5 (more widely deployed, actively maintained) and document Heimdal compat.
- **Impact**: Mixed-kerberos environments hit subtle interop bugs.
- **Severity**: medium
- **Constraints**: Must support MIT krb5 as primary; Heimdal for Samba AD-DC compat.
- **KB references**: `02-protocols/01-kerberos-internals.md`, `08-macos-equivalents/07-third-party-agents-mac.md`
- **Cross-platform**: Linux, macOS
- **Open questions**: Standardize on MIT krb5 everywhere? Contribute macOS Heimdal fork upstream?

#### PC-091
- **Capability**: Client SDK
- **Title**: Domain join (`realm join`/`adcli`/`net ads join`/`dsconfigad`) is fragmented
- **Description**: Linux: `realm join` (realmd D-Bus service) → `adcli join` or `net ads join` or `ipa-client-install`. macOS: `dsconfigad -a <name> -domain <domain> -u <user>`. Windows: `Add-Computer`. Each has different OU placement, OS-info reporting, keytab generation, SPN registration. A new framework should provide a unified join protocol (likely OAuth2-style device enrollment).
- **Impact**: Join procedures vary by OS; automation is per-OS.
- **Severity**: medium
- **Constraints**: Must support computer-object creation, machine-account password, keytab write, SPN registration.
- **KB references**: `09-linux-equivalents/06-realmd-join-flow.md`, `09-linux-equivalents/05-samba-tool-net-ads.md`, `08-macos-equivalents/02-dscl-dsconfigad.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt modern device enrollment (Windows Autopilot, Apple DEP, Linux cloud-init style)? Per-OS adapters?

#### PC-092
- **Capability**: Client SDK
- **Title**: PAM stack varies by distro (Debian/Ubuntu vs RHEL/Fedora vs SUSE)
- **Description**: Debian uses `pam-auth-update` (writes `/etc/pam.d/common-*`). RHEL/Fedora uses `authselect` (writes `system-auth`, `password-auth`). SUSE uses `pam-config` (writes `common-*-pc`). Each has different module ordering, control values, and feature flags. A new framework should provide a unified PAM profile generator that targets all three.
- **Impact**: PAM stack management is distro-specific.
- **Severity**: medium
- **Constraints**: Must support `pam_sss.so` (or framework equivalent); must support `pam_mkhomedir.so` / `pam_oddjob_mkhomedir.so`.
- **KB references**: `09-linux-equivalents/10-pam-nss-stack.md`
- **Cross-platform**: Linux
- **Open questions**: Provide framework-native PAM module + profile generator? Adopt `authselect` as the standard?

#### PC-093
- **Capability**: Client SDK
- **Title**: Kerberos ticket cache type varies (FILE:, KEYRING:, KCM:, API: on macOS)
- **Description**: Linux SSSD defaults to `KEYRING:persistent:<uid>`. macOS PSSO defaults to `API:Initialdefaultcache` (keychain-backed). KCM (`/run/.krb5_cc_uid_*` over D-Bus) is the systemd-style daemon-backed cache. FILE: cache at `/tmp/krb5cc_<uid>` is the legacy default. Each has different persistence, security, and renewal semantics. A new framework should standardize on KCM (cross-distro) + API: (macOS).
- **Impact**: Cache-type mismatches cause silent auth failures.
- **Severity**: medium
- **Constraints**: Must support KEYRING, KCM, FILE, API:; must support auto-renewal.
- **KB references**: `08-macos-equivalents/05-kerberos-sso-extension.md`, `09-linux-equivalents/01-sssd-ad-provider.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt KCM as the Linux standard + API: on macOS? Provide a unified cache abstraction?

### Cross-Platform Parity

#### PC-094
- **Capability**: Cross-Platform Parity
- **Title**: macOS has no native NTLM support; legacy apps fail
- **Description**: macOS SMBX client does not implement NTLMSSP. Samba (Homebrew) or third-party agents (Centrify) provide NTLM. Apps that hard-require NTLM (legacy SQL drivers, old IIS) fail on macOS. A new framework should provide NTLM as opt-in via a cross-platform SSP (likely Samba's `libnss_winbind` or a fresh implementation).
- **Impact**: Legacy app compat on macOS is poor.
- **Severity**: high
- **Constraints**: Must support NTLMv2 (NTLMv1 disabled); channel binding for relay defense.
- **KB references**: `02-protocols/04-ntlm-internals.md`, `10-comparison-matrices/01-feature-os-matrix.md`
- **Cross-platform**: macOS, Linux
- **Open questions**: Provide NTLM via Samba winbind on macOS? Document legacy apps as out of scope?

#### PC-095
- **Capability**: Cross-Platform Parity
- **Title**: macOS Configuration Profiles vs Windows GPO vs Linux SSSD-conf have no unified authoring
- **Description**: Windows: ADMX + Registry.pol + GptTmpl.inf + Preferences XML. macOS: Configuration Profile (`.mobileconfig`) with per-payload schema (~80 payload types). Linux: `sssd.conf` + `krb5.conf` + `smb.conf` + `nsswitch.conf` + PAM files + Ansible. No unified policy authoring. A new framework should adopt a single declarative policy format that compiles to platform-native.
- **Impact**: Policy authoring is per-OS; cross-platform policies require manual translation.
- **Severity**: blocker
- **Constraints**: Must compile to ADMX + Registry.pol (Windows), Configuration Profile (macOS), sssd.conf + Ansible (Linux).
- **KB references**: `08-macos-equivalents/09-mac-mdm-gpo-equivalents.md`, `10-comparison-matrices/05-gpo-equivalents-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: OPA Rego as the unified format? JSON Schema + per-platform executors? Per-policy-type DSL?

#### PC-096
- **Capability**: Cross-Platform Parity
- **Title**: macOS DDM (Declarative Device Management) is the future but not yet full-coverage
- **Description**: macOS 13+ DDM is stateful, declarative, JSON-over-MDM. As of macOS 14 covers: SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets. Configuration Profiles remain for the long tail. DDM migration is gradual. A new framework should adopt DDM where available + Configuration Profile for the rest.
- **Impact**: DDM is the future; Configuration Profiles are legacy.
- **Severity**: low
- **Constraints**: Must support DDM declarations; must support Configuration Profile fallback.
- **KB references**: `08-macos-equivalents/09-mac-mdm-gpo-equivalents.md`
- **Cross-platform**: macOS
- **Open questions**: Adopt DDM-first authoring? Auto-fallback to Configuration Profile?

#### PC-097
- **Capability**: Cross-Platform Parity
- **Title**: macOS FileVault recovery key escrow goes to Apple or MDM, not AD
- **Description**: Windows BitLocker recovery password backs up to AD (`CN=<GUID>,CN=<computer>,CN=BitLocker Recovery,...`). macOS FileVault recovery key escrows to Apple or MDM (Jamf, Intune). Linux LUKS has no AD recovery; Clevis/Tang (NBDE) is the alternative. A new framework should provide a unified disk-encryption recovery escrow.
- **Impact**: Cross-platform disk-encryption recovery is fragmented.
- **Severity**: medium
- **Constraints**: Must support per-computer recovery key in directory; must support rotation.
- **KB references**: `10-comparison-matrices/01-feature-os-matrix.md`, `10-comparison-matrices/05-gpo-equivalents-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Per-computer recovery key in framework directory? NBDE (Clevis/Tang) for all platforms?

#### PC-098
- **Capability**: Cross-Platform Parity
- **Title**: LAPS (local admin password rotation) has no macOS/Linux native equivalent
- **Description**: Windows LAPS (legacy + new Windows LAPS in Server 2022+) stores local admin password hash in `ms-MCS-AdmPwd`/`msLAPS-Password` on the computer object. macOS: Jamf rotates local admin via policy + escrows to Jamf server. Linux: Ansible custom role. A new framework should provide a unified LAPS-equivalent across platforms.
- **Impact**: Local admin password rotation is per-OS.
- **Severity**: medium
- **Constraints**: Must support per-host password rotation; must support directory escrow + ACL-gated retrieval.
- **KB references**: `10-comparison-matrices/05-gpo-equivalents-matrix.md`, `10-comparison-matrices/01-feature-os-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Per-host password in framework directory with ACL-gated read? Adopt Windows LAPS schema for compat?

#### PC-099
- **Capability**: Cross-Platform Parity
- **Title**: SSSD/Winbind/PBIS are alternative Linux stacks; migration between them is painful
- **Description**: SSSD (modern, Red Hat), Winbind (Samba, file-server-focused), PBIS (BeyondTrust, deprecated 2023) are three Linux AD-integration stacks. Each has different ID mapping, GPO support, PAM/NSS modules. Migration requires UID remap planning. A new framework should standardize on one stack (likely SSSD) and document migration from the others.
- **Impact**: Mixed-stack deployments cause UID/group drift.
- **Severity**: medium
- **Constraints**: Must support SSSD as primary; provide migration tooling from Winbind/PBIS.
- **KB references**: `09-linux-equivalents/01-sssd-ad-provider.md`, `09-linux-equivalents/04-winbind-internals.md`, `09-linux-equivalents/07-pbis-powerbroker.md`
- **Cross-platform**: Linux
- **Open questions**: Hard-deprecate Winbind for NSS/PAM (keep for SMB only)? Auto-migrate PBIS to SSSD?

#### PC-100
- **Capability**: Cross-Platform Parity
- **Title**: macOS OpenDirectory AD plug-in has gaps (GPO, ABE, full DFS-N)
- **Description**: Apple's `DSP.ActiveDirectory.bundle` plug-in implements AD binding + LDAP + Kerberos + CLDAP. Missing: GPO consumption (no native engine), ABE on SMB mounts, full DFS-N referral support. Third-party agents (Centrify, Jamf Connect) fill some gaps. A new framework should adopt PSSO + Jamf Connect + MDM as the macOS stack and document gaps.
- **Impact**: macOS AD integration is partial without third-party tooling.
- **Severity**: medium
- **Constraints**: Must support PSSO Extension (Kerberos), Jamf Connect (OIDC), MDM (Configuration Profiles).
- **KB references**: `08-macos-equivalents/01-opendirectory-internals.md`, `08-macos-equivalents/02-dscl-dsconfigad.md`, `08-macos-equivalents/07-third-party-agents-mac.md`
- **Cross-platform**: macOS
- **Open questions**: Provide first-party macOS client SDK that fills GPO/DFS-N/ABE gaps? Document third-party as required?

#### PC-101
- **Capability**: Cross-Platform Parity
- **Title**: FreeIPA is a separate Linux identity platform with AD cross-forest trust
- **Description**: FreeIPA bundles 389-DS + MIT krb5 + BIND + Dogtag PKI + certmonger + SSSD. Cross-forest trust to AD via `ipa trust-add` (uses Samba's `libads` for LSA trust creation). `ipa-extdom-plugin` proxies AD SID lookups. HBAC replaces GPO access control. Sudo rules in IPA LDAP. A new framework could either (a) adopt FreeIPA as the Linux identity layer with AD trust, or (b) provide a unified identity platform that subsumes both AD and FreeIPA roles.
- **Impact**: FreeIPA is the de facto Linux identity platform; integration with AD is via trust.
- **Severity**: medium
- **Constraints**: Must support cross-forest trust if FreeIPA is in scope; consider HBAC as the unified access model.
- **KB references**: `09-linux-equivalents/08-freeipa-trust.md`
- **Cross-platform**: Linux, cross-platform
- **Open questions**: Adopt FreeIPA as the Linux tier? Build native IPA-equivalent in the framework?

#### PC-102
- **Capability**: Cross-Platform Parity
- **Title**: RODC (Read-Only DC) has no Linux/macOS equivalent
- **Description**: RODC is a read-only DC for branch offices. Holds no password hashes by default (`msDS-RevealedUsers` controls). SSSD has RODC-aware mode (`ad_site` pinning, partial-KDC). No RODC server implementation on Linux/macOS. A new framework should consider whether RODC is in scope (branch offices, DMZ) and design accordingly.
- **Impact**: Branch-office deployments without RODC risk full-DC compromise.
- **Severity**: medium
- **Constraints**: If in scope, must support read-only DIT + per-DC password replication policy.
- **KB references**: `01-ad-core/01-ad-ds-internals.md`, `10-comparison-matrices/01-feature-os-matrix.md`
- **Cross-platform**: cross-platform
- **Open questions**: Kubernetes-style read-replica with no secrets? Edge-deployed DC with HSM-bound subset?

#### PC-103
- **Capability**: Cross-Platform Parity
- **Title**: OpenLDAP + MIT Kerberos (roll-your-own) is high-effort, low-feature
- **Description**: Manual stack of OpenLDAP `slapd` + MIT krb5 `krb5kdc`/`kadmind` + BIND + `nslcd` + `pam_krb5`/`pam_ldap`. No domain-join framework. No GPO. No DFS. Limited multi-master (MirrorMode or N-Way). No forest trusts (cross-realm only). FreeIPA bundles the same components into a managed product. A new framework should explicitly document this as out of scope (recommend FreeIPA or framework-native).
- **Impact**: Roll-your-own is a maintenance burden; FreeIPA is the modern replacement.
- **Severity**: low
- **Constraints**: N/A — out of scope.
- **KB references**: `09-linux-equivalents/09-openldap-mit-kerberos.md`
- **Cross-platform**: Linux
- **Open questions**: Document as out of scope? Provide migration tooling to FreeIPA?

#### PC-104
- **Capability**: Cross-Platform Parity
- **Title**: Centrify / PBIS / AdmitMac / DAVE are legacy third-party macOS agents
- **Description**: Centrify DirectControl (now Delinea/CyberArk) ships its own Kerberos fork + `adclient` daemon + `dzdo` (sudo replacement). PBIS (BeyondTrust, deprecated macOS 2022) ports the Linux stack. Thursby AdmitMac/DAVE provide alternative SMB/Kerberos. All are being superseded by Apple PSSO + Jamf Connect. A new framework should not depend on these; provide first-party macOS support via PSSO.
- **Impact**: Legacy agents are EOL or maintenance-only.
- **Severity**: low
- **Constraints**: N/A — out of scope.
- **KB references**: `08-macos-equivalents/07-third-party-agents-mac.md`
- **Cross-platform**: macOS
- **Open questions**: Document migration paths from Centrify/PBIS to PSSO? Provide import tooling for dzdo rules → sudoers?

#### PC-105
- **Capability**: Cross-Platform Parity
- **Title**: Heimdal Kerberos on macOS is a fork tracking upstream ~2014
- **Description**: Apple ships Heimdal Kerberos in `/usr/lib/libkerberos.dylib`. Fork has not tracked upstream since ~2014. Missing: PAC_FULL_CHECKSUM (Server 2016+), claims-based Kerberos, compound identity. Apple recommends PSSO Extension for new deployments. A new framework's macOS client should use PSSO + system Heimdal; document the gaps.
- **Impact**: macOS Kerberos is missing modern PAC features.
- **Severity**: medium
- **Constraints**: Must support PAC_FULL_CHECKSUM, PAC_REQUESTER via PSSO Extension.
- **KB references**: `08-macos-equivalents/05-kerberos-sso-extension.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: macOS
- **Open questions**: Contribute Apple Heimdal fork upstream? Document PSSO as the only modern path?

### Operations

#### PC-106
- **Capability**: Operations
- **Title**: No native Prometheus exporter / OpenTelemetry for AD
- **Description**: AD emits Windows Event Log (4768/4769/5136/etc.) + perfmon counters. No native Prometheus exporter. No OpenTelemetry traces. SIEM integration requires Windows Event Forwarding (WEF) or third-party agents (WinLogBeat, Splunk TA). A new framework should expose Prometheus metrics + OTel traces natively.
- **Impact**: AD observability is Windows-event-log-only; modern SIEM requires adapters.
- **Severity**: high
- **Constraints**: Must emit Prometheus metrics (auth rate, replication lag, KDC errors); must emit OTel traces (per-request).
- **KB references**: `02-protocols/01-kerberos-internals.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Adopt OTel semantic conventions for AD/Kerberos? Per-DC metrics or per-realm aggregation?

#### PC-107
- **Capability**: Operations
- **Title**: Schema upgrades are irreversible; `objectVersion` bump is one-way
- **Description**: AD schema version (`objectVersion` on Schema NC head) bumps with each Server release (13=2000, 30=2003, 88=2022). `adprep /forestprep` runs schema extensions. Once extended, schema cannot be rolled back (attributes/classes persist as defunct). A new framework should support schema versioning with rollback (likely via migration to typed schema).
- **Impact**: Schema upgrades are high-risk; orgs delay them.
- **Severity**: high
- **Constraints**: Must support schema migration; must support defunct-attribute cleanup.
- **KB references**: `03-directory-schema/01-schema-attributes.md`
- **Cross-platform**: Windows
- **Open questions**: Schema-as-code (Git-backed)? Typed-schema with versioned migrations?

#### PC-108
- **Capability**: Operations
- **Title**: Multi-region AD deployment has replication latency; PDC urgent replication
- **Description**: Inter-site replication is scheduled (default 15–180 sec) and compressed. PDC emulator receives urgent replication for password changes (within 15 sec). Cross-region latency can cause stale-password logon failures (DC falls back to PDC). A new framework should support multi-region with explicit PDC pinning for password changes + global cache.
- **Impact**: Cross-region password-change propagation is bounded by PDC urgent replication.
- **Severity**: high
- **Constraints**: Must support per-region DC pools; must support urgent replication for password changes.
- **KB references**: `00-overview/04-fsmo-roles.md`, `03-directory-schema/05-replication-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-region PDC? Active-active multi-region with conflict-free replicated data types?

#### PC-109
- **Capability**: Operations
- **Title**: AD has no containerization; no Kubernetes-native deployment
- **Description**: AD DCs are Windows Server VMs. Dcpromo is deprecated; deployment uses Server Manager. No container images (StatefulSet-style). No Helm chart. No operator. Samba AD-DC has experimental container images. A new framework should provide Kubernetes-native DC deployment (StatefulSet + CSI + PVC for DIT).
- **Impact**: AD deployment is VM-centric; cloud-native deployment is manual.
- **Severity**: high
- **Constraints**: Must support StatefulSet with PVC-backed DIT; must support rolling upgrades.
- **KB references**: `00-overview/01-active-directory-overview.md`
- **Cross-platform**: cross-platform
- **Open questions**: Container image per DC? Operator for DC lifecycle (promote/demote/backup)?

#### PC-110
- **Capability**: Operations
- **Title**: Disaster recovery is manual (ntdsutil + metadata cleanup + IFM)
- **Description**: AD DR involves: (a) `ntdsutil` metadata cleanup for dead DCs, (b) IFM (Install From Media) for offline DC provisioning, (c) `Restore-ADObject` (Recycle Bin) for object recovery, (d) `repadmin /removelingeringobjects` for stale-object cleanup. All manual. A new framework should automate DR: one-command DC restore, automated metadata cleanup, Recycle Bin by default.
- **Impact**: AD DR requires expert operators; RTO is hours.
- **Severity**: high
- **Constraints**: Must support point-in-time restore; must support automated metadata cleanup.
- **KB references**: `01-ad-core/01-ad-ds-internals.md`, `03-directory-schema/05-replication-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-DC backup with PITR? Operator-driven DR runbooks?

#### PC-111
- **Capability**: Operations
- **Title**: AD audit logs are Windows Event Log only; no structured logging
- **Description**: AD audit events (5136 Directory Service Access, 4768/4769 Kerberos, 4662 Object Access, 4624 Logon) are Windows Event Log XML. No structured JSON. No OTel. No SIEM-friendly format. WEF (Windows Event Forwarding) aggregates to a collector. A new framework should emit structured JSON/CEF events to OTel collector.
- **Impact**: SIEM integration requires WEF + parsing.
- **Severity**: high
- **Constraints**: Must emit per-event JSON with full context (user, source, action, result); must support OTel.
- **KB references**: `02-protocols/01-kerberos-internals.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: OTel semantic conventions for AD/Kerberos/GPO? MITRE ATT&CK technique IDs in event metadata?

#### PC-112
- **Capability**: Operations
- **Title**: AD has no REST/gRPC API; only LDAP + PowerShell
- **Description**: AD's only programmatic APIs are LDAP (RFC 4511 + AD controls), PowerShell (`ActiveDirectory` module), and ADWS (SOAP, deprecated). No REST. No gRPC. No GraphQL. Modern apps want REST/JSON. A new framework should provide a modern API layer (REST/gRPC) over the directory.
- **Impact**: Modern app integration is LDAP-only; no cloud-native API.
- **Severity**: high
- **Constraints**: Must support LDAP for legacy; add REST/gRPC for new apps.
- **KB references**: `01-ad-core/01-ad-ds-internals.md`, `11-code-examples/01-powershell-ad-cmdlets.md`
- **Cross-platform**: cross-platform
- **Open questions**: REST over directory (CRUD on objects)? gRPC for streaming (replication status)? GraphQL for flexible queries?

#### PC-113
- **Capability**: Operations
- **Title**: AD functional level upgrades are one-way; mixed-version forests are fragile
- **Description**: Domain/forest functional levels (2003, 2008, 2008R2, 2012, 2012R2, 2016, 2019, 2022) gate features. Once raised, cannot be lowered. Mixed-version forests (e.g. 2012 + 2022 DCs) work but with feature constraints. `Set-ADDomainMode -Identity <domain> -DomainMode <year>`. A new framework should adopt a continuous-deployment model (no functional levels) or document the equivalent.
- **Impact**: Functional-level upgrades are high-risk; orgs delay.
- **Severity**: medium
- **Constraints**: Must support mixed-version DCs during upgrade; must support feature gating by DC version.
- **KB references**: `03-directory-schema/01-schema-attributes.md`, `00-overview/03-domains-forests-trees.md`
- **Cross-platform**: Windows
- **Open questions**: Drop functional levels entirely (always-latest schema)? Per-feature flags instead?

#### PC-114
- **Capability**: Operations
- **Title**: Trust password rotation (every 30 days) can desync; manual reset required
- **Description**: Trust passwords rotate every 30 days (default) via `netlogon.dll!I_NetServerPasswordSet2`. The current + previous password are stored in `trustAuthBlob` for overlap. If a DC is offline during rotation, the trust can desync. `nltest /verify` detects; `netdom trust /reset` fixes. A new framework should automate trust-password rotation + health checks.
- **Impact**: Trust desync causes cross-domain auth failures.
- **Severity**: medium
- **Constraints**: Must support dual-password overlap; must support automated health check + reset.
- **KB references**: `03-directory-schema/04-trusts-topology.md`, `00-overview/04-fsmo-roles.md`
- **Cross-platform**: cross-platform
- **Open questions**: Auto-reset on desync detection? Per-trust rotation policy?

#### PC-115
- **Capability**: Operations
- **Title**: `dcdiag` / `repadmin` / `ntdsutil` are Windows-only; cross-platform tooling is fragmented
- **Description**: AD operational tooling (`dcdiag`, `repadmin`, `ntdsutil`, `nltest`, `ksetup`, `setspn`) is Windows-only. Samba provides `samba-tool drs showrepl` (subset). FreeIPA has `ipa-replica-manage` (different model). A new framework should provide a unified operational CLI (Go/Rust) that runs on any OS.
- **Impact**: Cross-platform AD operations require Windows admin workstations.
- **Severity**: medium
- **Constraints**: Must support replication status, FSMO queries, metadata cleanup, SPN management.
- **KB references**: `00-overview/04-fsmo-roles.md`, `01-ad-core/01-ad-ds-internals.md`, `10-comparison-matrices/03-tool-function-matrix.md`
- **Cross-platform**: Windows, macOS, Linux
- **Open questions**: Adopt `samba-tool` as the base? Write fresh CLI in Go/Rust?

### Security

#### PC-116
- **Capability**: Security
- **Title**: Kerberoasting (RC4 TGS brute-force) is the dominant AD attack
- **Description**: Any domain user can request a TGS for any SPN. The TGS is encrypted with the service account's long-term key. RC4-HMAC TGS is offline-brute-forceable (MD4-derived key). Mitigations: gMSA + AES-only etypes, disable RC4 via domain policy, long random service-account passwords. A new framework should default to AES-only + gMSA + service-account password-length enforcement.
- **Impact**: Kerberoasting is the #1 AD attack vector.
- **Severity**: blocker
- **Constraints**: Must default to AES-only etypes; must enforce long service-account passwords; must support gMSA.
- **KB references**: `00-overview/01-active-directory-overview.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Auto-detect Kerberoast attempts via 4769 events with etype 0x17? Force-migrate service accounts to AES on next rotation?

#### PC-117
- **Capability**: Security
- **Title**: DCSync (DRSGetNCChanges with EXOP_REPL_SECRETS) extracts all password hashes
- **Description**: Any principal with `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` on the domain NC can call `DRSGetNCChanges` with `EXOP_REPL_SECRETS` and pull `unicodePwd`/`ntPwdHistory`/`supplementalCredentials` for any user. Members of Domain Admins, Enterprise Admins, DCs have these by default. Detection: Event 4662 with `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`. A new framework should audit + alert on non-DC DRSGetNCChanges.
- **Impact**: DCSync = full domain compromise by any Domain Admin.
- **Severity**: blocker
- **Constraints**: Must audit all `DRSGetNCChanges` calls; must alert on non-DC callers.
- **KB references**: `00-overview/01-active-directory-overview.md`, `11-code-examples/05-python-impacket-examples.md`, `02-protocols/06-rpc-dcerpc-ms-drsr.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-principal `DS-Replication-Get-Changes-All` audit? Break-glass replication via HSM-bound key?

#### PC-118
- **Capability**: Security
- **Title**: Golden ticket (forged TGT via krbtgt hash) requires krbtgt rotation to invalidate
- **Description**: Attacker with krbtgt hash forges TGTs with arbitrary PAC. Detection requires krbtgt password rotation (twice within TGT lifetime). Without rotation, golden tickets persist indefinitely. A new framework should make krbtgt rotation a one-click operation + monitor for old-key usage.
- **Impact**: Compromised krbtgt = persistent forest compromise.
- **Severity**: blocker
- **Constraints**: Must support dual-krbtgt mode; must log old-key TGT usage as security signal.
- **KB references**: `00-overview/01-active-directory-overview.md`, `02-protocols/08-spn-upn-pac.md`
- **Cross-platform**: cross-platform
- **Open questions**: HSM-bound krbtgt key? Automatic rotation every N days?

#### PC-119
- **Capability**: Security
- **Title**: Silver ticket (forged TGS via service-account hash) requires PAC_BUFFER_TICKET_CHECKSUM
- **Description**: Attacker with service-account hash forges TGS for that service. Detection: Server 2016+ PAC_BUFFER_TICKET_CHECKSUM (KDC signs entire Ticket.enc-part with krbtgt key). Services that opt in to PAC validation detect silver tickets. Most services skip PAC validation. A new framework should default to ticket-signature validation by services.
- **Impact**: Silver tickets persist undetected without PAC validation.
- **Severity**: high
- **Constraints**: Must generate PAC_BUFFER_TICKET_CHECKSUM; must support per-service opt-in to validation.
- **KB references**: `02-protocols/08-spn-upn-pac.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Default-validate by services (perf cost)? Token-binding alternative?

#### PC-120
- **Capability**: Security
- **Title**: SIDHistory abuse allows privilege escalation across migrations
- **Description**: `sIDHistory` carries old-domain SIDs during migrations. Within-forest trusts allow sIDHistory passthrough; external trusts filter it. An attacker who injects a high-privilege SID (e.g. Enterprise Admins) into a user's sIDHistory gains forest-admin. Detection: audit `sIDHistory` writes; alert on non-migration sIDHistory additions. A new framework should default to sIDHistory filtering on all trusts + audit writes.
- **Impact**: sIDHistory injection = forest-admin escalation.
- **Severity**: high
- **Constraints**: Must support sIDHistory filtering (QUARANTINED trust attribute); must audit sIDHistory writes.
- **KB references**: `03-directory-schema/04-trusts-topology.md`, `00-overview/03-domains-forests-trees.md`
- **Cross-platform**: cross-platform
- **Open questions**: Drop sIDHistory entirely (use only current SIDs)? Per-trust filtering policy?

#### PC-121
- **Capability**: Security
- **Title**: Selective authentication (`Allowed to Authenticate` ACE) is per-resource; rarely used
- **Description**: Cross-forest trust with `CROSS_ORGANIZATION` flag requires `Allowed to Authenticate` (GUID `68b1d179-0d15-4d4f-ab71-46152e79a7bc`) ACE on each resource computer object. Without the ACE, foreign users get `KRB_ERR_GENERIC`. Rarely deployed due to per-resource ACL burden. A new framework should provide a more usable selective-auth model (per-OU, per-host-group).
- **Impact**: Selective auth is operationally painful; orgs use full-trust instead.
- **Severity**: medium
- **Constraints**: Must support `Allowed to Authenticate` for AD interop; consider HBAC-style as modern alternative.
- **KB references**: `03-directory-schema/04-trusts-topology.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-OU selective auth? FreeIPA HBAC-style server-side evaluation?

#### PC-122
- **Capability**: Security
- **Title**: AdminSDHolder + SDPROP (every 60 min) can override intended ACLs
- **Description**: `AdminSDHolder` object in `CN=System` holds the SD template for protected groups (Domain Admins, Enterprise Admins, etc.). SDPROP runs every 60 minutes, resets SDs on protected objects. Custom ACEs on protected groups get reverted. A new framework should preserve AdminSDHolder semantics or document the alternative.
- **Impact**: Custom ACEs on protected groups silently revert.
- **Severity**: medium
- **Constraints**: Must support AdminSDHolder template; must support SDPROP-equivalent.
- **KB references**: `00-overview/05-glossary.md`, `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace AdminSDHolder with declarative RBAC? Per-protected-group templates?

#### PC-123
- **Capability**: Security
- **Title**: Supply-chain risk: signed AD updates require WSUS trust
- **Description**: AD DCs receive updates via WSUS + Microsoft Update. WSUS signs updates with Microsoft root. Compromise of WSUS = malicious updates to all DCs. A new framework should support signed-update verification (Sigstore, in-toto) + reproducible builds.
- **Impact**: WSUS compromise = DC supply-chain attack.
- **Severity**: medium
- **Constraints**: Must support signed updates; must support reproducible builds.
- **KB references**: `01-ad-core/01-ad-ds-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Sigstore (cosign) for framework binaries? In-toto attestations?

### Migration

#### PC-124
- **Capability**: Migration
- **Title**: sidHistory migration requires `DRSAddSidHistory` + SeEnableDelegationPrivilege
- **Description**: ADMT (Active Directory Migration Tool) uses `DRSAddSidHistory` (opnum 20 on DRSUAPI) to inject old-domain SIDs into user `sIDHistory`. Requires `SeEnableDelegationPrivilege` on the source domain. SIDHistory flows through within-forest trusts (filtered on external). A new framework should support sIDHistory migration or document the alternative (claims-based migration).
- **Impact: Migration without sIDHistory breaks ACLs referencing old-domain SIDs.
- **Severity**: high
- **Constraints**: Must support `DRSAddSidHistory` for ADMT interop; must support sIDHistory filtering on external trusts.
- **KB references**: `03-directory-schema/04-trusts-topology.md`, `02-protocols/06-rpc-dcerpc-ms-drsr.md`
- **Cross-platform**: cross-platform
- **Open questions**: Replace sIDHistory with claims-based migration? Document ADMT as the only migration path?

#### PC-125
- **Capability**: Migration
- **Title**: GPO translation from AD to framework-native requires manual mapping
- **Description**: ADMX settings, Preferences XML, GptTmpl.inf, scripts — each requires translation to the framework's native policy format. No automated tool exists today (per the KB's comparison matrix). A new framework should provide a GPO-import tool that translates to native format with manual review.
- **Impact**: GPO migration is manual per-setting.
- **Severity**: high
- **Constraints**: Must parse ADMX/ADML/Registry.pol/GptTmpl.inf/Preferences XML; must produce native policy.
- **KB references**: `10-comparison-matrices/05-gpo-equivalents-matrix.md`, `04-group-policy/03-admx-templates.md`
- **Cross-platform**: cross-platform
- **Open questions**: Auto-translate known ADMX settings to native? Per-setting review UI?

#### PC-126
- **Capability**: Migration
- **Title**: Client switchover from AD to framework requires parallel-run support
- **Description**: Migrating clients from AD to a new framework requires parallel run: client is joined to both AD (for legacy) and the framework (for new). Kerberos cross-realm trust + LDAP referrals allow gradual migration. A new framework should support parallel-run mode + per-service migration.
- **Impact**: Big-bang migration is high-risk; parallel-run reduces risk.
- **Severity**: high
- **Constraints**: Must support cross-realm trust with AD; must support per-service SPN migration.
- **KB references**: `03-directory-schema/04-trusts-topology.md`, `02-protocols/01-kerberos-internals.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-SPN migration (move one service at a time)? Per-user migration (move one user at a time)?

#### PC-127
- **Capability**: Migration
- **Title**: Password hash migration requires either sIDHistory or password-sync agent
- **Description**: Migrating user passwords from AD to a new framework: (a) sIDHistory (preserves SID + password via ADMT), (b) password-sync agent (Microsoft Identity Manager / Entra Connect), (c) require password reset on migration. Option (a) preserves user experience; (b) requires agent; (c) is disruptive. A new framework should support (a) + (b) + document (c) as fallback.
- **Impact**: Password migration without reset preserves UX.
- **Severity**: high
- **Constraints**: Must support `DRSAddSidHistory` for ADMT; must support password-sync agent protocol.
- **KB references**: `03-directory-schema/04-trusts-topology.md`, `11-code-examples/05-python-impacket-examples.md`
- **Cross-platform**: cross-platform
- **Open questions**: Password-sync agent protocol (proprietary or standard)? Per-batch migration?

#### PC-128
- **Capability**: Migration
- **Title**: DNS namespace sharing during migration requires careful zone delegation
- **Description**: During AD→framework migration, both directories may serve the same DNS namespace (e.g. `corp.example.com`). AD-integrated DNS zones replicate via DRSUAPI; framework DNS may use BIND/CoreDNS. Zone delegation + split-brain handling required. A new framework should document the DNS migration path (likely: subdomain per directory during transition).
- **Impact**: DNS namespace conflict breaks client resolution.
- **Severity**: medium
- **Constraints**: Must support zone delegation; must support split-brain DNS during migration.
- **KB references**: `02-protocols/05-dns-dynamic-updates.md`, `03-directory-schema/04-trusts-topology.md`
- **Cross-platform**: cross-platform
- **Open questions**: Subdomain per directory (`ad.corp.example.com` + `new.corp.example.com`)? Per-record migration?

#### PC-129
- **Capability**: Migration
- **Title**: Kerberos cross-realm with AD during migration requires `capaths` + trust object
- **Description**: Cross-realm Kerberos trust (AD ↔ framework) requires `trustedDomain` object on both sides + `krbtgt/<other-realm>@<this-realm>` cross-realm principal + `[capaths]` in `krb5.conf`. Referral TGTs flow via the trust. A new framework should automate cross-realm setup + provide `capaths` generation.
- **Impact**: Cross-realm setup is manual + error-prone.
- **Severity**: medium
- **Constraints**: Must support RFC 4120 §3.3.3 referral; must support `capaths` config generation.
- **KB references**: `02-protocols/01-kerberos-internals.md`, `03-directory-schema/04-trusts-topology.md`, `09-linux-equivalents/08-freeipa-trust.md`
- **Cross-platform**: cross-platform
- **Open questions**: Auto-generate `capaths` from trust graph? Per-realm KDC discovery via DNS SRV?

#### PC-130
- **Capability**: Migration
- **Title**: SYSVOL migration (logon scripts, GPO files) requires SMB share compatibility
- **Description**: Clients read SYSVOL via `\\<domain>\SYSVOL\...` SMB share. During migration, both AD and framework must serve SYSVOL (or one must redirect). GPO files + logon scripts are SMB-dependency. A new framework should support `SYSVOL`-style share + DFS-N-compatible referral.
- **Impact**: SYSVOL migration disrupts GPO + logon-script distribution.
- **Severity**: medium
- **Constraints**: Must support `SYSVOL` + `NETLOGON` shares; must support DFS-N-style referral for `\\<domain>\...`.
- **KB references**: `04-group-policy/01-gpo-architecture.md`, `07-file-print/02-dfs-n-dfs-r.md`
- **Cross-platform**: cross-platform
- **Open questions**: Per-domain SYSVOL with DFS-N referral? Migrate to HTTP-based policy distribution?

---

## Cross-cutting observations

### Implementation-level gaps in open source

The KB repeatedly surfaces these stubs/TODOs/known-bugs in open-source implementations:
- **Samba AD-DC**: DRSUAPI server is functional but lags Microsoft on newer opnum versions (V10, V11). Claims-based Kerberos and compound identity are incomplete.
- **MIT krb5**: No PAC generation by default (only verification). FreeIPA's `ipa_kdb` plugin fills the gap but is IPA-specific.
- **Heimdal**: Apple's macOS fork has not tracked upstream since ~2014. Missing PAC_FULL_CHECKSUM, claims, compound identity.
- **SSSD**: GPO support is limited to `[Privilege Rights]` logon rights. No Registry.pol, no Preferences, no Scripts.
- **OpenLDAP client**: No AD-specific LDAP controls (TREE_DELETE, DIRSYNC, ASQ, NOTIFICATION). Only `LDAP_SERVER_SD_FLAGS_OID` is supported.
- **impacket**: DRSUAPI client works for DCSync but `DRSAddSidHistory` is stubbed in some versions.

### Operational footguns scattered throughout the KB

- Schema cache reload blocks LDAP writes for 5–30 seconds.
- GPO version mismatch (GPC vs GPT) is common during DFS-R lag.
- Trust password rotation can desync if DC is offline.
- USN rollback on snapshot-restored DCs is silent until strict-consistency quarantines.
- W32Time MS-SNTP is fragile; chrony/ntpd cannot authenticate.
- AD CS CA database corruption requires restore-from-backup (no `eseutil /p`).
- Kerberos skew > 5 min breaks auth; VM time drift is a common cause.

### Threat-model items

- Kerberoasting (RC4 TGS brute-force) — #1 AD attack.
- DCSync (DRSGetNCChanges with EXOP_REPL_SECRETS) — extracts all hashes.
- Golden ticket (forged TGT via krbtgt hash) — requires krbtgt rotation.
- Silver ticket (forged TGS via service-account hash) — requires PAC_BUFFER_TICKET_CHECKSUM.
- PrintNightmare (MS-RPRN driver install as SYSTEM) — CVE-2021-34527.
- NTLM relay — requires SMB signing + LDAP signing + channel binding + EPA.
- sIDHistory injection — requires sIDHistory filtering on external trusts.
- Pass-the-hash — requires LSASS protection / Credential Guard.

### Recommended next step

Hand off this working document to the writing subagents who will produce the per-capability catalog files. Each catalog file should:
1. Group problems by capability (Core Directory, KDC, Auth Provider, Policy Engine, Cert Service, Federation Gateway, File Gateway, Client SDK, Cross-Platform Parity, Operations, Security, Migration).
2. For each problem, expand the description with KB citations and concrete design recommendations.
3. Cross-reference problems that span capabilities (e.g. PC-030 krbtgt rotation spans KDC + Security + Operations).
4. Produce a per-capability "design recommendations" section that resolves each problem.
