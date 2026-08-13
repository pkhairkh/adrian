---
title: FSMO Roles — The Five Single-Master Operations
audience: senior-engineers
tags: [fsmo, schema, pdc, rid, infrastructure, domain-naming]
related:
  - ./03-domains-forests-trees.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../03-directory-schema/05-replication-internals.md
last_updated: 2026-08-13
---

# FSMO Roles — The Five Single-Master Operations

AD is multi-master for ordinary writes (any DC can write any object). For a small number of operations, multi-master would create ambiguity or schema corruption, so AD designates exactly one DC per forest or per domain as the master. These are the **FSMO** (Flexible Single-Master Operations) roles — five of them, plus the optional **PDC Emulator** semantics that go beyond just being a PDC.

## The five roles

| Role | Scope | Held by | Purpose |
|------|-------|---------|---------|
| **Schema Master** | Forest | One DC in the forest-root domain | Sole writer of the Schema NC. Other DCs reject schema writes with `ERROR_DS_DSA_MUST_BE_INT_MASTER` (8438). |
| **Domain Naming Master** | Forest | One DC in the forest-root domain | Sole arbiter of new domain / application partition creation. Ensures NetBIOS and DNS names are unique. |
| **PDC Emulator** | Domain | One DC per domain | Default preferred DC for password changes; trusted DC for downlevel clients; time master; authoritative for Group Policy credential rotation. |
| **RID Master** | Domain | One DC per domain | Allocates RID pools (500 RIDs at a time) to other DCs; ensures RID uniqueness; reclaims unused RIDs from DCs removed from the domain. |
| **Infrastructure Master** | Domain | One DC per domain | Updates cross-domain references (SID, DN) when an object is renamed or moved between domains. Reference updater for `member`, `managedBy`, etc. |

## Where the role is stored

The role holder is recorded in two places:

- **Forest-wide roles** (Schema, Domain Naming) — the `fSMORoleOwner` attribute on the Schema NC head (`CN=Schema,CN=Configuration,...`) and on the Partitions container (`CN=Partitions,CN=Configuration,...`).
- **Domain-wide roles** (PDC, RID, Infrastructure) — the `fSMORoleOwner` attribute on the domain NC head (`DC=corp,...`), on the RID Manager object (`CN=RID Manager$,CN=System,DC=corp,...`), and on the Infrastructure object (`CN=Infrastructure,DC=corp,...`).

The value is the DN of the **NTDS Settings** object of the DC, e.g. `CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com`.

## Discovering the role holders

PowerShell (preferred):

```powershell
# Forest-wide
Get-ADForest corp.example.com | Select-Object SchemaMaster, DomainNamingMaster

# Domain-wide
Get-ADDomain corp.example.com | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster

# Equivalent via .NET
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).SchemaRoleOwner
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).NamingRoleOwner
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).RidRoleOwner
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).InfrastructureRoleOwner
```

Legacy:

```cmd
netdom query fsmo
```

Or via LDAP query against the RootDSE:

```bash
ldapsearch -x -H ldap://dc01.corp.example.com \
  -b "CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com" \
  "(objectClass=*)" fSMORoleOwner
```

## Role transfer vs role seizure

- **Transfer** — graceful. The current holder demotes itself; the new holder is promoted. The role owner writes its own `fSMORoleOwner` attribute to point to the new DC and the change replicates normally. Use `Move-ADDirectoryServerOperationMasterRole -Identity DC02 -OperationMasterRole SchemaMaster,RIDMaster,PDCEmulator,InfrastructureMaster,DomainNamingMaster`.
- **Seizure** — forceful. The current holder is offline or unrecoverable. `ntdsutil roles seize <role>` forcibly sets the role owner to the new DC. The old holder **must not** come back online as a DC afterwards; if it does, it will believe it still holds the role, leading to a "torn-write" situation that will replicate as a conflict and may corrupt the schema.

After seizing the schema master from a DC that came back online, the only safe operation on the original holder is **demotion** (`dcpromo /forceremoval`).

## Per-role details

### Schema Master

When `ldp` (or any LDAP tool) attempts to write to the Schema NC, the DSA on the receiving DC checks `fSMORoleOwner`. If the local DC is not the holder, the request is rejected:

```
ldap_add: Constraint violation (19)
        additional info: 0000209E: SvcErr: DSID-031A0FF4, problem 5003 (WILL_NOT_PERFORM),
        data 0
        schema update failed: attribute on schema object not the master
```

Workaround: bind directly to the schema master, or use the `schemaUpdateNow` operation to invalidate the cache after the schema-master write.

The schema master is also the only DC that can increment `objectVersion` on the Schema NC head. The current `objectVersion` is what Windows setup checks to determine whether a DC can be upgraded to a new forest-functional level.

### Domain Naming Master

When `dcpromo` is invoked to create a new domain, the promoting server contacts the domain naming master. The master verifies:

- The proposed NetBIOS name does not collide with an existing domain's `flatName`.
- The proposed DNS name does not collide with an existing crossRef.
- The proposed domain's parent exists.

If the domain naming master is offline, no new domains or application partitions can be created in the forest. Existing domain operations continue normally.

The domain naming master should be a **GC**. This requirement exists because the domain naming master must check for cross-domain name collisions, which requires the GC's partial-attribute view. If you transfer the role to a non-GC, AD will warn on every startup until you make it a GC.

### PDC Emulator

The most operationally consequential role. The PDC emulator:

1. **Receives all password changes within 15 seconds.** Every DC, after a password change, immediately single-replicates the new password hash to the PDC emulator (this is called "urgent replication"). The DC then serves the new password; if a logon fails, the DC falls back to the PDC emulator before rejecting.
2. **Is the time source.** The PDC emulator of the forest root domain synchronizes to an external time source; PDC emulators of child domains synchronize to the forest-root PDC; all other DCs synchronize to their PDC; all clients synchronize to their authenticating DC. Maintained by W32Time, MS-SNTP.
3. **Is the preferred DC for downlevel clients** (NT4 BDCs, Windows 2000 mixed-mode). Largely historical but the role is still required.
4. **Is the master for Group Policy preference password changes**. GPOs that contain user passwords (e.g. Scheduled Tasks with stored credentials, Drive Map preferences with credentials) — the password rotation is coordinated by the PDC emulator.
5. **Is the master for DFS-N metadata changes** in legacy mode.

If the PDC emulator is offline, password changes still work (any DC will write) but urgent replication stops; concurrent logons may fail until the regular replication interval catches up.

### RID Master

Every DC maintains a pool of 500 RIDs, allocated from the RID master. When the pool drops below 50% (alert threshold), the DC requests a new pool. When the DC has issued 80% of its pool, the DCs are out and a new pool is requested.

When the RID master is offline:
- DCs continue issuing RIDs from their existing pool.
- When a DC's pool is exhausted, no new security principals can be created on that DC until the RID master comes back.

The RID master also reclaims RID pools from DCs that have been removed from the domain (or whose NTDS Settings object has been deleted). This is called RID pool reclamation.

To check RID pool status:

```cmd
ridpool.exe /dc:dc01.corp.example.com
```

(ridpool is an internal Microsoft tool; the equivalent via MS-DRSR is `DRSRIDGetProvider` / `DRSGetNT4ChangeLog`. The DSA exposes pool state via the `ridManager` reference attribute.)

### Infrastructure Master

The infrastructure master updates cross-domain references. When an object in domain A is referenced by an object in domain B (e.g. group in B has member from A), B stores the member's DN, SID, and a back-link. If the object in A is renamed, moved, or deleted, B's references must be updated. The infrastructure master scans for these references, queries the GC for the new state, and writes the update back.

**Important rule:** The infrastructure master **must not** be a GC. If it is a GC, it has the local data to do the cross-domain reference update itself, but it has no way to know whether the GC data is stale. So a GC infrastructure master simply won't do its job, and references in the domain will accumulate phantom records.

Exception: if **every** DC in the domain is a GC (common in modern single-domain forests), this is moot.

## Placement guidance

For a typical two-DC-per-domain forest:

- **Forest root domain**:
  - DC1: Schema Master + Domain Naming Master + PDC Emulator + RID Master (forest-wide + domain-wide operations master on one DC, called the "operations master").
  - DC2: Infrastructure Master (if it's not a GC; if every DC is a GC, this role is moot but should still have an owner).

- **Child domains**:
  - DC1 (PDC): PDC Emulator + RID Master.
  - DC2: Infrastructure Master (if not a GC).

## Seizure procedure (offline role holder)

1. Confirm the original holder is permanently offline (network unreachable, hardware failed).
2. On a healthy DC in the appropriate domain, run `ntdsutil`:

   ```
   ntdsutil
   roles
   connections
   connect to server DC02
   quit
   seize schema master
   seize domain naming master
   seize pdc
   seize rid master
   seize infrastructure master
   quit
   quit
   ```

3. Run `repadmin /syncall /A /e /d /q` to force replication of the role change.
4. Verify with `netdom query fsmo`.
5. If the original holder comes back online, demote it with `dcpromo /forceremoval` and clean up metadata: `ntdsutil metadata cleanup`.

## Cross-platform notes

- macOS and Linux clients do not interact with FSMO roles directly. They use AD as a black box: the KDC service on whichever DC they hit decides whether to handle the request or refer.
- The PDC emulator is implicitly preferred by Netlogon for password-change operations: when a Mac/Linux client changes its password via `kpasswd` (RFC 3244), the KDC may issue a `KRB-ERROR` referral to the PDC emulator for the password change operation. Samba's `lib/krb5_wrap.c:k5_change_password()` and MIT's `lib/krb5/os/changepw.c` both handle this.

## References

- [MS-ADTS] §7.3 „FSMO role objects”
- Microsoft — *FSMO Roles* — <https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles>
- [MS-DRSR] §4.1.27 `DRSGetNCChanges` (replication of FSMO attribute changes)
