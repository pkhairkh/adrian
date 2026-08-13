---
title: OUs vs Containers — classSchema, instanceType, systemFlags, Well-Known GUIDs, Move Semantics
audience: senior-engineers
tags: [organizationalunit, container, well-known-guids, instancetype, systemflags, crossdom-move]
related:
  - ./01-schema-attributes.md
  - ./03-global-catalog.md
  - ./04-trusts-topology.md
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/02-ldap-protocol.md
last_updated: 2026-08-13
---

Active Directory distinguishes container classes by their `objectClassCategory` (1=structural, 0=abstract, 2=auxiliary) and `systemPossSuperiors` rules — `organizationalUnit` (OID `1.2.840.113556.1.5.13`) is the only structural class on which Group Policy can be linked, while `container` (OID `1.2.840.113556.1.5.1`) is the generic parent used by built-in well-known GUID-named system containers that GPOs cannot scope to.

## classSchema comparison

| Property                  | `container` (OID 1.2.840.113556.1.5.1)             | `organizationalUnit` (OID 1.2.840.113556.1.5.13)        |
|---------------------------|----------------------------------------------------|----------------------------------------------------------|
| `objectClassCategory`     | 1 (structural)                                      | 1 (structural)                                            |
| `subClassOf`              | `top`                                               | `top`                                                     |
| `rDNAttID`                | `cn` (2.5.4.3)                                      | `ou` (2.5.4.11)                                           |
| `defaultSecurityDescriptor` | Allow Authenticated Users READ; Admins full control | Allow Authenticated Users READ; Account Operators full control; GPOs scoped via `gPLink` |
| `gPLink` allowed          | NO (GP does not process links on `container`)       | YES (GP processes `gPLink`, `gPOptions`)                  |
| Delegation granularity    | Per-object ACL only                                 | Per-object ACL + GP inheritance via `gPOptions=1`         |
| `systemPossSuperiors`     | wide (`domainDNS`, `organization`, `container`)     | `domainDNS`, `organization`, `organizationalUnit`         |
| Move via ADUC             | Allowed (subject to `systemFlags`)                  | Allowed                                                   |
| Rename                    | Allowed                                             | Allowed                                                   |
| Move target for users     | NO (built-in `Users` container only)                | YES — recommended parent for user accounts                |
| Move target for computers | NO (built-in `Computers` container only)            | YES — recommended parent for computer accounts            |

The two structural classes exist because GP needs a distinct class to scope to. The `container` class pre-dates GP (NT4-era SAM) and is used for objects whose existence is required by the directory itself but whose contents are not policy-targetable: `CN=Builtin`, `CN=Users`, `CN=Computers`, `CN=ForeignSecurityPrincipals`, `CN=System`, `CN=LostAndFound`, `CN=Program Data`, `CN=NTDS Quotas`.

## `instanceType` flag (MS-ADTS §3.1.1.2.2)

Each object has a 32-bit `instanceType` attribute (OID `2.5.21.1`) written by the DSA on create — cannot be set by LDAP clients (it's `systemOnly`):

| Bit | Mask  | Name                | Meaning                                                                                  |
|-----|-------|---------------------|-------------------------------------------------------------------------------------------|
| 0   | 0x01  | IT_WRITE            | Object is writable on this DC (FALSE on RODC copies).                                     |
| 1   | 0x02  | IT_NC_ABOVE         | Object's NC head is above this object in the tree (i.e. this object is NOT the NC head). |
| 2   | 0x04  | IT_NC               | Object IS the NC head (top of a naming context).                                          |
| 3   | 0x08  | IT_NC_BASE          | Object IS the base of the NC (used for NDNC heads).                                       |

Common values:

| `instanceType` | Typical object                                                                |
|----------------|--------------------------------------------------------------------------------|
| 0x00000000     | Uninstantiated (schema definition referencing an uncreated NC head).            |
| 0x00000001     | NC head on a non-replica (read-only NDNC).                                      |
| 0x00000003     | Writable object below an NC head (most user/computer/group objects).           |
| 0x00000004     | NC head replica (NOT writable) — e.g. GC partial replica of an NC.             |
| 0x00000005     | Writable NC head — e.g. a domain NC on a DC in that domain.                    |
| 0x00000007     | Writable NC head with IT_NC_BASE (NDNC heads on their home server).            |

Read with `Get-ADObject -Properties instanceType`. The DSA uses this attribute to know whether to invoke the NC-head initialization code path (`MIDL ModifyNCHead`).

## `systemFlags` attribute (MS-ADTS §3.1.1.2.4.1)

32-bit mask (OID `1.2.840.113556.1.4.378`):

| Bit | Mask         | Name                                | Effect                                                                                                                |
|-----|--------------|-------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| 0   | 0x00000001   | FLAG_ATTR_NOT_REPLICATED            | Attribute value not replicated (e.g. `badPwdCount`, `badPasswordTime`, `lastLogon`, `lastLogoff`, `lockoutTime`). Per-DC. |
| 1   | 0x00000002   | FLAG_ATTR_IS_CONSTRUCTED            | Attribute is constructed at read time (e.g. `memberOf`, `tokenGroups`, `canonicalName`).                              |
| 2   | 0x00000004   | FLAG_ATTR_IS_OPERATIONAL            | Operational — must be requested explicitly in LDAP search `attributes` list (default not returned).                  |
| 3   | 0x00000008   | FLAG_SCHEMA_BASE_OBJECT             | Object is part of base schema; cannot be deleted.                                                                     |
| 4   | 0x00000010   | FLAG_ATTR_IS_RDN                    | Attribute is an RDN attribute (e.g. `cn`, `ou`, `dc`).                                                                |
| 8   | 0x00000100   | FLAG_DOMAIN_DISALLOW_MOVE           | Object cannot be moved (set on `CN=Builtin`, `CN=Users`, `CN=Computers`, `CN=System`, etc.).                          |
| 9   | 0x00000200   | FLAG_DOMAIN_DISALLOW_MOVE_ON_DOMAIN | Object cannot be moved across domains.                                                                                |
| 10  | 0x00000400   | FLAG_DOMAIN_DISALLOW_RENAME         | Object cannot be renamed.                                                                                              |
| 11  | 0x00000800   | FLAG_DOMAIN_DISALLOW_DELETE         | Object cannot be deleted.                                                                                              |
| 16  | 0x00010000   | FLAG_DISALLOW_DELETE                | Generic disallow-delete (older flag, superseded by 0x800 for domain-NC head objects).                                 |
| 17  | 0x00020000   | FLAG_DISALLOW_MOVE                  | Generic disallow-move.                                                                                                |
| 23  | 0x00800000   | FLAG_CONFIG_ALLOW_LIMITED_MOVE      | Config NC head object can be moved within a config subtree.                                                            |
| 24  | 0x01000000   | FLAG_CONFIG_ALLOW_MOVE              | Config NC head object can be moved.                                                                                    |
| 25  | 0x02000000   | FLAG_CONFIG_ALLOW_RENAME            | Config NC head object can be renamed.                                                                                  |
| 26  | 0x04000000   | FLAG_DISALLOW_DELETE                | Generic disallow-delete (config NC).                                                                                  |

Well-known container `systemFlags` values:

```
CN=Builtin,        systemFlags = 0x00080000   (DISALLOW_MOVE | DISALLOW_RENAME | DISALLOW_DELETE)
CN=Computers,      systemFlags = 0x00080000
CN=Deleted Objects, systemFlags = 0x08080000  (also FLAG_ATTR_IS_CONSTRUCTED-ish semantics)
CN=ForeignSecurityPrincipals, systemFlags = 0x00080000
CN=Infrastructure, systemFlags = 0x00080000
CN=LostAndFound,   systemFlags = 0x00080000
CN=NTDS Quotas,    systemFlags = 0x00080000
CN=Program Data,   systemFlags = 0x00080000
CN=System,         systemFlags = 0x00080000
CN=Users,          systemFlags = 0x00080000
```

`systemFlags` is `systemOnly` on built-in objects; admins cannot unset it.

## Well-known container GUIDs

Each well-known container also carries a `wellKnownGUID` attribute (OID `1.2.840.113556.1.4.137`). The GUID is published in MS-ADTS §6.1.1 and is identical across all forests:

| Container                  | `wellKnownGUID` (attribute `wellKnownObjects`/`msDS-WellKnownObjects` on the NC head) |
|----------------------------|------------------------------------------------------------------------------------------|
| `CN=Users`                 | `aa312825-683f-11d2-8d6c-001999999999`                                                  |
| `CN=Computers`             | `a361b2bf-661b-4092-a59c-6e8ab9b9d919`                                                  |
| `CN=System`                | `30000000-66d7-4b81-bb2c-8e9b98f7d3f0`                                                  |
| `CN=Deleted Objects`       | `18e2ea80-84f1-11d2-9d4b-00c04f79f889`                                                  |
| `CN=LostAndFound`          | `e458b0b0-ff42-4718-aa9b-df6e7c7a9a9a`                                                  |
| `CN=ForeignSecurityPrincipals` | `221ac1a7-6f24-4c89-8e68-26d2bf7822bb`                                              |
| `CN=Infrastructure`        | `2fbac1870ade11d297c400c04fd8d5cd`                                                      |
| `CN=Program Data`          | `4bdf36c0-92f1-11d2-aee2-00c04f8e3c7f`                                                  |
| `CN=NTDS Quotas`           | `a8d7a478-9f6b-4ea2-8d20-3a51e9f7a7e5`                                                  |
| `CN=Managed Service Accounts` | `1eb93889-e40c-46aa-bb97-fa32b925c1e0`                                               |
| `CN=Builtin`               | `00000000-0000-0000-0000-000000000000` (actually hard-coded, no WKO entry)              |

These GUIDs are bound to the NC head through two multi-valued attributes:

- `wellKnownObjects` (built-in objects — every domain has them; populated at install).
- `msDS-WellKnownObjects` (extended — added when new features introduce containers, e.g. `CN=Managed Service Accounts` introduced with Server 2008 R2).

Lookup by GUID: bind to `<WKGUID=<guid>,<NC-dn>>`. The DSA resolves the placeholder to the actual DN.

```
ldap://dc01.corp.example.com/<WKGUID=aa312825-683f-11d2-8d6c-001999999999,DC=corp,DC=example,DC=com>
```

## Move semantics — `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID`

OID: `1.2.840.113556.1.4.521` (LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID).

An LDAP Modify-DN operation moves an object within an NC. To move across NCs (e.g. user from `corp.example.com` to `child.corp.example.com`), the client supplies this control with the **target DC** DN in the control value:

```
ControlType:   1.2.840.113556.1.4.521
Criticality:   TRUE
ControlValue:  SEQUENCE {
                  targetDomainController  LDAPDN    -- DN of NTDS Settings of target DC
                }
```

The DSA at the source reads the object's `nTSecurityDescriptor`, `sIDHistory`, group memberships, etc., and uses DRSUAPI `DRSAddEntry` against the target DC's invocationID to create the object in the target NC. The source DC then writes a tombstone with `lastKnownParent` = the original parent DN.

Cross-domain move requires:

1. Domain functional level ≥ Windows 2000 native (no mixed mode).
2. PDC emulator reachable in both domains.
3. RID master reachable in the target domain.
4. Admin privilege on both source and target OUs.
5. SPN attribute values cleared first (or the move fails with `constraintViolation`); `servicePrincipalName` is domain-scoped.

PowerShell:

```powershell
# Move user to another OU (intra-domain — simple Modify-DN)
Move-ADObject -Identity "CN=jdoe,CN=Users,DC=corp,DC=example,DC=com" `
              -TargetPath "OU=Sales,DC=corp,DC=example,DC=com"

# Cross-domain move requires the Move-ADObject -TargetServer parameter
Move-ADObject -Identity "CN=jdoe,CN=Users,DC=corp,DC=example,DC=com" `
              -TargetPath "OU=Sales,DC=child,DC=corp,DC=example,DC=com" `
              -TargetServer "dc-child.child.corp.example.com"
```

`Move-ADObject` issues the modify-DN request with the cross-domain control. The same is done by the `movetree.exe` tool (located in `%SystemRoot%\System32`).

## Diagnostic — LDAP filter

Find all OUs where GPO inheritance is blocked (`gPOptions` bit 1):

```ldap
(&(objectClass=organizationalUnit)(gPOptions:1.2.840.113556.1.4.803:=1))
```

`1.2.840.113556.1.4.803` is `LDAP_MATCHING_RULE_BIT_AND`. For `systemFlags` & `FLAG_DOMAIN_DISALLOW_MOVE` (0x100):

```ldap
(systemFlags:1.2.840.113556.1.4.803:=256)
```

## Wireshark display filter

```
ldap.opCode == modifyDNRequest && ldap.modifyDN_newrdn contains "OU="
```

For cross-domain moves:

```
ldap && ldap.controls.controlType == 1.2.840.113556.1.4.521
```

## PowerShell — enumerate well-known containers

```powershell
$root = (Get-ADRootDSE).defaultNamingContext
$nc   = Get-ADObject -Identity $root -Properties wellKnownObjects, msDS-WellKnownObjects

$nc.wellKnownObjects | ForEach-Object {
    # Each entry is "B:32:<guid-without-dashes>:<DN>"
    if ($_ -match '^B:32:([0-9A-Fa-f]{32}):(.+)$') {
        [PSCustomObject]@{
            GUID = $matches[1] -replace '(.{8})(.{4})(.{4})(.{4})(.{12})', '$1-$2-$3-$4-$5'
            DN   = $matches[2]
        }
    }
}
```

## Python ldap3 — enumerate OUs with GP inheritance blocked

```python
from ldap3 import Server, Connection, ALL, SUBTREE

server = Server('dc01.corp.example.com', get_info=ALL)
conn = Connection(server, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

base = 'DC=corp,DC=example,DC=com'
conn.search(base,
            '(objectClass=organizationalUnit)',
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'gPLink', 'gPOptions',
                        'instanceType', 'systemFlags', 'description'])

for entry in conn.entries:
    gpo = entry.gPOptions.value or 0
    if gpo & 1:
        print(f"BLOCKED inheritance: {entry.distinguishedName.value}")
        print(f"  gPLink       : {entry.gPLink.value or '(none)'}")
        print(f"  systemFlags  : 0x{int(entry.systemFlags.value):x}")
        print(f"  instanceType : 0x{int(entry.instanceType.value):x}")
```

## Registry / schema attribute table

`container` vs `organizationalUnit` schema attribute set (selected):

| Attribute                  | On `container` | On `organizationalUnit` | Notes                                                              |
|----------------------------|:--------------:|:-----------------------:|--------------------------------------------------------------------|
| `cn`                       | ✔              | ✔ (RDN is `ou` though)  | `cn` not RDN on OU; allowed but not used.                          |
| `ou`                       | ✘              | ✔ (RDN)                 | RDN attribute (rDNAttID = 2.5.4.11).                               |
| `gPLink`                   | ✘              | ✔                       | GP ignores `gPLink` on `container`.                                |
| `gPOptions`                | ✘              | ✔                       | Bit 1 = block inheritance.                                         |
| `managedBy`                | ✔              | ✔                       | Reference to a user/group responsible.                             |
| `streetAddress`/`st`/`l`   | ✘              | ✔                       | Address metadata on OU.                                            |
| `description`              | ✔              | ✔                       | Free-text.                                                         |

## Troubleshooting

- **`objectClassViolation` when moving user to OU** — Target DN's parent is not an `organizationalUnit` or `domainDNS`. Check `systemPossSuperiors` on the source object's class.
- **`unwillingToPerform` moving `CN=Users` → `OU=Users`** — Cannot rename the built-in `Users` container; create an OU elsewhere and migrate accounts.
- **`gPLink` ignored on `CN=System` subtree** — `container` class does not process GP. Move child objects into an OU under the domain root and re-link.
- **Cross-domain move fails with `constraintViolation` on `servicePrincipalName`** — Strip all SPNs before the move, re-add appropriate ones after.
- **Move fails with `referral`** — Wrong NC. Bind to the GC (`GC://`) for cross-NC enumeration but use `LDAP://` against the source-DC for the actual move.
- **`Move-ADObject -TargetServer` succeeds but `memberOf` not migrated** — Cross-domain move only migrates the object; group memberships across NC boundaries are rewritten as foreign-SID references. Use `Move-ADObject` followed by re-adding to groups in the target domain.

## Cross-platform equivalents

- **Linux — 389-DS / OpenLDAP**: No OU/container distinction in capability — both are LDAP entries and any node may have a child of any structural class allowed by `objectClass`. No equivalent of `gPLink`. Indexing equivalent is in `cn=config` per attribute. See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **Linux — FreeIPA**: Uses a fixed tree (`cn=accounts`, `cn=groups`, `cn=hosts`, `cn=services`) under each domain suffix; admin cannot reshape it. No well-known GUIDs. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **macOS — OpenDirectory**: Flat hierarchy with `/Users`, `/Groups`, `/Computers`, `/Locations` nodes; no OU concept. See `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.

## References

- MS-ADTS §3.1.1.2.2 — `instanceType`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/4e60634f-0e9f-4f6b-96d3-fb3962f5e2c0>
- MS-ADTS §3.1.1.2.4.1 — `systemFlags`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/70339f4a-9d24-404b-a3f8-79364677c4a0>
- MS-ADTS §6.1.1 — Well-Known Objects GUID table. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/b6459df2-c57e-4700-8f00-e1c8c1f6e4c0>
- MS-ADTS §3.1.1.3.4 — Cross-Domain Move (`LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID`). <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/49b0d4c6-9c5f-4d3b-8d49-9f4c2e7b8c5a>
- RFC 4511 §4.9 — ModifyDNRequest. <https://www.rfc-editor.org/rfc/rfc4511#section-4.9>
- `ntdsa.dll! SampModifyCrossDomainMove` — source path referenced in Samba `source4/dsdb/samdb/ldb_modules/objectclass.c`.
