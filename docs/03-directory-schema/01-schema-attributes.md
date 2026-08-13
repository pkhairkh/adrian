---
title: Schema Internals — attributeSchema, classSchema, OID Allocation, and Schema Update
audience: senior-engineers
tags: [schema, attributeschema, classschema, oid, searchflags, schemaupdate, objectversion]
related:
  - ./02-ous-containers.md
  - ./03-global-catalog.md
  - ./05-replication-internals.md
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
last_updated: 2026-08-13
---

The AD schema is itself a set of objects stored in `CN=Schema,CN=Configuration,<forest-root-dn>` — `attributeSchema` and `classSchema` instances — that the DSA loads into an in-memory hash table at boot (`ntdsa.dll!SCCacheUpdate`) and uses to validate every LDAP write, with each attribute tagged by a globally-unique X.500 OID assigned from the Microsoft private enterprise arc `1.2.840.113556.1.x`.

## Schema NC layout

```
CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com
 ├── CN=Aggregate (root of partial-attribute-set metadata)
 ├── CN=DisplaySpecifiers,CN=<locale-409>     (UI hints, adminContextMenu, etc.)
 ├── CN=Extended-Rights                        (controlAccessRight objects)
 ├── CN=LostAndFoundConfig
 ├── CN=Partitions                             (crossRef objects per NC)
 ├── CN=WellKnown Security Principals          (S-1-5-* aliases)
 ├── CN=<Class>, objectClass=classSchema        (e.g. CN=User, CN=Computer, CN=Group)
 └── CN=<Attr>,  objectClass=attributeSchema    (e.g. CN=User-Principal-Name)
```

Two objectClass values define the schema:

- `attributeSchema` (governsID `1.2.840.113556.1.5.18`) — one object per attribute.
- `classSchema` (governsID `1.2.840.113556.1.5.4`) — one object per class.

The schema NC is replicated forest-wide but only writable on the DC holding the **Schema Master** FSMO (default: first DC in the forest root). The schema NC head is `CN=Schema,CN=Configuration,...` with `instanceType = 0x4` (`IT_NC` — naming context head, not writable for non-FSMO).

## attributeSchema object — attribute table

| Attribute                  | OID / Syntax                              | Purpose                                                                |
|----------------------------|-------------------------------------------|------------------------------------------------------------------------|
| `cn`                       | 2.5.4.3 / DN-String (syntax tag 2.5.5.1)  | RDN (legacy "Common-Name" — usually the Windows-2000 era mixed-case display name, e.g. `User-Principal-Name`) |
| `lDAPDisplayName`          | 2.16.840.1.113730.3.1.241 / DirectoryString | Name visible to LDAP clients (e.g. `userPrincipalName`). MUST be unique forest-wide. Picked by `MakeLDAPDisplayName()` from the `cn`, dashes→camelCase. |
| `adminDisplayName`         | 2.16.840.1.113730.3.1.241 / DirectoryString | Display in ADUC / ADSI Edit snap-ins.                                   |
| `attributeID`              | 2.5.21.7 / OID                             | X.660 OID identifying the attribute. e.g. `1.2.840.113556.1.4.666` (UPN). MUST be unique. |
| `attributeSyntax`          | 2.5.21.7 / OID                             | X.500 abstract syntax (e.g. `2.5.5.12` = DirectoryString, `2.5.5.6` = Object-Identifier, `2.5.5.16` = LargeInteger, `2.5.5.9` = Integer). |
| `oMSyntax`                 | 2.5.21.7 / Integer                         | X.520 concrete syntax (e.g. 64 = caseExactString, 20 = IA5String, 27 = ObjectSecurityDescriptor). |
| `oMObjectClass`            | 2.5.21.7 / OctetString                     | 12-byte X.650 class identifier. Common: `58 73 0a 06 95 1d b8 9c 5c d8 5f 91` (DSLDAP_NAME) for objects, `58 73 0a 0c ...` for SDs. |
| `isSingleValued`           | 2.5.21.7 / Boolean                         | TRUE → only one value per object; stored in `datatable` directly. FALSE → stored in `linktable` if linked, else in LV-tree. |
| `systemOnly`               | 2.5.21.7 / Boolean                         | TRUE → cannot be added/modified/deleted via LDAP; only the DSA may write it (e.g. `objectGuid`, `whenCreated`). |
| `searchFlags`              | 2.5.21.7 / Integer                         | Bitmask controlling indexing — see below.                              |
| `schemaFlagsEx`            | 2.5.21.7 / Integer                         | Extended bitmask (bit 1 = `SCHEMA_FLAG_ATTR_IS_CRITICAL`). Used for base-schema attributes. |
| `isMemberOfPartialAttributeSet` | 2.5.21.7 / Boolean                    | TRUE → attribute replicated to Global Catalog. See `./03-global-catalog.md`. |
| `rangeLower` / `rangeUpper`| 2.5.21.7 / Integer                         | Min/max value (for ints) or string length (for strings).               |
| `linkID`                   | 2.5.21.7 / Integer                         | Even = forward link; forward+1 = backlink. e.g. `member`=3, `memberOf`=4. 0 = not linked. |
| `attributeSecurityGUID`    | 2.5.21.7 / String(UUID)                    | Property set GUID. ACEs can reference the GUID instead of each attribute. |
| `isDefunct`                | 2.5.21.7 / Boolean                         | TRUE = attribute marked deleted-but-not-removed; invisible to most clients. |
| `showInAdvancedViewOnly`   | 2.5.21.7 / Boolean                         | TRUE → hidden in ADUC standard view (most base-schema attributes).     |
| `mAPIID` / `attributeDisplayNames` | …                                  | Exchange/MAPI legacy / custom display name per-locale.                  |
| `msDS-IntId`               | … / Integer                                | Internal 32-bit ID assigned at schema add (used by SD table compression). |

### `searchFlags` bitmask (MS-ADTS §3.1.1.2.3)

| Bit | Mask    | Name                       | Effect                                                                                          |
|-----|---------|----------------------------|-------------------------------------------------------------------------------------------------|
| 0   | 0x0001  | fATTINDEX                  | Attribute indexed; enables `(&attr=*)` queries in milliseconds.                                 |
| 1   | 0x0002  | fPDNTATTINDEX              | Per-parent index (PDNT = parent DNT). Used for one-level searches on container children.        |
| 2   | 0x0004  | fANR                       | Ambiguous Name Resolution — auto OR of word-prefix matches against this attr. ANR-set defined per-schema (default: `sn`, `givenName`, `displayName`, `cn`, `mail`, `proxyAddresses`, `physicalDeliveryOfficeName`, `telephoneNumber`). |
| 3   | 0x0008  | fPRESERVEATON              | Preserve on tombstone (kept on the deleted object). Used for `member`, `sIDHistory`, `lastKnownParent`. |
| 4   | 0x0010  | fCOPY                      | Copied (clone semantics). Affects how the attribute behaves when the object is copied.          |
| 5   | 0x0020  | fTUPLEINDEX                | Tuple index — supports `*foo*` substring searches efficiently.                                 |
| 6   | 0x0040  | fSUBTREEATTRINDEX          | Subtree-attr index (Server 2012+). Allows indexed subtree searches for hierarchical attributes. |
| 7   | 0x0080  | fCONFIDENTIAL              | Confidential attribute. Read requires `CONTROL_ACCESS` right on the attribute's `attributeSecurityGUID`. Default for `msTPM-OwnerInformation`, `msDS-AzOperations*`, `UnicodePwd`-adjacent. |
| 8   | 0x0100  | fNEVERVALUEAUDIT           | Skip value-level audit (used when an attribute is replicated so frequently that per-value audit floods the log). |
| 9   | 0x0200  | fRODCFILTEREDATTRIBUTE     | Not replicated to RODCs (added in Server 2008). See `msDS-NonMember` / `msDS-RevealedUsers`.   |
| 10  | 0x0400  | fEXTENDEDINDEX             | Extended index — additional storage for `>=`/`<=` range queries.                                |
| 11  | 0x0800  | fBASEONLYSCAN              | Index scoped to base-only search.                                                               |
| 12  | 0x1000  | fPARTITIONSECRET_ATTRIBUTE | RODC partition secret attribute.                                                                |

`schemaFlagsEx` extends with bit `0x1` (`SCHEMA_FLAG_ATTR_IS_CRITICAL` — attribute is required for DSA boot; cannot be made defunct).

## classSchema object

Key attributes:

| Attribute                  | Purpose                                                                                |
|----------------------------|----------------------------------------------------------------------------------------|
| `governsID`                | OID for the class (e.g. `1.2.840.113556.1.5.9` for `user`).                            |
| `lDAPDisplayName`          | LDAP-visible class name (e.g. `user`, `computer`, `group`).                            |
| `defaultObjectCategory`    | DN written to every instance's `objectCategory` attribute. Defaults to the class's own DN. |
| `objectClassCategory`      | 0=Abstract, 1=Structural, 2=Auxiliary, 3=88 (`structural`-like; legacy X.500).         |
| `subClassOf`               | DN of parent class. `user`→`organizationalPerson`→`person`→`top`.                      |
| `systemAuxiliaryClass`     | Always-attached auxiliary classes (cannot be removed at instance time).                |
| `systemMayContain`, `systemMustContain` | Schema-defined optional/mandatory attributes.                            |
| `mayContain`, `mustContain`| Administrator-extensible attribute lists (added later via schema modify).              |
| `possSuperiors`, `systemPossSuperiors` | Classes that can be parents. `user` permits `organizationalUnit`/`container`.  |
| `rDNAttID`                 | Attribute used as RDN (default 2.5.4.3=`cn`; for `organizationalUnit`=2.5.4.11=`ou`; for `domainDNS`=2.5.4.15=`dc`). |
| `defaultSecurityDescriptor`| SDDL written into every instance's `nTSecurityDescriptor` at create time.              |
| `schemaIDGUID`             | 16-byte UUID — referenced in ACEs (e.g. `bf967aba-0de6-11d0-a285-00aa003049e2` = `user`). |
| `isDefunct`                | Tombstoned class.                                                                       |
| `defaultHidingValue`       | Boolean — should new instances be hidden in ADUC.                                       |

## OID allocation

Microsoft base arc:

```
1.2.840.113556         Microsoft
   └── .1              Active Directory
        ├── .4.x       classSchema OIDs         (e.g. 1.2.840.113556.1.5.9 = user)
        ├── .5.x       attributeSchema OIDs     (e.g. 1.2.840.113556.1.4.666 = userPrincipalName)
        │              Notes:
        │              - .4.x = classes, .5.x = attributes (yes, intentionally reversed from governing-rdn order)
        │              - Server 2003: 1.2.840.113556.1.4.1500–1799 (shadow accounts, etc.)
        │              - Server 2008 R2: 1.2.840.113556.1.4.1860+ (managed service accounts)
        │              - Server 2012: 1.2.840.113556.1.4.2000+ (gMSA, fine-grained password)
        │              - Server 2016: 1.2.840.113556.1.4.2190+ (Privileged Access Management)
        │              - Server 2022: 1.2.840.113556.1.4.2300+ (AKA "AD 88")
        ├── .6.x       syntax OID
        └── .3.x       attributeSyntax
```

Private enterprise arc `1.3.6.1.4.1.<PEN>` — get a Private Enterprise Number from IANA, then allocate sub-arcs. Example schema extension:

```
1.3.6.1.4.1.54832       Contoso Inc.
   └── .1.x             AD schema additions
        ├── .1.x        classes
        ├── .2.x        attributes
        └── .3.x        syntax
```

Every custom attribute/class **MUST** use a unique OID. Tools:

- `oidgen.exe` (legacy, Microsoft) — generates a random OID rooted at `1.2.840.113556.1.8000.x.xxx` (Microsoft's reserved pool for ad-hoc use). Discouraged in production.
- `New-ADObject` with a manually-tracked OID arc (preferred).

## Schema update procedure

1. **Obtain schema-master FSMO**. On any DC, run `Get-ADDomainController -Discover -Service Schema` to find it. Connect to it specifically; LDAP writes against other DCs return `unwillingToPerform` (53).
2. **Verify schema write permission**. Account must be in `Schema Admins` (or have explicit `Write` on the schema NC head).
3. **Check current schema version**:
   ```powershell
   Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com" `
                -SearchScope Base -LDAPFilter '(objectClass=*)' `
                -Properties objectVersion
   ```
   `objectVersion` values:
   - 13 = Windows 2000
   - 30 = Server 2003
   - 31 = Server 2003 R2
   - 44 = Server 2008
   - 47 = Server 2008 R2
   - 56 = Server 2012
   - 61 = Server 2012 R2
   - 69 = Server 2016
   - 72 = Server 2019
   - 88 = Server 2022 (current as of 2026)
4. **Stage the schema modification** (e.g., add an attribute):
   ```ldif
   dn: CN=contoso-employeeID,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com
   changetype: add
   objectClass: attributeSchema
   lDAPDisplayName: contosoEmployeeID
   attributeID: 1.3.6.1.4.1.54832.2.1
   attributeSyntax: 2.5.5.12
   oMSyntax: 64
   isSingleValued: TRUE
   searchFlags: 1
   showInAdvancedViewOnly: FALSE
   ```
5. **Trigger `schemaUpdateNow`** — AD does not pick up schema changes until this operational attribute is written. (Trigger automatically after every schema write since Server 2008.)
   ```powershell
   Set-ADObject -Identity "CN=Aggregate,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com" `
                -Replace @{schemaUpdateNow=1}
   ```
   Internally, `ntdsa.dll!SCCacheUpdate` reloads the entire schema cache into the `g_SchemaCache` hash table. Existing LDAP connections continue using the previous cache for in-flight requests; new requests get the new cache. This is the **only** way to refresh the cache without restarting the DSA.
6. **Wait for replication** — `repadmin /syncall /A /d /e` or simply wait for inter-site replication (default 15-180 sec).
7. **Validate** by querying the new attribute on a test object. If a previously-cached LDAP client returns `No such attribute`, restart the client application to drop its cached schema.

### Schema cache reload registry

Manual reload via registry (forces reload on next request without restart):

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  └── Schema Update Allowed         (REG_DWORD) = 1   (write-enable schema FSMO)
```

The presence of `Schema Update Allowed = 1` is required for any schema write. Set it before connecting the schema MMC snap-in. ADUC will silently fail without it.

## Diagnostic — LDAP filter

Find all confidential attributes in the schema:

```ldap
ldapsearch -LLL -b "CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com" \
  "(&(objectClass=attributeSchema)(searchFlags:1.2.840.113556.1.4.804:=128))" \
  cn lDAPDisplayName attributeID
```

`1.2.840.113556.1.4.804` is the LDAP_MATCHING_RULE_BIT_AND rule. For ANR-indexed attrs:

```ldap
(searchFlags:1.2.840.113556.1.4.804:=2)
```

## Wireshark display filter

```
ldap && (ldap.attributeValue contains "attributeSchema" || ldap.objectClass == "attributeSchema")
```

For schema-replication traffic (DRSUAPI `DRSGetNCChanges` on the Schema NC):

```
dcerpc && dcerpc.opnum == 3 && dcerpc.pn_ioflags == 0x03   && frame contains "CN=Schema"
```

(The DC requesting schema replication prefixes the request with the schema NC head DN; the response contains REPLENTINs whose `pName` value starts with `CN=Schema,`.)

## PowerShell — bulk dump of schema for diff

```powershell
$root = (Get-ADRootDSE).configurationNamingContext
$schema = "CN=Schema,$root"

Get-ADObject -SearchBase $schema -LDAPFilter '(objectClass=attributeSchema)' `
             -Properties lDAPDisplayName, attributeID, attributeSyntax, oMSyntax,
                         isSingleValued, searchFlags, systemOnly, isMemberOfPartialAttributeSet,
                         schemaFlagsEx, linkID, isDefunct |
  Sort-Object lDAPDisplayName |
  Select-Object lDAPDisplayName, attributeID, attributeSyntax, oMSyntax,
                isSingleValued, searchFlags, systemOnly, isMemberOfPartialAttributeSet,
                schemaFlagsEx, linkID, isDefunct |
  Export-Csv -NoTypeInformation schema-dump.csv
```

## Python ldap3 — read a single attribute schema definition

```python
from ldap3 import Server, Connection, ALL

server = Server('dc01.corp.example.com', get_info=ALL)
conn = Connection(server, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

base = 'CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com'
conn.search(base,
            '(&(objectClass=attributeSchema)(lDAPDisplayName=userPrincipalName))',
            attributes=['cn', 'lDAPDisplayName', 'attributeID', 'attributeSyntax',
                        'oMSyntax', 'isSingleValued', 'searchFlags', 'systemOnly',
                        'isMemberOfPartialAttributeSet', 'schemaFlagsEx', 'linkID'])

for entry in conn.entries:
    print(entry.entry_to_json())
    # Decode searchFlags bitmask
    sf = int(entry.searchFlags.value)
    flags = []
    for bit, name in [(0,'fATTINDEX'),(1,'fPDNTATTINDEX'),(2,'fANR'),
                      (3,'fPRESERVEATON'),(5,'fTUPLEINDEX'),(6,'fSUBTREEATTRINDEX'),
                      (7,'fCONFIDENTIAL'),(8,'fNEVERVALUEAUDIT'),(9,'fRODCFILTEREDATTRIBUTE')]:
        if sf & (1 << bit): flags.append(name)
    print(f"searchFlags=0x{sf:x} -> {','.join(flags)}")
```

## Troubleshooting

- **`unwillingToPerform (53)` on schema write** — DC is not the schema master. Run `Move-ADDirectoryServerOperationMasterRole -Identity <targetDC> -OperationMasterRole SchemaMaster`.
- **`attributeID not unique`** — OID already in use. Check `CN=Schema,CN=Configuration,...` for the duplicate. Use a different OID arc; never reuse.
- **Schema cache not refreshing** — `schemaUpdateNow` write failed silently. Check event log for `NTDS General` event 1425 (schema cache reload failure). Force with `Restart-Service NTDS` (last resort; demotes all clients for ~30 sec).
- **`objectVersion` mismatch on DCs** — schema replication is hung. `repadmin /showreps /verbose` on the schema master, then `repadmin /syncall /A /d /e /q`.
- **Defunct attribute resurrected but not visible** — write `isDefunct=FALSE` AND set `schemaUpdateNow=1`. Tools that pre-fetched the schema (ADUC, third-party) must be restarted.

## Cross-platform equivalents

- **Linux — 389-DS / FreeIPA**: schema is in `cn=schema` under the userRoot backend. Attributes are `attributeTypes` and `objectClasses` values of `cn=schema` (RFC 4512 §4.1.3.1 / §4.1.4). No OID pre-allocation; admins pick their own arc. No FSMO — schema is replicated via 389-DS's own multimaster. See `../09-linux-equivalents/09-openldap-mit-kerberos.md` and `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — OpenLDAP**: schema lives in `cn=schema,cn=config` (cn=config backend, LDIF-on-disk) or in `slapd.conf` `include` directives. `olcAttributeTypes` / `olcObjectClasses` use the same RFC 4512 ASN.1 syntax. See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **macOS — OpenDirectory**: `slapd`-based with the Apple schema (auxiliary objectclasses prefixed `apple-`). Schema editing via `dscl -plaintext` against `/LDAPv3/127.0.0.1/Schema` or `Server.app → Open Directory → Schema`. No equivalent to `searchFlags` indexing (indexing is configured in `slapd.conf` per attribute). See `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.

## References

- MS-ADTS §3.1.1.2 — Schema. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/4e60634f-0e9f-4f6b-96d3-fb3962f5e2c0>
- MS-ADTS §3.1.1.2.3 — `searchFlags`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/64acd8a9-0a2b-4a45-bef0-f720b31b4127>
- MS-ADTS §3.1.1.2.7 — `schemaUpdateNow`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/f4d2a91b-5b04-49b1-bf4b-93f415263f17>
- RFC 4512 §4.1.3.1 (`attributeTypes`), §4.1.4 (`objectClasses`). <https://www.rfc-editor.org/rfc/rfc4512>
- IANA Private Enterprise Numbers — apply for a PEN at <https://www.iana.org/assignments/enterprise-numbers>
- Samba `source4/setup/AD/` schema templates and `source4/dsdb/schema/schema_set.c` (`dsdb_attribute_by_lDAPDisplayName`).
