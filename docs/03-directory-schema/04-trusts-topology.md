---
title: Trusts — trustedDomain objects, trustDirection/Type/Attributes, trustAuthBlob, SID Filtering, Selective Auth, TGT Referral
audience: senior-engineers
tags: [trusts, trusteddomain, trustauthblob, sid-filtering, selective-authentication, tgt-referral]
related:
  - ./01-schema-attributes.md
  - ./03-global-catalog.md
  - ./05-replication-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/08-spn-upn-pac.md
last_updated: 2026-08-13
---

An AD trust is a `trustedDomain` object in the `System` container of the trusting domain (`CN=<NetBIOS-name-of-trusted>,CN=System,DC=...`) carrying the trust direction, type, attributes, the encrypted inter-domain trust password (`trustAuthBlob`), the trusted domain's NetBIOS name (`flatName`) and SID (`securityIdentifier`), and enforcing cross-realm authentication via RFC 4120 §3.3.3 TGT referral — with SID filtering (default since Server 2003) and optional selective authentication gates applied at the boundary.

## trustedDomain object

Class: `trustedDomain` (governsID `1.2.840.113556.1.5.165`).

Located at `CN=<trusted-flatname>,CN=System,<domain-dn>`. The RDN `cn` is the trusted domain's NetBIOS name (uppercase). Both sides of a trust have their own trustedDomain object — bidirectional trust = two objects, one in each domain, each pointing at the other.

### Attributes

| Attribute                    | OID                                 | Type          | Purpose                                                                                                          |
|------------------------------|-------------------------------------|---------------|------------------------------------------------------------------------------------------------------------------|
| `cn`                         | 2.5.4.3                             | DirectoryString| RDN — trusted domain's flat NetBIOS name (uppercased).                                                            |
| `trustDirection`             | 1.2.840.113556.1.4.1354             | Integer       | 0=disabled, 1=inbound (trusting), 2=outbound (trusted), 3=bidirectional.                                         |
| `trustType`                  | 1.2.840.113556.1.4.1355             | Integer       | 1=downlevel (NT4), 2=uplevel (Windows 2000+), 3=MIT (Kerberos realm), 4=DCE (historical, unused).                |
| `trustAttributes`            | 1.2.840.113556.1.4.1353             | Integer       | Bitmask — see below.                                                                                              |
| `flatName`                   | 1.2.840.113556.1.4.1356             | DirectoryString| NetBIOS name of trusted domain.                                                                                  |
| `securityIdentifier`         | 1.2.840.113556.1.4.1515             | OctetString   | Trusted domain's SID (e.g. `S-1-5-21-...`). For MIT realm trusts, this attribute is absent.                       |
| `trustAuthBlob`              | 1.2.840.113556.1.4.1357             | OctetString   | Encrypted trust authentication material (outgoing and incoming passwords). Encrypted with the local DC's master key. |
| `trustAuthIncoming`          | (derived)                           | —             | Decrypted portion of `trustAuthBlob` for incoming auth (we accept this from partner). Stored in `lsass.exe` cache.|
| `trustAuthOutgoing`          | (derived)                           | —             | Decrypted portion of `trustAuthBlob` for outgoing auth (we send this to partner).                                 |
| `msDS-TrustForestTrustInfo`  | 1.2.840.113556.1.4.2070             | OctetString   | Forest trust TLV records (names and SIDs exempted from SID filtering).                                           |
| `msDS-SupportedEncryptionTypes` | 1.2.840.113556.1.4.2106          | Integer       | Kerberos etypes the trusted realm supports (bitmap, RFC 3961 §8).                                                 |
| `name`                       | 2.5.4.41                            | DirectoryString| Same as `flatName` typically.                                                                                    |
| `whenChanged`, `whenCreated` | (standard)                          | GeneralizedTime| Trust creation/modify timestamps.                                                                                |

### `trustDirection` values

| Value | Name        | Trusting domain says...                                                       |
|-------|-------------|-------------------------------------------------------------------------------|
| 0     | Disabled    | Trust object exists but is dormant.                                            |
| 1     | Inbound     | "I (the trusting domain) trust users from the trusted domain to access me."   |
| 2     | Outbound    | "My users can be authenticated by the trusted domain."                        |
| 3     | Bidirectional | Both. Most common.                                                          |

### `trustType` values

| Value | Name     | Use case                                                            |
|-------|----------|---------------------------------------------------------------------|
| 1     | Downlevel | Trusted realm is NT 4.0 (NTLM-only, no Kerberos).                    |
| 2     | Uplevel   | Trusted realm is Windows 2000+ (Kerberos cross-realm + NTLM fallback).|
| 3     | MIT       | Trusted realm is non-AD Kerberos (MIT KDC, Heimdal, etc.). No NTLM. |
| 4     | DCE       | Historical; not used.                                                |

### `trustAttributes` bitmask (MS-ADTS §6.1.6.7.9)

| Bit | Mask    | Name                       | Meaning                                                                                                                              |
|-----|---------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| 0   | 0x0001  | TRUST_ATTRIBUTE_NON_TRANSITIVE | Trust does NOT transit. Users from this domain cannot use the trust to reach further trusted domains.                          |
| 1   | 0x0002  | TRUST_ATTRIBUTE_UPLEVEL_ONLY   | Trust is uplevel-only; NTLM fallback disabled.                                                                                 |
| 2   | 0x0004  | TRUST_ATTRIBUTE_QUARANTINED   | Domain is quarantined. SID filtering is enforced; sIDHistory is stripped; admin privileges do not transit. (For untrusted domains.) |
| 3   | 0x0008  | TRUST_ATTRIBUTE_FOREST_TRANSITIVE | Forest trust (Windows 2003 forest-level). Implies transitive across the entire trusted forest.                              |
| 4   | 0x0010  | TRUST_ATTRIBUTE_CROSS_ORGANIZATION | Cross-organization trust; selective authentication required.                                                                |
| 5   | 0x0020  | TRUST_ATTRIBUTE_WITHIN_FOREST   | Trust is between two domains in the same forest (implicit, auto-created).                                                    |
| 6   | 0x0040  | TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL | Treat as external for SID filtering purposes (forces external-trust-style filtering even within a forest).                  |
| 7   | 0x0080  | TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION | Trust uses RC4 for the cross-realm key (legacy).                                                                             |
| 8   | 0x0100  | TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION | TGTs from this domain cannot be delegated (sensitive-for-delegation). Equivalent to "Enable strict target server behavior". |
| 9   | 0x0200  | TRUST_ATTRIBUTE_PIM_TRUST      | Privileged Access Management trust (Forest trust with user-level isolation; Server 2016+).                                    |
| 10  | 0x0400  | TRUST_ATTRIBUTE_CROSS_ORGANIZATION_TGT_DELEGATION | TGTs from this domain may be delegated (overrides the default block on cross-org delegation; requires explicit admin opt-in). |
| 11  | 0x0800  | TRUST_ATTRIBUTE_DISABLE_AUTH_TARGET_VALIDATION | Skip target SPN validation in the referral.                                                                                   |

The combination `(WITHIN_FOREST=0x20) && (FOREST_TRANSITIVE=0x8)` is the implicit trust between parent and child domains in a tree (automatically created at child-domain DCPromo). External trusts to other forests use `TRUST_ATTRIBUTE_NON_TRANSITIVE=0x1` by default.

## `trustAuthBlob` — structure

`trustAuthBlob` is an encrypted binary attribute. Encryption: LSA secret-style encryption (`lsasrv.dll!LsaICryptEncrypt`) using the local DC's `G$` secret key. Decrypted plaintext is an `LSA_AUTH_INFORMATION` array:

```c
typedef struct _TRUSTED_DOMAIN_AUTH_BLOB {
    ULONG                   IncomingAuthInfos;       // count of incoming auth entries
    LSA_AUTH_INFORMATION    IncomingAuthInformation[IncomingAuthInfos];
    ULONG                   OutgoingAuthInfos;
    LSA_AUTH_INFORMATION    OutgoingAuthInformation[OutgoingAuthInfos];
} TRUSTED_DOMAIN_AUTH_BLOB;

typedef struct _LSA_AUTH_INFORMATION {
    LARGE_INTEGER   LastUpdateTime;          // FILETIME (UTC)
    ULONG           AuthType;                // 1=NTLM, 2=VERIFIER (verifier for trust), 3=Kerberos (5 for AES)
    ULONG           AuthInfoLength;
    [size_is(AuthInfoLength)] PUCHAR AuthInfo;
} LSA_AUTH_INFORMATION;
```

For a Kerberos uplevel trust (`AuthType = 2`), `AuthInfo` contains the UTF-16LE trust password bytes. For NTLM downlevel (`AuthType = 1`), `AuthInfo` contains both the Unicode password (16 bytes) and an LM hash (16 bytes), packed as `UnicodePW\0\0\0\0LMHash`. For AES (`AuthType = 5` since Server 2012), `AuthInfo` is the AES-256 cross-realm long-term key directly.

The DC uses this key as input to `string-to-key` for the `krbtgt/<trusted-realm>` cross-realm principal in its local Kerberos database — see `kdcsvc.dll!KdcGetCrossRealmKey`.

Read decrypted (PowerShell as Domain Admin):

```powershell
$td = Get-ADObject -Filter 'objectClass -eq "trustedDomain"' -Properties trustAuthBlob, flatName
# trustAuthBlob is encrypted; need to use LSA APIs to decrypt.
# Use netdom.exe or NLTest to get cleartext trust password (if any):
nltest /domain_trusts /server:dc01
```

## Cross-realm authentication — TGT referral

Per RFC 4120 §3.3.3 ("Cross-Realm Operation"). When a client in domain A requests a service ticket for a service in domain B (with a trust):

1. Client sends TGS-REQ for `cifs/server.b.example.com@B.EXAMPLE.COM` to its own KDC (A's KDC).
2. A's KDC sees the requested realm is `B.EXAMPLE.COM`. It looks up the trustedDomain object, finds the cross-realm key, and returns a TGT for the krbtgt principal of realm B (`krbtgt/B.EXAMPLE.COM@A.EXAMPLE.COM`) — a **referral TGT**, encoded as a TGS-REP with the referral ticket. Error code: `KDC_ERR_S_PRINCIPAL_UNKNOWN (6)` triggers referral.

3. Client receives the referral TGT and uses it as the credential for a second TGS-REQ to A's KDC, asking for a TGT for `krbtgt/B.EXAMPLE.COM@B.EXAMPLE.COM`. Wait — actually the client asks A's KDC for `krbtgt/B.EXAMPLE.COM@A.EXAMPLE.COM` first, then uses that to ask B's KDC for `cifs/server.b.example.com@B.EXAMPLE.COM`.

   More precisely (per RFC 4120):
   - TGS-REQ1 to A: `sname = krbtgt/B.EXAMPLE.COM@A.EXAMPLE.COM`
   - TGS-REP1 from A: TGT for B encrypted in the inter-realm key.
   - TGS-REQ2 to B (using TGT from step 1 as `KDC-REQ-BODY.kdc-rep-ticket`): `sname = cifs/server.b.example.com@B.EXAMPLE.COM`
   - TGS-REP2 from B: service ticket for `cifs/server.b.example.com`.

   If the trust chain is longer (A→B→C), this repeats for each hop. The accumulated extra TGTs are stored in a "TGT cache" (`ccache`) keyed by realm.

4. B's KDC, when issuing the service ticket, applies **SID filtering** to the PAC: only SIDs from B's domain (or transitively trusted domains where the trust chain permitted) are preserved in the new PAC's `ExtraSids`. The `sIDHistory` from A's PAC is stripped unless `TRUST_ATTRIBUTE_QUARANTINED` is unset AND the trust is within the forest (WITHIN_FOREST bit set).

5. B's service receives the ticket, validates the PAC. The `ExtraSids` from A are now present in the user's token.

## SID filtering

Default behavior:

| Trust type                          | SID filtering | `sIDHistory` | Explanation                                                                                          |
|-------------------------------------|:-------------:|:------------:|------------------------------------------------------------------------------------------------------|
| External (NON_TRANSITIVE=0x1)       | ON            | STRIPPED     | Old NT4-style external trusts. Quarantined.                                                          |
| Forest trust (FOREST_TRANSITIVE=0x8)| ON (per-domain) | PERMITTED for exempted | Per-domain exemptions in `msDS-TrustForestTrustInfo`.                                              |
| Within-forest (WITHIN_FOREST=0x20)  | OFF           | PERMITTED    | sIDHistory migration within the same forest is allowed.                                              |
| PIM trust (PIM_TRUST=0x200)         | ON            | STRIPPED     | Privileged Access Management; user isolation.                                                        |
| Quarantined (QUARANTINED=0x4)       | ON            | STRIPPED     | Even within a forest, this flag forces external-trust-style filtering.                              |

Toggle SID filtering (admin):

```
netdom trust <trusting-domain> /domain:<trusted-domain> /quarantine:No  /userD:admin /passwordD:*
netdom trust <trusting-domain> /domain:<trusted-domain> /enablesidhistory:Yes
```

`/quarantine:No` enables `sIDHistory` flow (only safe in migration scenarios). `/quarantine:Yes` is the default.

Microsoft has enforced SID filtering ON by default for all newly-created external trusts since Server 2003, and on forest trusts since Server 2008. Existing trusts created before these versions had to be re-configured.

## Selective authentication

When `trustAttributes` bit 4 (`CROSS_ORGANIZATION=0x10`) is set, the trust requires **selective authentication**. Users from the trusted domain can authenticate only to resources in the trusting domain where they have been explicitly granted the **"Allowed to Authenticate"** extended-right (controlAccessRight) on the resource computer object.

Extended right GUID: `68b1d179-0d15-4d4f-ab71-46152e79a7bc` (`Allowed-To-Authenticate`).

```powershell
# Grant "Allowed to Authenticate" to CORP\jdoe on SERVER01
$ace = New-ADObject -Type "AccessControlEntry" `
        -Properties @{
            AccessControlType = "Allow"
            ObjectType = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"   # Allowed-To-Authenticate
            IdentityReference = "CORP\jdoe"
            ActiveDirectoryRights = "ExtendedRight"
            InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"  # computer class
        }
# or via dsacls:
dsacls \\corp.example.com\CN=SERVER01,OU=Servers,DC=corp,DC=example,DC=com /G "CORP\jdoe:CA;Allowed to Authenticate"
```

Without this ACE, a cross-trust user receives `KRB_ERR_GENERIC` (or the SMB layer returns `STATUS_ACCESS_DENIED`). The event log on the resource server logs `LSA` event 4662 with `Accesses: Allowed to Authenticate` failed.

## Wireshark display filter

TGT referral Kerberos traffic across the trust:

```
kerberos && (kerberos.msg_type == 13 || kerberos.msg_type == 14)   # TGS-REQ / TGS-REP
&& kerberos.realm == "B.EXAMPLE.COM"
```

For referral error:

```
kerberos.error_code == 6    # KDC_ERR_S_PRINCIPAL_UNKNOWN
```

For PAC cross-realm:

```
kerberos && frame contains "ExtraSids"
```

## PowerShell — enumerate all trusts

```powershell
# 1. List all trustedDomain objects with all attributes
Get-ADObject -Filter 'objectClass -eq "trustedDomain"' -Properties * |
  Select-Object cn, flatName, trustDirection, trustType, trustAttributes,
                securityIdentifier, msDS-TrustForestTrustInfo,
                msDS-SupportedEncryptionTypes, whenCreated, whenChanged

# 2. Decode trustAttributes bitmask
$flags = @{
  0x0001 = 'NON_TRANSITIVE'
  0x0004 = 'QUARANTINED'
  0x0008 = 'FOREST_TRANSITIVE'
  0x0010 = 'CROSS_ORGANIZATION'
  0x0020 = 'WITHIN_FOREST'
  0x0040 = 'TREAT_AS_EXTERNAL'
  0x0100 = 'CROSS_ORG_NO_TGT_DELEGATION'
  0x0200 = 'PIM_TRUST'
  0x0400 = 'CROSS_ORG_TGT_DELEGATION'
}

Get-ADObject -Filter 'objectClass -eq "trustedDomain"' -Properties trustAttributes |
  ForEach-Object {
    [PSCustomObject]@{
      Name  = $_.cn
      Value = $_.trustAttributes
      Flags = ($flags.Keys | Where-Object { $_.trustAttributes -band $_ } | ForEach-Object { $flags[$_] }) -join ','
    }
  }

# 3. nltest alternative
nltest /domain_trusts /server:dc01 /all_trusts /v
```

## Python ldap3 — read trust objects

```python
from ldap3 import Server, Connection, ALL, SUBTREE
import struct

server = Server('dc01.corp.example.com', get_info=ALL)
conn = Connection(server, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

base = 'CN=System,DC=corp,DC=example,DC=com'
conn.search(base, '(objectClass=trustedDomain)',
            search_scope=SUBTREE,
            attributes=['cn', 'flatName', 'trustDirection', 'trustType',
                        'trustAttributes', 'securityIdentifier',
                        'msDS-SupportedEncryptionTypes',
                        'msDS-TrustForestTrustInfo'])

flag_names = {
    0x001:'NON_TRANSITIVE',0x004:'QUARANTINED',0x008:'FOREST_TRANSITIVE',
    0x010:'CROSS_ORGANIZATION',0x020:'WITHIN_FOREST',0x040:'TREAT_AS_EXTERNAL',
    0x100:'NO_TGT_DELEGATION',0x200:'PIM_TRUST',0x400:'TGT_DELEGATION'}

for entry in conn.entries:
    ta = int(entry.trustAttributes.value)
    flags = ','.join(n for b,n in flag_names.items() if ta & b)
    sid_raw = entry.securityIdentifier.value
    sid = 'S-' + '-'.join(str(x) for x in
              struct.unpack('<IQQ', sid_raw[8:24])) if sid_raw else None
    print(f"{entry.cn.value}: dir={entry.trustDirection.value} type={entry.trustType.value} flags=0x{ta:x} ({flags}) sid={sid}")
```

## Registry / attribute table — KDC trust-related settings

```
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
  ├── AvoidPdcOnWan                 (REG_DWORD)  = 0   (use PDC for trust-password changes)
  ├── DisablePasswordChange         (REG_DWORD)  = 0   (if 1, trust password never rotates)
  ├── MaximumPasswordAge            (REG_DWORD)  = 30  (days; trust password rotation interval)
  ├── ScavengeFile                  (REG_DWORD)  = ...
  ├── StronglyEncryptDatagram       (REG_DWORD)  = 1   (use AES for netlogon secure channel)
  └── RequireSignOrSeal             (REG_DWORD)  = 1

HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  ├── FullPrivilegeAuditing         (REG_BINARY)
  ├── LsaDbDtcpFirst                (REG_DWORD)  = 0
  ├── NoLmHash                      (REG_DWORD)  = 1   (no LM hash)
  ├── RestrictAnonymous             (REG_DWORD)  = 0
  └── LSA_FOREST_TRUST_INFO         (REG_DWORD)  = 1   (enable forest trust TLV records)
```

Trust password rotation: every 30 days (default), the PDC emulator of the trusting domain changes the outgoing password. The change is pushed via `netlogon.dll!I_NetServerPasswordSet2` to the trusted domain's PDC. The current password and the previous one (for overlap) are both stored in the `trustAuthBlob`.

## Troubleshooting

- **`KDC_ERR_S_PRINCIPAL_UNKNOWN (6)`** — Referral triggered. If it persists: trust is broken or KDC cannot decrypt the referral TGT. Verify trust password with `nltest /verify` and `ksetup /DumpState`.
- **`KRB_AP_ERR_TGT_NOSRV`** — Cross-realm SPN not registered on the target. Add the `cifs/server.b.example.com@B.EXAMPLE.COM` SPN explicitly (rare; usually auto-handled).
- **SID history lost after migration** — Trust has `QUARANTINED=0x4` set or `NON_TRANSITIVE=0x1`. Disable with `netdom /quarantine:No` (only for within-forest migration).
- **Cross-trust users can't log on** — `Allowed to Authenticate` not granted (selective auth). Check `trustAttributes & 0x10`. Add ACE on the resource computer object.
- **Trust password desync** — Symptom: `nltest /verify` returns `Trust verification failed`. Reset: `netdom trust <trusting> /d:<trusted> /reset /pd /po /ud:admin /pd:*`.
- **Cross-forest GC query fails** — Forest trust not transitive (`NON_TRANSITIVE`). Verify `FOREST_TRANSITIVE=0x8` set and `WITHIN_FOREST=0x20` cleared. Re-create trust as forest trust.
- **Kerberos delegation across trust blocked** — Bit `CROSS_ORG_NO_TGT_DELEGATION=0x100` set. To enable constrained delegation across the trust, clear via PowerShell:
  ```powershell
  Set-ADObject -Identity "CN=B,CN=System,DC=A,DC=com" `
               -Replace @{trustAttributes=($curr -band (-bnot 0x100))}
  ```

## Cross-platform equivalents

- **Linux — FreeIPA**: trusts AD via `ipa trust-add` which creates an MIT trust. Forest trusts supported (FreeIPA 4.5+) but AD-side external-trust semantics. SID filtering is on by default. See `../09-linux-equivalents/01-sssd-ad-provider.md` and `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **Linux — Samba 4 AD DC**: re-implements `trustedDomain` objects and the LSA trust APIs in `source4/rpc_server/lsa/`. Cross-realm Kerberos via `samba-tool domain trust create`. See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux — MIT Kerberos standalone**: cross-realm via `kadmin -q "add_principal krbtgt/B.COM@A.COM"` and the same password on both realms. No SID filtering (Kerberos-only). See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **macOS — OpenDirectory**: trusts are stub entries in `/LDAPv3/.../Config/KerberosKDC`. No native AD-trust model; macOS uses bound-mode (AD plugin via `dsconfigad`) instead. See `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.

## References

- MS-ADTS §6.1.6.7.9 — `trustAttributes`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e8d2e7f0-c220-4781-a3c5-48e0e10a1f1c>
- MS-LSAD / MS-LSAR § — `LsarQueryTrustedDomainInfo` and `LsarSetTrustedDomainInfo`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-lsad>
- MS-KILE §3.4.5 — PAC cross-realm handling, `sIDHistory` filtering. <https://learn.microsoft.com/openspecs/windows_protocols/ms-kile>
- RFC 4120 §3.3.3 — Cross-Realm Operation. <https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3>
- RFC 4537 §6 — Kerberos cross-realm referral (newer referral style). <https://www.rfc-editor.org/rfc/rfc4537>
- "SID Filter Quarantine" — MS Learn Windows Server security. <https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-to-configure-sid-filtering>
- Samba `source4/rpc_server/lsa/lsa_init.c` and `lib/ldb_wrap/util.c` (trust object mapping).
