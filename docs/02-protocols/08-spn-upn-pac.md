---
title: SPN, UPN, PAC Deep-Dive — Uniqueness, Attributes, and PAC Buffer Layout
audience: senior-engineers
tags: [spn, upn, pac, ms-kile, ms-pac, krbtgt, ticket-signature, requester, krb5-validation]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../08-macos-equivalents/05-kerberos-sso-extension.md
last_updated: 2026-08-13
---

Service Principal Names (SPNs), User Principal Names (UPNs), and the Privilege Attribute Certificate (PAC) are the three identity-binding constructs layered on top of RFC 4120 Kerberos in Active Directory: SPNs are stored as the multi-valued `servicePrincipalName` attribute (schema OID 1.2.840.113556.1.4.14) and enforced unique per-forest by the KDC via a `DRSWriteSPN` pre-commit check; UPNs are stored as the single-valued `userPrincipalName` attribute (OID 1.2.840.113556.1.4.666) with the suffix list maintained on the `CN=Partitions,CN=Configuration,...` object's `uPNSuffixes` attribute; and the PAC is the NDR-encoded authorization blob (MS-PAC) carried inside the Kerberos Ticket's `authorization-data`, populated by the KDC at AS-REQ time and signed twice with the `krbtgt` key (once over the PAC itself, once over the entire Ticket.enc-part as of Server 2016+).

## Service Principal Names (SPNs)

### Format

```
serviceclass/host:port/servicename@REALM

Examples:
  cifs/dc01.example.com                          (SMB file service on a DC)
  cifs/dc01                                       (NetBIOS form)
  HOST/dc01.example.com                           (generic — Host SPN)
  HOST/dc01.example.com/example.com               (servicename = domain)
  ldap/dc01.example.com/example.com               (LDAP)
  GC/dc01.example.com/example.com                 (Global Catalog)
  E3514235-8B63-11D0-A26C-00A0C92B955C/dc01.example.com/example.com   (DRSUAPI — uses the interface UUID as serviceclass)
  HTTP/web01.example.com                          (IIS / Negotiate auth)
  MSSQLSvc/sql01.example.com:1433                 (SQL Server with explicit port)
  MSSQLSvc/sql01.example.com:PROD                 (SQL Server with named instance)
  HTTP/sharepoint.example.com                     (SharePoint)
  kadmin/changepw                                 (password-change service)
  kpassword                                       (kpasswd)
```

The `serviceclass` is case-insensitive. The `host` portion is the FQDN of the host (or NetBIOS name in legacy). The `servicename` (optional) is typically the domain or forest DNS name. The `@REALM` is optional and almost never used in AD because the realm is implied by the user's domain.

### Storage in AD

The SPN is stored as the multi-valued `servicePrincipalName` attribute on the service account (a user account, computer account, or gMSA):

| Schema attribute | OID | Syntax | Indexed? |
|---|---|---|---|
| `servicePrincipalName` | 1.2.840.113556.1.4.14 | `Object(DS-DN)` (string) | Yes (`searchFlags` bit 1) |
| `userPrincipalName` | 1.2.840.113556.1.4.666 | `String(Unicode)` | Yes |
| `sAMAccountName` | 1.2.840.113556.1.4.221 | `String(Unicode)` | Yes |
| `dNSHostName` | 1.2.840.113556.1.4.1241 | `String(Unicode)` | Yes |

The attribute's index is critical — the KDC's SPN lookup at TGS-REQ time is a global catalog query by `servicePrincipalName = "<the SPN>"`. Without the index, this query would be a forest-wide table scan.

### Uniqueness enforcement

SPNs are enforced unique at the forest level. The KDC enforces uniqueness via `DRSWriteSPN` (opnum 13 of DRSUAPI, see `02-protocols/06-rpc-dcerpc-ms-drsr.md`):

```
DRSWriteSPN(hDrs, dwInVersion, pMsgIn)
  pMsgIn.V1.pwszAccountObj = <DN of the account being modified>
  pMsgIn.V1.cSPN = N
  pMsgIn.V1.rpSPN[] = array of SPN string operations
  pMsgIn.V1.rpSPN[i].code = DRS_ADD_SPN | DRS_REMOVE_SPN | DRS_CHECK_SPN
```

When the KDC handles a modify that adds an SPN to `servicePrincipalName`, it calls `DRSWriteSPN` with `DRS_ADD_SPN`. The DSA on the schema master checks the GC for any existing account with the same SPN:

- If exactly one existing account has the SPN, return `ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST (8647)`.
- If zero existing accounts have it, the write succeeds and is replicated to all DCs.

This check is performed by the DC that processes the LDAP modify (any DC), not by the schema master — because every DC has a GC. The check happens at pre-commit time inside the ESE transaction.

#### `setspn -X` duplicate detection

```cmd
setspn -X                    # forest-wide duplicate scan
setspn -X -P                 # also include pending accounts (with PROVISIONING_ADMIN)
```

Internally, `setspn.exe` issues an LDAP paged search across all naming contexts, collecting every `servicePrincipalName` value, then hashing and reports duplicates. This is the canonical pre-flight check before any Kerberos deployment.

### SPN registration tools

```cmd
# Register an SPN on an account
setspn -S HTTP/web01.example.com EXAMPLE\web-svc        # -S = add with uniqueness check
setspn -A HTTP/web01.example.com EXAMPLE\web-svc        # -A = add without check (dangerous)

# List SPNs on an account
setspn -L EXAMPLE\web-svc
# Or via AD PowerShell
Get-ADUser -Identity web-svc -Properties servicePrincipalName | Select -Expand servicePrincipalName

# Find which account owns an SPN
setspn -Q HTTP/web01.example.com
# Or via LDAP filter:
# (servicePrincipalName=HTTP/web01.example.com)
```

### Cross-realm behavior

When a client requests a service ticket for an SPN whose service account is in another domain in the same forest, the KDC:

1. Looks up the SPN in its local NC — not found.
2. Returns a TGS-REP with a referral ticket to the next domain in the trust path (`sname = krbtgt/<next-realm>`).
3. Client follows the referral chain by submitting each TGT to the next KDC, until the destination KDC resolves the SPN.

Cross-forest (forest trust) works the same way but the forest-root KDC's referral list is published via `msDS-TrustForestTrustInfo` on the `trustedDomain` object.

## User Principal Names (UPNs)

### Format

```
user@UPN-suffix

Examples:
  jdoe@example.com          (default UPN suffix = forest-root DNS name)
  jdoe@corp.example.com     (alternate suffix, if listed in CN=Partitions,.../uPNSuffixes)
  jdoe@sales.example.com    (alternate suffix tied to a child domain's DNS)
```

The UPN is RFC 822-style (`user@domain`). It is the user-friendly login name; `sAMAccountName` + domain (the `DOMAIN\user` form) is the legacy NTLM-style login name. Both work for Kerberos and NTLM.

### Storage

- Stored as the single-valued `userPrincipalName` attribute on the user object.
- The UPN suffix (right side of `@`) is one of:
  - The forest-root DNS name (always allowed).
  - A child domain's DNS name (always allowed for users in that child).
  - An explicit entry in `uPNSuffixes` on `CN=Partitions,CN=Configuration,DC=forest-root,DC=...`.

To list all UPN suffixes:

```powershell
Get-ADObject -Identity "CN=Partitions,CN=Configuration,DC=example,DC=com" `
             -Properties uPNSuffixes | Select -Expand uPNSuffixes
```

To add a suffix:

```powershell
Set-ADObject -Identity "CN=Partitions,CN=Configuration,DC=example,DC=com" `
             -Add @{ uPNSuffixes = @("branch.example.com", "alt.example.com") }
```

### Uniqueness

UPNs are enforced unique within the forest. The KDC at AS-REQ time resolves the UPN to a `DSNAME` via `DRSCrackNames` (DS_USER_PRINCIPAL_NAME → DS_UNIQUE_ID_NAME). If multiple accounts match, `DRSCrackNames` returns `DS_NAME_ERROR_NOT_UNIQUE (8649)`. The KDC then refuses the AS-REQ with `KDC_ERR_C_PRINCIPAL_UNKNOWN (6)`.

AD itself does NOT enforce uniqueness at the LDAP-modify level (unlike SPNs) — duplicate UPNs are technically creatable but cause Kerberos failures. Run periodic duplicate detection:

```powershell
Get-ADUser -Filter * -Properties userPrincipalName |
    Where-Object { $_.userPrincipalName } |
    Group-Object userPrincipalName |
    Where-Object { $_.Count -gt 1 }
```

### UPN vs. SAM account name

| Property | UPN | sAMAccountName |
|---|---|---|
| Format | user@suffix | user |
| Scope | Forest | Domain |
| Max length | 1024 chars | 20 chars (legacy) / 256 (Server 2019+) |
| Login form | `user@corp.example.com` | `CORP\user` |
| Kerberos cname | `user@REALM` if `canonicalize=true` | `user` |
| Where stored | `userPrincipalName` attribute | `sAMAccountName` attribute |

## PAC structure (MS-PAC)

The PAC is a Microsoft-specific extension to Kerberos carrying the user's authorization data. Defined in MS-PAC. The PAC is stored as `AuthorizationData` of type `AD-WIN2K-PAC (128)` wrapped in `AD-IF-RELEVANT (0)`, inside the Ticket's `EncTicketPart.authorization-data`.

### Top-level layout

The entire PAC is a single NDR-encoded blob:

```
PACTYPE {
    ULONG       cBuffers;                   // count of PAC_INFO_BUFFER entries
    ULONG       Version;                    // always 0
    PAC_INFO_BUFFER[cBuffers];              // array of buffer descriptors
    BYTE        Buffers[cBuffers][];        // the actual buffer data, padded to 8-byte boundaries
}

PAC_INFO_BUFFER {
    ULONG       ulType;                     // buffer type (see table below)
    ULONG       cbBufferSize;               // size of buffer
    ULONG64     Offset;                     // byte offset from start of PACTYPE
}
```

NDR encoding notes: `ULONG64 Offset` is 8-byte aligned (NDR64-style even when NDR20). Buffers are padded to 8-byte boundaries between each entry. The signature buffers are at the end of the PAC.

### Buffer types

| ulType | Name | Notes |
|---|---|---|
| 0x00000001 | `PAC_LOGON_INFO` | `KERB_VALIDATION_INFO` — user SID, group SIDs, profile path, etc. Always present. |
| 0x00000002 | `PAC_CREDENTIAL_TYPE` | `PAC_CREDENTIAL_DATA` — encrypted NTLM credentials the KDC had at logon (only included when the user has reversible-encryption password OR a smart-card logon; default off). |
| 0x00000006 | `PAC_SIGNATURE_DATA` (server) | Server signature — keyed with the service's long-term key. |
| 0x00000007 | `PAC_SIGNATURE_DATA` (KDC) | KDC signature — keyed with the krbtgt key. |
| 0x0000000A | `PAC_CLIENT_INFO` | Client name + logon time (FILETIME). |
| 0x0000000B | `PAC_CONSTRAINED_DELEGATION` | S4U2proxy permitted SPNs (Server 2008+). |
| 0x0000000C | `PAC_UPN_DNS_INFO` | User's UPN + DNS domain name (Server 2008+). |
| 0x0000000D | `PAC_CREDENTIAL_INFO` | Encrypted client credentials (TLS-enabled). |
| 0x0000000E | `PAC_BUFFER_TICKET_CHECKSUM` | Ticket signature (Server 2016+) — KDC-side HMAC over the entire Ticket.enc-part. |
| 0x00000011 | `PAC_ATTRIBUTES_INFO` | Requestor info (Server 2012). |
| 0x00000012 | `PAC_REQUESTER` | Requester SID + machine SID (Server 2016, MS-KILE 6). |
| 0x00000013 | `PAC_FULL_CHECKSUM` | KDC-side checksum over the entire PAC including all signature buffers (Server 2016+). |

### KERB_VALIDATION_INFO (`PAC_LOGON_INFO`)

The largest and most-used buffer. NDR-encoded per `netlogon.h`:

```
typedef struct _KERB_VALIDATION_INFO {
    FILETIME            LogonTime;
    FILETIME            LogoffTime;
    FILETIME            KickOffTime;
    FILETIME            PasswordLastSet;
    FILETIME            PasswordCanChange;
    FILETIME            PasswordMustChange;
    RPC_UNICODE_STRING  EffectiveName;
    RPC_UNICODE_STRING  FullName;
    RPC_UNICODE_STRING  LogonScript;
    RPC_UNICODE_STRING  ProfilePath;
    RPC_UNICODE_STRING  HomeDirectory;
    RPC_UNICODE_STRING  HomeDirectoryDrive;
    USHORT              LogonCount;
    USHORT              BadPasswordCount;
    ULONG               UserId;                 // user's RID
    ULONG               PrimaryGroupId;         // typically 513 = Domain Users
    ULONG               GroupCount;
    PGROUP_MEMBERSHIP   GroupIds;               // array of group RIDs (in this domain)
    ULONG               UserFlags;
    USER_SESSION_KEY    UserSessionKey;
    RPC_UNICODE_STRING  LogonServer;
    RPC_UNICODE_STRING  LogonDomainName;
    ULONG               LogonDomainId;          // SID of the domain
    ULONG               Reserved1[2];
    ULONG               UserAccountControl;
    ULONG               SubAuthStatus;
    FILETIME            LastSuccessfulILogon;
    FILETIME            LastFailedILogon;
    ULONG               FailedILogonCount;
    ULONG               Reserved3;
    ULONG               SidCount;
    PKERB_SID_AND_ATTRIBUTES ExtraSids;          // SIDs outside this domain (universal groups, resource groups)
    ULONG               ResourceGroupDomainSidCount;
    PSID                ResourceGroupDomainSid;
    ULONG               ResourceGroupCount;
    PGROUP_MEMBERSHIP   ResourceGroupIds;
} KERB_VALIDATION_INFO;
```

The `ExtraSids` field is the canonical cross-domain group membership signal — for a user in `corp.example.com` accessing a resource in `branch.example.com`, the resource-domain KDC adds the universal group SIDs from `corp` to `ExtraSids` (this is what `msDS-IsFullPrincipal` and the global catalog query give the KDC at TGS time).

### PAC_SIGNATURE_DATA

```
typedef struct _PAC_SIGNATURE_DATA {
    ULONG  SignatureType;
    UCHAR  Signature[ANYSIZE_ARRAY];     // variable length
} PAC_SIGNATURE_DATA;
```

`SignatureType` values:

| Hex | Constant | Algorithm |
|---|---|---|
| `0xFFFFFF76` | `KERB_CHECKSUM_HMAC_MD5` | HMAC-MD5 (RC4 etype) — 16-byte signature. |
| `0x00000011` | `HMAC_SHA1_96_AES128` | HMAC-SHA1 truncated to 12 bytes — AES-128. |
| `0x00000012` | `HMAC_SHA1_96_AES256` | HMAC-SHA1 truncated to 12 bytes — AES-256. |
| `0x00000013` | `HMAC_SHA384_192_AES256` | HMAC-SHA-384 truncated to 24 bytes — AES-256 (RFC 8009, Server 2022+). |

The server signature (ulType 0x06) is computed over the entire PAC buffer with the server signature field zeroed. The KDC signature (ulType 0x07) is then computed over the entire PAC (including the now-filled server signature, with the KDC signature field zeroed) using the krbtgt key.

### PAC_CLIENT_INFO

```
typedef struct _PAC_CLIENT_INFO {
    FILETIME ClientId;            // logon time
    USHORT   NameLength;          // bytes
    WCHAR    Name[1];             // client name (NetBIOS-style, e.g. "jdoe")
} PAC_CLIENT_INFO;
```

### PAC_UPN_DNS_INFO

```
typedef struct _PAC_UPN_DNS_INFO {
    USHORT UpnDnsFlags;           // bit 0x01 = HasUPN, 0x02 = HasSamName, 0x04 = HasSid
    USHORT UpnLength;
    USHORT UpnOffset;
    USHORT DnsDomainNameLength;
    USHORT DnsDomainNameOffset;
    USHORT SamNameLength;         // Server 2019+
    USHORT SamNameOffset;
    USHORT SidLength;             // Server 2019+
    USHORT SidOffset;
} PAC_UPN_DNS_INFO;
```

The UPN + DNS domain are stored as Unicode strings immediately following the structure.

### PAC_REQUESTER (Server 2016+)

```
typedef struct _PAC_REQUESTER {
    SID     RequesterSid;          // SID of the account that initiated the request
} PAC_REQUESTER;
```

This is the "who asked for this ticket?" field. Added to defend against S4U2self/S4U2proxy abuse — a service can inspect the PAC to see whether the request was for itself (a normal TGS) or for an admin impersonating another user. Tools like `Rubeus` and `kekeo` log this; blue teams can detect anomalous patterns via the RequesterSid.

### PAC_BUFFER_TICKET_CHECKSUM (Server 2016+, MS-KILE)

```
typedef struct _PAC_BUFFER_TICKET_CHECKSUM {
    ULONG  SignatureType;
    ULONG  SignatureLength;
    UCHAR  Signature[ANYSIZE_ARRAY];
} PAC_BUFFER_TICKET_CHECKSUM;
```

The ticket signature is computed by the KDC over the entire `Ticket.enc-part` BEFORE that data is encrypted with the krbtgt key. The signature is then included inside the PAC. This defends against "silver ticket" attacks — an attacker with only the service account's key can forge the `Ticket.enc-part` (encrypting a fake ticket body with the service key), but cannot forge the KDC-side ticket signature (which requires the krbtgt key).

This is **separate** from the KDC PAC signature (ulType 0x07). Both must be present and valid in Server 2016+ for full PAC validation.

### PAC_FULL_CHECKSUM (Server 2016+)

A KDC-side signature over the entire PAC (including the existing server and KDC signatures), keyed with the krbtgt key. This is a defense-in-depth: even if an attacker can modify one of the inner signatures, the full checksum will fail verification.

## KDC PAC verification flow

When a service (e.g., IIS with Windows Auth, SQL Server) receives an AP-REQ and wants to validate the PAC:

1. **Decrypt the Ticket** — `KrbDecrypt(Ticket.enc-part, service_long_term_key)`.
2. **Extract authorization-data** — walk `EncTicketPart.authorization-data` → find `AD-IF-RELEVANT(0)` → unwrap → find `AD-WIN2K-PAC(128)` → the PAC blob.
3. **Verify the server signature** — compute HMAC over the PAC (with server signature field zeroed) using the service's long-term key; compare to the stored server signature.
4. **Verify the KDC signature** — recompute over the PAC (with KDC signature field zeroed) using the krbtgt key (the service typically does NOT have this key directly — it asks the DC).
5. **Call the KDC's PAC validation RPC** — the service opens an RPC to its DC's `Netlogon` interface (`NetrLogonSamLogonEx` with the `MSV1_0_PAC` flag), passing the ticket and the PAC. The DC verifies the KDC signature (it has the krbtgt key) and returns success/failure.
6. **Verify the ticket signature (Server 2016+)** — same RPC also validates `PAC_BUFFER_TICKET_CHECKSUM`.

By default, only a handful of services do PAC validation (IIS w/ Windows Auth, SQL Server with Kerberos, COM+ with Kerberos). File services (SMB) and others rely on the KDC's signature check at issuance time only.

### Registry toggle for PAC validation

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
 ├── VerifyPacAuthenticators  (REG_DWORD, default 0 = off)
 │                              Set to 1 to require PAC validation on every AP-REQ
 │                              (significant perf hit, only for high-security services)
 └── EnablePacTgsLeew  (REG_DWORD, default 0)
```

## Wireshark display filters

```
kerberos.PAC                              # all PAC content (after decryption)
kerberos.PAC.logon_info                   # KERB_VALIDATION_INFO
kerberos.PAC.logon_info.UserId
kerberos.PAC.logon_info.PrimaryGroupId
kerberos.PAC.logon_info.GroupIds
kerberos.PAC.logon_info.ExtraSids
kerberos.PAC.client_info
kerberos.PAC.upn_dns_info
kerberos.PAC.kdc_signature
kerberos.PAC.svc_signature
kerberos.PAC.attributes_info
kerberos.PAC.requester
kerberos.PAC.ticket_checksum              # PAC_BUFFER_TICKET_CHECKSUM (2016+)

# SPN lookups via TGS-REQ
kerberos.SName.name_string contains "cifs"
kerberos.SName.name_string == "HTTP"
kerberos.req_body.realm == "EXAMPLE.COM"

# UPN-based logon (AS-REQ)
kerberos.cname.name_string == "jdoe"
kerberos.req_body.cname.name_type == 1   # NT_PRINCIPAL (UPN)
```

## Configuration / code examples

### PowerShell — SPN / UPN management

```powershell
# Set an SPN on a service account (with uniqueness check)
Set-ADUser -Identity "web-svc" -ServicePrincipalNames @{ Add = "HTTP/web01.example.com" }
# Equivalent via setspn (uses DRSWriteSPN internally)
setspn -S HTTP/web01.example.com EXAMPLE\web-svc

# Detect duplicate SPNs across the forest
setspn -X -F    # -F = forest-wide (performs GC query)

# List UPN suffixes available
Get-ADObject -Identity "CN=Partitions,CN=Configuration,DC=example,DC=com" `
             -Properties uPNSuffixes | Select -Expand uPNSuffixes

# Add a new UPN suffix
Set-ADObject -Identity "CN=Partitions,CN=Configuration,DC=example,DC=com" `
             -Add @{ uPNSuffixes = "branch.example.com" }

# Set a user's UPN
Set-ADUser -Identity "jdoe" -UserPrincipalName "j.doe@branch.example.com"

# Detect duplicate UPNs
Get-ADUser -Filter * -Properties userPrincipalName |
    Where-Object { $_.userPrincipalName } |
    Group-Object userPrincipalName | Where-Object { $_.Count -gt 1 } |
    ForEach-Object { Write-Warning "Duplicate UPN: $($_.Name) — accounts: $($_.Group.Name -join ', ')" }
```

### Python — decode a PAC from a TGT using impacket

```python
from impacket.krb5 import kerberosv5, types
from impacket.krb5.pac import PACInfo, KERB_VALIDATION_INFO, PAC_SIGNATURE_DATA, \
    PAC_CLIENT_INFO, PAC_UPN_DNS_INFO, PAC_REQUESTER, PAC_BUFFER_TICKET_CHECKSUM
from impacket.krb5.constants import AuthorizationDataType
import struct

def decode_pac(ticket_blob, service_key):
    """Given a Kerberos ticket blob and the service's long-term key, decode the PAC."""
    # Parse the outer Ticket ASN.1
    from impacket.krb5.asn1 import Ticket
    ticket = Ticket.load(ticket_blob)
    # Decrypt enc-part using service key
    from impacket.krb5.crypto import Key, _enctype_table
    etype = ticket['enc-part']['etype']
    cipher = _enctype_table[etype]()
    key = Key(etype, service_key)
    plain = cipher.decrypt(key, 2, ticket['enc-part']['cipher'])  # usage 2 = ticket
    from impacket.krb5.asn1 import EncTicketPart
    enc_ticket = EncTicketPart.load(plain)
    # Walk authorization-data
    for ad in enc_ticket['authorization-data']:
        if ad['ad-type'] == 0:  # AD-IF-RELEVANT
            for inner_ad in ad['ad-data']:
                if inner_ad['ad-type'] == 128:  # AD-WIN2K-PAC
                    pac_blob = inner_ad['ad-data'].as_bytes()
                    pac = PACInfo(pac_blob)
                    for buf in pac.buffers:
                        if buf.ulType == 0x01:  # PAC_LOGON_INFO
                            kvi = KERB_VALIDATION_INFO(buf.buffer)
                            print(f"User: {kvi.EffectiveName}  UserId: {kvi.UserId}")
                            print(f"Groups: {[g.RelativeId for g in kvi.GroupIds]}")
                            print(f"ExtraSids: {kvi.ExtraSids}")
                        elif buf.ulType == 0x06:
                            print(f"Server signature type: 0x{struct.unpack('<I', buf.buffer[:4])[0]:08X}")
                        elif buf.ulType == 0x07:
                            print(f"KDC signature type: 0x{struct.unpack('<I', buf.buffer[:4])[0]:08X}")
                        elif buf.ulType == 0x0A:
                            ci = PAC_CLIENT_INFO(buf.buffer)
                            print(f"Client: {ci.Name}  LogonTime: {ci.ClientId}")
                        elif buf.ulType == 0x0C:
                            upn = PAC_UPN_DNS_INFO(buf.buffer)
                            print(f"UPN: {upn.Upn}  DNS: {upn.DnsDomainName}")
                        elif buf.ulType == 0x0E:
                            print("Ticket signature present (Server 2016+)")
                        elif buf.ulType == 0x12:
                            req = PAC_REQUESTER(buf.buffer)
                            print(f"Requester SID: {req.RequesterSid}")
```

### Python — request a service ticket via S4U2self and inspect the PAC

```python
from impacket.krb5.kerberosv5 import S4U2Self
from impacket.krb5.types import Principal

# Service account "web-svc" requests a ticket to itself on behalf of "jdoe"
service = Principal("web-svc", type=constants.PrincipalNameType.NT_PRINCIPAL)
user    = Principal("jdoe@EXAMPLE.COM", type=constants.PrincipalNameType.NT_PRINCIPAL)
tgt, cipher, session_key = getKerberosTGT(service, ...)
# S4U2self:
tgs, cipher, session_key = S4U2Self(service, user, domain="EXAMPLE.COM",
                                    kdcHost="dc01.example.com", TGT=tgt)
# The PAC inside `tgs` now contains a PAC_REQUESTER buffer with the SID of web-svc.
```

### PowerShell — enable PAC validation for IIS (rare; high-overhead)

```powershell
# Only on the IIS server hosting Windows-auth apps
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
                 -Name "VerifyPacAuthenticators" -Value 1
Restart-Service WAS -Force    # Restart IIS App Service to reload
```

## Troubleshooting

- **`KDC_ERR_S_PRINCIPAL_UNKNOWN (7)` on TGS-REQ** — the requested SPN is not registered. Verify with `setspn -Q <spn>` (returns the owning account). If empty, register: `setspn -S <spn> <account>`.
- **`KRB_AP_ERR_MODIFIED (41)`** — the service ticket was encrypted to a different account's key. Classic cause: duplicate SPN registered on two accounts (the KDC picked the wrong one). Fix: `setspn -X` to find duplicates; remove from the wrong account.
- **`KRB_AP_ERR_BAD_INTEGRITY (31)`** — ticket signature verification failed. Usually means the service's long-term key has changed since the KDC issued the ticket (e.g., password change). Wait for the ticket to expire or purge with `klist purge`.
- **UPN not resolvable by Linux client** — Linux clients (via SSSD) read the UPN from the user object. If the suffix was added after the user account, you may need to clear SSSD cache: `sss_cache -u <user>` or restart `sssd`.
- **Duplicate UPN logon failures** — users with same UPN intermittently fail to log in (the KDC sometimes picks one, sometimes the other). Detection: see PowerShell snippet above. Fix: change one user's UPN to a unique value.
- **PAC validation failure (`STATUS_ACCESS_DENIED`)** — the service's PAC validation call to the DC failed. Could be: (a) the DC's krbtgt account key was rotated but the service has a stale ticket; (b) the PAC signature verification mismatch (ticket tampered with).
- **Ticket signature missing on a 2016+ deployment** — happens when the KDC hasn't been updated or when `msDS-SupportedEncryptionTypes` on the krbtgt account doesn't include AES. Verify with `Get-ADUser krbgt -Properties msDS-SupportedEncryptionTypes` (should be 0x30 for AES-128 + AES-256).

## Cross-platform equivalents

- **Linux (MIT krb5)**: PAC parsing in `lib/krb5/krb/pac.c`. PAC validation behavior toggled via `[libdefaults] pac = true` in `/etc/krb5.conf`. The MIT implementation supports `PAC_LOGON_INFO`, `PAC_SIGNATURE_DATA`, `PAC_UPN_DNS_INFO`, and `PAC_REQUESTER` parsing, but does not natively enforce Server 2016+ ticket signature validation without explicit configuration.
- **Linux (Heimdal)**: PAC parsing in `lib/krb5/pac.c` — Microsoft-compatible but with minor structural differences (some buffers are reordered).
- **Linux (Samba)**: Samba 4 as an AD DC builds and signs PACs in `source4/kdc/pac-glue.c` and `source4/dsdb/samdb/ldb_modules/extended_dn_in.c`. The PAC generation mirrors Microsoft's exactly, including `PAC_REQUESTER` and ticket signature on Server 2016+ level functionally. See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux (SSSD)**: When used as an AD client, SSSD reads `PAC_LOGON_INFO` from the user's TGT to populate local group membership (the `pac_responder` daemon). Useful for offline logon and for using AD groups in local authorization. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **macOS**: The Apple SSO Extension (Kerberos profile) reads the PAC for group information and applies it to local authorization via Open Directory's mapping. The Platform SSO extension is the only supported path for full PAC handling on macOS. See `../08-macos-equivalents/05-kerberos-sso-extension.md`.

## References

- MS-KILE — Kerberos Protocol Extensions (SPN/UPN behavior, S4U2self/S4U2proxy). <https://learn.microsoft.com/openspecs/windows_protocols/ms-kile>
- MS-PAC — Privilege Attribute Certificate Data Structure. <https://learn.microsoft.com/openspecs/windows_protocols/ms-pac>
- MS-DRSR §4.1.4.2.10 — `DRSWriteSPN` IDL.
- MS-DRSR §4.1.4.1 — `DRSCrackNames` (DS_USER_PRINCIPAL_NAME format).
- RFC 4120 §5.2.7 — `Authorization-Data` element structure (AD-IF-RELEVANT, AD-WIN2K-PAC).
- RFC 6806 §11 — ` principalType` canonicalization (UPN vs sAMAccountName).
- `setspn.exe` reference — MS Learn.
- MIT krb5 PAC source — <https://github.com/krb5/krb5/blob/master/src/lib/krb5/krb/pac.c>
- Heimdal PAC source — <https://github.com/heimdal/heimdal/blob/master/lib/krb5/pac.c>
- Samba PAC source — `source4/kdc/pac-glue.c`, `librpc/ndr/ndr_pac.c`.
- Impacket PAC implementation — `impacket/krb5/pac.py`.
