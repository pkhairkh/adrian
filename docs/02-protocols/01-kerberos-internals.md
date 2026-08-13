---
title: Kerberos Protocol Internals — RFC 4120 + MS-KILE, PAC, FAST, PKINIT
audience: senior-engineers
tags: [kerberos, rfc-4120, ms-kile, rfc-6806-fast, pkinit, pac, etype, asn1]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../02-protocols/07-ntp-time-sync.md
  - ../08-macos-equivalents/05-kerberos-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

Kerberos in Active Directory is the RFC 4120 protocol profiled by MS-KILE (the Microsoft Kerberos protocol extension doc), implemented in `lsass.exe!kdcsvc.dll` on the DC and `lsass.exe!kerberos.dll` on the client, with a Microsoft-specific Privilege Attribute Certificate (PAC) carrying the user's authorization data, FAST (RFC 6806) tunneling for pre-auth hardening, and PKINIT (RFC 4556) for smart-card logon. The KDC shares its key with the LSASS `krbtgt` account, whose NTLM hash is the long-term AS-REP signing key.

## Architecture

```
Client (lsass.exe!kerberos.dll)        KDC (lsass.exe!kdcsvc.dll on a DC)
   │                                       │
   │── AS-REQ (TGT request) ─────────────►│   (UDP/TCP 88)
   │◄── AS-REP (TGT encrypted to krbtgt) ──│
   │                                       │
   │── TGS-REQ (service ticket request) ──►│   (with TGT as PA-TGS-REQ)
   │   {TGT, authenticator, requested SPN} │
   │◄── TGS-REP (service ticket) ──────────│
   │                                       │
   │── AP-REQ to service ─────────────────►│   (any service, e.g. HTTP/web)
   │   {service ticket, authenticator}     │
   │◄── AP-REP (optional mutual auth) ─────│
```

- KDC host: any Domain Controller. Identified by ` SRV _kerberos._tcp.dc._msdcs.<domain>` records.
- Service accounts: each account that wants Kerberos auth has at least one SPN (`servicePrincipalName` attribute).
- Long-term keys: KDC's master key is the NTLM hash of the `krbtgt` account (`userPrincipalName` = `krbtgt/@REALM`). One per domain; the second one for cross-realm (`krbtgt_<foreign-realm>`).

## ASN.1 message structures

Defined in RFC 4120 §5 (with MS-KILE extensions). All Kerberos messages use ASN.1 DER encoding.

### AS-REQ (KDC-REQ)

```asn1
AS-REQ ::= [APPLICATION 10] KDC-REQ
KDC-REQ ::= SEQUENCE {
    pvno            [1] INTEGER (5),            -- protocol version 5
    msg-type        [2] INTEGER (10),           -- krb-as-req = 10
    padata          [3] SEQUENCE OF PA-DATA OPTIONAL,
    req-body        [4] KDC-REQ-BODY
}
KDC-REQ-BODY ::= SEQUENCE {
    kdc-options     [0] KDCOptions (BIT STRING),    -- see below
    cname           [1] PrincipalName OPTIONAL,     -- empty for AS-REQ pre-auth-less
    realm           [2] Realm,
    sname           [3] PrincipalName OPTIONAL,     -- defaults to krbtgt/<realm>
    from            [4] KerberosTime OPTIONAL,
    till            [5] KerberosTime,                -- typically 0 for "expire at TGT end"
    rtime           [6] KerberosTime OPTIONAL,
    nonce           [7] UInt32,
    etype           [8] SEQUENCE OF Int32,           -- proposed enctypes
    addresses       [9] HostAddresses OPTIONAL,
    enc-authorization-data [10] EncryptedData OPTIONAL,
    additional-tickets [11] SEQUENCE OF Ticket OPTIONAL
}
KDCOptions ::= BIT STRING {
    reserved0         (0), forwardable        (1),
    forwarded         (2), proxiable          (3),
    proxy             (4), allow-postdate     (5),
    postdated         (6), unused7            (7),
    renewable         (8), unused9            (9),
    unused10          (10), opt-hardware-auth (11),
    unused12          (12), unused13          (13),
    constrained-delegation  (14),             -- MS-KILE S4U2proxy
    canonicalize     (15),                    -- MS-KILE: return canonical cname
    disable-transited (16), renewable-ok      (27),
    enc-tkt-in-skey  (28), renew              (29),
    validate         (30)
}
```

### PA-DATA types (selected — full list in RFC 4120 §5.2.7 + MS-KILE §2.2)

| padata-type | Name | Purpose |
|---|---|---|
| 1 | PA-TGS-REQ | Carries an AP-REQ in a TGS-REQ. |
| 2 | PA-ENC-TIMESTAMP | The classic pre-auth: encrypted timestamp with the user's long-term key. |
| 128 | PA-ENC-TIMESTAMP (MS-KILE variant) | Same as 2, used when FAST armoring is in effect. |
| 133 | PA-FX-FAST | FAST armor (RFC 6806). |
| 143 | PA-FX-COOKIE | State cookie returned by KDC when pre-auth needs multiple round trips. |
| 16 | PA-DATA PVNO — ticket-granting-ticket | TGT reference for FAST armoring. |
| 17 | PA-PK-AS-REQ (PKINIT, RFC 4556) | Smart-card logon. |
| 19 | PA-ENCRYPTED-CHALLENGE | Used in Kerberos over TLS armoring. |
| 149 | PA-OTP-CHALLENGE | OTP pre-auth (RFC 6560). |
| 165 | PA-PKINIT-KX | PKINIT-derived key for FAST (RFC 6112). |
| 167 | PA-SUPPORTED-ENCTYPES | AD-extension: KDC lists supported enctypes. |
| 168 | PA-OTP-REQUEST | Client-side OTP. |
| 197 | PA-PK-AS-09 | PKINIT draft variant. |
| 209 | PA-OTP-CONFIRM | OTP confirmation. |
| 213 | PA-FX-FAST-START | FAST pre-auth start. |
| 302 | PA-RTGT | Renewable-TGT (s4u2proxy alternate). |

### AS-REP / TGS-REP

```asn1
AS-REP ::= [APPLICATION 11] KDC-REP
TGS-REP ::= [APPLICATION 13] KDC-REP
KDC-REP ::= SEQUENCE {
    pvno         [0] INTEGER (5),
    msg-type     [1] INTEGER (11 | 13),
    crealm       [2] Realm,
    cname        [3] PrincipalName,
    ticket       [4] Ticket,
    enc-part     [5] EncryptedData      -- encrypted to the requesting principal's key
}
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno      [0] INTEGER (5),
    realm        [1] Realm,
    sname        [2] PrincipalName,
    enc-part     [3] EncryptedData      -- encrypted to the service's key (or krbtgt for TGT)
}
EncTicketPart ::= [APPLICATION 3] SEQUENCE {
    flags                   [0] TicketFlags,
    key                     [1] EncryptionKey,    -- session key
    crealm                  [2] Realm,
    cname                   [3] PrincipalName,
    transited               [4] TransitedEncoding,
    authtime                [5] KerberosTime,
    starttime               [6] KerberosTime OPTIONAL,
    endtime                 [7] KerberosTime,
    renew-till              [8] KerberosTime OPTIONAL,
    caddr                   [9] HostAddresses OPTIONAL,
    authorization-data      [10] AuthorizationData OPTIONAL  -- PAC lives here, type AD-IF-RELEVANT (0) wraps type 128 (AD-WIN2K-PAC)
}
```

### Authenticator (inside AP-REQ)

```asn1
Authenticator ::= [APPLICATION 2] SEQUENCE {
    authenticator-vno       [0] INTEGER (5),
    crealm                  [1] Realm,
    cname                   [2] PrincipalName,
    cksum                   [3] Checksum OPTIONAL,
    cusec                   [4] Microseconds,
    ctime                   [5] KerberosTime,
    subkey                  [6] EncryptionKey OPTIONAL,
    seq-number              [7] UInt32 OPTIONAL,
    authorization-data      [8] AuthorizationData OPTIONAL,
    gss-api-token           [9] OCTET STRING OPTIONAL  -- MS-KILE: for DCE-style GSS
}
```

## Enctype table

| etype | Hex | Name | Status in AD | Key derivation |
|---|---|---|---|---|
| 0x01 | 1 | des-cbc-crc | Removed (Server 2008 R2 default off, removed 2012) | 7-byte DES key from string |
| 0x02 | 2 | des-cbc-md4 | Removed | — |
| 0x03 | 3 | des-cbc-md5 | Removed | — |
| 0x09 | 9 | des3-cbc-md5 | Not implemented by Microsoft | — |
| 0x10 | 16 | des3-cbc-sha1 | Not implemented by Microsoft | — |
| 0x11 | 17 | aes128-cts-hmac-sha1-96 | Default for 2008+ if AES enabled on the account | PBKDF2 4096 iters, 128-bit |
| 0x12 | 18 | aes256-cts-hmac-sha1-96 | Default for 2008+ if AES enabled on the account | PBKDF2 4096 iters, 256-bit |
| 0x13 | 19 | aes256-cts-hmac-sha384-192 | Server 2022+ (RFC 8009) | PBKDF2 — see note |
| 0x17 | 23 | rc4-hmac | Default for 2003 and earlier; still issued for accounts without `msDS-SupportedEncryptionTypes` | MD4 of password (= NTLM hash) |
| 0x18 | 24 | rc4-hmac-exp | Export-grade RC4; disabled | — |
| 0x1E | 30 | camellia128-cts-cmac | Not implemented by Microsoft | — |
| 0x1F | 31 | camellia256-cts-cmac | Not implemented by Microsoft | — |

Notes:

- AES-128/256 keys derived via `PBKDF2-HMAC-SHA1(password, salt, 4096)` per RFC 3962. The salt is `realm + concat(all principal components)` (e.g. for `host/web.example.com@EXAMPLE.COM`, salt = `EXAMPLE.COMhostweb.example.com`). This is why a renamed user requires a password reset to regenerate salt-derived AES keys.
- The `msDS-SupportedEncryptionTypes` AD attribute on the service account is a bitmask. Bit 0x01 = DES-CBC-CRC, 0x02 = DES-CBC-MD5, 0x04 = RC4-HMAC, 0x08 = RC4-HMAC-EXP, 0x10 = AES128-CTS-HMAC-SHA1-96, 0x20 = AES256-CTS-HMAC-SHA1-96. The KDC picks the highest mutually-supported etype from the requested set in `KDC-REQ-BODY.etype`.
- etype 0x13 (`aes256-cts-hmac-sha384-192`) is from RFC 8009 and is supported starting with Windows Server 2022. PBKDF2 iteration count stays 4096 for compatibility with existing keys (no break-glass re-derivation).

## Pre-authentication

### PA-ENC-TIMESTAMP (etype 2 / 128)

Client encrypts the current time (rounded to the second, plus a microsecond field of 0) using its long-term key:

```
PAData {
    padata-type  = 2 (PA-ENC-TIMESTAMP),
    padata-value = Encrypt(ETYPE, key=user-long-term-key, plain=PA-ENC-TS-ENC)
}
PA-ENC-TS-ENC ::= SEQUENCE {
    patimestamp [0] KerberosTime,    -- current time on client
    pausec      [1] Microseconds OPTIONAL
}
```

KDC decrypts with the user's long-term key (looking it up by `cname`). If the timestamp is within the KDC's clock skew (default 5 min — RFC 4120 §5.3), pre-auth succeeds. Pre-auth failure → KDC returns `KDC-REP` with code `KDC_ERR_PREAUTH_REQUIRED (25)` and an encrypted `EtypeInfo2` hint listing acceptable etypes.

### FAST — Flexible Authentication Secure Tunneling (RFC 6806)

FAST wraps the inner pre-auth in an armored tunnel encrypted to a TGT the client already holds (the "armor TGT"). Defeats offline password cracking from AS-REP captures (because the inner pre-auth response is now encrypted to the FAST armor key, not the user's long-term key).

```
AS-REQ (FAST) {
    padata = [
        PA-FX-FAST {                  -- type 143
            armor: TGT armor,         -- the user's existing TGT (or anonymous PKINIT TGT)
            encrypted-inner-req: EncryptedData {
                key: FAST-armor-key (derived from TGT session key + a nonce),
                plain: AS-REQ-padata-with-PA-ENC-TIMESTAMP-or-stronger
            }
        }
    ]
}
```

Active Directory FAST support: Server 2012+ (KDC); Windows 8+ (client). Must be enabled by GPO: `Computer Configuration → Policies → Administrative Templates → System → Kerberos → Configure FAST policy` (= "Supported" or "Required").

### PKINIT (RFC 4556)

Smart-card logon. The client signs a nonce with its smart-card private key. The KDC verifies the signature against the user's certificate (issued by an Enterprise CA whose cert is in `NTAuthCertificates` in AD). The KDC's reply includes a `PA-PK-AS-REP` containing a temporary Diffie-Hellman public key (or RSA-encrypted reply key) for establishing the AS-REP session key.

```
PA-PK-AS-REQ ::= SEQUENCE {
    signedAuthPack [0] SignedData,    -- CMS, contains AuthPack
    trustedCertifiers [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
    kdcCert [2] IssuerAndSerialNumber OPTIONAL,
    ...
}
AuthPack ::= SEQUENCE {
    pkAuthenticator [0] PKAuthenticator,
    clientPublicValue [1] SubjectPublicKeyInfo OPTIONAL,  -- for DH
    supportedCMSTypes [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
    clientDHNonce [3] DHNonce OPTIONAL
}
PKAuthenticator ::= SEQUENCE {
    cuSec        [0] Microseconds,
    ctime        [1] KerberosTime,
    nonce        [2] UInt32,        -- the same nonce as in KDC-REQ-BODY.nonce
    paChecksum   [3] OCTET STRING OPTIONAL  -- SHA-1 of the AS-REQ body, binds PKINIT to this request
}
```

PKINIT is required for smart-card logon (PIV/CAC cards, Windows Hello for Business with certificate trust). The user's certificate SAN must contain the user's UPN (or the `Subject Alt Name` must map to the user object via the `altSecurityIdentities` attribute).

## PAC — Privilege Attribute Certificate

The PAC is a Microsoft extension (MS-KILE §2.2 / MS-PAC) embedded in the Ticket's `authorization-data` element. It carries the user's group SIDs, user flags, profile data, and cryptographic signatures. The KDC populates the PAC in the TGT; subsequent TGS-REQs carry the same PAC into the service ticket (the KDC may modify `PAC_LOGON_INFO` to add resource-group SIDs for the target domain).

### PAC top-level structure (NDR-encoded, MS-PAC §2)

```
PACTYPE {
    ULONG       cBuffers;       // count of PAC_INFO_BUFFER
    ULONG       Version;        // 0
    PAC_INFO_BUFFER[cBuffers];
}

PAC_INFO_BUFFER {
    ULONG       ulType;         // see table
    ULONG       cbBufferSize;
    ULONG64     Offset;         // offset from start of PACTYPE
}
```

### PAC buffer types

| ulType | Name | Purpose |
|---|---|---|
| 0x00000001 | PAC_LOGON_INFO (KERB_VALIDATION_INFO) | The big one — user RID, group memberships, profile path, logon hours, etc. |
| 0x00000002 | PAC_CREDENTIAL_TYPE | Credentials the KDC had at logon time (NTLM hash, plaintext if reversible encryption on) — only included when `ForceLogoffWhenCompliant` or `CredentialsNotDelegated` flag set; default off. |
| 0x00000006 | PAC_SIGNATURE_DATA (svc) | Server signature: HMAC/CMAC keyed with the service's long-term key. |
| 0x00000007 | PAC_SIGNATURE_DATA (kdc) | KDC signature: HMAC/CMAC keyed with the krbtgt key, over the server signature + everything else. |
| 0x0000000A | PAC_CLIENT_INFO | Client name + logon time. |
| 0x0000000B | PAC_CONSTRAINED_DELEGATION | S4U2proxy permitted SPNs. |
| 0x0000000C | PAC_UPN_DNS_INFO | User's UPN + DNS domain (added Server 2008). |
| 0x0000000D | PAC_CREDENTIAL_INFO | Client credentials, encrypted with the PAC credential key. |
| 0x0000000E | PAC_BUFFER_TICKET_CHECKSUM | Ticket signature (added Server 2016) — KDC signs the entire Ticket.enc-part with the krbtgt key. |
| 0x00000011 | PAC_ATTRIBUTES_INFO | Requestor info (added Server 2012). |
| 0x00000012 | PAC_REQUESTER | Requester SID + the request's machine SID (added Server 2016, MS-KILE 6). |
| 0x00000013 | PAC_EXTENDED_KDC_CHECKSUM | KDC signature covering the entire PAC, including the ticket checksum. |

### KERB_VALIDATION_INFO (PAC_LOGON_INFO)

NDR-encoded structure (see `ms-pac.h` in Windows SDK). Highlights:

```
KERB_VALIDATION_INFO {
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
    ULONG               UserId;            // user's RID
    ULONG               PrimaryGroupId;    // typically 513 = Domain Users
    GROUP_MEMBERSHIP    GroupIds[];        // list of RIDs of groups the user is in
    ULONG               UserFlags;
    USER_SESSION_KEY    UserSessionKey;
    RPC_UNICODE_STRING  LogonServer;
    RPC_UNICODE_STRING  LogonDomainName;
    PSID                LogonDomainId;     // domain SID
    ULONG               Reserved1[];
    ULONG               UserAccountControl;
    SUBAUTHENTICATED_SID SubAuthSid OPTIONAL;
    PAC_EXTRA_SIDS      ExtraSids;         // universal groups, resource groups in other domains
    PAC_RESOURCE_GROUPS ResourceGroupDomainSid;  // for cross-domain resource groups
}
```

The `ExtraSids` field is the canonical cross-domain group membership signal — used by S4U and by global group nesting when the user's home domain != resource domain.

### PAC_SIGNATURE_DATA

Two of these (one for the service, one for the KDC). Format:

```
PAC_SIGNATURE_DATA {
    ULONG  SignatureType;     // 0xFFFFFF76 = KERB_CHECKSUM_HMAC_MD5 (RC4 etype)
                              // 0xFFFFFF76 + others for AES: 0xFFFFFF76 = HMAC_MD5
                              //   0x00000011 = HMAC_SHA1_96_AES128
                              //   0x00000012 = HMAC_SHA1_96_AES256
                              //   0x00000013 = HMAC_SHA384_192_AES256
    UCHAR  Signature[];       // actual HMAC/CMAC bytes, length depends on SignatureType
}
```

The service signature is computed over the entire PAC buffer with the signature field zeroed. The KDC signature is then computed over the service signature's `SignatureType` + the zeroed-PAC, with the krbtgt key.

### Ticket signature (Server 2016+, MS-KILE)

Added as `PAC_BUFFER_TICKET_CHECKSUM` (type 0x0E). A KDC-side signature over the entire `Ticket.enc-part` (the encrypted ticket body) using the krbtgt key, before ticket encryption. This defends against "silver ticket" attacks (forged service tickets) because an attacker with only the service account's key can forge the ticket plaintext but cannot forge the KDC-side ticket signature.

## KDC PAC verification flow

1. **Service receives AP-REQ** → decrypts `Ticket.enc-part` with its long-term key → extracts `EncTicketPart.authorization-data` → finds the AD-IF-RELEVANT(0) wrapping AD-WIN2K-PAC(128) → decodes PACTYPE.
2. **Service (if PAC-validation enabled)** — typically only services that need group membership (IIS, SQL Server) do PAC validation. The service sends the PAC + the ticket to the KDC via the `KRB5_VERIFY_PAC` RPC (via `NetrLogonSamLogonEx` — actually via the dedicated `KDC_PROXY` over TCP 135 epmapper, RPC interface UUID `c799d9f0-abb1-11d3-bb79-00c04f769d0d`).

Wait, more accurately: PAC validation is via the `KRB5_VERIFY_PAC` SVCCTL-style interface: actually it's done via `Kdcsvc` RPC `KDC_PROXY` interface, or simpler: via the SAMR / LSARPC `Netlogon`-like flow.

The mechanism: the service sends a `KRB_CRED` containing the ticket + authenticator over `ncacn_ip_tcp` to its own domain's KDC at port 88 — but actually PAC verification happens via `Netlogon` (the `NetrLogonSamLogonEx` RPC). The DC validates the KDC signature inside the PAC by recomputing it with the krbtgt key.

## Wireshark display filters

```
# All Kerberos traffic
kerberos || krb
# Only AS exchanges
kerberos.msg_type == 10 || kerberos.msg_type == 11
# Only TGS exchanges
kerberos.msg_type == 12 || kerberos.msg_type == 13
# Specific realm
kerberos.realm == "EXAMPLE.COM"
# Specific service principal
kerberos.SName.name_string == "cifs"
kerberos.SName.name_string == "HTTP" && kerberos.req_body.realm == "EXAMPLE.COM"
# Pre-auth failures (etype unsupported, key-mismatch)
kerberos.error_code == 24   # KDC_ERR_C_PREAUTH_FAILED
kerberos.error_code == 14   # KDC_ERR_ETYPE_NOTSUPP
# PAC contents (after decryption in Wireshark with keytab)
kerberos.PAC
kerberos.PAC.logon_info
kerberos.PAC.kdc_signature
# FAST
kerberos.padata_type == 133 || kerberos.padata_type == 143
# PKINIT
kerberos.padata_type == 16 || kerberos.padata_type == 17
```

## Configuration / code examples

### PowerShell — manage account etypes

```powershell
# Inspect the etypes an account supports (bitmask)
Get-ADUser -Identity "web-svc" -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
    Select-Object Name, msDS-SupportedEncryptionTypes, servicePrincipalName

# Enable AES-128 + AES-256, drop RC4
Set-ADUser -Identity "web-svc" -Replace @{ "msDS-SupportedEncryptionTypes" = 0x30 }  # 0x30 = AES128 | AES256
# Verify
Get-ADUser -Identity "web-svc" -Properties msDS-SupportedEncryptionTypes | % {
    $flags = $_."msDS-SupportedEncryptionTypes"
    "0x{0:X2}: AES128={1} AES256={2} RC4={3}" -f $flags, [bool]($flags -band 0x10), [bool]($flags -band 0x20), [bool]($flags -band 0x04)
}
```

### Python — request a TGT via impacket

```python
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.krb5 import constants

user = Principal("jdoe", type=constants.PrincipalNameType.NT_PRINCIPAL)
tgt, cipher, oldSession, newSession = getKerberosTGT(
    user,
    password="P@ssw0rd!",
    domain="EXAMPLE.COM",
    kdcHost="dc01.example.com"
)
# tgt is a binary Ticket; cipher is the EncryptionKey for the session
print(f"TGT service: {tgt['sname']}")
print(f"Session key etype: {newSession['key']['keytype']}")
# Save to a ccache file
from impacket.krb5.ccache import CCache
ccache = CCache()
ccache.fromTGT(tgt, oldSession, newSession)
ccache.saveFile("/tmp/krb5cc_jdoe")
```

### Python — pyspnego to wrap a Kerberos AP-REQ for SMB/HTTP

```python
import pyspnego
import socket

# Acquire a Kerberos AP-REQ for HTTP/web01.example.com@EXAMPLE.COM
ctx = pyspnego.client.Client(
    protocol="kerberos",
    hostname="web01.example.com",
    service="HTTP",
    username="jdoe@EXAMPLE.COM"
)
ap_req = ctx.step()
# Send the AP-REQ token in HTTP Authorization: Negotiate <base64(ap_req)>
import base64
print("Authorization: Negotiate " + base64.b64encode(ap_req).decode())

# For mutual auth, continue stepping with the server's response:
# server_token = <response>
# final = ctx.step(server_token)
```

### klist (Windows) — inspect cached tickets

```cmd
klist tickets
klist get cifs/dc01.example.com
klist purge
klist tgt 81      :: verbose of TGT
```

## MIT vs Heimdal differences

| Aspect | MIT krb5 | Heimdal | AD |
|---|---|---|---|
| Code base | `src/lib/krb5/` in MIT source | `lib/krb5/` in Heimdal source | `kerberos.dll` (closed source) |
| PAC parsing | `lib/krb5/krb/pac.c` — Microsoft-compatible | `lib/krb5/pac.c` — same struct, slight ordering diffs | Native MS-PAC |
| Canonicalization | By default disabled; `canonicalize=true` flag | On by default | `canonicalize` flag honored |
| Referrals | RFC 6806 realm-referral | Same | Yes, cross-realm TGT referrals since Server 2008 |
| FAST | Supported (krb5-1.10+) | Supported (Heimdal 1.5+) | Supported (Server 2012+) |
| PKINIT | Supported (krb5-1.6+) | Supported (Heimdal 1.0+) | Supported (2003+ with smart card) |
| Anonymous PKINIT | RFC 6112 | RFC 6112 | Supported (Server 2016+ via gMSA / Windows Hello) |
| AES SHA-384 (etype 0x13) | krb5-1.18+ | Heimdal 7.x+ | Server 2022+ |

Cross-platform note: AD-issued tickets are accepted by MIT and Heimdal; PAC verification by Linux services requires both implementations to be configured to honor the PAC (`[libdefaults] pac = true` in MIT `krb5.conf`).

## Cross-platform equivalents

- **Linux (server-side)**: Samba 4 ships a KDC (the `samba.source4/kdc/samba_kdc.c` Heimdal-based KDC) when running as an AD DC. For non-DC Linux hosts: MIT krb5 `krb5kdc` is the reference; rarely used as a Domain Controller substitute. For AD-joined Linux clients: SSSD includes a `krb5` provider. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux (protocol handling)**: Samba's `source4/librpc/` includes IDL for the PAC, KDC, etc. Pyrex/Python bindings via `python-impacket` for low-level work.
- **macOS**: Native Kerberos via the Apple SSO Extension (the Kerberos profile payload in a configuration profile). Pre-13.0: `/usr/libexec/kdc` (an ancient Heimdal fork). Post-13.0: the SSO Extension is the supported path. See `../08-macos-equivalents/05-kerberos-sso-extension.md`.

## References

- RFC 4120 — The Kerberos Network Authentication Service (V5).
- RFC 4121 — Kerberos V5 GSS-API mechanism (extended by MS-KILE).
- RFC 4556 — PKINIT.
- RFC 6806 — FAST.
- RFC 3961, RFC 3962 — Encryption and Key Derivation.
- RFC 8009 — AES-CTS-HMAC-SHA-384-192.
- MS-KILE — Kerberos Protocol Extensions. <https://learn.microsoft.com/openspecs/windows_protocols/ms-kile>
- MS-PAC — Privilege Attribute Certificate Data Structure. <https://learn.microsoft.com/openspecs/windows_protocols/ms-pac>
- MIT Kerberos source: <https://github.com/krb5/krb5>
- Heimdal source: <https://github.com/heimdal/heimdal>
- Impacket Kerberos implementation: `impacket.krb5`.
