---
title: LDAP Protocol — RFC 4511 + MS-ADTS Controls and Extended Ops
audience: senior-engineers
tags: [ldap, rfc-4511, ms-adts, ber, asn1, controls, extended-ops, ldap3, python]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../01-ad-core/04-ad-lds-adam.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/04-ntlm-internals.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

LDAP against Active Directory is RFC 4511 LDAPv3 wire-protocol carried over TCP/389 (cleartext or StartTLS), TCP/636 (LDAPS — deprecated but still widely deployed), TCP/3268/3269 (Global Catalog / GC-SSL), and UDP/389 (CLDAP per RFC 1798 for DC locator); the server is `lsass.exe!dsamain.dll` and the AD-specific behavior — paged queries, RDN-level delete, ranged retrieval, SD flags control — is defined in MS-ADTS §3.1.1 with eleven AD-only LDAP controls and four AD-only extended operations layered over the standard BER-encoded ASN.1 message envelope.

## Wire format

Every LDAP message is a single BER-encoded `SEQUENCE` (tag 0x30) using definite-length form:

```
LDAPMessage ::= SEQUENCE {
    messageID       MessageID,                  -- INTEGER 1..2^31-1
    protocolOp      CHOICE {
        bindRequest     BindRequest,            -- [APPLICATION 0]
        bindResponse    BindResponse,           -- [APPLICATION 1]
        unbindRequest   UnbindRequest,          -- [APPLICATION 2] NULL
        searchRequest   SearchRequest,          -- [APPLICATION 3]
        searchResEntry  SearchResultEntry,      -- [APPLICATION 4]
        searchResDone   SearchResultDone,       -- [APPLICATION 5]
        searchResRef    SearchResultReference,  -- [APPLICATION 19]
        modifyRequest   ModifyRequest,          -- [APPLICATION 6]
        modifyResponse  ModifyResponse,         -- [APPLICATION 7]
        addRequest      AddRequest,             -- [APPLICATION 8]
        addResponse     AddResponse,            -- [APPLICATION 9]
        delRequest      DelRequest,             -- [APPLICATION 10]
        delResponse     DelResponse,            -- [APPLICATION 11]
        modDNRequest    ModifyDNRequest,        -- [APPLICATION 12]
        modDNResponse   ModifyDNResponse,       -- [APPLICATION 13]
        compareRequest  CompareRequest,         -- [APPLICATION 14]
        compareResponse CompareResponse,        -- [APPLICATION 15]
        abandonRequest  AbandonRequest,         -- [APPLICATION 16]
        extendedReq     ExtendedRequest,        -- [APPLICATION 23]
        extendedResp    ExtendedResponse,       -- [APPLICATION 24]
        intermediateReq IntermediateRequest,    -- [APPLICATION 25]
        intermediateResp IntermediateResponse   -- [APPLICATION 26]
    },
    controls        [0] Controls OPTIONAL
}
```

A typical BindRequest over TCP/389 starts with `0x30 <len>` then `0x02 <len> <int>` (messageID) then `0x60 <len>` (APPLICATION 0 + constructed) for BindRequest. AD refuses any client that does not include version 3 in the BindRequest. The maximum LDAP message size defaults to 10 MB (configurable via `MaxReceiveBuffer` registry key — same as AD LDS).

## BindRequest — authentication flavors

| Mechanism | SASL / Simple | Notes |
|---|---|---|
| Anonymous | `authentication = simple` with empty credentials | Disabled by default on AD (DSHeuristics `fAllowAnonNSPI` etc.). |
| Simple bind (DN + password) | `authentication = simple` | Cleartext password over the wire — must use StartTLS or LDAPS. |
| SASL GSS-SPNEGO | `authentication = sasl, mechanism = GSS-SPNEGO` | Kerberos or NTLM, selected by SPNEGO. Default for ADUC, LDP, modern clients. |
| SASL GSSAPI | `authentication = sasl, mechanism = GSSAPI` | Pure Kerberos. |
| SASL EXTERNAL | `authentication = sasl, mechanism = EXTERNAL` | Client-cert TLS auth — only when TLS mutual auth is established. |
| SASL DIGEST-MD5 | `authentication = sasl, mechanism = DIGEST-MD5` | AD supports but disables by default (`DSHeuristics` flag). |

```asn1
BindRequest ::= [APPLICATION 0] SEQUENCE {
    version     INTEGER (3),                  -- 0x02 0x01 0x03
    name        LDAPDN,                       -- 0x04 ...
    authentication CHOICE {
        simple          [0] OCTET STRING,     -- 0x80 ...
        sasl            [3] SaslCredentials,  -- 0xA3 ...
        ...
    }
}
SaslCredentials ::= SEQUENCE {
    mechanism   LDAPString,
    credentials OCTET STRING OPTIONAL
}
```

After BindRequest, server returns BindResponse (APPLICATION 1) with `resultCode`. Common failures: `invalidCredentials (49)`, `unwillingToPerform (53)`, `operationsError (1)`.

## SearchRequest

```asn1
SearchRequest ::= [APPLICATION 3] SEQUENCE {
    baseObject      LDAPDN,
    scope           ENUMERATED {
        baseObject          (0),     -- one entry
        singleLevel         (1),     -- children
        wholeSubtree        (2)      -- recursive
    },
    derefAliases    ENUMERATED {
        neverDerefAliases   (0),
        derefInSearching    (1),
        derefFindingBaseObj (2),
        derefAlways         (3)
    },
    sizeLimit       INTEGER,
    timeLimit       INTEGER,
    typesOnly       BOOLEAN,
    filter          Filter,
    attributes      AttributeSelection
}
Filter ::= CHOICE {
    equalityMatch   [3] AttributeValueAssertion,
    greaterOrEqual  [5] AttributeValueAssertion,
    lessOrEqual     [6] AttributeValueAssertion,
    present         [7] AttributeDescription,       -- "(objectClass=*)"
    approxMatch     [8] AttributeValueAssertion,
    extensibleMatch [9] MatchingRuleAssertion,
    and             [0] SET OF Filter,
    or              [1] SET OF Filter,
    not             [2] Filter,
    substrings      [4] SubstringFilter
}
```

AD's filter evaluation engine (`ntdsa.dll!ABSearch`) uses indices defined by the schema's `searchFlags` attribute. Bit 1 = indexed, bit 5 = tuple-indexed (for sub-string searches on `cn`, `name`, `displayName`), bit 9 = preserve-on-delete (tombstone).

Result sequence:

1. Zero or more SearchResultEntry (APPLICATION 4) — each contains a `LDAPDN` and a list of `PartialAttribute` (attribute + values).
2. Zero or more SearchResultReference (APPLICATION 19) — referral URLs.
3. One SearchResultDone (APPLICATION 5) — final result code.

## AD-specific controls (MS-ADTS §3.1.1.3)

| Control OID | Constant | Purpose |
|---|---|---|
| `1.2.840.113556.1.4.319` | `LDAP_PAGED_RESULT_OID` | Paged results — server sends results in chunks of `pageSize`; client returns the `cookie` for the next page. |
| `1.2.840.113556.1.4.473` | `LDAP_SERVER_SORT_OID` | Server-side sort. |
| `1.2.840.113556.1.4.474` | `LDAP_SERVER_SORTRESP_OID` | Sort response (with attribute type if sort failed). |
| `1.2.840.113556.1.4.417` | `LDAP_SERVER_SHOW_DELETED_OID` | Return tombstones in search results. |
| `1.2.840.113556.1.4.418` | `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` | Cross-domain move — destination DC name. |
| `1.2.840.113556.1.4.528` | `LDAP_SERVER_SD_FLAGS_OID` | Restrict which parts of `nTSecurityDescriptor` are returned: OWNER (1), GROUP (2), DACL (4), SACL (8). Default: all (0xFFFFFFFF). |
| `1.2.840.113556.1.4.529` | `LDAP_SERVER_TREE_DELETE_OID` | Recursive subtree delete (one-shot). |
| `1.2.840.113556.1.4.801` | `LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID` | Range retrieval — fetch attributes with >1500 values in chunks (`member;range=0-1499`). |
| `1.2.840.113556.1.4.802` | (CLDAP-only) | Netlogon ping response over CLDAP. |
| `1.2.840.113556.1.4.805` | `LDAP_SERVER_ASQ_OID` | Attribute-scoped query — for each value of `baseObject.<attrName>`, perform a search at that DN. |
| `1.2.840.113556.1.4.1338` | (No public constant) | "Verify name" — verify the caller's access on each entry before returning it. |
| `1.2.840.113556.1.4.1339` | `LDAP_SERVER_DIRSYNC_OID` | DirSync — return only objects changed since a given cookie. Used by Azure AD Connect. |
| `1.2.840.113556.1.4.1340` | `LDAP_SERVER_RETURN_DELETED_OID` | Return deleted entries (DirSync-specific). |
| `1.2.840.113556.1.4.1413` | (Per-server) | "Per-property modify" — apply individual changes as separate updates. |
| `1.2.840.113556.1.4.1781` | `LDAP_SERVER_NOTIFICATION_OID` | Async change notification. |
| `1.2.840.113556.1.4.1852` | `LDAP_SERVER_QUOTA_CONTROL_OID` | Returns the user's quota (query policy). |
| `1.2.840.113556.1.4.2026` | `LDAP_SERVER_GET_STATS_OID` | Server-side statistics (index used, entries visited). |
| `1.2.840.113556.1.4.2064` | `LDAP_SERVER_SHOW_RECYCLED_OID` | Show recycled objects (post-Recycle-Bin). |
| `1.2.840.113556.1.4.2066` | `LDAP_SERVER_VERIFY_NAME_OID` | Cross-domain name verification. |
| `1.2.840.113556.1.4.2090` | `LDAP_SERVER_FORCE_UPDATE_OID` | Force a replication sync before responding. |
| `1.2.840.113556.1.4.2204` | `LDAP_SERVER_UPDATE_STATS_OID` | Per-update statistics. |
| `1.2.840.113556.1.4.2205` | `LDAP_SERVER_SEARCH_HINTS_OID` | Query hints (e.g., "use this index"). |
| `1.2.840.113556.1.4.2233` | (none) | Per-server "show delete + show tombstone" combination. |
| `1.2.840.113556.1.4.2428` | (none) | Range-retrieval-noerr with tombstones. |
| `1.2.840.113556.1.4.805` | `LDAP_SERVER_GET_REPL_INFO_OID` | Replication info retrieval via extended op. |

Each control is wrapped in:

```asn1
Control ::= SEQUENCE {
    controlType     LDAPOID,
    criticality     BOOLEAN DEFAULT FALSE,
    controlValue    OCTET STRING OPTIONAL    -- BER-encoded control-specific payload
}
```

### LDAP_SERVER_SD_FLAGS_OID — payload

```
ControlValue ::= BER-encoded SEQUENCE {
    sdFlags  INTEGER   -- bitmask: 1=OWNER 2=GROUP 4=DACL 8=SACL
}
```

Use this when you only need the DACL — fetching SACLs is expensive (read access requires `SeSecurityPrivilege`).

### LDAP_PAGED_RESULT_OID — payload

```
ControlValue ::= BER-encoded SEQUENCE {
    size    INTEGER,             -- requested page size
    cookie  OCTET STRING         -- server-returned, opaque; client returns on next request
}
```

The cookie is the `pagedResultsCookie`, a server-side opaque identifier. AD tracks paged result sets in memory (`dsamain.dll!ldapmgr_pagedResults`); abandoning a paged search (or simply not requesting the next page) leaks a server-side context until the connection closes. Default limit: 500 paged results open per connection.

### LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID

Used to fetch large multi-valued attributes in chunks. Syntax on the requested attribute:

```
member;range=0-1499          → first 1500 values
member;range=1500-2999       → next 1500
member;range=3000-*          → final chunk, server returns "member;range=3000-<last>"
```

Without the control, the server returns `sizeLimitExceeded` if the attribute has more than the configured `MaxValRange` (default 1500). With the control, it returns the range and no error.

### LDAP_SERVER_TREE_DELETE_OID

```
ControlValue ::= BER-encoded SEQUENCE {
    delOldRDN    BOOLEAN   -- (unused — TreeDelete always deletes children)
}
```

Single LDAP DelRequest with this control recursively deletes the entire subtree atomically. Used by `Remove-ADOrganizationalUnit -Recursive`. Server-side: `ntdsa.dll!DeleteTree`.

### LDAP_SERVER_ASQ_OID

```
ControlValue ::= BER-encoded SEQUENCE {
    sourceObject   OCTET STRING  -- the attribute name on baseObject whose values are DNs
}
```

E.g., search with `base = CN=Group1,OU=Groups,...`, control value `member` → returns one entry per `member` value. The filter still applies per entry. Used by ADUC "Members" tab.

### LDAP_SERVER_DIRSYNC_OID

```
ControlValue ::= BER-encoded SEQUENCE {
    flags       INTEGER,    -- 0x01=objectSecurity, 0x02=ancestorsFirst, 0x04=publicDataOnly,
                            -- 0x08=incrementalValues, 0x80000000=serverCtl
    maxBytes    INTEGER,
    cookie      OCTET STRING  -- server returns; client passes back on next call
}
```

Requires `DS-Replication-Get-Changes` privilege (typically only granted to DCs and Azure AD Connect's sync account). Returns changed objects since the cookie was issued. The cookie is a serialized USN vector.

### LDAP_SERVER_NOTIFICATION_OID

Server pushes async SearchResultEntry messages as changes occur. Requires no cookie. Subscription is per-connection: closing the LDAP connection cancels the subscription. Used by ADUC's "View → Advanced Features → object". Internally implemented via `ntdsa.dll!DBNotify`.

## Extended operations

```asn1
ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
    requestName      [0] LDAPOID,         -- the extended op OID
    requestValue     [1] OCTET STRING OPTIONAL
}
ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
    COMPONENTS OF LDAPResult,
    responseName     [10] LDAPOID OPTIONAL,
    responseValue    [11] OCTET STRING OPTIONAL
}
```

| Extended Op OID | Constant | Purpose |
|---|---|---|
| `1.3.6.1.4.1.1466.20037` | StartTLS | Negotiate TLS on cleartext port 389. Returns responseName = same OID. |
| `1.3.6.1.1.8` | Cancel | Cancel an in-progress operation by `messageID`. |
| `1.3.6.1.1.13.1` | PasswordModify | RFC 3062 — set password (deprecated by AD; use ModifyRequest on `unicodePwd`). |
| `1.3.6.1.4.1.4203.1.11.1` | PasswordModify (OpenLDAP variant) | Same. |
| `1.3.6.1.4.1.1466.101.119.1` | (TTL Refresh) | `LDAP_TTL_REFRESH` — refresh a dynamic object's TTL. Not supported by AD. |
| `1.3.6.1.4.1.1466.101.119.2` | (TTL expire) | `LDAP_TTL_EXPIRE`. |
| `1.2.840.113556.1.4.1781` | (not extended — actually a control) | (Mislisted above.) |
| `1.3.6.1.4.1.4203.1.11.3` | Who Am I? | Returns `dn:...` or `u:...` of the bound principal. |
| `1.2.840.113556.1.4.805` | (varies) | Actually a control, see above. |
| `1.2.840.113556.1.4.1781` | `LDAP_POLICY_HINTS_OID` | Policy hints — tell the server to apply fine-grained password policy for the next modify. |
| `1.3.6.1.4.1.1466.20037` | StartTLS | (Repeated.) |
| `1.2.840.113556.1.4.1852` | (server-side) | (Actually a control.) |
| `1.2.840.113556.1.4.1881` | (none) | "Lazy commit" — let the server commit a modify without forcing a transaction flush. |

Notes:
- AD does NOT support RFC 3062 PasswordModify (it expects ModifyRequest on `unicodePwd` with the value BER-encoded as a Unicode string surrounded by double quotes). The exact wire payload for a password change is `"\x00P\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x00!\x00"` — note the leading and trailing Unicode NULs acting as quotes.
- StartTLS on AD requires that the DC has a server certificate (with EKU = Server Authentication) and that the registry `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Certificate` references its thumbprint. Without this, StartTLS returns `unwillingToPerform (53)`.

## Wireshark display filters

```
ldap                      # all LDAP traffic
ldap.messageType == 0     # BindRequest
ldap.messageType == 3     # SearchRequest
ldap.messageType == 23    # ExtendedRequest
ldap.bind_mechanism == "GSS-SPNEGO"   # SPNEGO bind
ldap.result_code == 1     # operationsError
ldap.result_code == 49    # invalidCredentials
ldap.basedn == "DC=example,DC=com"
ldap.scope == 2           # wholeSubtree
ldap.filter               # show parsed filter
ldap.controls             # show all controls
ldap.ldap_control_oid == "1.2.840.113556.1.4.319"   # paged results
ldap.ldap_control_oid == "1.2.840.113556.1.4.528"   # SD flags
ldap.ldap_control_oid == "1.2.840.113556.1.4.529"   # tree delete
ldap.ldap_control_oid == "1.2.840.113556.1.4.1339"  # DirSync
ldap.ldap_extended_request_name == "1.3.6.1.4.1.1466.20037"   # StartTLS
```

## Configuration / code examples

### PowerShell — use `DirectorySearcher` with SD flags control

```powershell
$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Users,DC=example,DC=com")
$search = New-Object System.DirectoryServices.DirectorySearcher($de)
$search.Filter = "(objectClass=user)"
$search.PageSize = 1000
$search.SizeLimit = 0
$search.PropertiesToLoad.AddRange(@("cn","distinguishedName","nTSecurityDescriptor"))

# Add LDAP_SERVER_SD_FLAGS_OID = 0x05 (OWNER | DACL — skip SACL which needs SeSecurityPrivilege)
$sdFlagsControl = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(
    [System.DirectoryServices.Protocols.SecurityMasks]::Owner -bor
    [System.DirectoryServices.Protocols.SecurityMasks]::Dacl)
$search.DirectorySearcher.Controls.Add($sdFlagsControl)   # not exposed on DirectorySearcher; use LdapConnection below

# Use LdapConnection instead — fully exposes controls
$conn = New-Object System.DirectoryServices.Protocols.LdapConnection("dc01.example.com:389")
$conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
$conn.Bind()
$req = New-Object System.DirectoryServices.Protocols.SearchRequest(
    "CN=Users,DC=example,DC=com",
    "(objectClass=user)",
    [System.DirectoryServices.Protocols.SearchScope]::Subtree,
    @("cn","nTSecurityDescriptor"))
$req.Controls.Add($sdFlagsControl)
$resp = $conn.SendRequest($req)
$resp.Entries | ForEach-Object { $_.Attributes["cn"][0] }
```

### Python — paged search with ldap3

```python
from ldap3 import Server, Connection, ALL, SUBTREE, DEREF_NEVER
from ldap3.protocol.controls import build_control

server = Server('dc01.example.com', get_info=ALL, use_ssl=False)
conn = Connection(server,
                  user='jdoe@example.com',
                  password='P@ssw0rd!',
                  authentication='NTLM',
                  auto_bind=True)

# Standard paged search
entries = conn.extend.standard.paged_search(
    search_base='DC=example,DC=com',
    search_filter='(objectClass=user)',
    attributes=['cn', 'memberOf', 'userPrincipalName'],
    page_size=1000,
    paged_size=5000,
    generator=True
)
for entry in entries:
    print(entry['dn'], entry['attributes'].get('userPrincipalName'))
```

### Python — DirSync with ldap3 (low-level)

```python
from ldap3 import Server, Connection, ALL
from ldap3.protocol.formatters.formatters import format_sid
import struct

# DirSync control OID = 1.2.840.113556.1.4.1339
# Value: BER SEQUENCE { flags INTEGER, maxBytes INTEGER, cookie OCTET STRING }
def build_dirsync_control(cookie=b'', flags=0x80000001, max_bytes=0x100000):
    import pyasn1.type.namedtype
    from pyasn1.type.univ import Sequence, Integer, OctetString
    from pyasn1.codec.der import encoder

    seq = Sequence()
    seq.setComponentByPosition(0, Integer(flags))
    seq.setComponentByPosition(1, Integer(max_bytes))
    seq.setComponentByPosition(2, OctetString(cookie))
    return ('1.2.840.113556.1.4.1339', True, encoder.encode(seq))

conn = Connection(Server('dc01.example.com', use_ssl=True, get_info=ALL),
                  user='EXAMPLE\\sync-svc', password='P@ssw0rd!',
                  authentication='NTLM', auto_bind=True)
cookie = b''
while True:
    oid, criticality, value = build_dirsync_control(cookie)
    conn.search('DC=example,DC=com', '(objectClass=*)',
                search_scope='SUBTREE', attributes=['*'],
                controls=[(oid, criticality, value)])
    for entry in conn.entries:
        print(entry.entry_dn)
    # parse the DirSync cookie from the response control
    cookie = next((c[2] for c in conn.result['controls'] if c[0] == oid), None)
    if not cookie:
        break
```

### Python — modify a user password (the BER-quote trick)

```python
from ldap3 import Server, Connection, MODIFY_REPLACE

conn = Connection(Server('dc01.example.com', use_ssl=True),
                  user='EXAMPLE\\admin', password='P@ssw0rd!', auto_bind=True)

# unicodePwd requires TLS. The value is the UTF-16-LE of a quoted password.
new_pwd = '"P@ssw0rd-new!"'.encode('utf-16-le')
conn.modify('CN=jdoe,CN=Users,DC=example,DC=com',
            {'unicodePwd': [(MODIFY_REPLACE, [new_pwd])]})
print(conn.result)
```

### Registry — LDAP server policies (per-DC)

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Policy\
 ├── MaxPoolConnections   = 50         (REG_DWORD)
 ├── MaxReceiveBuffer     = 10485760   (REG_DWORD, default 10 MB)
 ├── MaxConnIdleTime      = 900        (REG_DWORD, sec)
 ├── MaxActiveQueries     = 100        (REG_DWORD)
 ├── MaxQueryDuration     = 120        (REG_DWORD, sec)
 ├── MaxPageSize          = 1000       (REG_DWORD)
 ├── MaxValRange          = 1500       (REG_DWORD)
 ├── MaxNotificationPerConn = 5        (REG_DWORD)
 ├── MaxBatchReturnObjects  = 0        (REG_DWORD, 0 = no batch limit)
 ├── MaxTempTableSize       = 10485760 (REG_DWORD, bytes)
 └── MaxQueryDurationEvent  = 100      (REG_DWORD, query exceeding threshold logs event 1644)
```

## Troubleshooting

- **Event 1644 (Query Performance)** — slow LDAP query. Enable 1644 logging via `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering = 5`, then look at the parsed filter — the first attribute in the filter that is not indexed forces a table scan.
- **`unwillingToPerform (53)` on bind** — common when the bind path is a DN but the server expects UPN. Try `jdoe@example.com` instead of `CN=jdoe,...`. Also returned when SSL is required (registry `LDAPClientIntegrity = 2`) but client used cleartext port 389.
- **`sizeLimitExceeded (4)`** — set `PageSize` (the paged control). The DC's default `MaxPageSize` is 1000; queries without paging are capped.
- **`operationsError (1)` on DirSync** — caller lacks `DS-Replication-Get-Changes` right. Grant on the domain head via `dsacls "DC=example,DC=com" /G "EXAMPLE\sync-svc:CA;DS-Replication-Get-Changes;*"`.
- **SASL GSS-SPNEGO bind returns "invalid credentials"** — usually a Kerberos failure. Run `klist get ldap/dc01.example.com` to verify a service ticket is acquirable; if not, check SPN (`setspn -L dc01$` should show `ldap/dc01.example.com`).
- **Range retrieval returning `member;range=0-*` but no values** — happens when the group has zero members. The attribute will not be present at all; the range syntax is just a Wireshark artifact.
- **`attributeOrValueExists (20)`** on add — usually a single-valued attribute is being set twice in the same request. Use Modify-Replace to overwrite.

## Cross-platform equivalents

- **Linux**: OpenLDAP (`slapd`) implements the same wire protocol (RFC 4511) but a different attribute model. 389-DS (Red Hat / FreeIPA) is closer to AD: supports DirSync-like ` Retro Changelog` plugin, multi-master replication, dynamic schema. Both use the OpenLDAP client library (`libldap`) or Mozilla LDAP C SDK. See `../09-linux-equivalents/09-openldap-389ds.md` (when present).
- **Linux**: SSSD's `ad` provider does LDAP bind via GSS-SPNEGO using `krb5` and `openldap` libraries — see `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux**: Samba 4 ships an LDAP server (`source4/dsdb/samdb/ldb_modules/`) that supports most AD-specific controls when running as a DC. See `../09-linux-equivalents/04-winbind-internals.md`.
- **macOS**: `opendirectoryd` provides a similar LDAP front-end (with Apple-specific extensions) but does not support AD controls (DirSync, paged-results native-but-different, no SD flags control). See `../08-macos-equivalents/06-open-directory.md` (when present).

## References

- RFC 4511 — LDAPv3: The Protocol.
- RFC 4510 — LDAPv3 Technical Specification Road Map.
- RFC 2696 — LDAP Control Extension for Simple Paged Results Manipulation.
- RFC 2891 — LDAP Control Extension for Server Side Sorting.
- RFC 3062 — LDAP Password Modify Extended Operation.
- RFC 4533 — LDAP Content Synchronization Operation.
- MS-ADTS §3.1.1 — Active Directory Technical Specification, LDAP behavior. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/>
- ldap3 Python library docs — <https://ldap3.readthedocs.io>
- OpenLDAP source — <https://github.com/openldap/openldap>
- 389-DS source — <https://github.com/389ds/389-ds-base>
