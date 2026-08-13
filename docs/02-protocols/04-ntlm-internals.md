---
title: NTLM Internals — NTLMv1, NTLMv2, NTLMSSP Three-Message Handshake
audience: senior-engineers
tags: [ntlm, ntlmv1, ntlmv2, ntlmssp, mic, pass-the-hash, relay, lm-hash]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/02-ldap-protocol.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

NTLM is a challenge-response authentication protocol carried inside an SPNEGO- or raw-NTLMSSP-branded GSS-API token, implemented in `lsass.exe!msv1_0.dll` on the server and `msv1_0.dll` (or `ntlmssp.dll` for kernel callers) on the client, with a fixed three-message handshake (NEGOTIATE → CHALLENGE → AUTHENTICATE) where the server issues an 8-byte server challenge and the client returns an HMAC-MD5-derived 24-byte NTLMv2 response plus a variable-length client blob; the protocol authenticates the user without sending the password over the wire but is considered deprecated because (a) the NT hash is the entire secret and is reusable offline (pass-the-hash), (b) the protocol has no mutual authentication, (c) NTLM relay attacks are trivial without channel binding, and (d) LM hash compatibility (`NoLMHash = 0`) leaves 14-char passwords crackable.

## Architecture

```
Client (msv1_0.dll, via SSPI InitializeSecurityContext)
   │
   │── Type 1 (NEGOTIATE)  ──────────►  Server (msv1_0.dll via AcceptSecurityContext)
   │                                       │
   │                                       ├── Resolve server account, fetch NT hash from SAM
   │                                       ├── Generate 8-byte ServerChallenge (random)
   │◄── Type 2 (CHALLENGE)  ───────────────│
   │                                       │
   │   Compute NTLMv2 response using
   │   NTOWFv2 (= HMAC-MD5(NT-hash, UPPER(user)+domain))
   │   applied to ServerChallenge + ClientChallenge + TargetInfo
   │                                       │
   │── Type 3 (AUTHENTICATE)  ─────────►   │
   │                                       ├── Recompute response using stored NT hash
   │                                       ├── If match → return SEC_E_OK
   │                                       ├── Extract session key (encrypts further traffic)
   │◄── SEC_E_OK / SEC_E_LOGON_DENIED  ────│
```

The wire token uses a binary structure (not ASN.1). The leading `NTLMSSP\0` signature (8 bytes, `0x4E 0x54 0x4C 0x4D 0x53 0x53 0x50 0x00`) is constant across all three messages.

## Message structures (MS-NLMP §2.2)

All multi-byte integers are little-endian.

### Type 1 — NEGOTIATE (client → server)

```
Offset  Size  Field
0x00    8     Signature           "NTLMSSP\0"
0x08    4     MessageType         0x00000001  (NTLMSSP_NEGOTIATE)
0x0C    4     NegotiateFlags      bitmask (see below)
0x10    2     DomainNameFields    (Len, MaxLen, BufferOffset — usually 0,0,0)
0x16    2     (continuation)
0x18    2     WorkstationFields
0x1E    2     (continuation)
0x20    8     Version             (optional, only if flag NEGOTIATE_VERSION set)
0x28    var   Payload             DomainName + Workstation (often empty)

Key NegotiateFlags bits:
0x00000001  NEGOTIATE_UNICODE
0x00000002  NEGOTIATE_OEM
0x00020000  REQUEST_TARGET          (client wants server name back in Type 2)
0x00008000  NEGOTIATE_EXTENDED_SESSIONSECURITY  (NTLMv2 / "NTLMv2 session security")
0x00010000  NEGOTIATE_IDENTIFY      (token is for identification only, not impersonation)
0x00040000  TARGET_TYPE_SERVER
0x00200000  NEGOTIATE_VERSION       (Version field is present)
0x00400000  NEGOTIATE_TARGET_INFO   (server should include TargetInfo in Type 2)
0x04000000  NEGOTIATE_128           (128-bit encryption)
0x08000000  NEGOTIATE_KEY_EXCH      (key exchange — session key encrypted)
0x20000000  NEGOTIATE_56            (56-bit key)
0x80000000  NEGOTIATE_ALWAYS_SIGN   (always sign, even if no integrity required)
```

### Type 2 — CHALLENGE (server → client)

```
Offset  Size  Field
0x00    8     Signature           "NTLMSSP\0"
0x08    4     MessageType         0x00000002  (NTLMSSP_CHALLENGE)
0x0C    2     TargetNameFields    Len, MaxLen, BufferOffset
0x10    2     (continuation)
0x14    4     NegotiateFlags      (server-side agreed flags)
0x18    8     ServerChallenge     RANDOM 8 bytes (the "nonce")
0x20    8     Reserved            0x0000000000000000
0x28    2     TargetInfoFields    Len, MaxLen, BufferOffset
0x2C    2     (continuation)
0x2E    2     Version             (optional)
0x30    2     (continuation)
0x30    var   Payload             TargetName (Unicode) + TargetInfo (AV_PAIRs)

TargetInfo is a sequence of AV_PAIRs:
  AvId (USHORT), AvLen (USHORT), Value (AvLen bytes)
AvId values:
  0x0001 MsvAvEOL               (end of list)
  0x0002 MsvAvNbComputerName    (NetBIOS server name)
  0x0003 MsvAvNbDomainName
  0x0004 MsvAvDnsComputerName
  0x0005 MsvAvDnsDomainName
  0x0006 MsvAvDnsTreeName       (forest DNS name)
  0x0007 MsvAvFlags             (DWORD bitmask: 0x01=CONSTRAINED, 0x02=INTEGRITY, 0x04=NTLMv2)
  0x0008 MsvAvTimestamp         (FILETIME — server's current time)
  0x0009 MsvAvSingleHost
  0x000A MsvAvTargetName        (SPN of the server)
  0x000B MsvAvChannelBindings   (SHA-256 hash of the TLS channel bindings, for EPHEMERAL/MIC)
```

### Type 3 — AUTHENTICATE (client → server)

```
Offset  Size  Field
0x00    8     Signature           "NTLMSSP\0"
0x08    4     MessageType         0x00000003  (NTLMSSP_AUTH)
0x0C    2     LmChallengeResponseFields   (Len, MaxLen, BufferOffset)
0x10    2     (continuation)
0x14    2     NtChallengeResponseFields   (Len, MaxLen, BufferOffset)
0x18    2     (continuation)
0x1C    2     DomainNameFields
0x20    2     (continuation)
0x24    2     UserNameFields
0x28    2     (continuation)
0x2C    2     WorkstationFields
0x30    2     (continuation)
0x34    2     EncryptedRandomSessionKeyFields
0x38    2     (continuation)
0x3C    4     NegotiateFlags
0x40    8     MIC                 (Message Integrity Code — HMAC-MD5 of all 3 messages,
                                   keyed with the session key; optional, present if
                                   NEGOTIATE_TARGET_INFO + AvFlags & 0x02)
0x48    8     Version             (optional)
0x50    var   Payload             LM + NT responses + domain + user + workstation + session key
```

### NTLMv2 response structure (the `NtChallengeResponse` payload)

```
NTLMv2_RESPONSE (16 + var bytes):
0x00  16    Response           = HMAC-MD5(NTOWFv2, ServerChallenge + ClientBlob)
0x10  var   ClientBlob         = NTLMv2_CLIENT_CHALLENGE structure (below)

NTLMv2_CLIENT_CHALLENGE:
0x00  4     RespType           0x00000001 (NTLMv2)
0x04  4     HiRespType         0x00000001
0x08  6     Reserved
0x0E  8     Timestamp          (FILETIME, nanoseconds since 1601)
0x16  8     ClientChallenge    RANDOM 8 bytes
0x1E  4     Reserved
0x22  var   AvPairs            (TargetInfo copied from Type 2, may add AvSingleHost etc.)
0x..  4     MsvAvEOL terminator
```

## Response computation

### NTOWFv2 (NT One-Way Function, version 2)

```
NT-hash = MD4(UTF-16-LE(password))                -- 16 bytes
NTOWFv2 = HMAC-MD5(key = NT-hash, msg = UTF-16-LE(UPPER(user) + Domain))   -- 16 bytes
```

Note: `Domain` here is the user's domain, case-sensitive (not uppercased). The user name is uppercased before concatenation. This case-folding is a classic interoperability bug between Samba and Windows.

### NTLMv2 Response

```
SessionBaseKey = HMAC-MD5(NTOWFv2, NTLMv2_RESPONSE)         -- 16 bytes; used to derive session key

Response = HMAC-MD5(
              key  = NTOWFv2,
              msg  = ServerChallenge (8 bytes) ++ ClientBlob (variable)
           )
```

The server stores `NT-hash` in SAM (or AD's `unicodePwd` attribute, which IS the NT-hash). It recomputes NTOWFv2 and the response and compares.

### Session key derivation

```
# With NEGOTIATE_EXTENDED_SESSIONSECURITY:
SessionKey = HMAC-MD5(SessionBaseKey, ServerChallenge ++ ClientChallenge)

# With key exchange (NEGOTIATE_KEY_EXCH):
RandomSessionKey = client-generated 16 random bytes
EncryptedRandomSessionKey = RC4K(SessionBaseKey, RandomSessionKey)
# Server decrypts to get RandomSessionKey; both sides use RandomSessionKey as the session key.

# Without key exchange:
RandomSessionKey = SessionBaseKey
```

Once `RandomSessionKey` is shared, both sides derive the sealing (encryption) and signing (MAC) keys via the "LM / NTLMv2" key derivation (MS-NLMP §3.2.7.1 — NTLMv2 pseudo-protocol). For SMB sealing, this is the key passed to `smb.signing` / `smb.encryption` — but only for SMB1; SMB 2+ uses its own KDF (see SMB protocol file).

### LMv2 response (legacy compatibility)

```
LMv2_RESPONSE = HMAC-MD5(NTOWFv2, ServerChallenge ++ ClientChallenge) ++ ClientChallenge
```

Same key, much shorter payload. Used as a fallback when the server doesn't support NTLMv2 fully. Server checks either LMv2 or NTLMv2 — LMv2 alone is enough.

## MIC and channel binding

### MIC (Message Integrity Code)

If the server includes `AvFlags & 0x02` in TargetInfo, the client computes a MIC over the concatenation of Type 1 + Type 2 + Type 3 messages (without the MIC field in Type 3):

```
MIC = HMAC-MD5(SessionKey, Type1Message ++ Type2Message ++ Type3MessageWithZeroedMIC)
```

The MIC defends against a MITM who would otherwise relay the messages (because the MITM cannot recompute it without the session key). However, the MIC only helps when paired with channel binding.

### Channel binding (with TLS)

When NTLM is layered under TLS (e.g., LDAPS, HTTPS, SMB 3.1.1), the client computes the `MsvAvChannelBindings` AV_PAIR value as `SHA-256(channel_bindings)` where `channel_bindings` is the `initiator_address_type || initiator_address || acceptor_address_type || acceptor_address || application_data`. For TLS, this is the `tls-server-end-point` channel binding type (RFC 5929): `SHA-256(server_cert_signature_algorithm_oid || server_cert_signature)`.

The server includes `MsvAvChannelBindings` in its TargetInfo (with the expected hash precomputed from its TLS cert), and the client includes the same in its Type 3. If the hashes differ (MITM with their own cert), the server rejects.

This defeats NTLM relay attacks against TLS-protected services. Support requires:
- Server: Windows 7+ / Server 2008 R2+ with the corresponding patch (MS16-077 and later).
- Client: Windows 7+ with the registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLmHash = 1` and channel binding enabled.
- The application must call `QueryContextAttributes` with `SECPKG_ATTR_ENDPOINT_BINDINGS` to retrieve the bindings.

### EPHEMERAL flag

`AvFlags & 0x04` (NTLMv2) in the server's TargetInfo tells the client "this is an ephemeral / NTLMv2 session — you cannot derive Kerberos-style delegatable credentials." Affects CredSSP / NLA flows.

## NTLMv1 (deprecated)

NTLMv1 (also called "NTLM" without a version suffix) is the original:

```
NT-response (24 bytes) = DESL(NT-hash, ServerChallenge)   -- 24-byte response
LM-response (24 bytes) = DESL(LM-hash, ServerChallenge)   -- LM hash is uppercased 14-char password
```

`DESL` is a specific DES key derivation: split the 16-byte hash into three 7-byte keys (with parity bits), DES-encrypt the 8-byte challenge with each, concatenate the three 8-byte outputs.

NTLMv1 is disabled by default since Server 2008 R2 (security policy `Network security: LAN Manager authentication level = 5: Send NTLMv2 only; refuse LM & NTLM`). The registry equivalent:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel
  0  Send LM & NTLM responses
  1  Send LM & NTLM — use NTLMv2 if negotiated
  2  Send NTLM only
  3  Send NTLMv2 only
  4  DC: Refuse LM; clients: Send NTLMv2 only, refuse LM
  5  DC: Refuse LM & NTLM; clients: Send NTLMv2 only, refuse LM & NTLM
```

## Storage

The user's NT-hash is stored:

- **In SAM** (local accounts) — `HKLM\SAM\SAM\Domains\Account\Users\<RID>` `V` value, RC4-encrypted with the boot key (syskey). Reg-edit cannot see it without `system` privilege.
- **In AD** — the `unicodePwd` attribute on the user object. Stored in the `linktable` Long-Value tree, encrypted at rest by ESE. Only Domain Admins / Account Operators can read it via LDAP (and even then, the attribute requires `Force-Change-Password` control to set, not read directly).
- **`unicodePwd` is the same as the NT-hash** — there is no separate derivation step. The KDC and the NTLM SSP both consume the same 16-byte value as the long-term key.

### `NoLMHash` registry

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash
  0  Store LM hash alongside NT hash (legacy, BAD — LM hash is the uppercased password truncated to 14 chars)
  1  Do NOT store LM hash (default since XP SP2 / Server 2003 SP1)
```

With `NoLMHash = 1`, the SAM stores only the NT-hash (16 bytes). LM responses from this client are rejected.

## Why NTLM is dangerous

### Pass-the-hash (PtH)

The NT-hash is the secret. An attacker with the NT-hash (e.g., from a `lsass.exe` memory dump) can construct a valid NTLMv2 response without ever knowing the plaintext password. Tools: `mimikatz sekurlsa::pth /user:jdoe /domain:EXAMPLE /ntlm:<hex> /service:cifs /target:dc01`, `impacket/psexec.py -hashes :<nt-hash> jdoe@target`.

Mitigation: Windows Defender Credential Guard (virtualization-based LSASS protection) prevents direct `msv1_0!NtComputeEnCred` access to the hash. Local Admin Password Solution (LAPS) rotates local admin passwords so dump+PtH lateral movement doesn't span machines.

### NTLM relay

A relay attack places the attacker between client and server. The client authenticates to the attacker; the attacker opens a separate connection to the real server and relays the NTLM messages verbatim. Server validates against the real client's NT-hash (which the attacker doesn't need). End result: attacker is authenticated as the client.

Mitigations:
- **SMB signing mandatory** — relayed SMB traffic fails signature check because the attacker cannot recompute signatures without the session key.
- **LDAP signing + channel binding** — same for LDAP.
- **EPA (Extended Protection for Authentication)** — channel binding for HTTP / LDAPS / RPC.
- **Disable NTLM entirely** via audit mode then enforce mode (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictSendingNTLMTraffic = 0|1|2`).

## Wireshark display filters

```
ntlmssp                              # all NTLMSSP messages
ntlmssp.message_type == 1            # Type 1 (NEGOTIATE)
ntlmssp.message_type == 2            # Type 2 (CHALLENGE)
ntlmssp.message_type == 3            # Type 3 (AUTHENTICATE)
ntlmssp.auth.username                # username from Type 3
ntlmssp.auth.domain
ntlmssp.auth.workstation
ntlmssp.ntlm_server_challenge        # the 8-byte challenge in Type 2
ntlmssp.ntlmv2_response              # the NTLMv2 response in Type 3
ntlmssp.ntlmv2_client_challenge      # the client blob
ntlmssp.mic                          # the MIC field
ntlmssp Negotiate Flags
ntlmssp.negotiate_flags.ntlmv2       # NTLMv2 negotiated
ntlmssp.target_info                  # TargetInfo AV_PAIRs
ntlmssp.target_info.msv_av_nb_computer_name
ntlmssp.target_info.msv_av_dns_computer_name
ntlmssp.target_info.msv_av_channel_bindings

# Filter for NTLM over SMB:
smb2.cmd == 1 && ntlmssp
# Filter for NTLM over LDAP:
ldap && ntlmssp
# Filter for NTLM relay attacks (CHALLENGE from one host, AUTHENTICATE to another):
ntlmssp.message_type == 2 and ip.src == 10.0.0.1   # capture from a single host
```

## Configuration / code examples

### PowerShell — audit and disable NTLM

```powershell
# Audit mode: log events 8001, 8002, 8003, 8004 (NTLM client/server activity)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                 -Name "AuditReceivingNTLMTraffic" -Value 1

# Audit mode: log NTLM authentication failures (audit-only)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                 -Name "AuditNTLMInDomain" -Value 1

# Audit + restrict NTLM in domain (clients)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                 -Name "RestrictSendingNTLMTraffic" -Value 1   # 1=allow, 2=deny

# Server-side: restrict incoming NTLM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                 -Name "RestrictReceivingNTLMTraffic" -Value 1  # 1=audit, 2=deny

# Set LmCompatibilityLevel to 5 (refuse LM & NTLM, accept only NTLMv2)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                 -Name "LmCompatibilityLevel" -Value 5
```

### Linux (Samba server-side) — disable NTLMv1

```ini
# /etc/samba/smb.conf
[global]
    ntlm auth = ntlmv2-only          # default in Samba 4.5+; was "yes" (allow NTLMv1) in older
    client ntlmv2 auth = yes
    client use spnego = yes
    lanman auth = no
    client lanman auth = no
    raw NTLMv2 auth = yes
    server signing = mandatory
```

### Python — NTLM relay detection / proof-of-concept (with impacket)

```python
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthChallengeResponse, NTLMMessageSignature
from impacket.smbconnection import SMBConnection

# Connect to a target, get its Type 2 CHALLENGE
conn = SMBConnection("dc01.example.com", "dc01.example.com", preferredDialect=0x311)
# Server's CHALLENGE is exposed during session setup — you can inspect ServerChallenge:
# (Impacket internally handles the NTLM exchange; to inspect raw, use lower-level NTLM class.)

# Compute NTLMv2 response given NT-hash
from impacket.ntlm import computeNTLMv2Response
import hashlib, hmac, struct

def nt_hash(password):
    return hashlib.new('md4', password.encode('utf-16-le')).digest()

def ntlmv2_response(nt_h, user, domain, server_challenge, client_challenge, timestamp, target_info):
    # NTOWFv2 = HMAC-MD5(NT-hash, UPPER(user) + domain)   (UTF-16-LE)
    ntowfv2 = hmac.new(nt_h, (user.upper() + domain).encode('utf-16-le'), 'md5').digest()
    client_blob = (
        b'\x01\x00\x00\x00' + b'\x01\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00' +
        struct.pack('<Q', timestamp) +
        client_challenge +
        b'\x00\x00\x00\x00' +
        target_info +
        b'\x00\x00\x00\x00'
    )
    response = hmac.new(ntowfv2, server_challenge + client_blob, 'md5').digest()
    return response + client_blob

# Example values
server_chal = b'\x11\x22\x33\x44\x55\x66\x77\x88'
client_chal = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
target_info = b'\x02\x00\x0c\x00D\x00C\x00\x01\x00\x1f\x00' + b'E\x00X\x00A\x00M\x00P\x00L\x00E\x00.\x00C\x00O\x00M\x00' + b'\x00\x00\x00\x00'
ts = 0  # FILETIME at 1601-01-01
resp = ntlmv2_response(nt_hash("P@ssw0rd!"), "jdoe", "EXAMPLE", server_chal, client_chal, ts, target_info)
print(resp.hex())
```

### PowerShell — generate a CRC LM hash check (for Samba-style LM compat)

```powershell
# Force-disable LM hash storage
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
# Verify
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").NoLMHash
```

## Troubleshooting

- **Event 4624 with `Authentication Package = NTLM` and `Logon Process = NtLmSsp`** — confirms NTLM was used. Event 8004 (NTLM audit) gives the calling process and target server.
- **`Access denied` with `0xC000006D` (STATUS_LOGON_FAILURE)** — wrong password, or NTLMv1 attempted against an `LmCompatibilityLevel >= 3` server.
- **`0xC0000193` (STATUS_ACCOUNT_EXPIRED)** — the user account has expired; AD stores `accountExpires` and `msDS-User-Account-Control-Computed` flags.
- **NTLM relay blocked at server** — if SMB signing is mandatory and the attacker relays, the relayed session's first signed packet fails signature check. The server logs event 5157 (filtering platform blocked connection).
- **MIC mismatch** — server returns `STATUS_ACCESS_DENIED (0xC0000022)` with internal code `STATUS_INVALID_PARAMETER`. The client's MIC was wrong; usually means the relay attacker doesn't have the session key.
- **Intermittent "trust failed"** — when the secure channel uses NTLM (`NetrServerAuthenticate3`) and the DC's stored machine account password has been reset by another DC, the SC NTLM response fails. Fix: `Test-ComputerSecureChannel -Repair -Credential (Get-Credential)`.
- **`NoLMHash = 0` left from legacy** — `secedit /export /cfg policy.inf` and grep for `NoLMHash`; set to 1 and apply via `secedit /configure /db secedit.sdb /cfg policy.inf`.

## Cross-platform equivalents

- **Linux**: Samba's `winbind` implements the NTLMSSP client and server. `ntlm_auth` helper binary exposed for use by squid, mod_auth_ntlm_winbind. Samba stores the NT-hash in `secrets.tdb` (for the machine account) and in `passdb.tdb` (for local Samba users). See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux**: SSSD can also use NTLMSSP via the `ad` provider when Kerberos is unavailable, but the recommended flow is Kerberos-first with NTLM as a fallback. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux**: `pysmbc`, `impacket-smbclient`, `smbclient` — all implement the NTLMSSP client for SMB access to Windows shares.
- **macOS**: Built-in `smbx.kext` performs NTLMSSP for SMB connections to legacy servers (SMB 1 dialect). Kerberos is preferred for SMB 2+ to AD-joined servers. See `../08-macos-equivalents/03-file-services-smb-nfs.md` (when present).

## References

- MS-NLMP — NT LAN Manager (NTLM) Authentication Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp>
- MS-NTLM — NTLM Authentication Protocol (legacy, superseded by MS-NLMP).
- MS-APDS — Authentication Protocol Domain Support.
- [MS-RPCE] §3.4.4.1 — RPC auth using NTLM.
- Pass-the-Hash whitepapers — SANS, Microsoft.
- RFC 4757 — The Kerberos V5 GSS-API Mechanism: Channel Binding (NTLM Channel Binding Hash).
- RFC 5929 — Channel Bindings for TLS (`tls-server-end-point`).
- Impacket source — `impacket/ntlm.py`. <https://github.com/fortra/impacket>
- Samba NTLM source: `source4/ntlmssp/`, `libcli/auth/ntlmssp*.c`.
