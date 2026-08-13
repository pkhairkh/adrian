---
title: SMB / CIFS Protocol — SMB1 through SMB 3.1.1, MS-SMB2
audience: senior-engineers
tags: [smb, cifs, ms-smb2, smb3, smb-direct, rdma, signing, encryption, oplocks, leasing]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-13
---

SMB against Windows is a single multiplexed connection-orientated protocol over TCP/445 (or, legacy, NetBIOS over TCP/139) where one TCP session carries many logical tree connects, each in turn carrying requests for create / read / write / close / change-notify; Windows Server dialects negotiated range from SMB 1.0 (Windows NT 4.0) through SMB 2.1 (Server 2008 R2) to SMB 3.1.1 (Server 2016+), with security improvements gating at each step: mandatory signing in SMB 2+, AES-CMAC signing in SMB 3+, AES-CCM encryption in SMB 3, and AES-GCM + pre-auth integrity (SHA-512) in SMB 3.1.1. The kernel-side server is `srv2.sys`; the client is `mrxsmb.sys` + `mrxsmb20.sys`.

## Dialect history

| Dialect | Hex | Introduced | Major additions |
|---|---|---|---|
| PC NETWORK PROGRAM 1.0 | — | MS-NET 1985 | The original Core protocol. |
| LANMAN1.0 | — | OS/2 1.2 1989 | Core+ extensions. |
| NT LM 0.12 | — | Windows NT 4.0 | SMB1 named NT Create AndX, transactions, NTLMSSP. |
| SMB 2.0.2 | 0x0202 | Server 2008 / Vista SP1 | New fixed-structure protocol, persistent handles, oplock v2. |
| SMB 2.1 | 0x0210 | Server 2008 R2 / Win 7 | Leasing, large MTU, multi-credit per request. |
| SMB 3.0 | 0x0300 | Server 2012 / Win 8 | Encryption (AES-CCM), multichannel, SMB Direct (RDMA), persistent handles, witness. |
| SMB 3.0.2 | 0x0302 | Server 2012 R2 / Win 8.1 | Minor. |
| SMB 3.1.1 | 0x0311 | Server 2016 / Win 10 | AES-GCM, pre-auth integrity (SHA-512), dialect negotiation downgrade protection. |

SMB1 (`lanman`, `NT LM 0.12`) is officially deprecated and disabled by default in Server 2019+ and Windows 10 1709+ (controlled by `Set-SmbServerConfiguration -EnableSMB1Protocol`).

## Architecture (SMB 2+)

```
TCP 445
 └── SMB2 packet stream
      ├── SMB2 header (64 bytes for SMB 2.x, 68 bytes for SMB 3.1.1 with TransformId)
      ├── SMB2 packet body (Command-specific)
      └── optional encrypted blob (for SMB3 ENCRYPTED commands)

Client side (kernel):
  mrxsmb.sys   → SMB1 redirector
  mrxsmb20.sys → SMB 2.x/3.x redirector
  rdbss.sys    → Redirected Drive Buffering Subsystem — caches, oplock state

Server side (kernel):
  srv2.sys     → SMB 2.x/3.x server
  srv.sys      → SMB1 server (legacy, removable)
  srvnet.sys   → network layer (handles RDMA in SMB Direct)
```

## SMB2 packet header

```
SMB2 Packet Header (64 bytes for SMB 2.x; 68 bytes SMB 3.1.1 when TransformHeader):
Offset  Size  Field
0x00    4     ProtocolId           0x4D 'FE' 'S' 'M'   (0xFE534D42 little-endian)
0x04    2     StructureSize        64 (or 65 for SMB 3.1.1 transform)
0x06    2     CreditCharge         Number of credits this request consumes
0x08    4     Status/ChannelSequence  Status for responses; ChannelSequence for multichannel
0x0C    2     Reserved             (in older specs was NextCommand offset)
0x0E    2     Command              e.g. 0x00=Negotiate, 0x01=SessionSetup, 0x02=Logoff,
                                    0x03=TreeConnect, 0x05=Create, 0x08=Read, 0x09=Write,
                                    0x0C=Close, 0x10=Lock, 0x12=Ioctl, 0x0E=QueryInfo,
                                    0x0F=SetInfo, 0x0D=Flush
0x10    8     SessionId            Identifies the SMB2 session (one per user-auth)
0x18    8     Signature            AES-CMAC-128 over the entire packet (zeroed during compute)
                                     or HMAC-SHA-256 in SMB 2.x
```

For SMB 3.1.1, the `Status/ChannelSequence` field is split: low 4 bytes = ChannelSequence, high 4 bytes = Reserved. The signature is 16 bytes AES-CMAC-128 (SMB 3) or 16 bytes AES-GMAC (SMB 3.1.1 with GCM).

### Compounded requests

Multiple SMB2 commands can be chained in a single TCP segment. Each command's `NextCommand` field (in the header, replacing the `Reserved` field per MS-SMB2 §2.2.1.1) gives the offset to the next command. The final command has `NextCommand = 0`. The server processes them in order. Typical use: TreeConnect + Create + Close in one segment.

## Negotiate (Command 0x0000)

Client lists supported dialects; server picks the highest mutually supported.

```
SMB2 NEGOTIATE Request:
0x00  36  StructureSize = 36
0x02  2   DialectCount
0x04  2   SecurityMode   (1=SIGNING_ENABLED, 2=SIGNING_REQUIRED)
0x06  2   Reserved
0x08  2   Capabilities   (0x1=DFS, 0x2=LEASING, 0x4=LARGE_MTU, 0x8=MULTICHANNEL,
                          0x10=ENCRYPTION (SMB3), 0x20=DIR_LEASING, 0x40=PERSISTENT_HANDLES)
0x0C  4   ClientGuid     (used for persistent-handle reconnection)
0x10  8   NegotiateContextOffset  (SMB 3.1.1+; offset to first NegotiateContext)
0x14  2   NegotiateContextCount
0x16  2   Reserved2
0x18  var Dialects[]      (each 2 bytes: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)

SMB2 NEGOTIATE Response:
0x00  65  StructureSize = 65
0x02  2   SecurityMode
0x04  2   DialectRevision    (e.g. 0x0311)
0x06  2   Reserved
0x08  4   ServerGuid
0x0C  4   Capabilities
0x10  4   MaxTransactSize
0x14  4   MaxReadSize
0x18  4   MaxWriteSize
0x1C  8   SystemTime
0x24  8   BootTime
0x2C  2   SecurityBufferOffset
0x2E  2   SecurityBufferLength
0x30  4   Reserved3
0x34  var SecurityBuffer     (GSS-SPNEGO TokenResponse — NTLMSSP or Kerberos)
```

### SMB 3.1.1 Negotiate Context List

After `SecurityBuffer`, optional `NegotiateContextList`:

| ContextType | Name | Purpose |
|---|---|---|
| 0x0001 | SMB2_PREAUTH_INTEGRITY_CAPABILITIES | Hash algorithms supported: 0x0001 = SHA-512. |
| 0x0002 | SMB2_ENCRYPTION_CAPABILITIES | Ciphers supported: 0x0001 = AES-128-CCM, 0x0002 = AES-128-GCM, 0x0003 = AES-256-CCM, 0x0004 = AES-256-GCM. |
| 0x0003 | SMB2_COMPRESSION_CAPABILITIES | LZNT1, LZ77, LZ77+Huffman, Pattern_V1. |
| 0x0005 | SMB2_NETNAME_NEGOTIATE_CONTEXT_ID | Server's NetBIOS name. |
| 0x0006 | SMB2_TRANSPORT_CAPABILITIES | RDMA transport flags. |
| 0x0008 | SMB2_SIGNING_CAPABILITIES | HMAC-SHA256, AES-CMAC, AES-GMAC. |

Pre-auth integrity (SHA-512) hashes the entire Negotiate exchange — protects against MITM dialect downgrade. The hash becomes the input to the Session Key derivation.

## Session Setup (Command 0x0001)

Auth flow uses SPNEGO over GSS-API (RFC 4178). The wire payload is a GSS-API Token ( ASN.1 DER-encoded `NegotiationToken`).

```
SMB2 SESSION_SETUP Request:
0x00  25  StructureSize = 25
0x02  1   Flags            (0x01 = binding a new session to existing)
0x03  1   SecurityMode
0x04  4   Capabilities
0x08  4   Channel          (0x00000000 = none, 0x00000001 = SMB2_CHANNEL_64)
0x0C  2   SecurityBufferOffset
0x0E  2   SecurityBufferLength
0x10  8   PreviousSessionId (for session reconnect after server reboot)
0x18  var SecurityBuffer   (GSS-SPNEGO TokenRequest)
```

Multiple round trips are allowed: client sends Type 1 NTLMSSP, server replies with Type 2 (challenge), client sends Type 3 (auth), server returns STATUS_SUCCESS. With Kerberos, the exchange is typically a single round trip.

## Tree Connect (Command 0x0003)

```
SMB2 TREE_CONNECT Request:
0x00  9   StructureSize = 9
0x02  2   Reserved
0x04  2   PathOffset
0x06  2   PathLength
0x08  var Path              (e.g. "\\dc01\NETLOGON" or "\\server\IPC$")
```

TreeConnect flags in the response:
- 0x0001 = SMB2_SHAREFLAG_CLUSTER
- 0x0002 = SMB2_SHAREFLAG_CONTINUOUS_AVAILABILITY (CA share)
- 0x0004 = SMB2_SHAREFLAG_DFS
- 0x0008 = SMB2_SHAREFLAG_DFS_ROOT
- 0x0010 = SMB2_SHAREFLAG_ENCRYPT_DATA (SMB 3+)

The share type in the response (0x01 = DISK, 0x02 = PIPE, 0x03 = PRINT) tells the client what kind of resource the tree refers to.

## Create (Command 0x0005)

The most complex command. Maps to `NtCreateFile` semantics.

```
SMB2 CREATE Request:
0x00  57  StructureSize = 57
0x02  1   Reserved
0x03  1   OplockLevel      (0x00=none, 0x01=II, 0x08=V2_BATCH, 0xFF=LEASE)
0x04  4   ImpersonationLevel  (0=Anonymous, 1=Identification, 2=Impersonation, 3=Delegate)
0x08  8   SmbCreateFlags
0x10  8   Reserved
0x18  4   DesiredAccess    (FILE_READ_DATA, FILE_WRITE_DATA, etc.)
0x1C  4   FileAttributes
0x20  4   ShareAccess      (0x01=READ, 0x02=WRITE, 0x04=DELETE)
0x24  4   CreateDisposition (1=Supercede, 2=Open, 3=Create, ...)
0x28  4   CreateOptions
0x2C  2   NameOffset
0x2E  2   NameLength
0x30  4   CreateContextsOffset
0x34  4   CreateContextsLength
0x38  var Name (UTF-16-LE)
0x..  var CreateContexts   (chain of context blobs: DurableHandle, Lease,
                            QueryMaximalAccess, ExtendedAttribute, ...)
```

Create contexts:

| ContextName | Purpose |
|---|---|
| `DH2Q` (0x44483251) | Durable Handle v2 Request — survives network outage if reconnecting within lease. |
| `DH2C` (0x44483243) | Durable Handle v2 Reconnect. |
| `RqLs` (0x52714C73) | Request Lease — oplock-like client-side caching of metadata. |
| `MxAc` (0x4D784163) | Query Maximal Access — return the access mask the caller has. |
| `AlsI` (0x416C7349) | Allocation Size hint. |
| `TWrp` (0x54577270) | Time Warp — open at a previous VSS shadow copy timestamp. |
| `QFid` (0x51466964) | Query File ID. |

## Read / Write / Close / Lock

```
SMB2 READ:
0x00  17  StructureSize = 17
0x02  1   Padding
0x03  1   Flags        (0x01 = READ_RESPONSE_FROM_FILESYSTEM_CACHED)
0x04  4   Length
0x08  8   Offset
0x10  8   FileId
0x18  4   MinimumCount (return only when this many bytes read)
0x1C  4   Channel
0x20  4   RemainingBytes
0x24  2   ReadChannelInfoOffset
0x26  2   ReadChannelInfoLength
0x28  4   Buffer   (RDMA channel descriptor for SMB Direct)

SMB2 WRITE:
0x00  49  StructureSize = 49
0x02  2   DataOffset
0x04  4   Length
0x08  8   Offset
0x10  8   FileId
0x18  4   Channel
0x1C  4   RemainingBytes
0x20  2   WriteChannelInfoOffset
0x22  2   WriteChannelInfoLength
0x24  4   Flags         (0x01 = WRITE_THROUGH, 0x02 = WRITE_UNBUFFERED)
0x28  var Data

SMB2 CLOSE:
0x00  24  StructureSize = 24
0x02  2   Flags       (0x01 = POSTQUERY_ATTRIB — return attribs on close)
0x04  4   Reserved
0x08  8   FileId
```

## Oplocks and leasing

Oplock (opportunistic lock) is a server-granted hint to a single client that it has exclusive cache rights. Levels:

| Level | Hex | Description |
|---|---|---|
| None | 0x00 | No oplock. |
| Level II (read) | 0x01 | Multiple readers can cache reads. |
| Batch | 0x02 | Client can cache reads/writes AND defer close (used for batch file open/close in executables). |
| Exclusive (v1) | 0x04 | Single-client exclusive write cache. |
| Level II + caching | (Lease state) | |
| Lease v2 | (SMB 2.1+) | Lease key per client (GUID); client holds lease on whole-handle cache. |

SMB 2.1+ **leases** (RqLs context in Create): the client holds a lease state (None, Read, Handle, Write, Read-Handle, Write-Handle, Read-Write, Read-Write-Handle) for the file by `LeaseKey` (a client-chosen GUID). Leases survive brief network outage (up to `LeaseBreak` timeout, default 16 s). On a lease break, the server sends an async BREAK notification, and the client must acknowledge.

SMB 3.0 **persistent handles** (DH2Q context in Create): handles survive server-cluster failover if the share is marked `CONTINUOUS_AVAILABILITY` (CSV-backed SOFS). Client reconnects via `DH2C` context after the cluster moves the file server role.

## Signing

| Dialect | Algorithm | Key derivation |
|---|---|---|
| SMB 1.0 | HMAC-MD5 | Session key from auth |
| SMB 2.0 | HMAC-SHA-256 (truncated to 16 bytes) | Session key + "SMB2AESCMAC..." |
| SMB 2.1 | HMAC-SHA-256 | Same |
| SMB 3.0 | AES-CMAC-128 (16 bytes) | `KDF(SessionKey, "SMB2AESCMAC\x00", "SmbSign\x00")` |
| SMB 3.0.2 | AES-CMAC-128 | Same |
| SMB 3.1.1 | AES-GMAC-128 (selected via Signing Capabilities context) | Derived with `KDF(SessionKey, "SMBSigningKey\x00", "SmbSign\x00")` |

SMB 3.1.1 also uses **pre-auth integrity** (SHA-512) to bind the Negotiate exchange to the session key derivation, preventing MITM downgrade attacks.

## Encryption

SMB 3.0+ supports per-message encryption. Toggle by share flag (`SMB2_SHAREFLAG_ENCRYPT_DATA`) or session-wide (`Smb2Session.Flags & SMB2_SESSION_FLAG_ENCRYPT_DATA`). Cipher:

| Dialect | Cipher | Key derivation |
|---|---|---|
| SMB 3.0 / 3.0.2 | AES-128-CCM | `KDF(SessionKey, "SMB2AESCCM\x00", "ServerIn\x00" / "ServerOut\x00")` |
| SMB 3.1.1 (negotiated CCM) | AES-128-CCM | `KDF(SessionKey, "SMB2AESCCM\x00", "ServerIn\x00" / "ServerOut\x00")` |
| SMB 3.1.1 (negotiated GCM) | AES-128-GCM | `KDF(SessionKey, "SMBAESGCM\x00", "ServerIn\x00" / "ServerOut\x00")` |
| SMB 3.1.1 (AES-256-GCM) | AES-256-GCM | Same KDF label |

Encrypted packets use `SMB2_TRANSFORM_HEADER` (0xFD 'S' 'M' 'B' 0x00000000 as protocolId):

```
SMB2 Transform Header (52 bytes):
0x00  4   ProtocolId         0x46534D42 (no, actually 0xFD 'S' 'M' 'B' for transform)
0x04  2   Signature          AES-GCM tag (16 bytes) — overlaps here
...
0x14  2   EncryptionAlgorithm  (0x0001 = AES-128-CCM, 0x0002 = AES-128-GCM, 0x0003/4 = 256)
0x16  2   Reserved
0x18  8   SessionId
0x20  var EncryptedMessage   (Nonce 12 bytes + ciphertext + tag 16 bytes)
```

When encryption is enabled, signing is implicit (GCM tag authenticates) and the `Signature` field of regular packets is unused.

## Multichannel and SMB Direct

- **Multichannel** — one SMB session spans multiple TCP connections across multiple NICs of the same client. Each connection has its own credit pool. Max throughput = sum of all channels. Requires Server 2012+.
- **SMB Direct (RDMA)** — SMB over InfiniBand / RoCE / iWARP via `srvnet.sys` and the RDMA provider's miniport. Zero-copy on large reads/writes. Kernel-mode data path bypasses the TCP stack entirely.
- **SMB Multichannel**: client discovers server NICs via `SRV_GET_INFO` ioctl (`FSCTL_QUERY_NETWORK_INTERFACE_INFO`), chooses the best NIC pairs (RSS, RDMA-capable) and opens additional channels.

## Wireshark display filters

```
smb2                       # all SMB 2/3 traffic
smb2.cmd == 0              # Negotiate
smb2.cmd == 1              # Session Setup
smb2.cmd == 5              # Create
smb2.cmd == 8              # Read
smb2.cmd == 9              # Write
smb2.cmd == 12             # Close
smb2.dialect == 0x311      # SMB 3.1.1
smb2.dialect == 0x300      # SMB 3.0
smb2.capabilities.leasing
smb2.capabilities.encryption
smb2.negotiate_context.preauth_integrity
smb2.negotiate_context.encryption
smb2.flags.encrypted       # Transform-header wrapped
smb2.flags.signed          # Signed
smb2.oplock_level == 0xff  # Lease
smb2.filename contains "NETLOGON"
smb2.filename contains "SYSVOL"

# SMB1 (legacy)
smb || smb1
smb1.command == 0x72        # Negotiate
```

## Configuration / code examples

### PowerShell — server-side configuration

```powershell
# Show SMB server settings
Get-SmbServerConfiguration | Format-List EnableSMB1Protocol, EnableSMB2Protocol,
    RequireSecuritySignature, EnableSecuritySignature, EncryptData,
    EnableMultiChannel, EnableLeasing, EnableStrictNameChecking,
    AnnounceServer, MaxSessionPerConnection

# Harden: require signing, disable SMB1, enable encryption on shares
Set-SmbServerConfiguration -EnableSMB1Protocol $false `
                           -EnableSMB2Protocol $true `
                           -RequireSecuritySignature $true `
                           -EnableSecuritySignature $true `
                           -EncryptData $true `
                           -Force

# Per-share config
Get-SmbShare -Special $false | Select Name, EncryptData, CachingMode
Set-SmbShare -Name "Share01" -EncryptData $true -CachingMode Documents

# Inspect open files / sessions
Get-SmbOpenFile | Format-Table ClientUserName, Path, ClusterRe Share
Get-SmbSession | Format-Table ClientUserName, ClientComputerName, NumOpens
Get-SmbConnection | Format-Table ServerName, ShareName, UserName, Dialect, Signed, Encrypted
```

### Linux (Samba server-side) — `smb.conf` example

```ini
[global]
    server min protocol = SMB3_11          # require SMB 3.1.1
    server max protocol = SMB3_11
    client min protocol = SMB3_11
    server signing = mandatory
    client signing = mandatory
    smb encrypt = required                 # require encryption
    ntlm auth = disabled                   # disable NTLMv1
    kerberos method = secrets and keytab
    log level = 3 auth:5 smb2:2

    # Multichannel
    server multi channel support = yes
    aio read size = 1
    aio write size = 1

    # Leasing
    kernel oplocks = yes
    oplocks = yes
    level2 oplocks = yes

[share01]
    path = /srv/samba/share01
    read only = no
    vfs objects = acl_xattr                 # AD ACL support via xattr
    map acl inherit = yes
    store dos attributes = yes
```

### Python — read a file from SMB share via impacket

```python
from impacket.smbconnection import SMBConnection, FILE_READ_DATA, FILE_SHARE_READ

# Connect with SMB 3.1.1 dialect
conn = SMBConnection("dc01.example.com", "dc01.example.com",
                     preferredDialect=0x311,
                     useSecurityMechanism="smb3")
conn.kerberosLogin(user="jdoe", password="P@ssw0rd!",
                   domain="EXAMPLE.COM",
                   kdcHost="dc01.example.com",
                   aesKey="<256-bit hex AES key>")

# Connect to a tree and open a file
conn.connectTree("share01")
fh = conn.openFile("share01", "\\docs\\secret.txt",
                   desiredAccess=FILE_READ_DATA,
                   shareMode=FILE_SHARE_READ)
data = conn.readFile("share01", fh, 0, 4096)
print(data)
conn.closeFile("share01", fh)
conn.logoff()
```

### Samba source paths of note

- `source3/smbd/` — Samba 3 (SMB1) server core; `smbd/server.c` is `main()`.
- `source4/smbd/` and `source3/smbd/smb2_*.c` — SMB 2/3 server (smbd/smb2_negprot.c, smbd/smb2_sesssetup.c, smbd/smb2_tcon.c, smbd/smb2_create.c, smbd/smb2_read.c, smbd/smb2_write.c, smbd/smb2_close.c, smbd/smb2_lock.c).
- `source3/libsmb/` — client libs (libsmbclient).
- `source4/torture/` — SMB torture tests (smb2.read, smb2.notify, smb2.durable_v2, smb2.lease, smb2.aes, smb2.signing, smb2.contexts).
- `source3/librpc/idl/smb2.idl` — Samba's SMB2 IDL.

## Troubleshooting

- **`STATUS_ACCESS_DENIED (0xC0000022)` on TreeConnect** — caller lacks share-level permission. Inspect via `Get-SmbShareAccess -Name <share>`. SPN on the share's underlying service account may also be missing.
- **Sign-algorithm mismatch (SMB 2 vs SMB 3.1.1)** — Windows 10 1709+ clients can refuse SMB 2 connections to non-domain-joined servers; check `Set-SmbClientConfiguration -RequireSecuritySignature`.
- **Multichannel not engaging** — both client and server NICs must have RSS (Receive Side Scaling) enabled. `Get-NetAdapterRss` on both sides. Verify with `Get-SmbMultichannelConnection`.
- **Persistent handle broken after CSV failover** — share must be marked CA (Continuous Availability): `Set-SmbShare -Name X -ContinuouslyAvailable $true`. The CA flag is only available on Cluster Shared Volumes (CSV).
- **Negotiate dialect downgrade** — Wireshark shows `0x0300` even though client supports `0x0311`. Check `server min protocol` on Samba or `Set-SmbServerConfiguration` (no min setting natively on Windows; GPO `Microsoft network server: Minimum SMB protocol version`).
- **Encryption failed on existing session** — happens when negotiating AES-256-GCM but only AES-128 is enabled. Verify with `Get-SmbConnection | Format-List Dialect, Cipher`.
- **ClientCertAuth via SMB** — not supported; SMB auth is always SPNEGO (NTLM / Kerberos). For cert-based access, layer on top of IPsec.

## Cross-platform equivalents

- **Linux (client)**: Linux CIFS utils (`mount.cifs`) + `cifs.ko` kernel module. Supports SMB 3.1.1 dialect since kernel 5.x. Mount option `vers=3.1.1,seal` enables encryption. See `../09-linux-equivalents/04-winbind-internals.md` for Samba-side auth integration.
- **Linux (server)**: Samba 4 (`smbd`) — implements SMB 1.0 through 3.1.1, with most AD-interop features (DFS, Kerberos, ACLs, multichannel). Sources above. See `../09-linux-equivalents/04-winbind-internals.md`.
- **macOS**: Built-in `smbx.kext` (Apple's SMBX kernel extension, replaced `smbfs.kext`). Supports SMB 3.0.2; SMB 3.1.1 support added in macOS 13. `mount_smbfs` command-line wrapper. Apple's implementation has known quirks with multichannel and persistent handles. See `../08-macos-equivalents/03-file-services-smb-nfs.md` (when present).

## References

- MS-SMB2 — Server Message Block (SMB) Protocol Versions 2 and 3. <https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2>
- MS-CIFS — SMB 1.0 (legacy).
- MS-SRVS — Server Service.
- MS-SMBD — SMB Direct (RDMA).
- MS-SWN — SMB Witness Protocol.
- SNIA SMB 2/3 specification snapshot.
- Samba source: <https://gitlab.com/samba-team/samba>.
- `smbd/smb2_*.c` reference (above).
