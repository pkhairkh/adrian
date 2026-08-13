---
title: Wireshark / tshark Filter Cookbook for AD Protocols
audience: senior-engineers
tags: [wireshark, tshark, kerberos, ldap, smb, ntlm, dcerpc, dns, network, troubleshooting]
related:
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/07-ntp-time-sync.md
  - ../02-protocols/08-spn-upn-pac.md
  - ./04-wireshark-tshark-filters.md
last_updated: 2026-08-13
---

# Wireshark / tshark Filter Cookbook for AD Protocols

Capture and display filters for every AD-relevant protocol. BPF for `tcpdump`/tshark capture, Wireshark display filters for post-capture analysis.

## Capture filters (BPF — used at packet-capture time)

| Goal | BPF |
|---|---|
| All AD-relevant ports on one host | `host dc01.corp.example.com and (tcp port 88 or tcp port 389 or tcp port 445 or tcp port 3268 or tcp port 135 or udp port 53 or udp port 123)` |
| Kerberos only (TCP+UDP) | `tcp port 88 or udp port 88` |
| LDAP + LDAPS | `tcp port 389 or tcp port 636` |
| SMB | `tcp port 445` |
| Global Catalog | `tcp port 3268 or tcp port 3269` |
| RPC EPM | `tcp port 135` |
| DNS (SRV lookups) | `udp port 53 or tcp port 53` |
| NTP (MS-SNTP) | `udp port 123` |
| Kerberos password change (RFC 3244) | `tcp port 464 or udp port 464` |
| CEP/CES (cert enrollment) | `tcp port 443 and host certenroll.corp.example.com` |
| Host filter | `host 10.10.0.10` |
| Two-host filter | `host 10.10.0.10 and host 10.10.0.20` |
| Exclude noise | `not (port 22 or port 443)` |
| Filter out local management | `not (host 10.10.0.5 and port 161)` |

`tshark` invocation with BPF:

```bash
tshark -i eth0 -f "host dc01.corp.example.com and (tcp port 88 or tcp port 389 or tcp port 445)"
```

## Display filters — Kerberos

| Goal | Filter |
|---|---|
| Any Kerberos | `kerberos` |
| AS-REQ (msg_type 10) | `kerberos.msg_type == 10` |
| AS-REP (msg_type 11) | `kerberos.msg_type == 11` |
| TGS-REQ (msg_type 12) | `kerberos.msg_type == 12` |
| TGS-REP (msg_type 13) | `kerberos.msg_type == 13` |
| AP-REQ (msg_type 14) | `kerberos.msg_type == 14` |
| AP-REP (msg_type 15) | `kerberos.msg_type == 15` |
| KRB-ERROR (msg_type 30) | `kerberos.msg_type == 30` |
| Protocol version 5 | `kerberos.pvno == 5` |
| RC4-HMAC (etype 0x17 = 23) | `kerberos.etype == 0x17` |
| AES-128 (etype 0x11 = 17) | `kerberos.etype == 0x11` |
| AES-256 (etype 0x12 = 18) | `kerberos.etype == 0x12` |
| AES-256-CTS-HMAC-SHA384 (etype 0x13) | `kerberos.etype == 0x13` |
| Client name matches | `kerberos.CName` (use `contains` for substring) |
| Service name matches | `kerberos.SName` |
| Specific realm | `kerberos.realm == "CORP.EXAMPLE.COM"` |
| Pre-auth type (PA-ENC-TIMESTAMP = 2) | `kerberos.patype == 2` |
| PA-FX-FAST (type 149) | `kerberos.patype == 149` |
| PA-PK-AS-REQ (type 16, PKINIT) | `kerberos.patype == 16` |
| Ticket flags: forwardable | `kerberos.flags.F` |
| Ticket flags: renewable | `kerberos.flags.R` |
| Ticket flags: pre-authenticated | `kerberos.flags.T` |
| KRB-AP-ERR_SKEW (clock skew) | `kerberos.error_code == 37` |
| KRB-AP-ERR_BAD_INTEGRITY (signing) | `kerberos.error_code == 31` |
| KDC_ERR_PREAUTH_REQUIRED | `kerberos.error_code == 25` |
| KDC_ERR_PREAUTH_FAILED | `kerberos.error_code == 24` |
| KDC_ERR_S_PRINCIPAL_UNKNOWN (SPN missing) | `kerberos.error_code == 7` |
| AS-REQ containing PAC request | `kerberos.pac.request == 1` |

### Combine filters

```
# All Kerberos errors
kerberos.msg_type == 30

# Failed pre-auth on AS-REQ
kerberos.msg_type == 10 and kerberos.error_code == 24

# TGS-REQ for cifs/ service
kerberos.msg_type == 12 and kerberos.SName contains "cifs"

# RC4 tickets (should be rare on modern DCs — security signal)
kerberos.msg_type == 11 and kerberos.etype == 0x17

# PKINIT (smart-card logon)
kerberos.msg_type == 10 and kerberos.patype == 16
```

## Display filters — LDAP

| Goal | Filter |
|---|---|
| Any LDAP | `ldap` |
| BindRequest (msg 0x00) | `ldap.messageType == 0x00` |
| BindResponse (msg 0x01) | `ldap.messageType == 0x01` |
| UnbindRequest (msg 0x02) | `ldap.messageType == 0x02` |
| SearchRequest (msg 0x03) | `ldap.messageType == 0x03` |
| SearchResultEntry (msg 0x04) | `ldap.messageType == 0x04` |
| SearchResultDone (msg 0x05) | `ldap.messageType == 0x05` |
| ModifyRequest (msg 0x06) | `ldap.messageType == 0x06` |
| AddRequest (msg 0x08) | `ldap.messageType == 0x08` |
| DelRequest (msg 0x0a) | `ldap.messageType == 0x0a` |
| ExtendedRequest (msg 0x17) | `ldap.messageType == 0x17` |
| Search filter (literal) | `ldap.search_filter` |
| Specific objectclass | `ldap.objectclass == "user"` |
| Bind with simple auth | `ldap.mechanism == "simple"` (note: this is implicit when no SASL) |
| Bind with SASL GSSAPI | `ldap.mechanism == "GSSAPI"` |
| Bind with SASL GSS-SPNEGO | `ldap.mechanism == "GSS-SPNEGO"` |
| Result code (0 = success) | `ldap.result_code == 0` |
| Result code 1 (operationsError) | `ldap.result_code == 1` |
| Result code 49 (invalidCredentials) | `ldap.result_code == 49` |
| Result code 32 (noSuchObject) | `ldap.result_code == 32` |
| Paged control (1.2.840.113556.1.4.319) | `ldap.control == "1.2.840.113556.1.4.319"` |
| SD Flags control (.801) | `ldap.control == "1.2.840.113556.1.4.801"` |
| DirSync control (.1339) | `ldap.control == "1.2.840.113556.1.4.1339"` |
| Tree Delete control (.529) | `ldap.control == "1.2.840.113556.1.4.529"` |
| StartTLS extended op | `ldap.oid == "1.3.6.1.4.1.1466.20037"` |

### Combine

```
# All searches for users
ldap.messageType == 0x03 and ldap.objectclass == "user"

# Bind failures
ldap.messageType == 0x01 and ldap.result_code == 49

# SASL GSSAPI binds
ldap.messageType == 0x00 and ldap.mechanism == "GSSAPI"

# Large search results (paged) — page size in cookie
ldap.messageType == 0x03 and ldap.control == "1.2.840.113556.1.4.319"
```

## Display filters — SMB

| Goal | Filter |
|---|---|
| Any SMB2 | `smb2` |
| Negotiate (cmd 0) | `smb2.cmd == 0` |
| Session Setup (cmd 1) | `smb2.cmd == 1` |
| Tree Connect (cmd 3) | `smb2.cmd == 3` |
| Tree Disconnect (cmd 4) | `smb2.cmd == 4` |
| Create (cmd 5) | `smb2.cmd == 5` |
| Close (cmd 6) | `smb2.cmd == 6` |
| Read (cmd 8) | `smb2.cmd == 8` |
| Write (cmd 9) | `smb2.cmd == 9` |
| Lock (cmd 10) | `smb2.cmd == 10` |
| IOCTL (cmd 11) | `smb2.cmd == 11` |
| Echo (cmd 13) | `smb2.cmd == 13` |
| SMB2 dialect 0x311 (SMB 3.1.1) | `smb2.dialect == 0x311` |
| SMB2 dialect 0x300 (SMB 3.0) | `smb2.dialect == 0x300` |
| Encrypted payload | `smb2.flags.encrypt` |
| Signed payload | `smb2.flags.signed` |
| Async operation | `smb2.flags.async` |
| Tree Connect to SYSVOL | `smb2.path contains "SYSVOL"` |
| Tree Connect to IPC$ | `smb2.path contains "IPC$"` |
| Session Setup with Kerberos (AP-REQ) | `smb2.cmd == 1 and kerberos.msg_type == 14` |
| Session Setup with NTLM | `smb2.cmd == 1 and ntlmssp` |
| Oplock break | `smb2.cmd == 18` |
| Lease break | `smb2.cmd == 18 and smb2.flags.lease` |

### Combine

```
# All SMB3.1.1 sessions
smb2.cmd == 1 and smb2.dialect == 0x311

# Encrypted SMB writes
smb2.cmd == 9 and smb2.flags.encrypt

# Kerberos-authenticated tree connects
smb2.cmd == 3 and kerberos.msg_type == 14

# Failed session setups (NTLM)
smb2.cmd == 1 and ntlmssp and smb2.nt_status != 0x00000000
```

## Display filters — DCE/RPC and DRSR

| Goal | Filter |
|---|---|
| Any DCE/RPC | `dcerpc` |
| Bind (Request, pkt_type 11) | `dcerpc.pkt_type == 11` |
| Bind Ack (12) | `dcerpc.pkt_type == 12` |
| Request (0) | `dcerpc.pkt_type == 0` |
| Response (2) | `dcerpc.pkt_type == 2` |
| Fault (3) | `dcerpc.pkt_type == 3` |
| Auth3 (16) | `dcerpc.pkt_type == 16` |
| Alter Context (14) | `dcerpc.pkt_type == 14` |
| Call ID (specific) | `dcerpc.cn_call_id == 1` |
| Specific interface UUID | `dcerpc.cn_ctx_item_uuid == "e3514235-8b63-11d0-a26c-00a0c92b955c"` (DRSUAPI) |
| DRSUAPI opnum 3 (DRSGetNCChanges) | `dcerpc.opnum == 3` (only if interface is DRSUAPI — combine with ctx uuid) |
| NRPC opnum 26 (NetrServerAuthenticate3) | `dcerpc.opnum == 26 and dcerpc.cn_ctx_item_uuid == "12345678-1234-abcd-ef00-01234567cffb"` |
| MS-WCCE / ICertPassage | `dcerpc.cn_ctx_item_uuid == "91b9b93a-57b4-11d0-8f16-00a0484d6c9c"` |
| LSARPC | `dcerpc.cn_ctx_item_uuid == "12345778-1234-abcd-ef00-0123456789ab"` |
| EPMAP (endpoint mapper) | `dcerpc.cn_ctx_item_uuid == "e1af8308-5d1f-11c9-91a4-08002b14a0fa"` |
| Auth level: none (1) | `dcerpc.auth_level == 1` |
| Auth level: connect (2) | `dcerpc.auth_level == 2` |
| Auth level: call (3) | `dcerpc.auth_level == 3` |
| Auth level: pkt integrity (4) | `dcerpc.auth_level == 4` |
| Auth level: pkt privacy (6) | `dcerpc.auth_level == 6` |
| Auth type: Kerberos (9) | `dcerpc.auth_type == 9` |
| Auth type: SPNEGO (10) | `dcerpc.auth_type == 10` |
| Auth type: NTLMSSP (10 also for SPNEGO; raw 0x0A is NTLMSSP at MS-RPCE level) | `dcerpc.auth_type == 10` (verify via `ntlmssp` filter) |

### Combine

```
# All DRSUAPI traffic
dcerpc.cn_ctx_item_uuid == "e3514235-8b63-11d0-a26c-00a0c92b955c"

# DRSGetNCChanges calls (replication)
dcerpc.cn_ctx_item_uuid == "e3514235-8b63-11d0-a26c-00a0c92b955c" and dcerpc.opnum == 3

# NetrServerAuthenticate3 (machine secure channel)
dcerpc.cn_ctx_item_uuid == "12345678-1234-abcd-ef00-01234567cffb" and dcerpc.opnum == 26

# Privacy-level DCE/RPC (encrypted)
dcerpc.auth_level == 6

# Kerberos-authenticated DCE/RPC
dcerpc.auth_type == 9
```

## Display filters — NTLM

| Goal | Filter |
|---|---|
| Any NTLMSSP | `ntlmssp` |
| Type 1 NEGOTIATE | `ntlmssp.message_type == 1` |
| Type 2 CHALLENGE | `ntlmssp.message_type == 2` |
| Type 3 AUTHENTICATE | `ntlmssp.message_type == 3` |
| Domain name | `ntlmssp.auth.domainname == "CORP"` |
| Username | `ntlmssp.auth.username == "jsmith"` |
| Workstation name | `ntlmssp.auth.workstation == "HOST01"` |
| Negotiate Unicode | `ntlmssp.negotiate_flags.unicode` |
| Negotiate OEM | `ntlmssp.negotiate_flags.oem` |
| Sign required | `ntlmssp.negotiate_flags.sign` |
| Seal required | `ntlmssp.negotiate_flags.seal` |
| NTLMv2 | `ntlmssp.auth.ntlmv2_response` (presence indicates NTLMv2) |
| Extended Session Security | `ntlmssp.negotiate_flags.ext_session_sec` |

### Combine

```
# All NTLM authentication attempts by user
ntlmssp.auth.username == "jsmith"

# NTLMv2 only (NTLMv1 deprecated but still seen)
ntlmssp.message_type == 3 and ntlmssp.auth.ntlmv2_response

# NTLM over SMB
smb2.cmd == 1 and ntlmssp

# Domain in CHALLENGE (Type 2)
ntlmssp.message_type == 2 and ntlmssp.auth.domainname == "CORP"
```

## Display filters — DNS

| Goal | Filter |
|---|---|
| Any DNS | `dns` |
| Query | `dns.flags.response == 0` |
| Response | `dns.flags.response == 1` |
| Authoritative answer | `dns.flags.authoritative` |
| Recursion desired | `dns.flags.recdesired` |
| Recursion available | `dns.flags.recavail` |
| Query type A (1) | `dns.qry.type == 1` |
| Query type AAAA (28) | `dns.qry.type == 28` |
| Query type SRV (33) | `dns.qry.type == 33` |
| Query type PTR (12) | `dns.qry.type == 12` |
| Query type TXT (16) | `dns.qry.type == 16` |
| Query type MX (15) | `dns.qry.type == 15` |
| Query type TSIG (250) | `dns.qry.type == 250` |
| Query type TKEY (249) | `dns.qry.type == 249` |
| RCODE 0 (NOERROR) | `dns.flags.rcode == 0` |
| RCODE 3 (NXDOMAIN) | `dns.flags.rcode == 3` |
| DC discovery via SRV | `dns.qry.name contains "_ldap._tcp.dc._msdcs"` |
| GC discovery | `dns.qry.name contains "_ldap._tcp.gc._msdcs"` |
| Kerberos SRV | `dns.qry.name contains "_kerberos._tcp"` |
| kpasswd SRV | `dns.qry.name contains "_kpasswd._tcp"` |
| PDC discovery | `dns.qry.name contains "_ldap._tcp.pdc._msdcs"` |
| Site-scoped lookup | `dns.qry.name contains "_sites.dc._msdcs"` |
| Dynamic update (opcode 5) | `dns.flags.opcode == 5` |
| GSS-TSIG (TKEY with Kerberos) | `dns.qry.type == 249 or dns.qry.type == 250` |

### Combine

```
# All DC discovery
dns.qry.name contains "_ldap._tcp.dc._msdcs"

# All GSS-TSIG dynamic updates
dns.flags.opcode == 5 and dns.qry.type == 250

# Failed DNS lookups (NXDOMAIN)
dns.flags.response == 1 and dns.flags.rcode == 3

# DC site-scoped lookups
dns.qry.name contains "_sites.dc._msdcs" and dns.qry.type == 33
```

## tshark CLI recipes

### Capture with both BPF and display filter

```bash
tshark -i eth0 \
  -f "host dc01.corp.example.com and tcp port 88" \
  -Y "kerberos.msg_type == 10 and kerberos.etype == 0x17" \
  -V
```

### Save to PCAP-NG

```bash
tshark -i eth0 -f "tcp port 88 or tcp port 389" -w /tmp/ad-capture.pcapng
```

### Read PCAP and apply display filter

```bash
tshark -r /tmp/ad-capture.pcapng -Y "kerberos.msg_type == 30"
```

### Export as JSON

```bash
tshark -r /tmp/ad-capture.pcapng -Y "ldap" -T json -x > /tmp/ldap.json
```

### Statistics — protocol hierarchy

```bash
tshark -r /tmp/ad-capture.pcapng -q -z io,phs
```

### Statistics — conversations

```bash
tshark -r /tmp/ad-capture.pcapng -q -z conv,tcp
```

### Extract specific fields

```bash
tshark -r /tmp/ad-capture.pcapng -Y "kerberos" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e ip.dst \
  -e kerberos.msg_type \
  -e kerberos.etype \
  -e kerberos.CName \
  -e kerberos.SName \
  -e kerberos.error_code
```

Output:
```
2026-08-13 09:14:33.001234  10.10.0.50  10.10.0.10  10  0x12  jsmith  krbtgt/CORP...  (null)
2026-08-13 09:14:33.005678  10.10.0.10  10.10.0.50  11  0x12  jsmith  krbtgt/CORP...  (null)
```

### Live capture with column output

```bash
tshark -i eth0 -Y "kerberos" \
  -T fields \
  -e frame.time_relative \
  -e ip.src -e ip.dst \
  -e kerberos.msg_type \
  -e kerberos.CName \
  -e kerberos.SName
```

### Decrypt Kerberos (requires keytab)

```bash
tshark -r /tmp/ad-capture.pcapng \
  -o "kerberos.keytab:/etc/krb5.keytab" \
  -Y "kerberos" -V
```

> ⚠ With Kerberos FAST (RFC 6806) armoring or AES-256 keys with no keytab, decryption is not possible. The session key is encrypted in the AS-REP using the client's long-term key — only the client knows it. Microsoft added `krb5.conf` `decrypt_tls` in Server 2019 for inspection; not portable to tshark.

### Decrypt SMB3 (requires session key)

SMB3 decryption requires extracting the session key from the Kerberos TGS-REP (or NTLMSSP AUTHENTICATE). Use Wireshark GUI → Edit → Preferences → Protocols → SMB2 → Session keys → import.

### Decrypt LDAPS (requires server private key)

```bash
tshark -r /tmp/ldap.pcapng \
  -o "tls.keys_list:10.10.0.10,636,http,/etc/pki/tls/private/dc01.key" \
  -Y "ldap" -V
```

## Save / read PCAP

```bash
# Capture with rotation (1 minute files, max 100 files)
tshark -i eth0 -f "tcp port 88" -w /tmp/capture.pcapng \
  -b duration:60 -b files:100

# Capture with size limit
tshark -i eth0 -f "tcp port 88" -w /tmp/capture.pcapng -b filesize:10240

# Read with following filter
tshark -r /tmp/capture.pcapng -Y "kerberos.error_code != 0"

# Convert PCAP-NG → PCAP (legacy tools)
tshark -r capture.pcapng -F pcap -w capture.pcap

# Convert PCAP → JSON
tshark -r capture.pcapng -T json > capture.json

# Convert PCAP → CSV (fields)
tshark -r capture.pcapng -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
  -e tcp.dstport -e _ws.col.Protocol \
  -E header=y -E separator=, -E quote=d -E occurrence=f \
  > capture.csv
```

## Common diagnostic captures

| Scenario | Capture command |
|---|---|
| User login failure | `tshark -i eth0 -f "host <dc> and (tcp port 88 or tcp port 389)" -w /tmp/login-fail.pcapng` |
| Replication stuck | `tshark -i eth0 -f "host <partner-dc> and tcp port 135" -w /tmp/repl.pcapng` then `tshark -i eth0 -f "host <partner-dc>" -w /tmp/repl-full.pcapng` |
| SMB mount slow | `tshark -i eth0 -f "host <fileserver> and tcp port 445" -w /tmp/smb.pcapng` |
| GPO not applying | `tshark -i eth0 -f "host <dc> and (tcp port 445 or tcp port 389)" -w /tmp/gpo.pcapng` |
| Cert enrollment fail | `tshark -i eth0 -f "host <ca> and (tcp port 135 or tcp port 443)" -w /tmp/cert.pcapng` |
| DNS dynamic update fail | `tshark -i eth0 -f "host <dns-server> and (tcp port 53 or udp port 53)" -w /tmp/dns.pcapng` |
| NTLM fallback occurring | `tshark -i eth0 -Y "ntlmssp" -w /tmp/ntlm.pcapng` |

## See also

- [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) — Kerberos ASN.1 wire format.
- [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) — LDAP message types and controls.
- [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) — SMB2/3 packet structure.
- [../02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) — NTLM message types.
- [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) — Dynamic update / GSS-TSIG.
- [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI opnum table.
