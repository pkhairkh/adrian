---
title: NTP / W32Time / MS-SNTP — Time Sync Internals, Kerberos Skew, Authentication
audience: senior-engineers
tags: [ntp, w32time, ms-sntp, rfc-5905, kerberos-skew, chrony, ntpd, timed]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../08-macos-equivalents/05-kerberos-sso-extension.md
last_updated: 2026-08-13
---

Windows time synchronization is `w32time.dll` loaded into a `svchost -k LocalService` host (`W32Time` service), pulling from a tiered hierarchy (forest-root PDC at top → DCs → members) using NTP per RFC 5905 for inter-host transport and the MS-SNTP authentication extension for cryptographically signed NTP packets keyed by the domain's secure-channel session key; the strict upper bound on client-KDC clock skew is 5 minutes per RFC 4120 §5.3 (Kerberos `clockskew` parameter), beyond which Kerberos pre-auth (`PA-ENC-TIMESTAMP`) fails with `KRB_AP_ERR_SKEW (37)` and AD replication enters quarantine.

## Architecture

```
Hierarchy (typical):
   External NTP source (GPS / NIST / pool.ntp.org)  — stratum 1
        │
        ▼
   Forest-root PDC emulator   (stratum 2)   — runs as Reliable Time Source
        │
        ▼
   Other DCs in forest root   (stratum 3)   — pull from PDC
        │
        ▼
   DCs in child domains       (stratum 4)   — pull from any DC in parent
        │
        ▼
   Member servers / clients   (stratum 5+)  — pull from their authenticating DC

Service: W32Time (Time Service)
 ├── process: %SystemRoot%\System32\svchost.exe -k LocalService
 │    └── w32time.dll (loaded as service DLL)
 │           ├── w32time.dll!ServiceMain          (entry point)
 │           ├── w32time.dll!W32TmEngine          (the core engine — drift, poll interval)
 │           ├── w32time.dll!NtpProvider          (the NTP client + server)
 │           ├── w32time.dll!DomainProvider       (AD-aware provider; selects best DC)
 │           └── crypt32.dll, netapi32.dll        (for MS-SNTP signature and DC location)
 │
 ├── Service account: NT AUTHORITY\LOCAL SERVICE
 ├── Service dependencies: RpcSs, Tcpip
 └── Registry root: HKLM\SYSTEM\CurrentControlSet\Services\W32Time
```

## Kerberos clock skew

RFC 4120 §5.3 specifies the skew window — the maximum allowed difference between the KDC's clock and the client's clock (or the service's clock) for a Kerberos authenticator to be accepted. AD's KDC (`lsass.exe!kdcsvc.dll`) hardcodes this at 5 minutes (300 s), configurable per realm in MIT krb5 (`[libdefaults] clockskew = 300`). Beyond the skew window:

- `PA-ENC-TIMESTAMP` pre-auth fails with `KDC_ERR_PREAUTH_FAILED (24)`.
- The KDC logs event 4 (KDC) "The client clock skew is too large."
- The service's `krb5_rd_req()` returns `KRB_AP_ERR_SKEW (37)`.

This 5-minute skew is also the maximum time window for AP-REQ replays — after 5 minutes, the authenticator's `ctime + cusec` is considered stale. This is why Kerberos does not need nonces for replay protection (unlike NTLM); the clock + cusec acts as the freshness indicator.

## NTP packet structure (RFC 5905)

```
NTP Packet (48 bytes minimum):
Offset  Size  Field
0x00    1     LI (Leap Indicator)        2 bits: 0=no warning, 1=last min 61s, 2=last min 59s, 3=alarm
0x00    1     VN (Version Number)        3 bits: 4 (NTPv4)
0x00    1     Mode                       3 bits: 1=symmetric active, 2=passive, 3=client,
                                                 4=server, 5=broadcast, 6=control, 7=private
0x01    1     Stratum                    1 byte: 0=unspecified, 1=primary ref,
                                                 2-15=secondary, 16=unsynchronized
0x02    1     Poll                       1 byte: log2 of poll interval (seconds).
                                                 Range 4 (16 s) to 17 (36 h).
0x03    1     Precision                  1 byte: log2 of system precision (sec).
                                                 Typically -10 (≈1 ms) to -20 (≈1 μs).
0x04    4     Root Delay                 4 bytes: total round-trip delay to ref clock
                                                 (fixed-point, 16.16 format).
0x08    4     Root Dispersion            4 bytes: max error vs. ref clock (16.16).
0x0C    4     Reference ID               4 bytes: ident of ref source. For stratum 1,
                                                 ASCII 4-char code (e.g. "GPS", "ATOM").
                                                 For higher strata, IPv4 address of ref.
0x10    8     Reference Timestamp        8 bytes: NTP timestamp (seconds since 1900-01-01
                                                 + fraction).
0x18    8     Origin Timestamp           8 bytes: time the request left the client (T1).
0x20    8     Receive Timestamp          8 bytes: time the request arrived at server (T2).
0x28    8     Transmit Timestamp         8 bytes: time the reply left the server (T3).
0x30    var   Optional extensions        variable; MAC follows (key ID + digest / signature).
0x..    4     Key Identifier             4 bytes: identifies the symmetric key (autokey or
                                                 pre-shared) or, for MS-SNTP, the security
                                                 context ID.
0x..    var   Message Authentication Code (MAC):
                Symmetric:  16-byte HMAC-MD5 (RFC 1321) of all preceding bytes.
                Autokey:    variable, public-key crypto.
                MS-SNTP:    variable — see below.
```

### NTP timestamp format (8 bytes)

```
[ 0 ...... 31 ][ 32 ........... 63 ]
[ seconds     ][ fraction (2^-32 s)]
```

Seconds since 1900-01-01 00:00:00 UTC (not 1970). Wraps in 2036. Fraction is a 32-bit unsigned with each unit representing 2^-32 seconds (≈ 233 picoseconds).

### Round-trip and offset computation

```
T1 = client sends request (Origin Timestamp in server response)
T2 = server receives request (Receive Timestamp)
T3 = server sends reply (Transmit Timestamp)
T4 = client receives reply (local clock at receipt)

Offset    = ((T2 - T1) + (T3 - T4)) / 2     -- how much to add to local clock to match server
Round-trip = (T4 - T1) - (T3 - T2)            -- total network delay
Dispersion = max(0, error estimate from poll)

# Apply: new_local = old_local + Offset
```

The W32Time engine uses a variant that applies a "discipline" — it does not jump the clock immediately, but adjusts the rate of the system clock to converge over multiple intervals (the "kernel clock discipline"). This is `W32TmEngine` in `w32time.dll`.

## MS-SNTP authentication extension

AD uses the MS-SNTP extension documented in `[MS-SNTP]`. The goal: authenticate NTP responses so a MITM cannot poison time. The signing key is the domain's secure-channel session key (the same key used by Netlogon secure channel `NetrServerAuthenticate3`).

### MAC format

```
After the standard 48-byte NTP packet:

0x30  4     Key Identifier              // identifies the signing key
0x34  var   MAC                         // signature

The Key Identifier field's interpretation:
  High 2 bytes: 0x0000 (fixed for MS-SNTP)
  Low 2 bytes:  the security context ID — matches a context established via
                NetrServerReqChallenge / NetrServerAuthenticate3 on the same
                Netlogon secure channel.
```

The MAC itself is computed over the entire NTP packet (48 bytes + extensions) using the secure-channel session key, with one of these algorithms (negotiated during `NetrServerAuthenticate3`):

- `AES_CFB8` (AES-256-CFB8 — Server 2008 R2+ default, `rpc_rc4_aes` flag in `ServerAuthenticate3`).
- `HMAC-MD5` (RC4-HMAC, legacy).
- `DES-CBC` + CRC (very old; disabled).

### NTP authentication handshake

The client and server have an existing Netlogon secure channel (the client machine account on the domain; the DC's machine account). The NTP server (running as part of the W32Time service on the DC) retrieves the same SC session key, derives an NTP signing sub-key, and signs responses. The client does the same on receipt.

For domain-joined clients querying an AD DC for time, MS-SNTP authentication is automatic — the client's W32Time picks the DC it has an SC with, uses the SC session key to verify the NTP response, and discards any unsigned or mis-signed response. For non-domain-joined clients (or domain-joined clients querying an external source), plain unauthenticated NTP is used.

```
Client                                    DC (NTP server)
  │                                          │
  │── NTP Request (Mode 3) ─────────────────►│
  │   (48 bytes; no MAC)                     │
  │                                          │── Look up caller IP → machine account
  │                                          │── Derive NTP signing key from SC session key
  │                                          │── Compute AES-CFB8 MAC over packet
  │◄── NTP Response (Mode 4) ────────────────│
  │   (48 bytes + 4-byte KeyID + 8-byte MAC) │
  │                                          │
  │── Verify MAC using SC session key        │
  │── Apply offset/delay                     │
```

Note: this is a Microsoft-specific extension; standard NTP authentication uses either symmetric pre-shared keys (`ntp-keygen`) or Autokey (public-key). MS-SNTP is neither — it leverages Netlogon's SC.

## Forest-root PDC and stratum

The forest-root PDC emulator FSMO is the canonical time source for the forest. By default, it is configured to use `time.windows.com` (Microsoft's public NTP) as its source and is marked as a "Reliable Time Source" (`ReliableTimeSource = 1` in registry). DCs in the forest root sync from the PDC; DCs in child domains sync from any DC in their parent or in the forest root (via `DomainProvider` algorithm in `w32time.dll`).

Best practices:
- For a real forest, point the forest-root PDC at a stratum-1 source (GPS receiver, radio clock) to avoid external dependency.
- The forest-root PDC should be `Reliable = 1`; all other DCs should be `Reliable = 0`.
- Member clients sync from their logon DC (`NT5DS` source type).

## Registry

```
HKLM\SYSTEM\CurrentControlSet\Services\W32Time
 ├── Parameters
 │     ├── Type                  = NT5DS     (REG_SZ)
 │     │     (NT5DS = sync from AD hierarchy; NTP = sync from NTP servers in NtpServer;
 │     │      AllSync = either; NoSync = disabled)
 │     ├── NtpServer             = time.windows.com,0x9   (REG_SZ)
 │     │     (the 0x9 flag: 0x1=SpecialInterval, 0x8=client mode; 0x2=use as fallback)
 │     ├── ServiceMain           = %SystemRoot%\system32\w32time.dll (REG_SZ)
 │     ├── ServiceDll            = %SystemRoot%\system32\w32time.dll (REG_SZ)
 │     └── EnableSecureTimeLoading = 1   (REG_DWORD; only enable after secure-channel setup)
 │
 ├── Config
 │     ├── AnnounceFlags         = 10 (REG_DWORD; bit 0x08=Timeserv_Announce_No,
 │     │                                bit 0x04=Reliable_TimeServ_Announce_Yes)
 │     ├── MaxPosPhaseCorrection = 3600   (REG_DWORD; seconds; max forward jump)
 │     ├── MaxNegPhaseCorrection = 3600   (REG_DWORD; seconds; max backward jump)
 │     ├── MaxAllowedPhaseOffset = 300    (REG_DWORD; seconds; below this, slew;
 │     │                                       above this, jump)
 │     ├── MaxPollInterval       = 10     (REG_DWORD; log2 sec; 10 = 1024 s ≈ 17 min)
 │     ├── MinPollInterval       = 6      (REG_DWORD; log2 sec; 6 = 64 s)
 │     ├── PollIntervalFactor    = 2      (REG_DWORD)
 │     ├── SpecialPollInterval   = 1024   (REG_DWORD; sec, used when NtpServer has 0x1 flag)
 │     ├── UpdateInterval        = 100    (REG_DWORD; 100 = 100 ticks = 10 s; clock-discipline rate)
 │     ├── FrequencyCorrectRate  = 4      (REG_DWORD)
 │     ├── HoldPeriod            = 5      (REG_DWORD; # samples to hold after spike detection)
 │     ├── LargePhaseOffset      = 50     (REG_DWORD; seconds; treats sample as spike)
 │     ├── SpikeWatchPeriod      = 900    (REG_DWORD; sec; ignore spike samples for this long)
 │     └── EventLogFlags         = 0      (REG_DWORD; bit 0x1=log on large jumps, 0x2=log on spike)
 │
 ├── TimeProviders
 │     ├── NtpClient
 │     │     ├── Enabled                = 1
 │     │     ├── InputProvider          = 1
 │     │     └── DllName                = %SystemRoot%\system32\w32time.dll
 │     ├── NtpServer
 │     │     ├── Enabled                = 1   (1 on DCs; 0 on clients by default)
 │     │     ├── InputProvider          = 0
 │     │     └── DllName                = %SystemRoot%\system32\w32time.dll
 │     └── VMICTimeProvider             (Hyper-V integration — disable for VMs that should sync via domain)
 │           ├── Enabled                = 0   (set to 0 in AD DC VMs to avoid host-time bleeding in)
 │           └── DllName                = %SystemRoot%\system32\vmictimeprovider.dll
 │
 └── State
       ├── LastClockRate            = ...
       ├── LastTimeSync             = ...
       ├── MaxClockRate             = ...
       └── CurrentClockRate         = ...
```

## W32tm.exe commands

```cmd
# Show current configuration
w32tm /query /configuration
w32tm /query /status
w32tm /query /source

# Show sync peers
w32tm /query /peers

# Manually sync now
w32tm /resync /force
w32tm /resync /rediscover /nowait

# Configure external NTP source (run on forest-root PDC)
w32tm /config /manualpeerlist:"0.us.pool.ntp.org,0x1 1.us.pool.ntp.org,0x1" /syncfromflags:manual /reliable:yes /update

# Restart service
net stop w32time && net start w32time

# Show stripchart (offset over time)
w32tm /stripchart /computer:dc01.example.com /samples:5 /dataonly

# Verify NTP authentication (only works against an AD DC with secure time)
w32tm /verify /computer:dc01.example.com
```

## Wireshark display filters

```
ntp                                    # all NTP
ntp.flags.mode == 3                    # client mode
ntp.flags.mode == 4                    # server mode
ntp.flags.stratum == 2                 # stratum 2
ntp.flags.li == 3                      # alarm (clock unsynchronized)
ntp.refid                              # reference identifier
ntp.xmt                                # transmit timestamp
ntp.rootdelay                          # root delay
ntp.mac                                # MAC field (MS-SNTP signature)
ntp.mac.keyid                          # key identifier (low 2 bytes = Netlogon SC context)
ntp.extensions                         # any NTP extensions

# Capture all NTP between client and DC
udp.port == 123 && (ip.src == <client_ip> || ip.dst == <client_ip>)

# Capture MS-SNTP authenticated packets
ntp && ntp.mac.keyid > 0
```

## Configuration / code examples

### PowerShell — configure time sync on a forest-root PDC

```powershell
# 1. Set the PDC to use external NTP servers
$peers = "0.us.pool.ntp.org,0x1 1.us.pool.ntp.org,0x1 time.windows.com,0x1"
w32tm /config /manualpeerlist:$peers /syncfromflags:manual /reliable:yes /update

# 2. Disable Hyper-V time provider on DC VMs (so the host doesn't override)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider" `
                 -Name "Enabled" -Value 0

# 3. Restart service
Restart-Service w32time

# 4. Verify
w32tm /query /status
w32tm /query /source
w32tm /query /configuration /verbose
```

### PowerShell — configure a member server to sync from domain

```powershell
# Reset to default NT5DS sync (sync from AD hierarchy)
w32tm /config /syncfromflags:domhier /update
Restart-Service w32time
w32tm /resync /rediscover

# Verify the chain
w32tm /query /status
```

### Linux — `chrony` config (for AD-joined Linux clients)

```ini
# /etc/chrony/chrony.conf
server dc01.example.com iburst
server dc02.example.com iburst

# Use AD's NTP authentication via the SC key (chrony does not support MS-SNTP natively;
# fall back to plain NTP — Kerberos skew protection on Linux relies on the KDC enforcing
# the 5-min skew, not on NTP authenticity):
makestep 1.0 3
rtcsync
driftfile /var/lib/chrony/drift
logdir /var/log/chrony
```

For full MS-SNTP on Linux: not directly supported by chrony or ntpd. The `msntp` tool (rare) can verify signed packets but requires manual SC key extraction. In practice, AD-joined Linux clients use plain NTP to a domain DC and rely on the KDC's skew enforcement.

### Linux — `ntpd` config with autokey (for non-AD secure NTP)

```ini
# /etc/ntp.conf
server ntp1.example.com autokey
server ntp2.example.com autokey
crypto pw <password>
crypto randfile /dev/urandom
keysdir /etc/ntp
```

This is the standard NTP public-key authentication, NOT MS-SNTP. Use only for non-AD environments.

### macOS — `timed` (system time daemon)

```bash
# Show current time configuration
sudo systemsetup -getusingnetworktime
sudo systemsetup -getnetworktimeserver
sudo systemsetup -gettimezone

# Set time server
sudo systemsetup -setusingnetworktime on
sudo systemsetup -setnetworktimeserver "time.apple.com"

# The actual daemon is `timed` (since OS X 10.13), running as a launchd service
# com.apple.timed.plist. It uses a simpler time-sync protocol over HTTPS
# (Apple's time server), not standard NTP. To use NTP, install ntpd via Homebrew
# or use the open-source `ntpdate` (deprecated).
sudo launchctl list | grep -i time
```

### Python — query an NTP server and parse the response

```python
import socket
import struct
from datetime import datetime, timedelta, timezone

def query_ntp(host, port=123, timeout=5):
    # NTP packet: 48 bytes; first byte = LI(2) | VN(3) | Mode(3)
    # LI=0, VN=4, Mode=3 (client) → 0x23
    packet = b'\x23' + b'\x00' * 47

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(packet, (host, port))
    data, addr = sock.recvfrom(1024)
    sock.close()

    # Unpack: T1 (orig), T2 (recv), T3 (xmt) are at offsets 24, 32, 40
    # Each is 8 bytes: 4 bytes seconds + 4 bytes fraction (since 1900-01-01)
    t1, t2, t3 = struct.unpack('!QQQ', data[24:48])
    t4 = datetime.now(timezone.utc)

    # Convert NTP seconds (since 1900-01-01) to UNIX epoch (since 1970-01-01)
    ntp_epoch = datetime(1900, 1, 1, tzinfo=timezone.utc)
    t2_dt = ntp_epoch + timedelta(seconds=float(t2) / 2**32)
    t3_dt = ntp_epoch + timedelta(seconds=float(t3) / 2**32)

    # Offset = ((T2 - T1) + (T3 - T4)) / 2  -- here T1 was sent just before T4 was received
    offset = ((t2_dt - t4).total_seconds() + (t3_dt - t4).total_seconds()) / 2
    return {
        'stratum': data[1],
        'root_delay': struct.unpack('!I', data[4:8])[0] / 65536.0,
        'root_dispersion': struct.unpack('!I', data[8:12])[0] / 65536.0,
        'reference_id': data[12:16],
        'offset_seconds': offset,
        'transmit_time': t3_dt.isoformat(),
    }

print(query_ntp('dc01.example.com'))
```

## Troubleshooting

- **`The time service is now using the current system time...` (event 142)** — service started without a stored time; uses the local BIOS clock. Normal on first boot.
- **`Event 12 (Time-Service)`** — the time service is syncing from `time.windows.com`. For a domain, this is wrong — should be from AD hierarchy. Fix: `w32tm /config /syncfromflags:domhier /update` and restart.
- **`Event 36 (Time-Service)`** — "The time service has not synchronized the system time for X seconds because none of the time service providers provided a usable time stamp." Usually a network/firewall issue blocking UDP 123.
- **`Event 52 (Time-Service)`** — "The time service has detected a large time difference." Check `MaxPosPhaseCorrection` / `MaxNegPhaseCorrection` — they may be too small to allow correction.
- **Kerberos `KRB_AP_ERR_SKEW (37)`** — client or service clock off by > 5 min. On the failing client: `w32tm /resync /force`. Verify with `w32tm /stripchart /computer:<dc> /samples:3 /dataonly`.
- **DC reports `Event 109 (Time-Service)`** — "The time service detected a time difference of greater than X seconds." AD replication (DFSR / FRS in older forests) refuses to replicate when source and destination differ by > the `tombstoneLifetime` / 2 (default 90 days). Even small differences can cause `USN rollback` style issues — fix clocks immediately.
- **VM time drift** — Hyper-V / VMware host's clock can bleed into guest via the integration services time provider. Disable on DCs: `HKLM\...\W32Time\TimeProviders\VMICTimeProvider\Enabled = 0` (Hyper-V) or set VMware Tools `time.sync.time = "FALSE"`.
- **MS-SNTP MAC verification fails on a non-domain client** — expected behavior; non-domain clients cannot validate MS-SNTP signatures. Configure them with plain NTP.
- **`w32tm /query /status` shows "Source: Local CMOS Clock"** — the time service fell back to the hardware clock. Indicates no successful sync from the configured source for > 24 h.

## Cross-platform equivalents

- **Linux**: `chrony` (recommended since RHEL 7 / Ubuntu 16.04) — better than `ntpd` for intermittent connectivity and faster convergence. Does NOT support MS-SNTP. For AD-joined Linux clients, point at a domain DC (plain NTP); the KDC enforces the 5-min skew anyway.
- **Linux**: `ntpd` (classic, RFC 5905) — supports autokey (public-key auth) but not MS-SNTP. Falling out of favor.
- **Linux**: `systemd-timesyncd` — minimal SNTP-only client (no server mode, no PTP). Used in many minimal/container deployments.
- **Linux**: `linuxptp` (PTP / IEEE 1588) — for high-precision time sync (sub-microsecond) over the network; replaces NTP for HFT and lab environments.
- **macOS**: `timed` (Apple's system time daemon since macOS 10.13) — uses Apple's own time-sync protocol over HTTPS to `time.apple.com`, not standard NTP. The `ntpdate` command-line tool was removed; macOS Server's NTP service was removed in macOS Server 5.7. To use NTP, install `chrony` or `ntpd` via Homebrew. See `../08-macos-equivalents/08-time-services-ntp.md` (when present).
- **macOS**: For AD-joined Macs, the Platform SSO extension can synchronize time via the Kerberos SSO mechanism (it queries the DC's time via the KDC's `KDC_ERR_PREAUTH_REQUIRED` error response and adjusts). See `../08-macos-equivalents/05-kerberos-sso-extension.md`.

## References

- RFC 5905 — Network Time Protocol Version 4: Protocol and Algorithms Specification.
- RFC 5906 — NTPv4 Public Key Cryptography (Autokey).
- RFC 5907 — Definitions of Managed Objects for NTPv4.
- RFC 4120 §5.3 — Kerberos Message Exchanges (clock skew definition).
- MS-SNTP — Simple Network Time Protocol (SNTP) Authentication Extensions. <https://learn.microsoft.com/openspecs/windows_protocols/ms-sntp>
- MS-DRSR §4 — DRSUAPI interface (mentions time sync for replication correctness).
- Windows Time Service Technical Reference — MS Learn.
- chrony documentation — <https://chrony.tuxfamily.org>
- ntp.org — <http://www.ntp.org>
