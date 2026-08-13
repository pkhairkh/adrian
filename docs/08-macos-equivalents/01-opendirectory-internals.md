---
title: OpenDirectory Internals — opendirectoryd, OD Framework, Plug-in Modules, Local Node Store
audience: senior-engineers
tags: [opendirectory, opendirectoryd, dscl, dslocal, od-framework, macos]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ./02-dscl-dsconfigad.md
  - ./04-platform-sso-extension.md
  - ./05-kerberos-sso-extension.md
  - ../09-linux-equivalents/09-openldap-mit-kerberos.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

OpenDirectory is the macOS directory-services stack: a single daemon `opendirectoryd` (launchd label `com.apple.opendirectoryd`) routes every identity lookup, authentication, and directory-mutation call from Apple frameworks through a plug-in registry that fronts the local Berkeley-DB-style `dslocal` store, the in-kernel `/BSD/local` node, LDAPv3 servers, Active Directory (via the bundled AD plug-in), and Bonjour-discovered nodes, exposing all of them behind a single C API in `OpenDirectory.framework`.

## Architecture

```
                       ┌─────────────────────────────────────────────┐
   Higher-level clients│ id(1), groups(1), loginwindow, Security,    │
                       │ Authorization, SSO extensions, MDM profiles │
                       └─────────────────────┬───────────────────────┘
                                             │  OpenDirectory C API
                                             │  (ODSessionCreate, ODNodeCreate,
                                             │   ODRecordSetValues, …)
                                             ▼
                       ┌─────────────────────────────────────────────┐
                       │  OpenDirectory.framework                    │
                       │  /System/Library/Frameworks/OpenDirectory.framework
                       │  public headers: ODSession.h, ODNode.h,     │
                       │  ODRecord.h, ODConfiguration.h              │
                       └─────────────────────┬───────────────────────┘
                                             │  XPC / Mach
                                             ▼
                       ┌─────────────────────────────────────────────┐
                       │  opendirectoryd  (PID 1 child via launchd)  │
                       │  label: com.apple.opendirectoryd            │
                       │  binary: /usr/libexec/opendirectoryd        │
                       │  config: /etc/opendirectory/opendirectoryd.conf
                       │           /Library/Preferences/OpenDirectory/Configurations/
                       │  plug-in dir: /System/Library/OpenDirectory/Modules/
                       └─────────────────────┬───────────────────────┘
                                             │  loadable bundles
            ┌────────────────┬───────────────┼───────────────┬────────────────────┐
            ▼                ▼               ▼               ▼                    ▼
        DSP.local       DSP.LDAPv3      DSP.ActiveDirectory  DSP.Bonjour    DSP.XML
        (local plug-in) (LDAP plug-in)  (AD plug-in)         (Bonjour)      (XML cfg)
            │                │               │                    │            │
            ▼                ▼               ▼                    ▼            ▼
        /var/db/dslocal  TCP 389/636    DRSUAPI/Kerberos/      mDNSResponder  plist-only
        /nodes/Default/  + LDAPv3        LDAP/SMB/CLDAP         (Bonjour)      (test)
                         wire proto      against DC
```

- The legacy daemon `DirectoryService` (pre-Snow-Leopard) was renamed to `opendirectoryd` in 10.6. The old binary `/usr/sbin/DirectoryService` no longer ships; its responsibilities were absorbed by `/usr/libexec/opendirectoryd` plus a much smaller shim `/usr/sbin/dscacheutil`.
- `opendirectoryd` is owned by `launchd(8)` via the system plist `/System/Library/LaunchDaemons/com.apple.opendirectoryd.plist`. It runs as root; client connections come in over a private Mach service `com.apple.system.opendirectoryd.api`.
- The `OpenDirectory.framework` is a thin client wrapper. It implements CFType-refcounted objects (`ODSessionRef`, `ODNodeRef`, `ODRecordRef`) and serialises calls to the daemon via XPC dictionaries. There is no in-process directory state of any consequence — the framework is a transport, the daemon is the truth.

## Configuration files

```
/etc/opendirectory/opendirectoryd.conf                         # main daemon config (text)
/Library/Preferences/OpenDirectory/Configurations/             # per-node XML configs
    ├── Local/
    │   └── Default.plist                                       # /Local/Default node config
    ├── LDAPv3/
    │   └── <host>.plist                                        # one per LDAP server
    └── ActiveDirectory/
        └── <domain>.plist                                      # AD binding config
/var/db/dslocal/nodes/Default/                                  # local node backing store
/var/db/dslocal/nodes/Default/users/                            # one plist per local user
/var/db/dslocal/nodes/Default/groups/                           # one plist per local group
/var/db/dslocal/nodes/Default/computers/                        # local computer records
/var/db/dslocal/nodes/Default/config/                           # node-level config
/var/db/opendirectory/                                          # daemon runtime state, caches
```

Each `dslocal` record is a binary plist whose root is a dictionary keyed by attribute name in the `dsAttrTypeStandard:` namespace (e.g. `dsAttrTypeStandard:RecordName`, `dsAttrTypeStandard:UniqueID`, `dsAttrTypeStandard:GeneratedUID`). Values are arrays of `NSData` blobs; strings are stored as UTF-8.

`opendirectoryd.conf` is line-based and sparsely documented. Default install ships an empty file; admins add explicit logging and node-discovery toggles. The real per-node configuration lives in the plists under `/Library/Preferences/OpenDirectory/Configurations/`.

## Plug-in architecture

Plug-ins are bundles (`.bundle`) in `/System/Library/OpenDirectory/Modules/`. Each implements the `ODPlugIn` C interface declared in the private header `ODPlugIn.h`. The core entry points are:

```c
// plug-in lifecycle
ODPlugInRef ODPlugInInit(CFStringRef plugInType, ODPlugInParams params);
void        ODPlugInDealloc(ODPlugInRef plugIn);

// node lifecycle
OSStatus ODPlugInCreateNode(ODPlugInRef plugIn, ODNodeRef node, CFDictionaryRef options);
OSStatus ODPlugInReleaseNode(ODPlugInRef plugIn, ODNodeRef node);

// record operations
OSStatus ODPlugInCreateRecord(ODPlugInRef plugIn, ODNodeRef node,
                              CFStringRef recordType, CFStringRef recordName,
                              CFDictionaryRef initialAttributes, ODRecordRef *outRecord);
OSStatus ODPlugInDeleteRecord(ODPlugInRef plugIn, ODRecordRef record);
OSStatus ODPlugInRecordAddAttribute(ODPlugInRef plugIn, ODRecordRef record,
                                    ODAttributeType attribute, CFArrayRef values);
OSStatus ODPlugInRecordSetValues(ODPlugInRef plugIn, ODRecordRef record,
                                 ODAttributeType attribute, CFArrayRef values);
OSStatus ODPlugInRecordRemoveAttribute(ODPlugInRef plugIn, ODRecordRef record,
                                       ODAttributeType attribute, CFArrayRef values);
OSStatus ODPlugInRecordsSearch(ODPlugInRef plugIn, ODNodeRef node,
                               CFDictionaryRef query, CFArrayRef *outRecords);
OSStatus ODPlugInAuthenticate(ODPlugInRef plugIn, ODNodeRef node,
                              CFStringRef recordName, CFDataRef password,
                              ODRecordType recordType, uid_t uid);
```

Public-framework callers surface these indirectly through `ODNodeCreateRecord`, `ODRecordSetValues`, `ODNodeCopyRecords`, `ODRecordSetNodeCredentials`, etc. — the framework wraps every call in an XPC dictionary round-trip.

Bundled modules on a stock 14.x/15.x install:

| Path (under `/System/Library/OpenDirectory/Modules/`) | Plug-in type | Wire protocol | Purpose |
|---|---|---|---|
| `DSP.local.bundle` | local | none | Reads/writes `/var/db/dslocal/nodes/Default/`. Default backing store for `/Local/Default`. |
| `DSP.LDAPv3.bundle` | LDAPv3 | RFC 4511 over TCP 389/636, plus LDAP StartTLS | Generic LDAP client. Powering `/LDAPv3/<host>` nodes. Uses OpenLDAP client library internally. |
| `DSP.ActiveDirectory.bundle` | ActiveDirectory | Kerberos + LDAP + CLDAP + SMB + DRSUAPI (read) | Drives AD binding; surfaces `/Active Directory/<DOMAIN>` magic node. |
| `DSP.Bonjour.bundle` | Bonjour | mDNS `_odinstance._tcp`, `_ssh._tcp`, `_device-info._txt` | Discover other Macs/OD servers on the LAN. |
| `DSP.Configure.bundle` | configure | none | Implements `dsconfigldap`, `dsconfigad` CLI side effects. |
| `DSP.XMLPlugIn.bundle` | XML | none | Test/sample plug-in that reads a static XML node description. |

## OD nodes — name space

Nodes are addressable by path-like strings. The leading segment identifies the plug-in:

| Node path | Plug-in | Typical use |
|---|---|---|
| `/Local/Default` | local | The local directory. `dscl .` and `dscl /Local/Default` resolve here. |
| `/Local/<other>` | local | Optional secondary local nodes; rare in practice. |
| `/BSD/local` | (synthetic) | Exposes getpwent/getgrent from the BSD nsswitch layer (mostly `/etc/passwd`, `/etc/group`). |
| `/LDAPv3/127.0.0.1` | LDAPv3 | Local LDAP server. |
| `/LDAPv3/ldap.example.com` | LDAPv3 | Remote LDAP/389-DS/OpenLDAP server. |
| `/Active Directory` | ActiveDirectory | Aggregator node: enumerates all bound AD domains. |
| `/Active Directory/CORP` | ActiveDirectory | One AD domain. `dscl /Active Directory/CORP -read ...` |
| `/Active Directory/CORP/All Domains` | ActiveDirectory | GC-style aggregate view across the forest. |
| `/Search` | (meta) | Search path. Concatenates local + LDAP + AD nodes per `/Library/Preferences/OpenDirectory/Configurations/Search.plist`. |
| `/Contacts` | (meta) | Search path for Contacts.app only. |
| `/Configure` | configure | Used by `dsconfigad` etc. to drive live node config. |

The `dscl localhost` form is the historical alias to the plug-in node enumeration endpoint — it returns the same list as `dscl / -list .` of node roots. Both work because `dscl` uses `ODNodeCopyDetails` against the daemon's root node.

## Schema — `dsAttrTypeStandard:`

OD attributes are namespaced strings. The standard namespace is the prefix `dsAttrTypeStandard:`; native and plug-in-specific namespaces (`dsAttrTypeNative:` for AD passthrough, `dsAttrTypePrefix:` for legacy) are valid. Each standard attribute has a canonical type (string, integer, binary, `OS X UUID`).

| Standard attribute | AD-side equivalent |
|---|---|
| `dsAttrTypeStandard:RecordName` | `sAMAccountName` (for user/computer) |
| `dsAttrTypeStandard:UniqueID` | `uidNumber` (POSIX) — no native AD equivalent |
| `dsAttrTypeStandard:PrimaryGroupID` | `primaryGroupID` |
| `dsAttrTypeStandard:GeneratedUID` | `objectGUID` |
| `dsAttrTypeStandard:RecordType` | `objectClass` (single-valued in OD) |
| `dsAttrTypeStandard:RealName` | `displayName` / `cn` |
| `dsAttrTypeStandard:NFSHomeDirectory` | `unixHomeDirectory` |
| `dsAttrTypeStandard:UserShell` | `loginShell` |
| `dsAttrTypeStandard:AuthenticationAuthority` | `userAccountControl` + `unicodePwd` (composite; encodes ShadowHash, Kerberos, etc.) |
| `dsAttrTypeStandard:AltSecurityIdentities` | `altSecurityIdentities` (X.509 issuer/subject pairs) |
| `dsAttrTypeStandard:SMBSID` | `objectSid` |
| `dsAttrTypeStandard:KerberosKeys` | `kerberos-secret` (keytab material, local shadow hash) |

The `AuthenticationAuthority` value on a local user plist is a semicolon-separated list of `;{scheme}data` entries. On a modern Mac it typically begins with `;ShadowHash;HASH:<base64>` followed by `;Kerberosv5;<hash>` for local Kerberos. The base64 payload is itself a plist containing the `SALTED-SHA512-PBKDF2` dictionary (iterations, salt, entropy) used by `opendirectoryd` for local-user auth.

## Local directory store internals

`/var/db/dslocal/nodes/Default/` is a flat directory tree with one binary plist per record. The plist is structured:

```
{
    "dsAttrTypeStandard:RecordName"        = [ "alice" ];
    "dsAttrTypeStandard:RealName"          = [ "Alice Example" ];
    "dsAttrTypeStandard:UniqueID"          = [ 502 ];
    "dsAttrTypeStandard:PrimaryGroupID"    = [ 20 ];
    "dsAttrTypeStandard:GeneratedUID"      = [ "AB12CD34-…-…" ];
    "dsAttrTypeStandard:NFSHomeDirectory"  = [ "/Users/alice" ];
    "dsAttrTypeStandard:UserShell"         = [ "/bin/zsh" ];
    "dsAttrTypeStandard:AuthenticationAuthority" = [
        ";ShadowHash;HASH:<base64-plist-with-SALTED-SHA512-PBKDF2>",
        ";Kerberosv5;alice@LKDC:SHA1.<hex>"
    ];
    "dsAttrTypeStandard:KerberosKeys"      = [ <binary keytab blob> ];
    "dsAttrTypeStandard:ShadowHashData"    = [ <binary plist: entropy,salt,iterations> ];
}
```

The local node is **authoritative for local accounts only**. There is no replication, no multi-master write path; if two Macs both think they own `uid=502`, they are independent.

A new feature in macOS 11+ is the **LKDC** (Local KDC): every Mac runs a tiny Heimdal KDC keyed by a per-host random master key in the system keychain (`com.apple.kerberos.kdc`), and every local user gets a principal `<user>@LKDC:SHA1.<host-guid-hash>`. This is what allows local users to authenticate via Kerberos to local services like Apple Filing Protocol (AFP) and Screen Sharing without an external KDC. The LKDC realm name starts with `LKDC:` and is non-routable.

## Configuration / commands

Inspect the running daemon:

```sh
# daemon status
sudo launchctl print system/com.apple.opendirectoryd
sudo log show --predicate 'process == "opendirectoryd"' --last 10m --info

# list all OD nodes the daemon currently exposes
dscl / -list .
# /Active Directory
# /Active Directory/CORP
# /BSD/local
# /Contacts
# /LDAPv3/127.0.0.1
# /Local/Default
# /Search
dscl localhost -list .          # historical alias of the same enumeration

# dump the entire local node as XML plists
sudo plutil -p /var/db/dslocal/nodes/Default/users/alice.plist
sudo defaults read /var/db/dslocal/nodes/Default/users/alice.plist
# (defaults cannot read nested-array plists well; prefer plutil -p or plutil -convert xml1 -o -)

# list local users via dscl
dscl . -list /Users UniqueID
dscl /Local/Default -read /Users/alice

# search across the /Search path
dscl /Search -read /Users/alice GeneratedUID
```

Inspect a remote AD-bound node:

```sh
dscl /Active Directory/CORP -read /Users/alice
dscl /Active Directory/CORP -read /Computers/MAC01$
dscl /Active Directory/CORP -search /Users name alice
```

Inspect node-config plists:

```sh
sudo plutil -p /Library/Preferences/OpenDirectory/Configurations/Search.plist
sudo plutil -p /Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/CORP.plist
sudo defaults read /Library/Preferences/OpenDirectory/Configurations/Local/Default
```

Force a node refresh after editing a config plist:

```sh
sudo killall -HUP opendirectoryd
# equivalent: sudo launchctl kickstart -k system/com.apple.opendirectoryd
```

## Troubleshooting

- **`id <user>` returns stale data** — `opendirectoryd` caches search results in `/var/db/opendirectory/Cache/`. Flush with `sudo dscacheutil -flushcache` and `sudo killall -HUP opendirectoryd`. The `dscacheutil` flush is mostly cosmetic post-10.8 — the real cache lives inside the daemon process.
- **Local user cannot log in** — verify `dsAttrTypeStandard:ShadowHashData` is present and the `SALTED-SHA512-PBKDF2` entropy decodes. Use `sudo plutil -convert xml1 -o - /var/db/dslocal/nodes/Default/users/alice.plist | grep -A1 ShadowHash`. If empty, reset with `sudo passwd alice` (writes via `PAM` → `opendirectoryd` → local plug-in).
- **AD plug-in node missing** — binding was lost; check `/Library/Preferences/DirectoryService/ActiveDirectoryDomains.plist` (see `02-dscl-dsconfigad.md`) and `/Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/`. Re-bind with `dsconfigad` (covered in `02-dscl-dsconfigad.md`).
- **`/Search` returns results from the wrong node** — `/Search` follows the policy in `Search.plist`. If you removed `/LDAPv3/...` from the policy list but `id` still resolves users, the policy was not reloaded. Restart `opendirectoryd`.
- **LKDC tickets failing** — `klist -v` for an `LKDC:SHA1.<hash>` principal. If the principal mismatched the host's current LKDC realm (changed during firmware reset / host rename), destroy with `kdestroy -a` and let the user re-auth.

## Wire-protocol diagnostics

When the AD plug-in or LDAPv3 plug-in is in play, traffic leaves the Mac on TCP/UDP 88 (Kerberos), TCP 389/636 (LDAP), UDP 389 (CLDAP for DC locator), TCP 445 (SMB for GPO/sysvol), and TCP 135 + dynamic (DRSUAPI for computer-object replication reads). Wireshark display filters for the most common investigations:

```
# full Kerberos (AS-REQ/AS-REP/TGS-REQ/TGS-REP) from this Mac to a DC
kerberos && ip.addr == 10.0.0.5

# CLDAP (DC locator) netlogon queries
cldap && cldap.filter.objectclass == "domainDNS"

# LDAP simple bind / search to AD
ldap && (ldap.messageType == 0 || ldap.messageType == 3)

# SMB tree connect to SYSVOL during GPO fetch
smb2.cmd == 3 && smb2.path contains "SYSVOL"
```

## Cross-platform comparison

- **AD counterpart** — OpenDirectory is structurally closer to a directory *client* with a small built-in directory server, not a full multi-master DC. The nearest AD-side analogue is a single-domain-controller AD LDS instance ([`../01-ad-core/04-ad-lds-adam.md`](../01-ad-core/04-ad-lds-adam.md)) for the local-only case, and the LSASS / Netlogon stack on a Windows member server ([`../01-ad-core/01-ad-ds-internals.md`](../01-ad-core/01-ad-ds-internals.md)) for the bound-to-AD case. The OD AD plug-in implements the same Kerberos / LDAP / SMB / CLDAP wire protocols described in [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md), [`../02-protocols/02-ldap-protocol.md`](../02-protocols/02-ldap-protocol.md), [`../02-protocols/03-smb-cifs-protocol.md`](../02-protocols/03-smb-cifs-protocol.md), and [`../02-protocols/05-dns-dynamic-updates.md`](../02-protocols/05-dns-dynamic-updates.md).
- **Linux counterpart** — `sssd` is the closest functional analogue: a daemon (`sssd`) that fronts multiple identity providers (AD, LDAP, IPA) behind a uniform D-Bus / NSS / PAM interface, with a plug-in architecture (`sssd-ad`, `sssd-ldap`, `sssd-ipa` providers). The local-only `dslocal` store has no real Linux equivalent; the closest is plain `/etc/passwd` + `/etc/shadow` plus `libnss-files`. See [`../09-linux-equivalents/01-sssd-ad-provider.md`](../09-linux-equivalents/01-sssd-ad-provider.md) and [`../09-linux-equivalents/09-openldap-mit-kerberos.md`](../09-linux-equivalents/09-openldap-mit-kerberos.md).
- **High-level side-by-side** — [`../10-comparison-matrices/01-feature-os-matrix.md`](../10-comparison-matrices/01-feature-os-matrix.md).

## References

- `OpenDirectory.framework` headers — `/System/Library/Frameworks/OpenDirectory.framework/Headers/` (`ODSession.h`, `ODNode.h`, `ODRecord.h`, `ODConfiguration.h`, `ODSession.h`).
- Apple Developer doc — "Open Directory" (archived, current as of macOS 14 framework reference).
- `opendirectoryd` manpage — `man opendirectoryd` (sparse; mostly refers to plists).
- `dscl` manpage — `man dscl`.
- `dslocal` layout — reverse-engineerable from `/var/db/dslocal/nodes/Default/` on any stock install.
- LKDC behaviour — see `klist -v` on a fresh macOS install; realm `LKDC:SHA1.<host-guid-hash>`.
- Samba project source for the OD-equivalent Linux side — `sssd/src/providers/ad/` (AD provider), `sssd/src/providers/ldap/` (LDAP provider).
- Internal Apple framework private headers (`ODPlugIn.h`, `CFODContext.h`) are documented only in the in-SDK PrivateFrameworks tree under `/System/Library/PrivateFrameworks/OpenDirectory.framework/`.
