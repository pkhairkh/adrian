---
title: SSSD ID Mapping — SID to POSIX UID/GID Algorithm
audience: senior-engineers
tags: [sssd, id-mapping, sid, rid, posix, idmap, tdb, ldb]
related:
  - ./01-sssd-ad-provider.md
  - ./04-winbind-internals.md
  - ./08-freeipa-trust.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../03-directory-schema/01-schema-attributes.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
last_updated: 2026-08-13
---

SSSD's ID mapping translates a Windows SID `S-1-5-21-<domain-authority>-<rid>` into a POSIX UID or GID either by algorithmic slice-based hashing of the domain SID into a configurable UID range (the `ldap_id_mapping = true` default) or by reading the AD-populated `uidNumber`/`gidNumber` attributes directly (the RFC 2307-style `ldap_id_mapping = false` mode), with the mapping cached in `/var/lib/sss/db/cache_<domain>.ldb` and the algorithm implemented in `src/lib/idmap/sss_idmap.c`.

## SID structure recap

A SID is a variable-length structure defined by MS-DTYP §2.4.2:

```
SID = Revision (1B) | SubAuthorityCount (1B) | IdentifierAuthority (6B) | SubAuthority[N] (4B each LE)
S-1-5-21-1004382210-1580850776-2749628208-1107
            ^^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^  ^^^^
            SubAuth[1]   SubAuth[2]  SubAuth[3]   RID (relative)
```

The last 32-bit subauthority is the RID (relative identifier). The preceding 3 subauthorities (`21-<X>-<Y>-<Z>`) form the domain SID — that is what SSSD hashes to allocate a slice.

ID mapping only applies to SIDs of security principals (users, groups, computers) in the scope of the joined domain or a configured trusted domain. SIDs of well-known accounts (`S-1-1-0`, `S-1-5-7`, `S-1-5-11`, `S-1-5-18`, etc.) are mapped statically by `src/providers/ldap/ldap_id.c:ldap_id_get_special_user`.

## Slice-based algorithm (`ldap_id_mapping = true`)

Default range: `ldap_idmap_range = 200000-2000200000` (a 2-billion-wide allocation table), sliced into `range_size = 200000` slices. The number of slices is `(range_max - range_min) / range_size = (2000200000 - 200000) / 200000 = 10000` slices. For a domain with SID `S-1-5-21-X-Y-Z`:

1. Take the binary form of the SID (all subauthorities, big-endian concatenation of the 6-byte authority + 4-byte-each subauthorities — `src/lib/idmap/sss_idmap.c:sss_idmap_sid_to_bin_sid`).
2. Compute a SHA-1 hash of the binary SID (`src/lib/idmap/sss_idmap.c:sss_idmap_domain_has_algorithmic_mapping` calls `sss_sha1`).
3. Slice index = first 8 bytes of SHA-1 interpreted as a big-endian uint64, modulo the number of slices (`src/lib/idmap/sss_idmap.c:gen_slice`).
4. `slice_offset = slice_index * range_size`.
5. For a user with RID `R`: `UID = range_min + slice_offset + R`. Symmetrically `GID = range_min + slice_offset + R` for a group with RID `R`.

Because the RID alone is added (not the full SID), the mapping is **stable across host reinstalls** (same domain SID → same slice → same UID), but **collisions are possible** if two different domains hash to the same slice index — SSSD detects this and refuses to start with an error in `sssd_ad.log` (`sss_idmap.c:check_collision`).

### Reserved slices

`ldap_idmap_default_domain_sid = S-1-5-21-X-Y-Z` and `ldap_idmap_default_domain = corp` force the named domain to slice 0 (the lowest slice), so the joined domain's users land in the lowest UIDs — useful when migrating from a legacy `idmap_rid` setup.

`ldap_idmap_default_domain_sid` does NOT change the algorithm for other domains; it only fixes one domain to a known slice.

### Configuration knobs

```
[domain/corp.example.com]
ldap_id_mapping = true
ldap_idmap_range = 200000-2000200000
ldap_idmap_range_size = 200000
ldap_idmap_default_domain_sid = S-1-5-21-1004382210-1580850776-2749628208
ldap_idmap_default_domain = corp
ldap_idmap_autorid_compat = false
ldap_idmap_helper_table_size = 10
```

- `ldap_idmap_autorid_compat = true` — emulates Samba's `idmap_autorid` mode (single autoranging table shared across all domains) rather than per-domain slices. Useful when migrating from Winbind.
- `ldap_idmap_helper_table_size = N` (>0) — enables a small auxiliary table to remap collisions: when a domain's hash collides with an already-allocated slice, the next free slot is allocated from a small "helper" table at the top of the range. Default 0 (no helper, collisions are fatal). Set to a small number like 10 if you run into collisions on a forest with many trusted domains.

### Authoritative mode (`ldap_id_mapping = false`)

If AD has `uidNumber` and `gidNumber` populated on the user/group objects (RFC 2307 schema, attributes `uidNumber` 1.2.840.113556.1.4.146, `gidNumber` 1.2.840.113556.1.4.149), SSSD can use those values directly:

```
[domain/corp.example.com]
ldap_id_mapping = false
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_group_gid_number = gidNumber
ldap_group_member = memberUid            # if using RFC2307; or 'member' for full DN refs

# fallback when uidNumber/gidNumber missing:
ldap_user_object_class = user
ldap_user_name = sAMAccountName
ldap_user_home_directory = unixHomeDirectory
ldap_user_shell = loginShell
ldap_group_object_class = group
ldap_group_name = sAMAccountName
```

This requires AD administrators to populate the Unix Attributes tab on each user/group (or do it programmatically — see `Set-ADUser -Add @{uidNumber=…; gidNumber=…; loginShell='/bin/bash'; unixHomeDirectory='/home/u'}` and `Set-ADGroup -Add @{gidNumber=…}`). Missing `uidNumber` means the user is **unresolvable via NSS** — `id user@domain` returns nothing.

### Hybrid: `override_homedir` / per-view overrides

FreeIPA "ID views" and SSSD's `sss_override` tool let you override `uidNumber`, `gidNumber`, `homeDirectory`, `shell`, and group membership for an individual user without touching AD — see `./08-freeipa-trust.md`. The override is stored in `/var/lib/sss/db/override_<domain>.ldb` and consulted before the algorithmic mapping.

## Comparison to Winbind idmap modules

| Mode | SSSD equivalent | Winbind module | Behavior |
|---|---|---|---|
| Algorithmic per-domain slice | `ldap_id_mapping = true` with `ldap_idmap_range_size` | `idmap_rid` | `UID = range_min + RID` (no hashing — uses only RID; requires the domain's range to be specified manually and risks collision across multi-domain forests) |
| Algorithmic auto-range | `ldap_id_mapping = true` with `ldap_idmap_autorid_compat = true` | `idmap_autorid` | First domain wins slice 0, subsequent domains allocated next free slice; shared `idmap.tdb` keeps the allocation |
| RFC 2307 (authoritative AD) | `ldap_id_mapping = false` | `idmap_ad` | Read `uidNumber`/`gidNumber` from AD directly |
| Allocating | not supported | `idmap_tdb` / `idmap_tdb2` | Allocate next free UID on first lookup; not stable across hosts unless the TDB is replicated |

Samba `idmap_ad` (`source3/winbindd/idmap_ad.c:idmap_ad_unixids_to_sids`) requires the same AD attribute population as SSSD's `ldap_id_mapping = false` — see `./04-winbind-internals.md` for the corresponding Winbind configuration.

## Worked example — slice computation

For domain SID `S-1-5-21-1004382210-1580850776-2749628208` and user RID `1107` (the `user1` account), with defaults `range_min=200000`, `range_size=200000`:

1. Binary SID (RFC 4120 / MS-DTYP §2.4.2.1):
   ```
   01 06 00 00 00 00 00 05 15 00 00 00
      21 00 00 00  (subauth 1 = 1004382210)
      78 0f 99 5e  (subauth 2 = 1580850776)
      40 5d 9e a3  (subauth 3 = 2749628208)
      53 04 00 00  (subauth 4 = RID 1107)
   ```
   Wait — only the **domain SID** (`S-1-5-21-1004382210-1580850776-2749628208`, subauth count = 3) is hashed. RID is added later.

2. SHA-1 over the 24-byte binary domain SID: `gen_slice` in `src/lib/idmap/sss_idmap.c:sss_idmap_gen_slice`.
3. Take first 8 bytes big-endian → uint64. With this domain SID: `0xa7 0x4c 0x9d 0x2e 0x18 0x33 0x6e 0xf9` (sample). Decimal ≈ `1.2 × 10^19`. Modulo 10000 = `4873` (sample value).
4. `slice_offset = 4873 × 200000 = 974600000`.
5. `UID = 200000 + 974600000 + 1107 = 974801107`.

The reverse lookup (`sss_idmap_unix_to_sid`) walks the same table: it checks each known domain's allocated slice. If the UID falls within `[range_min + slice*range_size, range_min + (slice+1)*range_size)`, it knows the domain and computes `RID = UID - range_min - slice*range_size`.

If the UID is not within any allocated slice, SSSD returns the well-known SID for "nobody" (`S-1-0-65535`) — i.e. `4294967294` (or `65534` on legacy systems).

## Cache and verification

```
# Inspect the cached mapping for a specific user
ldbsearch -H /var/lib/sss/db/cache_corp.example.com.ldb '(name=user1)' \
  name objectSID uidNumber gidNumber

# Decode the SID to confirm the algorithm
sid=`ldbsearch -H /var/lib/sss/db/cache_corp.example.com.ldb '(name=user1)' objectSID | awk '/objectSID:/{print $2}'`
# Then verify by hand: slice = sha1(sid_binary)[:8] % 10000; uid = 200000 + slice*200000 + rid

# Python re-implementation of SSSD's slice computation
python3 - <<'PY'
import hashlib, struct, sys
sid = 'S-1-5-21-1004382210-1580850776-2749628208-1107'  # user1
parts = sid.split('-')
revision = int(parts[1])
authority = int(parts[2])
subauth = [int(x) for x in parts[3:]]
binary = bytes([revision, len(subauth)]) + authority.to_bytes(6,'big')
for s in subauth:
    binary += struct.pack('<I', s)
digest = hashlib.sha1(binary).digest()
slice_index = int.from_bytes(digest[:8],'big') % 10000
rid = subauth[-1]
uid = 200000 + slice_index * 200000 + rid
print(f'slice_index={slice_index} rid={rid} uid={uid}')
PY

# Full cache invalidate after changing idmap config — required
sss_cache -E
systemctl restart sssd
```

If you change `ldap_idmap_range`, `ldap_idmap_range_size`, `ldap_idmap_default_domain_sid`, or switch `ldap_id_mapping` between true/false, **every UID on disk is potentially different**. Files owned by users through the old mapping will appear to be owned by `nobody`/`4294967294`. Always `find / -uid <old> -print0 | xargs -0 chown <new>` after such a change, or run a `chown -R --from=<old> <new>` sweep over affected filesystems.

### ID views and `sss_override`

SSSD supports per-user or per-host overrides stored separately from the algorithmic / authoritative mapping. The mechanism is identical to FreeIPA's ID views (the IPA server stores them; SSSD clients fetch via the `ipa` provider). In a pure-AD-joined SSSD deployment, you can create local overrides with `sss_override`:

```
# Add a local override (writes to /var/lib/sss/db/override_<domain>.ldb)
sudo sss_override user-add user1@corp.example.com -u 10042 -g 10042 \
  --home=/home/user1 --shell=/bin/zsh --gecos='User One'

sudo sss_override group-add 'domain admins@corp.example.com' -g 10050

# List / show / delete
sudo sss_override user-show user1@corp.example.com
sudo sss_override user-list
sudo sss_override user-del user1@corp.example.com

# Apply (writes the override into the in-memory cache; restart to fully reload)
sudo sss_override user-import /tmp/overrides.csv   # bulk
sudo systemctl restart sssd
```

`sss_override` is implemented in `src/tools/sss_override.c:user_add` and the lookup is performed in `src/responder/nss/nsssrv_cmd.c:nss_cmd_getpwnam` after the algorithmic / authoritative mapping. The override file format is LDB; the schema mirrors the IPA ID view schema (since SSSD uses the same code path for both).

### FreeIPA ID views

When the Linux host is FreeIPA-enrolled (not AD-joined directly), ID views live in the FreeIPA directory and are fetched as part of the `ipa` provider's `sdap_id_setup_tasks`:

```
cn=views,cn=accounts,dc=example,dc=com
  cn=<view_name>
    cn=<user_sid_or_name>,cn=<view_name>,...
      uidNumber: 10042
      gidNumber: 10042
      homeDirectory: /home/user1
      loginShell: /bin/zsh
      gecos: User One
      ipaAnchorUUID: <user_sid>
```

A view applied to a host (`ipa idview-apply <view> --hosts=<host>`) makes that host's SSSD fetch overrides for that view via the `ipa_idview_get_overrides_override` LDAP extended operation. See `./08-freeipa-trust.md` for the FreeIPA side.

### RFC 2307 attribute reference

When using `ldap_id_mapping = false`, SSSD reads (and Winbind `idmap_ad` reads) the following AD attributes — they all come from the `Service-For-Unix` schema extension (shipped since Windows Server 2003 R2, originally from Microsoft Services for UNIX 3.5):

| Attribute | OID | Object class | Maps to |
|---|---|---|---|
| `uidNumber` | 1.2.840.113556.1.4.146 | user (with `posixAccount` auxiliary) | `pw_uid` |
| `gidNumber` | 1.2.840.113556.1.4.149 | user and group | `pw_gid` / `gr_gid` |
| `unixHomeDirectory` | 1.2.840.113556.1.4.174 | user | `pw_dir` |
| `loginShell` | 1.2.840.113556.1.4.700 | user | `pw_shell` |
| `gecos` | 1.2.840.113556.1.4.407 | user | `pw_gecos` |
| `memberUid` | 1.2.840.113556.1.4.194 | group (when using `memberUid`-style membership) | `gr_mem` |
| `member` | 2.5.4.31 | group (default — full DN-style membership) | `gr_mem` (resolved to usernames) |
| `msSFU30Name` | 1.2.840.113556.1.4.1660 | user, group | SFU 3.0-style name |
| `msSFU30DomainInfo` | 1.2.840.113556.1.4.1660 | nTDSDSA | SFU 3.0 NIS domain |
| `uid` | 0.9.2342.19200300.100.1.1 | user | RFC 2307 `uid` (rarely populated in AD) |
| `ipHostNumber` | 0.9.2342.19200300.100.1.9 | ipHost | host-based authentication (rarely used) |

Set via PowerShell:

```powershell
Set-ADUser user1 -Add @{
  uidNumber=10042
  gidNumber=10042
  unixHomeDirectory='/home/user1'
  loginShell='/bin/bash'
  gecos='User One'
}
Set-ADGroup LinuxUsers -Add @{ gidNumber=10050 }
```

Or via ADUC's "UNIX Attributes" tab (which only appears if the NIS server role is installed, or via the SFU schema extension already being present).

## Wireshark / tshark

The ID mapping itself is local; the wire-visible signal is the LDAP response carrying `objectSid`, `uidNumber`, `gidNumber`:

```
# LDAP search response carrying both objectSid and uidNumber (RFC 2307 mode)
ldap.messageCode == 4 && (ldap.attribute.name == "objectSid" || ldap.attribute.name == "uidNumber" || ldap.attribute.name == "gidNumber")

# Filter for the sAMAccountName -> SID resolution queries from sssd_be
ldap.messageCode == 3 && ldap.filter contains "sAMAccountName"

# SID structure decoded by Wireshark in the objectSid attribute
ldap.attribute.value contains "S-1-5-21"
```

For the Kerberos side (PAC carries group SIDs that the access provider maps to GIDs for `initgroups`):

```
kerberos.pac.logon_info.groupMembership && kerberos.msg_type == 13   # TGS-REP
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `id user@domain` shows `no such user` but `ldbsearch` finds the row | Cache stale after ID map change | `sss_cache -E; systemctl restart sssd` |
| Two users in different domains get the same UID | Hash collision (rare with default 10000 slices); or `ldap_idmap_helper_table_size = 0` | Set `ldap_idmap_helper_table_size = 10` and restart; or set `ldap_idmap_default_domain_sid` for the joined domain |
| UID changed across reboot | `ldap_idmap_range_size` was edited but cache not wiped | `sss_cache -E`, `chown -R --from=<olduid> <newuid>` on `/home` |
| User has `uidNumber` in AD but SSSD returns algorithmic UID | `ldap_id_mapping = true` still set | Switch to `ldap_id_mapping = false` |
| `initgroups` returns wrong supplementary groups | PAC group SIDs cached stale in `/var/lib/sss/db/cache_<domain>.ldb` | `sss_cache -G -u user@domain` (group cache + user) |
| `Enumerating large group times out` | `ignore_group_members = false` causes SSSD to fetch every member of large groups (e.g. Domain Users with 50k members) | Set `ignore_group_members = true` unless you need `getent group` to enumerate members |

## Cross-platform comparison

- **AD-side counterpart:** The POSIX attributes `uidNumber`/`gidNumber`/`unixHomeDirectory`/`loginShell`/`gecos` are added to the user and group classSchema objects by the AD `Service-For-Unix` extension (originally from Services for UNIX 3.5; built-in since Server 2003 R2) — see `../03-directory-schema/01-schema-attributes.md` for the attribute OIDs. On the Windows side, POSIX identity is irrelevant for native Kerberos/LDAP auth, but the same SIDs flow in the PAC as documented in `../02-protocols/08-spn-upn-pac.md` (`PAC_LOGON_INFO` carries the `GroupId`/`ExtraSids` arrays).
- **Winbind:** Same algorithm with different config syntax — see `./04-winbind-internals.md` for `idmap config * : backend = rid|autorid|ad|tdb2`.
- **macOS counterpart:** macOS Xsan/OpenDirectory uses a UUID-based mapping (`GeneratedUID` attribute) and does NOT use SID-to-UID hashing — see `../08-macos-equivalents/02-dscl-dsconfigad.md` and `../08-macos-equivalents/01-opendirectory-internals.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- SSSD source — https://github.com/SSSD/sssd:
  - `src/lib/idmap/sss_idmap.c` — `gen_slice`, `sss_idmap_sid_to_unix`, `sss_idmap_unix_to_sid`, `check_collision`.
  - `src/providers/ldap/ldap_id.c:ldap_id_get_special_user` — well-known SID handling.
  - `src/providers/ad/ad_id.c:ad_id_connect` — sets `ldap_id_mapping` default to true.
- Samba `idmap_ad`, `idmap_rid`, `idmap_autorid` — https://github.com/samba-team/samba (see `source3/winbindd/idmap_*.c`).
- MS-DTYP §2.4.2 (SID structure) and §2.4.2.4 (well-known SIDs).
- RFC 2307 — "An Approach for Using LDAP as a Network Information Service".
- `sssd-ad(5)` and `sssd-ldap(5)` man pages — `ldap_id_mapping` and related.
