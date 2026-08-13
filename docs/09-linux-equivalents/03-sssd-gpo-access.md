---
title: SSSD GPO Access Control — User-Rights-AAssignment Subset Enforcement
audience: senior-engineers
tags: [sssd, gpo, access-control, pam, security, gptmpl, ad-gpo, cse]
related:
  - ./01-sssd-ad-provider.md
  - ./04-winbind-internals.md
  - ../04-group-policy/04-cse-client-side-extensions.md
  - ../04-group-policy/05-gpt-gpc-structure.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md
last_updated: 2026-08-13
---

SSSD's GPO access control is a partial re-implementation of the Windows **Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment** subset (only the logon-rights family), implemented in `src/providers/ad/ad_gpo.c` and a separate `ad_gpo_child` helper that fetches and parses `\\<sysvol>\<domain>\Policies\{<guid>}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` over SMB, then maps the listed SIDs to the requesting PAM service and accepts or rejects the logon accordingly — User Configuration CSEs, Registry.pol, and GP Preferences are NOT applied.

## What SSSD enforces vs what it ignores

| Windows GPO area | SSSD applies? | Notes |
|---|---|---|
| Computer Config → Windows Settings → Security Settings → Local Policies → User Rights Assignment (logon rights only) | Yes | Subset of 10 rights (see table below) |
| Computer Config → Windows Settings → Security Settings → Local Policies → User Rights Assignment (non-logon: SeTakeOwnership, SeBackup, …) | No | Not applicable to Linux |
| Computer Config → Security Settings → Account Policies (password, lockout, Kerberos) | No | PAM `pam_cracklib`/`pam_pwquality` + `krb5.conf` policy takes precedence |
| Computer Config → Administrative Templates (Registry.pol) | No | Linux has no registry; would need explicit translation |
| Computer Config → Scripts (Startup/Shutdown) | No | Use systemd units / `cron @reboot` |
| Computer Config → Preferences (Drive Maps, Files, Local Users and Groups, …) | No | No GP Preferences equivalent on Linux |
| User Configuration (any) | No | SSSD runs in computer context only |

### Supported logon rights

| Windows right | GptTmpl.inf key | Default PAM services mapped to it |
|---|---|---|
| Allow log on locally | `SeInteractiveLogonRight` | `login`, `su`, `su-l`, `gdm-password`, `gdm-pin`, `gdm-fingerprint`, `gdm-smartcard`, `lightdm`, `sddm`, `kdm`, `xdm` |
| Allow log on through Remote Desktop Services | `SeRemoteInteractiveLogonRight` | `sshd`, `cockpit`, `tmux` |
| Access this computer from the network | `SeNetworkLogonRight` | none by default (use `ad_gpo_map_network`) |
| Log on as a batch job | `SeBatchLogonRight` | `crond`, `atd`, `systemd-cron` (via `ad_gpo_map_batch`) |
| Log on as a service | `SeServiceLogonRight` | none by default (use `ad_gpo_map_service`) |
| Deny log on locally | `SeDenyInteractiveLogonRight` | same services as SeInteractiveLogonRight |
| Deny log on through Remote Desktop Services | `SeDenyRemoteInteractiveLogonRight` | same as SeRemoteInteractiveLogonRight |
| Deny access this computer from the network | `SeDenyNetworkLogonRight` | same as SeNetworkLogonRight |
| Deny log on as a batch job | `SeDenyBatchLogonRight` | same as SeBatchLogonRight |
| Deny log on as a service | `SeDenyServiceLogonRight` | same as SeServiceLogonRight |

The default mapping table is hard-coded in `src/providers/ad/ad_gpo.c:gpo_get_service_map`. Allow rights and Deny rights are evaluated together; Deny wins.

## Architecture / source paths

The access check is invoked from `src/providers/ad/ad_access.c:ad_access_handler` as the second link in the access chain (after `simple` and before the always-allow fallthrough). It runs asynchronously:

1. `ad_gpo.c:ad_gpo_access_send` — looks up the requesting PAM service in `gpo_get_service_map` to find which `Se*LogonRight` it requires. If the service is not in any mapping, the default is to **allow** (override with `ad_gpo_implicit_deny = true`).
2. `ad_gpo.c:ad_gpo_process_gpo_send` — checks `/var/lib/sss/db/cache_<domain>.ldb` for the cached GPO list (keyed by host DN + GPO GUID). If `ad_gpo_refresh_interval` (default 30 seconds on the periodic refresh task, see `ldap_id_setup_tasks` in `ldap_id.c`) has not expired, use cached.
3. Otherwise, `ad_gpo_child.c:ad_gpo_child_get_gpo_list` — runs `ldap_search_ext` against `<domain DN>` walking up the OU ancestry of the host's DN, plus the domain root and the site container (`CN=<site>,CN=Sites,CN=Configuration,<forest DN>`), collecting all `gPLink`-linked GPOs. Then `ldap_search_ext` against each `CN={<guid>},CN=Policies,CN=System,<domain DN>` to read `gPCFileSysPath` (the SYSVOL UNC), `nTSecurityDescriptor` (filtered for read access), `versionNumber`, and `flags` (disabled GPOs are skipped).
4. `ad_gpo_child.c:ad_gpo_child_read_gpo_ini` — connects to `\\<dc>\sysvol\<domain>\Policies\{<guid>}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` over SMB (libsmbclient, GSS-SPNEGO as the host machine account), reads the file, parses the `[Privilege Rights]` section. Samba client library `libsmbclient` is linked in via `src/providers/ad/ad_gpo_child.c:ad_gpo_get_smb_filename` — see `../02-protocols/03-smb-cifs-protocol.md` for the wire protocol.
5. `ad_gpo.c:ad_gpo_evaluate_gpo` — for each GPO in the LSDOU order (site → domain → OU parent-to-child, gPLink left-to-right, ENFORCED overrides ordering), iterate the rights in `[Privilege Rights]`. For each SID listed under a `Se*LogonRight`, look it up in the user's PAC (`PAC_LOGON_INFO.GroupIds`, `ExtraSids`, `LogonDomainId`) plus the user's own SID. Allow lists intersect: the user must appear in the Allow list of every applicable GPO in the chain (AND semantics) — there is no OR-across-GPOs.
6. `ad_gpo.c:ad_gpo_evaluate_gpo` returns `ALLOW` / `DENY` / `NO_APPLICABLE_POLICY`. With `ad_gpo_implicit_deny = false` (default), `NO_APPLICABLE_POLICY` ⇒ allow; with `ad_gpo_implicit_deny = true`, `NO_APPLICABLE_POLICY` ⇒ deny.

The `[Privilege Rights]` section syntax in GptTmpl.inf is one line per right, SIDs separated by commas; the SID is encoded as `*S-1-5-21-…` (the asterisk prefix is the SDDL convention for "SID string follows"). See `../04-group-policy/05-gpt-gpc-structure.md` for the full GptTmpl.inf schema.

```
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-21-1004382210-1580850776-2749628208-1107,*S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-21-1004382210-1580850776-2749628208-1107,CORP\LinuxAdmins
SeDenyInteractiveLogonRight = *S-1-5-21-1004382210-1580850776-2749628208-9999
```

(The `CORP\LinuxAdmins` form is also accepted — SSSD resolves it to a SID via `ad_gpo_child.c:ad_gpo_map_sids` calling `lookupnames` over MS-LSA / SAMR.)

## Configuration

```
[domain/corp.example.com]
# Required to enable the SMB fetch
ad_gpo_access_control = enforcing       # permissive (log only) | enforcing | disabled (default)

# When no applicable GPO has a [Privilege Rights] entry for the requested right
ad_gpo_implicit_deny = false            # default false; set true for "default deny"

# Map additional PAM services onto the rights
ad_gpo_map_interactive = +allow_logon_locally, +allow_logon_remote_interactive
ad_gpo_map_remote_interactive = +allow_logon_remote_interactive
ad_gpo_map_network = +allow_logon_network, +allow_logon_remote_interactive
ad_gpo_map_batch = +allow_logon_batch
ad_gpo_map_service = +allow_logon_service

# Per-service overrides (advanced) — add service names to a right
ad_gpo_map_permit = +myapp-login
ad_gpo_map_deny = +myapp-denied

# Invert an entire default mapping (rarely needed)
ad_gpo_default_right = deny             # if a service matches no mapping, deny

# Refresh interval — the background task that re-reads GPOs from SYSVOL
ad_gpo_refresh_interval = 30            # seconds (default 30; min 30)

# Host-SID cache timeout (for the host's own computer-object SID lookup)
ad_gpo_cache_timeout = 5                # seconds

# If a GPO is unreachable on SYSVOL during refresh, fall back to cached values
# instead of failing closed
ad_gpo_ignore_unreadable_gpos = false
```

### Mapping keywords

The `ad_gpo_map_*` lines accept add/remove syntax against the built-in default list:

- `+allow_logon_locally` — adds `SeInteractiveLogonRight` to the rights checked for the service
- `-allow_logon_locally` — removes that right from the service's check
- `+<service>` (in `ad_gpo_map_permit`) — adds the named PAM service to the interactive right's service list
- `-<service>` — removes it

## Commands

```bash
# Ask SSSD to evaluate access for a specific user without an actual login
sudo sssctl access-report corp.example.com user1@corp.example.com

# Inspect the cached GPO list for this host
sudo ldbsearch -H /var/lib/sss/db/cache_corp.example.com.ldb \
  '(objectClass=gpo_map)' \
  gpoGUID gpoPath gpoVersion policyType

# Force a GPO refresh (clears the cache entry; next login refetches)
sudo sss_cache -d corp.example.com -G

# Trigger the periodic task now
sudo sssctl domain-refresh corp.example.com  # if available; otherwise restart sssd
sudo systemctl restart sssd

# Read the GptTmpl.inf directly over SMB to verify what SSSD will parse
smbclient -k '//dc01.corp.example.com/sysvol' -c \
  'cd corp.example.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit; get GptTmpl.inf /dev/stdout' \
  | grep -A1 '^\[Privilege Rights\]'

# Test what PAM service name sshd actually presents
# (check via PAM debug or by reading /etc/pam.d/sshd's first non-comment line)
grep -v '^[[:space:]]*#' /etc/pam.d/sshd | head -5
```

### Verification workflow

1. From a Windows admin workstation, run `gpupdate /force` on a test Linux host's computer object context (you cannot do this directly; instead, edit the GPO and confirm via `gpresult /h` on a Windows reference host that the policy applies).
2. On the Linux host: `sudo sssctl access-report corp.example.com user1@corp.example.com` — output shows per-right evaluation, listed GPOs, and final ALLOW/DENY.
3. Attempt an SSH login; check `/var/log/sssd/sssd_ad.log` (with `debug_level = 7`) for `gpo_evaluate_gpo` lines and the `Se*LogonRight` resolution.

## Worked example — full GPO lifecycle on a Linux host

Scenario: a GPO linked to `OU=LinuxServers,DC=corp,DC=example,DC=com` grants `SeInteractiveLogonRight` to `CORP\LinuxAdmins` and `SeRemoteInteractiveLogonRight` to `CORP\LinuxUsers`. The Linux host `host01.corp.example.com` lives in that OU; an admin user `admin1` is in `LinuxAdmins`; a regular user `user1` is in `LinuxUsers` only.

1. SSSD joins via `realm join corp.example.com -U admin`. `adcli join` places the computer object in `OU=LinuxServers,…`. The host's DN is `CN=HOST01,OU=LinuxServers,DC=corp,DC=example,DC=com`.
2. First login attempt via `ssh user1@host01`:
   - `pam_sss.so` triggers `sss_access_check` in `sssd_pam` → AD provider access chain.
   - `ad_access_handler` runs the GPO check for PAM service `sshd` → maps to `SeRemoteInteractiveLogonRight`.
   - `ad_gpo_process_gpo_send` queries LDAP on the host's OU ancestry: `DC=corp,DC=example,DC=com` (domain root) and `OU=LinuxServers,DC=corp,DC=example,DC=com`. Returns `gPLink=[LDAP://CN={31B2F340-…},CN=Policies,…;0]`.
   - `ad_gpo_child_get_gpo_list` fetches the GPC `gPCFileSysPath = \\corp.example.com\SysVol\corp.example.com\Policies\{31B2F340-…}`.
   - `ad_gpo_child_read_gpo_ini` SMB-connects to `\\dc01.corp.example.com\SysVol`, reads `…\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`.
   - Parses `[Privilege Rights]`:
     ```
     SeInteractiveLogonRight = *S-1-5-21-…-1109 (LinuxAdmins)
     SeRemoteInteractiveLogonRight = *S-1-5-21-…-1110 (LinuxUsers)
     ```
   - `ad_gpo_evaluate_gpo`: user1's PAC (acquired during `pam_sss` auth phase) has `ExtraSids = {S-1-5-21-…-1110}`. Match on `SeRemoteInteractiveLogonRight` → ALLOW.
3. SSH session opens. `pam_sss.so session` writes the Kerberos ccache; `pam_oddjob_mkhomedir.so` creates `/home/corp.example.com/user1`.
4. `admin1` SSHs in — allowed because `LinuxAdmins` appears in BOTH `SeInteractiveLogonRight` and (for example) `SeRemoteInteractiveLogonRight`. Result: ALLOW.
5. A third user `user2` in `CORP\Domain Users` only attempts SSH — `Domain Users` (S-1-5-21-…-513) is NOT listed in any `SeRemoteInteractiveLogonRight` allow list, no deny right lists them either → with `ad_gpo_implicit_deny = false` (default), result is ALLOW. Set `ad_gpo_implicit_deny = true` to flip this to DENY.

### `[Privilege Rights]` parsing notes

- SIDs may be in SDDL form (`*S-1-5-21-…`) or `DOMAIN\Group` form (resolved via LSA `LsaLookupNames3`).
- The `[Privilege Rights]` section is the only section SSSD parses; other GptTmpl.inf sections (`[System Access]`, `[Event Audit]`, `[Registry Values]`) are ignored.
- A right with no SID list (empty value) means "no one has this right" — different from "right is not present at all" which means "no policy".
- Multiline values use the GptTmpl.inf continuation syntax (next line starts with whitespace).

## Wireshark / tshark

```
# LDAP query for gPLink on the host's OU ancestry
ldap.messageCode == 3 && (ldap.filter contains "gPLink" || ldap.filter contains "gPCFileSysPath")

# SMB2 TREE_CONNECT to \\dc\sysvol followed by CREATE of GptTmpl.inf
smb2.cmd == 3 || (smb2.cmd == 5 && smb2.filename contains "GptTmpl.inf")

# SMB2 READ response (the actual GPO file content)
smb2.cmd == 8 && smb2.filename contains "SecEdit"

# Full GPO refresh exchange (LDAP + SMB) from sssd_be
(ip.src == <linux-host> && (tcp.dst == 389 || tcp.dst == 445)) || (ip.dst == <linux-host> && (tcp.src == 389 || tcp.src == 445))
```

Capture:

```bash
sudo tshark -i eth0 -f 'host dc01.corp.example.com and (tcp port 389 or tcp port 445)' \
  -Y 'ldap || smb2' -V
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All logins denied after enabling `enforcing` | No GPO linked with `SeInteractiveLogonRight` populated; with `ad_gpo_implicit_deny=true` that means deny-all | Set `ad_gpo_implicit_deny = false` or link a GPO that grants `SeInteractiveLogonRight` to `Domain Users` (or a smaller group) |
| Logins allowed that should be denied | `ad_gpo_access_control = permissive` (default) only logs, does not enforce | Set to `enforcing` |
| `Access report` shows policy applied but `SeInteractiveLogonRight` evaluation skipped | PAM service name (e.g. `sshd`) not in the default mapping | Use `ad_gpo_map_interactive = +allow_logon_locally` and verify `pam_service_name` matches |
| GPO fetch times out | DC unreachable on TCP/445 from the Linux host; or the host account lacks read on the GPO container | Check `getent hosts dc01.corp.example.com`; verify SMB with `smbclient -k //dc01/sysvol`; check GPO NTFS ACLs |
| `gpo_evaluate_gpo: no GPOs in cache` | Periodic refresh never ran (e.g. `sssd_be` crashed) | `systemctl restart sssd`; inspect `sssd_ad.log` for `sdap_gpo_refresh_send` errors |
| Stale policy applied after admin edits GPO | `ad_gpo_refresh_interval = 30` not elapsed, or GPO `versionNumber` not incremented by Group Policy editor | `sss_cache -G -d corp.example.com`; verify GPO version on AD with `Get-GPO -Name <name> | select Version` |
| Deny right evaluated as Allow | `[Privilege Rights]` section uses `*S-1-5-21-…` but SSSD parsed as `S-1-5-21-…` (no asterisk) — pre-1.16 GptTmpl.inf editor quirk | Re-save GPO from a current Windows GPMC; check file with `smbclient` |
| `SeServiceLogonRight` doesn't apply to systemd services | systemd runs services as a fixed user, not via PAM `auth` phase — SSSD's GPO check is PAM-driven only | Use `ad_access_provider = simple` with `simple_allow_users` for service accounts, or rely on HBAC (FreeIPA, see `./08-freeipa-trust.md`) |

## Comparison with `pam_access` and SSSD `simple`

SSSD's `ad_access_provider` actually chains three access checks in order; if any returns `DENY`, the user is denied:

1. **`simple`** — checks `simple_allow_users`, `simple_deny_users`, `simple_allow_groups`, `simple_deny_groups`. Static lists in `sssd.conf`. Evaluated first.
2. **`ad_gpo`** — GPO `[Privilege Rights]` evaluation (this file). Evaluated second.
3. **`ad`** — always-allow fallthrough. Evaluated last.

For example, a host can have `simple_deny_users = legacy_admin` (block a specific account) and `ad_gpo_access_control = enforcing` simultaneously.

| Access control method | Source of truth | Pros | Cons |
|---|---|---|---|
| SSSD `simple_allow_users` | `sssd.conf` (per-host) | Simple, no AD changes | Per-host config; doesn't scale |
| SSSD `ad_gpo_access_control` | AD GPO `[Privilege Rights]` | Centralized in AD; uses existing GPO management tooling | Only logon rights; Linux host fetches GPO via SMB |
| FreeIPA HBAC | IPA LDAP (`ipaHBACRule` objects) | Multi-dimensional (user × host × service × source host); server-side evaluation | Requires FreeIPA deployment |
| `pam_access` (`/etc/security/access.conf`) | Local file | Powerful expression syntax (regex, NIS netgroups, IP ranges) | Per-host; no directory integration |
| `pam_listfile` | Local file (one item per line) | Tiny, focused | Very limited |
| `pam_succeed_if` | Inline in PAM stack | Conditional logic without separate config | Brittle; requires PAM file editing |
| `pam_winbind.so require_membership_of` | Inline in PAM stack | Single-group check | Winbind only; one group at a time |

Real-world deployment patterns observed:

- **Greenfield enterprise:** SSSD `ad_gpo_access_control = enforcing` for the broad rule set (Domain Admins + LinuxAdmins can log on), with `simple_allow_users` overrides for exceptional users.
- **Migration from legacy Unix NIS:** SSSD `simple_allow_groups` referencing groups whose membership is in AD, plus `pam_access` for legacy IP-range restrictions during the transition.
- **FreeIPA shop:** HBAC rules in IPA, with `ad_gpo_access_control = disabled` to avoid double-evaluation.

## Cross-platform comparison

- **AD-side counterpart:** The full Windows GPO processing pipeline including the Security CSE is documented in `../04-group-policy/01-gpo-architecture.md` (GPC/GPT), `../04-group-policy/02-gpo-processing-order.md` (LSDOU + slow-link + security filter), and `../04-group-policy/04-cse-client-side-extensions.md` (Security CSE = `scecli.dll!SceProcessReturnedGPOs` is the Windows equivalent of `ad_gpo.c`). The GptTmpl.inf format is fully decoded in `../04-group-policy/05-gpt-gpc-structure.md`. SSSD covers roughly 1/50th of the Windows GPO scope — only the `[Privilege Rights]` logon-right subset for computer context.
- **Winbind:** Winbind does not have a GPO access-control feature; it relies on `pam_winbind.so require_membership_of=` for ad-hoc group-based access. For policy-driven access on Linux with Winbind, you typically layer `pam_access.so` (`/etc/security/access.conf`) on top.
- **FreeIPA:** HBAC (Host-Based Access Control) is FreeIPA's central equivalent — see `./08-freeipa-trust.md`. HBAC rules are evaluated server-side and the result cached locally; they cover user, host, service, and source-host.
- **macOS counterpart:** macOS has no GPO engine; MDM payloads (Configuration Profiles) are the closest analog — see `../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md`.
- **High-level matrix:** `../10-comparison-matrices/05-gpo-equivalents-matrix.md`.

## References

- SSSD source — https://github.com/SSSD/sssd:
  - `src/providers/ad/ad_gpo.c` — `ad_gpo_access_send`, `ad_gpo_process_gpo_send`, `ad_gpo_evaluate_gpo`, `gpo_get_service_map`.
  - `src/providers/ad/ad_gpo_child.c` — `ad_gpo_child_get_gpo_list`, `ad_gpo_child_read_gpo_ini`, SMB fetch via libsmbclient.
  - `src/providers/ad/ad_access.c:ad_access_handler` — access-check chain orchestration.
- MS-GPOD — Group Policy: Core Protocol documentation (gPLink format, versionNumber packing).
- MS-ADTS §3.1.1 — LDAP controls used for `gPLink` retrieval.
- `../04-group-policy/05-gpt-gpc-structure.md` — GptTmpl.inf section schema.
- `sssd-ad(5)` man page — `ad_gpo_*` configuration keys.
- Red Hat Solutions — "Configuring GPO-based access control in SSSD" (solution 2793241).
