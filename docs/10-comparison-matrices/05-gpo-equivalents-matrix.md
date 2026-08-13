---
title: ADMX Setting × Cross-Platform Equivalent Matrix
audience: senior-engineers
tags: [gpo, admx, mdm, mcx, sssd, freeipa, ansible, cross-platform]
related:
  - ../04-group-policy/01-gpo-architecture.md
  - ../04-group-policy/03-admx-templates.md
  - ../04-group-policy/04-cse-client-side-extensions.md
  - ../04-group-policy/05-gpt-gpc-structure.md
  - ../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../09-linux-equivalents/03-sssd-gpo-access.md
  - ../09-linux-equivalents/08-freeipa-trust.md
  - ./01-feature-os-matrix.md
  - ../11-code-examples/02-sssd-conf-recipes.md
last_updated: 2026-08-13
---

# ADMX Setting × Cross-Platform Equivalent Matrix

For each common ADMX/GPO setting, the equivalent mechanism on macOS (MDM Configuration Profile payload, MCX legacy), Linux SSSD (where supported), Linux FreeIPA (HBAC/sudo/HBAC rules), and Ansible/IaC. Use as a cross-platform migration reference.

## Legend

| Column | Mechanism type |
|---|---|
| Windows native GPO | ADMX-backed Registry.pol, Security CSE GptTmpl.inf, Preferences XML |
| macOS MDM Profiles | Configuration Profile payload (`.mobileconfig`), pushed by MDM (Jamf/Intune/Kandji) |
| macOS MCX (legacy) | MCX settings in OpenDirectory (deprecated since 10.7; not recommended) |
| Linux SSSD | `sssd.conf` keys; GPO access control subset only |
| Linux FreeIPA | HBAC rules, sudo rules, `ipa-*` CLI, hostgroup-based policy |
| Ansible / IaC | `ansible.builtin.*` modules, `windows_*`, `community.general.dconf`, etc. |

## Matrix

| GPO Setting (ADMX area) | Windows native GPO | macOS MDM Profiles | macOS MCX (legacy) | Linux SSSD | Linux FreeIPA | Ansible / IaC |
|---|---|---|---|---|---|---|
| **Password policy: max age** (`secpol` Password Policy) | Computer Config → Windows Settings → Security Settings → Account Policies → Password Policy → Maximum password age | `com.apple.mobileconfig.passwordpolicy` payload → `maxPINAgeInDays` | MCX `com.apple.passwordpolicy` | n/a (server-side only; SSSD reads `maxPwdAge` from AD) | `ipa pwpolicy-mod --maxlife=90` | `ansible.windows.win_user_right` (no direct pw policy); `community.windows.win_pwpolicy` |
| **Account lockout threshold** | Computer Config → Windows Settings → Security Settings → Account Policies → Account Lockout Policy → Account lockout threshold | `com.apple.mobileconfig.passwordpolicy` payload → `maxFailedAttempts` (max 11) | MCX `com.apple.passwordpolicy` | n/a (server-side) | `ipa pwpolicy-mod --maxfail=5` | `community.windows.win_account_lockout_policy` |
| **User rights assignment: Allow log on locally** | Computer Config → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Allow log on locally | `com.apple.systempolicy.managed` payload → `LoginWindowAllowedUsers` (also `com.apple.loginwindow` for hidden users) | MCX `com.apple.loginwindow` `HiddenUsersList` | `ad_gpo_access_control = enforcing` + `ad_gpo_default_right = deny`; SSSD reads `SeInteractiveLogonRight` | HBAC rule: `ipa hbacrule-add allow-local-login --hostcat=all --servicecat=all; ipa hbacrule-add-user allow-local-login --groups=corp-users` | `ansible.builtin.lineinfile` on `/etc/security/access.conf` (Linux) or `ansible.windows.win_user_right` (Windows) |
| **Restricted Groups: Administrators** | Computer Config → Windows Settings → Security Settings → Restricted Groups → Administrators | `com.apple.systempolicy.managed` payload → `AdminUserNames` array; or `com.apple.configuration.profile.managed` payload → admin list | MCX `com.apple.MCX` `AdminRestrictions` | n/a (not natively; use sudoers) | `ipa sudorule-add-rule admin-all --cmdcat=all --hostcat=all; ipa sudorule-add-user admin-all --groups=linux-admins` | `ansible.builtin.copy` to `/etc/sudoers.d/admins`; `community.windows.win_group_membership` on Windows |
| **Security Options: LDAP client signing** | Computer Config → Windows Settings → Security Settings → Local Policies → Security Options → Domain controller: LDAP server signing requirements | n/a (macOS LDAP client doesn't enforce signing) | n/a | `ldap_sasl_mech = GSSAPI` + `ldap_tls_reqcert = demand` (signing implicit via SASL) | `ipa config-mod --user-auth-type=kerberos` (signing implicit via GSSAPI) | `ansible.builtin.lineinfile` on `sssd.conf` |
| **Windows Firewall: Domain Profile** | Computer Config → Administrative Templates → Network → Network Connections → Windows Firewall → Domain Profile | `com.apple.mobileconfig.firewall` payload → `applications`, `services` | n/a | n/a (use `firewalld` directly) | n/a (use `firewalld` directly) | `ansible.posix.firewalld` |
| **Software restriction policies / AppLocker** | Computer Config → Windows Settings → Security Settings → Application Control Policies → AppLocker | `com.apple.mobileconfig.applicationaccess` payload → `familyControlsEnabled`, `appStoreDisabled`; or `com.apple.systempolicy.managed` payload via Gatekeeper + `spctl` | MCX `com.apple.systempolicy.managed` | n/a | n/a | `ansible.builtin.command: spctl --add /path/to/app` (macOS); `ansible.windows.win_psmodule` with AppLocker cmdlets (Windows) |
| **WMI Filtering** | Computer Config → WMI Filters → query (`select * from Win32_OperatingSystem where Caption like "%Server%"`) | n/a (no equivalent — use MDM device scope) | n/a | n/a (no equivalent) | n/a (use hostgroups + host-based rules) | n/a (use `ansible.builtin.group_by` with facts) |
| **Drive Maps preference** | User Config → Preferences → Windows Settings → Drive Maps | `com.apple.mobileconfig.dock` payload (limited); `mount_smbfs` via `launchd` or `autofs` (manual) | MCX `com.apple.autodiskmount` | n/a | n/a (use `autofs` via `ipa automountlocation-*`) | `ansible.posix.mount` with `fstype: cifs` |
| **File preference** | User/Computer Config → Preferences → Windows Settings → Files | `com.apple.mobileconfig.management` payload (no direct equiv); use `scripts` payload + `cp` | MCX `com.apple.preferences.extensions.sharing` | n/a | n/a | `ansible.builtin.copy` / `ansible.builtin.template` |
| **Registry preference** | Computer Config → Preferences → Windows Settings → Registry | n/a (no registry on macOS); use `com.apple.configuration.profile.managed` for app-specific prefs | MCX `com.apple.*` (per-app) | n/a | n/a | `ansible.windows.win_regedit`; `community.general.osx_defaults` for macOS plists |
| **Environment variables preference** | User Config → Preferences → Windows Settings → Environment | `com.apple.loginwindow` payload → `EnvironmentVariables` (limited); typically via `launchd` plist | MCX `com.apple.environment` | `pam_env.so` (`/etc/security/pam_env.conf`) | n/a | `ansible.builtin.lineinfile` on `/etc/environment` or `~/.bashrc` |
| **Scheduled Tasks preference** | Computer/Config → Preferences → Control Panel Settings → Scheduled Tasks | `com.apple.mobileconfig.management` payload → `scripts` (run-once); recurring via `launchd` plist | MCX `com.apple.system.loginwindow` | n/a (use `cron` or `systemd` timers) | n/a | `ansible.builtin.cron` / `community.general.systemd` |
| **Folder Redirection** | User Config → Windows Settings → Folder Redirection | `com.apple.mobileconfig.management` (mobile account home on share); `NFSHomeDirectory` via directory binding | MCX `com.apple.MCXRedirector` | n/a (Linux users have local home + autofs) | n/a (use `ipa automountlocation` for home shares) | `ansible.posix.mount` |
| **Scripts: logon** | User Config → Windows Settings → Scripts (Logon/Logoff) | `com.apple.mobileconfig.management` payload → `scripts` (run on enroll / check-in) | MCX `com.apple.system.loginwindow LoginHook` | n/a (use `/etc/profile.d/*.sh` or `pam_exec`) | n/a (use `pam_exec.so` or sssd session hooks) | `ansible.builtin.copy` to `/etc/profile.d/` |
| **Deploy printer** | User/Computer Config → Preferences → Control Panel Settings → Printers | `com.apple.mobileconfig.airprint` payload (AirPrint only; for raw SMB print use `lpadmin`) | MCX `com.apple.printmanager` | n/a (use CUPS `lpadmin`) | n/a (use CUPS `lpadmin`) | `ansible.builtin.command: lpadmin -p PRN -E -v smb://...` |
| **BitLocker PIN enforcement** | Computer Config → Administrative Templates → Windows Components → BitLocker Drive Encryption → Operating System Drives → Require additional authentication at startup → Configure TPM startup PIN: Require | n/a (FileVault uses recovery key; no PIN equivalent) | n/a | n/a (LUKS has passphrase; no network PIN) | n/a (Clevis/Tang network-bound) | `community.windows.win_bitlocker` |
| **LAPS** (local admin password) | Computer Config → Administrative Templates → LAPS ADMX → Password Settings, Account Settings, Backup/Restore | n/a (no native LAPS for Mac; Jamf rotates local admin password via policy and escrows to Jamf server) | n/a | n/a (homemade scripts typically use Ansible) | partial: `ipa host-mod host01 --password=...` (rotates host OTP, not local admin) | `community.windows.win_laps` (Windows); custom Ansible for macOS/Linux |
| **Audit Policy: Logon events** | Computer Config → Windows Settings → Security Settings → Advanced Audit Policy → Logon | `com.apple.mobileconfig.management` → `logShow` config; `log show --predicate 'eventMessage CONTAINS "logon"'` | MCX `com.apple.systemaudit` | n/a (use `auditd` rules) | n/a (use `auditd` rules) | `ansible.builtin.lineinfile` on `/etc/audit/audit.rules` |
| **Kerberos Policy: Max lifetime for service ticket** | Computer Config → Windows Settings → Security Settings → Account Policies → Kerberos Policy → Maximum lifetime for service ticket | n/a (no policy setting on macOS) | n/a | n/a (server-side; SSSD reads from AD) | `ipa krbtpolicy-mod --maxtktlife=600` | n/a |
| **Windows Time Service: Configure Type** | Computer Config → Administrative Templates → System → Windows Time Service → Time Providers → Configure Windows NTP Client | `com.apple.mobileconfig.ntp` payload → `NTPServer`, `NTPServerName` (limited) | MCX `com.apple.systemsetup` | `chrony.conf` (`server dc01 iburst`) | `ipa-client-automount` doesn't cover NTP; use `chrony` | `community.general.timezone` + `ansible.builtin.template` on `chrony.conf` |
| **Power Management: Sleep timeout** | Computer Config → Administrative Templates → System → Power Management → Sleep Settings | `com.apple.mobileconfig.powermanagement` payload → `Sleep Timer` | MCX `com.apple.powermanagement` | n/a (use `systemd-logind` or `tlp`) | n/a | `community.general.timedatectl`; `ansible.builtin.command: pmset -a sleep 0` (macOS) |
| **Custom ADMX: Enable Windows Defender** | Computer Config → Administrative Templates → Windows Components → Windows Defender Antivirus → Turn off Windows Defender Antivirus = Disabled | `com.apple.mobileconfig.applicationaccess` (limited); third-party AV via vendor MDM profile | MCX n/a | n/a (Linux uses ClamAV) | n/a | `ansible.windows.win_feature` + `ansible.windows.win_psmodule: name=Defender` |

## Cross-platform notes

### SSSD GPO access control subset
SSSD only reads a subset of GPO: the **User Rights Assignment** section of `GptTmpl.inf` (security CSE). The supported rights are:
- `SeInteractiveLogonRight` (Allow log on locally)
- `SeRemoteInteractiveLogonRight` (Allow log on through Remote Desktop Services)
- `SeNetworkLogonRight` (Access this computer from the network)

All other GPO settings are ignored by SSSD. Configure via:
```ini
# /etc/sssd/sssd.conf
[domain/corp.example.com]
ad_gpo_access_control = enforcing
ad_gpo_default_right = deny
ad_gpo_map_interactive = +sjh-local-admins
ad_gpo_map_remote_interactive = +sjh-ssh-users
```

### macOS MDM payload types — quick reference
| Payload type | Use case |
|---|---|
| `com.apple.mobileconfig.passwordpolicy` | PIN / password complexity, max age, lockout |
| `com.apple.systempolicy.managed` | Gatekeeper, admin user list |
| `com.apple.mobileconfig.firewall` | Application Firewall rules |
| `com.apple.mobileconfig.airprint` | AirPrint printer deployment |
| `com.apple.mobileconfig.dock` | Dock items (limited drive map equiv) |
| `com.apple.mobileconfig.management` | Custom scripts, run-on-enrollment |
| `com.apple.configuration.profile.managed` | Generic key-value preferences |
| `com.apple.loginwindow` | Login window behavior, auto-login, hidden users |
| `com.apple.mobileconfig.ntp` | NTP server |
| `com.apple.mobileconfig.powermanagement` | Power/sleep settings |
| `com.apple.mobileconfig.applicationaccess` | App restrictions, family controls |

### FreeIPA HBAC vs Windows User Rights Assignment
| Windows URA | FreeIPA equivalent |
|---|---|
| SeInteractiveLogonRight | HBAC rule with `--servicecat=all` (or `sshd`, `login`) |
| SeRemoteInteractiveLogonRight | HBAC rule with `--services=sshd` |
| SeNetworkLogonRight | HBAC rule with `--services=smbd,httpd` (per service) |
| SeBatchLogonRight | HBAC rule with `--services=cron,systemd-cron` |
| SeServiceLogonRight | HBAC rule with `--services=<service>` (per service) |

### Ansible platform-coverage matrix
| Platform | GPO-equivalent modules |
|---|---|
| Windows | `ansible.windows.win_regedit`, `win_user_right`, `win_group_membership`, `win_psmodule`, `win_feature`, `community.windows.win_laps`, `win_bitlocker` |
| macOS | `community.general.osx_defaults`, `ansible.builtin.command` (with `profiles install`), `community.general.dconf` (Linux-only) |
| Linux (SSSD) | `ansible.builtin.lineinfile` (sssd.conf), `ansible.posix.authorized_key`, `ansible.builtin.copy` (sudoers.d) |
| Linux (FreeIPA) | `community.general.ipa_*` (`ipa_user`, `ipa_group`, `ipa_hbacrule`, `ipa_sudorule`, `ipa_host`) |

## See also

- [../04-group-policy/03-admx-templates.md](../04-group-policy/03-admx-templates.md) — ADMX schema and Central Store setup.
- [../04-group-policy/04-cse-client-side-extensions.md](../04-group-policy/04-cse-client-side-extensions.md) — CSE GUIDs and per-CSE behaviors.
- [../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) — macOS MDM payload deep-dive.
- [../09-linux-equivalents/03-sssd-gpo-access.md](../09-linux-equivalents/03-sssd-gpo-access.md) — SSSD GPO access control internals.

## Migration playbook — Windows GPO to macOS MDM

For each GPO category, the migration path:

| GPO category | macOS MDM payload type | Migration steps |
|---|---|---|
| Account Policies (Password, Lockout, Kerberos) | `com.apple.mobileconfig.passwordpolicy` | Map max age → `maxPINAgeInDays`, lockout → `maxFailedAttempts`, min length → `minLength`, complexity → `requireAlphaNumeric`. Kerberos policy: N/A on Mac. |
| Local Policies (User Rights, Security Options) | `com.apple.systempolicy.managed`, `com.apple.loginwindow` | Map "Allow log on locally" → `LoginWindowAllowedUsers`. "Access from network" → no direct MDM equivalent. |
| Event Log / Audit | `com.apple.systemaudit` (limited) | macOS audit via `auditd` is configured via `/etc/security/audit_control`; not MDM-pushable. Use `scripts` payload + `launchd` daemon. |
| Restricted Groups | `com.apple.systempolicy.managed` `AdminUserNames` | Map "Administrators" restricted group → `AdminUserNames` array; for non-admin restricted groups, use `pam_access.so` + `/etc/security/access.conf` via a `scripts` payload. |
| System Services | `com.apple.systempreferences` (limited) | Map "Startup type" → no MDM equivalent; use `launchctl` + `scripts` payload. |
| Registry (any HKLM/HKCU setting) | (no registry on macOS) | Map to `defaults write` via `scripts` payload, or `com.apple.configuration.profile.managed` for app-specific prefs. |
| File System / Registry Permissions | (no direct equivalent) | Use `scripts` payload with `chmod`/`chown`. |
| Windows Firewall | `com.apple.mobileconfig.firewall` | Map "Domain Profile" rules → `applications` array (by bundle ID + path). |
| Software Restriction / AppLocker | `com.apple.systempolicy.managed` (Gatekeeper) | Map path rules → `spctl --add` via `scripts`; bundle ID rules → `appswhitelisted` in payload. |
| Scripts (logon/logoff/startup/shutdown) | `com.apple.mobileconfig.management` `scripts` | Map logon script → script payload run at check-in. Startup/shutdown scripts → `launchd` daemon (no MDM-native equivalent). |
| Deployed Printers | `com.apple.mobileconfig.airprint` | Map TCP/IP printer → AirPrint if printer supports it; for raw SMB printers use `lpadmin` via `scripts` payload. |
| Drive Maps | `com.apple.dock` (limited) or `autofs` via `scripts` | Map drive map → `mount_smbfs` in login hook or `autofs` indirect map. |
| Folder Redirection | `com.apple.MCXRedirector` (legacy MCX) | No MDM-native equivalent. Use mobile account home on network share or `synthetic.conf` for home-on-share. |
| BitLocker | n/a (FileVault via MDM) | No equivalent for BitLocker PIN; FileVault recovery key escrow goes to Apple or MDM. |
| LAPS | (no native equivalent) | Use Jamf policy to rotate local admin password; escrow to Jamf server. |

## Migration playbook — Windows GPO to Linux SSSD

| GPO category | SSSD support | Linux equivalent |
|---|---|---|
| Password Policy | partial (reads `maxPwdAge` from AD) | `pam_pwquality.so` (RHEL) / `pam_cracklib.so` (Debian); cannot enforce AD policy locally |
| Account Lockout | partial (respects AD lockout) | n/a — DC enforces; client sees error |
| User Rights Assignment (5 supported) | ✓ (`ad_gpo_map_*`) | The 5 supported URA: SeInteractiveLogonRight, SeRemoteInteractiveLogonRight, SeNetworkLogonRight, SeBatchLogonRight, SeServiceLogonRight |
| All other URA | ✗ | Use `pam_access.so` + `/etc/security/access.conf` |
| Registry Policy | ✗ | Use Ansible / Puppet / Salt to manage configs |
| Windows Firewall | ✗ | Use `firewalld` (RHEL) / `ufw` (Debian); Ansible module `ansible.posix.firewalld` |
| Software Restriction | ✗ | Use `fapolicyd` (RHEL) / `apparmor` (Debian) |
| Scripts | ✗ | Use Ansible playbooks / Puppet manifests / systemd unit |
| Drive Maps | ✗ | Use `autofs` indirect map (IPA `ipa automountlocation`) |
| Folder Redirection | ✗ | Use `autofs` for home directory on NFS/SMB share |
| BitLocker | ✗ | LUKS + Clevis/Tang (NBDE) |
| LAPS | ✗ | Ansible custom role to rotate local admin password |

## Migration playbook — Windows GPO to FreeIPA

| GPO category | FreeIPA equivalent |
|---|---|
| Password Policy | `ipa pwpolicy-mod --maxlife=90 --maxfail=5 --minlength=12` (per-group via `--group`) |
| Account Lockout | Same `ipa pwpolicy` (maxfail, lockouttime) |
| User Rights Assignment | HBAC rules — `ipa hbacrule-add`, `ipa hbacrule-add-user`, `ipa hbacrule-add-host`, `ipa hbacrule-add-service` |
| Admin group membership | `ipa sudorule-add` + `ipa sudorule-add-user --groups=linux-admins` |
| Software Restriction | (out of IPA scope; use `fapolicyd` separately) |
| Scripts | (out of IPA scope; use Ansible) |
| Drive Maps | `ipa automountlocation-add` + `ipa automountkey-add` |
| Folder Redirection | Same as Drive Maps via automount |
| BitLocker | n/a (Linux uses LUKS + Clevis/Tang; IPA does not manage) |
| LAPS | `ipa host-mod --password=<otp>` rotates host enrollment password (conceptually similar but not the same as LAPS) |

## Sample migration: Windows GPO "Block USB Storage" → cross-platform

| Platform | Mechanism |
|---|---|
| Windows GPO | Computer Config → Administrative Templates → System → Removable Storage Access → All Removable Storage classes: Deny all access |
| macOS MDM | `com.apple.mobileconfig.restrictions` payload → `allowFlashDrives = false` (supervised only); or `mount_usbfs=0` via `scripts` payload |
| Linux SSSD | ✗ (not in GPO subset; use Ansible) |
| Ansible | `ansible.builtin.copy` `/etc/modprobe.d/block-usb.conf` with `install usb-storage /bin/true` |
| FreeIPA | (out of scope; use `ipa-advise` + Ansible) |

## Sample: Windows GPO "Enforce Screensaver Lock" → cross-platform

| Platform | Mechanism |
|---|---|
| Windows GPO | User Config → Admin Templates → Control Panel → Personalization → Enable screen saver = Enabled, Password protect the screen saver = Enabled, Screen saver timeout = 600 |
| macOS MDM | `com.apple.screensaver` payload → `askForPassword = 1`, `askForPasswordInterval = 5` (minutes) |
| Linux SSSD | ✗ (not in GPO subset) |
| Ansible (Linux) | `community.general.dconf`: `org/gnome/desktop/screensaver/lock-enabled = true`, `org/gnome/desktop/session/idle-delay = 600` |
| Ansible (macOS) | `community.general.osx_defaults`: `com.apple.screensaver askForPassword -int 1` |
| FreeIPA | (out of scope; use Ansible) |

## Sample: Windows GPO "Disable Local Account" → cross-platform

| Platform | Mechanism |
|---|---|
| Windows GPO | Computer Config → Preferences → Local Users and Groups: disable `Administrator` (built-in) |
| macOS MDM | `com.apple.mobileconfig.management` `scripts` payload running `dscl . -delete /Users/admin` or `pwpolicy -u admin -disableuser` |
| Linux SSSD | ✗ (not in GPO subset; use Ansible) |
| Ansible | `ansible.builtin.user: name=admin state=absent` or `ansible.builtin.command: passwd -l admin` |
| FreeIPA | n/a (IPA manages domain users, not local users; use Ansible for local) |

## Common pitfalls

1. **MDM payload scopes**: macOS Configuration Profiles apply at User or Device level. Device-level profiles apply pre-login (good for security policies); User-level apply only after user logs in. Choose scope based on the policy's intent.
2. **SSSD GPO `allow` vs `deny` lists**: SSSD's `ad_gpo_map_*` keys accept `+group` (add to allow list) or `-group` (remove from allow list). Mis-ordering can lock out all users — test in `permissive` mode first.
3. **FreeIPA HBAC rule "allow_all"**: FreeIPA ships with a default `allow_all` HBAC rule that permits everything. Disable it before enforcing real HBAC rules: `ipa hbacrule-disable allow_all`.
4. **Ansible idempotency for GPO-equivalent settings**: most Ansible modules are idempotent, but raw `ansible.builtin.command` runs are not. Use `creates:`/`removes:` parameters or check mode.
5. **macOS supervised vs unsupervised**: many MDM payload restrictions require supervised devices (enrolled via Apple Configurator or ABM). Unsupervised devices ignore these payloads silently.

## Field-tested recipes

### Enforce local-admin-only SSH on Linux clients

```ini
# /etc/sssd/sssd.conf
[domain/corp.example.com]
ad_gpo_access_control = enforcing
ad_gpo_map_remote_interactive = +corp-ssh-users
ad_gpo_default_right = deny
```

Result: only `corp-ssh-users` AD group members can SSH to SSSD-joined Linux hosts. Local users (root, etc.) are still allowed because SSSD's GPO control only applies to AD-backed logins.

### Restrict AD logon hours on macOS (PSSO Extension)

PSSO Extension does not natively respect AD `logonHours` — that attribute is checked server-side during Kerberos AS-REQ. The KDC rejects with `KDC_ERR_CLIENT_REVOKED` (31) if outside hours. macOS users will see "Authentication failed" at the login window.

Workaround: use Jamf Connect or a `scripts` payload that calls `pam_access.so` with time-based rules in `/etc/security/access.conf`:
```
+ : (corp-day-users) : 0700-1900
- : ALL : ALL
```

### Migrate "Audit Logon" GPO to macOS unified log

```
# Auditing on macOS is via /etc/security/audit_control (not MDM-pushable).
# Use a launchd daemon to ship logs to SIEM.
# /Library/LaunchDaemons/com.corp.audit-shipper.plist
```

Ansible role:
```yaml
- name: Install audit shipper
  ansible.builtin.copy:
    src: audit-shipper.plist
    dest: /Library/LaunchDaemons/com.corp.audit-shipper.plist
    mode: '0644'
- name: Load audit shipper
  ansible.builtin.command: launchctl load /Library/LaunchDaemons/com.corp.audit-shipper.plist
```

## See also (extended)

- [../04-group-policy/02-gpo-processing-order.md](../04-group-policy/02-gpo-processing-order.md) — LSDOU processing, security filtering, WMI filters.
- [../04-group-policy/05-gpt-gpc-structure.md](../04-group-policy/05-gpt-gpc-structure.md) — `Registry.pol`, `GptTmpl.inf`, Preferences XML.
- [../11-code-examples/01-powershell-ad-cmdlets.md](../11-code-examples/01-powershell-ad-cmdlets.md) — PowerShell GPO cmdlets.
- [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) — SSSD config recipes.
- [../11-code-examples/03-macos-cli-recipes.md](../11-code-examples/03-macos-cli-recipes.md) — macOS `profiles` CLI recipes.
