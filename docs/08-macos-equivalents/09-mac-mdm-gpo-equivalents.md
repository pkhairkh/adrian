---
title: macOS MDM Profiles as GPO Equivalents
audience: senior-engineers
tags: [macos, mdm, configuration-profiles, gpo-equivalents, mcx, jamf, profiles]
related:
  - ./03-jamf-connect-pro.md
  - ./04-platform-sso-extension.md
  - ../04-group-policy/01-gpo-architecture.md
  - ../04-group-policy/02-gpo-processing-order.md
  - ../09-linux-equivalents/03-sssd-gpo-access.md
  - ../10-comparison-matrices/05-gpo-equivalents-matrix.md
last_updated: 2026-08-13
---

# macOS MDM Profiles — the GPO Equivalents

macOS has no native concept of Group Policy. The closest functional equivalent is the **Configuration Profile** payload system, pushed via MDM (Mobile Device Management) or installed manually. Profiles are plist-encoded XML documents that target a specific subsystem (Passcode, Restrictions, Wi-Fi, Certificates, Login Window, FileVault, Kerberos, Printers, Custom Settings for arbitrary preference keys). The Declarative Device Management (DDM) framework introduced in macOS 13 adds a stateful, declarative alternative.

This file maps the GPO-equivalent primitives on macOS, the on-disk profile format, the payload schemas, and the verification commands.

## Profile architecture

A Configuration Profile (`.mobileconfig`) is a CMS-signed plist. The top-level structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <!-- one or more payload dicts -->
    </array>
    <key>PayloadDisplayName</key>
    <string>Corp Baseline Profile</string>
    <key>PayloadIdentifier</key>
    <string>com.corp.mdm.baseline</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>A1B2C3D4-E5F6-7890-1234-567890ABCDEF</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadScope</key>
    <string>System</string> <!-- or "User" -->
</dict>
</plist>
```

Each child of `PayloadContent` is a **payload** — a single-targeted configuration:

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.applicationaccess.new</string> <!-- Restrictions payload -->
    <key>PayloadIdentifier</key>
    <string>com.corp.mdm.baseline.restrictions</string>
    <key>PayloadUUID</key>
    <string>B2C3D4E5-F6A7-8901-2345-67890ABCDEF1</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>allowCamera</key>
    <false/>
    <key>allowCloudDocumentSync</key>
    <false/>
</dict>
```

`PayloadType` is the discriminator. The Apple Device Management Protocol Reference enumerates ~80 payload types (`com.apple.dock`, `com.apple.loginwindow`, `com.apple.security.FDERecoveryKeyEscrow`, `com.apple.security.firewall`, `com.apple.firstactiveethernet`, `com.apple.screensaver.user`, `com.apple.KerberosSSO`, `com.apple.configuration-ext.platform-sso`, etc.).

## Profile signing and trust

A profile is CMS-signed (`PKCS#7 SignedData` envelope) using the operator's MDM signing certificate. The signature is verified at install time:

- For MDM-delivered profiles: the device already trusts the MDM enrollment; the signature is a tamper-check.
- For manually installed profiles (`profiles install -path X.mobileconfig`): the user must accept the unsigned profile (or it must be signed by a CA in the user's trust store).
- For system profiles installed via `installer -pkg` or DEP: signature is mandatory.

Inspect a profile's signature with `security cms -D -i profile.mobileconfig` (dumps the signed content) or `profiles validate -p profile.mobileconfig`.

## Storage on disk

Installed profiles are stored under:

- `/private/var/db/ConfigurationProfiles/Settings/` — system-scope profiles
- `$HOME/Library/ConfigurationProfiles/Settings/` — user-scope profiles

The structure includes an index `config-profiles-index.plist` and per-payload `.plist` files keyed by the payload UUID. The Profile subsystem (`configd`-adjacent, runs under `mdmclient`) reads these at login, at boot, and on MDM-triggered refresh.

## Profile management commands

```bash
# List installed profiles (system scope)
profiles show -output stdout

# List user-scope profiles
profiles show -user -output stdout

# Install a profile (system)
sudo profiles install -path /path/to/profile.mobileconfig

# Install as a specific user
sudo profiles install -path /path/to/profile.mobileconfig -user jsmith

# Remove by identifier
sudo profiles remove -identifier com.corp.mdm.baseline

# Remove all profiles (nuclear option)
sudo profiles remove -all -enforced

# Validate (does NOT install)
profiles validate -p /path/to/profile.mobileconfig

# Sync from MDM (forces immediate MDM check-in)
sudo profiles renew -type enrollment
```

The `profiles` binary lives at `/usr/bin/profiles`; its source is closed but its command surface is documented in `man profiles`.

## GPO → Profile mapping (the 80% cases)

The matrix below maps the most-deployed GPO categories to their macOS Profile equivalents. The full mapping lives in [`../10-comparison-matrices/05-gpo-equivalents-matrix.md`](../10-comparison-matrices/05-gpo-equivalents-matrix.md).

| GPO Category | ADMX Path (Windows) | macOS PayloadType | Notes |
|--------------|---------------------|--------------------|-------|
| Password policy | `Account Policies/Password Policy` | `com.apple.mobiledevice.passwordpolicy` | `minLength`, `requireComplex`, `maxPINAgeInDays`, `minComplexChars`, `history` |
| Account lockout | `Account Policies/Account Lockout Policy` | `com.apple.mobiledevice.passwordpolicy` | `maxFailedAttempts`, `minutesUntilFailedLoginReset` |
| User rights: Allow log on locally | `Local Policies/User Rights Assignment` | (no native equivalent; use Configuration: Login Window to restrict shell access) | SSSD-like access control requires Jamf or custom PAM |
| Restricted Groups: Administrators | `Local Policies/Restricted Groups` | `com.apple.access` (Configuration: Access) | `local-only` array; restrict who can be in admin group |
| Windows Firewall: Domain Profile | `Windows Settings/Security/Windows Firewall` | `com.apple.security.firewall` | `EnableFirewall`, `BlockAllIncoming`, applications array |
| BitLocker | `Windows Components/BitLocker Drive Encryption` | `com.apple.security.FDERecoveryKeyEscrow` + `com.apple.security.FDE` | FileVault with escrow to MDM; key reissue |
| Software Restriction / AppLocker | `Windows Components/AppLocker` | `com.apple.applicationaccess.new` (Restrictions) | `familyControlsEnabled`, app bundle-id allowlist |
| Drive Maps (Preferences) | `Preferences/Drive Maps` | `com.apple.firstactiveethernet` (no native) — or custom via Jamf Policy | Typically handled via `mount_smbfs` in a login script |
| File Preferences (Preferences) | `Preferences/Files` | Custom — `com.apple.ManagedClient` payload with raw keys | Custom Settings payload with `Defaults write`-style keys |
| Registry Preferences | `Preferences/Registry` | `com.apple.ManagedClient.preferences` (Custom Settings) | The macOS equivalent is writing to any plist via MCX-style payload |
| Environment Variables | `Preferences/Environment` | Custom — `com.apple.ManagedClient.preferences` writing to `~/Library/LaunchAgents/com.corp.env.plist` | Hand-rolled |
| Scheduled Tasks | `Preferences/Scheduled Tasks` | `com.apple.applicationaccess.new` + Custom LaunchAgent/LaunchDaemon plist | The plist can be embedded as a custom payload |
| Folder Redirection | `Preferences/Folder Redirection` | (no native equivalent) | Hand-rolled via `hdiutil`/symlinks in login script |
| Scripts: Logon | `Windows Settings/Scripts (Logon/Logoff)` | MDM-provided via Jamf/Jamf Pro "Policy" with trigger `EnrollmentComplete` or `Login` | Not part of the MDM spec; vendor-specific |
| Deploy Printer | `Preferences/Control Panel/Printers` | `com.apple.printer` (Printing) | `PrinterURI`, `PrinterDeviceURI`, `DisplayName` |
| LAPS | Custom (Microsoft LAPS ADMX) | `com.apple.laps` (legacy — replaced by Platform SSO device password rotation on modern macOS) | Native macOS 14+ has `com.apple.configuration.device.password.rotation` |

## The ManagedClient / MCX legacy

Before Configuration Profiles (pre-10.7), macOS used MCX (Managed Client for OS X). MCX was stored in OD records (`mcx_settings` attribute on a user/computer/group record in OpenDirectory). The local copy of MCX was at `/Library/Managed Preferences/`. The MCX system is fully deprecated since macOS 10.14; the file format remains readable via `mcxrefresh -u <user>` (which mostly no-ops).

MCX lives on as the legacy format for the `com.apple.ManagedClient.preferences` payload type — this is a "custom settings" profile that writes arbitrary preference keys. Example:

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.ManagedClient.preferences</string>
    <key>PayloadIdentifier</key>
    <string>com.corp.mdm.mcx</string>
    <key>PayloadUUID</key>
    <string>C3D4E5F6-A7B8-9012-3456-7890ABCDEF12</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <dict>
        <key>com.apple.dock</key>
        <dict>
            <key>Forced</key>
            <array>
                <dict>
                    <key>mcx_preference_settings</key>
                    <dict>
                        <key>autohide</key>
                        <true/>
                        <key>orientation</key>
                        <string>left</string>
                    </dict>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

This writes `defaults write com.apple.dock autohide -bool true` enforced. Any user attempt to change it is reverted on next MCX refresh (which happens at login and every 15 minutes via `mcxd`).

The preference domain path under MCX is opaque; users see the managed preference as locked in System Settings (with a small orange "managed" badge). To check from CLI:

```bash
# Read managed setting
defaults read com.apple.dock autohide

# Check what's managed
profiles show -output stdout | grep -A5 "com.apple.dock"
```

## Declarative Device Management (DDM)

macOS 13+ adds Declarative Device Management, a stateful alternative to MDM. With DDM, the MDM server declares desired state; the device reconciles to that state and reports back asynchronously. The configuration is pushed as JSON (not plist) and lives in `/private/var/db/ConfigurationProfiles/Declarations/`.

The DDM manifest contains:

- **Activations** — bind a declaration set to a specific activation scope (System, User).
- **Assets** — files (e.g. a wallpaper PNG) referenced by other declarations.
- **Configurations** — a flat list of `ConfigurationType`-keyed declarations, similar to payload types.
- **Management** — server assertions (e.g. "Organizational Information" displayed in System Settings).

The DDM protocol exchanges JSON over the existing MDM check-in channel (`CheckInURL` of the MDM enrollment). Each declaration has a `DeclarationType`, `Identifier`, and `ServerToken` (used for change detection).

DDM does not yet cover everything Configuration Profiles cover — the migration is gradual. As of macOS 14, DDM covers: SoftwareUpdate restrictions, Passcode, Wallpaper, Organization Info, Asset declarations, and (in 15+) extensions to ScreenTime and a few more. Configuration Profiles remain necessary for the long tail.

## How MDM delivers profiles

The MDM protocol (Apple Push Notification service, APNs) is the transport. The MDM enrollment flow:

1. Device enrolls (via DEP at provisioning, or user-initiated via URL).
2. MDM server sends a `ProfileList` request to the device.
3. Device responds with installed profiles.
4. Server sends `InstallProfile` command with the plist-encoded profile.
5. Device installs, returns `Acknowledged`.
6. Server can later send `RemoveProfile`, `SetSettings` (declarative), `DeviceLock`, `ClearPasscode`, etc.

The MDM commands travel via the device's persistent connection to APNs. The actual command payloads are HTTPS POST to the `ServerURL` configured during enrollment. Profile installs are atomic: either the entire profile installs or none of it does; failed installs return `Error` to the server.

## Verification and audit

```bash
# All installed profiles, including from MDM
profiles show -output stdout

# System-scope only
sudo profiles show -output stdout -p

# User-scope for current user
profiles show -output stdout -u

# Get the signed payload of a specific installed profile
profiles show -output stdout -identifier com.corp.mdm.baseline -json | jq -r .[0].ProfileData | base64 -d | plutil -p -

# Audit logs (system scope)
log show --predicate 'subsystem == "com.apple.managedclient"' --last 1h

# Show MDM check-in traffic
log show --predicate 'process == "mdmclient"' --last 1h

# Validate a profile's signature
security cms -D -i /path/to/profile.mobileconfig | plutil -p -
```

The most useful `log` predicate for MDM debugging is `subsystem == "com.apple.managedclient" OR process == "mdmclient" OR process == "profiled"`.

## Wireshark / tshark

MDM traffic is HTTPS to the MDM vendor's server (Jamf Cloud, Microsoft Intune, Kandji, etc.); it's not directly inspectable without TLS interception. APNs is also HTTPS to `*.push.apple.com`. To see MDM check-in cadence at the network layer:

```bash
# Capture MDM-related TLS handshakes (will show SNI)
sudo tshark -i en0 -Y "tls.handshake.extensions_server_name contains mdm or tls.handshake.extensions_server_name contains push.apple.com" -f "tcp port 443"
```

For local profile install debug, the `profiled` daemon logs go to `system.log` under subsystem `com.apple.managedclient`.

## Cross-platform comparison

| Concept | Windows (GPO) | macOS (Profiles) | Linux (SSSD) |
|---------|---------------|------------------|--------------|
| Distribution mechanism | SYSVOL + GP Client | MDM APNs + profiles binary | LDAP-pulled CSE Computer\WindowsSecurity |
| Refresh interval | 90 min + 0-30 jitter | On MDM push or `profiles renew` | On SSSD restart + `adhoc_refresh_interval` |
| Format | GPT (registry.pol binary) + GPC | Plist (XML) | INI (GptTmpl.inf) |
| Auth backpressure | Security filtering | Profile scope (System vs User) | `ad_gpo_access_control` |
| Logging | GPSvc.log | `log show --predicate 'subsystem == "com.apple.managedclient"'` | `/var/log/sssd/sssd_ad.log` |
| Verbose audit | Group Policy Results report (`gpresult`) | `profiles show -output stdout -json` | `sssctl domain-status` |

Related files:
- AD-side: [`../04-group-policy/01-gpo-architecture.md`](../04-group-policy/01-gpo-architecture.md), [`../04-group-policy/02-gpo-processing-order.md`](../04-group-policy/02-gpo-processing-order.md)
- Linux-side: [`../09-linux-equivalents/03-sssd-gpo-access.md`](../09-linux-equivalents/03-sssd-gpo-access.md) (SSSD parses Computer\WindowsSecurity GptTmpl.inf but not other CSEs)
- macOS adjacent: [`./03-jamf-connect-pro.md`](./03-jamf-connect-pro.md), [`./04-platform-sso-extension.md`](./04-platform-sso-extension.md)
- Master matrix: [`../10-comparison-matrices/05-gpo-equivalents-matrix.md`](../10-comparison-matrices/05-gpo-equivalents-matrix.md)

## References

- Apple Developer — *Device Management Documentation* — <https://developer.apple.com/documentation/devicemanagement>
- Apple Developer — *Configuration Profile Reference* — <https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf>
- Apple Developer — *Declarative Device Management* — <https://developer.apple.com/documentation/devicemanagement/declarative_concepts>
- Jamf — *Jamf Pro Administrator's Guide* — <https://docs.jamf.com/>
- Microsoft Intune macOS Profile documentation — <https://learn.microsoft.com/en-us/mem/intune/configuration/>
- `man profiles` (macOS)
- `man mcxrefresh` (macOS)
