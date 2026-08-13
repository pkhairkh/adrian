---
title: "Cross-Platform Parity — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Cross-Platform Parity
tags: [spec, cross-platform-parity, linux, macos, windows, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Cross-Platform Parity — Technical Specification

## 1. Overview

The Cross-Platform Parity capability tracks platform-specific gaps and ensures a Windows client, a macOS client, and a Linux client all join the same framework domain, authenticate the same user, apply the same policy, mount the same shares, request the same certs, and federate to the same RPs without divergence. Where AD requires three different stacks (Windows AD-joined, macOS Enterprise Connect/Jamf, Linux SSSD/Winbind/PBIS), the framework provides one Rust core SDK with platform-native integrations that delegate to it.

Workshop Decision 12 resolved ORQ-202/203 in favor of SSSD primary + FreeIPA alternative + Winbind deprecated + PBIS unsupported. The `adrian-sssd-gpo` library extends SSSD's `[Privilege Rights]` coverage to the full `Security` PolicyArea via `gpo_access_provider = adrian` directive; FreeIPA remains supported via cross-realm trust (ADR-115) with `adrian-cli trust establish --peer freeipa` creating the trust object and configuring `altSecurityIdentities`. macOS strategy (ADR-116) is PSSO Extension first per ADR-056 — `com.apple.configuration-ext.platform-sso` MDM profile with `Hardware_Bound` mode default for T2/Apple Silicon, `Password` fallback for Intel-without-T2.

The capability carries 12 ADRs: ADR-052 (DDM-first authoring for macOS 13+), ADR-053 (key escrow + NBDE), ADR-054 (per-host LAPS rotation), ADR-055 (legacy agent migration dzdo/sudoers), ADR-056 (PSSO modern macOS Kerberos path), ADR-112 (macOS NTLM client gap closed by `adrian-ntlm-client`), ADR-113 (GPP + cross-platform policy compilation), ADR-114 (Linux identity stack SSSD primary), ADR-115 (FreeIPA alternative Linux tier), ADR-116 (legacy macOS agents EOL), ADR-117 (Apple Heimdal fork staleness mitigated), ADR-118 (MCX legacy → MDM/DDM migration). It resolves one blocker (PC-095 unified policy authoring).

The capability is implemented as **five** Rust crates at Layer 3: `adrian-sssd-gpo` (cdylib extending SSSD's GPO access provider, ~2K lines), `adrian-ntlm-client` (shared with Auth Provider, ~3K lines, macOS/Linux client), `adrian-pac-validator` (shared, unified PAC validator), `adrian-policy-executor` (shared, per-platform implementations), `adrian-authselect-profile` (Linux authselect profile generator), `adrian-base-container` (framework base container image with all integrations pre-installed). External dependencies include `clap`, `tokio`, `serde`, `serde_json`, `plist`, `ini`, `tdb`, `objc2`, `core-foundation`, `md4`, `hmac`, `sha2`, `rasn`, `rasn-pkix`, `keyring`, `tracing`, `opentelemetry`.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-sssd-gpo` | 3 | cdylib extending SSSD's `ad_gpo_access` to full `Security` PolicyArea via `gpo_access_provider = adrian`; ~2K lines | ADR-093, ADR-114 |
| `adrian-authselect-profile` | 3 | `adrian-with-sudo` authselect profile generator; installs PAM/NSS modules per ADR-050 | ADR-050, ADR-114 |
| `adrian-base-container` | 4 | Framework base container image (Ubuntu 22.04, RHEL 9 ubi9) with adrian-sdk + adrian-policyd + SSSD pre-installed | ADR-058, ADR-114 |
| `adrian-pac-validator` | 2 | Shared with KDC + File Gateway; unified PAC validator (libframework_pac_validator.dylib) | ADR-083, ADR-117 |
| `adrian-policy-executor` | 2 | Per-platform executors: WindowsPolicyExecutor, MacOsPolicyExecutor, LinuxPolicyExecutor | ADR-092, ADR-113, ADR-118 |
| `adrian-cli` (migration subcommands) | 4 | `adrian-cli migrate from-{sssd,winbind,pbis,dsconfigad,enterprise-connect,nomad,jamf-connect,centrify,admitmac,dave}` | ADR-055, ADR-116 |

## 3. Key types and traits

```rust
// crates/adrian-sssd-gpo/src/lib.rs (per ADR-093, ADR-114)

/// cdylib extending SSSD's ad_gpo_access provider.
/// Configured via sssd.conf:
///   [adrian]
///   gpo_access_provider = adrian
/// SSSD loads libadrian_sssd_gpo.so via dlopen() and calls
/// adrian_gpo_check_access() for each PAM auth attempt.
use std::os::raw::{c_char, c_int};

#[no_mangle]
pub extern "C" fn adrian_gpo_check_access(
    pamh: *mut libc::c_void,
    flags: c_int,
    upn: *const c_char,
    host_fqdn: *const c_char,
    policy_uuids: *const *const c_char,
    policy_count: usize,
) -> c_int {
    // 0 = allow, 1 = deny, -1 = error
    // Replaces SSSD's built-in [Privilege Rights] check with
    // full Security PolicyArea coverage (LogonHours,
    // HostAccessControl, GroupPolicyAccessControl).
    // ...
}

/// Full Security PolicyArea coverage per ADR-093.
#[derive(Clone, Debug)]
pub struct AccessCheck {
    pub principal: String,
    pub host: HostFacts,
    pub logon_hours: LogonHours,              // per-OU + per-user
    pub host_access_control: Vec<HostAce>,    // permit/deny hosts
    pub group_policy_access_control: Vec<GroupAce>,
    pub sudoers: Vec<SudoersEntry>,           // from GPP+policy
}
```

```rust
// crates/adrian-policy-executor/src/linux.rs (per ADR-092, ADR-118)

pub struct LinuxPolicyExecutor {
    state_db: rusqlite::Connection,
    shadow_root: PathBuf,                     // /var/lib/adrian/policy-shadow
    config: LinuxExecutorConfig,
}

impl PolicyExecutor for LinuxPolicyExecutor {
    async fn apply(&self, policy: &PolicyDoc, target_host: &HostFacts)
        -> Result<ApplyResult, PolicyError> {

        // 1. Begin transaction; write shadow paths for every file modified.
        // 2. Apply per-area compilation:
        //    Security.AccountPolicy   → /etc/login.defs.d/99-adrian.conf
        //    Security.AuditPolicy     → /etc/audit/rules.d/99-adrian.rules
        //    Security.UserRights      → authselect profile + polkit rules
        //    Security.Firewall        → /etc/nftables/adrian-*.nft
        //    Preferences.Files        → systemd-tmpfiles
        //    Preferences.Printers     → cups config
        //    Scripts.Startup          → systemd unit ExecStartPre
        // 3. Rename(2) atomic swaps to live paths.
        // 4. Reload services: authselect apply-changes, auditctl -R,
        //    nft -f, systemctl reload
        // 5. Commit transaction; on failure, roll back via shadow paths.
    }
}
```

```rust
// crates/adrian-policy-executor/src/macos.rs (per ADR-092, ADR-118)

pub struct MacOsPolicyExecutor {
    state_db: rusqlite::Connection,
    config: MacOsExecutorConfig,
}

impl PolicyExecutor for MacOsPolicyExecutor {
    async fn apply(&self, policy: &PolicyDoc, target_host: &HostFacts)
        -> Result<ApplyResult, PolicyError> {

        // Compile policy to MDM Configuration profiles:
        //   com.apple.ManagedClient.preferences   (registry equivalent)
        //   com.apple.security.firewall           (firewall)
        //   com.apple.passwordpolicy              (account policy)
        //   com.apple.configuration.files         (file deployment)
        //   com.apple.MCX         (legacy MCX, deprecated per ADR-118)
        // Install profiles via /usr/bin/profiles -I -F <profile.mobileconfig>
        // For macOS 13+ DDM-first authoring (per ADR-052):
        //   emit DDM declarations via MDM DeclarationInstall
    }
}
```

```rust
// crates/adrian-authselect-profile/src/lib.rs (per ADR-050, ADR-114)

/// adrian-with-sudo authselect profile (per ADR-114).
/// Installed via: authselect select adrian-with-sudo --force
pub const ADRIAN_AUTHSELECT_PROFILE: &str = r#"
# /etc/authselect/adrian-with-sudo/system-auth
auth        sufficient   pam_adrian.so try_first_pass
auth        required     pam_deny.so

account     sufficient   pam_adrian.so
account     required     pam_deny.so

password    sufficient   pam_adrian.so try_first_pass
password    required     pam_deny.so

session     required     pam_selinux.so close
session     required    pam_loginuid.so
session     sufficient   pam_adrian.so
session     optional    pam_systemd.so
session     required    pam_selinux.so open
"#;

/// Generate the authselect profile and install it.
pub fn install_profile() -> Result<(), ParityError> {
    let profile_dir = Path::new("/etc/authselect/adrian-with-sudo");
    fs::create_dir_all(profile_dir)?;
    fs::write(profile_dir.join("system-auth"), ADRIAN_AUTHSELECT_PROFILE)?;
    fs::write(profile_dir.join("password-auth"), ADRIAN_AUTHSELECT_PROFILE)?;
    fs::write(profile_dir.join("smartcard-auth"), ADRIAN_AUTHSELECT_PROFILE)?;
    fs::write(profile_dir.join("fingerprint-auth"), "")?;
    fs::write(profile_dir.join("postlogin"), "session optional pam_umask.so\n")?;
    fs::write(profile_dir.join("nsswitch.conf"),
              "passwd: files adrian\ngroup: files adrian\nshadow: files adrian\n")?;
    Command::new("authselect").args(["select", "adrian-with-sudo", "--force"]).status()?;
    Ok(())
}
```

```rust
// crates/adrian-cli/src/migrate.rs (per ADR-055, ADR-116)

/// Migration subcommands. Detects legacy agent installation,
/// translates config to framework equivalent, schedules removal
/// on next reboot.
pub enum MigrateTarget {
    Sssd,           // Linux: from existing SSSD config
    Winbind,        // Linux: deprecated, migrate to SSSD + adrian
    Pbis,           // Linux: unsupported, migrate
    Dsconfigad,     // macOS: from dsconfigad binding
    EnterpriseConnect, // macOS: legacy Kerberos agent
    Nomad,          // macOS: legacy Kerberos agent
    JamfConnect,    // macOS: legacy Kerberos agent
    Centrify,       // cross-platform: legacy
    Admitmac,       // macOS: legacy
    Dave,           // macOS: legacy
}

pub async fn migrate(target: MigrateTarget, opts: MigrateOpts) -> Result<(), ParityError>;
```

## 4. Data model

```
Cross-platform parity data — minimal FDB usage, mostly per-host state.

FDB subspaces used (cross-referenced):

  (0x06, 0x01, host_uuid) → host_sid           — host identity (per ADR-110)
  (0x06, 0x05, host_fqdn) → host_uuid           — host registration
  (0x0D, 0x03, host_fqdn) → applied_policy_uuids — policy tracking
  (0x08, ts, event_id) → audit event            — parity audit events

Per-host state (SQLite):

  /var/lib/adrian/parity_state.db (Linux)
  /Library/Application Support/Adrian/parity_state.db (macOS)
  %APPDATA%/Adrian/parity_state.db (Windows)

  CREATE TABLE platform_state (
    host_fqdn TEXT PRIMARY KEY,
    platform TEXT NOT NULL,            -- 'linux' | 'macos' | 'windows'
    os_version TEXT NOT NULL,
    adrian_sdk_version TEXT NOT NULL,
    enrolled_at INTEGER NOT NULL,
    last_sync_at INTEGER NOT NULL,
    migration_source TEXT              -- 'sssd' | 'winbind' | ... | 'greenfield'
  );

  CREATE TABLE legacy_agent_audit (
    detected_at INTEGER NOT NULL,
    agent_name TEXT NOT NULL,           -- 'NoMAD' | 'Enterprise Connect' | ...
    config_translated TEXT NOT NULL,    -- JSON of translated config
    removal_scheduled_at INTEGER        -- null = not yet scheduled
  );

  CREATE TABLE pac_validation_audit (   -- per ADR-117
    validated_at INTEGER NOT NULL,
    principal TEXT NOT NULL,
    pac_full_checksum_mode TEXT NOT NULL, -- 'required' | 'supported' | 'audit' | 'disabled'
    outcome TEXT NOT NULL               -- 'success' | 'failed' | 'skipped'
  );

  CREATE TABLE ddm_declarations (       -- per ADR-052, macOS 13+
    declaration_id TEXT PRIMARY KEY,
    declaration_type TEXT NOT NULL,     -- 'com.apple.configuration.management'
    payload JSON NOT NULL,
    activated_at INTEGER NOT NULL
  );

Linux SSSD integration (per ADR-114):
  /etc/sssd/sssd.conf
    [sssd]
    domains = adrian
    services = nss, pam

    [domain/adrian]
    id_provider = adrian
    auth_provider = adrian
    chpass_provider = adrian
    access_provider = adrian
    sudo_provider = adrian
    gpo_access_provider = adrian       # per ADR-093
    adrian_ldap_uri = ldaps://dc01.corp.example.com
    adrian_kdc = dc01.corp.example.com
    adrian_realm = CORP.EXAMPLE.COM

  SSSD loads libadrian_sssd_gpo.so via dlopen() and calls
  adrian_gpo_check_access() for each PAM auth attempt.

macOS PSSO Extension config (per ADR-056, ADR-116):
  /Library/Managed Preferences/com.adrian.psso.plist
    Realm = "CORP.EXAMPLE.COM"
    Hardware_Bound = true               # T2/Apple Silicon default
    Password_Fallback = false           # Intel-without-T2 = true
    Kerberos_Domain = "corp.example.com"
    KDC = "dc01.corp.example.com"
    Extension_Identifier = "com.adrian.psso"

  Com.apple.configuration-ext.platform-sso MDM profile payload:
    <key>PlatformSSO</key>
    <dict>
      <key>AuthenticationMethod</key>
      <string>Hardware_Bound</string>
      <key>Realm</key>
      <string>CORP.EXAMPLE.COM</string>
      <key>UseKeychain</key>
      <true/>
    </dict>

  adrian-kerberos-sync daemon bridges PSSO tickets to adrian
  TicketCache via com.apple.Kerberos plugin.

Apple Heimdal fork mitigation (per ADR-117):
  Framework does NOT replace system Heimdal (would break PSSO).
  Framework's Rust KDC produces modern PACs (PAC_FULL_CHECKSUM 0x13,
  PAC_REQUESTOR 0x12, compound identity, PAC_BUFFER_TICKET_CHECKSUM 0x0E
  per MS-KILE §2.2). Unified PAC validator (libframework_pac_validator.dylib)
  bypasses macOS system Heimdal's stale PAC parser.
  Config: pac_full_checksum_mode = "required" | "supported" | "audit" | "disabled"

MCX → MDM/DDM migration (per ADR-118):
  MCX (Managed Client for macOS X) — legacy, deprecated by Apple in 10.14.
  Migration: parse MCX plist, emit equivalent MDM Configuration Profile.
  For macOS 13+ payloads, emit DDM declarations (per ADR-052).
  MCX → DDM direct translation table:
    com.apple.ManagedClient.preferences → DDM declaration 'com.apple.configuration.management'
    com.apple.MCX        → DDM declaration 'com.apple.configuration.management' (legacy compat)
    com.apple.security.firewall → DDM declaration 'com.apple.configuration.firewall'
```

## 5. Protocol surface

```
Cross-platform parity protocol surface (mostly internal):

SSSD plugin protocol (per ADR-093):
  cdylib exported symbols:
    adrian_gpo_check_access(pamh, flags, upn, host, policy_uuids, count) → int
    adrian_sssd_init(config) → int
    adrian_sssd_shutdown() → int
  Loaded via dlopen() by sssd_be process.

authselect profile installation (per ADR-050, ADR-114):
  /usr/sbin/authselect select adrian-with-sudo --force
  Generates /etc/pam.d/system-auth, password-auth, smartcard-auth, etc.
  Calls `authselect apply-changes` to reload PAM.

MDM profile installation (per ADR-092):
  macOS: /usr/bin/profiles -I -F /Library/Managed Preferences/com.adrian.*.mobileconfig
  Verification: /usr/bin/profiles -L
  Removal: /usr/bin/profiles -R -p <identifier>

DDM declaration installation (per ADR-052, macOS 13+):
  POST https://mdm.corp.example.com/declared-management
  Body: JSON declaration per Apple DDM specification.
  Client polls for declaration updates every 15 minutes.

PAC validation protocol (per ADR-083, ADR-117):
  libframework_pac_validator.dylib exposes:
    adrian_pac_validate(pac, ticket, opts) → ValidationReport
  Called by every service that consumes Kerberos tickets:
    adrian-smb-server, adrian-ldap-server, adrian-cli, etc.
  Loads at runtime via dlopen on Linux/macOS, LoadLibrary on Windows.

Migration tool protocols (per ADR-055, ADR-116):
  adrian-cli migrate from-{target} --detect-only
    Detects legacy agent installation, prints report, no changes.
  adrian-cli migrate from-{target} --translate
    Translates legacy config to framework equivalent, writes to
    /tmp/adrian-migration/<timestamp>/.
  adrian-cli migrate from-{target} --apply
    Applies translated config, schedules legacy agent removal
    on next reboot.
  adrian-cli migrate from-{target} --remove-legacy
    Forcibly removes legacy agent (after manual verification).

FreeIPA cross-realm trust (per ADR-115):
  adrian-cli trust establish --peer freeipa \
    --peer-realm IPA.EXAMPLE.COM \
    --trust-password <secret>
  Creates:
    - cross-realm Kerberos trust (krbtgt/CORP.EXAMPLE.COM@IPA.EXAMPLE.COM)
    - LDAP trust object in CN=System,DC=corp,DC=example,DC=com
    - altSecurityIdentities mapping on user objects
    - DNS SRV records for cross-realm referral
  adrian-cli trust verify --peer freeipa
    Verifies trust health (one-way, two-way, transitivity).
```

## 6. Configuration

```toml
# /etc/adrian/parity.toml — Cross-platform parity configuration

[parity]
platform                = "linux"        # linux | macos | windows (auto-detected)
auto_detect_legacy_agents = true         # scan for NoMAD, Jamf, Centrify, etc.
migration_audit_log     = "/var/log/adrian/migration.log"

[linux]                                 # per ADR-114
sssd_gpo_provider       = "adrian"      # per ADR-093
authselect_profile      = "adrian-with-sudo"
base_container_image    = "ubuntu:22.04"
                       # or "registry.access.redhat.com/ubi9/ubi:9.3"
freeipa_alt_supported   = true          # per ADR-115

[macos]                                 # per ADR-116, ADR-117
psso_extension_id       = "com.adrian.psso"
psso_hardware_bound     = true          # T2/Apple Silicon
psso_password_fallback  = false         # set true for Intel-without-T2
opendirectory_bundle    = "/Library/OpenDirectory/Plugins/AdrianOpenDirectory.bundle"
kerberos_sync_daemon    = "com.adrian.kerberos-sync"
pac_full_checksum_mode  = "required"   # per ADR-117 (required|supported|audit|disabled)
replace_system_heimdal  = false        # would break PSSO; never do this
ddm_first_authoring     = true          # macOS 13+ per ADR-052
mcx_migration_enabled   = true          # per ADR-118

[windows]                               # per ADR-107
lsa_package             = "adrianlsa.dll"
credential_guard_aware  = true
gpo_compat_via_synth_cse = true         # per ADR-092

[container_native]                      # per ADR-058
base_image              = "adrian-base:latest"
distroless_variant      = false         # true for production
include_sssd            = true
include_policyd         = true
include_kerberos_renewd = true

[audit]
otel_endpoint           = "http://otel-collector:4317"
emit_legacy_agent_detected = true
emit_migration_events   = true
emit_pac_validation_events = true       # per ADR-117
emit_ddm_install_events = true
mitre_attack_mapping    = true
```

## 7. Error handling

```rust
// crates/adrian-sssd-gpo/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum ParityError {
    #[error("legacy agent detected: {0}; run `adrian-cli migrate from-{slug}`")]
    LegacyAgentDetected { agent: String, slug: String },
    #[error("migration translation failed for {target}: {reason}")]
    MigrationFailed { target: String, reason: String },
    #[error("authselect profile install failed: {0}")]
    AuthselectInstallFailed(String),
    #[error("SSSD gpo_check_access: host {0} not in directory")]
    HostNotEnrolled(String),
    #[error("SSSD gpo_check_access: policy UUID {0} not found in FDB")]
    PolicyNotFound(Uuid),
    #[error("PSSO extension not installed on macOS host")]
    PssoNotInstalled,
    #[error("OpenDirectory bundle not loaded; check /Library/OpenDirectory/Plugins/")]
    OpenDirectoryBundleNotLoaded,
    #[error("Heimdal fork PAC parse failed: {0}; using unified PAC validator")]
    HeimdalPacParseFailed(String),
    #[error("PAC full_checksum mode 'required' but ticket lacks 0x13 buffer")]
    PacFullChecksumRequired,
    #[error("MCX plist parse failed: {0}")]
    McxParseFailed(String),
    #[error("DDM declaration activation failed: {0}")]
    DdmActivationFailed(String),
    #[error("FreeIPA trust establishment failed: {0}")]
    FreeIpaTrustFailed(String),
    #[error("platform not supported: {0}")]
    UnsupportedPlatform(String),
}
```

**Error propagation.** Parity errors surface differently per platform: Linux → SSSD log + journald + `adrian-cli parity status`; macOS → `os_log` subsystem `com.adrian.parity` + Console.app; Windows → Event Log source "AdrianParity". Migration failures are non-fatal — the tool prints a translation report and exits non-zero, leaving the host in its pre-migration state. Legacy agent detection emits an alert via OTel (`T1218 System Binary Proxy Execution`, `T1547 Boot or Logon Autostart Execution`) so SOC can track orphaned legacy agents. PAC validation failures with mode=`required` block the auth attempt; mode=`audit` allows the auth but logs the failure for SOC review.

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - adrian-sssd-gpo: full Security PolicyArea coverage matrix
    - LinuxPolicyExecutor: all 7 PolicyArea compilations
    - MacOsPolicyExecutor: MDM Configuration Profile generation
    - WindowsPolicyExecutor: PReg + GptTmpl.inf generation
    - authselect profile installation (mock authselect binary)
    - Migration translator for each of 10 legacy agents
    - MCX plist parse + MDM profile emission
    - DDM declaration activation
    - PAC validation mode matrix (required/supported/audit/disabled)

Integration tests — tests/integration/, real Linux/macOS/Windows hosts
  Coverage:
    - SSSD + adrian-sssd-gpo end-to-end on Ubuntu 22.04
    - authselect adrian-with-sudo profile applied; sshd login works
    - macOS PSSO Extension MDM profile applied via Profile Manager
    - macOS OpenDirectory bundle loads; dscl query succeeds
    - adrian-kerberos-sync daemon bridges PSSO → adrian TicketCache
    - Windows LSA auth via adrianlsa.dll loaded into lsass.exe (test VM)
    - Migration from each of 10 legacy agents end-to-end
    - MCX → MDM profile migration end-to-end
    - DDM declaration activation on macOS 14+

Interop tests — tests/interop/
  Matrix:
    - Ubuntu 22.04, RHEL 9, Debian 12 with adrian-sssd-gpo
    - macOS 13, 14, 15 with PSSO Extension + OpenDirectory bundle
    - Windows Server 2022, Windows 11 with adrianlsa.dll
    - FreeIPA 4.10 cross-realm trust (per ADR-115)
    - Jamf Pro 11 pushing PSSO MDM profile
    - Microsoft Intune pushing Windows LSA config
    - Real legacy agent configs from customer migrations:
      NoMAD 1.2, Enterprise Connect 4.x, Jamf Connect 2.x,
      Centrify 5.x, PBIS 9.x, AdmitMac 10.x, DAVE 14.x

Property-based tests — proptest
  Parsers tested:
    - MCX plist round-trips
    - MDM profile plist round-trips
    - DDM declaration JSON round-trips
    - Legacy agent config parsers (10 different formats)
  Corpus: 60+ property tests across parity crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-114: Linux identity stack — SSSD primary, Winbind deprecated,
             PBIS unsupported
  - ADR-093: adrian-sssd-gpo Rust library (cdylib) extending SSSD's
             GPO coverage via gpo_access_provider = adrian
  - ADR-050: adrian-with-sudo authselect profile
  - ADR-092: LinuxPolicyExecutor + WindowsPolicyExecutor + MacOsPolicyExecutor
  - ADR-113: GPP + cross-platform policy compilation
  - ADR-112: macOS NTLM client gap closed (adrian-ntlm-client Rust crate)
  - ADR-117: Apple Heimdal fork staleness mitigated (unified PAC validator)

v1 (Phase 2):
  - ADR-116: legacy macOS agents EOL — adrian-cli migrate from-{enterprise-connect,
             nomad,jamf-connect,centrify,pbis,admitmac,dave}
  - ADR-056: PSSO as modern macOS Kerberos path
  - ADR-048: PSSO Extension + Jamf Connect migration tools
  - ADR-115: FreeIPA cross-realm trust alternative Linux tier
  - ADR-118: MCX → MDM Configuration Profile migration
  - ADR-054: per-host LAPS rotation
  - ADR-055: legacy agent migration dzdo/sudoers import
  - ADR-053: key escrow + NBDE per-host

v2 (Phase 3):
  - ADR-052: DDM-first authoring for macOS 14+ payloads
  - FreeIPA HBAC sync to framework Security.PermitHosts
  - Predictive parity drift detection via OTel anomaly scoring
  - Windows LSA via Credential Guard VSM isolation
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4 | CLI for migration subcommands |
| `tokio` | 1 | Async runtime |
| `serde` / `serde_json` | 1 | Config + audit serialization |
| `plist` | 1.6 | macOS plist (MCX + MDM profiles) |
| `rust-ini` | 0.21 | INI files (authselect, login.defs.d) |
| `tdb` | 0.1 | TDB parser for Samba legacy configs (migration) |
| `objc2` | 0.5 | macOS Objective-C runtime |
| `core-foundation` | 0.10 | macOS CoreFoundation |
| `md4` | 0.10 | MD4 for NTLM hash derivation (NTLM client shared) |
| `hmac` | 0.12 | HMAC for NTLMv2 (NTLM client shared) |
| `sha2` | 0.10 | SHA-256 (NTLM client shared) |
| `rasn` | 0.22 | ASN.1 for PAC + SPNEGO |
| `rasn-pkix` | 0.22 | X.509 for cert-based auth |
| `keyring` | 3 | Platform-secure credential store |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit events |
| `proptest` | 1 | Property-based tests |
| `rusqlite` | 0.31 | Per-host state DB |
| `libc` | 0.2 | POSIX bindings |
| `uuid` | 1.10 | UUIDs for hosts + policies |
| `adrian-policy-core` | * | PolicyDoc type |
| `adrian-policy-executor` | * | PolicyExecutor trait (shared, per-platform impls) |
| `adrian-ntlm-client` | * | NTLM client (shared with Auth Provider) |
| `adrian-pac-validator` | * | Unified PAC validator |
| `adrian-auth-core` | * | Principal type |
| `adrian-sdk` | * | AdrianClient for migration tools |

## 11. References

- ADRs: [ADR-050](../adr/ADR-050-authselect-standard-pam.md), [ADR-052](../adr/ADR-052-ddm-first-authoring.md), [ADR-053](../adr/ADR-053-key-escrow-and-nbde.md), [ADR-054](../adr/ADR-054-per-host-laps-rotation.md), [ADR-055](../adr/ADR-055-legacy-agent-migration-dzdo-sudoers.md), [ADR-056](../adr/ADR-056-psso-modern-macos-kerberos-path.md), [ADR-058](../adr/ADR-058-container-native-dcs-operator.md), [ADR-083](../adr/ADR-083-pac-validation-rpc.md), [ADR-092](../adr/ADR-092-policy-executor-trait-synthetic-windows-cse.md), [ADR-093](../adr/ADR-093-sssd-gpo-access-control-enhancement.md), [ADR-107](../adr/ADR-107-unified-rust-core-sdk.md), [ADR-112](../adr/ADR-112-macos-ntlm-client-rust-crate.md), [ADR-113](../adr/ADR-113-gpo-preferences-cross-platform-policy.md), [ADR-114](../adr/ADR-114-linux-identity-stack-sssd-primary.md), [ADR-115](../adr/ADR-115-freeipa-alternative-linux-tier.md), [ADR-116](../adr/ADR-116-legacy-macos-agents-eol.md), [ADR-117](../adr/ADR-117-apple-heimdal-fork-staleness-mitigated.md), [ADR-118](../adr/ADR-118-mcx-legacy-macos-mdm-ddm-migration.md)
- Workshop decisions: [Decision 12 — Linux Tier](../workshop/decision-12-linux-tier.md), [Decision 7 — Policy Format](../workshop/decision-07-policy-format.md), [Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md)
- KB files: [docs/09-linux-equivalents/01-sssd-ad-provider.md](../docs/09-linux-equivalents/01-sssd-ad-provider.md), [docs/09-linux-equivalents/02-sssd-id-mapping.md](../docs/09-linux-equivalents/02-sssd-id-mapping.md), [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md), [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md), [docs/08-macos-equivalents/01-opendirectory-internals.md](../docs/08-macos-equivalents/01-opendirectory-internals.md), [docs/08-macos-equivalents/06-enterprise-connect-nomad.md](../docs/08-macos-equivalents/06-enterprise-connect-nomad.md)
- RFCs: RFC 4120 (Kerberos), RFC 4178 (SPNEGO), RFC 5929 (Channel Binding)
- MS-* specs: MS-KILE (Kerberos PAC), MS-APDS (Auth Protocol Domain Support)
- Apple specs: Platform SSO Extension API (Apple Developer Documentation), Declarative Device Management (DDM) Specification, MDM Protocol Reference
- Linux: SSSD Documentation (sssd.io), authselect Manual (github.com/authselect/authselect), FreeIPA Documentation
