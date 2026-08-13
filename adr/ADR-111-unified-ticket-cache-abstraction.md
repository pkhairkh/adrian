---
title: "ADR-111: Unified Ticket Cache Abstraction — KCM on Linux, API: on macOS, LSA on Windows"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-091
severity: medium
unblocked_by: [workshop-decision-11]
tags: [adr, client-sdk, kerberos, ticket-cache, kcm, keychain, lsa, api-cache, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-051-kcm-linux-api-macos-cache-abstraction.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ./ADR-108-sspi-equivalent-auth-abstraction.md
  - ../catalog/08-client-sdk.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/08-macos-equivalents/05-kerberos-sso-extension.md
  - ../docs/09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-14
---

# ADR-111: Unified Ticket Cache Abstraction — KCM on Linux, API: on macOS, LSA on Windows

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK). Resolves the medium-severity problem [PC-091](../catalog/08-client-sdk.md) (domain join fragmented — the ticket cache type choice is set during domain join and must be consistent across the framework's fleet). Promotes [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) from "general direction" to "concrete SDK implementation" and locks the `TicketCache` abstraction inside `adrian-sdk`'s `AuthModule`.

## Context

Kerberos ticket caches (ccaches) come in five types with different persistence, security, and renewal semantics. Linux SSSD defaults to `KEYRING:persistent:<uid>` (kernel keyring, per-UID persistent across sessions, mode 600, accessible only to the owning UID and root). Linux systemd-style KCM (`/run/.krb5_cc_uid_<uid>` over D-Bus, backed by `sssd-kcm` or `kcm` daemon) is the modern cross-distro default in Fedora 32+ and Ubuntu 22.04+ — it supports renewal by a system daemon, multi-process ticket access, and cleaner session lifecycle. `FILE:/tmp/krb5cc_<uid>` is the legacy default (kernel 2.6-era), still used by older distros and by applications that explicitly set `KRB5CCNAME=FILE:...`. macOS PSSO Extension defaults to `API:Initialdefaultcache` (Heimdal's in-process store backed by the user's keychain at `~/Library/Keychains/login.keychain-db`, persisted across reboot, visible via `klist -v`). Windows stores tickets in LSA in-process memory (no file), accessed via `LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage)`, per [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) and [docs/09-linux-equivalents/01-sssd-ad-provider.md](../docs/09-linux-equivalents/01-sssd-ad-provider.md).

Per [PC-091](../catalog/08-client-sdk.md) and [PC-093](../catalog/08-client-sdk.md), the cache-type mismatches cause silent auth failures: an application that reads `KRB5CCNAME` and tries to open `KEYRING:persistent:502` will succeed on Linux but fail on macOS (no KEYRING type on macOS); an application that expects `FILE:/tmp/krb5cc_502` will fail on systemd-style KCM hosts (no file at that path); an application that uses the MIT `krb5_cc_default()` API will get whatever the system default is, which may not be where PSSO/SSSD wrote the TGT. ~5-10% of cross-platform SDK integration bugs trace to cache-type assumptions in application code; the operational cost is debugging time per incident, typically 2-4 hours. The renewal semantics also differ: SSSD's `krb5_renew_interval = 1h` triggers renewal at 50% of TGT lifetime via `sssd-kcm` (KCM) or the SSSD `krb5_child` (KEYRING/FILE); macOS PSSO Extension renews at 75% of TGT lifetime via Heimdal's `krb5_get_renewed_creds`; Windows LSA auto-renews at ~50% of lifetime.

[ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) established the general direction: KCM on Linux, `API:Initialdefaultcache` on macOS, LSA on Windows, with a unified `sdk.get_ticket_cache()` abstraction. Workshop Decision 11 ([workshop/decision-11-client-sdk.md](../workshop/decision-11-client-sdk.md)) §7 specifies that the macOS integration "uses the system Heimdal for PSSO Extension compatibility; framework-application Kerberos uses MIT krb5 installed at `/opt/adrian/lib/mit-krb5/`", and §8 specifies that the Linux PAM/NSS provider is `pam_adrian.so` + `nss_adrian.so.2`, with KCM as the default cache type. This ADR locks the concrete `TicketCache` abstraction inside `adrian-sdk`'s `AuthModule` and the per-platform delegation paths.

## Decision

The `adrian-sdk` Rust core ships a unified `TicketCache` abstraction in its `AuthModule`, providing a single API surface for ticket cache operations across all platforms. The abstraction delegates to the platform-native cache type: KCM (`sssd-kcm` or `kcm` daemon) on Linux, `API:Initialdefaultcache` (keychain-backed Heimdal store) on macOS, and LSA in-memory on Windows. The framework's Linux installer configures KCM as the default cache type and migrates existing FILE:/KEYRING: caches to KCM during framework enrollment. The framework's macOS client uses the PSSO-managed `API:Initialdefaultcache` cache and synchronizes tickets to the framework's MIT krb5 cache via the `adrian-kerberos-sync` daemon. The framework's Windows client wraps LSA via `LsaCallAuthenticationPackage`.

**Concrete specification**:

- The `AuthModule` exposes a `TicketCache` accessor:
  ```rust
  impl AuthModule {
      pub fn ticket_cache(&self) -> Result<&TicketCache, AuthError>;
  }
  pub struct TicketCache { inner: Arc<Inner> }
  impl TicketCache {
      pub async fn list(&self) -> Result<Vec<TicketInfo>, AuthError>;
      pub async fn get(&self, server: &Spn) -> Result<Option<Ticket>, AuthError>;
      pub async fn store(&self, ticket: Ticket) -> Result<(), AuthError>;
      pub async fn destroy(&self, server: Option<&Spn>) -> Result<(), AuthError>;
      pub async fn renew(&self) -> Result<Vec<TicketInfo>, AuthError>;
      pub async fn set_default_principal(&self, principal: &Principal) -> Result<(), AuthError>;
      pub async fn default_principal(&self) -> Result<Principal, AuthError>;
      pub fn cache_type(&self) -> CacheType;     // KCM | API | LSA | FILE | KEYRING
  }
  pub struct TicketInfo {
      pub client: Principal,
      pub server: Spn,
      pub etype: u16,                            // RFC 3961 etype
      pub end_time: SystemTime,
      pub renew_till: SystemTime,
      pub flags: TicketFlags,                    // forwardable, renewable, proxiable, etc.
  }
  ```

- Three platform-specific backends implement the abstraction via a `pub trait TicketCacheBackend`:
  ```rust
  pub trait TicketCacheBackend: Send + Sync {
      fn list(&self) -> Result<Vec<TicketInfo>, AuthError>;
      fn get(&self, server: &Spn) -> Result<Option<Ticket>, AuthError>;
      fn store(&self, ticket: Ticket) -> Result<(), AuthError>;
      fn destroy(&self, server: Option<&Spn>) -> Result<(), AuthError>;
      fn renew(&self) -> Result<Vec<TicketInfo>, AuthError>;
      fn cache_type(&self) -> CacheType;
  }
  ```
  - **`KcmCacheBackend` (Linux)**: Uses MIT krb5's `krb5_cc_resolve("KCM:")` API via the `gss-api = "0.1"` Rust crate (which wraps `libgssapi_krb5.so`). The `sssd-kcm` daemon (or `kcm` daemon) handles ticket storage and renewal. The backend reads `/etc/krb5.conf` `[libdefaults] default_ccache_name = KCM:` to confirm KCM is the default; if not, the backend logs a warning and falls back to the platform default (FILE or KEYRING), but the framework's installer ensures KCM is the default on supported distros.
  - **`ApiCacheBackend` (macOS)**: Uses Heimdal's `krb5_cc_resolve("API:Initialdefaultcache")` API via the `gss-api = "0.1"` Rust crate (which wraps `/usr/lib/libkerberos.dylib`). The PSSO Extension's auto-renewal at 75% of TGT lifetime is the renewal mechanism. The backend reads the keychain-backed cache at `~/Library/Keychains/login.keychain-db`. The backend does NOT set `KRB5CCNAME=FILE:...` to override the cache type (per [ADR-049](./ADR-049-standardize-mit-krb5.md) §macOS).
  - **`LsaCacheBackend` (Windows)**: Uses `LsaCallAuthenticationPackage(KerbRetrieveTicketMessage)` to enumerate tickets, `LsaCallAuthenticationPackage(KerbPurgeTicketCacheMessage)` to destroy tickets, and `LsaCallAuthenticationPackage(KerbSubmitTicketMessage)` to add tickets, via the `windows = "0.54"` Rust crate. Windows LSA auto-renews at ~50% of lifetime; the framework's `adrian-kerberos-renewd` daemon (per §renewal daemon below) provides a consistent metrics surface but does not duplicate LSA's renewal.

- The framework's `adrian-kerberos-renewd` daemon runs on every platform and triggers renewal at 50% of TGT lifetime (the framework's standard, between SSSD's 50% and PSSO's 75%). On Linux KCM, the daemon calls `krb5_cc_renew()` on each cache; on macOS `API:`, the daemon calls Heimdal's `krb5_get_renewed_creds()` (interoperates with PSSO's 75% renewal by checking the cache before renewal and skipping if PSSO has already renewed); on Windows, the daemon calls `LsaCallAuthenticationPackage(KerbRefreshSmartcardCredentialsMessage)`-equivalent (Windows LSA auto-renews, but the daemon provides a consistent metrics surface). The daemon runs as a system service (`systemd` on Linux, `launchd` on macOS, Windows Service on Windows) and is installed by the framework's `adrian-cli join` command.

- The framework's macOS client uses the `adrian-kerberos-sync` daemon (per [ADR-049](./ADR-049-standardize-mit-krb5.md) §macOS) to synchronize PSSO-acquired tickets from `API:Initialdefaultcache` to the framework's MIT krb5 cache at `/tmp/krb5cc_<uid>` (or `KCM:` if the framework's MIT krb5 is configured to use KCM). The sync daemon watches for PSSO ticket changes (via the `Kerberos.framework` notification API) and re-issues the ticket in the MIT cache via `krb5_cc_store_cred`. This adds a small amount of complexity (a LaunchAgent) but preserves the PSSO user experience for framework applications that use the framework's MIT Kerberos installation.

- The framework's Linux installer (`adrian-cli join` Linux path) configures KCM as the default cache type:
  - Installs the `sssd-kcm` package (or distro-equivalent KCM daemon) if not already installed.
  - Sets `default_ccache_name = KCM:` in `/etc/krb5.conf` `[libdefaults]`.
  - Sets `krb5_ccachedir = /run/user/%u` and `krb5_ccname_template = KCM:%u` in `/etc/sssd/sssd.conf` `[domain/adrian]` (per Decision 12 §1).
  - Enables and starts the `sssd-kcm.service` (or `kcm.service`) systemd unit.
  - Verifies `klist -v` returns a KCM cache (not FILE or KEYRING) on a freshly-enrolled host.
  - Migrates existing FILE: and KEYRING: caches to KCM during enrollment: (a) detects the current cache type via `echo $KRB5CCNAME` and `klist -v`; (b) reads existing tickets via `krb5_cc_resolve` on the old cache; (c) writes them to the KCM cache via `krb5_cc_store_cred`; (d) destroys the old cache via `krb5_cc_destroy`; (e) updates `/etc/krb5.conf` and per-user environment to use KCM. The migration is logged and reversible.

- The framework's macOS client uses `API:Initialdefaultcache` as the default ticket cache, inherited from PSSO Extension (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)). The macOS client MUST NOT set `KRB5CCNAME=FILE:...` to override the cache type. The macOS client MUST document `KRB5CCNAME` override as legacy and unsupported for PSSO-managed hosts.

- The framework's Windows client uses LSA in-memory ticket cache (via `LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage)`), the Windows-native behavior. The Windows client provides a `klist`-equivalent CLI (`adrian-cli klist`) that wraps the LSA call for diagnostic use; the built-in Windows `klist.exe` (available since Windows 7) is also supported.

- The C ABI exposes the `TicketCache` as opaque-handle functions following the same pattern as `AuthModule` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) §C ABI):
  ```c
  typedef struct AdrianTicketCache AdrianTicketCache;
  int32_t adrian_ticket_cache_list(AdrianTicketCache*, AdrianTicketInfo** out_infos, size_t* out_count);
  int32_t adrian_ticket_cache_get(AdrianTicketCache*, const char* spn, AdrianTicket** out);
  int32_t adrian_ticket_cache_store(AdrianTicketCache*, AdrianTicket* ticket);
  int32_t adrian_ticket_cache_destroy(AdrianTicketCache*, const char* spn_or_null);
  int32_t adrian_ticket_cache_renew(AdrianTicketCache*, AdrianTicketInfo** out_renewed, size_t* out_count);
  int32_t adrian_ticket_cache_default_principal(AdrianTicketCache*, char** out_principal);
  int32_t adrian_ticket_cache_type(AdrianTicketCache*, int* out_type);  // 0=KCM, 1=API, 2=LSA, 3=FILE, 4=KEYRING
  int32_t adrian_ticket_cache_free_infos(AdrianTicketInfo*, size_t count);
  int32_t adrian_ticket_cache_free(AdrianTicket*);
  ```

- The framework's `adrian-cli klist` CLI wraps the `TicketCache` abstraction and produces identical output on every platform: `adrian-cli klist -l` (list tickets), `adrian-cli klist -r` (renew), `adrian-cli klist -d` (destroy), matching `sso_util cache` semantics on macOS. The CLI's output format matches MIT krb5's `klist -e` output (principal, server, etype, times, flags) for operator familiarity.

- Audit logging: every `store`, `destroy`, `renew` operation emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "sdk_ticket_cache_op"`, `op`, `server_spn`, `client_principal`, `cache_type`, `result`, `platform`. `list` and `get` operations are not audited (read-only operations on the user's own cache).

## Rationale

The choice to standardize on KCM on Linux is forced by KCM's technical superiority over FILE: and KEYRING:, as established in [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) §Rationale. KCM is the only Linux cache type that supports a system-daemon renewal model; KCM supports multi-process ticket access; KCM has a cleaner session lifecycle. Fedora 32+ and Ubuntu 22.04+ have already adopted KCM as the default; the framework aligns with the distro trajectory.

The choice to standardize on `API:Initialdefaultcache` on macOS is forced by PSSO Extension's use of this cache type (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) and Decision 11 §7). The framework cannot change PSSO's cache type without breaking PSSO; the framework's macOS client inherits the PSSO cache choice. The `API:` cache is keychain-backed, persists across reboot, and is visible via the system `klist`; the framework's MIT krb5 applications on macOS (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) read from this cache via the `adrian-kerberos-sync` daemon.

The choice to use LSA in-memory on Windows is forced by Windows' native behavior. There is no file-based Kerberos cache on Windows; LSA stores tickets in `lsass.exe`'s in-process memory. The framework's Windows client wraps the LSA calls via `LsaCallAuthenticationPackage`; the framework's `adrian-cli klist` CLI produces output identical to the Windows built-in `klist.exe`.

The choice to ship a unified `TicketCache` abstraction in the `AuthModule` is forced by the framework's cross-platform-parity commitment (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)). Applications that use the framework's SDK call `auth.ticket_cache().list()` and get the same result on every platform; the SDK's platform-specific implementation handles the cache type differences. This eliminates the 5-10% cross-platform SDK integration bug rate documented in [PC-093](../catalog/08-client-sdk.md).

The choice to ship a unified renewal daemon (`adrian-kerberos-renewd`) is forced by the divergence in platform-native renewal timing (SSSD 50%, PSSO 75%, Windows LSA 50%). The framework's daemon standardizes on 50% (matching SSSD and Windows LSA); on macOS, the daemon inter-operates with PSSO's 75% renewal by checking the cache before renewal and skipping if PSSO has already renewed. The daemon also provides a consistent metrics surface (`kerberos_ticket_renewal_total{platform="...",result="..."}`) for operations teams.

The choice to migrate FILE:/KEYRING: to KCM during Linux enrollment is forced by the need to standardize on KCM. Existing Linux deployments that use FILE: or KEYRING: caches (the SSSD defaults before Fedora 32 / Ubuntu 22.04) must migrate to KCM to gain the system-daemon renewal benefit. The migration is automated and reversible; the framework's installer handles it without admin intervention.

## Consequences

**Positive**. The framework gains a single ticket-cache abstraction across platforms, eliminating the 5-10% cross-platform SDK integration bug rate. The framework's Linux posture aligns with the modern distro trajectory (KCM default on Fedora 32+, Ubuntu 22.04+). The framework's macOS posture preserves PSSO Extension's keychain-backed cache without modification. The framework's Windows posture is unchanged (LSA in-memory). The framework's `adrian-cli klist` CLI provides identical output on every platform, simplifying operations and support. The framework's `adrian-kerberos-renewd` daemon provides consistent renewal timing and metrics across platforms.

**Negative**. The framework's Linux installer requires the `sssd-kcm` package (or distro-equivalent KCM daemon) to be installed; on older distros that do not ship `sssd-kcm`, the framework's installer must fall back to KEYRING: and document the limitations (no system-daemon renewal). The framework's macOS client has a dual-cache situation (PSSO's `API:` cache + the framework's MIT cache synced via `adrian-kerberos-sync` per [ADR-049](./ADR-049-standardize-mit-krb5.md)); the cache abstraction hides this but the sync daemon adds operational surface. The framework's Windows client wraps LSA, which has a different API surface than MIT/Heimdal — the unified cache abstraction must hide this difference, which adds complexity to the Windows implementation.

**Neutral**. The framework's cache type choices are invisible to end users (they interact with `klist` / `adrian-cli klist`). The framework's cache migration is invisible to existing Kerberos users (their tickets are preserved during migration).

**Implementation cost**. ~6 person-weeks. Breakdown: `TicketCache` Rust core + `TicketCacheBackend` trait (1 pw), `KcmCacheBackend` Linux implementation (1 pw), `ApiCacheBackend` macOS implementation (1 pw, including `adrian-kerberos-sync` integration), `LsaCacheBackend` Windows implementation (1 pw), `adrian-kerberos-renewd` daemon (1 pw), C ABI surface + `adrian-cli klist` CLI + test matrix (1 pw).

**Operational impact**. Operations teams gain a single `adrian-cli klist` command for diagnostics across platforms. Operations teams gain a single renewal daemon (`adrian-kerberos-renewd`) with consistent metrics. Operations teams lose direct visibility into the platform-native cache types (KCM/API:/LSA are hidden behind the abstraction); the framework's `adrian-cli klist --verbose` provides platform-native cache details for advanced troubleshooting.

## Alternatives Considered

**Alternative 1: Use the platform-native cache type everywhere, accept the divergence, document the cache-type matrix.** The framework uses KCM on Linux, API: on macOS, LSA on Windows, and documents the matrix for application developers. The framework does not provide a unified cache abstraction; applications use the platform-native `krb5_cc_default()` API. **Rejection rationale**: This perpetuates the 5-10% cross-platform SDK integration bug rate documented in [PC-093](../catalog/08-client-sdk.md). The framework's cross-platform SDK commitment requires identical behavior across platforms; the unified cache abstraction is the structural fix.

**Alternative 2: Standardize on FILE: cache everywhere (Linux, macOS, Windows).** The framework writes all tickets to `FILE:/tmp/krb5cc_<uid>` on every platform, eliminating the cache-type divergence. **Rejection rationale**: FILE: cache is the legacy Linux default and is being replaced by KCM in modern distros; on macOS, FILE: cache breaks PSSO Extension (which requires `API:Initialdefaultcache`); on Windows, there is no FILE: cache concept (LSA stores tickets in-memory). The FILE:-everywhere alternative is not technically feasible without breaking PSSO and Windows LSA.

**Alternative 3: Standardize on KCM everywhere (Linux, macOS, Windows).** The framework installs a KCM daemon on every platform and uses KCM as the cache type. **Rejection rationale**: There is no KCM daemon for macOS (Heimdal's KCM plugin is experimental and does not integrate with PSSO's keychain-backed cache). There is no KCM daemon for Windows (LSA is the only Kerberos cache; KCM would require an additional layer on top of LSA, adding complexity for no benefit). KCM-everywhere is not technically feasible.

## Open Questions

None. The decision is fully specified by [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) (general direction) and Decision 11 (concrete SDK architecture). The implementation details (Linux cache migration logic, macOS `adrian-kerberos-sync` daemon) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The `TicketCache` is part of the `AuthModule` surface of the unified SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) and [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)).
- **Client SDK** ([PC-086](../catalog/08-client-sdk.md)): PSSO Extension uses `API:Initialdefaultcache` on macOS; the `TicketCache` abstraction inherits this.
- **Client SDK** ([PC-090](../catalog/08-client-sdk.md)): The cache type compatibility matrix is partly determined by Kerberos implementation (MIT vs Heimdal); the unified cache abstraction hides this.
- **KDC** ([PC-023](../catalog/02-kdc.md)): The KDC's TGT lifetime and renewable lifetime determine renewal timing; the cache must renew before expiry (the framework's `adrian-kerberos-renewd` runs at 50% of lifetime).
- **Operations** ([ADR-057](./ADR-057-prometheus-otel-observability.md)): Prometheus exporter exposes `kerberos_ticket_renewal_total{platform="...",result="..."}` and `kerberos_cache_size{platform="..."}` metrics.

## References

- [PC-091](../catalog/08-client-sdk.md) — problem statement (domain join fragmented — ticket cache type set at join time)
- [PC-093](../catalog/08-client-sdk.md) — Kerberos ticket cache type varies (FILE:, KEYRING:, KCM:, API: on macOS)
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings (macOS uses system Heimdal for PSSO)
- [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) — `API:Initialdefaultcache` cache type, auto-renewal at 75% of TGT lifetime
- [docs/09-linux-equivalents/01-sssd-ad-provider.md](../docs/09-linux-equivalents/01-sssd-ad-provider.md) — SSSD `krb5_ccachedir`, `krb5_renew_interval`, KEYRING default, `sssd-kcm` responder
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization (`adrian-kerberos-sync` daemon on macOS)
- [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) — KCM Linux API + macOS cache abstraction (general direction)
- [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) — PSSO modern macOS Kerberos path
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) — SSPI-equivalent auth abstraction (`AuthModule`)
- [MIT krb5 KCM Documentation](https://k5wiki.kerberos.org/wiki/Projects/KCM_client_cache) — KCM client cache design
- [RFC 4120 §5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3) — Credentials cache semantics
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) — MS-KILE profile (TGT lifetime, renewable lifetime)
- [gss-api Rust crate](https://docs.rs/gss-api) — Rust bindings to libgssapi_krb5
- [windows Rust crate](https://docs.rs/windows) — Win32 API bindings (LsaCallAuthenticationPackage)
