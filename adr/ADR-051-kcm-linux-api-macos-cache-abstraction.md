---
title: "ADR-051: KCM on Linux; API: on macOS; Unified Cache Abstraction"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-093
severity: medium
tags: [adr, client-sdk, kerberos, ticket-cache, kcm, keychain, api-cache]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/08-client-sdk.md
  - ../docs/08-macos-equivalents/05-kerberos-sso-extension.md
  - ../docs/09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

# ADR-051: KCM on Linux; API: on macOS; Unified Cache Abstraction

## Status

Accepted — 2026-08-13

## Context

Kerberos ticket caches (ccaches) come in five types with different persistence, security, and renewal semantics. Linux SSSD defaults to `KEYRING:persistent:<uid>` (kernel keyring, per-UID persistent across sessions, mode 600, accessible only to the owning UID and root). Linux systemd-style KCM (`/run/.krb5_cc_uid_<uid>` over D-Bus, backed by `sssd-kcm` or `kcm` daemon) is the modern cross-distro default in Fedora 32+ and Ubuntu 22.04+ — it supports renewal by a system daemon, multi-process ticket access, and cleaner session lifecycle. `FILE:/tmp/krb5cc_<uid>` is the legacy default (kernel 2.6-era), still used by older distros and by applications that explicitly set `KRB5CCNAME=FILE:...`. macOS PSSO Extension defaults to `API:Initialdefaultcache` (Heimdal's in-process store backed by the user's keychain at `~/Library/Keychains/login.keychain-db`, persisted across reboot, visible via `klist -v`). Windows stores tickets in LSA in-process memory (no file), accessed via `LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage)`, per [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) and [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md).

The cache-type mismatches cause silent auth failures. Per [PC-093](../catalog/08-client-sdk.md#pc-093--kerberos-ticket-cache-type-varies-file-keyring-kcm-api-on-macos)'s impact analysis, ~5-10% of cross-platform SDK integration bugs trace to cache-type assumptions in application code (e.g. `klist -v` works in the developer's terminal but fails in a service running under a different UID with a different cache type). The operational cost is debugging time per incident, typically 2-4 hours. An application that reads `KRB5CCNAME` and tries to open `KEYRING:persistent:502` will succeed on Linux but fail on macOS (no KEYRING type on macOS); an application that expects `FILE:/tmp/krb5cc_502` will fail on systemd-style KCM hosts (no file at that path); an application that uses the MIT `krb5_cc_default()` API will get whatever the system default is, which may not be where PSSO/SSSD wrote the TGT.

The renewal semantics also differ. SSSD's `krb5_renew_interval = 1h` triggers renewal at 50% of TGT lifetime via `sssd-kcm` (KCM) or the SSSD `krb5_child` (KEYRING/FILE). macOS PSSO Extension renews at 75% of TGT lifetime via Heimdal's `krb5_get_renewed_creds`. Windows LSA auto-renews at ~50% of lifetime. The framework's renewal daemon must run on every platform with consistent timing, abstracting the platform-native renewal mechanism.

The constraints from [PC-093](../catalog/08-client-sdk.md#pc-093--kerberos-ticket-cache-type-varies-file-keyring-kcm-api-on-macos) require the framework to: support KEYRING (Linux kernel keyring), KCM (Linux D-Bus daemon), FILE (legacy), API: (macOS keychain), and LSA in-memory (Windows); support auto-renewal at ~50-75% of TGT lifetime, abstracting the platform-native renewal mechanism; provide a unified cache abstraction in the SDK (`sdk.get_ticket_cache()` returns a handle that works on every platform); support `klist`-equivalent CLI on every platform; handle cache-type changes gracefully (e.g. if the user switches from FILE to KCM, the framework should migrate existing tickets).

The decision space is constrained by two platform-specific facts. First, Apple's PSSO Extension (per ADR-048) writes tickets to `API:Initialdefaultcache` (keychain-backed Heimdal store); the framework cannot change this without breaking PSSO. Second, Linux's KCM (via `sssd-kcm`) is the modern cross-distro default and the only cache type that supports a system-daemon renewal model (KEYRING requires per-user `krb5_child`; FILE requires per-user renewal). On Windows, the framework wraps LSA in-memory via `LsaCallAuthenticationPackage`; there is no file to abstract.

## Decision

The framework will standardize on KCM (`sssd-kcm` or equivalent) as the default Kerberos ticket cache type on Linux, on `API:Initialdefaultcache` (keychain-backed Heimdal store) on macOS, and on LSA in-memory on Windows. The framework's Client SDK will provide a unified cache abstraction (`sdk.get_ticket_cache()`) that returns a platform-native cache handle with `get_tickets()`, `renew()`, `destroy()`, and `set_default()` methods, abstracting the platform-native cache type. The framework's Linux installer will configure `sssd-kcm` (or `kcm` daemon) and set `KCM:` as the default cache type; existing FILE: and KEYRING: caches will be migrated to KCM automatically during framework enrollment.

**Concrete specification**:

- The framework's Linux installer MUST install and enable `sssd-kcm` (or distro-equivalent KCM daemon) on all supported Linux distros. The installer MUST set `default_ccache_name = KCM:` in `/etc/krb5.conf` `[libdefaults]`. The installer MUST verify `klist -v` returns a KCM cache (not FILE or KEYRING) on a freshly-enrolled host.
- The framework's macOS client MUST use `API:Initialdefaultcache` (keychain-backed Heimdal store) as the default ticket cache, inherited from PSSO Extension (per ADR-048). The macOS client MUST NOT set `KRB5CCNAME=FILE:...` to override the cache type. The macOS client MUST document `KRB5CCNAME` override as legacy and unsupported for PSSO-managed hosts.
- The framework's Windows client MUST use LSA in-memory ticket cache (via `LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage)`), the Windows-native behavior. The Windows client MUST provide a `klist`-equivalent CLI (`framework-klist`) that wraps the LSA call for diagnostic use; the built-in Windows `klist.exe` (available since Windows 7) is also supported.
- The framework's Client SDK MUST provide a unified cache abstraction: `sdk.get_ticket_cache()` returns a handle with the following methods:
  - `get_tickets()` — returns a list of `(principal, service, expiry, renewable_until, flags)` tuples for all tickets in the cache.
  - `renew()` — renews all renewable tickets in the cache. Returns the list of renewed tickets.
  - `destroy()` — destroys all tickets in the cache (equivalent to `kdestroy -A`).
  - `set_default()` — sets the cache as the default for new `kinit` operations (no-op on KCM and API: which are already default; meaningful on FILE: caches).
  - `get_default_principal()` — returns the default principal (the user's TGT principal).
- The framework's Client SDK MUST implement the unified cache abstraction on each platform:
  - Linux: uses MIT krb5's `krb5_cc_resolve("KCM:")` API; the `sssd-kcm` daemon handles ticket storage and renewal.
  - macOS: uses Heimdal's `krb5_cc_resolve("API:Initialdefaultcache")` API; the PSSO Extension's auto-renewal at 75% of TGT lifetime is the renewal mechanism.
  - Windows: uses `LsaCallAuthenticationPackage(KerbRetrieveTicketMessage)` to enumerate tickets, `LsaCallAuthenticationPackage(KerbPurgeTicketCacheMessage)` to destroy tickets, and `LsaCallAuthenticationPackage(KerbSubmitTicketMessage)` to add tickets.
- The framework's Client SDK MUST provide a unified renewal daemon (`framework-kerberos-renewd`) that runs on every platform and triggers renewal at 50% of TGT lifetime (the framework's standard, between SSSD's 50% and PSSO's 75%). On Linux KCM, the daemon calls `krb5_cc_renew()` on each cache; on macOS API:, the daemon calls Heimdal's `krb5_get_renewed_creds()` (interoperates with PSSO's renewal); on Windows, the daemon calls `LsaCallAuthenticationPackage(KerbRefreshSmartcardCredentialsMessage)`-equivalent (Windows LSA auto-renews, but the daemon provides a consistent metrics surface).
- The framework's Linux installer MUST migrate existing FILE: and KEYRING: caches to KCM during enrollment. The migration: (a) detects the current cache type via `echo $KRB5CCNAME` and `klist -v`; (b) reads existing tickets via `krb5_cc_resolve` on the old cache; (c) writes them to the KCM cache via `krb5_cc_store_cred`; (d) destroys the old cache via `krb5_cc_destroy`; (e) updates `/etc/krb5.conf` and per-user environment to use KCM. The migration MUST be logged and reversible.
- The framework's Client SDK MUST provide a `framework-klist` CLI that wraps the platform-native `klist` (or the framework's cache abstraction) and produces identical output on every platform. The CLI MUST support `framework-klist -l` (list tickets), `framework-klist -r` (renew), `framework-klist -d` (destroy), matching `sso_util cache` semantics on macOS.
- The framework's documentation MUST include a "Ticket cache types" section explaining the platform defaults (KCM on Linux, API: on macOS, LSA on Windows), the unified cache abstraction, the migration path from FILE:/KEYRING: to KCM on Linux, and the unsupported `KRB5CCNAME=FILE:...` override on macOS PSSO-managed hosts.
- The framework's automated test suite MUST include cache-type parity tests: acquire a TGT via `framework-join` on Linux (KCM), macOS (API:), and Windows (LSA); verify `framework-klist -l` produces identical output on all three; verify `sdk.get_ticket_cache().get_tickets()` returns the same ticket set on all three; verify renewal via `framework-kerberos-renewd` succeeds on all three; verify `framework-klist -d` destroys all tickets on all three.

## Rationale

The decision to standardize on KCM on Linux is forced by KCM's technical superiority over FILE: and KEYRING:. KCM is the only Linux cache type that supports a system-daemon renewal model (the `sssd-kcm` daemon renews tickets on behalf of the user, even when the user has no active session); KCM supports multi-process ticket access (multiple processes can read the same cache via the D-Bus daemon); KCM has a cleaner session lifecycle (tickets are destroyed when the user's last session ends, not when the kernel keyring expires). Fedora 32+ and Ubuntu 22.04+ have already adopted KCM as the default; the framework aligns with the distro trajectory.

The decision to standardize on `API:Initialdefaultcache` on macOS is forced by PSSO Extension's use of this cache type (per ADR-048). The framework cannot change PSSO's cache type without breaking PSSO; the framework's macOS client inherits the PSSO cache choice. The `API:` cache is keychain-backed, persists across reboot, and is visible via the system `klist`; the framework's MIT krb5 applications on macOS (per ADR-049) read from this cache via the `framework-kerberos-sync` daemon.

The decision to use LSA in-memory on Windows is forced by Windows' native behavior. There is no file-based Kerberos cache on Windows; LSA stores tickets in `lsass.exe`'s in-process memory. The framework's Windows client wraps the LSA calls; the framework's `framework-klist` CLI produces output identical to the Windows built-in `klist.exe`.

The decision to ship a unified cache abstraction (`sdk.get_ticket_cache()`) is forced by the framework's cross-platform SDK commitment (per PC-085). Applications that use the framework's SDK call `sdk.get_ticket_cache().get_tickets()` and get the same result on every platform; the SDK's platform-specific implementation handles the cache type differences. This eliminates the 5-10% cross-platform SDK integration bug rate documented in [PC-093](../catalog/08-client-sdk.md#pc-093--kerberos-ticket-cache-type-varies-file-keyring-kcm-api-on-macos).

The decision to ship a unified renewal daemon (`framework-kerberos-renewd`) is forced by the divergence in platform-native renewal timing (SSSD 50%, PSSO 75%, Windows LSA 50%). The framework's daemon standardizes on 50% (matching SSSD and Windows LSA); on macOS, the daemon inter-operates with PSSO's 75% renewal by checking the cache before renewal and skipping if PSSO has already renewed. The daemon also provides a consistent metrics surface (`kerberos_ticket_renewal_total{platform="...",result="..."}`) for operations teams.

The decision to migrate FILE:/KEYRING: to KCM during Linux enrollment is forced by the need to standardize on KCM. Existing Linux deployments that use FILE: or KEYRING: caches (the SSSD defaults before Fedora 32 / Ubuntu 22.04) must migrate to KCM to gain the system-daemon renewal benefit. The migration is automated and reversible; the framework's installer handles it without admin intervention.

## Consequences

**Positive**. The framework gains a single ticket-cache abstraction across platforms, eliminating the 5-10% cross-platform SDK integration bug rate. The framework's Linux posture aligns with the modern distro trajectory (KCM default on Fedora 32+, Ubuntu 22.04+). The framework's macOS posture preserves PSSO Extension's keychain-backed cache without modification. The framework's Windows posture is unchanged (LSA in-memory). The framework's `framework-klist` CLI provides identical output on every platform, simplifying operations and support.

**Negative**. The framework's Linux installer requires the `sssd-kcm` package (or distro-equivalent KCM daemon) to be installed; on older distros that do not ship `sssd-kcm`, the framework's installer must fall back to KEYRING: and document the limitations (no system-daemon renewal). The framework's macOS client has a dual-cache situation (PSSO's `API:` cache + the framework's MIT cache synced via `framework-kerberos-sync` per ADR-049); the cache abstraction hides this but the sync daemon adds operational surface. The framework's Windows client wraps LSA, which has a different API surface than MIT/Heimdal — the unified cache abstraction must hide this difference, which adds complexity to the Windows implementation.

**Neutral**. The framework's cache type choices are invisible to end users (they interact with `klist` / `framework-klist`). The framework's cache migration is invisible to existing Kerberos users (their tickets are preserved during migration).

**Implementation cost**. Medium. Estimated 8-12 engineer-weeks for: the unified cache abstraction (Rust or Go core with platform-specific implementations), the `framework-kerberos-renewd` daemon (Linux, macOS, Windows variants), the Linux cache migration logic, the `framework-klist` CLI, the test matrix (3 platforms × multiple cache scenarios), and the documentation. The unified cache abstraction is the largest single component (~4-5 engineer-weeks for a correct, well-tested implementation).

**Operational impact**. Operations teams gain a single `framework-klist` command for diagnostics across platforms. Operations teams gain a single renewal daemon (`framework-kerberos-renewd`) with consistent metrics. Operations teams lose direct visibility into the platform-native cache types (KCM/API:/LSA are hidden behind the abstraction); the framework's `framework-klist --verbose` provides platform-native cache details for advanced troubleshooting. The framework's runbook must include a "ticket cache troubleshooting" section explaining the abstraction, the platform defaults, and the diagnostic commands.

## Alternatives Considered

**Alternative 1: Use the platform-native cache type everywhere, accept the divergence, document the cache-type matrix.** The framework uses KCM on Linux, API: on macOS, LSA on Windows, and documents the matrix for application developers. The framework does not provide a unified cache abstraction; applications use the platform-native `krb5_cc_default()` API. **Rejection rationale**: This perpetuates the 5-10% cross-platform SDK integration bug rate documented in [PC-093](../catalog/08-client-sdk.md#pc-093--kerberos-ticket-cache-type-varies-file-keyring-kcm-api-on-macos). The framework's cross-platform SDK commitment requires identical behavior across platforms; the unified cache abstraction is the structural fix.

**Alternative 2: Standardize on FILE: cache everywhere (Linux, macOS, Windows).** The framework writes all tickets to `FILE:/tmp/krb5cc_<uid>` on every platform, eliminating the cache-type divergence. **Rejection rationale**: FILE: cache is the legacy Linux default and is being replaced by KCM in modern distros; on macOS, FILE: cache breaks PSSO Extension (which requires `API:Initialdefaultcache`); on Windows, there is no FILE: cache concept (LSA stores tickets in-memory). The FILE:-everywhere alternative is not technically feasible without breaking PSSO and Windows LSA.

**Alternative 3: Standardize on KCM everywhere (Linux, macOS, Windows).** The framework installs a KCM daemon on every platform and uses KCM as the cache type. **Rejection rationale**: There is no KCM daemon for macOS (Heimdal's KCM plugin is experimental and does not integrate with PSSO's keychain-backed cache). There is no KCM daemon for Windows (LSA is the only Kerberos cache; KCM would require an additional layer on top of LSA, adding complexity for no benefit). KCM-everywhere is not technically feasible.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the Client SDK architecture choice (Rust core vs per-platform wrappers, per ORQ-169/170/175/176), but the cache abstraction design is independent of the SDK architecture: the unified `sdk.get_ticket_cache()` API can be implemented in any language, with platform-specific backends calling MIT/Heimdal/LSA as appropriate.

## Cross-capability impact

- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The cache abstraction is part of the SDK surface; all framework applications that use Kerberos call `sdk.get_ticket_cache()`.
- **Client SDK** ([PC-086](../catalog/08-client-sdk.md)): PSSO Extension uses `API:Initialdefaultcache` on macOS; the cache abstraction inherits this.
- **Client SDK** ([PC-090](../catalog/08-client-sdk.md)): The cache type compatibility matrix is partly determined by Kerberos implementation (MIT vs Heimdal); the unified cache abstraction hides this.
- **KDC** ([PC-023](../catalog/02-kdc.md)): The KDC's TGT lifetime and renewable lifetime determine renewal timing; the cache must renew before expiry (the framework's `framework-kerberos-renewd` runs at 50% of lifetime).
- **Operations** ([PC-106](../catalog/10-operations.md)): Prometheus exporter exposes `kerberos_ticket_renewal_total{platform="...",result="..."}` and `kerberos_cache_size{platform="..."}` metrics.

## References

- [PC-093](../catalog/08-client-sdk.md) — problem statement
- [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) — `API:Initialdefaultcache` cache type (keychain-backed Heimdal store), auto-renewal at 75% of TGT lifetime, `sso_util cache` CLI
- [docs/09-linux-equivalents/01-sssd-ad-provider.md](../docs/09-linux-equivalents/01-sssd-ad-provider.md) — SSSD `krb5_ccachedir`, `krb5_renew_interval`, KEYRING default, `sssd-kcm` responder
- [MIT krb5 KCM Documentation](https://k5wiki.kerberos.org/wiki/Projects/KCM_client_cache) — KCM client cache design
- [RFC 4120 §5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3) — Credentials cache semantics
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) — MS-KILE profile (TGT lifetime, renewable lifetime)
