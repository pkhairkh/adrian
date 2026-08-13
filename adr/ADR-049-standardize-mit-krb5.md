---
title: "ADR-049: Standardize on MIT krb5 on Linux/macOS"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-090
severity: medium
tags: [adr, client-sdk, kerberos, mit-krb5, heimdal, pac, samba]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/08-client-sdk.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/08-macos-equivalents/07-third-party-agents-mac.md
last_updated: 2026-08-13
---

# ADR-049: Standardize on MIT krb5 on Linux/macOS

## Status

Accepted — 2026-08-13

## Context

Two Kerberos implementations dominate the open-source world: MIT krb5 (https://github.com/krb5/krb5, used by SSSD, FreeIPA, RHEL, Ubuntu) and Heimdal (https://github.com/heimdal/heimdal, used by Samba's bundled Kerberos, Apple's macOS system Kerberos, and Debian's Heimdal packages). The two are wire-compatible at the RFC 4120 protocol level (both speak MS-KILE profile against AD KDCs) but have subtle incompatibilities at the API, ticket-cache, and PAC-parsing layers. SSSD's `krb5_child` helper uses MIT krb5's `krb5_get_init_creds_password` / `krb5_get_init_creds_keytab`. Samba's `source3/libads/kerb_util.c:ads_keytab_add_entry` uses Heimdal's `krb5_kt_add_entry`. Apple's macOS ships Heimdal at `/usr/lib/libkerberos.dylib` and provides an MIT-compatible shim at `/usr/lib/libMITKerberosShim.dylib` that redirects MIT-style GSSAPI calls to Heimdal, per [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [docs/08-macos-equivalents/07-third-party-agents-mac.md](../docs/08-macos-equivalents/07-third-party-agents-mac.md).

The incompatibilities that bite in mixed environments include: (a) PAC parsing — Heimdal's `lib/krb5/pac.c` and MIT's `lib/krb5/krb/pac.c` have minor ordering differences in the `PAC_INFO_BUFFER` array walk, particularly around the `PAC_REQUESTER` (introduced Server 2016) and `PAC_FULL_CHECKSUM` (also Server 2016+) signature buffers; Heimdal's older fork (macOS ~2014-era, per PC-105) does not validate `PAC_FULL_CHECKSUM` and will accept tickets that MIT rejects; (b) ticket cache types — MIT supports `FILE:`, `DIR:`, `KEYRING:`, `KCM:`; Heimdal supports `FILE:`, `MEMORY:`, `API:` (keychain-backed on macOS), `KCM:` (via plugin); a ticket acquired by MIT's `kinit` into `FILE:/tmp/krb5cc_502` is readable by Heimdal, but a ticket acquired by Heimdal into `API:Initialdefaultcache` (keychain) is NOT readable by MIT without the shim; (c) canonicalization — MIT's `krb5_canonicalize` flag handling differs from Heimdal's in cross-realm scenarios, causing S4U2Self/S4U2Proxy flows to produce different `cname` values; (d) `kvno` and keytab formats — MIT keytab format (`/etc/krb5.keytab`) and Heimdal keytab format are byte-compatible at the KVNO level but differ in how they store enctype-specific key derivation parameters.

The framework cannot ignore this divergence. Per [PC-090](../catalog/08-client-sdk.md#pc-090--heimdal-vs-mit-kerberos-on-linuxmacos-have-subtle-incompatibilities)'s impact analysis, ~2-5% of enterprise mixed-OS deployments experience at least one of these per year, typically requiring vendor support escalation. PAC validation failures (Heimdal accepts tickets MIT rejects) create a security gap where macOS clients accept tickets that should be rejected; ticket cache incompatibilities (MIT `kinit` ticket not visible to Heimdal `klist` without shim) cause silent auth failures in mixed-OS environments; S4U2Self/S4U2Proxy canonicalization mismatches break constrained delegation; keytab format quirks cause join-tool failures.

The constraints from [PC-090](../catalog/08-client-sdk.md#pc-090--heimdal-vs-mit-kerberos-on-linuxmacos-have-subtle-incompatibilities) require the framework to: support MIT krb5 as the primary Kerberos implementation on Linux (SSSD already does); support Heimdal on macOS (Apple's PSSO Extension uses system Heimdal; cannot replace); support Heimdal on Samba AD-DC (Samba bundles Heimdal; cannot replace without forking Samba); provide a compat shim where MIT and Heimdal must coexist (macOS `libMITKerberosShim.dylib` is the reference); document PAC parsing differences and ensure the framework's PAC validator (in the KDC) accepts tickets from both MIT and Heimdal clients.

The decision space is constrained by two platform-specific facts. First, Apple's PSSO Extension (per ADR-048) uses the macOS system Heimdal at `/usr/lib/libkerberos.dylib`; the framework cannot replace the system Heimdal without breaking PSSO. Second, Samba's AD-DC bundles Heimdal at `samba-private/`; the framework cannot replace Samba's Heimdal without forking Samba. On Linux, however, SSSD uses MIT krb5 and the framework can install MIT krb5 system-wide; on macOS, the framework can install MIT krb5 in `/opt/framework/` alongside the system Heimdal, with the framework's applications using MIT and PSSO continuing to use system Heimdal.

## Decision

The framework will standardize on MIT krb5 as the primary Kerberos client implementation on Linux and as the framework-application Kerberos implementation on macOS. The framework will not replace the macOS system Heimdal (which PSSO uses) or Samba's bundled Heimdal (which Samba AD-DC uses). The framework will provide a unified PAC validator as a shared Rust/C library that all platforms use for PAC parsing and validation, bypassing each Kerberos implementation's bundled parser to ensure identical PAC validation results across platforms.

**Concrete specification**:

- The framework's Linux client MUST use MIT krb5 (system-installed at `/usr/lib/x86_64-linux-gnu/mit-krb5/` or distro-equivalent) for all framework-application Kerberos operations: `kinit`, `klist`, `kdestroy`, `kpasswd`, GSSAPI, keytab management. The framework's Linux installer MUST verify `krb5-config --version` returns `Kerberos 5 release 1.18` or later; the framework's documentation MUST list MIT krb5 1.18+ as a hard dependency.
- The framework's macOS client MUST use MIT krb5 installed at `/opt/framework/lib/mit-krb5/` for all framework-application Kerberos operations. The framework's macOS installer MUST install MIT krb5 alongside the system Heimdal; the framework's `krb5-config` MUST point at the framework's MIT installation. The system Heimdal at `/usr/lib/libkerberos.dylib` MUST NOT be modified or replaced.
- The framework's macOS client MUST interoperate with the system Heimdal via the existing `libMITKerberosShim.dylib` shim: applications that link against `libMITKerberosShim.dylib` (the macOS default for MIT-compiled code) continue to use the system Heimdal under the hood; applications that link against the framework's MIT krb5 (`/opt/framework/lib/mit-krb5/lib/libkrb5.dylib`) use the framework's MIT installation. The framework's macOS installer MUST document this distinction in the developer guide.
- The framework's macOS client MUST support PSSO Extension's use of system Heimdal (per ADR-048) without conflict: PSSO writes tickets to the keychain-backed `API:Initialdefaultcache`; the framework's MIT Kerberos applications read tickets from `/tmp/krb5cc_<uid>` (or KCM, per ADR-051). The framework's macOS client MUST synchronize tickets between the PSSO `API:Initialdefaultcache` and the framework's MIT cache via a small `framework-kerberos-sync` daemon that watches for PSSO ticket changes and re-issues them in the MIT cache.
- The framework's macOS client MUST document the system Heimdal fork's limitations (per ADR-056): missing `PAC_FULL_CHECKSUM` validation, missing `PAC_REQUESTER` support, missing compound identity for constrained delegation. The framework's unified PAC validator (see next bullet) closes the `PAC_FULL_CHECKSUM` gap by validating the checksum in the framework's code rather than relying on the system Heimdal's stale fork.
- The framework MUST ship a unified PAC validator as a shared Rust library (`libframework_pac_validator.so` on Linux, `libframework_pac_validator.dylib` on macOS, `framework_pac_validator.dll` on Windows). The library MUST implement: PAC buffer parsing (`PAC_INFO_BUFFER` array walk per MS-KILE §2.2), `PAC_FULL_CHECKSUM` validation (Server 2016+), `PAC_REQUESTER` extraction (Server 2016+), compound identity PAC handling (forest-trust constrained delegation), and signature verification (server-signature, kdc-signature, full-checksum). The library MUST be used by every framework Kerberos consumer (Linux SSSD-side PAC check, macOS framework-application PAC check, Windows framework-application PAC check, framework KDC PAC issuance).
- The framework's PAC validator MUST produce identical validation results for the same PAC on every platform. The framework's automated test suite MUST include a parity test: take a known PAC (issued by the framework KDC), validate it on Linux (via SSSD using the framework's PAC validator library), macOS (via the framework's MIT Kerberos using the framework's PAC validator library), and Windows (via the framework's Windows client using the framework's PAC validator library); assert that the validation results are byte-identical.
- The framework's Linux client MUST support Samba AD-DC's bundled Heimdal as a coexisting installation. Samba AD-DC's Heimdal at `/opt/samba/private/lib/` MUST NOT conflict with the system MIT krb5 at `/usr/lib/`. The framework's documentation MUST include a "Samba AD-DC coexistence" section explaining the dual-implementation model.
- The framework's macOS client MUST document the Homebrew Samba conflict: Homebrew Samba installs its own MIT Kerberos at `/opt/homebrew/etc/krb5.keytab`; the framework's macOS installer MUST detect Homebrew Samba and warn that the framework's MIT Kerberos installation takes precedence for framework applications. The warning MUST NOT auto-uninstall Homebrew Samba.
- The framework's documentation MUST include a "Kerberos implementation choice" section explaining the rationale (MIT primary, Heimdal retained where platform-required), the incompatibility history (PAC parsing, ticket cache, canonicalization, keytab format), and the PAC validator as the cross-platform correctness mechanism.

## Rationale

The decision to standardize on MIT krb5 as the framework-application Kerberos implementation is forced by MIT krb5's wider deployment and more active maintenance. MIT krb5 is the default on every RHEL, Ubuntu, Debian, and FreeBSD install; it has regular CVE patches; it is the reference implementation for RFC 6806 FAST and RFC 4556 PKINIT. Heimdal is bundled with Samba (for Samba AD-DC) and with macOS (as the system Kerberos); both bundled versions lag upstream Heimdal, and macOS's fork has not tracked upstream since ~2014 (per PC-105). Standardizing on MIT for framework applications gives the framework the most-maintained, most-widely-tested Kerberos implementation for the code paths the framework controls.

The decision to retain Heimdal where platform-required is forced by the framework's "do not break platform-native" posture. Apple's PSSO Extension (per ADR-048) uses system Heimdal; replacing system Heimdal would break PSSO and require the framework to reimplement the PSSO Extension's Kerberos integration. Samba AD-DC bundles Heimdal; replacing Samba's Heimdal would require forking Samba. The framework accepts these constraints and provides the framework-application MIT Kerberos as a parallel stack on macOS, leaving the system Heimdal untouched.

The decision to ship a unified PAC validator as a shared library is forced by the cross-platform correctness requirement. The framework's PAC validator must produce identical results on every platform; this cannot be achieved by relying on each Kerberos implementation's bundled parser (MIT and Heimdal have different PAC_INFO_BUFFER walk ordering, different `PAC_FULL_CHECKSUM` validation logic, different compound identity handling). A shared Rust library gives the framework one well-tested PAC parser used by every platform, eliminating the cross-platform divergence. The library closes the macOS system-Heimdal-fork gap (per ADR-056) by validating `PAC_FULL_CHECKSUM` in the framework's code rather than relying on the stale Heimdal fork.

The decision to install MIT krb5 at `/opt/framework/lib/mit-krb5/` on macOS (rather than `/usr/local/` or Homebrew) is forced by the need to avoid conflicts with the system Heimdal and with Homebrew Samba's MIT Kerberos. `/opt/framework/` is a framework-private prefix; the framework's installer manages it exclusively. The framework's `krb5-config` and `pkg-config` paths point at `/opt/framework/`, so applications that link against the framework's libraries get the framework's MIT krb5. System applications that link against `/usr/lib/libkerberos.dylib` continue to use system Heimdal; Homebrew applications that link against `/opt/homebrew/` continue to use Homebrew's stack.

The decision to ship a `framework-kerberos-sync` daemon on macOS is forced by the dual-cache problem. PSSO Extension writes tickets to `API:Initialdefaultcache` (the system Heimdal cache); the framework's MIT applications read from `/tmp/krb5cc_<uid>` or KCM (the MIT cache). Without a sync daemon, the framework's MIT applications would not see PSSO-acquired tickets and would have to re-`kinit`, defeating the PSSO purpose. The sync daemon watches for PSSO ticket changes (via the `Kerberos.framework` notification API) and re-issues the ticket in the MIT cache via `krb5_cc_store_cred`. This adds a small amount of complexity (a LaunchAgent) but preserves the PSSO user experience for framework applications.

## Consequences

**Positive**. The framework gains a single Kerberos implementation (MIT krb5) for all framework-application code paths, simplifying development, testing, and support. The framework's unified PAC validator eliminates the cross-platform PAC validation divergence that has historically caused 2-5% of mixed-OS deployment incidents. The framework's macOS strategy preserves PSSO Extension's use of system Heimdal without modification. The framework's Samba AD-DC coexistence is documented and supported.

**Negative**. The framework's macOS installation is more complex (MIT krb5 at `/opt/framework/` alongside system Heimdal at `/usr/lib/`). The framework's macOS client has a sync daemon (`framework-kerberos-sync`) that adds operational surface and a potential failure mode (if the daemon stops, framework applications lose access to PSSO-acquired tickets). The framework's PAC validator is a new shared library that must be maintained and patched as MS-KILE evolves (e.g. future PAC buffer types added by Microsoft).

**Neutral**. The framework's Linux posture is unchanged (SSSD already uses MIT krb5; the framework inherits this). The framework's Windows posture is unchanged (Windows uses MS-KILE in `kdcsvc.dll`; the framework's Windows client wraps this). The framework's macOS user-visible behavior is unchanged (PSSO continues to work; framework applications get Kerberos via MIT but the user does not see the difference).

**Implementation cost**. Medium-high. Estimated 12-16 engineer-weeks for: MIT krb5 packaging for `/opt/framework/` on macOS, the `framework-kerberos-sync` daemon, the unified PAC validator Rust library (with parity tests), the Samba AD-DC coexistence documentation, the Homebrew conflict detection, and the developer-guide documentation. The PAC validator is the largest single component (~6-8 engineer-weeks for a correct, well-tested implementation).

**Operational impact**. Operations teams gain a single PAC validation behavior across platforms (verifiable via the framework's Prometheus metric `pac_validation_total{platform="...",result="..."}`). Operations teams gain a macOS dual-Kerberos installation that requires understanding (the runbook must explain `framework-kerberos-sync` and how to troubleshoot PSSO-to-MIT cache sync failures). The framework's Prometheus exporter MUST expose `kerberos_ticket_sync_total{direction="psso_to_mit|mit_to_psso",result="..."}` on macOS for monitoring the sync daemon.

## Alternatives Considered

**Alternative 1: Standardize on MIT krb5 everywhere, including replacing system Heimdal on macOS.** The framework replaces `/usr/lib/libkerberos.dylib` with a framework-built MIT krb5 on macOS, accepting the loss of PSSO Extension compatibility. **Rejection rationale**: This breaks PSSO Extension (per ADR-048), which is the framework's macOS authentication strategy. PSSO uses `Kerberos.framework` which wraps system Heimdal; replacing system Heimdal breaks PSSO. The framework cannot justify sacrificing the macOS passwordless path for Kerberos implementation uniformity.

**Alternative 2: Standardize on Heimdal everywhere, contributing Apple's fork upstream.** The framework uses Heimdal on all platforms, contributing Apple's ~2014-era fork back to upstream Heimdal to reduce divergence. **Rejection rationale**: Heimdal is less actively maintained than MIT krb5 (fewer CVE patches, slower RFC adoption), and the upstreaming effort would require multi-year engagement with the Heimdal maintainer community (which has limited capacity). MIT krb5 is the more robust long-term choice for the framework's application code; Heimdal is retained only where platform-required (macOS system, Samba AD-DC).

**Alternative 3: Use the platform-native Kerberos implementation everywhere, accept the divergence.** The framework uses MIT krb5 on Linux, system Heimdal on macOS, and MS-KILE on Windows, accepting the cross-platform PAC parsing and canonicalization divergence. **Rejection rationale**: This perpetuates the 2-5% incident rate documented in [PC-090](../catalog/08-client-sdk.md#pc-090--heimdal-vs-mit-kerberos-on-linuxmacos-have-subtle-incompatibilities). The framework's cross-platform parity commitment requires identical behavior across platforms; the unified PAC validator is the structural fix that achieves this. The framework cannot ship a known-divergent Kerberos stack.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the Client SDK architecture choice (Rust core vs per-platform wrappers, per ORQ-169/170/175/176), but the Kerberos implementation choice is independent of the SDK architecture: the framework's PAC validator (a Rust library) and the platform-specific MIT/Heimdal/MS-KILE integrations work the same regardless of whether the SDK is Rust-core or per-platform-native.

## Cross-capability impact

- **KDC** ([PC-023](../catalog/02-kdc.md)): The KDC's PAC validator (which validates incoming tickets from clients) must use the framework's unified PAC validator library for consistency. The KDC's PAC issuance (which embeds group SIDs in the PAC) must produce PACs that the unified validator accepts on every platform.
- **Client SDK** ([PC-086](../catalog/08-client-sdk.md)): PSSO Extension uses system Heimdal; the framework's macOS client integrates with PSSO via the sync daemon (per this ADR).
- **Cross-Platform Parity** ([PC-105](../catalog/09-cross-platform-parity.md)): The macOS system Heimdal fork's limitations (per ADR-056) are closed by the framework's unified PAC validator.
- **Client SDK** ([PC-093](../catalog/08-client-sdk.md)): The ticket cache abstraction (per ADR-051) must handle both MIT cache types (`FILE:`, `KCM:`) and Heimdal cache types (`API:` on macOS) under a unified API.

## References

- [PC-090](../catalog/08-client-sdk.md) — problem statement
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — RFC 4120 ASN.1 message structures, PA-DATA type table, MS-KILE profile extensions
- [docs/08-macos-equivalents/07-third-party-agents-mac.md](../docs/08-macos-equivalents/07-third-party-agents-mac.md) — macOS system Heimdal at `/usr/lib/libkerberos.dylib`, `libMITKerberosShim.dylib` MIT-compat shim, Homebrew Samba's MIT Kerberos stack
- [MIT krb5](https://krb5.org/) — MIT Kerberos documentation and source
- [Heimdal](https://www.h5l.org/) — Heimdal Kerberos documentation and source
- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) — The Kerberos Network Authentication Service (V5)
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) — Kerberos Protocol Extensions (PAC, PAC_FULL_CHECKSUM, compound identity)
