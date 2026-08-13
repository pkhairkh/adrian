---
title: "ADR-056: PSSO as Modern macOS Kerberos Path"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-105
severity: medium
tags: [adr, cross-platform-parity, macos, kerberos, heimdal, psso, pac, fork]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/09-cross-platform-parity.md
  - ../docs/08-macos-equivalents/05-kerberos-sso-extension.md
  - ../docs/02-protocols/01-kerberos-internals.md
last_updated: 2026-08-13
---

# ADR-056: PSSO as Modern macOS Kerberos Path

## Status

Accepted — 2026-08-13

## Context

Apple ships Heimdal Kerberos at `/usr/lib/libkerberos.dylib` and `/usr/lib/libheimdal-asn1.dylib`, exposed via `/usr/bin/kinit`, `/usr/bin/klist`, `/usr/bin/kdestroy`, `/usr/bin/kpasswd`. The fork has not tracked upstream Heimdal since approximately 2014. Missing features vs upstream Heimdal and vs MIT krb5: (a) `PAC_FULL_CHECKSUM` (introduced Server 2016, MS-KILE §2.2) — a full-ticket signature over the entire PAC, separate from the per-buffer signatures, that defends against PAC tampering; macOS Heimdal fork does not validate `PAC_FULL_CHECKSUM` and will accept tickets that MIT krb5 1.16+ and Heimdal 7.5+ reject; (b) claims-based Kerberos (compound identity, MS-KILE `compound identity` for constrained delegation across forest trusts) — macOS Heimdal fork does not produce or consume compound identity PACs; (c) `PAC_REQUESTER` (Server 2016+) — a PAC buffer identifying the requesting client principal in TGS-REQ, used for KDC audit logging; macOS Heimdal fork ignores this buffer; (d) recent Kerberos CVE patches — Apple backports critical CVEs (e.g. CVE-2020-17049 Kerberos Bronze Bit) but less-critical CVEs (e.g. CVE-2024-26458, CVE-2024-26461) may not be backported, per [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md), [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), and [docs/08-macos-equivalents/07-third-party-agents-mac.md](../docs/08-macos-equivalents/07-third-party-agents-mac.md).

Apple recommends PSSO Extension for new deployments, which uses the system Heimdal under the hood (so the fork status affects PSSO too). The framework's macOS client must use PSSO + system Heimdal and document the gaps. For features that require `PAC_FULL_CHECKSUM` or compound identity (rare in practice — most deployments don't enable these on AD), the framework must either (a) document macOS as limited (PAC validation accepts tickets that other platforms reject), or (b) provide a fresh Kerberos implementation on macOS that tracks upstream Heimdal or MIT krb5 (large engineering effort, conflicts with PSSO's use of system Heimdal).

Apple also ships an MIT-compatible shim at `/usr/lib/libMITKerberosShim.dylib` that redirects MIT-style GSSAPI calls to Heimdal. This is what allows MIT-kerberos-compiled code (Homebrew packages) to work against the system keychain. The shim does not add the missing features (`PAC_FULL_CHECKSUM`, etc.) — it just maps API calls. So Homebrew MIT krb5 packages on macOS are also affected by the underlying Heimdal fork's limitations when they call into the system Kerberos via the shim.

Per [PC-105](../catalog/09-cross-platform-parity.md#pc-105--heimdal-kerberos-on-macos-is-a-fork-tracking-upstream-2014)'s impact analysis, in AD deployments that enable `PAC_FULL_CHECKSUM` enforcement (Server 2016+ default for new forests, but not retroactive on upgraded forests), macOS clients may accept tickets that should be rejected, creating a security gap. In AD deployments that use compound identity for constrained delegation (rare, requires forest functional level 2016+), macOS clients cannot participate. For typical AD deployments (Server 2012 R2 functional level, no `PAC_FULL_CHECKSUM` enforcement), macOS clients work fine.

The constraints from [PC-105](../catalog/09-cross-platform-parity.md#pc-105--heimdal-kerberos-on-macos-is-a-fork-tracking-upstream-2014) require the framework to: support `PAC_FULL_CHECKSUM` validation (KDC-side and client-side) for interop with Server 2016+ forests that enforce it; support `PAC_REQUESTER` (KDC-side audit logging) for Server 2016+ forests; support compound identity for constrained delegation across forest trusts; on macOS, use PSSO Extension + system Heimdal (cannot replace system Heimdal without breaking PSSO); document macOS limitations where the system Heimdal fork cannot support modern PAC features.

## Decision

The framework will document PSSO Extension as the only modern macOS Kerberos path, with the system Heimdal fork's limitations explicitly documented and closed by the framework's unified PAC validator (per ADR-049). The framework will not attempt to replace the system Heimdal on macOS (which would break PSSO Extension per ADR-048) or to upstream Apple's Heimdal fork to mainline Heimdal (Apple has shown limited interest in upstreaming). The framework's unified PAC validator (`libframework_pac_validator.dylib` on macOS, per ADR-049) will provide `PAC_FULL_CHECKSUM` validation, `PAC_REQUESTER` extraction, and compound identity PAC handling, bypassing the system Heimdal fork's stale PAC parser. The framework's macOS client will use the system Heimdal for ticket acquisition and session key management (via PSSO Extension) and the framework's unified PAC validator for PAC parsing and validation, ensuring consistent PAC validation behavior across macOS, Linux, and Windows.

**Concrete specification**:

- The framework's macOS client MUST use PSSO Extension (per ADR-048) for all Kerberos operations: TGT acquisition, TGS-REQ, ticket renewal, password change. The framework's macOS client MUST NOT install a parallel Kerberos implementation that competes with system Heimdal for ticket acquisition.
- The framework's macOS client MUST install the framework's MIT krb5 at `/opt/framework/lib/mit-krb5/` (per ADR-049) for framework-application Kerberos operations that do not conflict with PSSO (e.g. service-side Kerberos for framework-hosted SMB shares, keytab management for framework service principals). The framework's macOS client MUST use the `framework-kerberos-sync` daemon (per ADR-049) to synchronize PSSO-acquired tickets to the framework's MIT cache.
- The framework's unified PAC validator (`libframework_pac_validator.dylib` on macOS, per ADR-049) MUST implement: `PAC_FULL_CHECKSUM` validation per MS-KILE §2.2 (verifies the full-ticket signature over the entire PAC, separate from the per-buffer signatures); `PAC_REQUESTER` extraction (extracts the requesting client principal from the PAC buffer, used for KDC audit logging); compound identity PAC handling (parses compound identity PACs for forest-trust constrained delegation).
- The framework's macOS client MUST use the unified PAC validator for all PAC parsing and validation: when the framework's macOS client receives a Kerberos ticket (e.g. as a service accepting a TGS-REQ from a client), the client MUST parse the PAC via the unified PAC validator (not via system Heimdal's stale parser). The validator's result MUST be authoritative for the framework's access-control decisions.
- The framework's documentation MUST include a "macOS Kerberos limitations" section documenting the system Heimdal fork's missing features (per [PC-105](../catalog/09-cross-platform-parity.md#pc-105--heimdal-kerberos-on-macos-is-a-fork-tracking-upstream-2014)): `PAC_FULL_CHECKSUM` (closed by the unified PAC validator), `PAC_REQUESTER` (closed by the unified PAC validator), compound identity (closed by the unified PAC validator), recent CVE patches (Apple backports critical CVEs; less-critical CVEs may not be backported). The documentation MUST state that the unified PAC validator closes the PAC-related gaps but does not close the CVE-patch gap (which is Apple's responsibility).
- The framework's documentation MUST explicitly recommend PSSO Extension as the only modern macOS Kerberos path; legacy patterns (Enterprise Connect, removed in macOS 10.15; NoMAD, EOL after Jamf acquired Orchard & Grove in May 2021; Jamf Connect with ROPG, per ADR-048 deprecated) MUST be documented as deprecated.
- The framework's macOS client MUST support the `kinit --version` diagnostic: the output (`heimdal "Heimdal 1.21" (Apple MITKerberosShim-1.21)`) MUST be logged at framework enrollment time so operations teams can identify Macs with stale Heimdal versions (the version string suggests Heimdal 1.21-equivalent API surface but the underlying PAC validation code is older per PC-105).
- The framework's macOS client MUST log a warning when the system Heimdal version is older than the framework's required minimum (the framework's required minimum tracks upstream Heimdal releases; if Apple's system Heimdal is older, the warning documents the gap). The warning MUST be displayed at enrollment and logged to `/var/log/framework-macos-kerberos.log`.
- The framework's macOS client MUST defer the Heimdal fork upstreaming question to Tier 3 (per the triage methodology in [TRIAGE.md](./TRIAGE.md)). The framework's documentation MUST state that contributing Apple's Heimdal fork upstream is a Tier-3 question (Apple has shown limited interest in upstreaming; the framework's unified PAC validator closes the PAC-related gaps without requiring upstreaming).
- The framework's automated test suite MUST include a macOS PAC validation parity test: issue a Kerberos ticket with `PAC_FULL_CHECKSUM` from the framework's KDC (per ADR-015, HSM-bound krbtgt with auto-rotation), validate the ticket on macOS (via the framework's unified PAC validator), Linux (via the framework's unified PAC validator), and Windows (via the framework's unified PAC validator); assert that the validation results are byte-identical. The test MUST cover the case where `PAC_FULL_CHECKSUM` is present (Server 2016+ forest) and the case where it is absent (Server 2012 R2 forest, where the framework's KDC MAY optionally omit `PAC_FULL_CHECKSUM` for backward compat).
- The framework's automated test suite MUST include a compound identity test: issue a compound identity PAC from the framework's KDC, validate on macOS/Linux/Windows; assert that the compound identity is correctly parsed on all three platforms.

## Rationale

The decision to document PSSO as the only modern macOS Kerberos path is forced by Apple's direction. Apple introduced PSSO in macOS 13 (Ventura, October 2022) as the first-party passwordless path; the system Heimdal underpins PSSO and cannot be replaced without breaking PSSO. The framework's macOS strategy (per ADR-048) is PSSO-first; this ADR documents the Kerberos-specific implications of that strategy. Legacy patterns (Enterprise Connect, NoMAD, Jamf Connect with ROPG) are deprecated by their respective vendors; the framework's documentation aligns with the vendor trajectory.

The decision to close the system Heimdal fork's PAC-related gaps via the unified PAC validator (rather than replacing system Heimdal) is forced by the framework's PSSO commitment. PSSO uses system Heimdal for ticket acquisition and session key management; the framework cannot replace system Heimdal without breaking PSSO. The framework's unified PAC validator (per ADR-049) is a shared Rust/C library that handles PAC parsing and validation on every platform, bypassing each Kerberos implementation's bundled parser. On macOS, the validator closes the `PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, and compound identity gaps that the system Heimdal fork cannot handle.

The decision to defer the Heimdal fork upstreaming question to Tier 3 is forced by Apple's limited interest in upstreaming. Apple's Heimdal fork has not tracked upstream since ~2014; the framework's contributing patches to mainline Heimdal would require Apple's cooperation (which has not been forthcoming) and ongoing maintenance effort (the framework would have to track mainline Heimdal releases and re-base Apple's fork on each release). The framework's unified PAC validator closes the PAC-related gaps without requiring upstreaming; the remaining gap (less-critical CVE patches) is Apple's responsibility, and the framework's documentation makes this explicit.

The decision to install MIT krb5 at `/opt/framework/lib/mit-krb5/` on macOS (per ADR-049) for framework-application Kerberos operations is forced by the need to provide a non-stale Kerberos implementation for framework applications that do not require PSSO integration (e.g. service-side Kerberos for framework-hosted SMB shares, keytab management for framework service principals). The framework's MIT Kerberos installation does not replace system Heimdal; it coexists with it, with the `framework-kerberos-sync` daemon synchronizing PSSO-acquired tickets to the framework's MIT cache.

The decision to log a warning when the system Heimdal version is older than the framework's required minimum is forced by operational visibility. Operations teams need to know which Macs have stale Heimdal versions (which may have unpatched CVEs); the warning at enrollment and in the log provides this visibility. The framework's required minimum tracks upstream Heimdal releases; if Apple's system Heimdal is older, the warning documents the gap without preventing framework operation (the framework's unified PAC validator closes the PAC-related gaps).

## Consequences

**Positive**. The framework's macOS Kerberos story is consistent with the framework's PSSO-first macOS strategy (per ADR-048). The framework's unified PAC validator closes the system Heimdal fork's PAC-related gaps (`PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, compound identity) without requiring Apple to update system Heimdal. The framework's documentation makes the macOS Kerberos limitations explicit, enabling operations teams to make informed decisions about macOS deployment in Server 2016+ forests. The framework's `kinit --version` diagnostic at enrollment provides operational visibility into Macs with stale Heimdal versions.

**Negative**. The framework's macOS client has a dual-Kerberos installation (system Heimdal for PSSO + framework MIT at `/opt/framework/` for framework applications), adding operational complexity. The framework's `framework-kerberos-sync` daemon is a potential failure mode (if the daemon stops, framework applications lose access to PSSO-acquired tickets). The framework's documentation must be maintained as Apple updates system Heimdal (which happens rarely; the fork has not tracked upstream since ~2014). The framework's unified PAC validator is a new shared library that must be maintained and patched as MS-KILE evolves.

**Neutral**. The framework's PSSO-first macOS strategy is invisible to end users (they see PSSO, not the underlying Kerberos implementation). The framework's unified PAC validator is invisible to end users (they see access-control decisions, not the validator's internals).

**Implementation cost**. Medium. Estimated 6-8 engineer-weeks for: the macOS Kerberos limitations documentation, the `kinit --version` diagnostic, the warning logic, the PAC validation parity tests (with `PAC_FULL_CHECKSUM` present and absent), the compound identity test, and the documentation. The unified PAC validator itself is a shared component with ADR-049; the marginal cost for this ADR is the macOS-specific integration and tests.

**Operational impact**. Operations teams gain visibility into macOS Heimdal version staleness via the enrollment-time warning and the `/var/log/framework-macos-kerberos.log` log. Operations teams gain a unified PAC validation behavior across macOS, Linux, and Windows (verifiable via the parity test). Operations teams gain documentation of the macOS-specific limitations (which may affect deployment decisions in Server 2016+ forests). The framework's runbook must include a "macOS Kerberos troubleshooting" section explaining the system Heimdal fork, the unified PAC validator, the `framework-kerberos-sync` daemon, and the `kinit --version` diagnostic.

## Alternatives Considered

**Alternative 1: Replace system Heimdal on macOS with a framework-built Heimdal (or MIT krb5) that tracks upstream.** The framework ships a framework-built Heimdal at `/usr/local/framework/lib/libkerberos.dylib` and configures the OS to use it instead of the system Heimdal at `/usr/lib/libkerberos.dylib`. **Rejection rationale**: This breaks PSSO Extension (per ADR-048), which uses `Kerberos.framework` wrapping the system Heimdal. Replacing system Heimdal would require either modifying the system Kerberos framework (which Apple does not support) or shipping a parallel Kerberos framework that PSSO must be configured to use (which is not configurable — PSSO uses the system framework unconditionally). The framework cannot justify sacrificing PSSO for Kerberos implementation freshness.

**Alternative 2: Contribute Apple's Heimdal fork upstream to mainline Heimdal, reducing divergence over time.** The framework engages with the Heimdal maintainer community to upstream Apple's ~2014-era fork, reducing the divergence between macOS system Heimdal and mainline Heimdal. **Rejection rationale**: This requires Apple's cooperation (which has not been forthcoming — Apple has shown limited interest in upstreaming its Heimdal fork since 2014) and ongoing maintenance effort (the framework would have to track mainline Heimdal releases and re-base Apple's fork on each release, which is a multi-year engagement with uncertain outcome). The framework's unified PAC validator closes the PAC-related gaps without requiring upstreaming; the remaining gap (less-critical CVE patches) is Apple's responsibility.

**Alternative 3: Document macOS as limited (PAC validation accepts tickets that other platforms reject) and require Server 2012 R2 functional level for macOS-supportable forests.** The framework does not ship a unified PAC validator on macOS; instead, the framework's documentation requires macOS customers to deploy against Server 2012 R2 functional level forests (which do not enforce `PAC_FULL_CHECKSUM`), avoiding the macOS Heimdal fork's gap. **Rejection rationale**: This offloads the framework's cross-platform parity commitment to the customer's AD forest functional level. Customers with Server 2016+ forests (the modern default for new forests) would be unable to deploy the framework on macOS without downgrading their forest functional level, which is operationally infeasible. The framework's unified PAC validator closes the gap without requiring customer-side forest functional level changes.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-3 question (per the triage methodology in [TRIAGE.md](./TRIAGE.md)) is whether to engage with Apple to upstream its Heimdal fork; this is documented as Tier-3 and does not affect the framework's v1 macOS Kerberos strategy.

## Cross-capability impact

- **Client SDK** ([PC-086](../catalog/08-client-sdk.md)): PSSO Extension uses system Heimdal; the framework's macOS client integrates with PSSO (per ADR-048).
- **Client SDK** ([PC-090](../catalog/08-client-sdk.md)): The Heimdal vs MIT Kerberos decision (per ADR-049) standardizes on MIT for framework applications on macOS, with system Heimdal retained for PSSO.
- **KDC** ([PC-023](../catalog/02-kdc.md)): The KDC must produce `PAC_FULL_CHECKSUM`-bearing tickets for Server 2016+ interop; the macOS client's unified PAC validator validates them.
- **KDC** ([PC-030](../catalog/02-kdc.md)): HSM-bound krbtgt with auto-rotation (per ADR-015) is the framework's KDC strategy; the macOS client validates tickets issued by this KDC via the unified PAC validator.

## References

- [PC-105](../catalog/09-cross-platform-parity.md) — problem statement
- [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) — PSSO Extension's use of system Heimdal, `API:Initialdefaultcache` cache type
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — RFC 4120 ASN.1 message structures, MS-KILE profile extensions including `PAC_FULL_CHECKSUM` and `PAC_REQUESTER`
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) — Kerberos Protocol Extensions (`PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, compound identity)
- [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac) — Privilege Attribute Certificate Data Structure
- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) — The Kerberos Network Authentication Service (V5)
- [Heimdal Project](https://www.h5l.org/) — Heimdal Kerberos upstream (Apple's fork tracks ~2014)
