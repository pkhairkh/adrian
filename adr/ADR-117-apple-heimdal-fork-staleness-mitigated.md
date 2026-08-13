---
title: "ADR-117: Apple Heimdal Fork Staleness Mitigated by Fresh Rust KDC + Unified PAC Validator"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-102
severity: medium
unblocked_by: [workshop-decision-05, workshop-decision-11]
tags: [adr, cross-platform-parity, macos, heimdal, kerberos, pac, fresh-kdc, rust, ms-kile]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-056-psso-modern-macos-kerberos-path.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ./ADR-108-sspi-equivalent-auth-abstraction.md
  - ../catalog/09-cross-platform-parity.md
  - ../workshop/decision-05-kdc-implementation.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/08-macos-equivalents/05-kerberos-sso-extension.md
last_updated: 2026-08-14
---

# ADR-117: Apple Heimdal Fork Staleness Mitigated by Fresh Rust KDC + Unified PAC Validator

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 5](../workshop/decision-05-kdc-implementation.md) (fresh Rust KDC with `PAC_FULL_CHECKSUM` / `PAC_REQUESTER` / compound identity support) and [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK with platform-specific bindings). Resolves the medium-severity problem [PC-102](../catalog/09-cross-platform-parity.md) (Apple Heimdal fork stale, tracking upstream ~2014 — and the related catalog PC-105). Locks the framework's posture toward macOS system Heimdal: do not replace it (would break PSSO), do not upstream it (Apple has shown limited interest), mitigate via the framework's fresh Rust KDC (which produces PACs that the framework's unified PAC validator validates correctly on every platform).

## Context

Apple ships Heimdal Kerberos at `/usr/lib/libkerberos.dylib` and `/usr/lib/libheimdal-asn1.dylib`, exposed via `/usr/bin/kinit`, `/usr/bin/klist`, `/usr/bin/kdestroy`, `/usr/bin/kpasswd`. The fork has not tracked upstream Heimdal since approximately 2014. Missing features vs upstream Heimdal and vs MIT krb5: (a) `PAC_FULL_CHECKSUM` (introduced Server 2016, MS-KILE §2.2) — a full-ticket signature over the entire PAC, separate from the per-buffer signatures, that defends against PAC tampering; macOS Heimdal fork does not validate `PAC_FULL_CHECKSUM` and will accept tickets that MIT krb5 1.16+ and Heimdal 7.5+ reject; (b) claims-based Kerberos (compound identity, MS-KILE `compound identity` for constrained delegation across forest trusts) — macOS Heimdal fork does not produce or consume compound identity PACs; (c) `PAC_REQUESTER` (Server 2016+) — a PAC buffer identifying the requesting client principal in TGS-REQ, used for KDC audit logging; macOS Heimdal fork ignores this buffer; (d) recent Kerberos CVE patches — Apple backports critical CVEs (e.g. CVE-2020-17049 Kerberos Bronze Bit) but less-critical CVEs (e.g. CVE-2024-26458, CVE-2024-26461) may not be backported, per [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md), and the catalog PC-105.

Apple recommends PSSO Extension for new deployments, which uses the system Heimdal under the hood (so the fork status affects PSSO too). Apple also ships an MIT-compatible shim at `/usr/lib/libMITKerberosShim.dylib` that redirects MIT-style GSSAPI calls to Heimdal. The shim does not add the missing features (`PAC_FULL_CHECKSUM`, etc.) — it just maps API calls. So Homebrew MIT krb5 packages on macOS are also affected by the underlying Heimdal fork's limitations when they call into the system Kerberos via the shim.

Per [PC-102](../catalog/09-cross-platform-parity.md) (and catalog PC-105), in AD deployments that enable `PAC_FULL_CHECKSUM` enforcement (Server 2016+ default for new forests, but not retroactive on upgraded forests), macOS clients may accept tickets that should be rejected, creating a security gap. In AD deployments that use compound identity for constrained delegation (rare, requires forest functional level 2016+), macOS clients cannot participate. For typical AD deployments (Server 2012 R2 functional level, no `PAC_FULL_CHECKSUM` enforcement), macOS clients work fine.

[ADR-049](./ADR-049-standardize-mit-krb5.md) established the unified PAC validator (`libframework_pac_validator.dylib` on macOS) that closes the PAC-related gaps without replacing system Heimdal. [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) documented PSSO as the modern macOS Kerberos path. Workshop Decision 5 ([workshop/decision-05-kdc-implementation.md](../workshop/decision-05-kdc-implementation.md)) resolved the gating ORQs ORQ-042/043/044 in favor of a fresh Rust KDC that produces `PAC_FULL_CHECKSUM`-bearing tickets (per Decision 5 §3 PAC builder), `PAC_REQUESTER` (per Decision 5 §3), and compound identity PACs (per Decision 5 §3 and §mskile subdir). Workshop Decision 11 ([workshop/decision-11-client-sdk.md](../workshop/decision-11-client-sdk.md)) §7 specifies the macOS integration uses the system Heimdal for PSSO Extension compatibility. This ADR locks the end-to-end posture: the framework's fresh Rust KDC produces modern PACs; the framework's unified PAC validator validates them correctly on every platform (including macOS with its stale Heimdal fork); the framework's macOS client uses PSSO Extension for ticket acquisition (system Heimdal) and the unified PAC validator for PAC validation.

## Decision

The framework's posture toward the macOS system Heimdal fork is: **do not replace it** (would break PSSO Extension per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)), **do not upstream it** (Apple has shown limited interest since 2014), **mitigate via the framework's fresh Rust KDC + unified PAC validator**. The framework's fresh Rust KDC (per Decision 5) produces modern PACs (`PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, compound identity, `PAC_BUFFER_TICKET_CHECKSUM`); the framework's unified PAC validator (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) validates these PACs correctly on every platform (Linux via MIT krb5, macOS via the framework's `libframework_pac_validator.dylib`, Windows via MS-KILE in `kdcsvc.dll`). The macOS system Heimdal fork's missing PAC features are closed by the unified PAC validator, which bypasses the system Heimdal's stale PAC parser.

**Concrete specification**:

- **Fresh Rust KDC PAC builder** (per Decision 5 §3). The framework's KDC (`crates/adrian-kdc`, ~30K lines of Rust at v1) emits MS-KILE-conformant PACs with the following buffers per MS-PAC §2.2 and MS-KILE §2.2:
  - `PAC_LOGON_INFO` (KERB_VALIDATION_INFO) — the user's logon info (user SID, group SIDs, primary group SID, logon time, logoff time, kick-off time, password last set, password may change, password must change, user account control, user flags, user name, logon domain name, logon domain SID, extra SIDs, resource group domain SID, resource group IDs).
  - `PAC_CREDENTIAL_TYPE` — the user's encrypted credentials (NT hash, AES Kerberos keys, optional DPAPI master key).
  - `PAC_SERVER_CHECKSUM` — HMAC-MD5 signature over the PAC data using the server's key (per RFC 4120 §5.3).
  - `PAC_PRIVSVR_CHECKSUM` — HMAC-MD5 signature over `PAC_SERVER_CHECKSUM` using the KDC's krbtgt key (per RFC 4120 §5.3); the krbtgt key is HSM-bound per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md).
  - `PAC_CLIENT_INFO_TYPE` — the client's name and logon time.
  - `PAC_REQUESTER` (Server 2016+) — the requesting client principal in TGS-REQ (for KDC audit logging per [ADR-023](./ADR-023-kerberos-audit-events.md)).
  - `PAC_FULL_CHECKSUM` (Server 2016+) — a full-ticket signature over the entire PAC, computed as HMAC-MD5 over all PAC buffers except `PAC_FULL_CHECKSUM` itself, using the KDC's krbtgt key; the `PAC_FULL_CHECKSUM` defends against PAC tampering (an attacker who modifies a buffer would need to recompute both `PAC_SERVER_CHECKSUM` and `PAC_FULL_CHECKSUM`, which requires the krbtgt key).
  - `PAC_BUFFER_TICKET_CHECKSUM` (Server 2012+) — a signature over the ticket itself (silver-ticket mitigation per [PC-119](../catalog/02-kdc.md)), computed as HMAC-MD5 over the ticket's encrypted payload using the KDC's krbtgt key.
  - Compound identity PAC (for forest-trust constrained delegation, per MS-KILE §2.2) — claims-based Kerberos with compound identity for S4U2Self across forest trusts.

- **Fresh Rust KDC PAC issuance requirements**:
  - The KDC SHALL produce PACs byte-identical to Windows Server 2022+ for the same principal at the same replication point-in-time (per Decision 5 §Concrete specification). Byte-identity is validated by an interop test capturing Windows-issued and framework-issued PACs for the same principal and comparing them field-by-field.
  - The KDC SHALL include `PAC_FULL_CHECKSUM` in every PAC by default (Server 2016+ behavior); for forests that do not require `PAC_FULL_CHECKSUM` enforcement (Server 2012 R2 functional level), the KDC MAY optionally omit `PAC_FULL_CHECKSUM` for backward compat, controlled by the `pac_full_checksum_mode` setting (`"required"` / `"supported"` / `"audit"` / `"disabled"`, default `"required"` for new forests, `"supported"` for migrated forests).
  - The KDC SHALL include `PAC_REQUESTER` in every TGS-REQ's PAC (Server 2016+ behavior); the `PAC_REQUESTER` value is the requesting client principal's SID and name, used for KDC audit logging per [ADR-023](./ADR-023-kerberos-audit-events.md).
  - The KDC SHALL include `PAC_BUFFER_TICKET_CHECKSUM` in every TGS-REP's PAC (Server 2012+ behavior); the `PAC_BUFFER_TICKET_CHECKSUM` value is the HMAC-MD5 over the ticket's encrypted payload, defending against silver-ticket attacks per [PC-119](../catalog/02-kdc.md).
  - The KDC SHALL include compound identity PACs for S4U2Self flows across forest trusts (per MS-KILE §2.2); compound identity is the mechanism for constrained delegation across forest trusts.

- **Unified PAC validator** (per [ADR-049](./ADR-049-standardize-mit-krb5.md) §Decision §PAC validator). The framework's `libframework_pac_validator.{so,dylib,dll}` (shared Rust library) implements:
  - PAC buffer parsing (`PAC_INFO_BUFFER` array walk per MS-KILE §2.2) — handles all PAC buffer types including `PAC_LOGON_INFO`, `PAC_CREDENTIAL_TYPE`, `PAC_SERVER_CHECKSUM`, `PAC_PRIVSVR_CHECKSUM`, `PAC_CLIENT_INFO_TYPE`, `PAC_REQUESTER`, `PAC_FULL_CHECKSUM`, `PAC_BUFFER_TICKET_CHECKSUM`, compound identity.
  - `PAC_FULL_CHECKSUM` validation (Server 2016+) — verifies the full-ticket signature over the entire PAC, separate from the per-buffer signatures; the validation recomputes the HMAC-MD5 over all PAC buffers except `PAC_FULL_CHECKSUM` using the KDC's krbtgt key and compares to the `PAC_FULL_CHECKSUM` value. If the krbtgt key is HSM-bound (per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)), the HMAC-MD5 computation goes through the HSM (via the `cryptoki` Rust crate).
  - `PAC_REQUESTER` extraction (Server 2016+) — extracts the requesting client principal's SID and name from the `PAC_REQUESTER` buffer, used for the framework's audit logging per [ADR-023](./ADR-023-kerberos-audit-events.md).
  - Compound identity PAC handling — parses compound identity PACs for forest-trust constrained delegation, extracting the claims and compound identity assertions.
  - Signature verification — verifies `PAC_SERVER_CHECKSUM` (using the server's key), `PAC_PRIVSVR_CHECKSUM` (using the KDC's krbtgt key), `PAC_FULL_CHECKSUM` (using the KDC's krbtgt key), and `PAC_BUFFER_TICKET_CHECKSUM` (using the KDC's krbtgt key).
  - The library MUST be used by every framework Kerberos consumer (Linux SSSD-side PAC check, macOS framework-application PAC check via the SDK's `AuthModule` per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md), Windows framework-application PAC check, framework KDC PAC issuance per Decision 5).

- **macOS system Heimdal fork limitations are documented and closed by the unified PAC validator**:
  - The macOS system Heimdal fork's missing `PAC_FULL_CHECKSUM` validation is closed by the unified PAC validator (the framework's macOS client uses the unified PAC validator for PAC validation, not the system Heimdal's stale parser).
  - The macOS system Heimdal fork's missing `PAC_REQUESTER` support is closed by the unified PAC validator (the framework's macOS client extracts `PAC_REQUESTER` via the unified PAC validator, not the system Heimdal).
  - The macOS system Heimdal fork's missing compound identity support is closed by the unified PAC validator (the framework's macOS client parses compound identity PACs via the unified PAC validator, not the system Heimdal).
  - The macOS system Heimdal fork's missing recent CVE patches (CVE-2024-26458, CVE-2024-26461) are NOT closed by the unified PAC validator (these CVEs affect the Kerberos protocol implementation, not PAC validation). The framework's documentation explicitly states that CVE patches are Apple's responsibility; the framework's macOS posture recommends PSSO Extension (which uses system Heimdal for ticket acquisition, inheriting any unpatched CVEs in the ticket acquisition path) and the framework's unified PAC validator (for PAC validation, closing the PAC-related gaps). The framework's audit logging records the system Heimdal version at enrollment time (via `kinit --version` output) for operational visibility.

- **The framework does NOT replace the macOS system Heimdal.** Per [ADR-049](./ADR-049-standardize-mit-krb5.md) and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md), the framework's macOS client uses the system Heimdal for ticket acquisition (via PSSO Extension) and uses the framework's MIT krb5 at `/opt/adrian/lib/mit-krb5/` for framework-application Kerberos operations that do not conflict with PSSO. The framework does NOT replace `/usr/lib/libkerberos.dylib` (which would break PSSO Extension). The framework's `adrian-kerberos-sync` daemon (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) synchronizes PSSO-acquired tickets to the framework's MIT cache.

- **The framework does NOT upstream Apple's Heimdal fork to mainline Heimdal.** Per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) §Alternatives Considered Alternative 2, the upstreaming effort would require multi-year engagement with the Heimdal maintainer community (which has limited capacity) and Apple's cooperation (which has not been forthcoming). The framework's unified PAC validator closes the PAC-related gaps without requiring upstreaming; the remaining gap (less-critical CVE patches) is Apple's responsibility.

- **Rust crates**:
  - `adrian-kdc` (workspace member, binary) — the fresh Rust KDC (per Decision 5). Crates: `rasn = "0.10"` (ASN.1 parsing), `rasn-kerberos = "0.10"` (RFC 4120 Kerberos types), `ring = "0.17"` (HMAC-MD5 for PAC signatures), `aes = "0.8"` (AES Kerberos key derivation), `sha1 = "0.10"` (SHA-1 for legacy Kerberos etypes), `sha2 = "0.10"` (SHA-256 for etype 0x13), `pbkdf2 = "0.12"` (PBKDF2 for Kerberos key derivation), `md4 = "0.1"` (MD4 for NT hash), `cryptoki = "0.6"` (PKCS#11 for HSM binding per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)), `tokio = "1"`, `tokio-uring = "0.4"`, `ldap3 = "0.11"`, `tracing = "0.1"`, `opentelemetry = "0.22"`, `hickory-server = "0.24"` (per Decision 5 §Rust implementation implications).
  - `adrian-pac-validator` (workspace member, `cdylib` + `staticlib`) — the unified PAC validator. Crates: `rasn = "0.10"` (ASN.1 parsing for PAC buffers), `ring = "0.17"` (HMAC-MD5 for signature verification), `md4 = "0.1"` (for `PAC_CREDENTIAL_TYPE` NT hash decryption), `cryptoki = "0.6"` (for HSM-bound krbtgt key access), `thiserror = "1"`, `tracing = "0.1"`. ~3K lines of Rust.
  - `adrian-sdk` (workspace member, library) — the framework's Client SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)). Uses `adrian-pac-validator` for PAC validation in the `AuthModule` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)).

- **Audit logging** (per [ADR-023](./ADR-023-kerberos-audit-events.md) and [ADR-060](./ADR-060-structured-audit-logs-otel.md)):
  - Every PAC issuance by the framework's KDC emits an OpenTelemetry log event with `event_type = "kdc_pac_issuance"`, `principal`, `pac_buffers` (array: `LOGON_INFO`, `CREDENTIAL_TYPE`, `SERVER_CHECKSUM`, `PRIVSVR_CHECKSUM`, `CLIENT_INFO`, `REQUESTER`, `FULL_CHECKSUM`, `BUFFER_TICKET_CHECKSUM`, `COMPOUND_IDENTITY`), `pac_full_checksum_mode`, `kvno`, `result`, `kdc_instance_id`.
  - Every PAC validation by the framework's unified PAC validator emits an OpenTelemetry log event with `event_type = "pac_validation"`, `principal`, `server_spn`, `pac_buffers_present` (same array), `pac_full_checksum_validated`, `pac_requester_extracted`, `compound_identity_parsed`, `result` (`valid`/`invalid_full_checksum`/`invalid_server_checksum`/`invalid_privsvr_checksum`/`invalid_buffer_ticket_checksum`/`unknown_buffer_type`), `platform`, `validator_version`.

## Rationale

The choice to mitigate the macOS system Heimdal fork's staleness via the fresh Rust KDC + unified PAC validator (rather than replacing system Heimdal or upstreaming Apple's fork) is forced by three considerations.

First, **replacing system Heimdal would break PSSO Extension** (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) §Alternatives Considered Alternative 1). PSSO uses `Kerberos.framework` which wraps system Heimdal at `/usr/lib/libkerberos.dylib`; replacing system Heimdal would require either modifying the system Kerberos framework (which Apple does not support) or shipping a parallel Kerberos framework that PSSO must be configured to use (which is not configurable — PSSO uses the system framework unconditionally). The framework's PSSO-first macOS strategy (per [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md) and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)) requires preserving system Heimdal for PSSO ticket acquisition.

Second, **upstreaming Apple's Heimdal fork is not viable** (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) §Alternatives Considered Alternative 2). Apple's Heimdal fork has not tracked upstream since ~2014; the upstreaming effort would require Apple's cooperation (which has not been forthcoming — Apple has shown limited interest in upstreaming its Heimdal fork since 2014) and ongoing maintenance effort (the framework would have to track mainline Heimdal releases and re-base Apple's fork on each release, which is a multi-year engagement with uncertain outcome). The framework's unified PAC validator closes the PAC-related gaps without requiring upstreaming.

Third, **the fresh Rust KDC + unified PAC validator closes all PAC-related gaps** (per [ADR-049](./ADR-049-standardize-mit-krb5.md) §Rationale §PAC validator and Decision 5 §3 PAC builder). The framework's KDC produces `PAC_FULL_CHECKSUM`-bearing tickets (closing the macOS Heimdal fork's missing `PAC_FULL_CHECKSUM` validation — the framework's macOS client validates `PAC_FULL_CHECKSUM` via the unified PAC validator, not the system Heimdal). The framework's KDC produces `PAC_REQUESTER`-bearing tickets (closing the macOS Heimdal fork's missing `PAC_REQUESTER` support). The framework's KDC produces compound identity PACs (closing the macOS Heimdal fork's missing compound identity support). The unified PAC validator is a shared Rust library used by every framework Kerberos consumer on every platform, ensuring byte-identical PAC validation results.

The choice to implement the framework's KDC in fresh Rust (per Decision 5 §Decision §Fresh Rust KDC) is forced by the framework's memory-safety commitment (MIT krb5 has had 60+ CVEs since 2014, ~30 of which are memory-safety bugs; Heimdal's CVE history is similar; a Rust KDC eliminates this CWE class in the KDC code path — the most-security-critical capability in the framework). The fresh Rust KDC's PAC builder is a fresh ~3K-line implementation in a memory-safe language with a property-based test harness (bijectivity against Windows-issued PACs), reducing the defect surface compared to MIT's or Heimdal's C implementations.

The choice to make the unified PAC validator a shared Rust library (rather than embedding PAC validation in each Kerberos consumer) is forced by the cross-platform correctness requirement. The framework's PAC validator must produce identical results on every platform; this cannot be achieved by relying on each Kerberos implementation's bundled parser (MIT and Heimdal have different PAC_INFO_BUFFER walk ordering, different `PAC_FULL_CHECKSUM` validation logic, different compound identity handling). A shared Rust library gives the framework one well-tested PAC parser used by every platform, eliminating the cross-platform divergence.

## Consequences

**Positive**. The framework's macOS Kerberos story is consistent with the framework's PSSO-first macOS strategy (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)). The framework's unified PAC validator closes the macOS system Heimdal fork's PAC-related gaps (`PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, compound identity) without requiring Apple to update system Heimdal. The framework's fresh Rust KDC produces modern PACs with all the Server 2016+ buffers, ensuring that the framework's macOS, Linux, and Windows clients all receive the same modern PACs. The framework's documentation makes the macOS Kerberos limitations explicit, enabling operations teams to make informed decisions about macOS deployment in Server 2016+ forests. The framework's `kinit --version` diagnostic at enrollment provides operational visibility into Macs with stale Heimdal versions.

**Negative**. The framework's macOS client has a dual-Kerberos installation (system Heimdal for PSSO + framework MIT at `/opt/adrian/lib/mit-krb5/` for framework applications), adding operational complexity. The framework's `adrian-kerberos-sync` daemon is a potential failure mode (if the daemon stops, framework applications lose access to PSSO-acquired tickets). The framework's documentation must be maintained as Apple updates system Heimdal (which happens rarely; the fork has not tracked upstream since ~2014). The framework's unified PAC validator is a new shared library that must be maintained and patched as MS-KILE evolves (e.g. future PAC buffer types added by Microsoft). The framework's macOS CVE patch gap (less-critical CVEs not backported by Apple) is documented but not closed — customers in highly-regulated environments may need to consider this when deploying macOS.

**Neutral**. The framework's PSSO-first macOS strategy is invisible to end users (they see PSSO, not the underlying Kerberos implementation). The framework's unified PAC validator is invisible to end users (they see access-control decisions, not the validator's internals). The framework's fresh Rust KDC is invisible to end users (they see Kerberos authentication, not the KDC's implementation language).

**Implementation cost**. The fresh Rust KDC is the largest single implementation item (~42 person-weeks for v1, per Decision 5 §Implementation impact). The unified PAC validator is ~6-8 person-weeks (per [ADR-049](./ADR-049-standardize-mit-krb5.md) §Consequences). The macOS-specific integration (PSSO Extension + `adrian-kerberos-sync` daemon + unified PAC validator integration) is ~6-8 person-weeks (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) §Consequences). The marginal cost for this ADR (beyond Decision 5, [ADR-049](./ADR-049-standardize-mit-krb5.md), and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)) is ~2 person-weeks for the macOS-specific PAC validation parity tests and the documentation of the macOS CVE patch gap.

**Operational impact**. Operations teams gain visibility into macOS Heimdal version staleness via the enrollment-time warning and the `/var/log/adrian-macos-kerberos.log` log (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)). Operations teams gain a unified PAC validation behavior across macOS, Linux, and Windows (verifiable via the parity test). Operations teams gain documentation of the macOS-specific limitations (which may affect deployment decisions in Server 2016+ forests). The framework's runbook includes a "macOS Kerberos troubleshooting" section explaining the system Heimdal fork, the unified PAC validator, the `adrian-kerberos-sync` daemon, and the `kinit --version` diagnostic.

## Alternatives Considered

**Alternative 1: Replace system Heimdal on macOS with a framework-built Heimdal (or MIT krb5) that tracks upstream.** The framework ships a framework-built Heimdal at `/usr/local/adrian/lib/libkerberos.dylib` and configures the OS to use it instead of the system Heimdal at `/usr/lib/libkerberos.dylib`. **Rejection rationale**: This breaks PSSO Extension (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) §Alternatives Considered Alternative 1), which uses `Kerberos.framework` wrapping the system Heimdal. Replacing system Heimdal would require either modifying the system Kerberos framework (which Apple does not support) or shipping a parallel Kerberos framework that PSSO must be configured to use (which is not configurable — PSSO uses the system framework unconditionally). The framework cannot justify sacrificing PSSO for Kerberos implementation freshness.

**Alternative 2: Contribute Apple's Heimdal fork upstream to mainline Heimdal, reducing divergence over time.** The framework engages with the Heimdal maintainer community to upstream Apple's ~2014-era fork, reducing the divergence between macOS system Heimdal and mainline Heimdal. **Rejection rationale**: This requires Apple's cooperation (which has not been forthcoming — Apple has shown limited interest in upstreaming its Heimdal fork since 2014) and ongoing maintenance effort (the framework would have to track mainline Heimdal releases and re-base Apple's fork on each release, which is a multi-year engagement with uncertain outcome). The framework's unified PAC validator closes the PAC-related gaps without requiring upstreaming; the remaining gap (less-critical CVE patches) is Apple's responsibility.

**Alternative 3: Use MIT krb5 on macOS for all Kerberos operations (replacing system Heimdal for PSSO too).** The framework's macOS client installs MIT krb5 at `/opt/adrian/lib/mit-krb5/` and configures PSSO to use the framework's MIT krb5 instead of the system Heimdal. **Rejection rationale**: PSSO Extension uses `Kerberos.framework` which wraps the system Heimdal at `/usr/lib/libkerberos.dylib`; PSSO cannot be configured to use a different Kerberos implementation. The framework cannot replace system Heimdal for PSSO without breaking PSSO Extension. The framework's macOS strategy (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)) is PSSO Extension + system Heimdal for ticket acquisition; framework MIT krb5 at `/opt/adrian/lib/mit-krb5/` is for framework-application Kerberos operations that do not conflict with PSSO.

## Open Questions

None. The decision is fully specified by Decision 5 §3 (PAC builder), Decision 11 §7 (macOS system Heimdal for PSSO), [ADR-049](./ADR-049-standardize-mit-krb5.md) (unified PAC validator), and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) (PSSO modern macOS Kerberos path). The deferred Tier-3 question (per the triage methodology in [TRIAGE.md](./TRIAGE.md)) is whether to engage with Apple to upstream its Heimdal fork; this is documented as Tier-3 and does not affect the framework's v1 macOS Kerberos strategy.

## Cross-capability impact

- **KDC** ([PC-023](../catalog/02-kdc.md)): The framework's fresh Rust KDC (per Decision 5) produces `PAC_FULL_CHECKSUM`-bearing tickets for Server 2016+ interop; the macOS client's unified PAC validator validates them.
- **KDC** ([PC-030](../catalog/02-kdc.md)): HSM-bound krbtgt with auto-rotation (per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)) is the framework's KDC strategy; the macOS client validates tickets issued by this KDC via the unified PAC validator.
- **Client SDK** ([PC-086](../catalog/08-client-sdk.md)): PSSO Extension uses system Heimdal; the framework's macOS client integrates with PSSO (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)).
- **Client SDK** ([PC-090](../catalog/08-client-sdk.md)): The Heimdal vs MIT Kerberos decision (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) standardizes on MIT for framework applications on macOS, with system Heimdal retained for PSSO.
- **Security** ([PC-119](../catalog/11-security-threat-model.md)): The framework's `PAC_BUFFER_TICKET_CHECKSUM` (Server 2012+) is a silver-ticket mitigation (per PC-119); the unified PAC validator validates `PAC_BUFFER_TICKET_CHECKSUM` on every platform.

## References

- [PC-102](../catalog/09-cross-platform-parity.md) — problem statement (Apple Heimdal fork stale, tracking upstream ~2014)
- [PC-105](../catalog/09-cross-platform-parity.md) — Heimdal Kerberos on macOS is a fork tracking upstream ~2014
- [Workshop Decision 5 — KDC Implementation](../workshop/decision-05-kdc-implementation.md) — fresh Rust KDC with modern PAC builder
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings (macOS system Heimdal for PSSO)
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — RFC 4120 ASN.1 message structures, MS-KILE profile extensions including `PAC_FULL_CHECKSUM` and `PAC_REQUESTER`
- [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) — PSSO Extension's use of system Heimdal, `API:Initialdefaultcache` cache type
- [ADR-015](./ADR-015-krbtgt-hsm-rotation.md) — krbtgt HSM rotation (HSM-bound krbtgt key for PAC signatures)
- [ADR-023](./ADR-023-kerberos-audit-events.md) — Kerberos audit events (PAC issuance and validation events)
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization + unified PAC validator
- [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) — PSSO modern macOS Kerberos path
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs (PAC validation events)
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) — SSPI-equivalent auth abstraction (PAC extraction via unified PAC validator)
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) — Kerberos Protocol Extensions (`PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, compound identity)
- [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac) — Privilege Attribute Certificate Data Structure
- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) — The Kerberos Network Authentication Service (V5)
- [Heimdal Project](https://www.h5l.org/) — Heimdal Kerberos upstream (Apple's fork tracks ~2014)
- [rasn Rust crate](https://docs.rs/rasn) — ASN.1 parsing (PAC buffer types)
- [ring Rust crate](https://docs.rs/ring) — HMAC-MD5 for PAC signature verification
- [cryptoki Rust crate](https://docs.rs/cryptoki) — PKCS#11 for HSM-bound krbtgt key access
