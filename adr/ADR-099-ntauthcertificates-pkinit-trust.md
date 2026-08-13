---
title: "ADR-099: `NTAuthCertificates` replacement via `LogonAuthorizedCAs` directory attribute + trust-manager (resolves PC-067)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-067
severity: high
unblocked_by: Workshop Decision 8
tags: [adr, cert-service, ntauthcertificates, pkinit, trust-manager, logonauthorizedcas, kdc, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../workshop/decision-08-pki-enrollment.md
  - ../workshop/decision-05-kdc-implementation.md
  - ../docs/05-pki-certs/01-ad-cs-architecture.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ./ADR-036-trust-manager-cross-cert-interop.md
  - ./ADR-037-two-tier-ca-hsm-root.md
  - ./ADR-095-acme-primary-mswcce-bridge.md
last_updated: 2026-08-14
---

# ADR-099: `NTAuthCertificates` replacement via `LogonAuthorizedCAs` directory attribute + trust-manager (resolves PC-067)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §7, which specifies that AD's `NTAuthCertificates` object is replaced by a `LogonAuthorizedCAs` directory attribute on the framework's `TrustedCAContainer` object, distributed to all hosts by the trust-manager (per ADR-036), and validated by the KDC's PKINIT validator (per Decision 5) before accepting a smart-card logon. Also unblocked by [Workshop Decision 5](../workshop/decision-05-kdc-implementation.md) (Fresh Rust KDC), which provides the framework's KDC PKINIT validator that consumes `LogonAuthorizedCAs`. This ADR operationalises Decision 8 §7's specification against the PC-067 problem surface: the canonical-CA-list role of `NTAuthCertificates` in PKINIT smart-card logon and the framework's choice between preserving the `NTAuthCertificates` AD object, replacing it with a per-tenant trust store, or adopting a web-of-trust model.

## Context

AD publishes the `NTAuthCertificates` object at `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<NC>` listing CAs allowed to issue logon certs. Per [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md), PKINIT KDC validates user certs against this list — a smart-card logon cert issued by a CA not in `NTAuthCertificates` is rejected by the KDC with `KDC_ERR_CLIENT_REVOKED` (or `KDC_ERR_C_PRINCIPAL_UNKNOWN`). Publication is via `certutil -dspublish -f <cert.cer> NTAuthCA`, which appends the cert DER to the `cACertificate` attribute (multivalued binary). Per [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), the KDC's PKINIT verification path: client signs a nonce with smart-card private key → KDC verifies signature against user cert → KDC validates cert chain to a root in `NTAuthCertificates` → KDC issues TGT with PAC.

The mirror on the client side is `HKLM\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates` — a registry hive that the Group Policy Public Key Policies / Certificate Path Validation Settings GPO syncs from the AD object. If the client's `NTAuth` registry hive is stale (e.g., GPO not refreshed), smart-card logon fails with `0x800B010A — A certificate chain could not be built to a trusted root authority`. The diagnostic flow is `certutil -viewstore -enterprise NTAuth` (shows the AD-published list) vs. `certutil -viewstore NTAuth` (shows the local registry mirror). macOS has no `NTAuthCertificates`-equivalent — PSSO smart-card trust uses Keychain System Roots + per-app trust policies; PKINIT is via Heimdal on macOS. Linux has no `NTAuthCertificates`-equivalent — PKINIT trust uses `/etc/ssl/certs/` + per-app trust policies; SSSD `p11_child` does the cert validation. The matrix in [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) shows the cross-platform inconsistency: each platform has its own trust-store model with no unified PKINIT-trust mechanism.

For the framework, the equivalent PKI-trust distribution is required for PKINIT smart-card logon. The framework's KDC (per Decision 5) must validate user certs against the framework's `NTAuthCertificates`-equivalent. The choices are: (a) preserving the `NTAuthCertificates` AD object for AD interop, (b) replacing it with a per-tenant trust store (each tenant defines its own trusted CAs), or (c) a web-of-trust model (each application defines its own trust roots).

Workshop Decision 8 §7 specifies the framework's answer: replace `NTAuthCertificates` with a `LogonAuthorizedCAs` directory attribute on the framework's `TrustedCAContainer` object, distributed to all hosts by the trust-manager (per ADR-036), and validated by the KDC's PKINIT validator (per Decision 5). This ADR defines the `LogonAuthorizedCAs` schema, the trust-manager distribution model, the KDC PKINIT validator's contract, the cross-platform client-side trust-store synchronization, and the migration path from AD's `NTAuthCertificates`.

## Decision

The framework replaces AD's `NTAuthCertificates` object with a `LogonAuthorizedCAs` directory attribute on the framework's `TrustedCAContainer` object (at `CN=Trusted CA Container,CN=Public Key Services,CN=Services,CN=Configuration,<NC>`). The trust-manager service (per ADR-036) distributes the listed CA certs to all hosts via the framework's WebSocket push (per ADR-028) with HTTPS pull fallback. The KDC's PKINIT validator (per Decision 5) reads `LogonAuthorizedCAs` to determine which CAs are authorized to issue smart-card logon certs. The framework's Client SDK synchronizes the `LogonAuthorizedCAs` list to each platform's native trust store (CNG on Windows, Keychain on macOS, `/etc/ssl/certs/` + `p11_child` config on Linux).

### Concrete specification

1. **`LogonAuthorizedCAs` directory attribute.** The framework's directory schema defines a `logonAuthorizedCAs` attribute (governsID `1.3.6.1.4.1.<framework-PEN>.<n>`, multivalued binary, syntax `OctetString`) on the `TrustedCAContainer` object class (analogous to AD's `certificationAuthority` object class). Each value is the DER-encoded CA certificate of a CA authorized to issue smart-card logon certs. The attribute is replicated to all framework DCs via the framework's directory replication (DRSUAPI in AD-interop mode, Raft in native mode, per Decision 1). The attribute is writeable only by members of the framework's `PKI-Admins` group (the framework's RBAC model per ADR-066 enforces this).

2. **`TrustedCAContainer` object.** The `TrustedCAContainer` object at `CN=Trusted CA Container,CN=Public Key Services,CN=Services,CN=Configuration,<NC>` holds the `LogonAuthorizedCAs` attribute plus a child `certificationAuthority` object per trusted CA (each child object holds the CA cert's full metadata — subject, issuer, serial, fingerprint, validity, AIA/CDP URLs). The container's structure mirrors AD's `CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,<NC>` for AD-interop (the framework's directory schema includes AD-compatible `certificationAuthority` object classes per the framework's schema model decision — Decision 4). The `LogonAuthorizedCAs` attribute is the authoritative list; the child `certificationAuthority` objects are the metadata source.

3. **`LogonAuthorizedCAs` modification via CLI.** Operators modify the `LogonAuthorizedCAs` list via the `adrian-cli trust add-logon-ca <cert-file>` and `adrian-cli trust remove-logon-ca <cert-thumbprint>` CLI subcommands (part of the framework's unified CLI per ADR-063). The CLI performs an LDAP `MODIFY` operation on the `TrustedCAContainer` object, adding or removing the CA cert's DER from the `logonAuthorizedCAs` attribute. The CLI also creates or removes the child `certificationAuthority` object for the CA (per §2). The modification is atomic (per ADR-025's transactional pattern): the LDAP `MODIFY` and the child-object create/remove are in a single LDAP transaction. The CLI emits an audit event (per ADR-060) recording the modification, the operator's identity, and the CA cert's subject and thumbprint.

4. **Trust-manager distribution.** The trust-manager service (`adrian-trust-manager`, per ADR-036) reads the `LogonAuthorizedCAs` attribute from the framework's directory at startup and on every directory-change notification (per ADR-002's event-driven `memberOf` invalidation, generalized to all directory attributes). The trust-manager pushes the `LogonAuthorizedCAs` list to all enrolled hosts via the framework's WebSocket push (per ADR-028); hosts that are offline during the push receive the list via HTTPS pull fallback on next connection. The trust-manager's push frequency is event-driven (immediate on directory change) plus a periodic refresh (default 1 hour, configurable) for hosts that miss the event-driven push. The trust-manager's push payload is a signed JSON document (signed by the framework's directory-service key) containing the list of CA cert DERs and the directory's replication timestamp; the host's Client SDK verifies the signature before applying the update.

5. **Client-side trust-store synchronization.** The framework's Client SDK (`adrian-client-daemon`, per Decision 11) receives the `LogonAuthorizedCAs` list from the trust-manager and synchronizes it to the host's platform-native trust store:
   - **Windows (CNG)**: The SDK uses `windows = "0.54"` (`CertOpenStore` + `CertAddEncodedCertificateToStore`) to write the CA certs to the `Cert:\LocalMachine\Root` certificate store (the system root store). The SDK also writes the CA certs to `HKLM\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates` (the registry hive that Windows `pkinit.dll` reads for PKINIT trust) — this preserves AD-interop for Windows hosts that still run `pkinit.dll` (per ADR-095 §2's MS-WCCE bridge migration window). The SDK removes CA certs from both stores that are no longer in the `LogonAuthorizedCAs` list.
   - **macOS (Keychain)**: The SDK uses `security-framework = "2"` to write the CA certs to the System Roots keychain (`/Library/Keychains/System.keychain`). The SDK also writes the CA certs to a per-framework keychain (`/Library/Keychains/Adrian.keychain`) that the framework's macOS PKINIT implementation (via Heimdal, per Decision 5) reads for PKINIT trust. The SDK removes CA certs from both keychains that are no longer in the `LogonAuthorizedCAs` list.
   - **Linux (PEM files + `p11_child` config)**: The SDK writes the CA certs as PEM files to `/etc/adrian/trust/logon-cas/` (one file per CA, named by thumbprint). The SDK updates `/etc/adrian/trust/logon-cas.pem` (a concatenated PEM of all CA certs). The framework's Linux PKINIT implementation (via MIT krb5, per Decision 5 and ADR-049) reads `/etc/adrian/trust/logon-cas.pem` as the PKINIT trust anchor (configured via `pkinit_anchors = FILE:/etc/adrian/trust/logon-cas.pem` in `/etc/krb5.conf.d/adrian-pkinit.conf`). SSSD's `p11_child` is configured (via `/etc/sssd/sssd.conf`'s `[p11_child]` section's `certificate_verification` option) to use `/etc/adrian/trust/logon-cas.pem` as the CA list for smart-card logon. The SDK removes PEM files for CAs that are no longer in the `LogonAuthorizedCAs` list.

6. **KDC PKINIT validator.** The framework's KDC (per Decision 5) implements a PKINIT validator in `crates/adrian-kdc/src/pkinit.rs`. The validator reads the `LogonAuthorizedCAs` attribute from the framework's directory at startup and on every directory-change notification (the KDC's principal-store cache invalidation, per Decision 5 §5, is extended to cover `LogonAuthorizedCAs`). The validator's PKINIT verification path (per [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md)):
   - Client signs a nonce with smart-card private key (the PA-PK-AS-REQ pre-authentication, per RFC 4556).
   - KDC verifies the signature against the user cert (extracted from the PA-PK-AS-REQ's `signedAuthPack`).
   - KDC validates the cert chain to a root in `LogonAuthorizedCAs` (the KDC uses `x509-cert = "0.2"` + `rustls = "0.23"` for chain validation; the `LogonAuthorizedCAs` list is the trust anchor).
   - KDC checks the cert's EKU for `smartcard_logon` (OID `1.3.6.1.4.1.311.20.2.2`) and `client_auth` (OID `1.3.6.1.5.5.7.3.2`) — both are required for smart-card logon.
   - KDC checks the cert's validity period (not before ≤ now ≤ not after).
   - KDC checks the cert's revocation status via OCSP (per ADR-033) or CRL (per ADR-035).
   - On success, the KDC issues a TGT with PAC (per Decision 5 §3); on failure, the KDC returns `KDC_ERR_CLIENT_REVOKED` (cert revoked or not in `LogonAuthorizedCAs`), `KDC_ERR_C_PRINCIPAL_UNKNOWN` (cert subject not matching a directory principal), or `KDC_ERR_PREAUTH_FAILED` (signature verification or EKU check failure).

7. **`ntauth_member` profile flag.** Per ADR-096 §1, cert profiles have an `ntauth_member: true|false` flag. When a profile with `ntauth_member: true` is applied (via `adrian-ca profile apply`), the framework's CA automatically adds its issuing CA cert to the `LogonAuthorizedCAs` attribute (via the CLI in §3, invoked programmatically by the CA's profile-application logic). When a profile with `ntauth_member: true` is removed, the framework's CA removes its issuing CA cert from `LogonAuthorizedCAs` (unless another `ntauth_member: true` profile is still using the same issuing CA — the CA tracks per-profile `ntauth_member` usage to avoid removing a CA cert that is still in use). This couples cert-profile changes to PKINIT-trust changes, ensuring that a smart-card logon profile's CA is always in `LogonAuthorizedCAs`.

8. **Migration from AD's `NTAuthCertificates`.** The `adrian-migrate ntauth` CLI reads AD's `NTAuthCertificates` object (via LDAP query of `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<forest-root>`), extracts each CA cert's DER from the `cACertificate` attribute, and adds each CA cert to the framework's `LogonAuthorizedCAs` attribute (via the CLI in §3). The migration is one-way (AD → framework); the framework does not write back to AD's `NTAuthCertificates`. During the migration window, both lists must be kept in sync (the framework's `adrian-cli trust sync-from-ad` CLI runs on a schedule, default hourly, to copy any AD-side `NTAuthCertificates` changes to the framework's `LogonAuthorizedCAs`). Once all AD-enrolled Windows hosts are migrated to the framework's Client SDK, the `sync-from-ad` schedule is disabled.

9. **Cross-realm PKINIT trust.** For cross-realm scenarios (per ADR-013), the framework's KDC's PKINIT validator reads the `LogonAuthorizedCAs` list of the local realm only. A user from a trusted realm presenting a smart-card cert issued by the trusted realm's CA must have that CA in the local realm's `LogonAuthorizedCAs`. The framework's `adrian-cli trust establish --peer <realm>` command (per Decision 12 §3) optionally copies the peer realm's `LogonAuthorizedCAs` to the local realm's `LogonAuthorizedCAs` (with a `cross_realm: true` annotation, so the source is traceable). Operators can also add the peer realm's CA certs manually via `adrian-cli trust add-logon-ca <cert-file>`.

## Rationale

Three alternatives were considered (per Decision 8 §7 and §Rationale).

**Alternative A: Preserve the `NTAuthCertificates` AD object for AD interop.** Maintain an `NTAuthCertificates`-equivalent AD object in the framework's directory (with the same `cACertificate` attribute and `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<NC>` location), readable by AD's `pkinit.dll` and `certutil -dspublish`. Rejected because (a) the framework's directory is not AD (per Decision 1) — preserving the `NTAuthCertificates` AD object requires the framework's directory to maintain AD-schema-compatible attributes at the exact AD location, which couples the framework's schema to AD's schema; (b) the framework's KDC (per Decision 5) is a fresh Rust implementation, not AD's `kdcsvc.dll` — it does not read `NTAuthCertificates` natively; making it read `NTAuthCertificates` would require an AD-compat shim in the KDC; (c) the framework's cross-platform clients (macOS, Linux) do not have an `NTAuthCertificates` concept — preserving the AD object does not help non-Windows clients; (d) the framework's trust-manager (per ADR-036) is the cross-platform trust-distribution mechanism; routing through `NTAuthCertificates` would bypass the trust-manager and create a second distribution path. Decision 8 §7 replaces `NTAuthCertificates` with `LogonAuthorizedCAs` explicitly.

**Alternative B: Per-tenant trust store (each tenant defines its own trusted CAs).** Replace `NTAuthCertificates` with a per-tenant trust store; each tenant (organizational unit, business unit) defines its own list of logon-authorized CAs. Rejected because (a) PKINIT smart-card logon is a forest-wide concern (a user from tenant A logging into a host in tenant B requires tenant B to trust tenant A's CAs); per-tenant trust stores require explicit cross-tenant trust configuration, adding operational complexity; (b) the framework's directory is a single-forest model (per Decision 1) — per-tenant trust stores do not align with the single-forest model; (c) AD's `NTAuthCertificates` is forest-wide (one list per forest); preserving the forest-wide model is simpler than introducing per-tenant trust stores. Decision 8 §7 specifies a forest-wide `LogonAuthorizedCAs` attribute.

**Alternative C: Web-of-trust model (each application defines its own trust roots).** Replace `NTAuthCertificates` with a per-application trust model — each application (browser, RDP, S/MIME, PKINIT) defines its own trust roots. Rejected because (a) PKINIT smart-card logon is a KDC-side validation (the KDC validates the cert, not the application); per-application trust does not apply to KDC-side validation; (b) per-application trust is operationally complex (operators must manage trust roots per application); (c) per-application trust is incompatible with PKINIT centralization (the KDC must have a single, authoritative list of logon-authorized CAs); (d) per-application trust for non-PKINIT applications (browser, RDP, S/MIME) is a separate concern — the framework's trust-manager (per ADR-036) already supports per-application trust stores; the `LogonAuthorizedCAs` attribute is specifically for PKINIT smart-card logon. Decision 8 §7 specifies the `LogonAuthorizedCAs` attribute as the PKINIT-specific trust anchor.

The chosen model — `LogonAuthorizedCAs` directory attribute + trust-manager distribution + KDC PKINIT validator + cross-platform client-side trust-store synchronization — gives the framework: (a) a forest-wide, authoritative PKINIT trust list (matching AD's `NTAuthCertificates` model); (b) cross-platform distribution (the trust-manager pushes to Windows, macOS, and Linux); (c) a fresh-Rust KDC PKINIT validator (per Decision 5) that reads `LogonAuthorizedCAs` natively (no AD-compat shim); (d) a migration path from AD's `NTAuthCertificates` via `adrian-migrate ntauth`.

## Consequences

**Positive**. The framework has a unified, cross-platform PKINIT trust mechanism. The KDC's PKINIT validator reads `LogonAuthorizedCAs` natively (no AD-compat shim). The trust-manager distributes the list to all hosts (Windows, macOS, Linux) automatically. The `ntauth_member` profile flag couples cert-profile changes to PKINIT-trust changes (ensuring consistency). Migration from AD's `NTAuthCertificates` is supported via `adrian-migrate ntauth`.

**Negative**. During the migration window, both `NTAuthCertificates` (AD) and `LogonAuthorizedCAs` (framework) must be kept in sync (via `adrian-cli trust sync-from-ad`). The sync is one-way (AD → framework) and hourly; AD-side changes take up to 1 hour to propagate to the framework. The Windows client-side synchronization writes to both `Cert:\LocalMachine\Root` (the system root store) and `HKLM\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates` (the registry hive) — the dual-write is necessary for AD-interop (Windows `pkinit.dll` reads the registry hive) but adds complexity. macOS and Linux PKINIT trust depends on the framework's Client SDK being installed and running — unenrolled macOS/Linux hosts cannot participate in PKINIT smart-card logon (they fall back to password logon).

**Neutral**. The `LogonAuthorizedCAs` attribute is forest-wide (one list per forest); per-tenant trust is not supported. Operators who need per-tenant PKINIT trust must use cross-realm trust (per §9) with per-realm `LogonAuthorizedCAs` lists.

**Implementation cost**. ~3 person-weeks for v1 (per Decision 8 §Implementation impact, subsumed in the trust-manager line item): `LogonAuthorizedCAs` attribute + `TrustedCAContainer` object (1 pw), trust-manager distribution extension (1 pw, subsumed in ADR-036's effort), KDC PKINIT validator (1 pw, subsumed in Decision 5's effort), migration CLI `adrian-migrate ntauth` (0.5 pw, subsumed in the migration line item). Ongoing maintenance: ~0.5 person-week per year for cross-platform trust-store API evolution.

**Operational impact**. Operators add/remove logon-authorized CAs via `adrian-cli trust add-logon-ca`/`remove-logon-ca`. Operators migrate from AD's `NTAuthCertificates` via `adrian-migrate ntauth` (one-time) and `adrian-cli trust sync-from-ad` (hourly during migration window). The `adrian-cli trust list-logon-cas` CLI lists the current `LogonAuthorizedCAs`; the `adrian-cli trust status --host <name>` CLI shows the host's last-synced `LogonAuthorizedCAs` version.

## Alternatives Considered

### Alternative A: Preserve the `NTAuthCertificates` AD object for AD interop

Maintain an `NTAuthCertificates`-equivalent AD object in the framework's directory, readable by AD's `pkinit.dll` and `certutil -dspublish`.

Rejected as detailed in §Rationale and Decision 8 §7: the framework's directory is not AD; the framework's KDC is a fresh Rust implementation (does not read `NTAuthCertificates` natively); cross-platform clients do not have an `NTAuthCertificates` concept; preserving the AD object bypasses the trust-manager and creates a second distribution path.

### Alternative B: Per-tenant trust store (each tenant defines its own trusted CAs)

Replace `NTAuthCertificates` with a per-tenant trust store; each tenant defines its own list of logon-authorized CAs.

Rejected as detailed in §Rationale and Decision 8 §7: PKINIT smart-card logon is a forest-wide concern (cross-tenant logon requires cross-tenant trust); per-tenant trust stores do not align with the single-forest model; AD's `NTAuthCertificates` is forest-wide; per-tenant trust adds operational complexity.

### Alternative C: Web-of-trust model (each application defines its own trust roots)

Replace `NTAuthCertificates` with a per-application trust model — each application defines its own trust roots.

Rejected as detailed in §Rationale and Decision 8 §7: PKINIT is a KDC-side validation (per-application trust does not apply); per-application trust is operationally complex; per-application trust is incompatible with PKINIT centralization; per-application trust for non-PKINIT applications is a separate concern handled by ADR-036's trust-manager.

## Open Questions

- **`LogonAuthorizedCAs` size limits.** The `logonAuthorizedCAs` attribute is multivalued binary; the framework's directory allows up to ~1 MB per attribute value (configurable). For a deployment with 100 trusted CAs (each ~2 KB DER), the attribute is ~200 KB — well within limits. Revisit if deployments exceed 1,000 trusted CAs (unlikely).
- **PKINIT revocation checking latency.** The KDC's PKINIT validator checks the cert's revocation status via OCSP (per ADR-033) or CRL (per ADR-035) on every smart-card logon. OCSP latency (typically 50-200ms per query) adds to the logon latency. Current decision: the KDC caches OCSP responses for 1 hour (per ADR-033's OCSP caching); the cache hit rate is >99% for typical deployments. Revisit if customers report logon-latency issues.
- **Cross-realm `LogonAuthorizedCAs` sync.** For cross-realm scenarios (per §9), should the framework automatically sync `LogonAuthorizedCAs` between realms with bidirectional trust? Current decision: no automatic sync; operators explicitly add the peer realm's CAs via `adrian-cli trust add-logon-ca` or `adrian-cli trust establish --peer <realm> --sync-logon-cas`. Revisit if customers report cross-realm PKINIT failures due to missing peer CAs.

## Cross-capability impact

- **Cert Service (PC-057 enrollment)**: ADR-095's ACME server issues smart-card logon certs (via the `smartcard_logon` EKU profile per ADR-096); the issuing CA must be in `LogonAuthorizedCAs` for the certs to be accepted by the KDC.
- **Cert Service (PC-058 templates)**: ADR-096's `ntauth_member: true` profile flag triggers automatic `LogonAuthorizedCAs` modification (per §7).
- **KDC (PC-027 PKINIT)**: The KDC's PKINIT validator (per Decision 5 §1) reads `LogonAuthorizedCAs` to determine which CAs are authorized to issue smart-card logon certs.
- **Cross-Platform Parity (PC-099 Linux access-control)**: Linux PKINIT trust via `/etc/adrian/trust/logon-cas.pem` + SSSD `p11_child` config closes the cross-platform PKINIT-trust gap.
- **Federation Gateway (Decision 9)**: The Federation Gateway's token-signing cert is issued by the framework's CA but is not a smart-card logon cert — it does not need to be in `LogonAuthorizedCAs` (the Federation Gateway validates the token-signing cert via its own trust store, not via PKINIT).
- **Migration (PC-127 AD CS-to-framework)**: The `adrian-migrate ntauth` CLI is the migration entry point for AD's `NTAuthCertificates`; the `adrian-cli trust sync-from-ad` CLI keeps the lists in sync during the migration window.
- **Security (PC-123 threat model)**: The `LogonAuthorizedCAs` attribute is writeable only by `PKI-Admins` (per ADR-066); unauthorized modification is a top Security threat documented in the threat model.

## References

- [PC-067](../catalog/05-cert-service.md) — problem statement in the catalog
- [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §7 — `NTAuthCertificates` replacement specification
- [Workshop Decision 5](../workshop/decision-05-kdc-implementation.md) — Fresh Rust KDC (PKINIT validator implementation)
- [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md) — `NTAuthCertificates` AD object location, `cACertificate` attribute, `certutil -dspublish NTAuthCA` publication, registry mirror
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — PKINIT verification path: client signs nonce → KDC verifies signature → KDC validates chain against `NTAuthCertificates` → TGT issued with PAC
- [ADR-013](./ADR-013-cross-realm-tgt-referral.md) — Cross-realm TGT referral (cross-realm PKINIT trust per §9)
- [ADR-025](./ADR-025-transactional-policy-rollback.md) — Transactional policy application (atomic `LogonAuthorizedCAs` modification)
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — Push-based policy distribution (trust-manager push)
- [ADR-033](./ADR-033-ocsp-responder-rfc-6960-nonce-ha.md) — OCSP responder (cert revocation checking)
- [ADR-035](./ADR-035-multi-cdp-ocsp-cluster-crl-fallback.md) — Multi-CDP OCSP/CRL cluster fallback (CRL distribution)
- [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md) — Trust manager (cross-platform trust distribution)
- [ADR-037](./ADR-037-two-tier-ca-hsm-root.md) — Two-tier CA with HSM-bound root (the issuing CA whose cert is in `LogonAuthorizedCAs`)
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — Standardize MIT krb5 (Linux PKINIT via `pkinit_anchors`)
- [ADR-066](./ADR-066-adminsdholder-declarative-rbac.md) — AdminSDHolder declarative RBAC (`PKI-Admins` group)
- [ADR-095](./ADR-095-acme-primary-mswcce-bridge.md) — ACME-primary cert enrollment (smart-card logon cert issuance)
- [ADR-096](./ADR-096-cert-profile-yaml-replaces-templates.md) — Cert profile YAML (`ntauth_member` flag per §7)
- [RFC 4556 PKINIT](https://www.rfc-editor.org/rfc/rfc4556) — Public Key Cryptography for Initial Authentication in Kerberos
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) — Kerberos Protocol Extensions (PKINIT validation)
- [`x509-cert` crate](https://docs.rs/x509-cert) — RustCrypto X.509 certificate library (chain validation)
- [`rustls` crate](https://docs.rs/rustls) — Rust TLS library (cert chain validation)
- [`security-framework` crate](https://docs.rs/security-framework) — macOS Security framework (Keychain trust-store sync)
- [`windows` crate](https://docs.rs/windows) — Rust Windows API bindings (CNG + NTAuth registry hive)
