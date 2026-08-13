---
title: "ADR-084: PKINIT via FIDO2/WebAuthn Bridge (with RFC 4556 Smart-Card Path for Compliance)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: KDC
problem: PC-027
severity: high
unblocked_by: Workshop Decision 5 (ORQ-042/043/044)
tags: [adr, kdc, kerberos, pkinit, fido2, webauthn, passwordless, smart-card, piv, cac, hspd-12]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/05-pki-certs/02-certificate-templates.md
  - ../docs/05-pki-certs/05-smart-card-logon.md
  - ../workshop/decision-05-kdc-implementation.md
  - ./ADR-012-fast-armoring-required.md
  - ./ADR-037-two-tier-ca-hsm-root.md
  - ./ADR-082-ms-kile-pac-generation.md
last_updated: 2026-08-14
---

# ADR-084: PKINIT via FIDO2/WebAuthn Bridge (with RFC 4556 Smart-Card Path for Compliance)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 5](../workshop/decision-05-kdc-implementation.md) which resolved ORQ-042/043/044 in favor of a fresh Rust KDC in `crates/adrian-kdc`. The KDC's PKINIT protocol path is stubbed in v1 MVP per Decision 5 ("the protocol path is stubbed in v1"); this ADR specifies the full PKINIT posture for v1 GA and Phase 3: a **FIDO2/WebAuthn-to-PKINIT bridge** as the primary passwordless mechanism for ordinary users, with the **RFC 4556 smart-card path** retained for compliance-mandated users (HSPD-12 PIV/CAC, EU eIDAS, defense deployments). The bridge is implemented in a new framework crate `crates/adrian-pkinit-bridge` (~4K lines of Rust).

## Context

PKINIT ([RFC 4556](https://www.rfc-editor.org/rfc/rfc4556)) extends Kerberos AS-REQ with public-key pre-authentication. The client signs a `PKAuthenticator` (containing the KDC's nonce and the client's `cusn`/`ctime`) with its smart-card private key; the KDC verifies the signature against the user's certificate, which must chain to a CA in the `NTAuthCertificates` AD object (`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<forest-root-dn>`). The user cert SAN must contain the UPN (subjectAltName `otherName = 1.3.6.1.4.1.311.20.2.3`) or map via `altSecurityIdentities`.

AD's PKINIT requires (a) an Enterprise CA in the forest (the framework's Cert Service per [ADR-037](./ADR-037-two-tier-ca-hsm-root.md)); (b) the `NTAuthCertificates` object populated with the CA's cert; (c) the KDC reading `NTAuthCertificates` at boot and caching the chain; (d) the client having a smart card (PIV/CAC, YubiKey PIV) with the user's cert and private key; (e) the client's Kerberos stack supporting `PA-PK-AS-REQ` (padata-type 16). Smart cards are mandatory for HSPD-12 federal deployments and EU eIDAS regulated sectors; they are user-friendly anti-phishing for everyone else.

Modern passwordless alternatives — FIDO2 ([WebAuthn](https://www.w3.org/TR/webauthn-3/) for browser flows, [CTAP2](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) for native) — do not require an Enterprise CA. The user registers a FIDO2 authenticator (Windows Hello for Business, YubiKey, Touch ID, hardware token) with the IdP; the IdP issues signed assertions that the relying party verifies. FIDO2 supports user verification (PIN, biometric) and is phishing-resistant (origin-bound). The catch: FIDO2 is not Kerberos-native. Bridging FIDO2 to Kerberos requires a "FIDO2-to-PKINIT" gateway: the KDC accepts a FIDO2 assertion in place of the `PA-PK-AS-REQ` signature, validates the assertion against the user's registered FIDO2 credential, and issues a TGT.

The framework needs both paths: FIDO2 for ordinary users (modern, user-friendly, no Enterprise CA dependency); PKINIT/RFC 4556 for compliance-mandated users (HSPD-12, EU eIDAS, defense). Decision 5's commitment to a fresh Rust KDC makes both paths implementable in the same codebase.

Constraints from [PC-027](../catalog/02-kdc.md):

- Must support `NTAuthCertificates` AD object for AD interop (KDC reads this object at boot).
- Must support PKINIT (RFC 4556) — `PA-PK-AS-REQ` (padata-type 16) and `PA-PK-AS-REP` (17).
- Must support UPN-in-SAN cert mapping (`otherName = 1.3.6.1.4.1.311.20.2.3`).
- Must support `altSecurityIdentities` mapping for cross-forest certs.
- Consider FIDO2 as modern alternative — but FIDO2 is not Kerberos-native.

## Decision

The framework SHALL implement PKINIT in two modes, both in the fresh Rust KDC's `crates/adrian-kdc/src/pkinit.rs` and `crates/adrian-pkinit-bridge`:

### Mode A — RFC 4556 smart-card PKINIT (compliance path)

The KDC SHALL accept standard `PA-PK-AS-REQ` (padata-type 16) messages from clients with smart cards (PIV/CAC, YubiKey PIV). The KDC SHALL:

1. Validate the client certificate chain against `NTAuthCertificates`. The framework's directory SHALL expose the `NTAuthCertificates` object at the standard AD location (`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<forest-root-dn>`); the KDC reads this object at boot and caches the cert chain (with event-driven invalidation per [ADR-018](./ADR-018-kdc-horizontal-scaling.md) when the CA cert is rotated).
2. Map the client cert to a directory principal via UPN-in-SAN (`otherName = 1.3.6.1.4.1.311.20.2.3`) or `altSecurityIdentities`.
3. Verify the `PKAuthenticator` signature using the cert's public key.
4. Issue a TGT encrypted to a key derived from the DH key exchange (per RFC 4556 §3.2.3).

The framework's Cert Service ([ADR-037](./ADR-037-two-tier-ca-hsm-root.md)) SHALL issue Smart Card Logon EKU (`1.3.6.1.4.1.311.20.2.2`) certs for users with smart cards. The KDC's PKINIT module uses `ring` for signature verification, `x509-cert` for cert parsing, and `rasn` for the `PA-PK-AS-REQ` ASN.1 structures.

### Mode B — FIDO2/WebAuthn bridge (modern passwordless path)

The KDC SHALL accept FIDO2 assertions inside a framework-defined padata type (`PA-FIDO2-AS-REQ`, padata-type 0xAB — framework-allocated, in the AD-assigned vendor range). The bridge flow:

1. User initiates AS-REQ with `PA-FIDO2-AS-REQ` padata containing: user UPN, KDC nonce, KDC origin (`https://kdc.<domain>` — the KDC's WebAuthn RP ID).
2. The client's FIDO2 authenticator (Windows Hello for Business, YubiKey, Touch ID) generates an assertion over the KDC's challenge. The assertion includes the user's credential ID, the authenticator signature, and the client data (origin, type, challenge).
3. The KDC validates the assertion against the user's registered FIDO2 credentials (`msDS-Fido2Credentials` framework attribute on the user object — a multi-valued binary attribute containing `credential_id`, `public_key`, `sign_count`, `transports`). The KDC verifies the signature, checks the origin matches `https://kdc.<domain>`, checks the challenge matches the KDC's nonce, increments `sign_count` and stores it back (clone detection per FIDO2 §6.1).
4. The KDC issues a TGT as in Mode A — encrypted to a key derived from a KDC-generated ephemeral key wrapped for the client (the FIDO2 assertion has no DH key agreement; the KDC generates a fresh TGT session key and ships it in the AS-REP encrypted to the user's `pkinit-derived-key` — a long-term key derived from `HKDF(user_password, "pkinit-fido2")` if the user has a password, or to the user's pre-registered `msDS-PkinitDerivedKey` for passwordless users).

The FIDO2 bridge requires no Enterprise CA — the user's FIDO2 credentials are self-issued (the authenticator generates its own keypair at registration; the framework's directory stores the public key). This is the path for ordinary users who do not have smart cards.

### Concrete specification

- The KDC SHALL implement both PKINIT modes in `crates/adrian-kdc/src/pkinit.rs` (~2K lines) and the FIDO2 bridge logic in `crates/adrian-pkinit-bridge` (~4K lines, including FIDO2 assertion verification, credential storage, and the framework padata codec).
- The framework's directory SHALL expose `NTAuthCertificates` at `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<forest-root-dn>` populated with the framework's Enterprise CA cert (per [ADR-037](./ADR-037-two-tier-ca-hsm-root.md)).
- The framework's directory SHALL expose `msDS-Fido2Credentials` (multi-valued binary; FIDO2 credential storage) and `msDS-PkinitDerivedKey` (single-valued binary; long-term key for FIDO2-bridged TGT session-key wrapping) on user objects.
- The KDC SHALL support both `PKInitPA-AS-REQ` (padata-type 16, RFC 4556) and `PA-FIDO2-AS-REQ` (padata-type 0xAB, framework-allocated) in the AS-REQ `padata` sequence. A client MAY send both; the KDC SHALL process the first one it recognizes.
- The KDC SHALL support the `anonymous PKINIT armor TGT` (RFC 6112) for FAST armoring per [ADR-012](./ADR-012-fast-armoring-required.md). The anonymous armor TGT is issued via PKINIT with a self-signed cert; the KDC's PKINIT module SHALL support this mode (anonymous = no user principal; the resulting TGT has a generic `WELLKNOWN/ANONYMOUS` cname).
- The KDC SHALL prefer Mode B (FIDO2 bridge) for users who have `msDS-Fido2Credentials` populated and SHALL fall back to Mode A (RFC 4556) for users who have only smart-card certs.
- For AD-interop, the KDC SHALL accept `PA-PK-AS-REQ` from AD-issued smart cards (PIV/CAC certs that chain to the AD forest's Enterprise CA via cross-certification per [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md)). The framework's Cert Service SHALL cross-certify with AD's Enterprise CA during forest-trust setup.
- The framework's Client SDK ([Decision 11](../workshop/decision-11-client-sdk.md)) SHALL expose `AuthModule::pkinit_fido2(authenticator)` and `AuthModule::pkinit_smartcard(card_reader)` methods; the platform-specific FIDO2 authenticator access uses `webauthn-rs` (Rust), `windows::Security::Authentication::Web::Core` (Windows Hello), `LocalAuthentication` framework (Touch ID/macOS), and `libfido2` (Linux).
- The framework SHALL emit audit events per [ADR-023](./ADR-023-kerberos-audit-events.md): `pkinit_fido2.success`, `pkinit_fido2.failed` (with reason `signature_invalid`, `origin_mismatch`, `challenge_mismatch`, `unknown_credential`, `sign_count_regression`), `pkinit_smartcard.success`, `pkinit_smartcard.failed` (with reason `cert_chain_invalid`, `cert_expired`, `cert_revoked`, `signature_invalid`, `no_user_mapping`).
- The framework SHALL expose `adrian-cli register-fido2 <username>` (interactive FIDO2 registration) and `adrian-cli revoke-fido2 <username> <credential-id>` (revocation) CLI commands.

## Rationale

Four arguments drive this decision.

**1. FIDO2 is the modern passwordless standard; PKINIT's smart-card path is compliance-mandated.** The framework cannot mandate smart cards for ordinary users — smart cards cost $30-$100 per user and require physical distribution. FIDO2 authenticators are ubiquitous (Windows Hello, Touch ID, $25 hardware tokens). The FIDO2 bridge gives the framework passwordless auth for ordinary users without an Enterprise CA dependency. The RFC 4556 smart-card path is retained for HSPD-12 / EU eIDAS / defense deployments where smart cards are mandated by regulation.

**2. The FIDO2 bridge reuses the existing PKINIT TGT issuance path.** Mode B does not invent a new ticket type — the KDC still issues a standard RFC 4120 TGT, just with a different pre-auth mechanism. This means the framework's existing PAC builder ([ADR-082](./ADR-082-ms-kile-pac-generation.md)), FAST armoring ([ADR-012](./ADR-012-fast-armoring-required.md)), and audit emission ([ADR-023](./ADR-023-kerberos-audit-events.md)) work identically for FIDO2-bridged and smart-card-issued TGTs. The bridge is localized to the AS-REQ padata handling.

**3. `NTAuthCertificates` is preserved for AD-interop.** AD's KDC reads `NTAuthCertificates` at boot and caches the chain; the framework's KDC SHALL do the same. This means AD-issued smart cards (PIV/CAC certs that chain to AD's Enterprise CA) work with the framework's KDC after cross-certification per [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md). Mixed forests (AD + framework) preserve smart-card logon for users with AD-issued cards.

**4. Anonymous PKINIT armor TGT is the unblocker for FAST-required mode.** [ADR-012](./ADR-012-fast-armoring-required.md) defaults to `fast_mode = "supported"` for v1 MVP and flips to `"required"` in Phase 3 (per [Decision 5](../workshop/decision-05-kdc-implementation.md)). FAST-required needs an armor TGT — a TGT the client obtains without a password, used to armor the real AS-REQ. The anonymous PKINIT armor TGT (RFC 6112) is the standard mechanism; without PKINIT, FAST-required is unachievable for first-logon. This ADR's PKINIT implementation (both modes) unblocks the FAST-required flip in Phase 3.

External evidence: [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) defines PKINIT; [RFC 6112](https://www.rfc-editor.org/rfc/rfc6112) defines anonymous PKINIT; [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) defines the FIDO2 assertion format; [CTAP2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) defines the authenticator protocol; [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md) document the framework's PKINIT reference. [Microsoft Windows Hello for Business documentation](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/) documents the FIDO2-to-Kerberos bridge that the framework's Mode B mirrors.

## Consequences

**Positive**: Ordinary users get passwordless Kerberos via FIDO2 — no smart card, no Enterprise CA required. Compliance-mandated users (HSPD-12, EU eIDAS, defense) get RFC 4556 smart-card PKINIT. AD-interop is preserved (AD-issued smart cards work via cross-certification). The FAST-required flip in Phase 3 is unblocked by anonymous PKINIT armor TGT. The FIDO2 bridge is phishing-resistant (origin-bound) and supports user verification (PIN, biometric).

**Negative**: FIDO2 bridge adds a framework-specific padata type (`PA-FIDO2-AS-REQ`, 0xAB). AD-issued Kerberos clients (Windows `klist`, MIT `kinit`) do not generate this padata; only framework-managed clients (via `crates/adrian-sdk` per [Decision 11](../workshop/decision-11-client-sdk.md)) do. Mixed-forest users with FIDO2 registered against the framework must use framework-managed clients for FIDO2 logon; smart-card logon works with any RFC 4556-compatible client. The `msDS-Fido2Credentials` and `msDS-PkinitDerivedKey` attributes are framework extensions — they are not present in AD's schema; AD-interop tools that enumerate user attributes will see them as opaque binary blobs (acceptable; they are not used by AD).

**Neutral**: The framework's `PA-FIDO2-AS-REQ` padata type is in the AD-assigned vendor range (0x80-0xFF) but is not standardized. The framework SHALL register the type with IANA's Kerberos Parameters registry in a future revision; for v1, the type is framework-internal.

**Implementation cost**: 6 person-weeks total. RFC 4556 smart-card PKINIT: 2 pw (in `crates/adrian-kdc/src/pkinit.rs`). FIDO2 bridge: 3 pw (in `crates/adrian-pkinit-bridge`: FIDO2 assertion verification, credential storage schema, framework padata codec, Client SDK integration). Anonymous PKINIT armor TGT (RFC 6112): 0.5 pw. Audit events + CLI tooling: 0.5 pw. This is in addition to the v1 MVP KDC budget (24 person-weeks per [Decision 5](../workshop/decision-05-kdc-implementation.md)) — the PKINIT module is a Phase 3 deliverable that gates the `fast_mode = "required"` flip.

## Alternatives Considered

### Alternative 1: PKINIT only (RFC 4556); no FIDO2 bridge

Standard PKINIT for all passwordless users; smart cards mandatory. Rejected: smart-card cost and physical distribution are unacceptable for ordinary enterprise users. The framework would force every customer to issue smart cards — non-starter for cloud-native and SMB deployments.

### Alternative 2: FIDO2 only; no PKINIT smart-card path

FIDO2 for all passwordless users; smart cards unsupported. Rejected: HSPD-12 federal deployments, EU eIDAS regulated sectors, and defense customers mandate smart cards (PIV/CAC). The framework would lose these customers entirely.

### Alternative 3: OAuth2/OIDC-only passwordless; Kerberos stays password-based

FIDO2 issued against the framework's Federation Gateway (per [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md)); Kerberos tickets obtained via OAuth2-token-exchange (RFC 8693). Rejected: the resulting Kerberos tickets are short-lived (matching OAuth2 token lifetime, typically 1 hour) and require online validation against the Federation Gateway for every TGS-REQ — defeats Kerberos's offline-validation property. PKINIT/FIDO2-bridge keeps Kerberos's offline TGT model.

### Alternative 4: Wait for IETF-standardized FIDO2-Kerberos bridge

The IETF KITTEN working group has drafts for FIDO2-in-Kerberos; wait for standardization before implementing. Rejected: the IETF timeline is uncertain (3-5 years); the framework needs FIDO2 passwordless in Phase 3 (12-15 months). The framework's vendor padata type (0xAB) is forward-compatible with a future IETF standard — the framework can adopt the standard when it lands and migrate users incrementally.

## Open Questions

- For Mode B TGT session key wrapping: when the user has no password (pure-FIDO2 user), the `msDS-PkinitDerivedKey` is the only long-term secret available for wrapping. How is this key generated and rotated? Decision: generated at FIDO2 registration time as a random 256-bit key, encrypted with the user's FIDO2-public-key-wrapped key (the KDC stores `msDS-PkinitDerivedKey = AESEncrypt(K_FIDO2_pub, K_pkinit_derived)`); rotated whenever the user revokes their last FIDO2 credential (forcing re-registration).
- For `sign_count` clone detection: FIDO2 §6.1 specifies that the relying party SHALL reject assertions with `sign_count <= stored_count` (potential authenticator clone). Some authenticators (Windows Hello, Touch ID) always return `sign_count = 0`; the framework SHALL not enforce clone detection for `sign_count = 0` (per WebAuthn Level 3 §6.1.1). For non-zero `sign_count`, the framework SHALL enforce strict greater-than.
- Cross-reference [ADR-012](./ADR-012-fast-armoring-required.md) — anonymous PKINIT armor TGT (RFC 6112) is the unblocker for `fast_mode = "required"` in Phase 3.
- Cross-reference [ADR-037](./ADR-037-two-tier-ca-hsm-root.md) — the framework's Enterprise CA issues Smart Card Logon EKU certs for Mode A.

## Cross-capability impact

- **KDC** ([ADR-082](./ADR-082-ms-kile-pac-generation.md), [ADR-012](./ADR-012-fast-armoring-required.md)): the PKINIT module produces TGTs that the PAC builder signs and that FAST armoring consumes for `fast_mode = "required"`.
- **Cert Service** ([ADR-037](./ADR-037-two-tier-ca-hsm-root.md)): the Enterprise CA issues Smart Card Logon EKU certs for Mode A; the CA's cert is published to `NTAuthCertificates`.
- **Federation Gateway** ([ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md)): FIDO2 registration MAY be performed via the Federation Gateway's WebAuthn flow (browser-based) or via `adrian-cli register-fido2` (CLI-based); both end with `msDS-Fido2Credentials` populated on the user object.
- **Client SDK** ([Decision 11](../workshop/decision-11-client-sdk.md)): the SDK's `AuthModule` exposes `pkinit_fido2()` and `pkinit_smartcard()` methods; platform-specific FIDO2 authenticator access.
- **Operations**: `adrian-cli register-fido2`, `adrian-cli revoke-fido2`, `adrian-krb5 audit-pkinit` CLI commands. SIEM queries for `pkinit_fido2.failed` and `pkinit_smartcard.failed` provide passwordless-auth-failure monitoring.
- **Security** ([ADR-023](./ADR-023-kerberos-audit-events.md)): audit events for PKINIT success/failure feed passwordless-auth monitoring; FIDO2 clone detection (`sign_count_regression`) feeds authenticator-clone-attack detection.
- **Migration** ([ADR-069](./ADR-069-cross-realm-capaths.md)): AD users with smart cards migrate to the framework with their existing PIV/CAC cards (via cross-certification per [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md)); AD users without smart cards register FIDO2 credentials during migration.

## References

- [PC-027](../catalog/02-kdc.md) — problem statement in the catalog
- [Workshop Decision 5 — Fresh Rust KDC](../workshop/decision-05-kdc-implementation.md) — unblocking decision; PKINIT stub in v1, full implementation in Phase 3
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — PKINIT ASN.1 structures, DH key exchange, `NTAuthCertificates`
- [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md) — `NTAuthCertificates` object, Smart Card Logon EKU, certificate template configuration
- [docs/05-pki-certs/05-smart-card-logon.md](../docs/05-pki-certs/05-smart-card-logon.md) — Smart-card logon flow, PIV/CAC integration
- [ADR-012](./ADR-012-fast-armoring-required.md) — FAST armoring; anonymous PKINIT armor TGT (RFC 6112) is the unblocker for `fast_mode = "required"`
- [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md) — Cross-certification for AD-interop smart cards
- [ADR-037](./ADR-037-two-tier-ca-hsm-root.md) — Two-tier CA with HSM root; Enterprise CA issues Smart Card Logon certs
- [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md) — Federation Gateway OIDC; FIDO2 registration MAY use the Federation Gateway's WebAuthn flow
- [ADR-082](./ADR-082-ms-kile-pac-generation.md) — PAC builder signs PKINIT-issued TGTs identically to password-issued TGTs
- [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) — PKINIT
- [RFC 6112](https://www.rfc-editor.org/rfc/rfc6112) — Anonymous PKINIT
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) — FIDO2 assertion format
- [CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) — Client-to-Authenticator Protocol
- [Microsoft Windows Hello for Business](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/) — Reference FIDO2-to-Kerberos bridge (framework's Mode B mirrors this)
