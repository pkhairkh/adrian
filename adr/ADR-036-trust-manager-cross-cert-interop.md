---
title: "ADR-036: Trust-manager model; cross-cert for interop only"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-065
severity: low
tags: [adr, cert-service, trust-manager, cross-cert, trust-store]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../docs/05-pki-certs/02-certificate-templates.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ./ADR-037-two-tier-ca-hsm-root.md
last_updated: 2026-08-13
---

# ADR-036: Trust-manager model; cross-cert for interop only

## Status

Accepted — 2026-08-13.

## Context

Cross-certification is the PKI mechanism where root A signs root B's cert (and vice versa, or one-way), creating a bridge. Per [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md), AD stores cross-certs in the `CrossCertificatePair` attribute (OID 2.5.4.41) on the `NTAuthCertificates` object at `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,...`. Path validation must then walk both native and cross-cert chains, applying `NameConstraints` (OID 2.5.29.30), `PolicyConstraints` (OID 2.5.29.36), and `PolicyMappings` (OID 2.5.29.33) extensions to constrain the cross-certified namespace.

Per [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), cross-cert is rarely deployed in practice due to path-validation complexity. Windows CryptoAPI (`CryptFindCertificateInCRL` / `CertGetCertificateChain`) supports cross-cert chains but the `CertGetCertificateChain` `CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT` flag is frequently needed to avoid rejecting cross-certs with non-standard extensions. Browsers (Chrome, Firefox) often do not honor cross-certs at all — they use their own root store (Mozilla CA Program, Chrome Root Store) rather than the OS trust store.

For the framework, the question is whether to support cross-cert for partner-PKI scenarios. The alternative is a trust-manager model (like browser CA bundles) where each application has its own trust store, and partner PKI trust is established by importing the partner root directly. This is operationally simpler but loses the chain-walking benefits of cross-cert (e.g., `NameConstraints` to restrict what the partner CA can certify), per [PC-065](../catalog/05-cert-service.md).

The framework must support `CrossCertificatePair` attribute on `NTAuthCertificates` for AD interop, must support `pathLenConstraint` in BasicConstraints (OID 2.5.29.19), and must support `NameConstraints` (OID 2.5.29.30) for namespace restriction.

## Decision

The framework shall adopt the trust-manager model (per-OS CA bundles, refreshable) as the primary trust mechanism, and shall support cross-cert (`CrossCertificatePair`) only for explicit AD-interop scenarios.

1. **Trust-manager model as primary** — the framework's primary trust mechanism is per-OS CA bundles, managed by a "trust-manager" component. Each OS has a native trust store: Windows `Trusted Root Certification Authorities` (`certlm.msc` / `certmgr.msc`), macOS System Roots (`/System/Library/Keychains/SystemRootCertificates.keychain` + System keychain `/Library/Keychains/System.keychain`), Linux `/etc/ssl/certs/` (ca-certificates bundle, with `c_rehash` for hash-based lookup). The trust-manager component pushes the framework's root CA cert to each OS's trust store on host enrollment, and refreshes the trust store on root CA cert rotation (per ADR-037).
2. **Per-application trust stores** — applications may have their own trust stores layered on top of the OS trust store. The framework's trust-manager supports per-application trust store management: Java `cacerts` (`$JAVA_HOME/lib/security/cacerts`), Python `certifi` (`/usr/lib/python3.x/site-packages/certifi/cacert.pem`), Node.js `node --use-openssl-ca` (uses OS store) or `node --use-bundled-ca` (uses bundled store), curl `/etc/pki/tls/certs/ca-bundle.crt`. The trust-manager updates these per-application stores alongside the OS store.
3. **Trust refresh** — the trust-manager refreshes trust stores on: (a) root CA cert rotation (per ADR-037, every 5–10 years), (b) issuing CA cert rotation (every 5 years), (c) cross-cert addition/removal (for AD-interop scenarios), (d) partner root addition/removal (manual). Refresh is triggered by the framework's policy engine (per ADR-028 push or ADR-027 periodic refresh) and is transactional (per ADR-025).
4. **Cross-cert for interop only** — the framework supports the `CrossCertificatePair` attribute on `NTAuthCertificates` for explicit AD-interop scenarios where a partner PKI must be cross-certified. Cross-cert is not the default; it is opt-in per-partner-PKI. The framework provides a CLI `adrian-ca cross-cert --partner-root <cert.cer> --name-constraints <config>` that generates a cross-cert signed by the framework's root CA, with `NameConstraints` restricting the partner CA's namespace.
5. **NameConstraints enforcement** — when a cross-cert is in use, the framework's TLS clients enforce `NameConstraints` (OID 2.5.29.30) per RFC 5280 §4.2.1.10. The framework's TLS stack (OpenSSL, Schannel, Secure Transport) enforces NameConstraints natively; the trust-manager verifies that the partner CA's issued certs comply with the constraints.
6. **Partner PKI trust (no cross-cert)** — for partner PKI scenarios where cross-cert is not needed (the common case), the framework's trust-manager imports the partner root directly into the OS trust store and per-application trust stores. This is the trust-manager model: trust is established by direct root import, not by chain-walking through a cross-cert.
7. **AD interop** — for AD interop, the framework publishes cross-certs to `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,...` via `certutil -dspublish -f <cert.cer> NTAuthCA` (or the framework's equivalent LDAP `modify`). AD's CryptoAPI then walks the cross-cert chain. For framework-native clients, the trust-manager imports the partner root directly (no cross-cert chain-walking).

**Concrete specification**:

- The trust-manager is a per-platform component in the Client SDK: `adrian-trust-manager` on Linux (systemd service), Windows Service on Windows, launchd daemon on macOS.
- On host enrollment, the trust-manager pushes the framework's root CA cert to: Windows `HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\<thumbprint>` (via `CertAddCertificateStoreEntry`); macOS System keychain (via `security add-trusted-cert`); Linux `/usr/local/share/ca-certificates/adrian-root.crt` (followed by `update-ca-certificates`).
- The trust-manager refreshes per-application trust stores: Java `cacerts` (via `keytool -importcert`), Python `certifi` (via `pip install --force-reinstall certifi` with custom CA bundle), curl `/etc/pki/tls/certs/ca-bundle.crt` (via symlink to OS bundle).
- The `adrian-ca cross-cert` CLI generates a cross-cert with: `BasicConstraints` (CA=true, `pathLenConstraint=0`), `KeyUsage` (`keyCertSign`), `NameConstraints` (per `--name-constraints` config), `Subject` (`CN=Adrian Cross-Cert for <partner-name>`).
- The `adrian-trust-manager list` CLI shows the current trust store contents: framework root, framework issuing CAs, partner roots, cross-certs.
- The `adrian-trust-manager add-partner --root <cert.cer>` CLI imports a partner root directly (no cross-cert) — the trust-manager model.
- The `adrian-trust-manager add-cross-cert --partner-root <cert.cer> --name-constraints <config>` CLI generates and publishes a cross-cert (the interop model).

## Rationale

Three alternatives were considered.

**Alternative 1: Cross-cert as primary (chain-walking for all partner PKI).** Use cross-cert for all partner PKI trust, leveraging `NameConstraints` for namespace restriction. Rejected because cross-cert is rarely deployed in practice (per the KB citation), browsers do not honor it (they use their own root stores), and path-validation complexity is high (the `CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT` flag is frequently needed). The trust-manager model is operationally simpler and matches browser behavior.

**Alternative 2: Web-of-trust (each application defines its own trust roots, no central trust-manager).** Rejected because web-of-trust is operationally complex at enterprise scale — each application's trust roots must be managed separately, with no central control. The trust-manager model provides central control (the framework pushes trust roots) while preserving per-application trust store fidelity.

**Alternative 3: Cross-cert + trust-manager hybrid (both always).** Always publish cross-certs and import partner roots directly. Rejected because cross-cert adds path-validation complexity for no benefit when the partner root is already trusted directly. Cross-cert should be opt-in for scenarios that need `NameConstraints` namespace restriction; the default should be direct root import.

The decision aligns with industry practice: browsers use trust-manager models (Mozilla CA Program, Chrome Root Store, Apple Root Program); Kubernetes uses `cert-manager` (a trust-manager component that distributes CA bundles to pods); HashiCorp Vault uses per-mount trust stores. Cross-cert is rare in modern PKI; the trust-manager model is the default.

Cost: ~3 person-weeks for the trust-manager component (per-platform trust store integration, per-application trust store updates), the cross-cert generation CLI, and the partner root import CLI.

## Consequences

**Positive**. The trust-manager model is operationally simple: partner PKI trust is established by direct root import, no chain-walking complexity. Per-application trust store management ensures all applications (Java, Python, curl) see the same trust roots. Trust refresh is automatic on root CA rotation. Cross-cert is available for the rare scenarios that need `NameConstraints` namespace restriction.

**Negative**. Direct root import loses the `NameConstraints` benefit: a partner root imported directly can certify any namespace (e.g., a partner CA could issue a cert for `corp.example.com` even if the partner should only certify `partner.com`). Operators must trust partner CAs to stay in their lane, or use cross-cert with `NameConstraints` for high-security partner PKI. Per-application trust store management is a maintenance burden — applications update their bundled CAs on their own schedule (Java quarterly, Python monthly via `certifi`), which may desync from the framework's trust store.

**Neutral**. The framework's trust-manager is the central trust authority; partner roots must be added via the trust-manager, not directly via OS commands (which would be overwritten on next refresh). This is a deliberate design choice for central control.

**Implementation cost**. ~3 person-weeks for the trust-manager component, cross-cert CLI, and partner root import CLI.

**Operational impact**. Operators add partner roots via `adrian-trust-manager add-partner`. Cross-cert is opt-in via `adrian-ca cross-cert` for high-security partner PKI. Trust refresh is automatic.

## Alternatives Considered

### Alternative A: Cross-cert as primary (chain-walking for all partner PKI)

Use cross-cert for all partner PKI trust. The framework's root CA signs each partner root's cert, creating a cross-cert chain. `NameConstraints` restricts each partner CA's namespace. Clients walk the cross-cert chain during path validation.

Rejected because (a) cross-cert is rarely deployed in practice per the KB citation — AD CS supports it but field deployments are uncommon due to path-validation complexity; (b) browsers (Chrome, Firefox, Safari) do not honor cross-cert chains — they use their own root stores (Mozilla CA Program, Chrome Root Store) rather than the OS trust store, so cross-cert certs are rejected by browsers even if the OS accepts them; (c) path-validation complexity is high — the `CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT` flag is frequently needed to avoid rejecting cross-certs with non-standard extensions, indicating real-world interop pain; (d) cross-cert requires the framework's root CA to sign partner roots, which means the framework's root CA must be online (or the signing must happen offline and the cross-cert distributed) — operational overhead. The trust-manager model (direct root import) is operationally simpler and matches browser behavior, which is the dominant client.

### Alternative B: Web-of-trust (each application defines its own trust roots)

No central trust-manager; each application (Java, Python, curl, OpenSSL) manages its own trust roots independently. The framework does not push trust roots; operators configure each application separately.

Rejected because web-of-trust is operationally complex at enterprise scale. A 100-application deployment requires 100 trust store configurations, with no central control. Desync between applications (Java trusts partner root A, Python does not) produces confusing failures ("the cert works in Java but not in curl"). The trust-manager model provides central control (the framework pushes trust roots to all applications) while preserving per-application trust store fidelity (each application's trust store is updated in its native format). Central control is essential for enterprise PKI management.

### Alternative C: Cross-cert + trust-manager hybrid (both always)

Always publish cross-certs for partner PKI (chain-walking) AND import partner roots directly (trust-manager). Clients can use either path.

Rejected because cross-cert adds path-validation complexity for no benefit when the partner root is already trusted directly. If the partner root is in the trust store, path validation succeeds via the direct root; the cross-cert chain is not walked (clients prefer the shorter chain). Cross-cert should be opt-in for scenarios that need `NameConstraints` namespace restriction (e.g., a partner CA that should only certify `partner.com` but the partner root is in the trust store for convenience); the default should be direct root import without cross-cert. Always publishing both adds operational overhead (cross-cert generation and distribution) for no benefit in the common case.

## Open Questions

- Should the trust-manager support per-tenant trust stores (each tenant has its own set of trusted CAs)? Multi-tenant deployments (e.g., a SaaS PKI provider) may need this. Current decision: per-deployment trust store (single set of trusted CAs for the whole deployment); revisit if multi-tenant demand emerges.
- The cross-cert `NameConstraints` configuration: should it be expressible as a structured config (JSON) or as raw ASN.1? Current decision: structured config (`{"permitted_dns": ["partner.com", "*.partner.com"], "excluded_dns": ["corp.example.com"]}`), compiled to ASN.1 by the CLI.
- The per-application trust store updates: should the trust-manager bundle the framework's root CA into Java `cacerts` and Python `certifi`, or rely on the OS trust store (which Java and Python can be configured to use)? Current decision: bundle into per-application stores (more reliable; Java and Python do not always read the OS store by default).

## Cross-capability impact

- **Cert Service (PC-065)**: This ADR. PC-067 (`NTAuthCertificates`) — cross-certs are stored on the same AD object; PC-067 is gated by ORQ-110/111 (enrollment protocol).
- **Cert Service (PC-066)**: ADR-037 (two-tier CA with HSM root) — root CA rotation triggers trust-manager refresh.
- **Client SDK (PC-085..PC-093)**: The trust-manager is a Client SDK component; per-platform trust store integration is part of the SDK.
- **Federation Gateway (PC-068..PC-077)**: Federation trust (token-signing cert validation) uses the trust-manager's trust store.

## References

- [PC-065](../catalog/05-cert-service.md) — problem statement in the catalog
- [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md) — `CrossCertificatePair` attribute, `NameConstraints`/`PolicyConstraints`/`PolicyMappings` extension OIDs
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — Cross-cert topology, `NTAuthCertificates` storage, rare deployment
- [RFC 5280 X.509](https://www.rfc-editor.org/rfc/rfc5280) — NameConstraints (§4.2.1.10), BasicConstraints (§4.2.1.9), path validation (§6)
- [Mozilla CA Program](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/) — industry precedent for trust-manager model
- [cert-manager trust-manager](https://cert-manager.io/docs/projects/trust-manager/) — industry precedent for Kubernetes trust distribution
