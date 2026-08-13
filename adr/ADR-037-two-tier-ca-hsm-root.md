---
title: "ADR-037: Two-tier CA with HSM-bound root"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-066
severity: medium
tags: [adr, cert-service, ca-topology, two-tier, hsm, offline-root]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../docs/05-pki-certs/01-ad-cs-architecture.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ./ADR-032-hsm-bound-kra-shamir.md
  - ./ADR-036-trust-manager-cross-cert-interop.md
last_updated: 2026-08-13
---

# ADR-037: Two-tier CA with HSM-bound root

## Status

Accepted — 2026-08-13.

## Context

Two-tier CA topology (offline root + online issuing) is most common: the root CA is air-gapped, signs the issuing CA's cert, and the issuing CA issues end-entity certs. Per [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md), the offline root has a long CRL lifetime (6–12 months or longer) because the root is offline — the CRL must remain valid for the duration of any planned outage. AIA/CDP URLs in the issued sub-CA cert point to an HTTP path reachable by all clients (e.g., `http://pki.corp.example.com/certs/<CAName>.crt`). The issuing CA is online, joined to the domain, Enterprise mode, with templates enabled.

Three-tier topology adds a policy CA between root and issuing: `Root CA (offline, in safe) → Policy CA (offline or online; enforces name constraints, EKU constraints) → Issuing CA → end-entity certs`. The advantage is policy isolation: the Policy CA can carry `NameConstraints` (OID 2.5.29.30) restricting the namespace the issuing CA can certify, and `PolicyConstraints` (OID 2.5.29.36) limiting the policy mapping depth. Compromise of an issuing CA is contained by the policy CA's path length and constraints. The disadvantage is operational complexity — three CAs to back up, three keys to protect, three CRLs to publish, per [PC-066](../catalog/05-cert-service.md).

For the framework, two-tier with HSM-protected root is the recommended default for most enterprises. Three-tier is for high-assurance (government, finance, healthcare) where compromise containment outweighs operational complexity. Cloud-based root CA (AWS Private CA, GCP CA Service, Azure Key Vault CA) is an alternative for organizations that want managed root — but introduces a cloud dependency and cost-per-cert pricing.

The framework must support offline root (air-gapped, sneakernet CRL/cert transfer), must support HSM-protected CA keys (CNG KSP / PKCS#11), must support `NameConstraints` and `PolicyConstraints` for three-tier, and should support cloud-based root CA (AWS Private CA, GCP CA Service) as an alternative.

## Decision

The framework shall default to a two-tier CA topology (offline root + online issuing), with the root CA private key bound to an HSM (offline HSM or HSM partition). Three-tier topology is supported for high-assurance deployments but is not the default. Cloud-based root CA is supported as an alternative.

1. **Two-tier default** — the framework's CA installer defaults to two-tier topology: an offline root CA (air-gapped, sneakernet CRL/cert transfer) and an online issuing CA (joined to the framework's directory, with templates enabled). The root CA cert is self-signed, valid for 20 years (configurable). The issuing CA cert is signed by the root, valid for 10 years. End-entity certs are issued by the issuing CA, valid for 1–2 years (per template).
2. **HSM-bound root key** — the root CA private key is generated inside and never leaves an HSM. The HSM is offline (disconnected from any network) for the root CA; root CA operations (signing the issuing CA cert, signing the root CRL) are performed by booting the root CA host from read-only media, connecting the offline HSM, and running the signing operation. The HSM is then disconnected and stored in a physical safe. This matches the operational model of high-assurance PKI (per NIST SP 800-57).
3. **Root CRL lifetime** — the root CA CRL has a long lifetime (default 12 months), because the root CA is offline and the CRL must remain valid for the duration of any planned outage. The root CRL is published to the HTTP CDP URL (`http://pki.<domain>/crl/root-ca.crl`) via sneakernet: the root CA generates the CRL, writes it to removable media, and the media is transferred to the online CRL distribution host.
4. **Issuing CA online** — the issuing CA is online (joined to the framework's directory, with autoenroll templates enabled). The issuing CA private key is bound to an HSM partition (online HSM, not air-gapped). The issuing CA cert is signed by the root CA (offline operation), with `BasicConstraints` (`CA=true`, `pathLenConstraint=0` — the issuing CA cannot sign sub-CAs), `KeyUsage` (`keyCertSign`, `cRLSign`), and AIA/CDP URLs pointing to the online distribution host.
5. **Three-tier (opt-in)** — for high-assurance deployments (government, finance, healthcare), the framework supports a three-tier topology with a policy CA between root and issuing. The policy CA is offline (like the root), with `NameConstraints` (restricting the issuing CA's namespace) and `PolicyConstraints` (limiting policy mapping depth). The framework's CA installer prompts for topology choice; two-tier is default, three-tier is opt-in.
6. **Cloud-based root CA (alternative)** — for organizations that want managed root, the framework supports AWS Private CA, GCP CA Service, and Azure Key Vault CA as the root CA. The cloud root CA signs the framework's issuing CA cert (via cloud API); the issuing CA is self-hosted. This introduces a cloud dependency (the framework cannot issue new issuing CA certs without cloud connectivity) and cost-per-cert pricing (AWS Private CA charges $400/CA/year + $5.16/10K certs issued). The framework's CA installer prompts for root CA type (offline HSM vs. cloud); offline HSM is default, cloud is opt-in.
7. **Root CA rotation** — the root CA cert is rotated every 20 years (configurable). Rotation is a multi-step process: (a) generate a new root CA keypair in the HSM, (b) create a cross-cert (the new root signs the old root, and the old root signs the new root) to support transition, (c) distribute the new root CA cert to all trust stores via the trust-manager (per ADR-036), (d) after the transition window (default 1 year), revoke the old root CA cert and remove it from trust stores.

**Concrete specification**:

- The framework's CA installer (`adrian-ca install`) prompts for: topology (two-tier default, three-tier opt-in), root CA type (offline HSM default, cloud opt-in), HSM configuration (KSP/PKCS#11 provider, partition, PIN), root CA cert validity (default 20 years), root CRL lifetime (default 12 months), issuing CA cert validity (default 10 years).
- The offline root CA host is a dedicated, air-gapped machine booted from read-only media (USB stick or CD-ROM). The HSM is connected via USB or PCIe. The root CA operations (sign issuing CA cert, sign root CRL) are performed via `adrian-ca-root sign-issuing --csr <file>` and `adrian-ca-root sign-crl`.
- The online issuing CA runs as `adrian-ca-issuing` service on Linux, Windows Service on Windows, launchd daemon on macOS. It listens on HTTPS (`https://<ca-host>:/api/v1/enroll`) for enrollment requests (per the framework's enrollment protocol, gated by ORQ-110/111).
- The root CA cert and CRL are published to `http://pki.<domain>/certs/root-ca.crt` and `http://pki.<domain>/crl/root-ca.crl` via sneakernet (root CA host → removable media → online distribution host).
- The issuing CA cert and CRL are published to `http://pki.<domain>/certs/issuing-ca.crt` and `http://pki.<domain>/crl/issuing-ca.crl` automatically (the issuing CA is online).
- The three-tier topology adds: `adrian-ca-policy install` for the policy CA (offline, like the root), `NameConstraints` configuration (per ADR-036), and `PolicyConstraints` configuration.
- The cloud-based root CA integration uses the cloud provider's API: `adrian-ca-cloud enroll --provider aws-pca --csr <file>` calls AWS Private CA's `IssueCertificate` API. The issuing CA cert is downloaded and installed in the framework's online issuing CA.

## Rationale

Three alternatives were considered.

**Alternative 1: Single-tier (online root CA).** One CA that is both root and issuing. Rejected because the root CA private key is online, making it a single point of catastrophic failure. Root key compromise → all issued certs untrustworthy → the entire PKI must be rebuilt (re-issue all certs, redistribute root, revoke old root). The two-tier model isolates the root key offline, limiting compromise impact.

**Alternative 2: Three-tier as default.** Rejected because three-tier adds operational complexity (three CAs to back up, three keys to protect, three CRLs to publish) that is unnecessary for most enterprises. Three-tier is for high-assurance deployments where the policy isolation (via `NameConstraints`) outweighs the complexity. Making three-tier the default would impose complexity on organizations that do not need it.

**Alternative 3: Cloud-based root CA as default.** Rejected because cloud-based root introduces a cloud dependency (the framework cannot operate without internet connectivity to the cloud CA) and cost-per-cert pricing. Many deployments (government, defense, regulated industries) require air-gapped PKI; cloud-based root is incompatible. Cloud-based root is supported as an opt-in alternative for organizations that want managed root, but offline HSM is the default.

The decision aligns with industry practice: Microsoft AD CS deployment guidance recommends two-tier as the default; Dogtag PKI documentation recommends two-tier; the U.S. federal PKI uses three-tier (because of high-assurance requirements). The framework's default (two-tier) and opt-in (three-tier) match industry consensus.

Cost: ~5 person-weeks for the CA installer, the offline root CA tooling, the online issuing CA service, and the three-tier and cloud integrations. The offline root CA tooling is the highest-risk item (the air-gapped workflow must be documented and tested; HSM integration via CNG KSP and PKCS#11 is non-trivial).

## Consequences

**Positive**. Two-tier with HSM-bound root is the secure default: root key is offline, compromise impact is limited. Three-tier is available for high-assurance deployments that need policy isolation. Cloud-based root is available for organizations that want managed root. Root CA rotation is a documented, supported workflow with cross-cert transition.

**Negative**. Two-tier requires operating an offline root CA host (air-gapped machine, HSM, safe storage) — operational overhead that single-tier avoids. Root CA operations (signing issuing CA cert, signing root CRL) require physical access to the offline root CA host, which may be in a different location than the operational team. The 20-year root cert validity means root CA rotation is rare (every 20 years), so the rotation workflow is tested infrequently — risk of operator error during the actual rotation.

**Neutral**. The framework's CA installer prompts for topology and root CA type; the defaults (two-tier, offline HSM) are suitable for most deployments. Operators who want three-tier or cloud root must explicitly choose them.

**Implementation cost**. ~5 person-weeks for the installer, offline root tooling, online issuing service, and three-tier/cloud integrations.

**Operational impact**. Operators run an offline root CA host in a physical safe, with HSM access. Root CA operations are scheduled maintenance windows. Issuing CA operations are routine (online service, monitored via Prometheus metrics per ADR-057). Root CA rotation is a planned, multi-month project every 20 years.

## Alternatives Considered

### Alternative A: Single-tier (online root CA)

One CA that is both root and issuing. The root CA private key is online (in an HSM partition, but the HSM is connected to a network-accessible host). End-entity certs are issued directly by the root CA.

Rejected because the root CA private key is online, making it a single point of catastrophic failure. If the root key is compromised (HSM breach, host compromise with HSM access, insider threat), every cert issued by the root is untrustworthy. The entire PKI must be rebuilt: generate a new root keypair, re-issue all end-entity certs, distribute the new root to all trust stores, revoke the old root. For a 10,000-host deployment, this is a multi-week outage. The two-tier model isolates the root key offline (in an air-gapped HSM in a safe), limiting compromise impact to the issuing CA (which can be re-signed by the root without re-issuing end-entity certs). The operational overhead of an offline root CA host is acceptable given the security gain.

### Alternative B: Three-tier as default

Default to three-tier topology (root → policy → issuing) for all deployments. The policy CA carries `NameConstraints` restricting the issuing CA's namespace.

Rejected because three-tier adds operational complexity (three CAs to back up, three keys to protect in HSMs, three CRLs to publish, three certs to rotate) that is unnecessary for most enterprises. Three-tier is for high-assurance deployments (government, finance, healthcare) where the policy isolation (via `NameConstraints` restricting what the issuing CA can certify) outweighs the operational complexity. For a typical enterprise PKI, the issuing CA's namespace is already constrained by the deployment scope (one issuing CA per business unit, with `NameConstraints` enforced at the issuing CA cert level if needed). Making three-tier the default would impose complexity on organizations that do not need it, increasing operational cost and the risk of misconfiguration (more CAs to misconfigure = more attack surface).

### Alternative C: Cloud-based root CA as default

Default to a cloud-based root CA (AWS Private CA, GCP CA Service, Azure Key Vault CA) for all deployments. The cloud provider manages the root key.

Rejected because cloud-based root introduces (a) a cloud dependency — the framework cannot issue new issuing CA certs without internet connectivity to the cloud CA, breaking air-gapped deployments (government, defense, regulated industries); (b) cost-per-cert pricing — AWS Private CA charges $400/CA/year + $5.16/10K certs issued, which compounds for high-volume CAs (100K certs/year = $400 + $51.60 = $451.60/year, manageable, but the cost grows with cert volume and is recurring); (c) vendor lock-in — migrating from one cloud CA to another (or to self-hosted) requires re-issuing all certs, a multi-week project. Cloud-based root is supported as an opt-in alternative for organizations that want managed root (e.g., small enterprises without PKI operations expertise), but offline HSM is the default for security and portability.

## Open Questions

- The root CA cert validity (default 20 years): should it be shorter (10 years) to force more frequent rotation practice? Longer validity means less rotation practice; shorter validity means more rotation operations. Current decision: 20 years (matching industry standard for root CAs); revisit if operators report rotation skill atrophy.
- The three-tier topology: should the policy CA be online or offline? Offline policy CA matches the root CA model (maximum security) but requires sneakernet for policy CA operations. Online policy CA is more operationally convenient but reduces the compromise-isolation benefit. Current decision: offline (matches the root CA model); revisit if operators report operational pain.
- The cloud-based root CA: should the framework support multi-cloud (e.g., AWS Private CA as root, GCP CA Service as backup root)? Current decision: single cloud root per deployment; multi-cloud root adds complexity for marginal resilience gain.
- Root CA rotation: the cross-cert transition window (default 1 year) — should it be shorter (6 months) or longer (2 years)? Shorter means faster cleanup but less time for clients to refresh trust stores; longer means more time but old root stays in trust stores longer. Current decision: 1 year (matches industry standard); revisit if operators report trust-store-refresh issues.

## Cross-capability impact

- **Cert Service (PC-066)**: This ADR. PC-060 (KRA, ADR-032) — KRA placement depends on CA topology; KRA certs are on the issuing CA.
- **Cert Service (PC-065)**: ADR-036 (trust-manager) — root CA rotation triggers trust-manager refresh.
- **Client SDK (PC-085..PC-093)**: The trust-manager (per ADR-036) is a Client SDK component that distributes the root CA cert to all hosts.
- **Operations (PC-106..PC-115)**: ADR-058 (Kubernetes operator) — the issuing CA runs as a StatefulSet; the offline root CA is a separate, non-Kubernetes host.
- **Security (PC-116..PC-123)**: Root key compromise is a top Security threat; the offline HSM model is documented in the Security threat model.

## References

- [PC-066](../catalog/05-cert-service.md) — problem statement in the catalog
- [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md) — Two-tier vs three-tier topology, offline root pattern, AIA/CDP URLs, `NameConstraints`/`PolicyConstraints`
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — CA hierarchy classes, `KeyUsage` bitmask, `BasicConstraints` `pathLenConstraint`
- [RFC 5280 X.509](https://www.rfc-editor.org/rfc/rfc5280) — BasicConstraints (§4.2.1.9), NameConstraints (§4.2.1.10), KeyUsage (§4.2.1.3)
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/final) — Key management recommendations (offline root, HSM)
- [AWS Private CA](https://aws.amazon.com/private-ca/) — cloud-based root CA alternative
- [PKCS#11](https://docs.oasis.org/projects/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html) — HSM API standard
