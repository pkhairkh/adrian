---
title: "ADR-042: AD RMS out of scope; recommend AIP"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-077
severity: low
tags: [adr, federation-gateway, rms, irm, aip, out-of-scope]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../docs/01-ad-core/05-ad-rms-rights.md
  - ../docs/05-pki-certs/02-certificate-templates.md
  - ./ADR-037-two-tier-ca-hsm-root.md
last_updated: 2026-08-13
---

# ADR-042: AD RMS out of scope; recommend AIP

## Status

Accepted — 2026-08-13.

## Context

AD RMS (`rmssvc.exe` inside `svchost -k netsvcs`) issues use licenses for protected content, per [docs/01-ad-core/05-ad-rms-rights.md](../docs/01-ad-core/05-ad-rms-rights.md). The Server Licensor Certificate (SLC) private key compromise = all issued ILs compromised — every protected document ever issued by the RMS cluster becomes decryptable by anyone with the SLC private key. RMS uses a multi-stage pipeline: machine activation (client generates RSA keypair), enrollment (RMS server signs public key in RAC — Rights Account Certificate), client licensor cert (CLC — fresh RSA keypair, public key + validity signed with SLC), content encryption (AES-256 content key + per-recipient RSA wrap inside Issuance License IL), use license (recipient decrypts AES key with their RSA private key).

Microsoft's Azure Information Protection (AIP) is the cloud migration target for on-prem AD RMS. The Microsoft Information Protection (MIP) SDK exists for Linux/macOS clients (`mip_sdk` NuGet / pip package), enabling cross-platform protected-content consumption. But there is no open-source RMS server — the SLC issuance, use-license issuance, and revocation machinery is proprietary to Microsoft, per [PC-077](../catalog/06-federation-gateway.md).

For the framework, the question is whether IRM (Information Rights Management) is in scope. The use cases are narrow: legal, finance, healthcare with strict IRM requirements. Implementing a minimal RMS-compatible server (SLC issuance + use-license issuance + revocation) is a significant engineering effort with no open-source reference; the only viable path is AIP or a third-party IRM (Vera, VeraCloud, Seclore).

If in scope, the framework must support use-license issuance + content key encryption (AES-256 content key + per-recipient RSA wrap), must support SLC private key protection (HSM-backed), and should support SLC archival (`msPKI-Private-Key-Flag.REQUIRE_ARCHIVAL` per [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md)). If out of scope, the framework recommends AIP or third-party IRM (Vera, Seclore).

## Decision

The framework shall document AD RMS (and IRM generally) as out of scope. The framework does not implement an RMS server, does not issue Server Licensor Certificates, does not issue use licenses, and does not provide content-key encryption. The framework recommends Azure Information Protection (AIP) as the migration path for orgs that need IRM, and documents third-party IRM alternatives (Vera, Seclore) for orgs that cannot use AIP.

1. **Out of scope** — the framework does not implement any RMS functionality: no SLC issuance, no use-license issuance, no content-key encryption, no RAC/CLC pipeline, no RMS client integration. The framework's federation service does not include RMS endpoints; the framework's directory does not include RMS-specific objects (`CN=Encryption Configuration,CN=Services,CN=Configuration,...`); the framework's cert service does not issue RMS server licensor certs.
2. **Recommend AIP** — the framework's documentation recommends Azure Information Protection (AIP) as the migration path for orgs that need IRM. AIP provides cloud-hosted IRM with the MIP SDK for cross-platform client consumption (Windows, macOS, Linux, iOS, Android). AIP integrates with Microsoft Purview for data classification and labeling.
3. **Third-party IRM alternatives** — for orgs that cannot use AIP (e.g., air-gapped deployments, non-Microsoft environments), the framework's documentation lists third-party IRM alternatives: Vera (data-centric encryption with policy enforcement), Seclore (enterprise IRM with detailed usage controls), Fasoo (enterprise DRM). These are commercial products; the framework does not integrate with them but documents them as alternatives.
4. **No open-source RMS server** — the framework's documentation notes that there is no open-source RMS server implementation. The SLC issuance, use-license issuance, and revocation machinery is proprietary to Microsoft (AD RMS) and other commercial IRM vendors. Implementing a minimal RMS-compatible server from scratch is a significant engineering effort (estimated 50+ person-weeks) with no open-source reference, and the resulting implementation would not be RMS-protocol-compatible with Microsoft Office clients (which use the proprietary MS-DRM protocol).
5. **Migration guidance** — for orgs migrating from AD RMS to AIP, the framework's migration guide (per ADR-055) documents the AIP migration path: export SLC from AD RMS, import to AIP, configure AIP cross-domain trust, migrate protected content. The framework does not perform the migration (it is an AIP-side operation) but documents the prerequisites and post-migration framework configuration (the framework's federation service no longer needs to trust AD RMS certs).
6. **Cert Service implications** — the framework's Cert Service (per ADR-037) does not issue RMS server licensor certs. The `pKICertificateTemplate` AD class for RMS server licensor cert templates (with `pKIExtendedKeyUsage` OID `1.3.6.1.4.1.311.10.3.6` Key Recovery and related RMS EKU OIDs) is not supported. Orgs that need RMS server licensor certs should use AD CS (legacy) or AIP (cloud).
7. **Federation implications** — the framework's federation service (per ADR-039) does not include RMS-specific endpoints. AD RMS uses a separate trust model (SLC trust, not federation trust); the framework's federation trust (per ADR-036) does not extend to RMS. Orgs that need RMS federation should use AIP's built-in federation.

**Concrete specification**:

- The framework's documentation includes an "IRM scope statement" page: "AD RMS and IRM are out of scope for the framework. The framework recommends Azure Information Protection (AIP) for orgs that need IRM. Third-party alternatives (Vera, Seclore, Fasoo) are documented for orgs that cannot use AIP."
- The framework's migration guide (per ADR-055) includes a section "Migrating AD RMS to AIP" with the AIP-side migration steps.
- The framework's Cert Service documentation explicitly lists RMS server licensor certs as not supported.
- The framework's federation service documentation explicitly lists RMS endpoints as not implemented.
- The framework's capability matrix (per the catalog) marks RMS as "out of scope — recommend AIP."

## Rationale

Three alternatives were considered.

**Alternative 1: Implement a minimal RMS-compatible server.** Build SLC issuance, use-license issuance, and revocation machinery in the framework. Rejected because (a) it is a significant engineering effort (50+ person-weeks) with no open-source reference; (b) the resulting implementation would not be MS-DRM-protocol-compatible with Microsoft Office clients (which use the proprietary MS-DRM protocol, undocumented in detail); (c) the use cases are narrow (legal, finance, healthcare with strict IRM requirements) — most orgs do not need IRM; (d) AIP is the established migration path with cross-platform MIP SDK support. The engineering effort is better spent on capabilities that benefit all orgs (Policy Engine, Cert Service, Federation Gateway core).

**Alternative 2: Integrate with a third-party IRM (Vera, Seclore).** Build framework integration with Vera or Seclore as the IRM layer. Rejected because (a) the integration would be vendor-specific (Vera and Seclore have different APIs); (b) the framework would be coupling to a commercial product, limiting customer choice; (c) the use cases are narrow — most orgs do not need IRM, and orgs that do typically already have an IRM solution (AD RMS or AIP). The framework's role is to document the alternatives, not to integrate with one.

**Alternative 3: Defer the decision (mark as TBD).** Do not decide whether RMS is in scope; revisit after v1. Rejected because (a) the framework's capability matrix needs a clear scope statement for customers evaluating adoption; (b) the engineering effort for RMS (if in scope) is large enough that it affects v1 planning; (c) the decision is low-risk (RMS is a separate service from AD FS, with narrow use cases) — there is no research spike needed to make it. The decision is "out of scope, recommend AIP" — clear and actionable.

The decision aligns with industry practice: no open-source identity or directory framework implements RMS (FreeIPA, Samba, OpenLDAP all do not); Microsoft itself recommends AIP over on-prem AD RMS for new deployments; the IRM market is dominated by commercial products (AIP, Vera, Seclore, Fasoo) with no open-source competitor. The framework's "out of scope, recommend AIP" decision matches the industry direction.

Cost: ~1 person-week for the documentation (scope statement, migration guide section, capability matrix update). No implementation cost (out of scope).

## Consequences

**Positive**. The framework's scope is clear: IRM is out of scope, AIP is the recommended path. Customers evaluating adoption know upfront that IRM is not provided. The engineering effort is focused on capabilities that benefit all orgs. The migration guide documents the AIP migration path for orgs with existing AD RMS.

**Negative**. Orgs with strict IRM requirements that cannot use AIP (e.g., air-gapped deployments, non-Microsoft environments) must use third-party IRM (Vera, Seclore, Fasoo) — an additional commercial product to license and operate. The framework does not integrate with these products, so the customer must manage the integration themselves.

**Neutral**. The framework's Cert Service and Federation Service are unaffected — they do not issue RMS certs or provide RMS endpoints. The framework's capability matrix marks RMS as "out of scope — recommend AIP" for customer clarity.

**Implementation cost**. ~1 person-week for documentation. No implementation cost.

**Operational impact**. Operators with IRM needs adopt AIP (or third-party IRM). The framework's documentation points to AIP. Operators without IRM needs (most orgs) are unaffected.

## Alternatives Considered

### Alternative A: Implement a minimal RMS-compatible server

Build SLC issuance, use-license issuance, and revocation machinery in the framework. The framework's Cert Service issues RMS server licensor certs (with `pKIExtendedKeyUsage` OID `1.3.6.1.4.1.311.10.3.6`); the framework's federation service provides RMS endpoints (`/rightsmanager/issuancelicense`, `/rightsmanager/uselicense`); the framework's directory includes RMS-specific objects.

Rejected because (a) it is a significant engineering effort — 50+ person-weeks to implement SLC issuance, use-license issuance, content-key encryption, RAC/CLC pipeline, and revocation, with no open-source reference implementation to guide the work; (b) the resulting implementation would not be MS-DRM-protocol-compatible with Microsoft Office clients — Office uses the proprietary MS-DRM protocol (MS-DRMP, MS-RMP), which is partially documented in [MS-DRM] open specifications but with critical details omitted, making a compatible reimplementation infeasible; (c) the use cases are narrow — only legal, finance, and healthcare orgs with strict IRM requirements need RMS, and most of these orgs already have AD RMS or AIP; (d) AIP is the established migration path with cross-platform MIP SDK support (Windows, macOS, Linux, iOS, Android), and Microsoft recommends AIP over on-prem AD RMS for new deployments. The engineering effort is better spent on capabilities that benefit all orgs (Policy Engine, Cert Service, Federation Gateway core). For the narrow set of orgs that need IRM and cannot use AIP, third-party IRM (Vera, Seclore, Fasoo) is the alternative — these are commercial products with their own SLC issuance and use-license machinery, and the framework's role is to document them, not to integrate with them.

### Alternative B: Integrate with a third-party IRM (Vera, Seclore)

Build framework integration with Vera or Seclore as the IRM layer. The framework's federation service proxies IRM requests to the third-party IRM; the framework's directory syncs IRM principals.

Rejected because (a) the integration would be vendor-specific — Vera and Seclore have different APIs, data models, and trust mechanisms; building integration with one (e.g., Vera) would not work with the other (Seclore), forcing the framework to pick a vendor and limiting customer choice; (b) the framework would be coupling to a commercial product, introducing a vendor dependency that conflicts with the framework's open-standards philosophy; (c) the use cases are narrow — most orgs do not need IRM, and orgs that do typically already have an IRM solution (AD RMS or AIP) and would not benefit from framework-third-party-IRM integration; (d) the customer can integrate the framework with their chosen IRM themselves via the framework's standard APIs (per ADR-061 REST API) — the framework does not need to provide the integration. The framework's role is to document the third-party IRM alternatives, not to integrate with one. Customers needing IRM adopt AIP (the recommended path) or a third-party IRM (for air-gapped or non-Microsoft environments) and integrate it with the framework via standard APIs.

### Alternative C: Defer the decision (mark as TBD)

Do not decide whether RMS is in scope. Mark RMS as "TBD — revisit after v1" in the capability matrix and proceed with v1 without RMS functionality.

Rejected because (a) the framework's capability matrix needs a clear scope statement for customers evaluating adoption — a "TBD" leaves customers uncertain whether to plan for framework-provided IRM or to adopt a separate IRM solution, delaying their adoption decisions; (b) the engineering effort for RMS (if later decided in scope) is large enough (50+ person-weeks) that it affects v1 planning — resources allocated to RMS would come from other capabilities, and the trade-off should be made explicitly, not deferred; (c) the decision is low-risk — RMS is a separate service from AD FS, with narrow use cases, and there is no research spike needed to make the decision (the technical evaluation is straightforward: no open-source RMS server exists, AIP is the recommended path, third-party IRM is the alternative for orgs that cannot use AIP). The decision is "out of scope, recommend AIP" — clear, actionable, and aligned with industry practice. Deferring would create uncertainty without benefiting the framework.

## Open Questions

- Should the framework provide a stub "IRM redirect" endpoint that redirects RMS client requests to AIP (for smooth migration from AD RMS to AIP)? Current decision: no — the AD RMS-to-AIP migration is an AIP-side operation (Microsoft provides the migration tooling); the framework does not need to intercept RMS client requests. Revisit if operators report RMS client confusion during migration.
- Should the framework's documentation include a comparison of third-party IRM products (Vera, Seclore, Fasoo) with feature matrices? Current decision: yes — a brief comparison is included in the migration guide; the framework does not endorse any specific product.
- Should the framework's Cert Service issue RMS server licensor certs for orgs that want to keep AD RMS but use the framework's CA? Current decision: yes, as a legacy interop feature (the cert template with `pKIExtendedKeyUsage` OID `1.3.6.1.4.1.311.10.3.6` is supported for issuance, but the framework does not provide the RMS server itself). Revisit if demand is low.

## Cross-capability impact

- **Federation Gateway (PC-077)**: This ADR. PC-068 (IdP choice, gated by ORQ-132/133/134) — RMS is a separate service from the IdP; the federation layer choice does not affect RMS scope.
- **Cert Service (PC-057..PC-067)**: ADR-037 (two-tier CA with HSM root) — the framework's Cert Service may issue RMS server licensor certs as a legacy interop feature (per Open Questions above), but does not provide the RMS server.
- **Migration (PC-124..PC-130)**: ADR-055 (migration paths) — the migration guide documents the AD RMS-to-AIP migration path (AIP-side operation).
- **Security (PC-116..PC-123)**: IRM is a Security concern (data protection); the framework's scope statement is documented in the Security threat model.

## References

- [PC-077](../catalog/06-federation-gateway.md) — problem statement in the catalog
- [docs/01-ad-core/05-ad-rms-rights.md](../docs/01-ad-core/05-ad-rms-rights.md) — RMS architecture, SLC issuance, RAC/CLC pipeline, content encryption, use license flow
- [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md) — RMS server licensor cert templates, RMS EKU OIDs
- [Azure Information Protection](https://www.microsoft.com/en-us/security/business/information-protection/azure-information-protection) — AIP (recommended IRM path)
- [Microsoft MIP SDK](https://learn.microsoft.com/en-us/information-protection/develop/) — MIP SDK for cross-platform IRM client consumption
- [Vera Security](https://www.vera.com/) — third-party IRM alternative
- [Seclore](https://www.seclore.com/) — third-party IRM alternative
- [MS-DRM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drm) — RMS protocol (partially documented)
