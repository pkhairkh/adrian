---
title: "ADR-096: Declarative `cert-profiles.yaml` replaces AD CS certificate templates (resolves PC-058)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-058
severity: high
unblocked_by: Workshop Decision 8
tags: [adr, cert-service, certificate-templates, cert-profiles, yaml, declarative, mspki, migration, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../workshop/decision-08-pki-enrollment.md
  - ../docs/05-pki-certs/02-certificate-templates.md
  - ../docs/05-pki-certs/01-ad-cs-architecture.md
  - ./ADR-037-two-tier-ca-hsm-root.md
  - ./ADR-095-acme-primary-mswcce-bridge.md
  - ./ADR-031-git-backed-policy-history.md
last_updated: 2026-08-14
---

# ADR-096: Declarative `cert-profiles.yaml` replaces AD CS certificate templates (resolves PC-058)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §5, which specifies that AD CS certificate templates (v1/v2/v3) with their `msPKI-*` attributes are replaced by declarative YAML profiles in `cert-profiles.yaml`, version-controlled in Git, validated by the framework's CLI, and applied atomically. This ADR operationalises Decision 8 §5's profile specification against the PC-058 problem surface: the complexity of AD CS templates and the operator-hostile nature of `msPKI-*` attribute configuration.

## Context

AD CS certificate templates are `pKICertificateTemplate` AD objects (governsID `1.2.840.113556.1.5.119`) at `CN=<Template>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<NC>`, per [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md). The template drives:

- **Subject name construction** via `msPKI-Certificate-Name-Flag` bitmask — `0x1` `ENROLLEE_SUPPLIES_SUBJECT` (the enrollee supplies the subject CN, dangerous on sensitive templates), `0x10` `SUBJECT_ALT_REQUIRE_SPN`, `0x40` `SUBJECT_ALT_REQUIRE_UPN`, `0x100` `SUBJECT_ALT_REQUIRE_DNS_AS_CN`, `0x200` `SUBJECT_ALT_REQUIRE_EMAIL`, `0x400` `SUBJECT_ALT_REQUIRE_DIRECTORY_GUID`, etc.
- **Key generation** via `msPKI-Private-Key-Flag` — `0x1` `EXPORTABLE_KEY`, `0x4` `REQUIRE_ARCHIVAL`, `0x8` `REQUIRE_PRIVATE_KEY_ARCHIVAL`, `0x80` `REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM` (for CNG RSASSA-PSS), `0x100` `REQUIRE_ATTESTATION` (for TPM-bound keys), `0x200` `LEGACY_KEYSPEC` (uses AT_KEYEXCHANGE vs AT_SIGNATURE), `0x800` `USE_LEGACY_PROVIDER`.
- **EKU enforcement** via `pKIExtendedKeyUsage` OID array — `1.3.6.1.5.5.7.3.1` `serverAuth`, `1.3.6.1.5.5.7.3.2` `clientAuth`, `1.3.6.1.4.1.311.20.2.1` `smartCardLogon` (OID `1.3.6.1.4.1.311.20.2.2` for the `EnrollmentAgent` EKU is different), `1.3.6.1.4.1.311.21.6` `KRA` (Key Recovery Agent), `1.3.6.1.5.5.8.2.2` `IPSec`, etc.
- **Key usage** via `pKIKeyUsage` 2-byte bitmask — `0x80` `digital_signature`, `0x40` `non_repudiation`, `0x20` `key_encipherment`, `0x10` `data_encipherment`, `0x08` `key_agreement`, `0x04` `key_cert_sign`, `0x02` `crl_sign`, `0x01` `encipher_only`/`decipher_only`.
- **Basic Constraints** via `pKIMaxIssuingDepth` → `pathLenConstraint`.
- **Validity** via `pKIExpirationPeriod` / `pKIOverlapPeriod` (8-byte FILETIME structs).
- **ACL** via `nTSecurityDescriptor` with `Enroll` right (extended-right GUID `0e10c968-78d0-11d2-af90-00c04f990c33`) and `Autoenroll` right (extended-right GUID `a05b8cc2-17bc-4802-a710-e7c15ab866a2`).

Template versions: v1 (NT4/Win2000, no ACLs), v2 (Win2003, adds `nTSecurityDescriptor` ACL, full customization via CryptoAPI legacy CSP), v3 (Win2008, CNG-based `msPKI-Private-Key-Flag` for key isolation, KSP, Suite B algorithms, key attestation). `msPKI-Template-Schema-Version` (`1.2.840.113556.1.4.1499`) maps `1` = v2 template, `2` = v3 template. Per the same KB, supersession via `msPKI-Supersede-Templates` (multi-valued list of template `cn` values) drives autoenroll to purge superseded certs when `REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE` (`0x100` in `msPKI-Enrollment-Flag`) is set.

The complexity is operator-hostile. A single template misconfiguration (e.g., `msPKI-Certificate-Name-Flag` set to `0x1` `ENROLLEE_SUPPLIES_SUBJECT` on a smart-card template) can allow a user to request a cert with arbitrary subject, escalating privileges. The ACL model is fragile: removing `Authenticated Users` from a template's ACL is the most common cause of `0x80094012 — The permissions on the certificate template do not allow the current user to enroll`. macOS MDM SCEP profiles encode a subset of this (SubjectName, KeyUsage, ExtendedKeyUsage) but no ACL model; FreeIPA Dogtag profiles use `.cfg` files with `policyset` stanzas replacing `msPKI-*` attributes and `auth.class_id` replacing the template ACL.

Workshop Decision 8 §5 specifies the framework's answer: declarative YAML profiles in `cert-profiles.yaml` replace AD CS templates. This ADR defines the profile schema, the ACL model, the migration from AD CS templates, and the ADMX-to-profile compiler integration.

## Decision

The framework replaces AD CS certificate templates with declarative YAML profiles in `cert-profiles.yaml`. Profiles are version-controlled in Git (per ADR-031's pattern), validated by the framework's `adrian-ca profile validate` CLI, applied atomically (per ADR-025's transactional pattern), and consumed by the ACME server (per ADR-095) for cert issuance.

### Concrete specification

1. **`cert-profiles.yaml` schema.** Per Decision 8 §5, each profile is a YAML document:
   ```yaml
   profiles:
     - name: machine
       slug: machine
       validity_days: 365
       key_algorithms: [rsa-2048, ecdsa-p256, ed25519]
       key_usages: [digital_signature, key_encipherment]
       extended_key_usages: [client_auth, server_auth]
       subject:
         cn: "{{ host.dns_name }}"
         san_dns: ["{{ host.dns_name }}"]
         san_upn: null
         san_spn: null
       issuance_policy:
         require_eab: true
         require_attestation: true
         max_validity_days: 730
       name_constraints:
         permitted_dns: ["{{ domain }}"]
       ntauth_member: true
       archival_required: false
       acl:
         enroll_groups: ["{{ host.enroll_group }}"]
         autoenroll_groups: ["{{ host.enroll_group }}"]
       supersede_templates: []
       coverage_report: true
   ```
   The profile's fields map to AD CS template attributes:
   - `validity_days` → `pKIExpirationPeriod` (converted from days to FILETIME).
   - `key_algorithms` → `msPKI-Private-Key-Flag` algorithm bits (RSA 2048 → legacy CSP; ECDSA P-256 → CNG KSP; Ed25519 → CNG KSP with `REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM`).
   - `key_usages` → `pKIKeyUsage` 2-byte bitmask.
   - `extended_key_usages` → `pKIExtendedKeyUsage` OID array (translated from mnemonic names to OIDs via a bundled table).
   - `subject.{cn, san_dns, san_upn, san_spn}` → `msPKI-Certificate-Name-Flag` bits (`san_dns` → `SUBJECT_ALT_REQUIRE_DNS_AS_CN`; `san_upn` → `SUBJECT_ALT_REQUIRE_UPN`; `san_spn` → `SUBJECT_ALT_REQUIRE_SPN`).
   - `issuance_policy.{require_eab, require_attestation, max_validity_days}` → ACME-server-side enforcement (no `msPKI-*` equivalent; this is framework-native).
   - `name_constraints` → `NameConstraints` X.509 extension (RFC 5280 §4.2.1.10).
   - `ntauth_member` → whether the issuing CA is added to `LogonAuthorizedCAs` (per ADR-099), enabling PKINIT smart-card logon for certs issued under this profile.
   - `archival_required` → `msPKI-Private-Key-Flag` bit `REQUIRE_PRIVATE_KEY_ARCHIVAL` (invokes the KRA per ADR-032).
   - `acl.{enroll_groups, autoenroll_groups}` → `nTSecurityDescriptor` with `Enroll` and `Autoenroll` extended rights granted to the listed groups (translated from group UUIDs/SIDs to `nTSecurityDescriptor` ACEs).
   - `supersede_templates` → `msPKI-Supersede-Templates` (drives autoenroll to purge superseded certs when `REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE` is set).
   - `coverage_report` → whether to emit per-issued-cert coverage reports (for audit).

2. **Template variables (`{{ host.* }}`, `{{ domain }}`).** Profile fields support Jinja2-style template variables resolved at cert-issuance time against the host's directory object. `{{ host.dns_name }}` resolves to the host's `dNSHostName` attribute; `{{ host.enroll_group }}` resolves to the host's `enrollGroup` attribute (a per-host group set by the framework's host-enrollment workflow, per Decision 11); `{{ domain }}` resolves to the host's domain DNS name. The template variables enable per-host cert subject construction without per-host profile authoring — a single `machine` profile serves all hosts in the domain, with each host's cert subject derived from its directory attributes.

3. **Profile validation.** The `adrian-ca profile validate <file>` CLI validates each profile against the framework's JSON Schema for `cert-profiles.yaml`. Validation rules:
   - `key_algorithms` must be a non-empty subset of `{rsa-2048, rsa-3072, rsa-4096, ecdsa-p256, ecdsa-p384, ed25519}`.
   - `key_usages` must be a non-empty subset of `{digital_signature, non_repudiation, key_encipherment, data_encipherment, key_agreement, key_cert_sign, crl_sign}`.
   - `extended_key_usages` must be a non-empty subset of `{server_auth, client_auth, code_signing, email_protection, time_stamping, ocsp_signing, smartcard_logon, kra, ipsec, eap_over_lan}`.
   - `validity_days` must be ≤ `issuance_policy.max_validity_days` (the max is a deployment-wide ceiling).
   - `subject.cn` must not be null (the cert must have a CN).
   - `acl.enroll_groups` must be a non-empty list (the profile must grant enroll rights to at least one group; this prevents the `0x80094012` error caused by an empty ACL).
   - `ntauth_member: true` requires `extended_key_usages` to include `smartcard_logon` or `client_auth` (PKINIT requires client-auth EKU).
   - `archival_required: true` requires the KRA to be configured (per ADR-032); validation fails if no KRA cert is installed.

4. **Profile application.** The `adrian-ca profile apply <file>` CLI applies a `cert-profiles.yaml` file to the CA. Application is atomic (per ADR-025's transactional pattern): the CLI reads the current profile set from the CA's PostgreSQL database, computes the diff (additions, modifications, deletions), applies the diff in a single PostgreSQL transaction, and commits. On failure, the transaction rolls back. The CLI emits a diff report listing the changes for audit.

5. **AD-interop via synthesised AD CS template objects.** For AD-interop with existing Windows `autoenroll.dll` clients (per ADR-095 §2), the MS-WCCE bridge serves profile metadata via MS-XCEP (CEP) SOAP responses. The bridge translates framework profiles to AD CS template-equivalent SOAP elements (`<OID>`, `<FriendlyName>`, `<ValidityPeriod>`, `<RenewalPeriod>`, `<EnrollmentFlags>`, `<PrivateKeyFlags>`, `<KeyUsage>`, `<ExtendedKeyUsage>`, `<SubjectNameFlags>`). The translation is one-way (framework profile → CEP SOAP); the bridge does not expose framework profiles as `pKICertificateTemplate` AD objects (the framework's directory is not AD). Windows `autoenroll.dll` consumes the CEP SOAP response and constructs the PKCS#10 CSR accordingly.

6. **Migration from AD CS templates.** The `adrian-migrate from-adcs` CLI walks an AD CS server's template list (via `certutil -catemplates` or LDAP query of `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<forest-root>`), translates each v1/v2/v3 template to a framework profile, and emits `cert-profiles.yaml` for review and commit. The translation:
   - `msPKI-Certificate-Name-Flag` bitmask → `subject.{cn, san_dns, san_upn, san_spn}` flags.
   - `msPKI-Private-Key-Flag` bitmask → `key_algorithms` (with `REQUIRE_ATTESTATION` → `require_attestation: true`) and `archival_required`.
   - `pKIExtendedKeyUsage` OID array → `extended_key_usages` mnemonic list (translated via a bundled OID-to-mnemonic table).
   - `pKIKeyUsage` 2-byte bitmask → `key_usages` mnemonic list.
   - `pKIMaxIssuingDepth` → `name_constraints` (if applicable) or ignored (framework profiles do not enforce `pathLenConstraint` directly; the issuing CA cert's `BasicConstraints` provides the constraint, per ADR-037).
   - `pKIExpirationPeriod` / `pKIOverlapPeriod` FILETIME → `validity_days`.
   - `nTSecurityDescriptor` ACEs (with `Enroll` and `Autoenroll` extended-right GUIDs) → `acl.{enroll_groups, autoenroll_groups}` (resolved from SIDs to group UUIDs via the framework's directory).
   - `msPKI-Supersede-Templates` → `supersede_templates`.
   
   Complex `msPKI-*` attributes with no framework equivalent are dropped with `WARN` and recorded in the migration report. The `adrian-migrate from-adcs` CLI also generates `template-map.yaml` (per ADR-095 §2), which maps the original AD CS template OIDs to framework profile slugs (the MS-WCCE bridge uses this mapping to translate incoming MS-WCCE requests to ACME orders).

7. **ADMX-to-profile compiler integration.** Per Decision 7 §3, the ADMX-to-JSON compiler (`admx2adrian`, per ADR-090) translates AD CS ADMX-defined policy settings to framework policy. The cert-profiles schema is separate from the ADMX compiler (profiles are not ADMX-driven); however, the framework's `CertAutoenroll` PolicyArea (per Decision 7 §Cross-capability dependencies) is a policy area that references cert profiles by slug. The `CertAutoenroll` area's settings include `profile_slug` (the cert profile to enroll), `renewal_window` (when to renew, default 2/3 of validity), and `key_store` (the platform-native key store: CNG KSP on Windows, Keychain on macOS, `systemd`-managed keyring or `/etc/adrian/keys/` on Linux).

## Rationale

Three alternatives were considered (per Decision 8 §5 and §Rationale).

**Alternative A: Preserve `msPKI-*` attributes for AD interop; add a higher-level JSON wrapper.** Keep `msPKI-*` attributes as the canonical template representation; add a JSON wrapper that translates to/from `msPKI-*` at the boundary. Rejected because (a) `msPKI-*` attributes are AD-implementation-shaped (the bitmasks `msPKI-Certificate-Name-Flag` and `msPKI-Private-Key-Flag` encode AD-specific semantics that don't translate to macOS MDM or Linux `certmonger`); (b) the `nTSecurityDescriptor` ACL model is AD-specific (Windows SDDL with extended-right GUIDs); preserving it requires the framework to maintain SDDL parsing and AD-ACL semantics, defeating the framework's cross-platform goal; (c) the `msPKI-*` complexity is the root cause of PC-058 — preserving it preserves the operator-hostile complexity; (d) the framework's directory is not AD (per Decision 1), so storing `msPKI-*` attributes as native directory attributes would require the framework to maintain AD-schema-compatible attributes for AD-interop only. Decision 8 §5 replaces `msPKI-*` with declarative YAML explicitly.

**Alternative B: Adopt Dogtag's `.cfg` profile format directly.** Use FreeIPA/Dogtag's `.cfg` profile format with `policyset` stanzas as the framework's profile representation. Rejected because (a) Dogtag's `.cfg` format is Java-properties-file-shaped (key=value pairs with no nesting, no arrays, no comments), which is less expressive than YAML for the framework's profile schema (which has nested `subject`, `issuance_policy`, `name_constraints`, `acl` objects); (b) Dogtag's `policyset` stanzas encode policy logic in the profile (e.g., `policyset.serverCertSet.1.default.class_id=subjectNameDefaultImpl`), coupling the profile to Dogtag's Java policy implementation; the framework's profiles are declarative (data, not code); (c) Dogtag's `caacl` (CA Access Control List) is separate from the profile (in `.cfg`), forcing operators to manage two files per profile; the framework's `acl` field integrates the ACL into the profile for single-file authoring.

**Alternative C: Single JSON template schema with ACL projection to AD (and translation for Dogtag).** Use a JSON template schema (similar to the chosen YAML) but project to AD `msPKI-*` attributes for AD-interop and translate to Dogtag `.cfg` for FreeIPA interop. Rejected because (a) the framework does not project to AD `msPKI-*` attributes (per Alternative A rejection — the framework's directory is not AD); (b) the framework does not translate to Dogtag `.cfg` (per Decision 12 §1 — SSSD is the primary Linux tier, not FreeIPA; FreeIPA is a supported alternative via cross-realm trust, not via template translation); (c) YAML is preferred over JSON for human authoring (per ADR-029's rejection of JSON for human authoring — though ADR-029 selects JSON for the policy format, profiles are operator-authored less frequently than policies and benefit from YAML's comments and readability).

The chosen model — declarative `cert-profiles.yaml` with template variables, validation, atomic application, and migration from AD CS — gives the framework: (a) a modern, declarative profile format (replacing the operator-hostile `msPKI-*` bitmask model); (b) template variables for per-host subject construction without per-host profile authoring; (c) atomic application with diff reporting (replacing AD's `Set-CATemplate` with no rollback); (d) a migration path from AD CS templates via `adrian-migrate from-adcs`.

## Consequences

**Positive**. Profile authoring is operator-friendly (YAML with mnemonic names instead of `msPKI-*` bitmask constants). Template variables enable per-host subject construction without per-host profiles. Validation catches authoring errors before application. Atomic application with diff reporting provides audit. Migration from AD CS is supported via `adrian-migrate from-adcs`. The `acl` field integrates ACL into the profile (single-file authoring, vs. AD's separate `nTSecurityDescriptor`).

**Negative**. The MS-WCCE bridge must translate framework profiles to CEP SOAP responses (per §5) — a non-trivial translation that must track MS-XCEP schema revisions. The migration CLI cannot translate 100% of `msPKI-*` attributes (complex attributes with no framework equivalent are dropped with `WARN`); operators must review the migration report and manually adjust profiles for unsupported features. The framework's profile schema is not ADMX-driven (per §7); operators who maintain ADMX-defined AD CS policy settings must re-author the corresponding framework profiles.

**Neutral**. The framework's profile schema is YAML; operators who prefer JSON can use a YAML-to-JSON converter in their editor. The framework's `cert-profiles.yaml` is version-controlled in Git (per ADR-031); profile changes go through Git PR review (per ADR-031).

**Implementation cost**. ~3 person-weeks for v1 (per Decision 8 §Implementation impact, subsumed in the CA-core line item): YAML schema + validation (1 pw), profile application with atomic transaction (1 pw), migration CLI `adrian-migrate from-adcs` (1 pw). Ongoing maintenance: ~0.5 person-week per year for profile-schema evolution (semver-minor additions).

**Operational impact**. Operators author profiles via the framework's UI (which emits YAML) or via Git PR (YAML committed directly). The `adrian-ca profile validate` CLI catches authoring errors before commit. The `adrian-ca profile apply` CLI applies profiles atomically with diff reporting. The `adrian-ca profile list` CLI lists installed profiles; the `adrian-ca profile diff <file>` CLI previews the diff against the current installed profiles.

## Alternatives Considered

### Alternative A: Preserve `msPKI-*` attributes; add a JSON wrapper

Keep `msPKI-*` attributes as canonical; add a JSON wrapper that translates to/from `msPKI-*` at the boundary.

Rejected as detailed in §Rationale and Decision 8 §5: `msPKI-*` attributes are AD-implementation-shaped (bitmasks encode AD-specific semantics); the `nTSecurityDescriptor` ACL model is AD-specific; preserving `msPKI-*` preserves the operator-hostile complexity (the root cause of PC-058); the framework's directory is not AD.

### Alternative B: Adopt Dogtag's `.cfg` profile format directly

Use FreeIPA/Dogtag's `.cfg` profile format with `policyset` stanzas as the framework's profile representation.

Rejected as detailed in §Rationale: Dogtag's `.cfg` is Java-properties-file-shaped (less expressive than YAML); `policyset` stanzas couple the profile to Dogtag's Java policy implementation; Dogtag's `caacl` is separate from the profile (two-file authoring).

### Alternative C: Single JSON template schema with ACL projection to AD and translation for Dogtag

Use a JSON template schema but project to AD `msPKI-*` for AD-interop and translate to Dogtag `.cfg` for FreeIPA interop.

Rejected as detailed in §Rationale: the framework does not project to AD `msPKI-*` (the framework's directory is not AD); the framework does not translate to Dogtag `.cfg` (per Decision 12 §1, SSSD is the primary Linux tier, not FreeIPA); YAML is preferred over JSON for human authoring of profiles.

## Open Questions

- **Profile schema evolution.** The `cert-profiles.yaml` schema is versioned (`apiVersion: adrian/v1`). Schema evolution (adding new fields) is semver-minor; breaking changes (renaming or removing fields) require `adrian/v2`. The framework's `adrian-ca profile validate` CLI refuses to apply a profile with an unknown `apiVersion`. Revisit if a v2 schema is needed (no current driver).
- **Profile inheritance.** Should profiles support inheritance (a `parent` field that inherits settings from a parent profile, with overrides)? AD CS does not support template inheritance; the framework's profiles are flat. Current decision: no inheritance; operators who want shared settings use YAML anchors (`&base` / `*base`) in `cert-profiles.yaml`. Revisit if operators report duplication across profiles.
- **Profile-level key-attestation enforcement.** The `require_attestation: true` flag requires TPM2/SE attestation for cert issuance. Should the profile specify the attestation root (e.g., a specific TPM manufacturer's EK root CA)? Current decision: the attestation root is deployment-wide (configured at the CA level, not per-profile); profiles only specify whether attestation is required. Revisit if customers need per-profile attestation roots.

## Cross-capability impact

- **Cert Service (PC-057 enrollment)**: ADR-095's ACME server and MS-WCCE bridge consume framework profiles; the MS-WCCE bridge translates profiles to CEP SOAP responses.
- **Cert Service (PC-059 autoenroll)**: ADR-097's framework Client SDK cert enrollment module reads the host's profile assignments from the directory and enrolls via ACME against the framework's CA.
- **Cert Service (PC-060 KRA)**: ADR-032's HSM-bound KRA is invoked for `archival_required: true` profiles.
- **Cert Service (PC-067 NTAuthCertificates)**: ADR-099's `LogonAuthorizedCAs` directory attribute is populated based on each profile's `ntauth_member: true` flag.
- **Policy Engine (Decision 7)**: The `CertAutoenroll` PolicyArea (per Decision 7 §Cross-capability dependencies) references cert profiles by slug; the canonical JSON's `secret_ref` type carries the host's enrollment secret.
- **Migration (PC-127 AD CS-to-framework)**: The `adrian-migrate from-adcs` CLI is the migration entry point for AD CS templates; it generates `cert-profiles.yaml` and `template-map.yaml` from the AD CS server's template list.
- **Operations (PC-115 unified CLI)**: The `adrian-ca profile {validate, apply, list, diff}` CLI subcommands are part of the framework's unified CLI.

## References

- [PC-058](../catalog/05-cert-service.md) — problem statement in the catalog
- [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §5 — declarative `cert-profiles.yaml` specification
- [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md) — Full `msPKI-*` attribute table, v1/v2/v3 schema differences, ACL extended-right GUIDs, supersession model
- [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md) — AD CS architecture, policy/exit modules, template-driven issuance
- [ADR-025](./ADR-025-transactional-policy-rollback.md) — Transactional policy application (atomic profile application)
- [ADR-031](./ADR-031-git-backed-policy-history.md) — Git-backed policy history (profiles are version-controlled in Git)
- [ADR-032](./ADR-032-hsm-bound-kra-shamir.md) — HSM-bound KRA (invoked for `archival_required: true` profiles)
- [ADR-037](./ADR-037-two-tier-ca-hsm-root.md) — Two-tier CA with HSM-bound root (profiles are issued by the issuing CA)
- [ADR-095](./ADR-095-acme-primary-mswcce-bridge.md) — ACME-primary cert enrollment with MS-WCCE bridge (consumes framework profiles)
- [ADR-099](./ADR-099-ntauthcertificates-pkinit-trust.md) — NTAuthCertificates PKINIT trust (consumes `ntauth_member` flag)
- [RFC 5280 X.509](https://www.rfc-editor.org/rfc/rfc5280) — KeyUsage (§4.2.1.3), ExtendedKeyUsage (§4.2.1.12), BasicConstraints (§4.2.1.9), NameConstraints (§4.2.1.10)
- [`serde_yaml` crate](https://docs.rs/serde_yaml) — Rust YAML parser/serializer used by the profile CLI
