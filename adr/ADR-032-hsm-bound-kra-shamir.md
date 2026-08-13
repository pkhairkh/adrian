---
title: "ADR-032: HSM-bound KRA keys; Shamir secret sharing M-of-N"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-060
severity: high
tags: [adr, cert-service, kra, hsm, shamir, key-archival]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../docs/05-pki-certs/03-autoenrollment.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ./ADR-037-two-tier-ca-hsm-root.md
last_updated: 2026-08-13
---

# ADR-032: HSM-bound KRA keys; Shamir secret sharing M-of-N

## Status

Accepted — 2026-08-13.

## Context

When `msPKI-Private-Key-Flag.REQUIRE_PRIVATE_KEY_ARCHIVAL` (bit `0x8`) is set on a certificate template, the CSR is wrapped with the CA's Key Recovery Agent (KRA) certificate(s) per RFC 2511 (CMS `EnvelopedData`): AES-256 content key + RSA-OAEP wrap with the KRA cert's RSA public key, per [docs/05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md). The CA's `certca.dll!KRAArchiveRequest` decrypts the envelope using the KRA private key (only after operator-initiated recovery via `certutil -recoverkey`), then stores the original private key in the `KeyRecoveryTable` row linked to the issued certificate's `CertificateHash`. KRA certificates are published to AD at `CN=KRAContainer,CN=Public Key Services,CN=Services,CN=Configuration,...`. The CA reads them at service start; the registry value `HKLM\...\CertSvc\Configuration\<CA>\KeyRecoveryAgentCount` (default 1) controls how many KRAs are needed for quorum.

Per [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), the failure mode is binary: if KRA private keys are lost, all archived keys are unrecoverable. The recovery flow requires `certutil -recoverkey` with the KRA cert + private key, then operator approval via the CA console (`certsrv.msc` → "Key Recovery Agent" → "Recover Key"). If the KRA cert expires or its private key is destroyed (e.g., HSM failure without backup), every cert issued under the archival-required template becomes unrecoverable.

The single-KRA default (`KeyRecoveryAgentCount = 1`) is operationally risky: there is no quorum, no redundancy, no rotation procedure baked in. Multi-KRA with quorum (N-of-M) requires the CA to use multiple KRA certs and require N to recover — but AD CS does not natively support Shamir secret sharing or multi-party recovery. KRA cert rotation requires re-issuing all archived keys (or keeping old KRA certs valid forever, defeating rotation), per [PC-060](../catalog/05-cert-service.md).

For the framework, HSM-backed KRA private keys + multi-KRA quorum (N-of-M via Shamir secret sharing) is the right design. KRA cert rotation should be transparent (re-wrap archived keys under new KRA without re-enrolling users). The framework must support multiple KRAs with quorum, transparent KRA cert rotation, HSM-backed KRA private keys (CNG KSP / PKCS#11), and for AD interop must honor `REQUIRE_PRIVATE_KEY_ARCHIVAL` template flag and `KeyRecoveryAgentCount` registry.

## Decision

The framework shall bind KRA private keys to an HSM and shall use Shamir secret sharing (M-of-N) for multi-party key recovery.

1. **HSM-bound KRA private keys** — KRA private keys are generated inside and never leave the HSM (CNG KSP on Windows, PKCS#11 on Linux). The framework supports all HSMs that implement CNG KSP or PKCS#11: SoftHSM (development), Thales Luna, Utimaco SecurityServer, AWS CloudHSM, Azure Managed HSM. KRA private key operations (decrypt the CMS `EnvelopedData` envelope) are performed inside the HSM; the unwrapped content key (AES-256) is returned to the framework for storage in the `KeyRecoveryTable`.
2. **Multi-KRA with quorum (M-of-N)** — the framework uses Shamir secret sharing to split the content key into N shares, with M required to reconstruct. The split happens inside the HSM (the HSM's `GenerateKRAShares` operation, exposed via PKCS#11 `C_GenerateKRAShares` extension or vendor-specific API). Each share is wrapped with a different KRA cert's public key and stored separately in the `KeyRecoveryTable`. Recovery requires M of the N KRA private keys to be present (each performs an HSM-bound decryption of its share), and the HSM reconstructs the content key from the M shares.
3. **Default quorum** — N=5 KRA certs, M=3 required to recover. This is the same default as HashiCorp Vault's auto-unseal and provides tolerance for 2 KRA key losses. Operators can configure N and M at CA install time; changing N or M requires re-wrapping all archived keys (see transparent rotation below).
4. **Transparent KRA cert rotation** — when a KRA cert is rotated (renewed or replaced), the framework re-wraps all archived content keys under the new KRA cert set. The re-wrap is performed inside the HSM: the old KRA private key decrypts the content key (via quorum if M-of-N), the new KRA public keys re-wrap the content key. Users are not re-enrolled; the rotation is invisible to cert holders. Rotation is a framework CLI: `adrian-ca kra-rotate --old-kra <cert-id> --new-kra <cert-id>`.
5. **KRA recovery workflow** — recovery is a multi-step process: (a) operator initiates recovery via `adrian-ca recover-key --cert <cert-id> --reason "<audit-reason>"`; (b) the framework contacts M of the N KRA holders (each KRA holder is a separate human with access to a KRA HSM partition); (c) each KRA holder authenticates to their HSM partition and approves the recovery (the HSM performs the share decryption); (d) the framework reconstructs the content key inside the HSM, decrypts the archived private key, and returns it to the operator (encrypted to the operator's public key for secure delivery). All steps are audit-logged.
6. **AD interop** — for AD-authored templates with `REQUIRE_PRIVATE_KEY_ARCHIVAL`, the framework honors the flag and performs archival. The framework publishes KRA certs to AD at `CN=KRAContainer,CN=Public Key Services,CN=Services,CN=Configuration,...` (same location as AD CS), so `certutil -viewstore` shows them. The framework's `KeyRecoveryAgentCount` registry value is set to M (the quorum size), so AD CS clients see the correct quorum.
7. **Storage** — archived keys are stored in the framework's CA database (per ADR-034) in the `KeyRecoveryTable`. Each row contains: `CertificateHash` (foreign key to issued cert), `EncryptedContentKeyShares` (N shares, each wrapped with a different KRA cert's public key), `KRAQuorumConfig` (M, N), `ArchivalTimestamp`, `ArchivedBy`.

**Concrete specification**:

- The framework's CA installer prompts for HSM configuration (KSP/PKCS#11 provider, partition, PIN) and KRA quorum configuration (N, M).
- The CA generates N KRA keypairs inside the HSM at install time; each KRA cert is valid for 5 years (configurable).
- KRA certs are published to AD `CN=KRAContainer` and to the framework's CA database `KRARegistry` table.
- On cert issuance with `REQUIRE_PRIVATE_KEY_ARCHIVAL`, the CA: (a) generates a random AES-256 content key inside the HSM, (b) splits the content key into N shares via Shamir secret sharing (threshold M) inside the HSM, (c) wraps each share with a different KRA cert's RSA public key, (d) stores the N wrapped shares in `KeyRecoveryTable`.
- The `adrian-ca recover-key` CLI: takes `--cert <cert-id>`, `--reason "<audit-reason>"`, `--operator-key <pubkey-file>` (the operator's public key for encrypted delivery). The CLI blocks until M KRA holders approve.
- KRA holders approve via `adrian-ca kra-approve --recovery-id <id> --hra-partition <partition>` (the CLI contacts the HSM partition and performs the share decryption).
- The framework's audit log records: recovery initiation (who, when, reason), KRA approvals (which holders approved, when), recovery completion (which shares were used).
- KRA rotation: `adrian-ca kra-rotate --old-kra <cert-id> --new-kra <cert-id>` re-wraps all archived keys; the CLI reports progress (N rows re-wrapped) and completion time.

## Rationale

Three alternatives were considered.

**Alternative 1: Single KRA with HSM (no quorum).** HSM protects the KRA private key; recovery requires a single KRA holder. Rejected because a single KRA holder is a single point of trust — a malicious or coerced KRA holder can recover any archived key without oversight. Quorum (M-of-N) requires collusion of M holders, dramatically reducing insider-threat risk.

**Alternative 2: Multi-KRA without Shamir (each KRA wraps the full content key).** Each KRA cert wraps the full content key; recovery requires any 1 of the N KRA private keys. Rejected because this reduces to single-KRA security (any 1 KRA holder can recover) while adding operational complexity (N KRA certs to manage). Shamir secret sharing enforces true M-of-N: M holders must cooperate, no fewer.

**Alternative 3: External key management (AWS KMS, Azure Key Vault HSM).** Use a cloud KMS to manage KRA keys; the framework calls the KMS API to decrypt. Rejected because (a) cloud KMS does not support Shamir secret sharing natively (AWS KMS supports key policies with multiple principals but not M-of-N cryptographic quorum), (b) cloud KMS introduces a cloud dependency and cost-per-operation pricing that compounds for high-volume archival, (c) cloud KMS does not support air-gapped deployments. HSM-bound KRA with Shamir works on-prem and in-cloud, with no per-operation cost.

The decision aligns with industry practice: HashiCorp Vault uses Shamir secret sharing for auto-unseal (M-of-N key shares); Thales and Utimaco HSMs support M-of-N quorum natively via their vendor APIs; the U.S. federal PKI requires M-of-N quorum for KRA keys (per NIST SP 800-57). The framework's design is the same shape.

Cost: ~6 person-weeks for the HSM integration (CNG KSP + PKCS#11), the Shamir secret sharing implementation, the recovery workflow, and the KRA rotation tooling. The Shamir implementation is the highest-risk item (cryptographic correctness must be verified; use a vetted library like `secrets` in Rust or `crypto/secretsharing` in Go).

## Consequences

**Positive**. KRA key loss is no longer catastrophic — M-of-N quorum tolerates up to N-M KRA key losses. Insider threat is reduced — M KRA holders must cooperate to recover a key. Transparent KRA rotation means certs do not need re-enrollment when KRA certs rotate. HSM-bound KRA keys are immune to host compromise (the private key never leaves the HSM). AD interop is preserved (KRA certs published to the same AD location; `KeyRecoveryAgentCount` registry honored).

**Negative**. The M-of-N recovery workflow is operationally heavier than single-KRA recovery — M KRA holders must be available and approve. For urgent recovery (e.g., recovering an executive's S/MIME key on a deadline), coordinating M holders can take hours. HSM cost is real — production HSMs (Thales Luna, Utimaco) cost $10K-$50K; SoftHSM is free but not FIPS-certified. The Shamir secret sharing implementation must be cryptographically vetted; using an unvetted implementation is a security risk.

**Neutral**. The default N=5, M=3 quorum is configurable; high-security deployments may use N=7, M=5. The KRA rotation workflow is non-trivial (re-wrapping all archived keys) but is a rare operation (every 5 years, when KRA certs expire).

**Implementation cost**. ~6 person-weeks for HSM integration, Shamir, recovery workflow, and rotation tooling. HSM procurement (if not already owned) is a capital expense.

**Operational impact**. KRA holders are a new operational role (separate humans, each with access to a separate HSM partition). The recovery workflow is documented in the framework's runbook. KRA rotation is a planned maintenance window (the re-wrap is online but adds load to the HSM).

## Alternatives Considered

### Alternative A: Single KRA with HSM (no quorum)

Generate one KRA keypair inside the HSM; recovery requires the single KRA private key (held in the HSM). HSM access control (PIN, smart card) gates recovery.

Rejected because a single KRA holder is a single point of trust. A malicious or coerced KRA holder can recover any archived key without oversight — the HSM access control (PIN, smart card) does not prevent this, because the KRA holder is the legitimate user of the HSM. Quorum (M-of-N) requires collusion of M holders, dramatically reducing insider-threat risk. The marginal operational cost of M-of-N (coordinating M holders for recovery) is acceptable given the security gain.

### Alternative B: Multi-KRA without Shamir (each KRA wraps full content key)

Generate N KRA keypairs; each KRA cert wraps the full AES-256 content key. Recovery requires any 1 of the N KRA private keys. This is AD CS's native multi-KRA mode.

Rejected because this reduces to single-KRA security: any 1 KRA holder can recover any archived key, because each KRA holds a full wrap of the content key. The N KRA certs add operational complexity (N certs to manage, rotate, audit) without adding security over single-KRA. Shamir secret sharing enforces true M-of-N: M holders must cooperate to reconstruct the content key, no fewer. The cryptographic guarantee is stronger.

### Alternative C: External key management (AWS KMS, Azure Key Vault HSM)

Use a cloud KMS to manage KRA keys. The framework calls the KMS API (`Decrypt`) to unwrap the content key. KMS key policies with multiple principals provide access control.

Rejected because (a) cloud KMS does not support Shamir secret sharing natively — AWS KMS supports key policies with multiple principals (any principal with `kms:Decrypt` can decrypt), but not M-of-N cryptographic quorum (M of N principals must cooperate to decrypt); (b) cloud KMS introduces a cloud dependency (the framework cannot operate without internet connectivity to the KMS) and cost-per-operation pricing (AWS KMS charges $0.03 per 10K requests; for a high-volume archival CA issuing 100K certs/year with archival, this is $300/year — small but non-zero); (c) cloud KMS does not support air-gapped deployments (government, defense, regulated industries). HSM-bound KRA with Shamir works on-prem and in-cloud, with no per-operation cost, no cloud dependency, and full air-gap support.

## Open Questions

- Should the framework support a "standby KRA" mode where M-of-N shares are stored but only K of M (K<M) holders are required during business hours (faster recovery) and full M-of-N outside business hours (slower but more secure)? Current decision: no — quorum is fixed at M; revisit if operators report recovery-latency issues.
- The Shamir secret sharing implementation: should the framework use a vetted library (e.g., HashiCorp's `shamir` Go package, `secrets` Rust crate) or implement from scratch? Current decision: vetted library; cryptographic correctness is too critical to implement from scratch without external review.
- KRA holder authentication: should KRA holders authenticate to the HSM via PIN, smart card, or biometric? Current decision: smart card (the same smart cards used for admin logon per the framework's PIV/CAC support); revisit if HSMs without smart-card reader support are deployed.

## Cross-capability impact

- **Cert Service (PC-060)**: This ADR. PC-066 (CA topology, ADR-037) — KRA placement depends on CA topology; in a two-tier topology, KRA certs are on the issuing CA.
- **Cert Service (PC-062)**: ADR-034 (transactional CA DB) — the `KeyRecoveryTable` is part of the CA database; transactional DB with PITR protects archived keys.
- **Security (PC-116..PC-123)**: Insider threat mitigation is a Security concern; M-of-N quorum is documented in the Security threat model.
- **Migration (PC-124..PC-130)**: Migrating archived keys from AD CS to the framework requires re-wrapping under the framework's KRA certs; the migration tooling performs this via the AD CS `certutil -recoverkey` path.

## References

- [PC-060](../catalog/05-cert-service.md) — problem statement in the catalog
- [docs/05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md) — Key archival flow (Phase 4), KRA cert publication, `KeyRecoveryAgentCount` registry
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — KRA recovery procedure, `KeyRecoveryTable` schema, single-KRA default risk
- [RFC 2511 CMS](https://www.rfc-editor.org/rfc/rfc2511) — CMS `EnvelopedData` for key archival
- [Shamir Secret Sharing](https://dl.acm.org/doi/10.1145/359168.359176) — Shamir's original paper
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/final) — Key management recommendations (M-of-N quorum)
- [PKCS#11](https://docs.oasis.org/projects/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html) — HSM API standard
