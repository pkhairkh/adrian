---
title: "ADR-067: Sigstore Signing + in-toto Attestations for Supply-Chain Security"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-123
severity: medium
tags: [adr, security, supply-chain, sigstore, cosign, in-toto, rekor, slsa, reproducible-builds]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ./ADR-058-container-native-dcs-operator.md
  - ./ADR-063-unified-cross-platform-cli.md
last_updated: 2026-08-13
---

# ADR-067: Sigstore Signing + in-toto Attestations for Supply-Chain Security

## Status

Accepted — 2026-08-13

## Context

AD DCs receive security updates and feature updates via WSUS (Windows Server Update Services) or Microsoft Update. WSUS signs update packages with the Microsoft root certificate; the DC's Windows Update client (`wuaueng.dll`) verifies the signature before installing. The trust chain is: Microsoft root CA → Microsoft Update signing cert → update package signature. Compromise of WSUS = malicious updates pushed to all DCs in the org.

The threat is not theoretical. In 2021, the SolarWinds Sunburst attack demonstrated a software supply-chain compromise where the vendor's build pipeline was compromised, malicious code was signed with the vendor's legitimate signing cert, and the update was pushed to ~18,000 customers including US government agencies. The same attack pattern against the framework's build pipeline (or against a self-hosted registry) would compromise every framework DC.

The framework's binary distribution must support stronger supply-chain verification than AD's WSUS model. The cross-platform angle: WSUS is Windows-only. macOS DCs (theoretical) would receive updates via Apple Software Update, signed with Apple's root. Linux DCs would receive updates via the distro's package manager (apt, dnf, zypper), signed with the distro's GPG key. Each platform has its own supply-chain trust model. The framework must define a unified update-verification policy that applies across platforms, with per-platform signing roots but a single framework-level verification step.

The constraint set: support signed updates (binary signature verification before install); support reproducible builds (third-party can verify binary matches source); support a transparency log (Rekor-style) for signing events; support a deny-by-default update policy (only allowlisted signatures install); work cross-platform (Windows: Authenticode; macOS: codesign; Linux: package-manager GPG).

## Threat model

**STRIDE classification**: Tampering, Elevation of privilege

**Attack vector** (step-by-step — WSUS compromise pattern):

1. Attacker compromises the WSUS infrastructure (either Microsoft's WSUS upstream, or the org's self-hosted WSUS server).
2. Attacker packages a malicious update (e.g. a Trojaned `lsass.exe` patch that exfiltrates password hashes) and signs it with the compromised WSUS signing cert.
3. The DC's Windows Update client receives the malicious update, verifies the signature (passes — attacker's cert is valid), and installs.
4. The Trojaned `lsass.exe` runs on every DC. On each password-change event, it exfiltrates the new hash to attacker C2.
5. Attacker collects hashes passively for weeks/months. Detects Domain Admin password change → DCSync using the harvested DA hash → full forest compromise.

SolarWinds pattern (build-pipeline compromise):

1. Attacker compromises the framework's build pipeline (CI/CD).
2. Attacker injects malicious code into a framework release.
3. The malicious release is signed with the framework's legitimate signing cert (because the CI/CD pipeline has signing access).
4. Customers install the signed release via the framework's update mechanism. Signature verification passes (cert is valid).
5. Malicious code runs on every framework DC.

**Known mitigations in AD**:
- WSUS signing cert is Microsoft-controlled; trust model is "trust Microsoft". No transparency log.
- Microsoft's Source Code Integrity (since 2023) requires code-signing transparency for some Windows components, but not all.
- Windows Defender Application Control (WDAC) can restrict which binaries run on a DC, but the policy is hard to author and DCs typically run with permissive WDAC.
- Microsoft's Secure Supply Chain (S2C2F) framework recommends: dependency verification, build-pipeline isolation, signing-key HSM storage, reproducible builds. Most orgs do not implement S2C2F.

**Residual risk in AD**:
- No transparency log: a maliciously signed update is indistinguishable from a legitimate one without external intelligence.
- Build-pipeline compromise is not detectable from the binary alone; the binary is signed with the legitimate cert.
- WDAC policies are per-org and rarely comprehensive; most DCs accept any Microsoft-signed binary.
- Reproducible builds are not available for AD binaries (closed source).
- Cross-platform trust is fragmented: WSUS for Windows, Apple Software Update for macOS, distro GPG for Linux — no unified framework-level verification.

## Decision

The framework signs all released artifacts (container images, binaries, packages, Helm charts) with Sigstore (`cosign`) using ephemeral keys whose certificates are recorded in the Rekor transparency log. Every release is accompanied by in-toto attestations documenting the build pipeline from source commit to released artifact, including the SLSA (Supply-chain Levels for Software Artifacts) provenance. The framework's operator verifies the signature and the in-toto attestations before installing any update; updates that fail verification are rejected by default (deny-by-default policy).

The framework's signing key is stored in an HSM (or KMS for cloud deployments); the CI/CD pipeline uses OIDC-bound short-lived signing certificates (Sigstore's keyless signing) instead of long-lived signing keys. Each signing event is recorded in Rekor (https://rekor.sigstore.dev), a public append-only transparency log; organisations can monitor Rekor for their framework's signing events and alert on unexpected signatures.

The framework's operator (per [ADR-058](./ADR-058-container-native-dcs-operator.md)) verifies the signature on every container image pull, every binary download, and every Helm chart deployment. The verification includes: (a) the Sigstore signature is valid, (b) the signing certificate was issued by the framework's OIDC provider (Sigstore Fulcio), (c) the signing event is in Rekor, (d) the in-toto attestations are present and valid, (e) the SLSA provenance level meets the configured threshold (default: SLSA Level 3).

For non-container artifacts (binaries for the unified CLI per [ADR-063](./ADR-063-unified-cross-platform-cli.md), packages for Linux distros), the framework uses platform-native signing (Authenticode for Windows, codesign for macOS, GPG for Linux packages) in addition to Sigstore. The platform-native signature is for OS-level verification (e.g. macOS Gatekeeper); the Sigstore signature is for framework-level verification (the operator's deny-by-default check).

**Concrete specification**:

- The framework's CI/CD pipeline MUST sign every released artifact with Sigstore `cosign sign --keyless` (OIDC-bound short-lived certificate from Fulcio).
- Every signing event MUST be recorded in Rekor (https://rekor.sigstore.dev or a self-hosted Rekor instance for air-gapped deployments).
- Every release MUST include in-toto attestations:
  - `cosign attest --predicate slsa-provenance.json --type slsaprovenance` (SLSA Level 3 provenance: source commit, build pipeline, build inputs, build outputs).
  - `cosign attest --predicate sbom.spdx.json --type spdxjson` (SBOM in SPDX format).
  - `cosign attest --predicate vuln-scan.json --type vuln` (vulnerability scan results at build time).
- The framework's operator MUST verify the signature on every container image pull:
  - `cosign verify --certificate-identity-regexp 'https://github.com/adrian/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com <image>`
- The operator MUST verify the in-toto attestations:
  - `cosign verify-attestation --type slsaprovenance --certificate-identity-regexp 'https://github.com/adrian/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com <image>`
- The operator MUST enforce a deny-by-default update policy: any artifact that fails signature verification, lacks required attestations, or has SLSA provenance below the configured threshold MUST be rejected.
- The operator MUST emit an audit event (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)) on every verification decision with attributes `adrian.supplychain.artifact`, `adrian.supplychain.signature_valid`, `adrian.supplychain.attestations_present`, `adrian.supplychain.slsa_level`, `adrian.supplychain.decision` (`install` | `reject`), and MITRE ATT&CK T1195 (Supply Chain Compromise) when the decision is `reject`.
- The framework MUST support reproducible builds: any third party can rebuild the binary from source and verify byte-equality with the released binary. The build pipeline documentation MUST specify the exact build environment (compiler version, OS, environment variables, build flags).
- The framework MUST ship an SBOM (Software Bill of Materials) in SPDX format with every release, listing all dependencies (direct and transitive) with their versions and source URLs.
- The framework MUST ship a vulnerability scan report with every release, listing all known vulnerabilities (CVEs) in the framework's dependencies at build time.
- For Windows binaries (the unified CLI per ADR-063), the framework MUST additionally sign with Authenticode (using the same HSM-bound signing key, exposed via a separate code-signing cert).
- For macOS binaries, the framework MUST additionally sign with `codesign` (Apple Developer ID) and notarize via Apple's notarization service.
- For Linux packages (`.deb`, `.rpm`), the framework MUST additionally sign with the framework's GPG key (the same key used for Sigstore's KMS backend, exposed via a separate GPG subkey).
- The framework MUST ship a `Rekor` monitoring tool that alerts on unexpected signing events (e.g. a signature by a non-framework OIDC identity, or a signature outside the normal release window).
- The framework MUST support air-gapped deployments: a self-hosted Rekor instance and a self-hosted Fulcio CA can be used instead of the public Sigstore infrastructure.

## Rationale

Sigstore (cosign + Rekor + Fulcio) is the CNCF sandbox project that has become the de facto standard for software supply-chain signing in 2026. It is used by Kubernetes, by major Linux distributions (Debian, Fedora), and by thousands of open-source projects. Choosing anything else (long-lived PGP keys, vendor-specific signing infrastructure) would be choosing a niche.

Keyless signing (OIDC-bound short-lived certificates) eliminates the long-lived signing key — the single biggest attack surface in traditional code-signing. The signing key exists only for the duration of the CI/CD job (typically a few minutes); it is generated in Fulcio on demand, used to sign, and then discarded. The certificate is recorded in Rekor for transparency. An attacker who compromises the CI/CD pipeline gets a short-lived key that is useless after the job ends.

Rekor (the transparency log) provides the tamper-evidence property. Every signing event is recorded in an append-only log; organisations can monitor the log for unexpected signatures (e.g. a signature by an unknown OIDC identity, or a signature at an unusual time). This is the same model as Certificate Transparency (RFC 6962) for TLS certificates.

in-toto attestations (SLSA provenance, SBOM, vulnerability scan) provide the build-pipeline integrity property. Even if the signing key is compromised, the attestations document what was built (source commit, build inputs, build outputs). An attacker who injects malicious code into the source cannot forge the SLSA provenance without compromising the build pipeline's attestation generation (which is a separate, hardened component).

SLSA Level 3 is the minimum threshold for supply-chain integrity in 2026. SLSA Level 3 requires: (a) build pipeline is hosted on a hardened platform, (b) build pipeline is isolated from the source, (c) build pipeline's provenance is generated by the platform (not the build script), (d) provenance is cryptographically signed. The framework's CI/CD pipeline (GitHub Actions, hardened runners) meets SLSA Level 3.

Reproducible builds are the gold standard for supply-chain verification. A third party can rebuild the binary from source and verify byte-equality, providing independent verification that the released binary matches the source. This is the strongest possible mitigation against build-pipeline compromise (the attacker must compromise both the build pipeline and the source repository, and the modifications must produce a byte-identical binary — which is computationally infeasible for non-trivial modifications).

Platform-native signing (Authenticode, codesign, GPG) is necessary because OS-level mechanisms (Windows SmartScreen, macOS Gatekeeper, Linux package-manager verification) require platform-native signatures. The Sigstore signature is for the framework's operator-level verification; the platform-native signature is for OS-level verification. Both are required.

The deny-by-default update policy is the security-critical default. The operator refuses to install any artifact that fails verification. This is the opposite of AD's WSUS model, where any Microsoft-signed update is installed. The framework's policy is "trust but verify"; the verification is mandatory.

## Consequences

**Positive**: Supply-chain attacks are detected and blocked by default. Build-pipeline compromise is detectable via in-toto attestations. Transparency log (Rekor) enables monitoring for unexpected signatures. Reproducible builds enable independent verification. SBOM and vulnerability scan enable downstream vulnerability management. Cross-platform consistency: the same Sigstore verification applies to Windows, macOS, and Linux artifacts.

**Negative**: The framework's CI/CD pipeline complexity increases (keyless signing, attestation generation, Rekor upload, reproducible builds). Build times increase by 10-30% (signing and attestation overhead). Air-gapped deployments require a self-hosted Rekor and Fulcio, adding infrastructure. The deny-by-default policy can block legitimate updates if the verification infrastructure (Rekor, Fulcio) is unavailable.

**Neutral**: The framework's Sigstore signing does not preclude other signing mechanisms (long-lived GPG keys, vendor-specific signing) via the operator's configurable verification policy. Sigstore is the default; other mechanisms are opt-in.

**Implementation cost**: ~2 person-months for the CI/CD pipeline integration (cosign, in-toto, Rekor upload); ~3 person-months for the operator verification logic (cosign verify, attestation verification, deny-by-default enforcement); ~2 person-months for the reproducible-build infrastructure (hermetic builds, build-environment documentation); ~2 person-months for the SBOM and vulnerability scan generation; ~1 person-month for the Rekor monitoring tool. Total: ~10 person-months for v1.

**Operational impact**: SREs see supply-chain verification as an operator-emitted audit event. SOC analysts see rejected-installation alerts with MITRE T1195 tags. Security teams monitor Rekor for unexpected signatures. The framework's runbook includes supply-chain incident response (revoke the signing identity, rebuild from a known-good source, force-rotate affected DCs).

## Alternatives Considered

**Alternative A: Long-lived GPG signing keys only.** Sign all artifacts with a long-lived GPG key stored in an HSM. Rejected because (a) long-lived keys are a high-value target (compromise of the key compromises all past and future releases until rotation), (b) GPG does not have a transparency log (no tamper-evidence), (c) GPG does not support build-pipeline attestation, (d) Sigstore's keyless model is strictly better for short-lived signing.

**Alternative B: Vendor-specific signing (Microsoft Authenticode, Apple codesign, Linux distro GPG) only.** Use the platform-native signing mechanisms without Sigstore. Rejected because (a) there is no unified framework-level verification (the operator would need separate verification logic per platform), (b) platform-native signing does not have a transparency log, (c) platform-native signing does not support build-pipeline attestation, (d) cross-platform consistency is lost.

**Alternative C: WSUS-style single-vendor trust (AD's model).** Trust the framework vendor's signing cert without transparency log or attestation. Rejected because (a) it is exactly the model that the SolarWinds attack bypassed, (b) it provides no defence against build-pipeline compromise, (c) it provides no transparency for monitoring, (d) the framework cannot in good conscience ship a less-secure supply chain than what is standard in 2026.

**Alternative D: S2C2F (Secure Supply Chain Consumption Framework) without Sigstore.** Implement Microsoft's S2C2F framework (dependency verification, build-pipeline isolation, signing-key HSM storage, reproducible builds) without adopting Sigstore. Rejected because S2C2F is a framework (a set of practices), not an implementation; Sigstore is the implementation that codifies S2C2F's practices. The two are complementary, not alternatives. The framework adopts Sigstore as the implementation and follows S2C2F practices for the surrounding processes.

## Open Questions

None — this is an ADR-ELIGIBLE decision. The framework's storage engine choice (PC-007 / Tier-1 ORQ-011/012/013/014) does not gate this decision: the supply-chain verification applies to all framework artifacts regardless of storage engine.

## Cross-capability impact

- **Operations (PC-109)**: ADR-058 (container-native DCs + operator) — the operator verifies container image signatures before pulling; the deny-by-default policy is enforced by the operator.
- **Operations (PC-110)**: ADR-059 (PITR backup + DR) — DR restores must verify binary signatures (a restore from a maliciously-modified backup must not bypass signature verification).
- **Operations (PC-115)**: ADR-063 (unified CLI) — the CLI binary is signed with Sigstore (and platform-native Authenticode/codesign/GPG); the operator verifies on install.
- **Core Directory (PC-007)**: Storage engine choice (deferred) — RocksDB/FoundationDB are open-source and reproducible-build-friendly; ESE is closed-source and not reproducible. The supply-chain verification applies to the framework's code, not to third-party dependencies (those are covered by the SBOM and vulnerability scan).
- **Migration (PC-126)**: Client switchover (PC-126, deferred) — the migration tooling must verify framework artifact signatures before deploying to client machines.

## References

- [PC-123](../catalog/11-security-threat-model.md) — problem statement (Supply-chain risk: signed AD updates require WSUS trust)
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — LSASS process model, DLL loading (`ntdsa.dll`, `kdcsvc.dll`, `esent.dll`), boot sequence — these are the binaries that must be supply-chain-verified
- [AD overview](../docs/00-overview/01-active-directory-overview.md) — DC service binaries and update mechanisms
- [Sigstore — cosign, Rekor, Fulcio](https://www.sigstore.dev/)
- [in-toto — framework for securing software supply chains](https://in-toto.io/)
- [SLSA — Supply-chain Levels for Software Artifacts](https://slsa.dev/)
- [SPDX — Software Package Data Exchange (SBOM format)](https://spdx.dev/)
- [CISQ — Cybersecurity Supply Chain Risk Management practices](https://www.cisa.gov/sites/default/files/publications/ESF_Securing_the_Software_Supply_Chain_Developers_PDF_10082021.pdf)
- [RFC 6962 — Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962) (the model for Rekor's transparency log)
- [MITRE ATT&CK T1195 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
