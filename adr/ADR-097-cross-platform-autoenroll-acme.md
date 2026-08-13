---
title: "ADR-097: Cross-platform autoenrollment via Client SDK ACME client + attestation (resolves PC-059)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-059
severity: high
unblocked_by: Workshop Decision 8
tags: [adr, cert-service, autoenroll, acme, attestation, tpm2, secure-enclave, keychain, cng-ksp, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../workshop/decision-08-pki-enrollment.md
  - ../docs/05-pki-certs/03-autoenrollment.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ./ADR-095-acme-primary-mswcce-bridge.md
  - ./ADR-096-cert-profile-yaml-replaces-templates.md
  - ./ADR-092-policy-executor-trait-synthetic-windows-cse.md
last_updated: 2026-08-14
---

# ADR-097: Cross-platform autoenrollment via Client SDK ACME client + attestation (resolves PC-059)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §6, which specifies that AD CS autoenrollment via `autoenroll.dll` CSE + GPO is replaced by the framework's Client SDK cert enrollment module — an ACME client that reads the host's profile assignments from the directory, runs an ACME order against the framework's CA (fulfilling `adrian-attest-01` via TPM2 quote on Windows/Linux or Apple Secure Enclave attestation on macOS), stores the issued cert and private key in the platform-native key store, and re-enrolls automatically at 2/3 of validity (RFC 8823 ARI preferred). This ADR operationalises Decision 8 §6's autoenroll specification against the PC-059 problem surface: the Windows-only nature of `autoenroll.dll` and the absence of cross-platform autoenroll.

## Context

Autoenrollment is the client-side `autoenroll.dll` invoked by Group Policy CSE `{71587597-1207-11D2-8250-00A0C903A8CB}` (registered at `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{71587597-...}` with `DllName = %SystemRoot%\system32\autoenroll.dll`), per [docs/05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md). The CSE is triggered by `gpsvc.dll` at every GP refresh (default 90 min + jitter), at logon/startup via `winlogon`, by Task Scheduler `\Microsoft\Windows\CertificateServicesClient\AutoEnroll`, or manually via `certutil -pulse`. Per [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md), the CSE exports `ProcessGroupPolicy`/`ProcessGroupPolicyEx`.

The flow: `autoenroll.dll` performs MS-XCEP policy discovery (CEP HTTPS POST to `/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP` with `<cep:GetPolicies>` SOAP envelope), filters policies by caller domain and EKU context, then submits CSRs over MS-WCCE (DCOM ICertPassage opnum 36) or MS-WSTEP (CES HTTPS SOAP wrapping PKCS#10 in `<wst:RequestSecurityToken>`). The CA's exit module publishes the issued cert to the requester's `userCertificate` AD attribute via `ldap_modify_s` with `LDAP_MOD_REPLACE`. Renewal triggers at 80% of cert lifetime (or per-template `pKIOverlapPeriod`).

macOS has no equivalent — MDM SCEP profile is per-device with no autoenroll trigger; re-enrollment on expiry requires MDM push or a `launchd` daemon. Linux uses `certmonger` with the `cepces` plugin (MS-WCCE/MS-XCEP client) or Dogtag/SCEP/EST. `certmonger` runs as a systemd service with per-cert timers; `getcert request -c dogtag -T <profile> -f <file> -k <file>` polls and renews. The Windows-only nature of `autoenroll.dll` and the per-platform fragmentation of macOS/Linux autoenroll creates a multi-tool management burden — operators maintain three different autoenroll stacks (one per platform) with different configuration models, different renewal triggers, and different key stores.

Workshop Decision 8 §6 specifies the framework's answer: the framework's Client SDK cert enrollment module is the ACME client on every platform, replacing `autoenroll.dll` on Windows, MDM SCEP push on macOS, and `certmonger` on Linux. This ADR defines the enrollment module's flow, the platform-native key store integration, the attestation challenge fulfillment, the renewal trigger, and the synthetic Windows CSE that preserves GPO-driven autoenroll invocation during migration.

## Decision

The framework's Client SDK cert enrollment module (`adrian-cert-enroll`) is the ACME client on every platform (Windows, macOS, Linux). The module reads the host's profile assignments from the directory (the host object's `certProfiles` attribute, set by the framework's `CertAutoenroll` PolicyArea per Decision 7), runs an ACME order against the framework's CA (per ADR-095), fulfills the `adrian-attest-01` challenge via TPM2 quote (Windows/Linux) or Apple Secure Enclave attestation (macOS), stores the issued cert and private key in the platform-native key store, and re-enrolls automatically at 2/3 of validity (per RFC 8823 ARI guidance).

### Concrete specification

1. **Module architecture.** `adrian-cert-enroll` is a Rust library (workspace member) that runs as part of the Client SDK daemon (`adrian-client-daemon`, per Decision 11). The module exposes a `CertEnroller` trait with methods:
   ```rust
   #[async_trait]
   pub trait CertEnroller: Send + Sync {
       async fn discover_profiles(&self, host_uuid: &Uuid) -> Result<Vec<ProfileAssignment>, EnrollError>;
       async fn enroll(&self, profile: &ProfileAssignment) -> Result<EnrolledCert, EnrollError>;
       async fn renew(&self, cert_id: &CertId) -> Result<EnrolledCert, EnrollError>;
       async fn list_enrolled(&self) -> Result<Vec<EnrolledCert>, EnrollError>;
       async fn revoke(&self, cert_id: &CertId, reason: RevocationReason) -> Result<(), EnrollError>;
   }
   ```
   The `CertEnroller` implementation is platform-specific (selected at build time via cargo features): `WindowsCertEnroller` (uses CNG KSP for key storage, TPM2 via TBS API for attestation), `MacOSCertEnroller` (uses Keychain for key storage, Secure Enclave via `DeviceCheck` API for attestation), `LinuxCertEnroller` (uses `systemd`-managed keyring or `/etc/adrian/keys/` for key storage, TPM2 via `tss2-esapi` for attestation).

2. **Profile discovery.** The module queries the framework's directory for the host object's `certProfiles` attribute (a multi-valued attribute listing profile slugs assigned to the host, set by the framework's `CertAutoenroll` PolicyArea per Decision 7). The directory query is via LDAP (per ADR-012 LDAP signing + channel binding). The module caches the profile assignments for 60 seconds (with event-driven invalidation via the WebSocket push per ADR-028 — the directory notifies the SDK daemon when the host's `certProfiles` attribute changes). The module emits a `ProfileDiscovery` audit event (per ADR-060) listing the discovered profiles.

3. **ACME enrollment flow.** For each assigned profile, the module runs an ACME order against the framework's CA (per ADR-095 §1):
   - **Account creation** (first-time only): The module creates an ACME account with EAB (per ADR-095 §1) using the host's EAB MAC key (provisioned during host enrollment by the framework's directory service). The account key is an ECDSA P-256 keypair stored in the platform-native key store (CNG KSP on Windows, Keychain on macOS, `systemd`-managed keyring on Linux). The account key is reused for all subsequent orders.
   - **Order creation**: The module creates an ACME order against the profile's URL path (`https://ca.<domain>/acme/directory/<profile-slug>`) with the requested SAN (derived from the host's `dNSHostName` directory attribute, per ADR-096 §2's `{{ host.dns_name }}` template variable).
   - **Authorization challenge**: The module fulfills the `adrian-attest-01` challenge (per ADR-095 §1) by generating a TPM2 quote (Windows/Linux) or Apple Secure Enclave attestation (macOS) signed by the host's attestation key (provisioned during host enrollment). The quote/attestation includes the ACME order's `thumbprint` as a nonce, binding the attestation to the specific order.
   - **Finalize**: The module generates a keypair in the platform-native key store (CNG KSP, Keychain, `systemd`-managed keyring) and creates a PKCS#10 CSR with the requested subject and SAN. The CSR is submitted as the ACME `finalize` payload.
   - **Certificate retrieval**: The module retrieves the issued cert from the ACME `certificate` endpoint and stores it in the platform-native key store alongside the private key. The module emits an `Enrolled` audit event with the cert's serial number, subject, SAN, EKU, validity, and profile slug.

4. **Attestation fulfillment.** The `adrian-attest-01` challenge (per ADR-095 §1) requires a hardware attestation that binds the ACME order to the host's hardware identity:
   - **Windows/Linux TPM2**: The module uses `tss-esapi = "0.5"` (Rust bindings to the TPM2 TSS C library) on Linux and `windows = "0.54"` (TBS API via `tbsi.dll`) on Windows. The module loads the host's attestation key (an RSA 2048 or ECDSA P-256 key generated in the TPM2 during host enrollment, with its public key registered with the framework's CA). The module generates a TPM2 quote over the ACME order's `thumbprint` (the quote includes the selected PCRs — by default PCR 7 for Secure Boot policy and PCR 11 for BitLocker-measured boot; operators can configure the PCR selection per profile). The quote is signed by the attestation key; the signed quote is submitted as the `adrian-attest-01` challenge payload. The CA verifies the quote's signature against the host's registered attestation root and verifies the PCR values against the host's expected measurements (per the framework's measured-boot policy).
   - **macOS Secure Enclave**: The module uses a Swift bridge (compiled as a static library, linked via `swift-bridge = "0.2"`) to call Apple's `DeviceCheck` API. The module generates an attestation token that includes the ACME order's `thumbprint` as a nonce. The token is signed by the Secure Enclave's attestation key (provisioned during host enrollment via MDM). The token is submitted as the `adrian-attest-01` challenge payload. The CA verifies the token's signature via Apple's attestation root CA (the framework's CA bundles Apple's DeviceCheck root certificates).

5. **Platform-native key store integration.** The module stores the issued cert and private key in the platform-native key store:
   - **Windows (CNG KSP)**: The module uses `windows = "0.54"` (`NCrypt*` API) to store the cert and key in the Microsoft Software Key Storage Provider (or a TPM-backed KSP if the profile's `require_attestation: true` flag is set). The cert is stored in the `Cert:\LocalMachine\My` certificate store; the key is stored in the KSP with `NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG` key-usage policy.
   - **macOS (Keychain)**: The module uses `security-framework = "2"` (Rust bindings to the macOS Security framework) to store the cert and key in the System Keychain (`/Library/Keychains/System.keychain`). The key is stored as a `SecKey` with `kSecAttrIsPermanent = true`; the cert is stored as a `SecCertificate` with `kSecAttrLabel = "<profile-slug>"`.
   - **Linux (systemd-managed keyring or `/etc/adrian/keys/`)**: The module uses `systemd = "0.10"` (D-Bus interface to `systemd`-managed keyring) on systems with `systemd` 250+; on older systems, the module stores the key in `/etc/adrian/keys/<profile-slug>.key` (mode 0600, owned by root) and the cert in `/etc/adrian/certs/<profile-slug>.crt` (mode 0644, owned by root). The cert is also installed into the system trust store (`/usr/local/share/ca-certificates/` on Debian/Ubuntu, `/etc/pki/ca-trust/source/anchors/` on RHEL/CentOS) for system-wide trust.

6. **Renewal trigger.** The module renews certs automatically at 2/3 of validity (e.g., a 365-day cert is renewed at day 243). The renewal timing is governed by RFC 8823 ARI (per ADR-095 §1): the module queries the CA's `renewalInfo` endpoint at every refresh (default 6 hours, configurable) and renews when the ARI indicates the renewal window is open. ARI's renewal window is randomized per-cert (to spread CA load); the module respects the ARI-recommended renewal time. On renewal, the module reuses the existing keypair (per RFC 8823 §5: "key rollover" — the same key is used for the renewed cert, simplifying trust-store updates) unless the profile's `key_renewal_policy: rotate` flag is set, in which case the module generates a new keypair for each renewal.

7. **Synthetic Windows CSE for GPO-driven autoenroll (migration period).** Per Decision 8 §6, on Windows the Client SDK additionally registers as an `autoenroll.dll`-compatible synthetic CSE (per ADR-024 + Decision 7 §6 + ADR-092 §5) so existing GPO-driven autoenroll policies continue to invoke the framework's enrollment path; the MS-WCCE bridge is bypassed for framework-enrolled Windows hosts and is only needed during migration. The synthetic CSE's GUID is registered at `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<framework-autoenroll-CSE-GUID>}` with `DllName = %ProgramFiles%\Adrian\adrian_cse.dll`. When `gpsvc.dll` invokes the synthetic CSE, the CSE calls the `CertEnroller::discover_profiles` method (which reads the host's `certProfiles` from the directory via the Client SDK) and enrolls via ACME (per §3). Legacy `autoenroll.dll` (the Microsoft CSE) is not removed; it continues to handle AD-enrolled Windows hosts (per ADR-095 §2 — the MS-WCCE bridge serves these hosts). Once all Windows hosts are migrated to the framework's Client SDK, the Microsoft `autoenroll.dll` CSE is no longer invoked (no GPO drives it) and the MS-WCCE bridge can be decommissioned (per ADR-095 §8).

8. **Key-based renewal for unattended hosts.** For unattended hosts (servers, IoT devices), the module supports key-based renewal: the renewed cert is authenticated using the old cert's private key (per MS-WSTEP's `msPKI-Certificate-Name-Flag` bit `0x4000000` for key-based renewal). The module submits the ACME renewal order with a `client_auth` EKU cert (the old cert) as the TLS client certificate for the ACME HTTPS connection; the CA verifies the old cert's chain to a trusted CA and the renewal is approved without re-attestation. This is essential for unattended hosts that cannot prompt for user credentials.

9. **`certmonger` compatibility (migration).** Per Decision 8 §Rust implementation implications, the framework ships `adrian-certmonger-compat` — a compatibility shim that exposes the framework's ACME enrollment to `certmonger` (Linux's standard cert enrollment daemon) via a `certmaster`-style plugin. Customers with existing `certmonger` deployments can keep using `certmonger` as the orchestration layer while the framework provides the CA backend. The shim translates `certmonger`'s `getcert request` invocations to `CertEnroller::enroll` calls. Customers who prefer the framework-native experience use `adrian-cert-enroll` directly (via the Client SDK daemon).

## Rationale

Three alternatives were considered.

**Alternative A: Preserve `autoenroll.dll` on Windows; ship `certmonger` on Linux; MDM SCEP on macOS.** Keep AD's autoenroll model on Windows (via the MS-WCCE bridge, per ADR-095); use `certmonger` with `cepces` on Linux for AD-interop and `certmonger` with a framework plugin for framework-interop; use MDM SCEP push on macOS. Rejected because (a) the framework's value proposition is unified policy across platforms — requiring three different autoenroll stacks (Windows `autoenroll.dll`, Linux `certmonger`, macOS MDM) defeats the unification; (b) `certmonger`'s per-cert-timer model does not scale to thousands of certs per host (each timer consumes a `systemd` unit, a D-Bus connection, and a `getcert` polling cycle); (c) MDM SCEP push requires MDM enrollment (per ADR-052) and cannot serve unenrolled macOS hosts; (d) the attestation challenge (`adrian-attest-01`, per ADR-095 §1) requires a framework-native ACME client — `certmonger` and `autoenroll.dll` cannot fulfill the attestation challenge without framework extensions.

**Alternative B: Use `certmonger` as the universal autoenroll daemon (all platforms).** Port `certmonger` to Windows and macOS; use `certmonger` as the framework's universal autoenroll daemon. Rejected because (a) `certmonger` is a C daemon designed for Linux (uses `systemd` for timers, D-Bus for IPC, NSS for cert storage); porting to Windows (which uses Service Control Manager, COM, CNG KSP) and macOS (which uses `launchd`, `XPC`, Keychain) is a multi-month project per platform with no upstream support; (b) `certmonger`'s plugin architecture is C-based and does not integrate with the framework's Rust core (per Decision 11); (c) `certmonger` does not support TPM2 attestation (per §4) without framework extensions — extending `certmonger` to support `adrian-attest-01` would require a custom `certmonger` plugin that duplicates the framework's attestation library.

**Alternative C: Drop autoenroll entirely; require operators to manually enroll certs.** Acknowledge that autoenroll is complex; tell operators to manually enroll certs via the framework's CLI. Rejected because (a) autoenroll is the most common AD CS use case (per PC-057) — dropping it blocks migration for the majority of AD CS customers; (b) manual enrollment does not scale to large fleets (10,000 hosts × 5 certs/host = 50,000 manual enrollments); (c) renewal without autoenroll requires operator intervention at every cert expiry (a 365-day cert on 10,000 hosts = ~27 renewals per day on average — a full-time job).

The chosen model — framework-native `adrian-cert-enroll` ACME client on every platform, with synthetic Windows CSE for migration-period GPO-driven invocation, and `certmonger` compatibility shim for existing Linux deployments — gives the framework: (a) unified autoenroll across platforms (one Rust module, three platform-specific key-store backends); (b) TPM2/SE attestation enforcement for machine-identity certs; (c) RFC 8823 ARI-driven renewal with staggered timing; (d) key-based renewal for unattended hosts; (e) `certmonger` compatibility for migration-period Linux deployments.

## Consequences

**Positive**. Operators author one `CertAutoenroll` policy (per Decision 7) that assigns cert profiles to hosts; the framework's enrollment module handles enrollment, renewal, and revocation across all platforms. TPM2/SE attestation ensures that machine-identity certs are only issued to enrolled hardware (closing the "anyone who can solve `http-01` can get a machine cert" gap). ARI-driven renewal staggers CA load. Key-based renewal serves unattended hosts. The synthetic Windows CSE preserves GPO-driven autoenroll during migration. The `certmonger` shim preserves existing Linux cert-orchestration deployments.

**Negative**. The module's platform-specific key-store backends (CNG KSP, Keychain, `systemd`-managed keyring) require per-platform testing and maintenance — the framework's CI tests cert enrollment on Windows Server 2022, macOS 14, and Ubuntu 22.04 on every PR. The TPM2 attestation integration depends on the host's TPM2 being provisioned with an attestation key during host enrollment — if the host's TPM2 is not provisioned (e.g., a VM without a virtual TPM), the `adrian-attest-01` challenge fails and the cert is not issued; operators must either provision a virtual TPM (per the hypervisor's documentation) or relax the profile's `require_attestation: true` flag (with `WARN` and audit-log entry). The macOS Secure Enclave attestation depends on the host being MDM-enrolled (per ADR-052) with the framework's attestation-root MDM profile installed.

**Neutral**. The module is part of the Client SDK daemon (per Decision 11); operators do not invoke the module directly — they author `CertAutoenroll` policy and the daemon handles enrollment. The `adrian-cert list` CLI (per ADR-063) shows the host's enrolled certs; the `adrian-cert revoke <cert-id>` CLI revokes a cert.

**Implementation cost**. ~6 person-weeks for v1 (per Decision 8 §Rust implementation implications, subsumed in the attestation-library and Client SDK line items): ACME client (2 pw), platform-native key-store integration (2 pw), TPM2/SE attestation integration (1.5 pw), synthetic Windows CSE for autoenroll (0.5 pw, subsumed in ADR-092's synthetic-CSE effort). Ongoing maintenance: ~1 person-week per year for platform-native key-store API evolution (CNG KSP, Keychain, systemd keyring).

**Operational impact**. Operators author `CertAutoenroll` policy via the framework's UI (which emits canonical JSON) or via Git PR. The `adrian-policy compile --target windows <file>` CLI previews the synthesised GPO that drives the synthetic Windows CSE. The `adrian-cert list` CLI shows the host's enrolled certs; the `adrian-cert renew --force <cert-id>` CLI forces immediate renewal (useful for testing).

## Alternatives Considered

### Alternative A: Preserve `autoenroll.dll` on Windows; ship `certmonger` on Linux; MDM SCEP on macOS

Keep AD's autoenroll model on Windows (via the MS-WCCE bridge); use `certmonger` with `cepces` on Linux; use MDM SCEP push on macOS.

Rejected as detailed in §Rationale: three different autoenroll stacks defeats unification; `certmonger` does not scale to thousands of certs per host; MDM SCEP push requires MDM enrollment; the attestation challenge requires a framework-native ACME client.

### Alternative B: Use `certmonger` as the universal autoenroll daemon (all platforms)

Port `certmonger` to Windows and macOS; use `certmonger` as the framework's universal autoenroll daemon.

Rejected as detailed in §Rationale: `certmonger` is Linux-specific (systemd, D-Bus, NSS); porting to Windows/macOS is multi-month per platform; `certmonger`'s C-based plugin architecture does not integrate with the framework's Rust core; `certmonger` does not support TPM2 attestation without framework extensions.

### Alternative C: Drop autoenroll entirely; require manual enrollment

Acknowledge that autoenroll is complex; tell operators to manually enroll certs via the framework's CLI.

Rejected as detailed in §Rationale: autoenroll is the most common AD CS use case; manual enrollment does not scale to large fleets; renewal without autoenroll requires operator intervention at every cert expiry.

## Open Questions

- **TPM2 PCR selection per profile.** The default PCR selection for TPM2 attestation is PCR 7 (Secure Boot policy) and PCR 11 (BitLocker measured boot). Should profiles specify a custom PCR selection (e.g., PCR 22 for kernel-measured boot)? Current decision: the PCR selection is deployment-wide (configured at the CA level, not per-profile); profiles only specify whether attestation is required. Revisit if customers need per-profile PCR selection.
- **Renewal failure escalation.** If a renewal fails (e.g., the CA is unreachable for the entire renewal window), what is the escalation path? Current decision: the module retries every 6 hours until the cert expires; on cert expiry, the module emits a critical audit event and the framework's alerting system (per ADR-057) notifies the operator. The cert's expiry triggers service-specific failures (e.g., TLS handshake failures) that the operator must investigate. Revisit if customers report renewal-failure blind spots.
- **macOS Keychain access for non-root users.** The module stores machine certs in the System Keychain (`/Library/Keychains/System.keychain`); user certs (e.g., S/MIME certs) should be stored in the user's login Keychain. Current decision: machine certs only (the framework's `CertAutoenroll` policy is machine-scoped); user-cert autoenroll is deferred to v2. Revisit if customers report user-cert autoenroll demand.

## Cross-capability impact

- **Cert Service (PC-057 enrollment)**: ADR-095's ACME server and MS-WCCE bridge serve the module's ACME orders; the MS-WCCE bridge is bypassed for framework-enrolled Windows hosts.
- **Cert Service (PC-058 templates)**: ADR-096's `cert-profiles.yaml` defines the profiles consumed by the module.
- **Cert Service (PC-060 KRA)**: ADR-032's HSM-bound KRA is invoked for `archival_required: true` profiles; the module wraps the private key in a CRMF envelope (per RFC 4211) for archival.
- **Policy Engine (Decision 7)**: The `CertAutoenroll` PolicyArea (per Decision 7 §Cross-capability dependencies) drives the module's profile discovery; the canonical JSON's `secret_ref` type carries the host's EAB MAC key.
- **Client SDK (Decision 11)**: The module is a Client SDK component; the SDK daemon hosts the module.
- **Migration (PC-127 AD CS-to-framework)**: The `certmonger` compatibility shim (per §9) preserves existing `certmonger` deployments during migration; the synthetic Windows CSE (per §7) preserves existing GPO-driven autoenroll during migration.
- **Security (PC-123 threat model)**: The TPM2/SE attestation enforcement is documented in the threat model as the mechanism that prevents unauthorized cert issuance to non-enrolled hardware.

## References

- [PC-059](../catalog/05-cert-service.md) — problem statement in the catalog
- [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §6 — autoenrollment mechanism specification
- [docs/05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md) — AD CS autoenroll flow, `autoenroll.dll` CSE, MS-XCEP/MS-WSTEP, renewal triggers, key archival
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — CSE registration, `ProcessGroupPolicyEx` prototype, autoenroll CSE GUID
- [ADR-024](./ADR-024-per-platform-policy-executors.md) — per-platform policy executors (the synthetic Windows CSE)
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution (WebSocket; profile-assignment changes)
- [ADR-032](./ADR-032-hsm-bound-kra-shamir.md) — HSM-bound KRA (invoked for `archival_required: true` profiles)
- [ADR-052](./ADR-052-ddm-first-authoring.md) — DDM-first macOS authoring (MDM enrollment for macOS attestation)
- [ADR-057](./ADR-057-prometheus-otel-observability.md) — Prometheus/OpenTelemetry observability (renewal-failure alerting)
- [ADR-092](./ADR-092-policy-executor-trait-synthetic-windows-cse.md) — `PolicyExecutor` trait + synthetic Windows CSE (the CSE that invokes the module)
- [ADR-095](./ADR-095-acme-primary-mswcce-bridge.md) — ACME-primary cert enrollment with MS-WCCE bridge (the CA backend)
- [ADR-096](./ADR-096-cert-profile-yaml-replaces-templates.md) — Cert profile YAML (the profiles consumed by the module)
- [RFC 8555 ACME](https://www.rfc-editor.org/rfc/rfc8555) — Automatic Certificate Management Environment
- [RFC 8823 ARI](https://www.rfc-editor.org/rfc/rfc8823) — ACME Renewal Information
- [RFC 4211 CRMF](https://www.rfc-editor.org/rfc/rfc4211) — Certificate Request Message Format (for key archival)
- [`tss-esapi` crate](https://docs.rs/tss-esapi) — TPM2 TSS Rust bindings
- [`security-framework` crate](https://docs.rs/security-framework) — macOS Security framework Rust bindings
- [`windows` crate](https://docs.rs/windows) — Rust Windows API bindings (CNG KSP, TBS API)
- [TPM2 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/) — TPM Main Specification
- [Apple DeviceCheck](https://developer.apple.com/documentation/devicecheck) — Apple Secure Enclave attestation API
