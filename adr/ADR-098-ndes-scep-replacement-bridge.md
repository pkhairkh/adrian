---
title: "ADR-098: NDES/SCEP replacement via standalone `adrian-scep-bridge` (resolves PC-064)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-064
severity: medium
unblocked_by: Workshop Decision 8
tags: [adr, cert-service, ndes, scep, est, network-devices, iot, iis-free, rust, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../workshop/decision-08-pki-enrollment.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ../docs/05-pki-certs/03-autoenrollment.md
  - ./ADR-095-acme-primary-mswcce-bridge.md
  - ./ADR-096-cert-profile-yaml-replaces-templates.md
last_updated: 2026-08-14
---

# ADR-098: NDES/SCEP replacement via standalone `adrian-scep-bridge` (resolves PC-064)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §4 and §9, which specify that the framework ships `adrian-scep-bridge` — a standalone Rust service that replaces AD's NDES (Network Device Enrollment Service) with no IIS dependency, and that NDES is marked deprecated. This ADR operationalises Decision 8 §4 and §9's specification against the PC-064 problem surface: the fragility of NDES (IIS + ASP.NET + dynamic RPC dependency), the manual challenge-password distribution, and the absence of a native Linux/macOS NDES server.

## Context

NDES (Network Device Enrollment Service) is the AD CS role that provides SCEP (Simple Certificate Enrollment Protocol, RFC 8894) enrollment for routers, switches, IoT devices, and other non-domain-joined devices. Per [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), NDES runs as `SCEP.exe` service under IIS + ASP.NET + dynamic RPC. Configuration is multi-step: install the NDES role, configure the RA (Registration Authority) cert, configure the SCEP URL (`https://<server>/certsrv/mscep/`), set the challenge password, configure the CA template (an NDES-specific copy of an existing template with `msPKI-Certificate-Name-Flag = 0x1` `ENROLLEE_SUPPLIES_SUBJECT` and the RA's ACL), and verify the IIS application pool identity has `Enroll` on the template.

Per [docs/05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md), the NDES flow: (1) device fetches the RA cert + CA cert via `GET /certsrv/mscep/mscep.dll?operation=GetCACert&message=<ra-name>`; (2) device obtains a one-time challenge password from the NDES admin (via `https://<server>/certsrv/mscep/`); (3) device submits a PKCS#10 CSR wrapped in a PKCS#7 envelope signed by the RA, encrypted to the RA, via `POST /certsrv/mscep/mscep.dll?operation=PKIOperation`; (4) NDES unwraps, submits to the CA via DCOM ICertPassage, returns the issued cert. The challenge password is single-use (regenerated every 60 minutes by default).

The fragility is multi-dimensional: NDES depends on IIS + ASP.NET, which adds a heavy Windows-only stack (IIS application pools, ASP.NET pipeline, dynamic RPC for the CA submission). The challenge password distribution is manual (admin copies from the NDES web page to the device, often via SSH or console — operationally painful for fleets of hundreds of network devices). The RA cert must be renewed before expiry (a separate autoenroll task on the NDES host — and if the RA cert expires, NDES stops working silently). Configuration errors are common: mis-scoped template ACL, IIS app pool identity mismatch, expired RA cert. There is no native Linux/macOS NDES server; the only third-party options are Gatekeeper, certNanny, and xCA SCEP — all less mature than NDES and with their own configuration quirks.

Workshop Decision 8 §4 specifies the framework's answer: ship `adrian-scep-bridge` — a standalone Rust service that exposes `/scep` and translates the SCEP `pkioperation` message (a PKCS#7 envelope containing the PKCS#10 CSR) into an ACME order. Decision 8 §9 marks NDES as deprecated. This ADR defines the `adrian-scep-bridge` service's contract, the challenge-password replacement, the RA cert management, and the migration path from NDES.

## Decision

The framework ships `adrian-scep-bridge` — a standalone Rust service (no IIS, no ASP.NET, no Windows dependency) that exposes the SCEP protocol (RFC 8894) for routers, switches, IoT devices, and other non-domain-joined devices. The bridge translates each SCEP `pkioperation` message into an ACME order against the framework's CA (per ADR-095). The bridge also serves the EST protocol (RFC 7030) for IoT devices that prefer EST over SCEP. AD's NDES is marked deprecated; the framework's documentation guides customers to migrate from NDES to `adrian-scep-bridge`.

### Concrete specification

1. **Service architecture.** `adrian-scep-bridge` is a Rust binary in the `adrian-ca` workspace. The service runs as a standalone HTTPS server (via `axum = "0.7"` + `rustls = "0.23"`), listening on TCP/443 (or a configurable port). The service is deployed as a container (per ADR-058) or as a systemd service on Linux, a Windows Service on Windows, or a launchd daemon on macOS — but the typical deployment is Linux (network devices are typically in a DMZ; the bridge is deployed on a Linux host in the DMZ). The service has no IIS, no ASP.NET, no DCOM dependencies.

2. **SCEP endpoints.** The service exposes the standard SCEP endpoints (per RFC 8894):
   - `GET /scep?operation=GetCACert&message=<name>` — returns the RA cert + CA cert chain as a `application/x-x509-ca-cert` (single cert) or `application/x-x509-ca-ra-cert` (RA + CA pair, CMS-signed) payload. The `<name>` parameter identifies which RA to use (the framework supports multiple RAs, each with its own cert and ACL; the framework's `adrian-scep-ra` CLI manages RAs).
   - `GET /scep?operation=GetNextCACert` — returns the next CA cert (for CA rotation, per RFC 8894 §3.2.1.5).
   - `POST /scep?operation=PKIOperation` — accepts a PKCS#7 envelope (CMS SignedData + EnvelopedData) containing the PKCS#10 CSR, signed by the device's existing cert (for renewal) or self-signed (for initial enrollment), encrypted to the RA's public key. The service unwraps the envelope, extracts the CSR, and processes it per §3.

3. **CSR processing and ACME translation.** The service processes each SCEP `PKIOperation` as follows:
   - **Unwrap the PKCS#7 envelope**: The service uses `pkcs7 = "0.4"` (RustCrypto's PKCS#7 library) to parse the CMS SignedData + EnvelopedData. The service verifies the envelope's signature (if the request is a renewal, the signature is from the device's existing cert, which the service validates against the framework's CA database; if the request is initial enrollment, the signature is self-signed and the service skips signature verification). The service decrypts the EnvelopedData using the RA's private key (stored in the framework's HSM via PKCS#11, per ADR-037 §2).
   - **Extract the PKCS#10 CSR**: The service uses `pkcs10 = "0.2"` to parse the CSR. The service extracts the subject, SAN, public key, and (if present) the `challengePassword` attribute.
   - **Validate the challenge password**: For initial enrollment (no existing cert), the service validates the `challengePassword` against the framework's per-host enrollment secret (provisioned by the framework's Client SDK during host enrollment, per Decision 8 §4). The challenge password is a one-time-use token; the service marks it as used after successful validation. For renewal (existing cert presented), the service skips challenge-password validation (the existing cert's chain to a trusted CA is the authentication).
   - **Map to framework profile**: The service maps the SCEP request to a framework cert profile (per ADR-096) via the `scep_profile_map` configuration. The mapping can be static (one profile per RA, configured via the `adrian-scep-ra` CLI) or dynamic (per-request profile selection based on the CSR's subject OU or the device's source IP). The default is static (one profile per RA); dynamic mapping is opt-in.
   - **Create ACME order**: The service creates an ACME order against the framework's CA (per ADR-095 §1) using the bridge's service-account ACME account (the bridge does not require per-device attestation — SCEP devices are non-attestable; the challenge password + RA-signed envelope is the authentication). The ACME order's SAN is taken from the CSR's SAN extension. The service fulfills the ACME `http-01` or `dns-01` challenge automatically (the bridge has framework-admin privileges to solve challenges on behalf of devices that cannot solve them themselves — e.g., a router that cannot run an HTTP server for `http-01`).
   - **Wrap the issued cert in PKCS#7 response**: The service uses `pkcs7` to wrap the issued cert in a CMS SignedData + EnvelopedData response, signed by the RA, encrypted to the device's public key (from the CSR). The response is returned as the SCEP `PKIOperation` response (`application/x-pki-message`).

4. **Challenge-password replacement.** Per Decision 8 §4, SCEP's challenge password (the `challengePassword` attribute in the CSR) is the framework's host-specific enrollment secret, provisioned by the framework's Client SDK during host enrollment. The framework's enrollment workflow generates a random 32-byte secret per device, stores it in the framework's directory (in the device's `enrollmentSecret` attribute, encrypted via the framework's secret service per Decision 11), and provides it to the operator (via the framework's UI) for manual entry on the device. The secret is one-time-use (the bridge marks it as used after the first successful enrollment); for re-enrollment (e.g., after device factory reset), the operator rotates the secret via `adrian-cli device rotate-secret <device-uuid>`. This replaces NDES's 60-minute challenge-password rotation (which forces operators to enroll devices within 60 minutes of obtaining the password) with a per-device one-time secret that is valid until used or rotated.

5. **RA cert management.** The service supports multiple RAs (Registration Authorities), each with its own cert and private key. RA certs are issued by the framework's CA (per ADR-095) via a special `scep-ra` cert profile (with `extended_key_usages: [scep_ra]` — a framework-specific EKU). RA private keys are stored in the framework's HSM (per ADR-037 §2). RA cert renewal is automatic (via the framework's `adrian-cert-enroll` module, per ADR-097 — the bridge itself is a framework-enrolled host and enrolls its RA cert via ACME). RA cert rotation (when the RA cert approaches expiry) is handled transparently: the bridge continues to serve the old RA cert for in-flight requests while issuing new requests with the new RA cert; the `GetCACert` endpoint returns both certs during the overlap window (per RFC 8894 §3.2.1.4).

6. **EST bridge (RFC 7030).** Per Decision 8 §3, the service also exposes the EST protocol (RFC 7030) for IoT devices that prefer EST over SCEP. The EST endpoints are:
   - `GET /est/.well-known/est/cacerts` — returns the CA cert chain.
   - `POST /est/.well-known/est/simpleenroll` — accepts a PKCS#7 envelope containing the PKCS#10 CSR, authenticated via TLS client certificate (the device presents an existing cert for renewal, or a manufacturer-installed cert for initial enrollment).
   - `POST /est/.well-known/est/simplereenroll` — accepts a CSR for renewal, authenticated via the existing cert's TLS client certificate.
   - `POST /est/.well-known/est/serverkeygen` — accepts a CSR and returns a keypair + cert (the bridge generates the keypair in the HSM and returns the public cert + a wrapped private key).
   
   The EST flow translates to ACME orders analogously to the SCEP flow (per §3), with the TLS client certificate replacing the challenge password as the authentication mechanism.

7. **Audit logging.** The service logs every SCEP and EST request to the framework's audit log (per ADR-060) via OpenTelemetry. The log entry includes: the device's source IP, the device's existing cert's serial number (for renewal) or the challenge password's identifier (for initial enrollment), the requested profile, the ACME order's URL, the issued cert's serial number, and the response status (success, failure with reason). The audit log enables operators to track which devices have enrolled via SCEP/EST and to investigate enrollment failures.

8. **Rate limiting.** The service enforces per-device rate limiting (default: 1 enrollment request per device per hour, 10 renewal requests per device per day) to prevent abuse. The rate limit is per source IP (for initial enrollment) and per existing cert's serial number (for renewal). The rate limit is configurable via the `adrian-scep-ra` CLI. Rate-limit violations are logged to the audit log with a `RateLimitExceeded` reason.

9. **Migration from NDES.** The `adrian-migrate from-ndes` CLI walks an AD NDES server's configuration (via `reg query HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP` and `certutil -ping` against the NDES host), extracts the RA cert and CA template mapping, and emits a framework `scep-ra` profile and `scep_profile_map` configuration. The CLI also extracts the list of devices that have enrolled via NDES (from the NDES's request log, `%SystemRoot%\System32\CertLog\NDES_*.log`) and generates a per-device enrollment secret in the framework's directory (replacing NDES's challenge password). Operators then re-enroll devices via the framework's SCEP endpoint (the device's SCEP client URL is changed from `https://<ndes>/certsrv/mscep/` to `https://<adrian-scep>/scep`).

10. **NDES deprecation.** Per Decision 8 §9, the framework's documentation marks NDES as deprecated. Customers moving from AD CS to the framework are guided to deploy `adrian-scep-bridge` alongside the ACME server (per ADR-095) and migrate network devices from NDES to the bridge. The framework's documentation provides per-vendor migration guides (Cisco IOS, Juniper Junos, Arista EOS, Palo Alto PAN-OS) for reconfiguring the SCEP client URL.

## Rationale

Three alternatives were considered.

**Alternative A: Preserve NDES via the MS-WCCE bridge.** Implement NDES-equivalent functionality in the MS-WCCE bridge (per ADR-095 §2), reusing the MS-WCCE bridge's DCE/RPC and IIS-equivalent infrastructure. Rejected because (a) NDES's IIS + ASP.NET dependency is one of the main pain points the framework is solving — preserving IIS-equivalent infrastructure in the bridge inherits the pain; (b) NDES's flow (RA cert signing + CMS envelope + challenge password) is unrelated to MS-WCCE's flow (DCOM ICertPassage + template OID + attribute blob) — combining them in one service creates a confusing surface; (c) SCEP is a published RFC (8894) with a simple HTTPS-based protocol — a standalone Rust service is the natural implementation; (d) the framework's ACME server (per ADR-095) already provides the cert-issuance backend; the SCEP bridge is a thin protocol-translator that reuses the ACME server, with no need to share infrastructure with the MS-WCCE bridge. Decision 8 §4 specifies the standalone bridge explicitly.

**Alternative B: Adopt a third-party SCEP server (Gatekeeper, certNanny, xCA SCEP).** Use an existing third-party SCEP server instead of writing a fresh implementation. Rejected because (a) Gatekeeper is Python 2 (EOL); certNanny is Perl (deprecated upstream); xCA SCEP is a hobbyist project with limited production deployment; (b) third-party SCEP servers do not integrate with the framework's CA (they typically expect a file-based CA backend or a PKCS#11 HSM directly, not an ACME server); (c) third-party SCEP servers do not support the framework's per-device enrollment-secret model (per §4) or the framework's audit logging (per §7); (d) writing a fresh Rust implementation (~1.2K lines, per Decision 8 §Rust implementation implications) is faster than adapting a third-party server to the framework's architecture.

**Alternative C: EST-only (drop SCEP).** Ship EST (RFC 7030) only; require network devices to migrate from SCEP to EST. Rejected because (a) the installed base of SCEP clients is enormous — Cisco IOS, Juniper Junos, Arista EOS, Palo Alto PAN-OS all ship SCEP clients; many older devices do not support EST; (b) SCEP and EST serve different use cases (SCEP for routers/switches with challenge-password authentication; EST for IoT devices with TLS-client-cert authentication); (c) the framework's value proposition is migration with minimal device-side changes — requiring customers to upgrade their network devices' firmware to support EST is a multi-year project per customer; (d) EST and SCEP share the same ACME backend (per §6); the additional cost of supporting SCEP alongside EST is ~1.2K lines of Rust (per Decision 8 §Rust implementation implications), which is small relative to the migration cost savings for customers.

The chosen model — standalone `adrian-scep-bridge` Rust service with SCEP + EST, per-device enrollment-secret, automatic RA cert renewal, audit logging, rate limiting, and migration CLI — gives the framework: (a) no IIS dependency (the main NDES pain point eliminated); (b) per-device enrollment secret (replacing NDES's 60-minute challenge-password rotation); (c) automatic RA cert renewal (replacing NDES's separate autoenroll task); (d) SCEP + EST support (covering both legacy network devices and modern IoT); (e) a migration path from NDES via `adrian-migrate from-ndes`.

## Consequences

**Positive**. The framework's SCEP/EST endpoint is a standalone Rust service with no IIS/ASP.NET/DCOM dependencies — deployable on Linux in a DMZ. Per-device enrollment secret replaces NDES's 60-minute challenge-password rotation. RA cert renewal is automatic (via the framework's `adrian-cert-enroll` module). SCEP + EST support covers both legacy network devices and modern IoT. Audit logging tracks every enrollment. Rate limiting prevents abuse. Migration from NDES is supported via `adrian-migrate from-ndes`.

**Negative**. The service's per-device enrollment-secret model requires operators to provision a secret per device (via the framework's UI or CLI) before enrollment — an operational step that NDES's 60-minute challenge-password rotation avoided (the operator obtained the password at enrollment time). For fleets of hundreds of network devices, the per-device secret provisioning is a one-time bulk operation (the framework's `adrian-cli device bulk-rotate-secret --csv <file>` CLI supports CSV-driven bulk provisioning). The service's automatic ACME challenge fulfillment (per §3, the bridge solves `http-01`/`dns-01` on behalf of devices that cannot solve them themselves) requires the bridge to have framework-admin privileges — a security-sensitive capability that is documented in the threat model (per PC-123) and audited via the framework's audit log.

**Neutral**. The service is deployed alongside the ACME server (per ADR-095); the two services share the CA backend (per ADR-037) but run as separate binaries. The `adrian-scep-ra` CLI manages RAs (create, list, rotate cert); the `adrian-scep` CLI is part of the framework's unified CLI (per ADR-063).

**Implementation cost**. ~3 person-weeks for v1 (per Decision 8 §Rust implementation implications): SCEP protocol implementation (1.5 pw), EST protocol implementation (1 pw, subsumed in the EST-bridge line item), migration CLI `adrian-migrate from-ndes` (0.5 pw). Ongoing maintenance: ~0.5 person-week per year for protocol-revision tracking (SCEP and EST are stable RFCs with rare revisions).

**Operational impact**. Operators deploy `adrian-scep-bridge` in a DMZ (typically as a container per ADR-058). Operators provision per-device enrollment secrets via the framework's UI or CLI. Operators configure RA certs and profile mappings via `adrian-scep-ra`. Network devices are configured with the SCEP URL `https://<adrian-scep>/scep` (per vendor documentation). The framework's audit log tracks every enrollment.

## Alternatives Considered

### Alternative A: Preserve NDES via the MS-WCCE bridge

Implement NDES-equivalent functionality in the MS-WCCE bridge, reusing the bridge's DCE/RPC and IIS-equivalent infrastructure.

Rejected as detailed in §Rationale and Decision 8 §4: NDES's IIS + ASP.NET dependency is the main pain point; NDES's flow is unrelated to MS-WCCE's flow; SCEP is a published RFC with a simple HTTPS protocol; the standalone Rust bridge reuses the ACME server backend without sharing infrastructure with the MS-WCCE bridge.

### Alternative B: Adopt a third-party SCEP server (Gatekeeper, certNanny, xCA SCEP)

Use an existing third-party SCEP server instead of writing a fresh implementation.

Rejected as detailed in §Rationale: Gatekeeper is Python 2 (EOL); certNanny is Perl (deprecated); xCA SCEP is hobbyist; third-party servers do not integrate with the framework's CA; third-party servers do not support the framework's per-device enrollment-secret model or audit logging; a fresh Rust implementation (~1.2K lines) is faster than adapting a third-party server.

### Alternative C: EST-only (drop SCEP)

Ship EST (RFC 7030) only; require network devices to migrate from SCEP to EST.

Rejected as detailed in §Rationale: the installed base of SCEP clients is enormous (Cisco IOS, Juniper Junos, Arista EOS, Palo Alto PAN-OS); many older devices do not support EST; SCEP and EST serve different use cases; requiring customers to upgrade firmware is a multi-year project; EST and SCEP share the same ACME backend (the additional SCEP cost is ~1.2K lines of Rust).

## Open Questions

- **SCEP challenge-password strength.** The framework's per-device enrollment secret is a random 32-byte value (256 bits). Some SCEP clients (notably older Cisco IOS versions) truncate the `challengePassword` attribute to 16 bytes. Current decision: the framework's secret is 32 bytes; the `adrian-cli device rotate-secret --length 16` option produces 16-byte secrets for legacy clients. Revisit if customers report truncation-related enrollment failures on other clients.
- **RA cert overlap window.** During RA cert rotation, the bridge serves both the old and new RA certs (per RFC 8894 §3.2.1.4). The overlap window is configurable (default 30 days). Revisit if customers report overlap-window-related issues (e.g., devices that cache the old RA cert beyond the overlap window).
- **Manufacturer-installed EST certificates.** For EST initial enrollment, the device presents a manufacturer-installed TLS client certificate. The framework's CA must trust the manufacturer's CA. Current decision: the framework bundles the manufacturer CAs for major IoT device vendors (Cisco, Juniper, Arista, Palo Alto, Intel, ARM); customers can add additional manufacturer CAs via the `adrian-cli trust add-manufacturer-ca <file>` CLI. Revisit if customers report missing manufacturer CAs.

## Cross-capability impact

- **Cert Service (PC-057 enrollment)**: ADR-095's ACME server is the cert-issuance backend for the bridge; the bridge creates ACME orders on behalf of SCEP/EST devices.
- **Cert Service (PC-058 templates)**: ADR-096's `cert-profiles.yaml` defines the profiles consumed by the bridge (via the `scep_profile_map` configuration).
- **Cert Service (PC-059 autoenroll)**: ADR-097's `adrian-cert-enroll` module enrolls the bridge's own RA cert (the bridge is a framework-enrolled host).
- **KDC (PC-027 PKINIT)**: The bridge is unrelated to PKINIT (network devices do not use PKINIT); however, IPSec certs issued via the bridge may be used by network devices for IPSec tunnels to framework-managed hosts.
- **Operations (PC-115 unified CLI)**: The `adrian-scep`, `adrian-scep-ra`, and `adrian-migrate from-ndes` CLI subcommands are part of the framework's unified CLI.
- **Migration (PC-127 AD CS-to-framework)**: The `adrian-migrate from-ndes` CLI is the migration entry point for NDES.
- **Security (PC-123 threat model)**: The bridge's automatic ACME challenge fulfillment (per §3) requires framework-admin privileges — documented in the threat model and audited.

## References

- [PC-064](../catalog/05-cert-service.md) — problem statement in the catalog
- [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) §4 and §9 — SCEP bridge specification; NDES deprecation
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — NDES architecture, IIS dependency, RA cert, challenge password
- [docs/05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md) — NDES flow, `SCEP.exe`, `mscep.dll`, PKCS#7 envelope, PKIOperation
- [ADR-037](./ADR-037-two-tier-ca-hsm-root.md) — Two-tier CA with HSM-bound root (RA private keys stored in HSM)
- [ADR-058](./ADR-058-container-native-dcs-operator.md) — Container-native DCS operator (bridge deployed as container)
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — Structured audit logs (bridge audit events)
- [ADR-095](./ADR-095-acme-primary-mswcce-bridge.md) — ACME-primary cert enrollment with MS-WCCE bridge (the ACME backend)
- [ADR-096](./ADR-096-cert-profile-yaml-replaces-templates.md) — Cert profile YAML (profiles consumed by the bridge)
- [ADR-097](./ADR-097-cross-platform-autoenroll-acme.md) — Cross-platform autoenroll (the bridge's own RA cert enrollment)
- [RFC 8894 SCEP](https://www.rfc-editor.org/rfc/rfc8894) — Simple Certificate Enrollment Protocol
- [RFC 7030 EST](https://www.rfc-editor.org/rfc/rfc7030) — Enrollment over Secure Transport
- [`pkcs7` crate](https://docs.rs/pkcs7) — RustCrypto PKCS#7 library (CMS envelope parsing)
- [`pkcs10` crate](https://docs.rs/pkcs10) — RustCrypto PKCS#10 library (CSR parsing)
- [`rasn` crate](https://docs.rs/rasn) — Rust ASN.1 library (SCEP message types)
- [`axum` crate](https://docs.rs/axum) — Rust HTTP server framework
- [`rustls` crate](https://docs.rs/rustls) — Rust TLS library
