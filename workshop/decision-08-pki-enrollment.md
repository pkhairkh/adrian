---
title: "Workshop Decision 08 — PKI enrollment: ACME primary + MS-WCCE bridge (resolves ORQ-110/111)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cert Service
orqs_resolved: [ORQ-110, ORQ-111]
gates: [PC-027, PC-057, PC-058, PC-059, PC-064, PC-067]
tags: [workshop, decision, cert-service, pki, acme, ms-wcce, autoenroll, rust]
related:
  - ./CONTEXT.md
  - ../adr/TRIAGE.md
  - ../adr/ADR-037-two-tier-ca-hsm-root.md
  - ../adr/ADR-032-hsm-bound-kra-shamir.md
  - ../adr/ADR-033-ocsp-responder-rfc-6960-nonce-ha.md
  - ../adr/ADR-035-multi-cdp-ocsp-cluster-crl-fallback.md
  - ../adr/ADR-036-trust-manager-cross-cert-interop.md
  - ../catalog/05-cert-service.md
last_updated: 2026-08-14
---

# Workshop Decision 08 — PKI enrollment: ACME primary + MS-WCCE bridge

## Status

Accepted — 2026-08-14. Tier-1 (architectural) decision made at the Day 2 morning session of the Tier-1 ORQ Resolution Workshop. Resolves ORQ-110 (ACME + MS-WCCE adapter for Windows) and ORQ-111 (Dogtag-style REST API vs. ACME-only). Supersedes the open enrollment-protocol questions in ADR-037 (Two-tier CA with HSM-bound root) and locks the v1 enrollment surface.

## ORQs resolved

- **ORQ-110** — "Adopt ACME (RFC 8555) for new clients + MS-WCCE adapter for Windows?" → **Yes.** ACME (RFC 8555) is the primary enrollment protocol for all platforms; a Rust MS-WCCE bridge service translates legacy Windows `autoenroll.dll` / `certreq.exe` SOAP/RPC traffic into ACME orders against the framework's CA. The bridge is a separate deployable component, not bundled into the CA core, so it can be deprecated and removed when the last Windows autoenroll client migrates.
- **ORQ-111** — "Implement Dogtag-style REST API?" → **No.** The framework exposes ACME (RFC 8555) as the public enrollment API and a small gRPC admin API (CA management, template CRUD, revocation) for the framework's own UI and CLI. A Dogtag-style REST API is not implemented; customers with existing Dogtag tooling should use the framework's ACME endpoint instead, since Dogtag's REST API is non-standard and ties customers to Dogtag-specific tooling.

## Decision

The framework's Cert Service ships an **ACME primary enrollment server** (RFC 8555 + RFC 8737 `tls-alpn-01` + RFC 8823 `ARI` Renewal Information) and a **separate MS-WCCE bridge service** that translates MS-WCCE/MS-XCEP/MS-WSTEP traffic from Windows `autoenroll.dll` into ACME orders. EST (RFC 7030) is supported as a thin wrapper over ACME for IoT/network devices that cannot run an ACME client. SCEP (RFC 8894) is supported as a thin wrapper over ACME for routers/switches that only speak SCEP. The CA itself speaks only ACME internally; the bridges are protocol-translators, not separate CA implementations.

### Concrete specification

1. **ACME server (primary).** The framework's CA exposes a standard ACME server at `https://ca.<domain>/acme/directory`. The server supports:
   - **Account management** (RFC 8555 §7.3) — `newAccount`, `account`, `keyChange`. Account keys are JWK (RFC 7517); ECDSA P-256 is the default, RSA 2048/3072 supported.
   - **Order management** (RFC 8555 §7.4) — `newOrder`, `order`, `finalize`, `certificate`. Orders are bound to an account and a certificate template (the template is encoded in the order's `not-before`/`not-after` ACME field as a `template` extension per framework convention; the ACME client requests a specific template by URL path: `https://ca.<domain>/acme/directory/<template-slug>`).
   - **Authorization challenges** (RFC 8555 §7.5, §8) — `http-01`, `dns-01`, `tls-alpn-01` (RFC 8737). The framework also supports a non-standard `adrian-attest-01` challenge type for framework-enrolled clients that present a hardware attestation (TPM2 quote or Apple Secure Enclave attestation); this is used for machine-identity enrollment where the framework's Client SDK orchestrates the attestation.
   - **ARI** (RFC 8823) — ` renewalInfo` endpoint exposes renewal-window guidance so clients renew at staggered times, avoiding CA-overload spikes.
   - **External account binding (EAB)** (RFC 8555 §7.3.5) — required for all framework-enrolled clients; the framework's Client SDK obtains an EAB MAC key from the framework's directory service during host enrollment and uses it for all subsequent ACME account creations. EAB binds an ACME account to a framework host identity, closing the "anyone who can solve a challenge can get a cert" gap that public ACME CAs accept but private enterprise CAs cannot.
   - **Certificate profile** — the framework maps ACME `identifier` to a subject alt name (SAN) and the requested template (via URL path) to a certificate profile. The profile controls key algorithm (RSA 2048/3072/4096, ECDSA P-256/P-384, Ed25519), validity period, EKU, basic constraints, name constraints (if any), and key usage. Profiles are defined declaratively in `cert-profiles.yaml` and version-controlled in Git (per ADR-031's Git-backed pattern).
   - **State machine** — the ACME server persists orders in the CA's PostgreSQL database (`acme_orders`, `acme_authorizations`, `acme_challenges` tables). The state machine is `pending → ready → processing → valid | invalid`; expired orders are GC'd after 7 days.

2. **MS-WCCE bridge (Windows interop).** The framework ships `adrian-wcce-bridge`, a Rust service that exposes the MS-WCCE DCE/RPC interface (ICertPassage UUID `91b9b93a-57b4-11d0-8f16-00a0484d6c9c`, opnum 0/1/2/36) and the MS-XCEP/MS-WSTEP SOAP endpoints (`/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP` and `/CertificateEnrollment/Service.svc/CES`). The bridge accepts incoming MS-WCCE `Request` (opnum 36) calls from Windows `autoenroll.dll` and `certreq.exe`, extracts the PKCS#10 CSR and template OID, maps the template OID to a framework certificate profile (via `template-map.yaml` — Microsoft's built-in templates have default mappings), creates an ACME order against the framework's CA (fulfilling `adrian-attest-01` automatically via the host-identity context from the Kerberos-authenticated MS-WCCE RPC), and returns the issued cert as an MS-WCCE `Request` response. For MS-XCEP (CEP), the bridge serves the policy discovery SOAP response; for MS-WSTEP (CES), the bridge wraps the PKCS#10 in the SOAP envelope and unwraps the response. The bridge is a separate binary deployed on Linux (systemd) or Windows (Service); the DCE/RPC endpoint is implemented in pure Rust (`rustls` + `tokio` + a hand-rolled NCNDR/MS-RPCE encoder), listening on TCP/135 (endpoint mapper) and the dynamic RPC port range. The bridge is the only framework component that listens on TCP/135.

3. **EST bridge (RFC 7030).** For IoT devices, network appliances, and embedded systems that speak EST (RFC 7030) but not ACME, the framework ships `adrian-est-bridge` — a Rust service that exposes `/est/.well-known/est/simpleenroll`, `/est/.well-known/est/simplereenroll`, `/est/.well-known/est/cacerts`, and translates each EST request to an ACME order. EST's `application/pkcs10` CSR is parsed and submitted as an ACME `finalize` payload. The EST `Authorization: Digest` header is mapped to the framework's host identity (via a pre-shared key provisioned during device enrollment).

4. **SCEP bridge (RFC 8894).** For routers/switches (Cisco IOS, Juniper Junos) that only speak SCEP, the framework ships `adrian-scep-bridge` — a Rust service that exposes `/scep` and translates the SCEP `pkioperation` message (a PKCS#7 envelope containing the PKCS#10 CSR) into an ACME order. SCEP's challenge password (the `challengePassword` attribute in the CSR) is the framework's host-specific enrollment secret, provisioned by the framework's Client SDK during host enrollment.

5. **Certificate profiles (replaces AD CS templates).** AD CS certificate templates (v1/v2/v3) with their `msPKI-*` attributes are replaced by declarative YAML profiles in `cert-profiles.yaml`:
   ```yaml
   profiles:
     - name: machine
       slug: machine
       validity_days: 365
       key_algorithms: [rsa-2048, ecdsa-p256, ed25519]
       key_usages: [digital_signature, key_encipherment]
       extended_key_usages: [client_auth, server_auth]
       subject: { cn: "{{ host.dns_name }}", san_dns: ["{{ host.dns_name }}"] }
       issuance_policy: { require_eab: true, require_attestation: true, max_validity_days: 730 }
       name_constraints: { permitted_dns: ["{{ domain }}"] }
       ntauth_member: true
   ```
   Profiles are version-controlled in Git, validated by the framework's CLI (`adrian-ca profile validate`), and applied atomically (per ADR-025's transactional pattern). The ADMX-to-policy compiler (Decision 7) maps AD CS template attributes to framework profile fields for migration.

6. **Autoenrollment mechanism.** AD CS autoenrollment via `autoenroll.dll` CSE + GPO is replaced by the framework's Client SDK cert enrollment module, which reads the host's profile assignments from the directory (the host object's `certProfiles` attribute, set by policy), runs an ACME client against the framework's CA (fulfilling `adrian-attest-01` via TPM2 quote on Windows/Linux or Apple Secure Enclave attestation on macOS), stores the issued cert and private key in the platform-native key store (Windows CNG KSP, macOS Keychain, Linux `systemd`-managed keyring or `/etc/adrian/keys/`), and re-enrolls automatically at 2/3 of validity (RFC 8823 ARI preferred). On Windows, the Client SDK additionally registers as an `autoenroll.dll`-compatible synthetic CSE (per ADR-024 + Decision 7) so existing GPO-driven autoenroll policies continue to invoke the framework's enrollment path; the MS-WCCE bridge is bypassed for framework-enrolled Windows hosts and is only needed during migration.

7. **NTAuthCertificates replacement.** AD's `NTAuthCertificates` object (per PC-067) is replaced by a `LogonAuthorizedCAs` directory attribute on the framework's `TrustedCAContainer` object. The trust-manager (per [ADR-036](../adr/ADR-036-trust-manager-cross-cert-interop.md)) distributes the listed CA certs to all hosts. The KDC's PKINIT validator (per PC-027) checks the issuing CA's presence in `LogonAuthorizedCAs` before accepting a smart-card logon.

8. **Key archival (KRA).** Per [ADR-032](../adr/ADR-032-hsm-bound-kra-shamir.md), profiles with `archival_required: true` require the CSR wrapped in a CMS envelope (CRMF `archiveOffs`, RFC 4211) encrypted to the KRA's public key. The ACME server unwraps the envelope using the HSM-backed KRA key and stores the archived private key in the KRA database, sharded across N HSM partitions.

9. **NDES replacement.** AD's NDES (IIS-based SCEP server) is replaced by `adrian-scep-bridge` (standalone Rust service, no IIS dependency). The framework's documentation marks NDES as deprecated.

## Rationale

Three candidate architectures were considered.

**Candidate A: MS-WCCE server implementation, no ACME.** Implement the full MS-WCCE/MS-XCEP/MS-WSTEP server stack in Rust so Windows `autoenroll.dll` works unchanged, and ship `certmonger`/`cepces` for Linux. Rejected because (a) MS-WCCE is Windows-implementation-shaped (DCE/RPC, ICertPassage UUID, template-OID-based profile selection, `msPKI-*` attribute blob) coupling the CA to AD-specific concepts; (b) implementing MS-WCCE server-side requires reimplementing the entire AD CS policy/exit module lifecycle (`ICertPolicy2`/`ICertExit2` COM interfaces), ~3x the code of an ACME server; (c) MS-WCCE has no macOS or iOS client (Apple uses SCEP via MDM), forcing a second protocol for Apple platforms; (d) MS-WCCE has no equivalent of ACME's `http-01`/`dns-01`/`tls-alpn-01` challenge types, blocking automated cert issuance for non-domain-joined hosts.

**Candidate B: ACME-only, no MS-WCCE bridge.** Ship only ACME; require all Windows hosts to run the framework's Client SDK. Rejected because (a) during migration, Windows hosts are in a mixed state (some framework-enrolled, some still on AD); the framework cannot serve cert enrollment to AD-enrolled Windows hosts without MS-WCCE; (b) third-party Windows software using `X509Enrollment` COM API cannot be re-pointed at ACME without code changes — customers would wait for vendors to ship ACME-aware versions, which may never happen; (c) the framework's migration value proposition (drop-in AD replacement) requires that existing Windows autoenroll policies continue to work. The bridge approach (separate service, deprecate when Windows hosts migrate to the SDK) provides interop without making MS-WCCE a first-class protocol.

**Candidate C: Dogtag-style REST API, no ACME.** Implement a custom REST API similar to Dogtag PKI's. Rejected because (a) ACME is a published RFC (8555) with mature client libraries (acme-macro in Rust, certbot in Python, lego in Go, win-acme in .NET) giving the framework immediate cross-language client support; (b) a custom REST API would require the framework to ship and maintain clients for every language its customers use; (c) ACME's challenge-based authorization is well-suited to the framework's attestation-based enrollment; (d) Dogtag's REST API is non-standard and ties customers to Dogtag-specific tooling.

The chosen ACME-primary + bridge model gives the framework: (a) a standard, RFC-compliant enrollment protocol with broad client-library support; (b) Windows interop via the MS-WCCE bridge (migration path); (c) IoT/network-device support via EST and SCEP bridges; (d) a clean deprecation path for the bridges once customers migrate to the SDK (the bridges become no-op services when no clients use them, and can be removed in v2).

The `adrian-attest-01` challenge type is non-standard but ACME explicitly allows non-standard challenge types (RFC 8555 §8.1). The challenge payload is a TPM2 quote (per TPM2 spec) or Apple Secure Enclave attestation (per Apple's `DeviceCheck` API), signed by the host's attestation key. The ACME server validates the quote/attestation against the host's registered attestation root (provisioned during host enrollment).

## Trade-offs accepted

- **MS-WCCE bridge is a maintenance burden.** The bridge must be maintained for the duration of Windows-mixed-mode operation (potentially 5-7 years). The bridge's MS-WCCE implementation must track Microsoft's MS-WCCE protocol revisions (rare but real — e.g., the v4 template format introduced with Server 2016 added new `msPKI-*` attributes). Acceptable because the alternative (no bridge) blocks Windows migration.
- **`adrian-attest-01` is non-standard.** Customers using third-party ACME clients (certbot, lego) cannot use the attestation challenge; they must use the framework's Client SDK or a framework-compatible ACME client. Acceptable because attestation is mandatory for machine-identity enrollment (otherwise any host that can solve `http-01` can get a machine cert). Third-party ACME clients still work for non-attestation profiles (e.g., web server TLS certs via `http-01`/`dns-01`).
- **ACME has no native key archival.** ACME assumes the client generates the keypair; the CA never sees the private key. For archival-required profiles, the framework extends ACME with a CRMF-wrapped envelope (per RFC 4211), which is non-standard ACME. Customers using third-party ACME clients for archival-required profiles see an ACME error directing them to the framework's SDK. Acceptable because key archival is rare (S/MIME and a few compliance-mandated use cases).
- **NTAuthCertificates is replaced, not preserved.** The framework does not maintain an `NTAuthCertificates` AD object for AD interop. During migration, both lists must be kept in sync via the framework's `adrian-migrate ntauth` CLI. Acceptable because the framework's trust-manager (ADR-036) handles cross-platform distribution.
- **No Dogtag REST API.** Customers with existing Dogtag REST tooling must rewrite against ACME. Acceptable because ACME is the modern standard and Dogtag's REST API is non-portable.

## Rust implementation implications

The decision is implementable in pure Rust with the following crate graph:

- **`adrian-ca-core`** (workspace member) — the CA itself: X.509 issuance, signing, profile validation, key archival. Crates: `x509-cert = "0.2"` (RustCrypto's X.509 library), `der = "0.7"`, `pkcs8 = "0.10"`, `pkcs10 = "0.2"`, `pkcs7 = "0.4"` (for CMS envelopes), `signature = "2"`, `rsa = "0.9"`, `ecdsa = "0.16"`, `ed25519-dalek = "2"`, `sha2 = "0.10"`, `rand = "0.8"`, `tokio = "1"`, `sqlx = "0.7"` (PostgreSQL for CA database, replacing AD CS's ESE), `rustls = "0.23"` (TLS termination).
- **`adrian-acme-server`** (workspace member) — the ACME server. Crates: `axum = "0.7"` (HTTP server), `tower-http = "0.5"`, `serde_json`, `jsonwebtoken = "9"` (JWS/JWT), `josekit = "0.8"` (JWK management), `base64 = "0.21"`, `sha2`, `ring = "0.17"` (signature verification, complementing RustCrypto). The ACME state machine is implemented as a `tokio` task per order, persisting state in PostgreSQL via `sqlx`.
- **`adrian-wcce-bridge`** (workspace member, binary) — the MS-WCCE bridge. Crates: `tokio`, `rustls`, `axum` (for the MS-XCEP/MS-WSTEP SOAP-over-HTTPS endpoints), `quick-xml` (SOAP envelope parsing), `x509-cert`, `pkcs10`. The MS-WCCE DCE/RPC server is implemented via a hand-rolled MS-RPCE encoder (no published Rust crate for MS-WCCE server side; `samba-rs` has partial DCE/RPC support but is not production-ready). The DCE/RPC endpoint mapper (TCP/135) and the dynamic RPC port listener are implemented in pure Rust using `tokio` TCP. Estimated 4K lines of Rust for the DCE/RPC layer.
- **`adrian-est-bridge`** (workspace member, binary) — the EST bridge. Crates: `axum`, `rustls`, `pkcs7`, `pkcs10`, `x509-cert`. EST is HTTP-based (no DCE/RPC), so the bridge is a thin wrapper. ~800 lines of Rust.
- **`adrian-scep-bridge`** (workspace member, binary) — the SCEP bridge. Crates: `axum`, `rustls`, `pkcs7`, `pkcs10`, `x509-cert`, `rasn = "0.7"` (for the SCEP ASN.1 message types). ~1.2K lines of Rust.
- **`adrian-attest`** (workspace member, library) — the attestation verification library used by the ACME server to validate `adrian-attest-01` challenges. Crates: `tpm2-rs = "0.1"` (TPM2 quote verification; if no mature crate exists, use `tss-esapi` FFI bindings to the TPM2 TSS C library), `serde_json`, `signature`. For macOS attestation, the bridge calls Apple's `DeviceCheck` API via a small Swift bridge (compiled as a static library, linked into the Rust binary via `swift-bridge = "0.2"`).
- **`adrian-trust-manager`** (workspace member) — the trust distribution service. Per [ADR-036](../adr/ADR-036-trust-manager-cross-cert-interop.md). Crates: `x509-cert`, `tokio`, `axum`, `sqlx`. Distributes `LogonAuthorizedCAs` to all hosts.
- **`adrian-certmonger-compat`** (workspace member, library) — a compatibility shim that exposes the framework's ACME enrollment to `certmonger` (Linux's standard cert enrollment daemon) via a certmonger `certmaster`-style plugin. Crates: `tokio`, `serde`, `clap`. This allows customers with existing `certmonger` deployments to keep using `certmonger` as the orchestration layer while the framework provides the CA backend. ~600 lines of Rust.
- **`adrian-ca-cli`** (workspace member, binary) — the `adrian-ca` CLI. Crates: `clap = "4"`, `tokio`, `serde_json`, `tracing-subscriber`. Subcommands: `install`, `profile validate`, `profile apply`, `revoke`, `crl publish`, `ocsp status`, `kra recover`, `migrate ntauth`.

The CA's signing key is bound to an HSM via PKCS#11 (per ADR-037). The Rust PKCS#11 bindings use `cryptoki = "0.5"` (the RustCrypto PKCS#11 crate). On Windows, the framework also supports CNG KSP via `windows = "0.54"` (`NCrypt*` API). The CA's HSM access is mediated by a small `adrian-hsm` library that exposes a uniform `Signer` trait regardless of the underlying PKCS#11 or CNG backend.

The MS-WCCE bridge's DCE/RPC implementation is the highest-risk item. The framework's CI includes a Windows Server 2022 VM that runs `certreq.exe` against the bridge on every PR, validating that the bridge correctly translates the MS-WCCE request to an ACME order and returns the issued cert. The bridge's MS-XCEP/MS-WSTEP SOAP endpoints are tested via `certutil -pulse` (which triggers autoenroll) on the Windows VM.

Estimated effort: ~22 person-weeks for v1. Breakdown: ACME server (5 pw), CA core (4 pw), MS-WCCE bridge + DCE/RPC (6 pw, highest-risk), EST bridge (1 pw), SCEP bridge (2 pw), attestation library + TPM2/SE integration (3 pw), `certmonger` compat (1 pw). The MS-WCCE bridge is the critical-path item; if it slips, Windows autoenroll migration is blocked.

## Problems unblocked

| Problem | Capability | Severity | Gating ORQ before | Status after |
|---------|-----------|----------|---------------------|--------------|
| PC-057 — AD CS Windows-only; no open-source MS-WCCE server | Cert Service | blocker | ORQ-110/111 | Unblocked — ACME server (Rust) provides cross-platform enrollment; MS-WCCE bridge provides Windows `autoenroll.dll` interop |
| PC-058 — Certificate templates (msPKI-*) complex | Cert Service | high | ORQ-110/111 | Unblocked — declarative `cert-profiles.yaml` replaces `msPKI-*` template attributes; ADMX/profile migration tooling translates AD CS templates to framework profiles |
| PC-059 — Autoenrollment via `autoenroll.dll` CSE Windows-only | Cert Service | high | ORQ-110/111 | Unblocked — framework Client SDK cert enrollment module (ACME + `adrian-attest-01`) replaces `autoenroll.dll`; synthetic Windows CSE (per Decision 7) preserves GPO-driven autoenroll invocation |
| PC-060 — Key archival (KRA) risky | Cert Service | high | (ADR-032 covers KRA mechanism) | Implementation locked — `archival_required` profile field triggers CRMF-wrapped enrollment per ADR-032 |
| PC-061 — OCSP responder scaling | Cert Service | high | (ADR-033 covers OCSP) | Implementation locked — ACME issuance feeds the OCSP responder database per ADR-033 |
| PC-064 — NDES (SCEP) fragile + IIS dependency | Cert Service | medium | ORQ-110/111 | Unblocked — `adrian-scep-bridge` replaces NDES with a standalone Rust service (no IIS) |
| PC-067 — NTAuthCertificates canonical CA list | Cert Service | high | ORQ-110/111 | Unblocked — `LogonAuthorizedCAs` directory attribute + trust-manager (ADR-036) replaces `NTAuthCertificates`; migration CLI copies AD's `NTAuthCertificates` contents |
| PC-027 — PKINIT smart-card logon | KDC | high | ORQ-110/111 (NTAuthCertificates + Enterprise CA dependency) | Unblocked — KDC's PKINIT validator reads `LogonAuthorizedCAs`; smart-card logon certs issued via ACME with the `smartcard_logon` EKU profile |

## Implementation impact

The decision locks the Cert Service's v1 architecture. The ACME server is the public enrollment API; the bridges are deployment-time choices. The Helm chart (per ADR-058) deploys the ACME server, the CA core, and optionally the bridges as separate Deployments/StatefulSets in the same Kubernetes namespace.

The MS-WCCE bridge is migration-critical. Customers moving from AD CS must keep the bridge running until all Windows hosts are migrated to the framework's Client SDK. The bridge's deprecation timeline is 5 years (matching ADR-039's WS-Trust bridge), with removal in v2.0.

The `adrian-migrate from-adcs` CLI walks an AD CS server's template list (via `certutil -catemplates` or LDAP query of `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<forest-root>`), translates each v1/v2/v3 template to a framework profile, and emits `cert-profiles.yaml` for review and commit. Complex `msPKI-*` attributes with no framework equivalent are dropped with `WARN`.

The attestation library's TPM2 integration is platform-specific: Windows uses `tbsi.dll` via `windows = "0.54"` FFI; Linux uses `tss2-esapi` via `tss-esapi = "0.5"` Rust bindings; macOS uses Apple's Secure Enclave attestation via a Swift bridge. The library exposes a uniform `AttestationVerifier` trait; platform-specific implementation is selected at build time via cargo features.

## Cross-capability dependencies

- **KDC (PC-027 PKINIT).** The KDC's PKINIT validator reads `LogonAuthorizedCAs` to determine which CAs are authorized to issue smart-card logon certs. The KDC's PKINIT is implemented in Rust against `rustls` and `x509-cert`.
- **Auth Provider (smart-card logon).** The Auth Provider's smart-card logon path consumes certs issued by the framework's CA. The cert's EKU must include `smartcard_logon` (OID 1.3.6.1.4.1.311.20.2.2) and `client_auth` (OID 1.3.6.1.5.5.7.3.2).
- **Federation Gateway (Decision 9).** Uses a cert issued by the framework's CA for signing OIDC ID tokens and SAML assertions. Enrollment is automated via the Client SDK; the cert is rotated automatically via ARI.
- **File Gateway (Decision 10).** SMB 3.1.1 encryption uses certs issued by the framework's CA for Kerberos-based SMB session security.
- **Client SDK (Decision 11).** The Client SDK's cert enrollment module is the ACME client on every platform.
- **Policy Engine (Decision 7).** The `CertAutoenroll` policy area (per-host cert profile assignment) is consumed by the Client SDK's cert enrollment module. The canonical JSON's `secret_ref` type carries the host's enrollment secret.
- **Migration (PC-127 AD CS-to-framework).** The `adrian-migrate from-adcs` CLI is the migration entry point for AD CS.
- **Security (PC-123 threat model).** CA key compromise is a top Security threat; the HSM-bound root (per ADR-037) and KRA Shamir sharding (per ADR-032) are documented. The `adrian-attest-01` challenge is documented as the mechanism that prevents unauthorized cert issuance to non-enrolled hosts.

## References

- [ADR-032](../adr/ADR-032-hsm-bound-kra-shamir.md) — HSM-bound KRA with Shamir
- [ADR-033](../adr/ADR-033-ocsp-responder-rfc-6960-nonce-ha.md) — OCSP responder (RFC 6960 + nonce + HA)
- [ADR-035](../adr/ADR-035-multi-cdp-ocsp-cluster-crl-fallback.md) — multi-CDP OCSP/CRL cluster fallback
- [ADR-036](../adr/ADR-036-trust-manager-cross-cert-interop.md) — trust manager (replaces NTAuthCertificates)
- [ADR-037](../adr/ADR-037-two-tier-ca-hsm-root.md) — two-tier CA with HSM-bound root (this decision locks the enrollment protocol that ADR-037 left open)
- [PC-027, PC-057, PC-058, PC-059, PC-064, PC-067](../catalog/05-cert-service.md) — problem statements
- [RFC 8555 ACME](https://www.rfc-editor.org/rfc/rfc8555) — Automatic Certificate Management Environment
- [RFC 8737 ACME-TLS-ALPN](https://www.rfc-editor.org/rfc/rfc8737) — tls-alpn-01 challenge
- [RFC 8823 ARI](https://www.rfc-editor.org/rfc/rfc8823) — ACME Renewal Information
- [RFC 7030 EST](https://www.rfc-editor.org/rfc/rfc7030) — Enrollment over Secure Transport
- [RFC 8894 SCEP](https://www.rfc-editor.org/rfc/rfc8894) — Simple Certificate Enrollment Protocol
- [RFC 4211 CRMF](https://www.rfc-editor.org/rfc/rfc4211) — Certificate Request Message Format (for key archival)
- [MS-WCCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce) — Windows Client Certificate Enrollment Protocol
- [MS-XCEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep) — Certificate Enrollment Policy Protocol
- [MS-WSTEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep) — Certificate Enrollment Web Service
- [RustCrypto x509-cert](https://docs.rs/x509-cert) — X.509 certificate library
- [cryptoki](https://docs.rs/cryptoki) — PKCS#11 Rust bindings
