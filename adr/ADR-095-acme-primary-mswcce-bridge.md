---
title: "ADR-095: ACME-primary cert enrollment with MS-WCCE bridge for Windows `autoenroll.dll` (resolves PC-057)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-057
severity: blocker
unblocked_by: Workshop Decision 8
tags: [adr, cert-service, acme, ms-wcce, ms-xcep, ms-wstep, autoenroll, enrollment, rust, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../workshop/decision-08-pki-enrollment.md
  - ../docs/05-pki-certs/01-ad-cs-architecture.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ./ADR-037-two-tier-ca-hsm-root.md
  - ./ADR-096-cert-profile-yaml-replaces-templates.md
  - ./ADR-097-cross-platform-autoenroll-acme.md
last_updated: 2026-08-14
---

# ADR-095: ACME-primary cert enrollment with MS-WCCE bridge for Windows `autoenroll.dll` (resolves PC-057)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) (PKI enrollment: ACME primary + MS-WCCE bridge + EST bridge + SCEP bridge). This ADR operationalises Decision 8's enrollment-protocol specification against the PC-057 problem surface: the Windows-only nature of AD CS (`certsvc.exe` + ESE CA database + MS-WCCE/MS-XCEP/MS-WSTEP) and the absence of any open-source MS-WCCE server implementation. It locks the enrollment-protocol choice that ADR-037 (two-tier CA with HSM-bound root) deferred.

## Context

AD CS runs as `certsvc.exe` inside `svchost -k certsvc`, hosting one or more CA instances each backed by an ESE (Jet Blue) database (`*.edb`) at `%SystemRoot%\System32\CertLog\<CAName>.edb`, per [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md). The CA database is opened via `JetInit3` + `JetBeginSession` + `JetOpenDatabase` in `certca.dll!caOpenDatabase` with tables `RequestTable`, `CertificateTable`, `CRLTable`, `KeyRecoveryTable`. Policy module `certpmod.dll` exports `ICertPolicy2` (`{8691B64C-A8D5-4FAD-A40D-7DC81CABF1CC}`); exit module `certxmod.dll` exports `ICertExit2` (`{9c37b45a-4b3f-11d1-8250-00a0c903a8cb}`).

The enrollment protocol is MS-WCCE (Windows Client Certificate Enrollment) — DCE/RPC interface ICertPassage UUID `91b9b93a-57b4-11d0-8f16-00a0484d6c9c`, version 0.0. Per [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), key opnums are 0 (`Request`), 1 (`GetCACert`), 2 (`Ping`), 36 (`Request` modern path with template OID + attribute blob). MS-XCEP (CEP, HTTPS SOAP) provides policy discovery at `/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP`. MS-WSTEP (CES, HTTPS SOAP) wraps PKCS#10 CSR in `<wstep:RequestSecurityToken>` for enrollment across forests/DMZ. The matrix in [docs/10-comparison-matrices/02-protocol-implementation-matrix.md](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md) shows that Samba does NOT implement MS-WCCE server; FreeIPA's Dogtag uses a different RA protocol; `certmonger` with the `cepces` plugin is the only Linux client of MS-WCCE/MS-XCEP.

The blocker: there is no open-source MS-WCCE server. Customers who need Windows autoenrollment (the most common AD CS use case) cannot run a non-Windows CA without losing `autoenroll.dll` integration. FreeIPA's Dogtag CA is the closest functional equivalent — supports SCEP, EST, cert autoenrollment via `certmonger`, but does NOT speak MS-WCCE/MS-XCEP/MS-WSTEP.

Workshop Decision 8 specifies the framework's answer: ship an ACME-primary enrollment server (RFC 8555 + RFC 8737 `tls-alpn-01` + RFC 8823 ARI) and a separate MS-WCCE bridge service that translates MS-WCCE/MS-XCEP/MS-WSTEP traffic from Windows `autoenroll.dll` into ACME orders. EST (RFC 7030) and SCEP (RFC 8894) are supported as thin wrappers over ACME for IoT/network devices. This ADR defines the ACME server's contract, the MS-WCCE bridge's translation model, and the deprecation timeline.

## Decision

The framework ships `adrian-acme-server` (the primary enrollment server) and `adrian-wcce-bridge` (the MS-WCCE bridge service) as separate binaries in the `adrian-ca` workspace. The ACME server speaks only ACME internally; the MS-WCCE bridge is a protocol-translator that converts MS-WCCE/MS-XCEP/MS-WSTEP traffic into ACME orders against the framework's CA. The CA core (`adrian-ca-core`) issues certs signed by the HSM-bound CA key (per ADR-037).

### Concrete specification

1. **ACME server (primary).** Per Decision 8 §1, the framework's CA exposes a standard ACME server at `https://ca.<domain>/acme/directory`. The server supports:
   - **Account management** (RFC 8555 §7.3) — `newAccount`, `account`, `keyChange`. Account keys are JWK (RFC 7517); ECDSA P-256 is the default, RSA 2048/3072 supported. Accounts are persisted in the CA's PostgreSQL database (`acme_accounts` table) with the account key's JWK thumbprint as the primary key.
   - **Order management** (RFC 8555 §7.4) — `newOrder`, `order`, `finalize`, `certificate`. Orders are bound to an account and a certificate profile (the profile is encoded in the order's URL path: `https://ca.<domain>/acme/directory/<template-slug>`). Orders persist in PostgreSQL (`acme_orders`, `acme_authorizations`, `acme_challenges` tables) with state machine `pending → ready → processing → valid | invalid`; expired orders are GC'd after 7 days.
   - **Authorization challenges** (RFC 8555 §7.5, §8) — `http-01`, `dns-01`, `tls-alpn-01` (RFC 8737). The framework also supports a non-standard `adrian-attest-01` challenge type for framework-enrolled clients that present a hardware attestation (TPM2 quote or Apple Secure Enclave attestation); this is used for machine-identity enrollment where the framework's Client SDK orchestrates the attestation.
   - **ARI** (RFC 8823) — `renewalInfo` endpoint exposes renewal-window guidance so clients renew at staggered times, avoiding CA-overload spikes.
   - **External account binding (EAB)** (RFC 8555 §7.3.5) — required for all framework-enrolled clients; the framework's Client SDK obtains an EAB MAC key from the framework's directory service during host enrollment and uses it for all subsequent ACME account creations. EAB binds an ACME account to a framework host identity, closing the "anyone who can solve a challenge can get a cert" gap that public ACME CAs accept but private enterprise CAs cannot.

2. **MS-WCCE bridge (Windows interop).** Per Decision 8 §2, the framework ships `adrian-wcce-bridge`, a Rust service that exposes the MS-WCCE DCE/RPC interface (ICertPassage UUID `91b9b93a-57b4-11d0-8f16-00a0484d6c9c`, opnum 0/1/2/36) and the MS-XCEP/MS-WSTEP SOAP endpoints (`/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP` and `/CertificateEnrollment/Service.svc/CES`). The bridge accepts incoming MS-WCCE `Request` (opnum 36) calls from Windows `autoenroll.dll` and `certreq.exe`, extracts the PKCS#10 CSR and template OID, maps the template OID to a framework certificate profile (via `template-map.yaml` — Microsoft's built-in templates have default mappings; the `adrian-migrate from-adcs` CLI generates the mappings from an AD CS server's template list), creates an ACME order against the framework's CA (fulfilling `adrian-attest-01` automatically via the host-identity context from the Kerberos-authenticated MS-WCCE RPC), and returns the issued cert as an MS-WCCE `Request` response. For MS-XCEP (CEP), the bridge serves the policy discovery SOAP response listing the framework's cert profiles mapped to AD CS template OIDs. For MS-WSTEP (CES), the bridge wraps the PKCS#10 in the SOAP envelope and unwraps the response. The bridge is a separate binary deployed on Linux (systemd) or Windows (Service); the DCE/RPC endpoint is implemented in pure Rust (`rustls` + `tokio` + a hand-rolled NCNDR/MS-RPCE encoder), listening on TCP/135 (endpoint mapper) and the dynamic RPC port range. The bridge is the only framework component that listens on TCP/135.

3. **EST bridge (RFC 7030).** Per Decision 8 §3, for IoT devices, network appliances, and embedded systems that speak EST (RFC 7030) but not ACME, the framework ships `adrian-est-bridge` — a Rust service that exposes `/est/.well-known/est/simpleenroll`, `/est/.well-known/est/simplereenroll`, `/est/.well-known/est/cacerts`, and translates each EST request to an ACME order. EST's `application/pkcs10` CSR is parsed and submitted as an ACME `finalize` payload. The EST `Authorization: Digest` header is mapped to the framework's host identity (via a pre-shared key provisioned during device enrollment).

4. **SCEP bridge (RFC 8894).** Per Decision 8 §4, for routers/switches (Cisco IOS, Juniper Junos) that only speak SCEP, the framework ships `adrian-scep-bridge` — a Rust service that exposes `/scep` and translates the SCEP `pkioperation` message (a PKCS#7 envelope containing the PKCS#10 CSR) into an ACME order. SCEP's challenge password (the `challengePassword` attribute in the CSR) is the framework's host-specific enrollment secret, provisioned by the framework's Client SDK during host enrollment.

5. **CA core.** The framework's CA core (`adrian-ca-core`) issues certs signed by the HSM-bound CA key (per ADR-037). The CA's signing key is bound to an HSM via PKCS#11 (per Decision 8 §Rust implementation implications, using `cryptoki = "0.5"`). On Windows, the framework also supports CNG KSP via `windows = "0.54"` (`NCrypt*` API). The CA's HSM access is mediated by a small `adrian-hsm` library that exposes a uniform `Signer` trait regardless of the underlying PKCS#11 or CNG backend. The CA's PostgreSQL database stores: issued certs (with serial number, subject, SAN, EKU, profile, issuance timestamp, expiry timestamp, revocation status), pending ACME orders, ACME accounts, CRLs, OCSP responses (per ADR-033), and KRA-archived private keys (per ADR-032).

6. **Attestation library.** The `adrian-attest` library (per Decision 8 §Rust implementation implications) verifies `adrian-attest-01` challenges. For TPM2 quotes, the library uses `tss-esapi = "0.5"` (Rust bindings to the TPM2 TSS C library) on Linux and `windows = "0.54"` (TBS API via `tbsi.dll`) on Windows. For Apple Secure Enclave attestation, the library uses a Swift bridge (compiled as a static library, linked via `swift-bridge = "0.2"`). The library exposes a uniform `AttestationVerifier` trait; platform-specific implementation is selected at build time via cargo features.

7. **`certmonger` compatibility.** Per Decision 8 §Rust implementation implications, the framework ships `adrian-certmonger-compat` — a compatibility shim that exposes the framework's ACME enrollment to `certmonger` (Linux's standard cert enrollment daemon) via a `certmaster`-style plugin. This allows customers with existing `certmonger` deployments to keep using `certmonger` as the orchestration layer while the framework provides the CA backend.

8. **Deprecation timeline.** The MS-WCCE bridge is migration-critical and must be maintained for the duration of Windows-mixed-mode operation (potentially 5-7 years). The bridge's deprecation timeline is 5 years (matching ADR-039's WS-Trust bridge), with removal in v2.0. Customers moving from AD CS must keep the bridge running until all Windows hosts are migrated to the framework's Client SDK (per Decision 11). Once all Windows hosts run the Client SDK's cert enrollment module (per ADR-097), the bridge is no-op and can be decommissioned.

## Rationale

Three candidate architectures were considered (per Decision 8 §Rationale).

**Candidate A: MS-WCCE server implementation, no ACME.** Implement the full MS-WCCE/MS-XCEP/MS-WSTEP server stack in Rust so Windows `autoenroll.dll` works unchanged, and ship `certmonger`/`cepces` for Linux. Rejected because (a) MS-WCCE is Windows-implementation-shaped (DCE/RPC, ICertPassage UUID, template-OID-based profile selection, `msPKI-*` attribute blob) coupling the CA to AD-specific concepts; (b) implementing MS-WCCE server-side requires reimplementing the entire AD CS policy/exit module lifecycle (`ICertPolicy2`/`ICertExit2` COM interfaces), ~3x the code of an ACME server; (c) MS-WCCE has no macOS or iOS client (Apple uses SCEP via MDM), forcing a second protocol for Apple platforms; (d) MS-WCCE has no equivalent of ACME's `http-01`/`dns-01`/`tls-alpn-01` challenge types, blocking automated cert issuance for non-domain-joined hosts.

**Candidate B: ACME-only, no MS-WCCE bridge.** Ship only ACME; require all Windows hosts to run the framework's Client SDK. Rejected because (a) during migration, Windows hosts are in a mixed state (some framework-enrolled, some still on AD); the framework cannot serve cert enrollment to AD-enrolled Windows hosts without MS-WCCE; (b) third-party Windows software using `X509Enrollment` COM API cannot be re-pointed at ACME without code changes — customers would wait for vendors to ship ACME-aware versions, which may never happen; (c) the framework's migration value proposition (drop-in AD replacement) requires that existing Windows autoenroll policies continue to work. The bridge approach (separate service, deprecate when Windows hosts migrate to the SDK) provides interop without making MS-WCCE a first-class protocol.

**Candidate C: Dogtag-style REST API, no ACME.** Implement a custom REST API similar to Dogtag PKI's. Rejected because (a) ACME is a published RFC (8555) with mature client libraries (`acme-macro` in Rust, `certbot` in Python, `lego` in Go, `win-acme` in .NET) giving the framework immediate cross-language client support; (b) a custom REST API would require the framework to ship and maintain clients for every language its customers use; (c) ACME's challenge-based authorization is well-suited to the framework's attestation-based enrollment; (d) Dogtag's REST API is non-standard and ties customers to Dogtag-specific tooling.

The chosen ACME-primary + bridge model gives the framework: (a) a standard, RFC-compliant enrollment protocol with broad client-library support; (b) Windows interop via the MS-WCCE bridge (migration path); (c) IoT/network-device support via EST and SCEP bridges; (d) a clean deprecation path for the bridges once customers migrate to the SDK (the bridges become no-op services when no clients use them, and can be removed in v2).

## Consequences

**Positive**. The framework's CA is cross-platform (Rust, no Windows dependency). ACME is RFC-compliant with broad client-library support. Windows autoenroll interop is preserved via the MS-WCCE bridge (migration path). IoT/network-device support via EST and SCEP bridges. `certmonger` compatibility preserves existing Linux cert-orchestration deployments. The bridges have a clean deprecation path (removal in v2.0).

**Negative**. The MS-WCCE bridge is a maintenance burden — it must be maintained for 5-7 years of Windows-mixed-mode operation and must track Microsoft's MS-WCCE protocol revisions (rare but real — e.g., the v4 template format introduced with Server 2016 added new `msPKI-*` attributes). The `adrian-attest-01` challenge is non-standard, so third-party ACME clients (`certbot`, `lego`) cannot use it; customers using third-party ACME clients see an ACME error directing them to the framework's SDK for attestation-required profiles. ACME has no native key archival (the client generates the keypair); for archival-required profiles, the framework extends ACME with a CRMF-wrapped envelope (per RFC 4211), which is non-standard ACME — customers using third-party ACME clients for archival-required profiles see an ACME error.

**Neutral**. The MS-WCCE bridge's DCE/RPC implementation is the highest-risk item (per Decision 8 §Rust implementation implications); the framework's CI includes a Windows Server 2022 VM that runs `certreq.exe` against the bridge on every PR, validating that the bridge correctly translates the MS-WCCE request to an ACME order and returns the issued cert. The bridge's MS-XCEP/MS-WSTEP SOAP endpoints are tested via `certutil -pulse` (which triggers autoenroll) on the Windows VM.

**Implementation cost**. ~22 person-weeks for v1 (per Decision 8 §Rust implementation implications): ACME server (5 pw), CA core (4 pw), MS-WCCE bridge + DCE/RPC (6 pw, highest-risk), EST bridge (1 pw), SCEP bridge (2 pw), attestation library + TPM2/SE integration (3 pw), `certmonger` compat (1 pw). The MS-WCCE bridge is the critical-path item; if it slips, Windows autoenroll migration is blocked.

**Operational impact**. Operators deploy the ACME server as the primary enrollment endpoint. The MS-WCCE bridge is deployed alongside the ACME server during the migration window; it is decommissioned after all Windows hosts are migrated to the Client SDK. The `adrian-ca profile validate` and `adrian-ca profile apply` CLIs manage cert profiles (per ADR-096). The `adrian-ca revoke` CLI revokes certs; the `adrian-ca ocsp status` CLI queries OCSP (per ADR-033).

## Alternatives Considered

### Alternative A: MS-WCCE server implementation, no ACME

Implement the full MS-WCCE/MS-XCEP/MS-WSTEP server stack in Rust so Windows `autoenroll.dll` works unchanged; ship `certmonger`/`cepces` for Linux.

Rejected as detailed in §Rationale and Decision 8 §Rationale Candidate A: MS-WCCE is Windows-implementation-shaped; the implementation effort is ~3x ACME; MS-WCCE has no macOS/iOS client; MS-WCCE has no challenge types for non-domain-joined hosts.

### Alternative B: ACME-only, no MS-WCCE bridge

Ship only ACME; require all Windows hosts to run the framework's Client SDK.

Rejected as detailed in §Rationale and Decision 8 §Rationale Candidate B: migration-period Windows hosts in mixed state cannot be served; third-party Windows software using `X509Enrollment` COM API cannot be re-pointed at ACME; the framework's drop-in-AD-replacement value proposition requires the bridge.

### Alternative C: Dogtag-style REST API, no ACME

Implement a custom REST API similar to Dogtag PKI's.

Rejected as detailed in §Rationale and Decision 8 §Rationale Candidate C: ACME is a published RFC with mature client libraries; a custom REST API requires shipping clients for every language; ACME's challenge-based authorization suits the framework's attestation-based enrollment; Dogtag's REST API is non-standard and ties customers to Dogtag tooling.

## Open Questions

- **`adrian-attest-01` challenge standardization.** Should the framework submit `adrian-attest-01` to the IETF ACME working group for standardization? Current decision: no — the challenge is framework-specific (uses the framework's host-enrollment attestation root); standardization would require a cross-vendor attestation root, which is out of scope. Revisit if industry demand for a standardized TPM2-attestation ACME challenge emerges.
- **MS-WCCE bridge protocol-revision tracking.** Microsoft has shipped MS-WCCE protocol revisions rarely (v4 templates with Server 2016, v5 with Server 2022 in some scenarios). The bridge must track these revisions. Current decision: the bridge's CI runs against Windows Server 2016, 2019, 2022, 2025 (when available); new revisions are added within 90 days of Microsoft release. Revisit if a Microsoft revision breaks the bridge's DCE/RPC encoding.
- **ACME account portability.** Should ACME accounts be portable across framework CA instances (e.g., for disaster recovery)? Current decision: ACME accounts are stored in the CA's PostgreSQL database; PostgreSQL streaming replication provides CA-database replication; accounts are portable via PostgreSQL failover. Revisit if customers request cross-forest ACME account portability.

## Cross-capability impact

- **Cert Service (PC-058 templates)**: ADR-096's declarative `cert-profiles.yaml` replaces AD CS templates; the MS-WCCE bridge's `template-map.yaml` maps AD CS template OIDs to framework profiles.
- **Cert Service (PC-059 autoenroll)**: ADR-097's framework Client SDK cert enrollment module is the ACME client on every platform; the MS-WCCE bridge is bypassed for framework-enrolled Windows hosts.
- **Cert Service (PC-060 KRA)**: ADR-032's HSM-bound KRA is invoked for `archival_required: true` profiles via CRMF-wrapped enrollment.
- **Cert Service (PC-061 OCSP)**: ADR-033's OCSP responder database is fed by the ACME server's cert-issuance events.
- **KDC (PC-027 PKINIT)**: The KDC's PKINIT validator reads `LogonAuthorizedCAs` (per ADR-099) to validate smart-card logon certs issued via the ACME server's `smartcard_logon` EKU profile.
- **File Gateway (Decision 10)**: SMB 3.1.1 encryption uses certs issued by the framework's CA for Kerberos-based SMB session security.
- **Client SDK (Decision 11)**: The Client SDK's cert enrollment module is the ACME client on every platform.
- **Migration (PC-127 AD CS-to-framework)**: The `adrian-migrate from-adcs` CLI is the migration entry point for AD CS; it generates `template-map.yaml` and `cert-profiles.yaml` from the AD CS server's template list.

## References

- [PC-057](../catalog/05-cert-service.md) — problem statement in the catalog
- [Workshop Decision 8](../workshop/decision-08-pki-enrollment.md) — PKI enrollment: ACME primary + MS-WCCE bridge
- [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md) — AD CS architecture, ESE CA database, policy/exit modules
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — MS-WCCE/MS-XCEP/MS-WSTEP protocols, ICertPassage UUID, opnum table
- [ADR-032](./ADR-032-hsm-bound-kra-shamir.md) — HSM-bound KRA with Shamir (key archival)
- [ADR-033](./ADR-033-ocsp-responder-rfc-6960-nonce-ha.md) — OCSP responder (RFC 6960 + nonce + HA)
- [ADR-037](./ADR-037-two-tier-ca-hsm-root.md) — Two-tier CA with HSM-bound root (this ADR locks the enrollment protocol that ADR-037 deferred)
- [ADR-096](./ADR-096-cert-profile-yaml-replaces-templates.md) — Cert profile YAML (replaces AD CS templates)
- [ADR-097](./ADR-097-cross-platform-autoenroll-acme.md) — Cross-platform autoenroll via ACME
- [RFC 8555 ACME](https://www.rfc-editor.org/rfc/rfc8555) — Automatic Certificate Management Environment
- [RFC 8737 ACME-TLS-ALPN](https://www.rfc-editor.org/rfc/rfc8737) — tls-alpn-01 challenge
- [RFC 8823 ARI](https://www.rfc-editor.org/rfc/rfc8823) — ACME Renewal Information
- [MS-WCCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce) — Windows Client Certificate Enrollment Protocol
- [MS-XCEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep) — Certificate Enrollment Policy Protocol
- [MS-WSTEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep) — Certificate Enrollment Web Service
- [`x509-cert` crate](https://docs.rs/x509-cert) — RustCrypto X.509 certificate library
- [`cryptoki` crate](https://docs.rs/cryptoki) — PKCS#11 Rust bindings
- [`tss-esapi` crate](https://docs.rs/tss-esapi) — TPM2 TSS Rust bindings
