---
title: "Cert Service (PKI / CA / Enrollment) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Cert Service
tags: [spec, cert-service, pki, ca, acme, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Cert Service (PKI / CA / Enrollment) — Technical Specification

## 1. Overview

The Cert Service replaces Active Directory Certificate Services (AD CS) with a two-tier CA (offline HSM-bound root + online enterprise CA), ACME-primary enrollment (RFC 8555 + RFC 8737 + RFC 8823 ARI), MS-WCCE/MS-XCEP/MS-WSTEP bridge for Windows `autoenroll.dll` interop, OCSP responder per RFC 6960 with HA cluster, multi-CDP with CRL fallback, HSM-bound KRA keys with Shamir M-of-N secret sharing, and YAML-defined certificate profiles replacing `msPKI-*` templates. Workshop Decision 8 made ACME the primary protocol — modern, RFC-standard, and the only one with a mature Rust ecosystem (the framework's CA is the ACME server, not a client).

The capability carries 11 ADRs: ADR-032 (HSM-bound KRA keys with Shamir M-of-N), ADR-033 (OCSP responder RFC 6960 + nonce + HA cluster), ADR-034 (transactional DB with PITR, reject repair tools), ADR-035 (multi-CDP + OCSP cluster + CRL fallback), ADR-036 (trust-manager model, cross-cert for interop only), ADR-037 (two-tier CA with HSM-bound root), ADR-095 (ACME-primary + MS-WCCE bridge), ADR-096 (YAML cert profiles replace `msPKI-*`), ADR-097 (cross-platform autoenroll via ACME), ADR-098 (NDES/SCEP replacement bridge), ADR-099 (NTAuthCertificates per-tenant trust store). It resolves one blocker (PC-057 no open-source MS-WCCE server) plus four high-severity problems.

The capability is implemented as **nine** Rust crates at Layer 3: `adrian-ca` (CA core, cert issuance, HSM-bound keys), `adrian-acme-server` (RFC 8555 server), `adrian-wcce-bridge` (MS-WCCE → ACME translation), `adrian-est-bridge` (RFC 7030 EST → ACME), `adrian-scep-bridge` (RFC 8894 SCEP → ACME), `adrian-ocsp` (RFC 6960 responder), `adrian-hsm` (uniform `Signer` trait over PKCS#11/CNG), `adrian-ca-core` (shared types). External dependencies include `cryptoki` (PKCS#11), `windows` (NCrypt CNG KSP), `x509-cert`, `ring`, `rustls`, `tokio`, `axum`, `serde_yaml`, `thiserror`. The CA's PostgreSQL database stores issued certs, pending ACME orders, accounts, CRLs, OCSP responses, and KRA-archived private keys; backup/restore extends to PostgreSQL via `pgBackRest` PITR (per ADR-059).

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-ca` | 3 | CA core; cert issuance; HSM-bound CA keys; KRA key recovery with Shamir M-of-N | ADR-032, ADR-034, ADR-037, ADR-096, ADR-099 |
| `adrian-acme-server` | 3 | RFC 8555 + RFC 8737 (anycast) + RFC 8823 (ARI) ACME server; `adrian-attest-01` challenge type for framework-enrolled hosts with TPM2 / Apple Secure Enclave attestation; EAB required for all framework accounts | ADR-095, ADR-097 |
| `adrian-wcce-bridge` | 3 | MS-WCCE / MS-XCEP / MS-WSTEP → ACME translation; Windows `autoenroll.dll` interop; 4 MS-WCCE opnums (3, 4, 5, 36); gated by `ad-interop` | ADR-095 |
| `adrian-est-bridge` | 3 | RFC 7030 EST → ACME; for IoT/network devices | ADR-095, ADR-098 |
| `adrian-scep-bridge` | 3 | RFC 8894 SCEP → ACME; for legacy MDM enrollment | ADR-098 |
| `adrian-ocsp` | 3 | RFC 6960 OCSP responder; HA cluster behind load balancer; signs with delegated-issuance cert (not CA key) for HSM-offload | ADR-033, ADR-035 |
| `adrian-hsm` | 2 | Uniform `Signer` trait over PKCS#11 (via `cryptoki`) and CNG KSP (via `windows`); 5 HSM-bound keys: krbtgt, KDS, CA, KRA, token-signing | ADR-015, ADR-020, ADR-032, ADR-037 |
| `adrian-ca-core` | 2 | Shared types: `CertificateProfile`, `CertRequest`, `CertResponse`, `KeyEscrowEntry` | ADR-096 |
| `adrian-ca` (cont.) | 3 | Multi-CDP HTTP fallback; CRL fallback (per ADR-035); trust-manager cross-cert for AD-interop only (per ADR-036) | ADR-035, ADR-036 |

## 3. Key types and traits

```rust
// crates/adrian-hsm/src/lib.rs (per ADR-032, ADR-037)

/// Uniform Signer trait over PKCS#11 and CNG. The CA's issuance
/// path, the KRA's key recovery path, and the KDC's krbtgt signing
/// path all consume this trait — never the underlying cryptoki or
/// windows APIs directly.
#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, hash: &[u8], scheme: SigScheme)
        -> Result<Vec<u8>, HsmError>;
    async fn public_key(&self) -> Result<PublicKey, HsmError>;
    async fn key_label(&self) -> &str;
    async fn rotate(&self) -> Result<(), HsmError>;        // ADR-015 krbtgt
    fn algorithm(&self) -> KeyAlgorithm;
}

pub enum SigScheme { RsaPss(Hsf), EcdsaP256, EcdsaP384, Ed25519 }
pub enum KeyAlgorithm { Rsa2048, Rsa4096, EcdsaP256, EcdsaP384, Ed25519, Aes256Gcm }

pub struct Pkcs11Signer { /* cryptoki Session */ }
pub struct CngSigner { /* NCrypt NCRYPT_KEY_HANDLE */ }

impl Signer for Pkcs11Signer { /* ... */ }
impl Signer for CngSigner { /* ... */ }
```

```rust
// crates/adrian-ca/src/lib.rs (per ADR-037, ADR-096)

use x509_cert::Certificate;
use adrian_hsm::Signer;

pub struct Ca {
    signer: Arc<dyn Signer>,           // CA signing key, HSM-bound
    kra_signers: Vec<Arc<dyn Signer>>, // KRA recovery keys, HSM-bound (per ADR-032)
    db: PgPool,                         // PostgreSQL — issued certs, orders, CRLs
    profiles: Arc<DashMap<String, CertificateProfile>>,  // YAML profiles
    config: CaConfig,
}

impl Ca {
    pub async fn issue(
        &self,
        csr: &Pkcs10Csr,
        profile_name: &str,
        requesting_principal: &Principal,
    ) -> Result<Certificate, CaError>;

    pub async fn revoke(
        &self,
        serial: u64,
        reason: RevocationReason,
    ) -> Result<(), CaError>;

    pub async fn archive_private_key(
        &self,
        cert: &Certificate,
        encrypted_key: &[u8],           // encrypted to KRA public keys (Shamir M-of-N)
    ) -> Result<KeyEscrowId, CaError>;

    pub async fn recover_private_key(
        &self,
        escrow_id: KeyEscrowId,
        kra_quorum: Vec<KraPartialKey>, // M partial keys required
    ) -> Result<Vec<u8>, CaError>;

    pub async fn generate_crl(&self) -> Result<Vec<u8>, CaError>;
}

/// YAML certificate profile (per ADR-096) — replaces msPKI-* LDAP attrs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateProfile {
    pub name: String,                        // e.g. "WebServer-ECDSA-P256"
    pub version: u32,                        // profile-versioned, migration path
    pub subject_name_pattern: String,        // "CN={{fqdn}},OU=...,O=..."
    pub subject_alt_name_policy: SanPolicy,
    pub eku_constraints: Vec<Oid>,           // 1.3.6.1.5.5.7.3.1 (serverAuth), etc.
    pub validity_period: Duration,           // e.g. 90 days for short-lived
    pub renewal_window: Duration,            // e.g. 30 days before expiry
    pub key_algorithm: KeyAlgorithm,
    pub signature_algorithm: SigScheme,
    pub key_usage: KeyUsage,
    pub basic_constraints: BasicConstraints,
    pub crl_distribution_points: Vec<String>,    // HTTP URLs per ADR-035
    pub ocsp_responder_url: String,
    pub authority_information_access: Vec<String>,
    pub issuer: IssuerRef,                   // which CA tier (root/enterprise)
    pub enrollment_authz: EnrollmentAuthz,   // who can enroll
    pub archive_private_key: bool,           // KRA escrow
}

pub enum EnrollmentAuthz {
    Anonymous,                               // ACME with HTTP-01 challenge
    EabRequired,                             // ACME with EAB (account key)
    FrameworkEnrolledHost,                   // adrian-attest-01 (TPM2/SE attestation)
    AdGroup(Sid),                            // AD-interop, msPKI-certificate-application-policy
    Manual,                                  // operator-issued via CLI
}
```

```rust
// crates/adrian-acme-server/src/lib.rs (per ADR-095, ADR-097)

use axum::Router;

pub struct AcmeServer {
    ca: Arc<Ca>,
    db: PgPool,
    directory_url: String,                   // https://ca.corp.example.com/acme/directory
    eab_required: bool,
    external_account_binder: Arc<dyn EabBinder>,
}

/// ACME challenge types supported.
pub enum ChallengeType {
    Http01,                                  // RFC 8555 §8.3
    Dns01,                                   // RFC 8555 §8.4
    TlsAlpn01,                               // RFC 8737 (anycast)
    AdrianAttest01,                          // vendor; framework-enrolled hosts
                                             // TPM2 quote or Apple Secure Enclave
}

/// ARI (RFC 8823) — renewal window override based on CA-side info.
/// Hosts poll ARI endpoint to learn renewal window rather than
/// hardcoding profile's renewal_window.
pub async fn get_ari(window: ARIWindow) -> Json<ARIResponse> { /* ... */ }
```

```rust
// crates/adrian-wcce-bridge/src/lib.rs (per ADR-095)

/// MS-WCCE → ACME translation. Windows autoenroll.dll calls
/// MS-WCCE opnum 36 (Request); bridge extracts PKCS#10 CSR,
/// maps template OID to framework YAML profile via template-map.yaml,
/// creates ACME order with adrian-attest-01 challenge
/// (auto-fulfilled via Kerberos-authenticated RPC context),
/// returns issued cert as MS-WCCE response.
pub struct WcceBridge {
    acme: Arc<AcmeServer>,
    template_map: TemplateMap,
}

impl WcceBridge {
    pub async fn handle_request(
        &self,
        opnum: u8,
        request: WcceRequest,
        principal: &Principal,
    ) -> Result<WcceResponse, WcceError>;

    // Opnum 3: Request — full issuance
    // Opnum 4: GetCACert — return CA cert chain
    // Opnum 5: PKCS7 — accept response from server
    // Opnum 36: Request (modern) — full issuance with templates
}
```

## 4. Data model

```
PostgreSQL schema (CA database, per ADR-034):

  CREATE TABLE accounts (                          -- ACME accounts
    account_id UUID PRIMARY KEY,
    public_key_jwk JSONB NOT NULL,
    contact_emails TEXT[] NOT NULL,
    eab_key_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL CHECK (status IN ('valid', 'deactivated', 'revoked'))
  );

  CREATE TABLE orders (
    order_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts,
    status TEXT NOT NULL CHECK (status IN ('pending','ready','processing',
                                            'valid','invalid')),
    expires_at TIMESTAMPTZ NOT NULL,
    identifiers JSONB NOT NULL,                   -- array of {type,value}
    profile_name TEXT NOT NULL,
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    error JSONB,                                  -- RFC 8555 problem details
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE authorizations (
    authz_id UUID PRIMARY KEY,
    order_id UUID NOT NULL REFERENCES orders,
    identifier JSONB NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    wildcard BOOLEAN NOT NULL DEFAULT FALSE
  );

  CREATE TABLE challenges (
    challenge_id UUID PRIMARY KEY,
    authz_id UUID NOT NULL REFERENCES authorizations,
    type TEXT NOT NULL,                           -- 'http-01','dns-01','tls-alpn-01','adrian-attest-01'
    status TEXT NOT NULL,
    token TEXT NOT NULL,
    payload JSONB                                 -- attestation payload for adrian-attest-01
  );

  CREATE TABLE certificates (
    serial BIGINT PRIMARY KEY,
    order_id UUID REFERENCES orders,
    profile_name TEXT NOT NULL,
    subject_dn TEXT NOT NULL,
    subject_alt_names TEXT[],
    issuer_dn TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    public_key_spki BYTEA NOT NULL,
    der BYTEA NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    archived_private_key_id UUID,                 -- key escrow reference
    requesting_principal TEXT NOT NULL,           -- audit
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE key_escrow (
    escrow_id UUID PRIMARY KEY,
    cert_serial BIGINT NOT NULL REFERENCES certificates,
    encrypted_key_shards JSONB NOT NULL,          -- Shamir M-of-N shards,
                                                  -- each encrypted to one KRA public key
    shard_count INT NOT NULL,
    quorum_required INT NOT NULL,                 -- default 3 of 5
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE crls (
    crl_id UUID PRIMARY KEY,
    crl_number BIGINT NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    revoked_certs JSONB NOT NULL,                 -- array of {serial,revocation_date,reason}
    der BYTEA NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE ocsp_responses (
    serial BIGINT PRIMARY KEY REFERENCES certificates,
    cert_status TEXT NOT NULL,                    -- 'good','revoked','unknown'
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    response_der BYTEA NOT NULL,
    signature_generated_by TEXT NOT NULL          -- 'ca' or 'delegated-issuer'
  );

FDB cross-references (per ADR-073, subspace 0x09):
  (0x09, 0x01, cert_serial:u64) → { issuer, subject, status, expires }
  (0x09, 0x02, template_oid:oid) → yaml_profile_name:String

YAML profile storage (per ADR-096):
  /etc/adrian/ca/profiles/
    WebServer-ECDSA-P256.yaml
    WebServer-RSA-2048.yaml
    ClientAuth-Smartcard.yaml
    MachineIdentity-ECDSA-P256.yaml
    IPSec-IKE-Intermediate.yaml
    ...

template-map.yaml (AD-interop, per ADR-095):
  "1.3.6.1.4.1.311.21.7.1.1.1.1": WebServer-ECDSA-P256
  "1.3.6.1.4.1.311.21.7.1.1.1.2": WebServer-RSA-2048
  "1.3.6.1.4.1.311.21.7.1.1.1.3": ClientAuth-Smartcard
  ...
  # Maps AD msPKI-Certificate-Application-Policy OID to YAML profile
```

## 5. Protocol surface

```
ACME protocol (per RFC 8555 + RFC 8737 + RFC 8823):

  GET  /acme/directory              — list endpoints + nonce
  HEAD /acme/new-nonce              — get fresh nonce
  POST /acme/new-account            — create account (EAB if required)
  POST /acme/account/{id}           — account update / deactivation
  POST /acme/new-order              — create order with identifiers
  POST /acme/order/{id}             — get order status
  POST /acme/authz/{id}             — get authorization
  POST /acme/challenge/{id}         — challenge acceptance
  POST /acme/cert/{id}              — fetch issued cert (GET-cached)
  POST /acme/cert/{id}/revoke       — revoke
  GET  /acme/ari/{issuer}/{serial}  — ARI renewal window per RFC 8823
  POST /acme/key-change             — account key rollover

  All requests: JWS (RFC 7515) signed with account key.
  EAB (External Account Binding) required for all framework accounts:
    JWS protected header includes "kid" referencing EAB key ID.

  adrian-attest-01 challenge (vendor):
    payload = { "type": "tpm2-quote", "pcr_bank": "sha256",
                "pcrs": [0, 7, 11], "quote": <base64>,
                "signature": <base64>, "ak_pub": <pem> }
    OR
    payload = { "type": "apple-se-attest",
                "attestation_obj": <cbor base64>, "client_data": <json> }
    CA validates attestation against enrolled host's TPM2 AK cert
    or Apple Secure Enclave attestation root.

MS-WCCE wire protocol (per ADR-095, AD-interop):
  RPC UUID: 91ae6020-9e3c-11d1-91ad-00c04fd8d8cd (MS-WCCE)
  Opnums:
    3: Request (CARequest)        — full issuance
    4: GetCACert (CACert)         — return CA cert chain
    5: PKCS7 (Response)           — accept server response
    36: Request2 (CARequest2)     — modern issuance with templates

  Bridge translates: MS-WCCE opnum 36 → ACME new-order + adrian-attest-01
  challenge (auto-fulfilled via Kerberos-authenticated RPC context, no
  HTTP-01/DNS-01 needed for framework-enrolled hosts).

MS-XCEP / MS-WSTEP (per ADR-095):
  MS-XCEP: SOAP/HTTP — get templates, return as CEP response
  MS-WSTEP: SOAP/HTTP — request enrollment token (per-device)
  Bridge translates both to ACME account creation + EAB issuance.

EST (RFC 7030) protocol (per ADR-098):
  HTTPS /est/.well-known/est/
    cacert            — GET CA certs
    simpleenroll       — POST PKCS#10 CSR
    simplereenroll     — POST renewal CSR
    fullcmc            — POST CMC full request
    serverkeygen       — POST key generation request

SCEP (RFC 8894) protocol (per ADR-098):
  HTTP GET /scep?operation=GetCACert&message=<issuer>
  HTTP GET /scep?operation=GetCACaps
  HTTP POST /scep?operation=PKIOperation (PKCS#7 enveloped)

OCSP (RFC 6960) protocol (per ADR-033):
  HTTP POST /ocsp
    request = OCSPRequest (DER-encoded)
    response = OCSPResponse (signed by delegated-issuance cert, not CA)
  Nonce extension mandatory (per ADR-033); HA cluster behind LB.
  Reply cached 60 seconds at CDN/LB layer.

CRL distribution (per ADR-035):
  HTTP GET /crl/<issuer-hash>.crl (full CRL)
  HTTP GET /crl/<issuer-hash>-delta.crl (delta CRL)
  Multi-CDP: 2+ HTTP URLs per cert, failover on timeout.

NTAuthCertificates (per ADR-099):
  Per-tenant trust store (modernization vs AD's global canonical).
  LDAP path: CN=NTAuthCertificates,CN=Public Key Services,
             CN=Services,CN=Configuration,DC=<tenant>,...
  Each tenant has its own NTAuthCertificates object; cross-tenant
  trust requires explicit operator action.
```

## 6. Configuration

```toml
# /etc/adrian/ca.toml — Cert Service configuration

[ca]
tier                   = "enterprise"           # "root" (offline) | "enterprise" (online)
subject_dn             = "CN=Adrian Enterprise CA,DC=corp,DC=example,DC=com"
parent_ca_url          = "https://root-ca.airgap.local:8443"
key_algorithm          = "ecdsa-p256"            # CA key algorithm
validity_years         = 5                       # enterprise CA; root = 20
crl_validity_days      = 7
crl_overlap_hours      = 24
multi_cdp_urls         = [
  "http://crl1.corp.example.com/adrian-enterprise.crl",
  "http://crl2.corp.example.com/adrian-enterprise.crl"
]
ocsp_url               = "http://ocsp.corp.example.com/ocsp"

[db]
url                    = "postgres://ca@db-1.corp.example.com:5432/adrian_ca"
max_connections        = 50
pitr_enabled           = true                    # ADR-034
pitr_retention_days    = 30
pgbackrest_config      = "/etc/adrian/pgbackrest.conf"

[hsm]                                  # enterprise-hsm feature
module                 = "pkcs11"     # pkcs11 | cng
library                = "/usr/lib/softhsm/libsofthsm2.so"
slot_id                = 0
pin                    = "@file:/etc/adrian/hsm-pin"
ca_key_label           = "adrian-ca-enterprise"
kra_key_labels         = ["adrian-kra-1","adrian-kra-2","adrian-kra-3",
                          "adrian-kra-4","adrian-kra-5"]
kra_quorum_required    = 3                         # M-of-N per ADR-032
ocsp_signing_key_label = "adrian-ocsp-delegated"
root_key_label         = "adrian-ca-root"          # root tier only

[acme]
enabled                = true
directory_url          = "https://ca.corp.example.com/acme/directory"
listen_addr            = "0.0.0.0:8443"
tls_cert_file          = "/etc/adrian/acme.crt"
tls_key_file           = "/etc/adrian/acme.key"
eab_required           = true                      # ADR-095
adrian_attest_01_enabled = true                    # ADR-097
challenge_timeout_secs = 300
order_validity_secs    = 600

[wcce_bridge]                          # ADR-095, ad-interop feature
enabled                = true
rpc_listen_addr        = "0.0.0.0:135"             # RPC endpoint mapper
template_map_file      = "/etc/adrian/template-map.yaml"

[est_bridge]                           # ADR-098
enabled                = true
listen_addr            = "0.0.0.0:8444"

[scep_bridge]                          # ADR-098
enabled                = true
listen_addr            = "0.0.0.0:8080"

[ocsp]                                 # ADR-033
enabled                = true
listen_addr            = "0.0.0.0:80"
ha_cluster_members     = ["ocsp1.corp.example.com",
                          "ocsp2.corp.example.com",
                          "ocsp3.corp.example.com"]
nonce_required         = true
delegated_signing_enabled = true       # use OCSP signing cert, not CA key

[profiles]                             # ADR-096
directory              = "/etc/adrian/ca/profiles"
default_profile        = "MachineIdentity-ECDSA-P256"

[ntauth_certificates]                  # ADR-099
per_tenant             = true
ldap_base              = "CN=NTAuthCertificates,CN=Public Key Services,..."

[trust_manager]                        # ADR-036
cross_cert_for_interop = true          # cross-cert for AD-interop only
native_mode_no_cross_cert = true

[audit]
otel_endpoint          = "http://otel-collector:4317"
emit_issue             = true
emit_revoke            = true
emit_recover           = true
emit_eab_failure       = true
mitre_attack_mapping   = true
```

## 7. Error handling

```rust
// crates/adrian-ca/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("certificate profile {0} not found")]
    ProfileNotFound(String),
    #[error("CSR validation failed: {0}")]
    CsrInvalid(String),
    #[error("CSR subject '{subject}' does not match profile pattern '{pattern}'")]
    SubjectMismatch { subject: String, pattern: String },
    #[error("SAN policy violation: {0}")]
    SanPolicyViolation(String),
    #[error("EKU constraint violation: requested {requested:?}, allowed {allowed:?}")]
    EkuConstraintViolation { requested: Vec<Oid>, allowed: Vec<Oid> },
    #[error("HSM signing failed: {0}")]
    HsmError(String),
    #[error("KRA quorum not met: got {got}, required {required}")]
    KraQuorumNotMet { got: u32, required: u32 },
    #[error("key escrow {0} not found")]
    EscrowNotFound(Uuid),
    #[error("certificate with serial {0} not found")]
    CertNotFound(u64),
    #[error("certificate already revoked: serial {0}")]
    AlreadyRevoked(u64),
    #[error("PostgreSQL error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("ACME account not found: {0}")]
    AcmeAccountNotFound(Uuid),
    #[error("ACME order {0} not in valid state for cert issuance")]
    OrderNotValid(Uuid),
    #[error("EAB binding failed: {0}")]
    EabBindingFailed(String),
    #[error("adrian-attest-01 attestation verification failed: {0}")]
    AttestationFailed(String),
}

// crates/adrian-wcce-bridge/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum WcceError {
    #[error("template OID {0} not in template-map.yaml")]
    TemplateNotMapped(String),
    #[error("MS-WCCE opnum {0} not supported")]
    UnsupportedOpnum(u8),
    #[error("ACME order creation failed: {0}")]
    AcmeOrderFailed(String),
    #[error("autoenroll.dll client principal not authorized for profile {0}")]
    NotAuthorized(String),
    #[error("CA: {0}")]
    Ca(#[from] CaError),
}

// crates/adrian-ocsp/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    #[error("OCSP request malformed: {0}")]
    Malformed(String),
    #[error("nonce missing (required per ADR-033)")]
    NonceMissing,
    #[error("nonce mismatch (replay attack suspect)")]
    NonceMismatch,
    #[error("cert serial {0} not in database")]
    UnknownSerial(u64),
    #[error("HSM signing failed: {0}")]
    HsmError(String),
}
```

**Error propagation.** ACME errors use RFC 8555 problem documents with proper `type`, `title`, `detail`, `status`, and `instance` fields. MS-WCCE errors map to Windows HRESULT codes: `0x80094005` (CERTSRV_E_NO_CERTIFICATE) for `ProfileNotFound`, `0x80094811` (CERTSRV_E_TEMPLATE_DENIED) for `NotAuthorized`. OCSP errors map to OCSP response status: `malformedRequest`, `internalError`, `tryLater`, `unauthorized`. KRA quorum failures are alert-worthy and require operator intervention via `adrian-cli ca key-recover --quorum-file <file>`.

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - CertificateProfile YAML loading + validation
    - CSR validation (subject pattern, SAN policy, EKU, key usage)
    - X.509 cert construction (x509-cert builder)
    - HSM Signer mock for signing operations
    - Shamir M-of-N shard combine (positive + negative cases)
    - ACME JWS verification (RFC 7515)
    - ACME challenge HTTP-01 token derivation
    - adrian-attest-01 TPM2 quote verification (mock)
    - adrian-attest-01 Apple SE attestation verification (mock)
    - OCSP request/response round-trip
    - CRL generation (full + delta)
    - EST PKCS#7 envelope round-trip
    - SCEP PKCS#7 envelope round-trip

Integration tests — tests/integration/, real PostgreSQL + tokio
  Coverage:
    - ACME account creation + EAB binding
    - ACME new-order → authorizations → challenges → cert issuance
    - HTTP-01 challenge fulfillment by mock client
    - DNS-01 challenge fulfillment by mock client
    - adrian-attest-01 challenge fulfillment (mock TPM2 quote)
    - ARI endpoint polling
    - Cert revocation + OCSP response update
    - KRA key archive + recovery with 3-of-5 quorum
    - EST enrollment end-to-end
    - SCEP enrollment end-to-end

Interop tests — tests/interop/
  Matrix:
    - Windows Server 2022 autoenroll.dll against framework CA via
      MS-WCCE bridge (verify Windows sees issued cert in certmgr)
    - certbot (ACME client) against framework ACME server
    - step-cli (ACME client) against framework ACME server
    - OpenSSL `ocsp` client against framework OCSP responder
    - macOS Profile Manager SCEP enrollment against framework SCEP bridge
    - iOS/iPadOS MDM SCEP enrollment
    - Android Enterprise SCEP enrollment
    - Cisco IOS EST enrollment against framework EST bridge
    - FreeIPA 4.10 cert enrollment via cross-realm trust

Property-based tests — proptest
  Parsers tested:
    - X.509 cert DER round-trips
    - PKCS#10 CSR DER round-trips
    - PKCS#7 envelope round-trips
    - OCSP request/response round-trips
    - ACME JWS round-trips
    - Shamir shard encoding round-trips
  Corpus: 80+ property tests across CA crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-037: two-tier CA with HSM-bound root and enterprise CA
  - ADR-032: HSM-bound KRA keys with Shamir M-of-N (3-of-5 default)
  - ADR-096: YAML certificate profiles (replace msPKI-* attrs)
  - ADR-095: ACME server (RFC 8555 + 8737 + 8823 ARI) +
             basic autoenroll.dll interop via MS-WCCE bridge
  - ADR-033: OCSP responder (RFC 6960, nonce, HA cluster)
  - ADR-035: multi-CDP with CRL fallback
  - ADR-099: NTAuthCertificates per-tenant trust store

v1 (Phase 2):
  - Full adrian-wcce-bridge for all 4 MS-WCCE opnums (3, 4, 5, 36)
  - MS-XCEP / MS-WSTEP bridge for Windows device enrollment
  - ADR-098: EST and SCEP bridges
  - KRA key recovery with quorum (operator CLI workflow)
  - adrian-attest-01 with real TPM2 + Apple Secure Enclave attestation
  - ADR-036: trust-manager cross-cert for AD-interop
  - ADR-034: PostgreSQL PITR via pgBackRest

v2 (Phase 3):
  - Short-lived cert default (lifetime ≤ 24 hours, ARI-driven renewal)
  - Cross-forest CA trust via `adrian-cli trust establish`
  - Predictive renewal (host agent polls ARI based on cert usage patterns)
  - Clustered CA (active-active via PostgreSQL HA)
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `cryptoki` | 0.5 | PKCS#11 HSM binding (CA, KRA, OCSP signing keys) |
| `windows` | 0.54 | NCrypt CNG KSP for Windows HSM binding (alt path) |
| `x509-cert` | 0.2 | X.509 cert construction + parsing |
| `ring` | 0.17 | Crypto primitives (ECDSA, RSA, ECDH) |
| `rustls` | 0.23 | TLS for ACME/EST/SCEP/OCSP HTTPS listeners |
| `tokio` | 1 | Async runtime |
| `axum` | 0.7 | REST/HTTP server (ACME, EST, OCSP) |
| `serde_yaml` | 0.9 | YAML cert profiles |
| `sqlx` | 0.7 | PostgreSQL client (certs, orders, CRLs) |
| `rasn` | 0.22 | ASN.1 for OCSP, PKCS#10 CSR, PKCS#7 |
| `rasn-pkix` | 0.22 | X.509 + OCSP ASN.1 types |
| `rasn-cms` | 0.22 | PKCS#7/CMS for EST/SCEP/MS-WCCE |
| `jsonwebtoken` | 9 | JWS verification for ACME |
| `sha2` | 0.10 | SHA-256 for cert fingerprints + Shamir |
| `thiserror` | 1 | Error enums |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit events |
| `prometheus` | 0.13 | Metrics |
| `proptest` | 1 | Property-based tests |
| `clap` | 4 | CLI for `adrian-cli ca` subcommands |
| `uuid` | 1.10 | UUIDs for orders, accounts, escrow |
| `adrian-hsm` | * | Uniform Signer trait |
| `adrian-auth-core` | * | Principal type for enrollment authz |
| `adrian-storage-fdb` | * | FDB cross-references (subspace 0x09) |

## 11. References

- ADRs: [ADR-032](../adr/ADR-032-hsm-bound-kra-shamir.md), [ADR-033](../adr/ADR-033-ocsp-responder-rfc-6960-nonce-ha.md), [ADR-034](../adr/ADR-034-transactional-db-pitr-reject-repair.md), [ADR-035](../adr/ADR-035-multi-cdp-ocsp-cluster-crl-fallback.md), [ADR-036](../adr/ADR-036-trust-manager-cross-cert-interop.md), [ADR-037](../adr/ADR-037-two-tier-ca-hsm-root.md), [ADR-059](../adr/ADR-059-pitr-backup-dr-runbooks.md), [ADR-095](../adr/ADR-095-acme-primary-mswcce-bridge.md), [ADR-096](../adr/ADR-096-cert-profile-yaml-replaces-templates.md), [ADR-097](../adr/ADR-097-cross-platform-autoenroll-acme.md), [ADR-098](../adr/ADR-098-ndes-scep-replacement-bridge.md), [ADR-099](../adr/ADR-099-ntauthcertificates-pkinit-trust.md)
- Workshop decisions: [Decision 8 — PKI Enrollment](../workshop/decision-08-pki-enrollment.md)
- KB files: [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md), [docs/05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md), [docs/05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md), [docs/05-pki-certs/04-ocsp-crl.md](../docs/05-pki-certs/04-ocsp-crl.md)
- RFCs: RFC 5280 (X.509), RFC 6960 (OCSP), RFC 8555 (ACME), RFC 8737 (ACME-TLS-ALPN), RFC 8823 (ARI), RFC 7030 (EST), RFC 8894 (SCEP), RFC 7515 (JWS), RFC 5272 (CMC)
- MS-* specs: MS-WCCE (Windows Client Certificate Enrollment), MS-XCEP (X.509 Certificate Enrollment Policy), MS-WSTEP (Windows Secure Trust Enrollment Protocol), MS-CERTS (Certificate Services), MS-PKCA (Public Key Cryptography for Active Directory)
