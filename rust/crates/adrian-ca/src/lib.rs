//! # adrian-ca
//!
//! CA service — certificate issuance, revocation, templates as
//! `cert-profiles.yaml`. HSM-bound keys via `adrian-hsm`.
//!
//! ## ADRs
//!
//! - ADR-037: Two-tier CA with HSM-bound root
//! - ADR-096: cert-profile.yaml replaces AD CS templates
//! - ADR-099: NTAUTHCertificates + PKINIT trust
//! - ADR-036: Trust manager cross-cert interop
//! - ADR-053: Key escrow and NBDE
//! - ADR-067: Sigstore supply chain (cert signing)
//!
//! ## Implementation (Wave 3a)
//!
//! Real X.509 v3 certificate issuance using:
//! - [`ring::signature::EcdsaKeyPair`] for ECDSA-P256 key generation + signing
//!   (ring returns ASN.1-DER-encoded `ECDSA-Sig-Value` directly, which is
//!   what `BIT STRING` signature fields in X.509 expect).
//! - [`rasn_pkix`] types (`Certificate`, `TbsCertificate`, `AlgorithmIdentifier`,
//!   `SubjectPublicKeyInfo`, `Extension`, `CertificateList`, `TbsCertList`) for
//!   the DER-encoded certificate / CRL structure.
//! - [`adrian_hsm::SoftwareHsm`] is plumbed through (optional) for symmetric
//!   key operations; asymmetric signing uses `ring` because the HSM trait in
//!   Wave 3c only supports `Aes256` / `HmacSha1` (no `Rsa`/`Ecdsa` yet).
//!
//! The CA generates a self-signed root on `CaService::new()`, holds the
//! private key in process memory, and issues end-entity certificates from
//! PKCS#10 CSRs (parsed via a hand-rolled `CertificationRequest` ASN.1 type
//! because rasn-pkix does not yet expose PKCS#10).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitvec::prelude::{BitVec, Msb0};
use chrono::{DateTime, Duration, Utc};
use rasn::prelude::*;
use rasn_pkix::*;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as RingKeyPair};
use thiserror::Error;
use tokio::sync::RwLock;

// Domain-06 Wave 1: HSM-backed CA signing (ADR-037).
use adrian_hsm::{Hsm, KeyHandle, KeyType};

#[derive(Debug, Error)]
pub enum CaError {
    #[error("profile not found: {0}")]
    ProfileNotFound(String),
    #[error("csr invalid: {0}")]
    CsrInvalid(String),
    #[error("issuance denied: {0}")]
    IssuanceDenied(String),
    #[error("hsm: {0}")]
    Hsm(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("encoding: {0}")]
    Encoding(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<rasn::error::EncodeError> for CaError {
    fn from(e: rasn::error::EncodeError) -> Self {
        CaError::Encoding(e.to_string())
    }
}

impl From<rasn::error::DecodeError> for CaError {
    fn from(e: rasn::error::DecodeError) -> Self {
        CaError::Encoding(e.to_string())
    }
}

impl From<ring::error::KeyRejected> for CaError {
    fn from(e: ring::error::KeyRejected) -> Self {
        CaError::Crypto(e.to_string())
    }
}

impl From<ring::error::Unspecified> for CaError {
    fn from(e: ring::error::Unspecified) -> Self {
        CaError::Crypto(e.to_string())
    }
}

impl From<adrian_hsm::HsmError> for CaError {
    fn from(e: adrian_hsm::HsmError) -> Self {
        CaError::Hsm(e.to_string())
    }
}

// ===========================================================================
// Certificate profile (ADR-096)
// ===========================================================================

/// Certificate profile (canonical YAML, ADR-096).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CertProfile {
    pub name: String,
    pub template_oid: String,
    pub key_usages: Vec<String>,
    pub extended_key_usages: Vec<String>,
    pub validity_days: u32,
    pub subject_name_format: String,
    pub san_templates: Vec<String>,
    pub enrollment_auth: EnrollmentAuth,
}

/// Enrollment authorization mode (replaces AD CS template ACLs).
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub enum EnrollmentAuth {
    Anonymous,
    DomainAuth,
    AgentApproval,
}

/// Built-in profile kinds (Wave 3a). Each maps to a canonical `CertProfile`
/// via `CertProfileKind::profile()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertProfileKind {
    WebServer,
    Client,
    CodeSigning,
    KerberosKdc,
}

impl CertProfileKind {
    /// Convert this built-in kind into a fully-populated `CertProfile`.
    pub fn profile(self) -> CertProfile {
        match self {
            CertProfileKind::WebServer => CertProfile {
                name: "adrian-webserver".into(),
                template_oid: "1.3.6.1.4.1.5991.1.10".into(),
                key_usages: vec!["digitalSignature".into(), "keyEncipherment".into()],
                extended_key_usages: vec![
                    "1.3.6.1.5.5.7.3.1".into(), // serverAuth
                ],
                validity_days: 90,
                subject_name_format: "CN={common_name}".into(),
                san_templates: vec!["DNS:{dns_name}".into()],
                enrollment_auth: EnrollmentAuth::Anonymous,
            },
            CertProfileKind::Client => CertProfile {
                name: "adrian-client".into(),
                template_oid: "1.3.6.1.4.1.5991.1.11".into(),
                key_usages: vec!["digitalSignature".into()],
                extended_key_usages: vec![
                    "1.3.6.1.5.5.7.3.2".into(), // clientAuth
                ],
                validity_days: 365,
                subject_name_format: "CN={common_name}".into(),
                san_templates: vec!["UPN:{upn}".into()],
                enrollment_auth: EnrollmentAuth::DomainAuth,
            },
            CertProfileKind::CodeSigning => CertProfile {
                name: "adrian-codesigning".into(),
                template_oid: "1.3.6.1.4.1.5991.1.12".into(),
                key_usages: vec!["digitalSignature".into(), "keyCertSign".into()],
                extended_key_usages: vec![
                    "1.3.6.1.5.5.7.3.3".into(), // codeSigning
                ],
                validity_days: 1095,
                subject_name_format: "CN={common_name}".into(),
                san_templates: vec![],
                enrollment_auth: EnrollmentAuth::AgentApproval,
            },
            CertProfileKind::KerberosKdc => CertProfile {
                name: "adrian-kdc".into(),
                template_oid: "1.3.6.1.4.1.5991.1.1".into(),
                key_usages: vec!["digitalSignature".into(), "keyEncipherment".into()],
                extended_key_usages: vec![
                    "1.3.6.1.5.2.3.5".into(), // KRB5 KDC PKINIT
                ],
                validity_days: 365,
                subject_name_format: "CN={host}.adrian.dev".into(),
                san_templates: vec!["DNS:{host}.adrian.dev".into()],
                enrollment_auth: EnrollmentAuth::DomainAuth,
            },
        }
    }

    /// Lookup a kind by canonical profile name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "adrian-webserver" => Some(Self::WebServer),
            "adrian-client" => Some(Self::Client),
            "adrian-codesigning" => Some(Self::CodeSigning),
            "adrian-kdc" => Some(Self::KerberosKdc),
            _ => None,
        }
    }
}

// ===========================================================================
// Algorithm identifiers (RFC 5480 — ECDSA P-256 / SHA-256)
// ===========================================================================

/// OID `1.2.840.10045.4.3.2` — ecdsa-with-SHA256 (signature algorithm).
const OID_ECDSA_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];

/// OID `1.2.840.10045.2.1` — id-ecPublicKey (subject public key algorithm).
const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];

/// OID `1.2.840.10045.3.1.7` — secp256r1 (named curve parameter).
const OID_SECP256R1: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];

/// OID `2.5.4.3` — commonName (X.520 attribute type).
const OID_COMMON_NAME: &[u32] = &[2, 5, 4, 3];

/// OID `2.5.29.14` — subjectKeyIdentifier.
const OID_SKI: &[u32] = &[2, 5, 29, 14];

/// OID `2.5.29.15` — keyUsage.
const OID_KU: &[u32] = &[2, 5, 29, 15];

/// OID `2.5.29.17` — subjectAltName.
const OID_SAN: &[u32] = &[2, 5, 29, 17];

/// OID `2.5.29.19` — basicConstraints.
const OID_BC: &[u32] = &[2, 5, 29, 19];

/// OID `2.5.29.35` — authorityKeyIdentifier.
const OID_AKI: &[u32] = &[2, 5, 29, 35];

/// OID `2.5.29.37` — extKeyUsage.
const OID_EKU: &[u32] = &[2, 5, 29, 37];

/// Build an `AlgorithmIdentifier` for ECDSA-with-SHA256 (no parameters).
fn ecdsa_sha256_alg_id() -> AlgorithmIdentifier {
    AlgorithmIdentifier {
        algorithm: ObjectIdentifier::new(OID_ECDSA_SHA256).expect("valid ecdsa oid"),
        parameters: None,
    }
}

/// Build an `AlgorithmIdentifier` for id-ecPublicKey with secp256r1 parameter.
fn ec_p256_pubkey_alg_id() -> AlgorithmIdentifier {
    let curve_oid = ObjectIdentifier::new(OID_SECP256R1).expect("valid secp256r1 oid");
    let curve_der = rasn::der::encode(&curve_oid).expect("encode curve oid");
    AlgorithmIdentifier {
        algorithm: ObjectIdentifier::new(OID_EC_PUBLIC_KEY).expect("valid ec-pubkey oid"),
        parameters: Some(Any::new(curve_der)),
    }
}

/// Build an `Any` from a value that implements `Encode` by encoding it to DER.
#[allow(dead_code)]
fn any_of<T: Encode>(value: &T) -> Result<Any, CaError> {
    let bytes = rasn::der::encode(value)?;
    Ok(Any::new(bytes))
}

// ===========================================================================
// Distinguished Name helpers
// ===========================================================================

/// Build an X.509 `Name` (RDN sequence) containing a single `CN={cn}`
/// attribute. Good enough for the CA subject / end-entity subject in Wave 3a.
fn name_from_cn(cn: &str) -> Name {
    let ps = PrintableString::try_from(cn).expect("CN is printable");
    let atv = AttributeTypeAndValue {
        r#type: ObjectIdentifier::new(OID_COMMON_NAME).expect("valid cn oid"),
        value: Any::from(rasn::der::encode(&ps).unwrap_or_default()),
    };
    let rdn = RelativeDistinguishedName::from(SetOf::from(vec![atv]));
    Name::RdnSequence(vec![rdn])
}

// ===========================================================================
// CA signing key pair (ring ECDSA-P256)
// ===========================================================================

/// ECDSA-P256 signing key pair held by the CA. Wraps a `ring::EcdsaKeyPair`
/// and caches the SEC1-uncompressed public-key bytes for embedding into
/// `SubjectPublicKeyInfo` and the SPKI SHA-1 hash for the SubjectKeyIdentifier
/// extension (RFC 5280 §4.2.1.2 method 1).
pub struct CaKeyPair {
    kp: Arc<EcdsaKeyPair>,
    public_sec1: Vec<u8>,
    ski_bytes: Vec<u8>,
}

impl CaKeyPair {
    /// Generate a fresh ECDSA-P256 key pair using `ring`.
    pub fn generate() -> Result<Self, CaError> {
        let rng = SystemRandom::new();
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)?;
        let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng)?;
        let public_sec1 = kp.public_key().as_ref().to_vec();
        let ski_bytes = sha1_digest(&public_sec1);
        Ok(Self {
            kp: Arc::new(kp),
            public_sec1,
            ski_bytes,
        })
    }

    /// Build from an existing PKCS#8 document (used to rehydrate a CA across
    /// restarts in future waves).
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<Self, CaError> {
        let rng = SystemRandom::new();
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8_der, &rng)?;
        let public_sec1 = kp.public_key().as_ref().to_vec();
        let ski_bytes = sha1_digest(&public_sec1);
        Ok(Self {
            kp: Arc::new(kp),
            public_sec1,
            ski_bytes,
        })
    }

    /// Sign `data` and return the DER-encoded `ECDSA-Sig-Value`
    /// (`SEQUENCE { r INTEGER, s INTEGER }`). Ring already produces this
    /// encoding, so no post-processing is needed.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CaError> {
        let rng = SystemRandom::new();
        let sig = self.kp.sign(&rng, data)?;
        Ok(sig.as_ref().to_vec())
    }

    /// SEC1 uncompressed public key (65 bytes for P-256: `0x04 || X || Y`).
    pub fn public_sec1(&self) -> &[u8] {
        &self.public_sec1
    }

    /// SubjectKeyIdentifier bytes (SHA-1 of the SEC1 public key per
    /// RFC 5280 §4.2.1.2 method (1)).
    pub fn ski_bytes(&self) -> &[u8] {
        &self.ski_bytes
    }

    /// Build the `SubjectPublicKeyInfo` for this key pair.
    pub fn spki(&self) -> SubjectPublicKeyInfo {
        let bits = BitVec::<u8, Msb0>::from_vec(self.public_sec1.clone());
        SubjectPublicKeyInfo {
            algorithm: ec_p256_pubkey_alg_id(),
            subject_public_key: bits,
        }
    }
}

// ===========================================================================
// CA signer abstraction — direct (ring) vs HSM-bound (ADR-037)
// ===========================================================================

/// Unified CA signer. Two variants:
///
/// - `Direct(CaKeyPair)` — the legacy path: ring ECDSA key pair held in
///   process memory. Used by `CaService::new()` / `with_subject_cn()` and
///   by all Wave 3a tests. Suitable for development and small deployments.
/// - `HsmBound` — the Wave 1 path: the ECDSA P-256 private key lives
///   inside an `Hsm` (software or PKCS#11), and signing goes through
///   `Hsm::sign_ecdsa`. The public key + SKI are cached in the variant
///   so cert construction stays synchronous. Used by
///   `CaService::with_hsm()` (ADR-037).
///
/// Both variants expose the same accessor surface (`public_sec1`,
/// `ski_bytes`, `spki`) and a `sign` async method.
pub enum CaSigner {
    /// Ring-backed direct signing (legacy / dev path).
    Direct(CaKeyPair),
    /// HSM-bound signing (ADR-037). The `Arc<dyn Hsm>` is shared with the
    /// caller so the HSM can be reused for other keys (OCSP signing,
    /// krbtgt, etc.).
    HsmBound {
        hsm: Arc<dyn Hsm>,
        handle: KeyHandle,
        public_sec1: Vec<u8>,
        ski_bytes: Vec<u8>,
    },
}

impl CaSigner {
    /// Sign `data` and return the DER-encoded `ECDSA-Sig-Value`. For
    /// `Direct`, uses `ring::EcdsaKeyPair::sign` directly. For `HsmBound`,
    /// delegates to `Hsm::sign_ecdsa`.
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CaError> {
        match self {
            CaSigner::Direct(kp) => kp.sign(data),
            CaSigner::HsmBound { hsm, handle, .. } => {
                let sig = hsm.sign_ecdsa(handle, data).await?;
                Ok(sig)
            }
        }
    }

    /// SEC1 uncompressed public key (65 bytes for P-256: `0x04 || X || Y`).
    pub fn public_sec1(&self) -> &[u8] {
        match self {
            CaSigner::Direct(kp) => kp.public_sec1(),
            CaSigner::HsmBound { public_sec1, .. } => public_sec1,
        }
    }

    /// SubjectKeyIdentifier bytes (SHA-1 of the SEC1 public key per
    /// RFC 5280 §4.2.1.2 method (1)).
    pub fn ski_bytes(&self) -> &[u8] {
        match self {
            CaSigner::Direct(kp) => kp.ski_bytes(),
            CaSigner::HsmBound { ski_bytes, .. } => ski_bytes,
        }
    }

    /// Build the `SubjectPublicKeyInfo` for this signer's public key.
    pub fn spki(&self) -> SubjectPublicKeyInfo {
        let bits = BitVec::<u8, Msb0>::from_vec(self.public_sec1().to_vec());
        SubjectPublicKeyInfo {
            algorithm: ec_p256_pubkey_alg_id(),
            subject_public_key: bits,
        }
    }
}

/// Compute SHA-1 digest (used for the SubjectKeyIdentifier — RFC 5280 method 1).
fn sha1_digest(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec()
}

/// Compute SHA-256 digest (used for nonce / hash tokens).
fn sha256_digest(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

// ===========================================================================
// Extension builders
// ===========================================================================

/// Build the SubjectKeyIdentifier extension (non-critical).
fn ext_ski(ski: &[u8]) -> Result<Extension, CaError> {
    let oct = OctetString::from(ski.to_vec());
    Ok(Extension {
        extn_id: ObjectIdentifier::new(OID_SKI).expect("valid ski oid"),
        critical: false,
        extn_value: OctetString::from(rasn::der::encode(&oct)?),
    })
}

/// Build the AuthorityKeyIdentifier extension (non-critical) referencing the
/// CA's SubjectKeyIdentifier.
fn ext_aki(ca_ski: &[u8]) -> Result<Extension, CaError> {
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::from(ca_ski.to_vec())),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    Ok(Extension {
        extn_id: ObjectIdentifier::new(OID_AKI).expect("valid aki oid"),
        critical: false,
        extn_value: OctetString::from(rasn::der::encode(&aki)?),
    })
}

/// Build the BasicConstraints extension. For the root CA `ca=true` with a
/// `path_len_constraint`; for end-entity certs `ca=false` with no path len.
fn ext_basic_constraints(ca: bool, path_len: Option<u64>) -> Result<Extension, CaError> {
    let bc = BasicConstraints {
        ca,
        path_len_constraint: path_len.map(Integer::from),
    };
    Ok(Extension {
        extn_id: ObjectIdentifier::new(OID_BC).expect("valid bc oid"),
        critical: true,
        extn_value: OctetString::from(rasn::der::encode(&bc)?),
    })
}

/// Bit positions in the KeyUsage BIT STRING (RFC 5280 §4.2.1.3).
const KU_DIGITAL_SIGNATURE: usize = 0;
const KU_KEY_ENCIPHERMENT: usize = 2;
const KU_KEY_CERT_SIGN: usize = 5;

/// Build the KeyUsage extension. The bit string is MSb-first per RFC 5280:
/// bit 0 (most significant) = digitalSignature, bit 2 = keyEncipherment,
/// bit 5 = keyCertSign.
fn ext_key_usage(bits: &[usize]) -> Result<Extension, CaError> {
    // 2 bytes is enough for the key usages we care about (max bit 5).
    let mut buf = [0u8; 2];
    for &b in bits {
        let byte = b / 8;
        let bit = 7 - (b % 8);
        buf[byte] |= 1u8 << bit;
    }
    // Number of unused trailing bits in the last byte.
    let last_used = bits.iter().copied().max().unwrap_or(0) % 8;
    let unused = if last_used == 0 { 0 } else { 7 - last_used };
    // BitVec from the populated bytes (we trim to just the bytes we need).
    let needed_bytes = bits.iter().map(|b| b / 8 + 1).max().unwrap_or(1);
    let mut bv = BitVec::<u8, Msb0>::from_vec(buf[..needed_bytes].to_vec());
    // Truncate the unused trailing bits so the encoder reports them.
    bv.truncate(needed_bytes * 8 - unused);
    Ok(Extension {
        extn_id: ObjectIdentifier::new(OID_KU).expect("valid ku oid"),
        critical: true,
        extn_value: OctetString::from(rasn::der::encode(&bv)?),
    })
}

/// Build the ExtendedKeyUsage extension from a list of dotted-string OIDs
/// (e.g. `"1.3.6.1.5.5.7.3.1"` for serverAuth).
fn ext_eku(ekus: &[String]) -> Result<Extension, CaError> {
    let mut oids: Vec<KeyPurposeId> = Vec::new();
    for s in ekus {
        let arcs: Vec<u32> = s
            .split('.')
            .map(|a| {
                a.parse::<u32>()
                    .map_err(|_| CaError::Encoding(format!("bad eku arc '{a}'")))
            })
            .collect::<Result<_, _>>()?;
        let oid = ObjectIdentifier::new(arcs)
            .ok_or_else(|| CaError::Encoding(format!("bad eku oid '{s}'")))?;
        oids.push(oid);
    }
    let seq: SequenceOf<KeyPurposeId> = oids.into_iter().collect();
    Ok(Extension {
        extn_id: ObjectIdentifier::new(OID_EKU).expect("valid eku oid"),
        critical: false,
        extn_value: OctetString::from(rasn::der::encode(&seq)?),
    })
}

/// Build a SubjectAltName extension from a list of DNS names.
fn ext_san_dns(dns_names: &[String]) -> Result<Extension, CaError> {
    let mut names: Vec<GeneralName> = Vec::new();
    for d in dns_names {
        let ia = Ia5String::try_from(d.clone())
            .map_err(|e| CaError::Encoding(format!("dns san: {e}")))?;
        names.push(GeneralName::DnsName(ia));
    }
    let seq: SubjectAltName = names.into_iter().collect();
    Ok(Extension {
        extn_id: ObjectIdentifier::new(OID_SAN).expect("valid san oid"),
        critical: false,
        extn_value: OctetString::from(rasn::der::encode(&seq)?),
    })
}

// ===========================================================================
// PKCS#10 CertificationRequest (RFC 2986) — manual rasn definition
// ===========================================================================

/// PKCS#10 CertificationRequestInfo (RFC 2986 §4).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub struct CertificationRequestInfo {
    pub version: Integer,
    pub subject: Name,
    pub subject_pk_info: SubjectPublicKeyInfo,
    #[rasn(tag(0))]
    pub attributes: SetOf<Attribute>,
}

/// PKCS#10 CertificationRequest (RFC 2986 §3).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub struct CertificationRequest {
    pub certification_request_info: CertificationRequestInfo,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
}

impl CertificationRequest {
    /// Parse a DER-encoded CSR.
    pub fn from_der(der: &[u8]) -> Result<Self, CaError> {
        rasn::der::decode::<Self>(der).map_err(|e| CaError::CsrInvalid(format!("der decode: {e}")))
    }

    /// Extract the SEC1 uncompressed public key bytes from the CSR's SPKI.
    /// Returns `Err` if the SPKI isn't an ECDSA-P256 key.
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, CaError> {
        let alg = &self.certification_request_info.subject_pk_info.algorithm;
        let want_alg = ObjectIdentifier::new(OID_EC_PUBLIC_KEY).expect("valid oid");
        if alg.algorithm != want_alg {
            return Err(CaError::CsrInvalid(format!(
                "unsupported public key algorithm: {}",
                alg.algorithm
            )));
        }
        // Verify the parameter is secp256r1.
        if let Some(p) = &alg.parameters {
            let decoded_oid: ObjectIdentifier = rasn::der::decode(p.as_bytes())
                .map_err(|_| CaError::CsrInvalid("bad curve parameter".into()))?;
            let want_curve = ObjectIdentifier::new(OID_SECP256R1).expect("valid oid");
            if decoded_oid != want_curve {
                return Err(CaError::CsrInvalid(format!(
                    "unsupported curve: {decoded_oid}"
                )));
            }
        } else {
            return Err(CaError::CsrInvalid("missing curve parameter".into()));
        }
        // The BitString stores the SEC1 point bytes directly.
        Ok(self
            .certification_request_info
            .subject_pk_info
            .subject_public_key
            .clone()
            .into_vec())
    }

    /// Return the subject CN (first RDN's first ATV's PrintableString value)
    /// if present.
    pub fn subject_cn(&self) -> Option<String> {
        let Name::RdnSequence(rdns) = &self.certification_request_info.subject;
        let rdn = rdns.first()?;
        let atv = rdn.to_vec().into_iter().next()?;
        let want_cn = ObjectIdentifier::new(OID_COMMON_NAME)?;
        if atv.r#type != want_cn {
            return None;
        }
        // Decode the Any as a PrintableString.
        let ps: Result<PrintableString, _> = rasn::der::decode(atv.value.as_bytes());
        ps.ok()
            .map(|s| String::from_utf8_lossy(s.as_slice()).into_owned())
    }

    /// Verify the CSR's self-signature using its embedded public key. Uses
    /// `ring::signature::UnparsedPublicKey` with `ECDSA_P256_SHA256_ASN1`
    /// (accepts DER-encoded `ECDSA-Sig-Value`).
    pub fn verify_signature(&self) -> Result<(), CaError> {
        let pub_sec1 = self.public_key_sec1()?;
        let tbs_der = rasn::der::encode(&self.certification_request_info)?;
        let sig_bytes = self.signature.clone().into_vec();
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1;
        let pk = ring::signature::UnparsedPublicKey::new(alg, pub_sec1);
        pk.verify(&tbs_der, &sig_bytes)
            .map_err(|_| CaError::CsrInvalid("self-signature invalid".into()))?;
        Ok(())
    }
}

/// Build a minimal `Attribute` set for a CSR (empty for Wave 3a — extension
/// request attributes will be added in a later wave).
#[allow(dead_code)]
fn empty_csr_attributes() -> SetOf<Attribute> {
    SetOf::from(Vec::<Attribute>::new())
}

// ===========================================================================
// Issued-cert / revoked-entry book-keeping
// ===========================================================================

/// Record of an issued certificate held in process memory.
#[derive(Clone, Debug)]
pub struct IssuedCert {
    pub serial: u64,
    pub subject_cn: Option<String>,
    pub not_after: DateTime<Utc>,
    pub der: Vec<u8>,
}

/// Record of a revoked certificate.
#[derive(Clone, Debug)]
pub struct RevokedEntry {
    pub serial: u64,
    pub revocation_date: DateTime<Utc>,
    pub reason: CrlReason,
}

/// Parse a revocation reason string into a `CrlReason`. Unknown strings
/// resolve to `Unspecified`.
pub fn parse_crl_reason(s: &str) -> CrlReason {
    match s {
        "keyCompromise" => CrlReason::KeyCompromise,
        "caCompromise" => CrlReason::CaCompromise,
        "affiliationChanged" => CrlReason::AffiliationChanged,
        "superseded" => CrlReason::Superseded,
        "cessationOfOperation" => CrlReason::CessationOfOperation,
        "certificateHold" => CrlReason::CertificateHold,
        "privilegeWithdrawn" => CrlReason::PrivilegeWithdrawn,
        "aACompromise" => CrlReason::AaCompromise,
        _ => CrlReason::Unspecified,
    }
}

// ===========================================================================
// CA service handle
// ===========================================================================

/// CA service handle. Owns the CA's signer (direct ring keypair OR HSM-bound
/// ECDSA key per ADR-037), the self-signed root certificate, an in-memory
/// issued-cert ledger, and an in-memory CRL ledger.
pub struct CaService {
    signer: Arc<CaSigner>,
    subject: Name,
    root_der: Vec<u8>,
    serial: AtomicU64,
    issued: RwLock<Vec<IssuedCert>>,
    revoked: RwLock<Vec<RevokedEntry>>,
    profiles: RwLock<HashMap<String, CertProfile>>,
}

impl CaService {
    /// Create a new CA with a freshly generated ECDSA-P256 key pair and a
    /// freshly self-signed root certificate. The root has `basicConstraints
    /// CA:TRUE pathlen:1` per the two-tier model (ADR-037). Uses the
    /// `Direct` (ring-backed) signer — for HSM-bound signing, use
    /// `with_hsm()`.
    pub fn new() -> Result<Self, CaError> {
        Self::with_subject_cn("Adrian Root CA")
    }

    /// Create a new CA with a custom subject CN.
    pub fn with_subject_cn(cn: &str) -> Result<Self, CaError> {
        let key = CaKeyPair::generate()?;
        let subject = name_from_cn(cn);
        let mut profiles = HashMap::new();
        for kind in [
            CertProfileKind::WebServer,
            CertProfileKind::Client,
            CertProfileKind::CodeSigning,
            CertProfileKind::KerberosKdc,
        ] {
            let p = kind.profile();
            profiles.insert(p.name.clone(), p);
        }
        let signer = Arc::new(CaSigner::Direct(key));
        let root_der = build_root_cert(&signer, subject.clone())?;
        Ok(Self {
            signer,
            subject,
            root_der,
            serial: AtomicU64::new(1),
            issued: RwLock::new(Vec::new()),
            revoked: RwLock::new(Vec::new()),
            profiles: RwLock::new(profiles),
        })
    }

    /// Create a new CA whose ECDSA P-256 signing key lives inside an HSM
    /// (ADR-037). The `hsm` must already have an `EcdsaP256` key under
    /// `key_id`; this constructor calls `generate_key` (idempotent) to
    /// ensure the key exists, then fetches the public key to build the
    /// root certificate. Suitable for production deployments where the
    /// CA private key must never leave the HSM boundary.
    pub async fn with_hsm(hsm: Arc<dyn Hsm>, key_id: &str, cn: &str) -> Result<Self, CaError> {
        let handle = hsm.generate_key(key_id, KeyType::EcdsaP256).await?;
        let public_sec1 = hsm.public_key_ecdsa(&handle).await?;
        let ski_bytes = sha1_digest(&public_sec1);
        let subject = name_from_cn(cn);
        let mut profiles = HashMap::new();
        for kind in [
            CertProfileKind::WebServer,
            CertProfileKind::Client,
            CertProfileKind::CodeSigning,
            CertProfileKind::KerberosKdc,
        ] {
            let p = kind.profile();
            profiles.insert(p.name.clone(), p);
        }
        let signer = Arc::new(CaSigner::HsmBound {
            hsm: hsm.clone(),
            handle: handle.clone(),
            public_sec1: public_sec1.clone(),
            ski_bytes: ski_bytes.clone(),
        });
        let root_der = build_root_cert_async(&signer, subject.clone()).await?;
        Ok(Self {
            signer,
            subject,
            root_der,
            serial: AtomicU64::new(1),
            issued: RwLock::new(Vec::new()),
            revoked: RwLock::new(Vec::new()),
            profiles: RwLock::new(profiles),
        })
    }

    /// Return the DER bytes of the self-signed root certificate.
    pub fn root_cert_der(&self) -> &[u8] {
        &self.root_der
    }

    /// Return the SEC1 uncompressed CA public key (65 bytes for P-256).
    pub fn ca_public_key_sec1(&self) -> &[u8] {
        self.signer.public_sec1()
    }

    /// Return the SubjectKeyIdentifier of the CA (for AKI on issued certs).
    pub fn ca_ski(&self) -> &[u8] {
        self.signer.ski_bytes()
    }

    /// Return the CA's subject DN.
    pub fn ca_subject(&self) -> &Name {
        &self.subject
    }

    /// Return the CA's signer (Direct or HsmBound). Used by OCSP / ARI
    /// sub-services that need to sign with the CA key.
    pub fn signer(&self) -> &Arc<CaSigner> {
        &self.signer
    }

    /// Look up an issued certificate by its serial number. Returns the
    /// `IssuedCert` record (including `not_after` for ARI renewal window
    /// computation) or `None` if the serial was never issued by this CA.
    /// Used by the ARI endpoint (RFC 8823).
    pub async fn issued_cert_by_serial(&self, serial: u64) -> Option<IssuedCert> {
        let issued = self.issued.read().await;
        issued.iter().find(|c| c.serial == serial).cloned()
    }

    /// Look up a profile by name (built-in or loaded via `load_profiles`).
    pub async fn profile(&self, name: &str) -> Result<CertProfile, CaError> {
        let profiles = self.profiles.read().await;
        profiles
            .get(name)
            .cloned()
            .ok_or_else(|| CaError::ProfileNotFound(name.to_string()))
    }

    /// List all known profile names.
    pub async fn profile_names(&self) -> Vec<String> {
        let profiles = self.profiles.read().await;
        let mut names: Vec<String> = profiles.keys().cloned().collect();
        names.sort();
        names
    }

    /// Issue a certificate per the named profile, using the CSR's subject
    /// and public key. The CSR's self-signature MUST verify. Returns the
    /// DER-encoded X.509 v3 certificate.
    pub async fn issue(&self, profile_name: &str, csr_der: &[u8]) -> Result<Vec<u8>, CaError> {
        let profile = self.profile(profile_name).await?;
        let csr = CertificationRequest::from_der(csr_der)?;
        csr.verify_signature()?;
        let pub_sec1 = csr.public_key_sec1()?;
        let subject = csr.certification_request_info.subject.clone();
        let dns_names: Vec<String> = csr.subject_cn().map(|cn| vec![cn]).unwrap_or_default();
        let serial = self.serial.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();
        let not_after = now + Duration::days(profile.validity_days as i64);

        let der = build_end_entity_cert(
            &self.signer,
            &self.subject,
            &subject,
            &pub_sec1,
            serial,
            now,
            not_after,
            &profile,
            &dns_names,
        )
        .await?;

        let issued = IssuedCert {
            serial,
            subject_cn: csr.subject_cn(),
            not_after,
            der: der.clone(),
        };
        self.issued.write().await.push(issued);
        Ok(der)
    }

    /// Revoke a certificate by its serial number. Idempotent — revoking an
    /// already-revoked serial is a no-op.
    pub async fn revoke(&self, serial: &[u8], reason: &str) -> Result<(), CaError> {
        let serial_u64 = parse_serial_bytes(serial)?;
        let entry = RevokedEntry {
            serial: serial_u64,
            revocation_date: Utc::now(),
            reason: parse_crl_reason(reason),
        };
        let mut revoked = self.revoked.write().await;
        if !revoked.iter().any(|e| e.serial == serial_u64) {
            revoked.push(entry);
        }
        Ok(())
    }

    /// Return the list of currently-revoked serials (sorted by serial).
    pub async fn revoked_serials(&self) -> Vec<u64> {
        let revoked = self.revoked.read().await;
        let mut out: Vec<u64> = revoked.iter().map(|e| e.serial).collect();
        out.sort_unstable();
        out
    }

    /// Build and sign a CRL (RFC 5280 §5) covering all currently-revoked
    /// certificates. Returns the DER-encoded `CertificateList`.
    pub async fn crl_der(&self) -> Result<Vec<u8>, CaError> {
        let revoked = self.revoked.read().await;
        let now = Utc::now();
        let next_update = now + Duration::days(7);
        let revoked_entries: Vec<RevokedCerificate> = revoked
            .iter()
            .map(|e| RevokedCerificate {
                user_certificate: Integer::from(e.serial),
                revocation_date: Time::General(e.revocation_date.fixed_offset()),
                crl_entry_extensions: None,
            })
            .collect();

        let tbs = TbsCertList {
            version: Version::V1,
            signature: ecdsa_sha256_alg_id(),
            issuer: self.subject.clone(),
            this_update: Time::General(now.fixed_offset()),
            next_update: Some(Time::General(next_update.fixed_offset())),
            revoked_certificates: revoked_entries.into_iter().collect(),
            crl_extensions: Some(Extensions::from(vec![ext_aki(self.signer.ski_bytes())?])),
        };
        let tbs_der = rasn::der::encode(&tbs)?;
        let sig = self.signer.sign(&tbs_der).await?;
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: ecdsa_sha256_alg_id(),
            signature: BitVec::<u8, Msb0>::from_vec(sig),
        };
        Ok(rasn::der::encode(&crl)?)
    }

    /// Load `cert-profiles.yaml` (ADR-096) and merge into the in-memory
    /// profile registry. Existing profiles with the same name are replaced.
    pub async fn load_profiles(&self, path: &str) -> Result<Vec<CertProfile>, CaError> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| CaError::Storage(format!("read {path}: {e}")))?;
        let parsed: Vec<CertProfile> = serde_yaml::from_str(&yaml)
            .map_err(|e| CaError::ProfileNotFound(format!("yaml parse: {e}")))?;
        let mut profiles = self.profiles.write().await;
        for p in &parsed {
            profiles.insert(p.name.clone(), p.clone());
        }
        Ok(parsed)
    }
}

impl Default for CaService {
    fn default() -> Self {
        Self::new().expect("CA generation should not fail in dev")
    }
}

// ===========================================================================
// Certificate construction helpers
// ===========================================================================

/// Build a self-signed root certificate (CA:TRUE, pathlen=1). Async because
/// the signer may be HSM-bound (signing goes through `Hsm::sign_ecdsa`).
async fn build_root_cert_async(signer: &CaSigner, subject: Name) -> Result<Vec<u8>, CaError> {
    let serial = 1u64;
    let now = Utc::now();
    let not_after = now + Duration::days(3650); // 10 years

    let mut extensions = vec![
        ext_basic_constraints(true, Some(1))?,
        ext_key_usage(&[KU_KEY_CERT_SIGN])?,
        ext_ski(signer.ski_bytes())?,
        ext_aki(signer.ski_bytes())?,
    ];

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: Integer::from(serial),
        signature: ecdsa_sha256_alg_id(),
        issuer: subject.clone(),
        validity: Validity {
            not_before: Time::General(now.fixed_offset()),
            not_after: Time::General(not_after.fixed_offset()),
        },
        subject: subject.clone(),
        subject_public_key_info: signer.spki(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(Extensions::from(std::mem::take(&mut extensions))),
    };
    let tbs_der = rasn::der::encode(&tbs)?;
    let sig = signer.sign(&tbs_der).await?;
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256_alg_id(),
        signature_value: BitVec::<u8, Msb0>::from_vec(sig),
    };
    Ok(rasn::der::encode(&cert)?)
}

/// Backwards-compat sync wrapper for `build_root_cert_async`. Used by
/// `CaService::with_subject_cn` (the non-HSM path) so existing callers
/// don't need to be async. Only supports the `Direct` signer variant
/// (HSM-bound signers MUST use the async `with_hsm` constructor).
fn build_root_cert(signer: &CaSigner, subject: Name) -> Result<Vec<u8>, CaError> {
    match signer {
        CaSigner::Direct(key) => build_root_cert_direct(key, subject),
        CaSigner::HsmBound { .. } => Err(CaError::Internal(
            "HSM-bound signer requires async construction (use with_hsm)".into(),
        )),
    }
}

/// Sync root cert builder for the `Direct` (ring-backed) signer.
fn build_root_cert_direct(key: &CaKeyPair, subject: Name) -> Result<Vec<u8>, CaError> {
    let serial = 1u64;
    let now = Utc::now();
    let not_after = now + Duration::days(3650); // 10 years

    let mut extensions = vec![
        ext_basic_constraints(true, Some(1))?,
        ext_key_usage(&[KU_KEY_CERT_SIGN])?,
        ext_ski(key.ski_bytes())?,
        ext_aki(key.ski_bytes())?,
    ];

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: Integer::from(serial),
        signature: ecdsa_sha256_alg_id(),
        issuer: subject.clone(),
        validity: Validity {
            not_before: Time::General(now.fixed_offset()),
            not_after: Time::General(not_after.fixed_offset()),
        },
        subject: subject.clone(),
        subject_public_key_info: key.spki(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(Extensions::from(std::mem::take(&mut extensions))),
    };
    let tbs_der = rasn::der::encode(&tbs)?;
    let sig = key.sign(&tbs_der)?;
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256_alg_id(),
        signature_value: BitVec::<u8, Msb0>::from_vec(sig),
    };
    Ok(rasn::der::encode(&cert)?)
}

/// Build an end-entity certificate signed by the CA. Async because the
/// signer may be HSM-bound.
#[allow(clippy::too_many_arguments)]
async fn build_end_entity_cert(
    ca_signer: &CaSigner,
    issuer: &Name,
    subject: &Name,
    pub_sec1: &[u8],
    serial: u64,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    profile: &CertProfile,
    dns_names: &[String],
) -> Result<Vec<u8>, CaError> {
    // Build key usage bits from the profile.
    let mut ku_bits: Vec<usize> = Vec::new();
    for ku in &profile.key_usages {
        match ku.as_str() {
            "digitalSignature" => ku_bits.push(KU_DIGITAL_SIGNATURE),
            "keyEncipherment" => ku_bits.push(KU_KEY_ENCIPHERMENT),
            "keyCertSign" => ku_bits.push(KU_KEY_CERT_SIGN),
            _ => {} // ignore unknown usages gracefully
        }
    }
    let mut extensions: Vec<Extension> = vec![
        ext_basic_constraints(false, None)?,
        ext_key_usage(&ku_bits)?,
        ext_ski(&sha1_digest(pub_sec1))?,
        ext_aki(ca_signer.ski_bytes())?,
    ];
    if !profile.extended_key_usages.is_empty() {
        extensions.push(ext_eku(&profile.extended_key_usages)?);
    }
    if !dns_names.is_empty() {
        extensions.push(ext_san_dns(dns_names)?);
    }

    let spki = SubjectPublicKeyInfo {
        algorithm: ec_p256_pubkey_alg_id(),
        subject_public_key: BitVec::<u8, Msb0>::from_vec(pub_sec1.to_vec()),
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: Integer::from(serial),
        signature: ecdsa_sha256_alg_id(),
        issuer: issuer.clone(),
        validity: Validity {
            not_before: Time::General(not_before.fixed_offset()),
            not_after: Time::General(not_after.fixed_offset()),
        },
        subject: subject.clone(),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(Extensions::from(
            extensions.into_iter().collect::<Vec<Extension>>(),
        )),
    };
    let tbs_der = rasn::der::encode(&tbs)?;
    let sig = ca_signer.sign(&tbs_der).await?;
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256_alg_id(),
        signature_value: BitVec::<u8, Msb0>::from_vec(sig),
    };
    Ok(rasn::der::encode(&cert)?)
}

/// Parse a big-endian byte slice into a `u64` serial number. Returns
/// `NotFound` if the value doesn't fit in 64 bits.
fn parse_serial_bytes(b: &[u8]) -> Result<u64, CaError> {
    if b.is_empty() {
        return Err(CaError::NotFound("empty serial".into()));
    }
    if b.len() > 8 {
        return Err(CaError::NotFound(format!(
            "serial too long: {} bytes",
            b.len()
        )));
    }
    let mut v: u64 = 0;
    for &byte in b {
        v = (v << 8) | u64::from(byte);
    }
    Ok(v)
}

/// Hash a token to a base64url string (used internally for nonce-like tokens).
#[allow(dead_code)]
fn hash_token(data: &[u8]) -> String {
    let h = sha256_digest(data);
    base64url(&h)
}

/// Encode bytes as base64url (no padding) — minimal in-crate implementation
/// so we don't add a base64 dependency for the CA crate.
fn base64url(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    let mut chunks = data.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(TABLE[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

// ===========================================================================
// OCSP responder (RFC 6960 + RFC 8954 nonce) — Domain-06 Wave 2
// ===========================================================================

/// OID `1.3.6.1.5.5.7.48.1.1` — id-pkix-ocsp-basic (BasicOCSPResponse).
const OID_OCSP_BASIC: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];

/// OID `1.3.6.1.5.5.7.48.1.2` — id-pkix-ocsp-nonce (RFC 8954).
const OID_OCSP_NONCE: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2];

/// OID `1.3.14.3.2.26` — id-sha1 (used for CertId issuerNameHash / issuerKeyHash
/// per RFC 6960 §4.4.1 — SHA-1 is mandatory to support).
const OID_SHA1: &[u32] = &[1, 3, 14, 3, 2, 26];

/// OCSP response status (RFC 6960 §4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OcspResponseStatus {
    /// successful (0).
    Successful = 0,
    /// malformedRequest (1).
    MalformedRequest = 1,
    /// internalError (2).
    InternalError = 2,
    /// tryLater (3).
    TryLater = 3,
    /// sigRequired (5).
    SigRequired = 5,
    /// unauthorized (6).
    Unauthorized = 6,
}

/// OCSP CertID (RFC 6960 §4.1.1). Identifies a certificate by issuer name
/// hash, issuer key hash, and serial number.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub struct OcspCertId {
    /// Hash algorithm used to compute `issuer_name_hash` and
    /// `issuer_key_hash`. RFC 6960 §4.4.1 mandates SHA-1 support.
    pub hash_algorithm: AlgorithmIdentifier,
    /// Hash of the issuer's DN (the DER encoding of Name).
    pub issuer_name_hash: OctetString,
    /// Hash of the issuer's public key (the DER BIT STRING contents,
    /// i.e. the SEC1 point bytes for ECDSA).
    pub issuer_key_hash: OctetString,
    /// Serial number of the certificate being queried.
    pub serial_number: Integer,
}

/// OCSP request entry (RFC 6960 §4.1.2).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub struct OcspRequestEntry {
    /// The certificate being queried.
    pub req_cert: OcspCertId,
    /// Optional single-request extensions (e.g. nonce per-entry).
    #[rasn(default)]
    pub single_request_extensions: Option<Extensions>,
}

/// OCSP TBSRequest (RFC 6960 §4.1.1).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub struct TbsOcspRequest {
    /// RFC 6960 defaults version to v1 (0).
    #[rasn(tag(explicit(0)), default)]
    pub version: u32,
    /// Optional requestor name (X.509 GeneralName).
    #[rasn(tag(explicit(1)), default)]
    pub requestor_name: Option<GeneralName>,
    /// List of certificate status queries.
    pub request_list: SequenceOf<OcspRequestEntry>,
    /// Optional request list extensions.
    #[rasn(tag(explicit(2)), default)]
    pub request_extensions: Option<Extensions>,
}

/// OCSP request (RFC 6960 §4.1).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub struct OcspRequest {
    pub tbs_request: TbsOcspRequest,
    /// Optional signature (not used in Wave 2 — the responder accepts
    /// unsigned requests per RFC 6960 §4.1.2 which makes the signature
    /// optional for clients).
    #[rasn(default)]
    pub optional_signature: Option<OcspSignature>,
}

/// OCSP request signature (RFC 6960 §4.1.2). Unused in Wave 2 but defined
/// so the ASN.1 parser accepts signed requests (it just ignores the sig).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub struct OcspSignature {
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
    #[rasn(default)]
    pub certs: Option<SequenceOf<crate::Certificate>>,
}

/// OCSP CertStatus (RFC 6960 §4.2.1). The CHOICE is encoded as:
/// - `good` — implicit (no value, tag [0] context-specific primitive)
/// - `revoked` — SEQUENCE with revocation time + optional reason
/// - `unknown` — implicit (no value, tag [2] context-specific primitive)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// Certificate is not revoked (and not expired per CA's view).
    Good,
    /// Certificate is revoked. The `DateTime` is the revocation time.
    Revoked(DateTime<Utc>),
    /// Certificate status is unknown (e.g. serial not in CA's ledger).
    Unknown,
}

/// OCSP SingleResponse (RFC 6960 §4.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspSingleResponse {
    pub cert_id: OcspCertId,
    pub cert_status: OcspCertStatus,
    pub this_update: DateTime<Utc>,
    pub next_update: Option<DateTime<Utc>>,
}

/// Responder ID (RFC 6960 §4.2.1). Either by-name (the responder's X.509
/// DN) or by-key (SHA-1 hash of the responder's public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OcspResponderId {
    /// Responder identified by X.509 Name (RFC 6960 §4.2.1, [0] EXPLICIT).
    ByName(Name),
    /// Responder identified by SHA-1 hash of public key ([1] EXPLICIT).
    ByKey(Vec<u8>),
}

/// ResponseData (RFC 6960 §4.2.1) — the to-be-signed payload of a
/// BasicOCSPResponse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspResponseData {
    pub responder_id: OcspResponderId,
    pub produced_at: DateTime<Utc>,
    pub responses: Vec<OcspSingleResponse>,
    /// Response-level extensions (e.g. the OCSP nonce echo).
    pub extensions: Vec<Extension>,
}

/// BasicOCSPResponse (RFC 6960 §4.2.1) — the signed response payload.
#[derive(Clone, Debug)]
pub struct BasicOcspResponse {
    pub response_data: OcspResponseData,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
}

/// OCSP response (RFC 6960 §4.2.1).
#[derive(Clone, Debug)]
pub struct OcspResponse {
    pub response_status: OcspResponseStatus,
    pub response_bytes: Option<BasicOcspResponse>,
}

/// OCSP responder (RFC 6960). Holds a reference to the CA for revocation
/// state and signing. The responder signs responses with the CA's signer
/// (the CA key acts as the OCSP signing key per ADR-035's "Multi-CDP OCSP
/// cluster CRL fallback" — a delegated OCSP signing key is a future
/// enhancement).
pub struct OcspResponder {
    ca: Arc<CaService>,
}

impl OcspResponder {
    /// Create a new OCSP responder backed by the given CA.
    pub fn new(ca: Arc<CaService>) -> Self {
        Self { ca }
    }

    /// Handle a DER-encoded `OCSPRequest` (RFC 6960 §4.1). Returns a
    /// DER-encoded `OCSPResponse` (RFC 6960 §4.2.1).
    ///
    /// Steps:
    /// 1. Parse the request.
    /// 2. For each `Request` in `requestList`, look up the cert status in
    ///    the CA's revocation ledger (by serial number).
    /// 3. Build a `BasicOCSPResponse` with a `SingleResponse` per request.
    /// 4. Echo the request's nonce extension (RFC 8954) if present.
    /// 5. Sign the `ResponseData` with the CA's signer.
    /// 6. Encode the `OCSPResponse` as DER.
    pub async fn handle_request(&self, req_der: &[u8]) -> Result<Vec<u8>, CaError> {
        let req: OcspRequest = rasn::der::decode(req_der)
            .map_err(|e| CaError::Encoding(format!("ocsp request decode: {e}")))?;

        // Extract the nonce extension from the request (if any).
        let mut request_nonce: Option<Vec<u8>> = None;
        if let Some(exts) = &req.tbs_request.request_extensions {
            for ext in exts.iter() {
                if ext.extn_id == ObjectIdentifier::new(OID_OCSP_NONCE).unwrap() {
                    // The nonce extn_value is an OCTET STRING containing the
                    // raw nonce bytes (RFC 8954 — no inner DER wrapping).
                    request_nonce = Some(ext.extn_value.to_vec());
                }
            }
        }

        // Build a SingleResponse per request entry.
        let mut responses: Vec<OcspSingleResponse> = Vec::new();
        for entry in req.tbs_request.request_list.iter() {
            let cert_id = &entry.req_cert;
            let serial_u64 = u64::try_from(&cert_id.serial_number)
                .map_err(|_| CaError::Encoding("serial too large for u64".into()))?;
            let revoked = self.ca.revoked_serials().await;
            let now = Utc::now();
            let next_update = now + Duration::days(1);
            let status = if revoked.contains(&serial_u64) {
                OcspCertStatus::Revoked(now)
            } else {
                OcspCertStatus::Good
            };
            responses.push(OcspSingleResponse {
                cert_id: cert_id.clone(),
                cert_status: status,
                this_update: now,
                next_update: Some(next_update),
            });
        }

        // Build the ResponseData.
        let mut response_extensions: Vec<Extension> = Vec::new();
        if let Some(nonce) = request_nonce {
            // Echo the nonce (RFC 8954 §4: the responder MUST echo the
            // client's nonce in the response).
            response_extensions.push(Extension {
                extn_id: ObjectIdentifier::new(OID_OCSP_NONCE).unwrap(),
                critical: false,
                extn_value: OctetString::from(nonce),
            });
        }

        let response_data = OcspResponseData {
            responder_id: OcspResponderId::ByKey(self.ca.ca_ski().to_vec()),
            produced_at: Utc::now(),
            responses,
            extensions: response_extensions,
        };

        // Encode + sign the ResponseData.
        let tbs_der = encode_response_data(&response_data)?;
        let sig = self.ca.signer().sign(&tbs_der).await?;

        let basic = BasicOcspResponse {
            response_data,
            signature_algorithm: ecdsa_sha256_alg_id(),
            signature: sig,
        };

        let resp = OcspResponse {
            response_status: OcspResponseStatus::Successful,
            response_bytes: Some(basic),
        };

        encode_ocsp_response(&resp)
    }

    /// Build an axum router for the OCSP responder. The endpoint is
    /// `POST /ocsp` accepting `application/ocsp-request` and returning
    /// `application/ocsp-response`.
    pub fn router(&self) -> axum::Router {
        use axum::routing::post;
        let state = Arc::new(OcspState {
            ca: self.ca.clone(),
        });
        axum::Router::new()
            .route("/ocsp", post(ocsp_handler))
            .with_state(state)
    }
}

/// Internal state for the axum OCSP handler.
struct OcspState {
    ca: Arc<CaService>,
}

/// Axum handler for `POST /ocsp`.
async fn ocsp_handler(
    axum::extract::State(state): axum::extract::State<Arc<OcspState>>,
    body: axum::body::Body,
) -> axum::response::Response {
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    let bytes = match body.collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "body read failed").into_response();
        }
    };
    let responder = OcspResponder::new(state.ca.clone());
    match responder.handle_request(&bytes).await {
        Ok(resp_der) => {
            let mut resp = resp_der.into_response();
            resp.headers_mut().insert(
                "Content-Type",
                HeaderValue::from_static("application/ocsp-response"),
            );
            resp
        }
        Err(e) => {
            tracing::warn!("OCSP request failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "ocsp error").into_response()
        }
    }
}

/// Compute the SHA-1 hash of the issuer's Name (DER-encoded).
pub fn issuer_name_hash(name: &Name) -> Vec<u8> {
    let der = rasn::der::encode(name).unwrap_or_default();
    sha1_digest(&der)
}

/// Compute the SHA-1 hash of the issuer's public key (SEC1 bytes for ECDSA).
pub fn issuer_key_hash(public_sec1: &[u8]) -> Vec<u8> {
    sha1_digest(public_sec1)
}

/// Build a `CertId` for a certificate issued by the given CA, identified
/// by `serial`. Convenience helper for OCSP clients.
pub fn build_cert_id(ca: &CaService, serial: u64) -> OcspCertId {
    OcspCertId {
        hash_algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier::new(OID_SHA1).unwrap(),
            parameters: None,
        },
        issuer_name_hash: OctetString::from(issuer_name_hash(ca.ca_subject())),
        issuer_key_hash: OctetString::from(issuer_key_hash(ca.ca_public_key_sec1())),
        serial_number: Integer::from(serial),
    }
}

/// Manually DER-encode `OcspResponseData` (RFC 6960 §4.2.1 ResponseData).
///
/// We can't derive `Encode` for `OcspResponseData` directly because
/// `OcspCertStatus` is a CHOICE with implicit tags, and `OcspResponderId`
/// is also a CHOICE. Hand-rolling the DER is simpler than fighting rasn's
/// derive for this one-off case.
fn encode_response_data(rd: &OcspResponseData) -> Result<Vec<u8>, CaError> {
    // ResponseData ::= SEQUENCE {
    //   version            [0] EXPLICIT Version DEFAULT v1,
    //   responderID            ResponderID,
    //   producedAt             GeneralizedTime,
    //   responses              SEQUENCE OF SingleResponse,
    //   responseExtensions [1] EXPLICIT Extensions OPTIONAL
    // }
    let mut contents: Vec<u8> = Vec::new();

    // version: omit (DEFAULT v1).

    // responderID: CHOICE { byName [1] EXPLICIT Name, byKey [2] EXPLICIT KeyHash }
    match &rd.responder_id {
        OcspResponderId::ByName(name) => {
            let name_der = rasn::der::encode(name)?;
            // [1] EXPLICIT — context tag 1, constructed.
            contents.extend_from_slice(&der_tag_len(0xA1, name_der.len()));
            contents.extend_from_slice(&name_der);
        }
        OcspResponderId::ByKey(key_hash) => {
            // [2] EXPLICIT OCTET STRING.
            let oct = OctetString::from(key_hash.clone());
            let oct_der = rasn::der::encode(&oct)?;
            contents.extend_from_slice(&der_tag_len(0xA2, oct_der.len()));
            contents.extend_from_slice(&oct_der);
        }
    }

    // producedAt: GeneralizedTime.
    let gt: GeneralizedTime = rd.produced_at.into();
    let gt_der = rasn::der::encode(&gt)?;
    contents.extend_from_slice(&gt_der);

    // responses: SEQUENCE OF SingleResponse.
    let mut responses_der: Vec<u8> = Vec::new();
    for sr in &rd.responses {
        responses_der.extend_from_slice(&encode_single_response(sr)?);
    }
    contents.extend_from_slice(&der_tag_len(0x30, responses_der.len()));
    contents.extend_from_slice(&responses_der);

    // responseExtensions [1] EXPLICIT Extensions OPTIONAL.
    if !rd.extensions.is_empty() {
        let exts: Extensions = Extensions::from(rd.extensions.clone());
        let exts_der = rasn::der::encode(&exts)?;
        contents.extend_from_slice(&der_tag_len(0xA1, exts_der.len()));
        contents.extend_from_slice(&exts_der);
    }

    // Wrap in SEQUENCE.
    let mut out = der_tag_len(0x30, contents.len());
    out.extend_from_slice(&contents);
    Ok(out)
}

/// Manually DER-encode a single `SingleResponse` (RFC 6960 §4.2.1).
fn encode_single_response(sr: &OcspSingleResponse) -> Result<Vec<u8>, CaError> {
    // SingleResponse ::= SEQUENCE {
    //   certID                       CertID,
    //   certStatus                   CertStatus,
    //   thisUpdate                   GeneralizedTime,
    //   nextUpdate         [0] EXPLICIT GeneralizedTime OPTIONAL,
    //   singleExtensions   [1] EXPLICIT Extensions OPTIONAL
    // }
    let mut contents: Vec<u8> = Vec::new();

    // certID
    let cert_id_der = rasn::der::encode(&sr.cert_id)?;
    contents.extend_from_slice(&cert_id_der);

    // certStatus: CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo, unknown [2] IMPLICIT NULL }
    match &sr.cert_status {
        OcspCertStatus::Good => {
            // [0] IMPLICIT NULL — context tag 0, primitive (0x80), zero length.
            contents.extend_from_slice(&[0x80, 0x00]);
        }
        OcspCertStatus::Revoked(time) => {
            // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL }
            let gt: GeneralizedTime = (*time).into();
            let gt_der = rasn::der::encode(&gt)?;
            let mut revoked_info = Vec::new();
            revoked_info.extend_from_slice(&gt_der);
            // revocationReason omitted (Unspecified).
            // [1] IMPLICIT RevokedInfo — context tag 1, constructed (0xA1).
            contents.extend_from_slice(&der_tag_len(0xA1, revoked_info.len()));
            contents.extend_from_slice(&revoked_info);
        }
        OcspCertStatus::Unknown => {
            // [2] IMPLICIT NULL — context tag 2, primitive (0x82), zero length.
            contents.extend_from_slice(&[0x82, 0x00]);
        }
    }

    // thisUpdate
    let gt: GeneralizedTime = sr.this_update.into();
    let gt_der = rasn::der::encode(&gt)?;
    contents.extend_from_slice(&gt_der);

    // nextUpdate [0] EXPLICIT
    if let Some(nu) = sr.next_update {
        let gt: GeneralizedTime = nu.into();
        let gt_der = rasn::der::encode(&gt)?;
        contents.extend_from_slice(&der_tag_len(0xA0, gt_der.len()));
        contents.extend_from_slice(&gt_der);
    }

    // singleExtensions [1] EXPLICIT — omitted (empty).

    let mut out = der_tag_len(0x30, contents.len());
    out.extend_from_slice(&contents);
    Ok(out)
}

/// Manually DER-encode an `OCSPResponse` (RFC 6960 §4.2.1).
fn encode_ocsp_response(resp: &OcspResponse) -> Result<Vec<u8>, CaError> {
    // OCSPResponse ::= SEQUENCE {
    //   responseStatus         OCSPResponseStatus,
    //   responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL
    // }
    let mut contents: Vec<u8> = Vec::new();

    // responseStatus: ENUMERATED.
    let status_byte = resp.response_status as u8;
    contents.extend_from_slice(&der_tag_len(0x0A, 1)); // ENUMERATED, 1 byte.
    contents.push(status_byte);

    // responseBytes [0] EXPLICIT.
    if let Some(basic) = &resp.response_bytes {
        let rb_der = encode_response_bytes(basic)?;
        contents.extend_from_slice(&der_tag_len(0xA0, rb_der.len()));
        contents.extend_from_slice(&rb_der);
    }

    let mut out = der_tag_len(0x30, contents.len());
    out.extend_from_slice(&contents);
    Ok(out)
}

/// Encode `ResponseBytes` (RFC 6960 §4.2.1).
fn encode_response_bytes(basic: &BasicOcspResponse) -> Result<Vec<u8>, CaError> {
    // ResponseBytes ::= SEQUENCE {
    //   responseType   OBJECT IDENTIFIER,
    //   response       OCTET STRING
    // }
    let tbs_der = encode_response_data(&basic.response_data)?;
    // The `response` OCTET STRING contains the DER encoding of
    // BasicOCSPResponse.
    let mut basic_contents: Vec<u8> = Vec::new();
    // tbsResponseData (already DER-encoded above).
    basic_contents.extend_from_slice(&tbs_der);
    // signatureAlgorithm: AlgorithmIdentifier.
    let alg_der = rasn::der::encode(&basic.signature_algorithm)?;
    basic_contents.extend_from_slice(&alg_der);
    // signature: BIT STRING.
    let bs: BitString = BitVec::<u8, Msb0>::from_vec(basic.signature.clone());
    let bs_der = rasn::der::encode(&bs)?;
    basic_contents.extend_from_slice(&bs_der);
    // Wrap BasicOCSPResponse in SEQUENCE.
    let basic_der = der_tag_len(0x30, basic_contents.len());
    let mut full_basic = basic_der.clone();
    full_basic.extend_from_slice(&basic_contents);

    let mut contents: Vec<u8> = Vec::new();
    // responseType: OID.
    let oid = ObjectIdentifier::new(OID_OCSP_BASIC).unwrap();
    let oid_der = rasn::der::encode(&oid)?;
    contents.extend_from_slice(&oid_der);
    // response: OCTET STRING containing BasicOCSPResponse DER.
    let oct = OctetString::from(full_basic);
    let oct_der = rasn::der::encode(&oct)?;
    contents.extend_from_slice(&oct_der);

    let mut out = der_tag_len(0x30, contents.len());
    out.extend_from_slice(&contents);
    Ok(out)
}

/// Build a DER tag-length-value header for `tag` and `len`.
fn der_tag_len(tag: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + if len >= 128 { 4 } else { 0 });
    out.push(tag);
    if len < 128 {
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out
}

/// Build a test OCSP request for the given CertID. Convenience helper
/// for tests and for the ACME server's OCSP integration.
pub fn build_ocsp_request(cert_id: &OcspCertId, nonce: &[u8]) -> Result<Vec<u8>, CaError> {
    let mut request_extensions: Vec<Extension> = Vec::new();
    if !nonce.is_empty() {
        request_extensions.push(Extension {
            extn_id: ObjectIdentifier::new(OID_OCSP_NONCE).unwrap(),
            critical: false,
            extn_value: OctetString::from(nonce.to_vec()),
        });
    }
    let tbs = TbsOcspRequest {
        version: 0,
        requestor_name: None,
        request_extensions: if request_extensions.is_empty() {
            None
        } else {
            Some(Extensions::from(request_extensions))
        },
        request_list: SequenceOf::from(vec![OcspRequestEntry {
            req_cert: cert_id.clone(),
            single_request_extensions: None,
        }]),
    };
    let req = OcspRequest {
        tbs_request: tbs,
        optional_signature: None,
    };
    Ok(rasn::der::encode(&req)?)
}

/// Parse a DER-encoded `OCSPResponse` back into the structured form.
/// This is the inverse of `encode_ocsp_response`. Used by tests to verify
/// the response contents (status, cert status, nonce echo).
pub fn parse_ocsp_response(der: &[u8]) -> Result<OcspResponse, CaError> {
    // We hand-roll the parser to match the hand-rolled encoder (the
    // `OcspResponse` / `OcspResponseData` / `OcspCertStatus` types don't
    // derive Decode because of the CHOICE with implicit tags).
    let mut p = DerParser::new(der);
    p.expect_tag(0x30)?;
    let inner = p.rest_until_end()?;

    let mut p = DerParser::new(inner);
    // responseStatus: ENUMERATED.
    p.expect_tag(0x0A)?;
    let status_len = p.read_len()?;
    let status_byte = p.read_n(status_len)?[0];
    let response_status = match status_byte {
        0 => OcspResponseStatus::Successful,
        1 => OcspResponseStatus::MalformedRequest,
        2 => OcspResponseStatus::InternalError,
        3 => OcspResponseStatus::TryLater,
        5 => OcspResponseStatus::SigRequired,
        6 => OcspResponseStatus::Unauthorized,
        other => return Err(CaError::Encoding(format!("unknown ocsp status {other}"))),
    };

    // responseBytes [0] EXPLICIT (optional).
    let response_bytes = if p.remaining().is_empty() {
        None
    } else {
        p.expect_tag(0xA0)?;
        let rb_len = p.read_len()?;
        let rb_bytes = p.read_n(rb_len)?;
        Some(parse_response_bytes(rb_bytes)?)
    };

    Ok(OcspResponse {
        response_status,
        response_bytes,
    })
}

/// Parse `ResponseBytes` (contains a `BasicOCSPResponse`).
fn parse_response_bytes(der: &[u8]) -> Result<BasicOcspResponse, CaError> {
    let mut p = DerParser::new(der);
    p.expect_tag(0x30)?;
    let inner = p.rest_until_end()?;

    let mut p = DerParser::new(inner);
    // responseType: OID.
    p.expect_tag(0x06)?;
    let oid_len = p.read_len()?;
    let _oid_bytes = p.read_n(oid_len)?;
    // response: OCTET STRING containing BasicOCSPResponse DER.
    p.expect_tag(0x04)?;
    let oct_len = p.read_len()?;
    let basic_der = p.read_n(oct_len)?;
    parse_basic_ocsp_response(basic_der)
}

/// Parse a `BasicOCSPResponse`. Input is the full BasicOCSPResponse TLV.
fn parse_basic_ocsp_response(der: &[u8]) -> Result<BasicOcspResponse, CaError> {
    let mut p = DerParser::new(der);
    p.expect_tag(0x30)?;
    let inner = p.rest_until_end()?;

    let mut p = DerParser::new(inner);
    // tbsResponseData: SEQUENCE. Capture full TLV for parsing.
    let rd_tlv = p.read_tlv()?;
    let response_data = parse_response_data_tlv(rd_tlv)?;

    // signatureAlgorithm: AlgorithmIdentifier (SEQUENCE). Full TLV for rasn.
    let alg_tlv = p.read_tlv()?;
    let signature_algorithm: AlgorithmIdentifier = rasn::der::decode(alg_tlv)
        .map_err(|e| CaError::Encoding(format!("decode sig alg: {e}")))?;

    // signature: BIT STRING.
    p.expect_tag(0x03)?;
    let bs_len = p.read_len()?;
    let bs_bytes = p.read_n(bs_len)?;
    // BIT STRING: first byte is unused-bits count, rest is the signature.
    let signature = if bs_bytes.is_empty() {
        Vec::new()
    } else {
        bs_bytes[1..].to_vec()
    };

    Ok(BasicOcspResponse {
        response_data,
        signature_algorithm,
        signature,
    })
}

/// Parse a GeneralizedTime TLV's content bytes (e.g. `b"20260814120000Z"`)
/// into a `DateTime<Utc>`. RFC 5280 §4.2.1.6 requires GeneralizedTime to
/// always be in UTC (ending in `Z`), never with a local-time offset.
fn parse_generalized_time_content(bytes: &[u8]) -> Result<DateTime<Utc>, CaError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|e| CaError::Encoding(format!("producedAt utf8: {e}")))?;
    // Format: YYYYMMDDHHMMSS.fffZ or YYYYMMDDHHMMSSZ (we support the latter;
    // fractional seconds are rare in OCSP responses).
    let s = s.trim();
    let s = s.trim_end_matches('Z');
    // Pad to at least YYYYMMDDHHMMSS (14 chars).
    if s.len() < 14 {
        return Err(CaError::Encoding(format!(
            "GeneralizedTime too short: '{s}'"
        )));
    }
    let year: i32 = s[0..4]
        .parse()
        .map_err(|e| CaError::Encoding(format!("year: {e}")))?;
    let month: u32 = s[4..6]
        .parse()
        .map_err(|e| CaError::Encoding(format!("month: {e}")))?;
    let day: u32 = s[6..8]
        .parse()
        .map_err(|e| CaError::Encoding(format!("day: {e}")))?;
    let hour: u32 = s[8..10]
        .parse()
        .map_err(|e| CaError::Encoding(format!("hour: {e}")))?;
    let min: u32 = s[10..12]
        .parse()
        .map_err(|e| CaError::Encoding(format!("min: {e}")))?;
    let sec: u32 = s[12..14]
        .parse()
        .map_err(|e| CaError::Encoding(format!("sec: {e}")))?;
    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(hour, min, sec))
        .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
        .ok_or_else(|| CaError::Encoding(format!("invalid GeneralizedTime: '{s}'")))
}

/// Parse `ResponseData` from its full TLV (tag + length + content).
fn parse_response_data_tlv(der: &[u8]) -> Result<OcspResponseData, CaError> {
    let mut p = DerParser::new(der);
    p.expect_tag(0x30)?;
    let inner = p.rest_until_end()?;
    parse_response_data_content(inner)
}

/// Parse `ResponseData` content (the bytes inside the ResponseData SEQUENCE).
fn parse_response_data_content(der: &[u8]) -> Result<OcspResponseData, CaError> {
    let mut p = DerParser::new(der);

    // responderID: CHOICE { byName [1] EXPLICIT, byKey [2] EXPLICIT }.
    let tag = p.peek_tag()?;
    let responder_id = match tag {
        0xA1 => {
            p.expect_tag(0xA1)?;
            let len = p.read_len()?;
            let name_bytes = p.read_n(len)?;
            let name: Name = rasn::der::decode(name_bytes)
                .map_err(|e| CaError::Encoding(format!("decode responder name: {e}")))?;
            OcspResponderId::ByName(name)
        }
        0xA2 => {
            p.expect_tag(0xA2)?;
            let len = p.read_len()?;
            let kh_bytes = p.read_n(len)?;
            // The byKey is an OCTET STRING inside the [2] EXPLICIT.
            let mut p2 = DerParser::new(kh_bytes);
            p2.expect_tag(0x04)?;
            let oct_len = p2.read_len()?;
            let key_hash = p2.read_n(oct_len)?;
            OcspResponderId::ByKey(key_hash.to_vec())
        }
        other => {
            return Err(CaError::Encoding(format!(
                "expected responderID tag [1] or [2], got 0x{other:02X}"
            )));
        }
    };

    // producedAt: GeneralizedTime (tag 0x18).
    p.expect_tag(0x18)?;
    let gt_len = p.read_len()?;
    let gt_bytes = p.read_n(gt_len)?;
    let produced_at = parse_generalized_time_content(gt_bytes)?;

    // responses: SEQUENCE OF SingleResponse.
    p.expect_tag(0x30)?;
    let resp_seq_len = p.read_len()?;
    let resp_seq = p.read_n(resp_seq_len)?;
    let responses = parse_single_responses(resp_seq)?;

    // responseExtensions [1] EXPLICIT (optional).
    let extensions = if !p.remaining().is_empty() {
        p.expect_tag(0xA1)?;
        let ext_len = p.read_len()?;
        let ext_bytes = p.read_n(ext_len)?;
        let exts: Extensions = rasn::der::decode(ext_bytes)
            .map_err(|e| CaError::Encoding(format!("decode response exts: {e}")))?;
        // `Extensions` derefs to `SequenceOf<Extension>` which derefs to
        // `Vec<Extension>`; `.iter().cloned().collect()` gets us a owned Vec.
        exts.iter().cloned().collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    Ok(OcspResponseData {
        responder_id,
        produced_at,
        responses,
        extensions,
    })
}

/// Parse a SEQUENCE of SingleResponse. The input is the content of the
/// `responses` SEQUENCE OF — i.e. a concatenation of SingleResponse TLVs.
fn parse_single_responses(der: &[u8]) -> Result<Vec<OcspSingleResponse>, CaError> {
    let mut out = Vec::new();
    let mut p = DerParser::new(der);
    while !p.remaining().is_empty() {
        p.expect_tag(0x30)?;
        let sr_len = p.read_len()?;
        let sr_bytes = p.read_n(sr_len)?;
        out.push(parse_single_response(sr_bytes)?);
    }
    Ok(out)
}

/// Parse a single `SingleResponse`. The input is the CONTENT of the
/// SingleResponse SEQUENCE.
fn parse_single_response(der: &[u8]) -> Result<OcspSingleResponse, CaError> {
    let mut p = DerParser::new(der);

    // certID: SEQUENCE. Capture the full TLV so rasn can decode it.
    let cid_tlv = p.read_tlv()?;
    let cert_id: OcspCertId =
        rasn::der::decode(cid_tlv).map_err(|e| CaError::Encoding(format!("decode certId: {e}")))?;

    // certStatus: CHOICE { good [0], revoked [1], unknown [2] }.
    let tag = p.peek_tag()?;
    let cert_status = match tag {
        0x80 => {
            p.expect_tag(0x80)?;
            let _len = p.read_len()?;
            // NULL body (0 bytes).
            OcspCertStatus::Good
        }
        0xA1 => {
            p.expect_tag(0xA1)?;
            let len = p.read_len()?;
            let ri_bytes = p.read_n(len)?;
            // [1] IMPLICIT RevokedInfo — the SEQUENCE tag is replaced by
            // [1], so `ri_bytes` is directly the content of RevokedInfo:
            // revocationTime GeneralizedTime [optional revocationReason].
            let mut p2 = DerParser::new(ri_bytes);
            p2.expect_tag(0x18)?;
            let gt_len = p2.read_len()?;
            let gt_bytes = p2.read_n(gt_len)?;
            let t = parse_generalized_time_content(gt_bytes)?;
            OcspCertStatus::Revoked(t)
        }
        0x82 => {
            p.expect_tag(0x82)?;
            let _len = p.read_len()?;
            OcspCertStatus::Unknown
        }
        other => {
            return Err(CaError::Encoding(format!(
                "expected certStatus tag [0]/[1]/[2], got 0x{other:02X}"
            )));
        }
    };

    // thisUpdate: GeneralizedTime.
    p.expect_tag(0x18)?;
    let gt_len = p.read_len()?;
    let gt_bytes = p.read_n(gt_len)?;
    let this_update = parse_generalized_time_content(gt_bytes)?;

    // nextUpdate [0] EXPLICIT (optional).
    let next_update = if !p.remaining().is_empty() {
        let tag = p.peek_tag()?;
        if tag == 0xA0 {
            p.expect_tag(0xA0)?;
            let len = p.read_len()?;
            let nu_bytes = p.read_n(len)?;
            let mut p2 = DerParser::new(nu_bytes);
            p2.expect_tag(0x18)?;
            let gt_len = p2.read_len()?;
            let gt_bytes = p2.read_n(gt_len)?;
            Some(parse_generalized_time_content(gt_bytes)?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(OcspSingleResponse {
        cert_id,
        cert_status,
        this_update,
        next_update,
    })
}

/// Minimal hand-rolled DER parser for OCSP response decoding.
struct DerParser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerParser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn rest_until_end(&mut self) -> Result<&'a [u8], CaError> {
        // After the caller has consumed the tag, we still need to consume
        // the length and return the content slice.
        let len = self.read_len()?;
        if self.pos + len > self.buf.len() {
            return Err(CaError::Encoding(format!(
                "truncated DER: need {len} bytes at pos {} (buf len {})",
                self.pos,
                self.buf.len()
            )));
        }
        let rest = &self.buf[self.pos..self.pos + len];
        self.pos = self.buf.len();
        Ok(rest)
    }

    fn peek_tag(&self) -> Result<u8, CaError> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| CaError::Encoding("unexpected end of DER".into()))
    }

    fn expect_tag(&mut self, expected: u8) -> Result<(), CaError> {
        let tag = self.peek_tag()?;
        if tag != expected {
            return Err(CaError::Encoding(format!(
                "expected DER tag 0x{expected:02X}, got 0x{tag:02X}"
            )));
        }
        self.pos += 1;
        Ok(())
    }

    fn read_len(&mut self) -> Result<usize, CaError> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| CaError::Encoding("missing length byte".into()))?;
        self.pos += 1;
        if b < 0x80 {
            return Ok(b as usize);
        }
        let n = (b & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(CaError::Encoding(format!(
                "unsupported DER length form: 0x{b:02X}"
            )));
        }
        let mut len = 0usize;
        for _ in 0..n {
            let byte = self
                .buf
                .get(self.pos)
                .copied()
                .ok_or_else(|| CaError::Encoding("truncated length".into()))?;
            self.pos += 1;
            len = (len << 8) | (byte as usize);
        }
        Ok(len)
    }

    fn read_n(&mut self, n: usize) -> Result<&'a [u8], CaError> {
        if self.pos + n > self.buf.len() {
            return Err(CaError::Encoding(format!(
                "truncated DER: need {n} bytes at pos {} (buf len {})",
                self.pos,
                self.buf.len()
            )));
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a full TLV (tag + length + value) and return it as a borrowed
    /// slice. Used when we need to pass a sub-structure to rasn's decoder
    /// (which expects the full TLV, not just the content).
    fn read_tlv(&mut self) -> Result<&'a [u8], CaError> {
        let start = self.pos;
        // Consume tag.
        let _tag = self.peek_tag()?;
        self.pos += 1;
        // Consume length.
        let len = self.read_len()?;
        // Consume value.
        self.read_n(len)?;
        Ok(&self.buf[start..self.pos])
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-ca`. Wave 3a covers real X.509 v3 issuance,
    //! CSRs, profiles, revocation, CRL, and ASN.1 round-trips.

    use super::*;

    /// Build a real ECDSA-P256 CSR for `subject_cn` using ring, returning
    /// the DER bytes. Used by several issuance tests.
    fn make_csr(subject_cn: &str) -> Vec<u8> {
        let rng = SystemRandom::new();
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
        let pub_sec1 = kp.public_key().as_ref().to_vec();

        let spki = SubjectPublicKeyInfo {
            algorithm: ec_p256_pubkey_alg_id(),
            subject_public_key: BitVec::<u8, Msb0>::from_vec(pub_sec1),
        };
        let info = CertificationRequestInfo {
            version: Integer::from(0u32),
            subject: name_from_cn(subject_cn),
            subject_pk_info: spki,
            attributes: empty_csr_attributes(),
        };
        let info_der = rasn::der::encode(&info).unwrap();
        let sig = kp.sign(&rng, &info_der).unwrap();
        let csr = CertificationRequest {
            certification_request_info: info,
            signature_algorithm: ecdsa_sha256_alg_id(),
            signature: BitVec::<u8, Msb0>::from_vec(sig.as_ref().to_vec()),
        };
        rasn::der::encode(&csr).unwrap()
    }

    #[test]
    fn cert_profile_constructs_with_expected_fields() {
        let p = CertProfileKind::KerberosKdc.profile();
        assert_eq!(p.name, "adrian-kdc");
        assert_eq!(p.validity_days, 365);
        assert_eq!(p.key_usages.len(), 2);
        assert_eq!(p.extended_key_usages, vec!["1.3.6.1.5.2.3.5"]);
    }

    #[test]
    fn cert_profile_serde_round_trip_preserves_fields() {
        let p = CertProfileKind::WebServer.profile();
        let json = serde_json::to_string(&p).expect("serialize");
        let back: CertProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name, p.name);
        assert_eq!(back.template_oid, p.template_oid);
        assert_eq!(back.key_usages, p.key_usages);
        assert_eq!(back.extended_key_usages, p.extended_key_usages);
        assert_eq!(back.validity_days, p.validity_days);
        assert_eq!(back.subject_name_format, p.subject_name_format);
        assert_eq!(back.san_templates, p.san_templates);
    }

    #[test]
    fn enrollment_auth_variants_serialise_as_expected() {
        let cases = [
            (EnrollmentAuth::Anonymous, "\"Anonymous\""),
            (EnrollmentAuth::DomainAuth, "\"DomainAuth\""),
            (EnrollmentAuth::AgentApproval, "\"AgentApproval\""),
        ];
        for (variant, expected) in cases {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn ca_error_variants_render_messages() {
        assert_eq!(
            CaError::ProfileNotFound("foo".into()).to_string(),
            "profile not found: foo"
        );
        assert_eq!(
            CaError::CsrInvalid("bad".into()).to_string(),
            "csr invalid: bad"
        );
        assert_eq!(
            CaError::IssuanceDenied("no".into()).to_string(),
            "issuance denied: no"
        );
        assert_eq!(CaError::Hsm("locked".into()).to_string(), "hsm: locked");
        assert_eq!(CaError::Storage("eof".into()).to_string(), "storage: eof");
        assert_eq!(CaError::Encoding("der".into()).to_string(), "encoding: der");
        assert_eq!(CaError::Crypto("rng".into()).to_string(), "crypto: rng");
        assert_eq!(
            CaError::NotFound("serial".into()).to_string(),
            "not found: serial"
        );
        assert_eq!(
            CaError::Internal("boom".into()).to_string(),
            "internal: boom"
        );
    }

    #[test]
    fn ca_keypair_generate_produces_valid_sec1_public_key() {
        // P-256 uncompressed public key is exactly 65 bytes: 0x04 || X(32) || Y(32).
        let kp = CaKeyPair::generate().expect("generate");
        assert_eq!(kp.public_sec1().len(), 65);
        assert_eq!(kp.public_sec1()[0], 0x04);
        assert_eq!(kp.ski_bytes().len(), 20); // SHA-1 = 20 bytes
    }

    #[test]
    fn ca_service_root_certificate_generation() {
        // CA root certificate generation — must be a real X.509 v3 DER.
        let ca = CaService::new().expect("new");
        let der = ca.root_cert_der();
        assert!(!der.is_empty());
        // X.509 Certificate is a SEQUENCE — DER tag 0x30.
        assert_eq!(der[0], 0x30);
        // Round-trip: parse it back.
        let parsed: Certificate = rasn::der::decode(der).expect("parse root");
        assert_eq!(parsed.tbs_certificate.version, Version::V3);
        // Self-signed: issuer == subject.
        assert_eq!(
            parsed.tbs_certificate.issuer,
            parsed.tbs_certificate.subject
        );
        // Signature algorithm is ecdsa-with-SHA256.
        assert_eq!(
            parsed.signature_algorithm.algorithm,
            ObjectIdentifier::new(OID_ECDSA_SHA256).unwrap()
        );
    }

    #[tokio::test]
    async fn ca_service_issues_cert_from_csr() {
        let ca = CaService::new().expect("ca");
        let csr_der = make_csr("host1.adrian.dev");
        let cert_der = ca.issue("adrian-webserver", &csr_der).await.expect("issue");
        assert!(!cert_der.is_empty());
        // Parse it back.
        let parsed: Certificate = rasn::der::decode(&cert_der).expect("parse cert");
        assert_eq!(parsed.tbs_certificate.version, Version::V3);
        // Issuer = CA subject.
        assert_eq!(parsed.tbs_certificate.issuer, *ca.ca_subject());
        // Extensions present.
        let exts = parsed
            .tbs_certificate
            .extensions
            .as_ref()
            .expect("extensions present");
        assert!(exts
            .iter()
            .any(|e| e.extn_id == ObjectIdentifier::new(OID_BC).unwrap()));
        assert!(exts
            .iter()
            .any(|e| e.extn_id == ObjectIdentifier::new(OID_KU).unwrap()));
    }

    #[tokio::test]
    async fn ca_service_issue_records_serial_and_cert() {
        let ca = CaService::new().expect("ca");
        let csr1 = make_csr("a.adrian.dev");
        let csr2 = make_csr("b.adrian.dev");
        let _d1 = ca.issue("adrian-webserver", &csr1).await.unwrap();
        let _d2 = ca.issue("adrian-webserver", &csr2).await.unwrap();
        // Two distinct serials.
        let issued = ca.issued.read().await;
        assert_eq!(issued.len(), 2);
        assert_ne!(issued[0].serial, issued[1].serial);
    }

    #[tokio::test]
    async fn ca_service_issue_rejects_invalid_csr_signature() {
        let ca = CaService::new().expect("ca");
        let mut csr_der = make_csr("bad.adrian.dev");
        // Corrupt the signature bytes (last byte).
        let last = csr_der.len() - 1;
        csr_der[last] ^= 0xFF;
        let err = ca.issue("adrian-webserver", &csr_der).await.unwrap_err();
        assert!(matches!(err, CaError::CsrInvalid(_)));
    }

    #[tokio::test]
    async fn ca_service_unknown_profile_returns_profile_not_found() {
        let ca = CaService::new().expect("ca");
        let csr = make_csr("host.adrian.dev");
        let err = ca.issue("nonexistent-profile", &csr).await.unwrap_err();
        assert!(matches!(err, CaError::ProfileNotFound(_)));
    }

    #[tokio::test]
    async fn ca_service_webserver_profile_has_serverauth_eku() {
        let ca = CaService::new().expect("ca");
        let csr = make_csr("www.adrian.dev");
        let der = ca.issue("adrian-webserver", &csr).await.unwrap();
        let parsed: Certificate = rasn::der::decode(&der).unwrap();
        let exts = parsed.tbs_certificate.extensions.as_ref().unwrap();
        let eku_ext = exts
            .iter()
            .find(|e| e.extn_id == ObjectIdentifier::new(OID_EKU).unwrap())
            .expect("eku present");
        let eku: ExtKeyUsageSyntax = rasn::der::decode(&eku_ext.extn_value).expect("parse eku");
        let server_auth = ObjectIdentifier::new(vec![1, 3, 6, 1, 5, 5, 7, 3, 1]).unwrap();
        assert!(eku.contains(&server_auth));
    }

    #[tokio::test]
    async fn ca_service_client_profile_has_clientauth_eku() {
        let ca = CaService::new().expect("ca");
        let csr = make_csr("client1");
        let der = ca.issue("adrian-client", &csr).await.unwrap();
        let parsed: Certificate = rasn::der::decode(&der).unwrap();
        let exts = parsed.tbs_certificate.extensions.as_ref().unwrap();
        let eku_ext = exts
            .iter()
            .find(|e| e.extn_id == ObjectIdentifier::new(OID_EKU).unwrap())
            .unwrap();
        let eku: ExtKeyUsageSyntax = rasn::der::decode(&eku_ext.extn_value).unwrap();
        let client_auth = ObjectIdentifier::new(vec![1, 3, 6, 1, 5, 5, 7, 3, 2]).unwrap();
        assert!(eku.contains(&client_auth));
    }

    #[tokio::test]
    async fn ca_service_kerberos_kdc_profile_has_krb5kdc_eku() {
        let ca = CaService::new().expect("ca");
        let csr = make_csr("kdc.adrian.dev");
        let der = ca.issue("adrian-kdc", &csr).await.unwrap();
        let parsed: Certificate = rasn::der::decode(&der).unwrap();
        let exts = parsed.tbs_certificate.extensions.as_ref().unwrap();
        let eku_ext = exts
            .iter()
            .find(|e| e.extn_id == ObjectIdentifier::new(OID_EKU).unwrap())
            .unwrap();
        let eku: ExtKeyUsageSyntax = rasn::der::decode(&eku_ext.extn_value).unwrap();
        let krb5_kdc = ObjectIdentifier::new(vec![1, 3, 6, 1, 5, 2, 3, 5]).unwrap();
        assert!(eku.contains(&krb5_kdc));
    }

    #[tokio::test]
    async fn ca_service_revocation_adds_serial_to_crl() {
        let ca = CaService::new().expect("ca");
        let csr = make_csr("rev.me.adrian.dev");
        let _der = ca.issue("adrian-webserver", &csr).await.unwrap();
        let serial_bytes = 1u64.to_be_bytes();
        ca.revoke(&serial_bytes, "keyCompromise").await.unwrap();
        let revoked = ca.revoked_serials().await;
        assert_eq!(revoked, vec![1u64]);
    }

    #[tokio::test]
    async fn ca_service_crl_contains_revoked_entry() {
        let ca = CaService::new().expect("ca");
        let serial_bytes = 42u64.to_be_bytes();
        ca.revoke(&serial_bytes, "keyCompromise").await.unwrap();
        let crl_der = ca.crl_der().await.unwrap();
        let crl: CertificateList = rasn::der::decode(&crl_der).unwrap();
        // CRL issuer == CA subject.
        assert_eq!(crl.tbs_cert_list.issuer, *ca.ca_subject());
        // One revoked entry.
        assert_eq!(crl.tbs_cert_list.revoked_certificates.len(), 1);
        // Serial = 42.
        let entry = crl.tbs_cert_list.revoked_certificates.first().unwrap();
        let got: u64 = u64::try_from(&entry.user_certificate).unwrap();
        assert_eq!(got, 42u64);
    }

    #[tokio::test]
    async fn ca_service_revocation_is_idempotent() {
        let ca = CaService::new().expect("ca");
        let s = 7u64.to_be_bytes();
        ca.revoke(&s, "unspecified").await.unwrap();
        ca.revoke(&s, "keyCompromise").await.unwrap();
        assert_eq!(ca.revoked_serials().await, vec![7u64]);
    }

    #[tokio::test]
    async fn ca_service_profile_names_listed_sorted() {
        let ca = CaService::new().expect("ca");
        let names = ca.profile_names().await;
        assert_eq!(
            names,
            vec![
                "adrian-client".to_string(),
                "adrian-codesigning".to_string(),
                "adrian-kdc".to_string(),
                "adrian-webserver".to_string(),
            ]
        );
    }

    #[test]
    fn parse_crl_reason_covers_all_rfc_5280_reasons() {
        assert_eq!(parse_crl_reason("keyCompromise"), CrlReason::KeyCompromise);
        assert_eq!(parse_crl_reason("caCompromise"), CrlReason::CaCompromise);
        assert_eq!(parse_crl_reason("unknown"), CrlReason::Unspecified);
        assert_eq!(parse_crl_reason(""), CrlReason::Unspecified);
    }

    #[test]
    fn parse_serial_bytes_handles_be_u64() {
        assert_eq!(parse_serial_bytes(&[0x01]).unwrap(), 1u64);
        assert_eq!(parse_serial_bytes(&[0x01, 0x00]).unwrap(), 256u64);
        assert_eq!(parse_serial_bytes(&[0xFF]).unwrap(), 255u64);
        assert!(parse_serial_bytes(&[]).is_err());
        assert!(parse_serial_bytes(&[0u8; 9]).is_err());
    }

    #[test]
    fn base64url_encodes_without_padding() {
        // "foobar" without padding.
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        // "foo" -> "Zm9v" (1 byte short, no padding).
        assert_eq!(base64url(b"foo"), "Zm9v");
        // "foob" -> "Zm9vYg".
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        // "fooba" -> "Zm9vYmE".
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
    }

    #[test]
    fn ext_basic_constraints_round_trips_as_der() {
        let ext = ext_basic_constraints(true, Some(1)).unwrap();
        let bc: BasicConstraints = rasn::der::decode(&ext.extn_value).unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(Integer::from(1u32)));
    }

    #[test]
    fn ext_ski_round_trips_as_der() {
        let ski = vec![0xABu8; 20];
        let ext = ext_ski(&ski).unwrap();
        let parsed: OctetString = rasn::der::decode(&ext.extn_value).unwrap();
        assert_eq!(parsed.as_ref(), &ski[..]);
    }

    #[test]
    fn csr_round_trips_via_ring_signature() {
        // Build a CSR, parse it back, verify the self-signature.
        let der = make_csr("round.trip.adrian.dev");
        let csr = CertificationRequest::from_der(&der).unwrap();
        csr.verify_signature().unwrap();
        assert_eq!(csr.subject_cn().as_deref(), Some("round.trip.adrian.dev"));
    }

    #[test]
    fn csr_rejects_non_ecdsa_key() {
        // Build a CSR but swap the public key algorithm OID to RSA.
        let der = make_csr("hacker.adrian.dev");
        let mut csr = CertificationRequest::from_der(&der).unwrap();
        csr.certification_request_info.subject_pk_info.algorithm = AlgorithmIdentifier {
            algorithm: ObjectIdentifier::new(vec![1, 2, 840, 113549, 1, 1, 1]).unwrap(),
            parameters: None,
        };
        assert!(csr.public_key_sec1().is_err());
    }

    // ===== Domain-06 Wave 1: CA signs through HSM + crypto verification =====

    /// The CA's issued cert signature MUST cryptographically verify under
    /// the CA's public key. The Wave 3a tests only checked the signature
    /// algorithm OID; this test catches the latent bug where the CA used
    /// `ECDSA_P256_SHA256_FIXED_SIGNING` (raw 64-byte r||s) but the X.509
    /// `BIT STRING` expects DER-encoded `ECDSA-Sig-Value`. After the Wave 1
    /// fix (switch to `ECDSA_P256_SHA256_ASN1_SIGNING`), the signature
    /// MUST verify under `ECDSA_P256_SHA256_ASN1`.
    #[tokio::test]
    async fn ca_issued_cert_signature_cryptographically_verifies() {
        let ca = CaService::new().expect("ca");
        let csr_der = make_csr("verify.adrian.dev");
        let cert_der = ca.issue("adrian-webserver", &csr_der).await.expect("issue");

        // Parse the cert and re-encode the TBS certificate to DER.
        let parsed: Certificate = rasn::der::decode(&cert_der).expect("parse cert");
        let tbs_der = rasn::der::encode(&parsed.tbs_certificate).expect("encode tbs");
        let sig_bytes = parsed.signature_value.clone().into_vec();

        // Verify under the CA's public key.
        let ca_pub = ca.ca_public_key_sec1();
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            ca_pub,
        );
        pk.verify(&tbs_der, &sig_bytes)
            .expect("cert signature MUST verify under CA public key");
    }

    /// The CA's root cert self-signature MUST cryptographically verify.
    #[tokio::test]
    async fn ca_root_cert_self_signature_verifies() {
        let ca = CaService::new().expect("ca");
        let root_der = ca.root_cert_der();
        let parsed: Certificate = rasn::der::decode(root_der).expect("parse root");
        let tbs_der = rasn::der::encode(&parsed.tbs_certificate).expect("encode tbs");
        let sig_bytes = parsed.signature_value.clone().into_vec();
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            ca.ca_public_key_sec1(),
        );
        pk.verify(&tbs_der, &sig_bytes)
            .expect("root self-signature MUST verify");
    }

    /// `CaService::with_hsm()` constructs a CA whose signing key lives in
    /// an `adrian_hsm::SoftwareHsm`. The issued cert's signature MUST
    /// verify under the HSM's public key, proving that the CA correctly
    /// routes signing through `Hsm::sign_ecdsa` (ADR-037).
    #[tokio::test]
    async fn ca_with_hsm_signs_through_hsm_trait() {
        let hsm = Arc::new(adrian_hsm::SoftwareHsm::new());
        let ca = CaService::with_hsm(hsm.clone(), "ca-hsm", "HSM Root CA")
            .await
            .expect("with_hsm");

        // The CA's public key MUST match the HSM's public key.
        let hsm_handle = adrian_hsm::KeyHandle {
            id: "ca-hsm".into(),
            version: 1,
            key_type: adrian_hsm::KeyType::EcdsaP256,
        };
        let hsm_pub = hsm
            .public_key_ecdsa(&hsm_handle)
            .await
            .expect("hsm public key");
        assert_eq!(ca.ca_public_key_sec1(), hsm_pub.as_slice());

        // Issue a cert and verify the signature under the HSM's public key.
        let csr_der = make_csr("hsm-signed.adrian.dev");
        let cert_der = ca.issue("adrian-webserver", &csr_der).await.expect("issue");
        let parsed: Certificate = rasn::der::decode(&cert_der).expect("parse cert");
        let tbs_der = rasn::der::encode(&parsed.tbs_certificate).expect("encode tbs");
        let sig_bytes = parsed.signature_value.clone().into_vec();

        // Verify the signature using the HSM's verify_ecdsa (independent of
        // the CA's signer path — proves the signature was produced by the
        // HSM-bound key).
        assert!(
            hsm.verify_ecdsa(&hsm_handle, &tbs_der, &sig_bytes)
                .await
                .expect("hsm verify_ecdsa"),
            "cert signature MUST verify via HSM's verify_ecdsa"
        );

        // Also verify using ring directly (independent of the HSM trait).
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &hsm_pub,
        );
        pk.verify(&tbs_der, &sig_bytes)
            .expect("cert signature MUST verify via ring");
    }

    /// `CaSigner::Direct` and `CaSigner::HsmBound` produce different public
    /// keys (since they're independent key pairs), but both MUST produce
    /// 65-byte SEC1 uncompressed P-256 public keys and 20-byte SKIs.
    #[tokio::test]
    async fn ca_signer_variants_produce_valid_keys() {
        let direct = CaSigner::Direct(CaKeyPair::generate().expect("generate"));
        assert_eq!(direct.public_sec1().len(), 65);
        assert_eq!(direct.public_sec1()[0], 0x04);
        assert_eq!(direct.ski_bytes().len(), 20);

        let hsm = Arc::new(adrian_hsm::SoftwareHsm::new());
        let handle = hsm
            .generate_key("signer-test", adrian_hsm::KeyType::EcdsaP256)
            .await
            .expect("generate_key");
        let pub_sec1 = hsm.public_key_ecdsa(&handle).await.expect("public_key");
        let ski = sha1_digest(&pub_sec1);
        let bound = CaSigner::HsmBound {
            hsm,
            handle,
            public_sec1: pub_sec1,
            ski_bytes: ski,
        };
        assert_eq!(bound.public_sec1().len(), 65);
        assert_eq!(bound.public_sec1()[0], 0x04);
        assert_eq!(bound.ski_bytes().len(), 20);
    }

    // ===== Domain-06 Wave 2: OCSP responder (RFC 6960) tests =====

    /// Helper: issue a cert from the CA and return its serial number.
    async fn issue_cert_for_ocsp(ca: &CaService, cn: &str) -> u64 {
        let csr_der = make_csr(cn);
        ca.issue("adrian-webserver", &csr_der).await.expect("issue");
        // Serial 1 is the first issued (CA root is serial 0 conceptually;
        // the CA's `serial` AtomicU64 starts at 1 and fetch_add returns the
        // pre-increment value, so the first issued cert is serial 1).
        1
    }

    /// OCSP request/response round-trip for a good (non-revoked) cert.
    /// The response MUST be `successful` and the SingleResponse certStatus
    /// MUST be `good`.
    #[tokio::test]
    async fn ocsp_request_for_good_cert_returns_successful_response() {
        let ca = Arc::new(CaService::new().expect("ca"));
        let serial = issue_cert_for_ocsp(&ca, "good.adrian.dev").await;

        let cert_id = build_cert_id(&ca, serial);
        let nonce = b"test-nonce-12345678";
        let req_der = build_ocsp_request(&cert_id, nonce).expect("build request");

        let responder = OcspResponder::new(ca.clone());
        let resp_der = responder
            .handle_request(&req_der)
            .await
            .expect("handle_request");

        // The response MUST start with a SEQUENCE tag.
        assert_eq!(resp_der[0], 0x30, "OCSPResponse is DER SEQUENCE");

        // Parse the response to verify the status.
        let resp: OcspResponse = parse_ocsp_response(&resp_der).expect("parse response");
        assert_eq!(resp.response_status, OcspResponseStatus::Successful);
        assert!(
            resp.response_bytes.is_some(),
            "responseBytes MUST be present"
        );
    }

    /// OCSP request for a revoked cert returns `revoked` status.
    #[tokio::test]
    async fn ocsp_request_for_revoked_cert_returns_revoked_status() {
        let ca = Arc::new(CaService::new().expect("ca"));
        let serial = issue_cert_for_ocsp(&ca, "revoked.adrian.dev").await;
        // Revoke the cert.
        let serial_bytes = serial.to_be_bytes();
        ca.revoke(&serial_bytes, "keyCompromise")
            .await
            .expect("revoke");

        let cert_id = build_cert_id(&ca, serial);
        let req_der = build_ocsp_request(&cert_id, b"").expect("build request");

        let responder = OcspResponder::new(ca.clone());
        let resp_der = responder
            .handle_request(&req_der)
            .await
            .expect("handle_request");

        let resp: OcspResponse = parse_ocsp_response(&resp_der).expect("parse response");
        assert_eq!(resp.response_status, OcspResponseStatus::Successful);
        let basic = resp.response_bytes.expect("responseBytes");
        assert_eq!(basic.response_data.responses.len(), 1);
        match &basic.response_data.responses[0].cert_status {
            OcspCertStatus::Revoked(_) => {}
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    /// OCSP request for an unknown serial (not in CA's ledger) returns
    /// `good` (the CA only tracks revoked certs; any non-revoked serial is
    /// treated as good — this is the standard OCSP responder behavior per
    /// RFC 6960 §4.2.1, since the CA doesn't have a complete issued-cert
    /// ledger in this wave).
    #[tokio::test]
    async fn ocsp_request_for_unknown_cert_returns_good() {
        let ca = Arc::new(CaService::new().expect("ca"));
        // Query for serial 99999 which was never issued.
        let cert_id = build_cert_id(&ca, 99999);
        let req_der = build_ocsp_request(&cert_id, b"").expect("build request");

        let responder = OcspResponder::new(ca.clone());
        let resp_der = responder
            .handle_request(&req_der)
            .await
            .expect("handle_request");

        let resp: OcspResponse = parse_ocsp_response(&resp_der).expect("parse response");
        assert_eq!(resp.response_status, OcspResponseStatus::Successful);
        let basic = resp.response_bytes.expect("responseBytes");
        assert_eq!(basic.response_data.responses.len(), 1);
        match &basic.response_data.responses[0].cert_status {
            OcspCertStatus::Good => {}
            other => panic!("expected Good for unknown serial, got {other:?}"),
        }
    }

    /// OCSP nonce extension (RFC 8954) is echoed in the response. The
    /// responder MUST copy the request's nonce into the response's
    /// responseExtensions.
    #[tokio::test]
    async fn ocsp_nonce_extension_is_echoed_in_response() {
        let ca = Arc::new(CaService::new().expect("ca"));
        let cert_id = build_cert_id(&ca, 1);
        let nonce = b"unique-nonce-value-1234";
        let req_der = build_ocsp_request(&cert_id, nonce).expect("build request");

        let responder = OcspResponder::new(ca.clone());
        let resp_der = responder
            .handle_request(&req_der)
            .await
            .expect("handle_request");

        let resp: OcspResponse = parse_ocsp_response(&resp_der).expect("parse response");
        let basic = resp.response_bytes.expect("responseBytes");
        // Find the nonce extension in the response.
        let nonce_oid = ObjectIdentifier::new(OID_OCSP_NONCE).unwrap();
        let nonce_ext = basic
            .response_data
            .extensions
            .iter()
            .find(|e| e.extn_id == nonce_oid)
            .expect("nonce extension MUST be echoed in response");
        // The nonce value MUST match the request's nonce.
        assert_eq!(nonce_ext.extn_value.to_vec(), nonce.to_vec());
    }

    /// OCSP nonce replay rejection: a response with a mismatched nonce
    /// is detected by the client. We simulate this by making two requests
    /// with different nonces and verifying the responses carry different
    /// nonces (a replayed response would have the wrong nonce for the
    /// second request).
    #[tokio::test]
    async fn ocsp_nonce_replay_detection() {
        let ca = Arc::new(CaService::new().expect("ca"));
        let cert_id = build_cert_id(&ca, 1);

        // Request 1 with nonce A.
        let nonce_a = b"nonce-A-aaaaaaaa";
        let req_a = build_ocsp_request(&cert_id, nonce_a).expect("build request A");
        let responder = OcspResponder::new(ca.clone());
        let resp_a_der = responder
            .handle_request(&req_a)
            .await
            .expect("handle request A");
        let resp_a: OcspResponse = parse_ocsp_response(&resp_a_der).expect("parse A");
        let basic_a = resp_a.response_bytes.expect("responseBytes A");
        let nonce_oid = ObjectIdentifier::new(OID_OCSP_NONCE).unwrap();
        let echo_a = basic_a
            .response_data
            .extensions
            .iter()
            .find(|e| e.extn_id == nonce_oid)
            .expect("nonce A echoed");
        assert_eq!(echo_a.extn_value.to_vec(), nonce_a.to_vec());

        // Request 2 with nonce B (different).
        let nonce_b = b"nonce-B-bbbbbbbb";
        let req_b = build_ocsp_request(&cert_id, nonce_b).expect("build request B");
        let resp_b_der = responder
            .handle_request(&req_b)
            .await
            .expect("handle request B");
        let resp_b: OcspResponse = parse_ocsp_response(&resp_b_der).expect("parse B");
        let basic_b = resp_b.response_bytes.expect("responseBytes B");
        let echo_b = basic_b
            .response_data
            .extensions
            .iter()
            .find(|e| e.extn_id == nonce_oid)
            .expect("nonce B echoed");
        assert_eq!(echo_b.extn_value.to_vec(), nonce_b.to_vec());

        // Replay detection: response A's nonce does NOT match request B's
        // nonce — a client checking the nonce would reject response A as
        // a replay for request B.
        assert_ne!(
            echo_a.extn_value.to_vec(),
            echo_b.extn_value.to_vec(),
            "different requests MUST produce different nonces"
        );
    }
}
