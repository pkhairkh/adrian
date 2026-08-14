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
}
