//! # adrian-acme-server
//!
//! ACME endpoint — RFC 8555 (core), RFC 8737 (tls-alpn-01), RFC 8823 (ARI
//! renewal information). Primary enrollment path in native mode.
//!
//! ## ADRs
//!
//! - ADR-095: ACME primary; MS-WCCE bridge for AD-interop
//! - ADR-096: cert-profile.yaml replaces AD CS templates
//! - ADR-097: Cross-platform autoenroll via ACME
//! - ADR-098: NDES/SCEP replacement bridge
//!
//! ## Implementation (Wave 3a)
//!
//! Real axum-based HTTP server implementing RFC 8555 §7.1-§7.7:
//! - `GET  /directory`           — directory object (§7.1.1)
//! - `HEAD /new-nonce`           — fresh nonce (§7.2)
//! - `POST /new-account`         — account creation (§7.3)
//! - `POST /new-order`           — order creation (§7.4)
//! - `POST /authz/{id}`          — authorization polling (§7.5)
//! - `POST /challenge/{id}`      — challenge response (§7.5.1)
//! - `POST /order/{id}/finalize` — CSR submission (§7.4)
//! - `GET  /order/{id}/cert`     — certificate download (§7.4.2)
//!
//! JWS verification (RFC 7515) uses `ring::signature::ECDSA_P256_SHA256_FIXED`
//! for ES256 signatures. Nonces are 32 random bytes (base64url). The CA is
//! `adrian_ca::CaService` (real X.509 v3 issuance).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

// ===========================================================================
// Errors
// ===========================================================================

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("malformed request: {0}")]
    Malformed(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("rate limited")]
    RateLimited,
    #[error("ca: {0}")]
    Ca(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl AcmeError {
    /// Map an ACME error to an HTTP status code per RFC 8555 §6.7.
    pub fn status_code(&self) -> StatusCode {
        match self {
            AcmeError::Malformed(_) => StatusCode::BAD_REQUEST,
            AcmeError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AcmeError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AcmeError::Ca(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AcmeError::NotFound(_) => StatusCode::NOT_FOUND,
            AcmeError::Conflict(_) => StatusCode::CONFLICT,
            AcmeError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AcmeError {
    fn into_response(self) -> Response {
        let typ = match &self {
            AcmeError::Malformed(_) => "urn:ietf:params:acme:error:malformed",
            AcmeError::Unauthorized(_) => "urn:ietf:params:acme:error:unauthorized",
            AcmeError::RateLimited => "urn:ietf:params:acme:error:rateLimited",
            AcmeError::Ca(_) => "urn:ietf:params:acme:error:serverInternal",
            AcmeError::NotFound(_) => "urn:ietf:params:acme:error:not-found",
            AcmeError::Conflict(_) => "urn:ietf:params:acme:error:conflict",
            AcmeError::Internal(_) => "urn:ietf:params:acme:error:serverInternal",
        };
        let body_json = serde_json::json!({
            "type": typ,
            "detail": self.to_string(),
        });
        let body_bytes = serde_json::to_vec(&body_json).unwrap_or_else(|_| b"{}".to_vec());
        let mut resp = (self.status_code(), body_bytes).into_response();
        resp.headers_mut().insert(
            "Content-Type",
            HeaderValue::from_static("application/problem+json"),
        );
        resp
    }
}

impl From<adrian_ca::CaError> for AcmeError {
    fn from(e: adrian_ca::CaError) -> Self {
        AcmeError::Ca(e.to_string())
    }
}

// ===========================================================================
// ACME account / order / authz / challenge state
// ===========================================================================

/// ACME account.
#[derive(Clone, Debug)]
pub struct AcmeAccount {
    pub kid: String,
    pub contact: Vec<String>,
    pub status: AccountStatus,
    pub jwk: Jwk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

/// ACME order.
#[derive(Clone, Debug, Serialize)]
pub struct AcmeOrder {
    pub status: OrderStatus,
    pub expires: String,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OrderStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "invalid")]
    Invalid,
}

/// ACME identifier (DNS, IP, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub typ: String,
    pub value: String,
}

/// ACME authorization.
#[derive(Clone, Debug, Serialize)]
pub struct AcmeAuthz {
    pub identifier: Identifier,
    pub status: AuthzStatus,
    pub expires: String,
    pub challenges: Vec<Challenge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum AuthzStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "invalid")]
    Invalid,
}

/// ACME challenge (http-01 only in Wave 3a).
#[derive(Clone, Debug, Serialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: String,
    pub url: String,
    pub status: ChallengeStatus,
    pub token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ChallengeStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "invalid")]
    Invalid,
}

// ===========================================================================
// JWS (RFC 7515) — protected header, body, verification
// ===========================================================================

/// JSON Web Key (EC P-256 only in Wave 3a).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl Jwk {
    /// Build a Jwk from a 65-byte SEC1 uncompressed public key (0x04 || X || Y).
    pub fn from_sec1(sec1: &[u8]) -> Result<Self, AcmeError> {
        if sec1.len() != 65 || sec1[0] != 0x04 {
            return Err(AcmeError::Malformed(
                "expected 65-byte uncompressed P-256 public key".into(),
            ));
        }
        let x = URL_SAFE_NO_PAD.encode(&sec1[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&sec1[33..65]);
        Ok(Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y,
        })
    }

    /// Decode the Jwk back to a 65-byte SEC1 uncompressed point.
    pub fn to_sec1(&self) -> Result<Vec<u8>, AcmeError> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(AcmeError::Malformed(format!(
                "unsupported jwk: kty={}, crv={}",
                self.kty, self.crv
            )));
        }
        let x = URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|e| AcmeError::Malformed(format!("jwk.x: {e}")))?;
        let y = URL_SAFE_NO_PAD
            .decode(&self.y)
            .map_err(|e| AcmeError::Malformed(format!("jwk.y: {e}")))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(AcmeError::Malformed(
                "jwk P-256 coords must be 32 bytes".into(),
            ));
        }
        let mut out = Vec::with_capacity(65);
        out.push(0x04);
        out.extend_from_slice(&x);
        out.extend_from_slice(&y);
        Ok(out)
    }

    /// Compute the RFC 7638 SHA-256 thumbprint (base64url-encoded).
    /// The canonical JSON is `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`
    /// with lexicographic key order and no whitespace.
    pub fn thumbprint(&self) -> Result<String, AcmeError> {
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.x, self.y
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(digest.as_ref()))
    }
}

/// JWS protected header (RFC 7515 §4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwsProtectedHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub nonce: String,
    pub url: String,
}

/// JWS body as POSTed by the client (RFC 7515 §7.2.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwsBody {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

impl JwsBody {
    /// Decode the base64url-encoded protected header.
    pub fn decoded_header(&self) -> Result<JwsProtectedHeader, AcmeError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.protected)
            .map_err(|e| AcmeError::Malformed(format!("protected: {e}")))?;
        serde_json::from_slice(&bytes).map_err(|e| AcmeError::Malformed(format!("header: {e}")))
    }

    /// Decode the base64url-encoded payload as UTF-8.
    pub fn decoded_payload(&self) -> Result<Vec<u8>, AcmeError> {
        URL_SAFE_NO_PAD
            .decode(&self.payload)
            .map_err(|e| AcmeError::Malformed(format!("payload: {e}")))
    }

    /// Decode the base64url-encoded signature into raw bytes.
    pub fn decoded_signature(&self) -> Result<Vec<u8>, AcmeError> {
        URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| AcmeError::Malformed(format!("signature: {e}")))
    }
}

/// Verify a JWS body and return the public key (as a Jwk) that signed it.
/// Returns `Err` if the signature is invalid, the algorithm is unsupported,
/// or the URL field doesn't match `expected_url`.
pub fn verify_jws(body: &JwsBody, expected_url: &str) -> Result<Jwk, AcmeError> {
    let header = body.decoded_header()?;
    if header.alg != "ES256" {
        return Err(AcmeError::Malformed(format!(
            "unsupported alg: {} (only ES256)",
            header.alg
        )));
    }
    if header.url != expected_url {
        return Err(AcmeError::Unauthorized(format!(
            "url mismatch: header={} expected={}",
            header.url, expected_url
        )));
    }
    let jwk = header
        .jwk
        .clone()
        .ok_or_else(|| AcmeError::Malformed("jwk required for new-account requests".into()))?;
    let pub_sec1 = jwk.to_sec1()?;

    // Signing input: ASCII(protected || "." || payload).
    let mut signing_input = Vec::with_capacity(body.protected.len() + 1 + body.payload.len());
    signing_input.extend_from_slice(body.protected.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(body.payload.as_bytes());

    let sig = body.decoded_signature()?;
    let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pub_sec1);
    pk.verify(&signing_input, &sig)
        .map_err(|_| AcmeError::Unauthorized("invalid JWS signature".into()))?;
    Ok(jwk)
}

/// Verify a JWS body that uses `kid` (instead of `jwk`) for the protected
/// header. The caller must supply the Jwk corresponding to `kid`.
pub fn verify_jws_with_kid(body: &JwsBody, expected_url: &str, jwk: &Jwk) -> Result<(), AcmeError> {
    let header = body.decoded_header()?;
    if header.alg != "ES256" {
        return Err(AcmeError::Malformed(format!(
            "unsupported alg: {} (only ES256)",
            header.alg
        )));
    }
    if header.url != expected_url {
        return Err(AcmeError::Unauthorized(format!(
            "url mismatch: header={} expected={}",
            header.url, expected_url
        )));
    }
    let pub_sec1 = jwk.to_sec1()?;
    let mut signing_input = Vec::with_capacity(body.protected.len() + 1 + body.payload.len());
    signing_input.extend_from_slice(body.protected.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(body.payload.as_bytes());
    let sig = body.decoded_signature()?;
    let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pub_sec1);
    pk.verify(&signing_input, &sig)
        .map_err(|_| AcmeError::Unauthorized("invalid JWS signature".into()))?;
    Ok(())
}

// ===========================================================================
// Nonce generation
// ===========================================================================

/// Generate a fresh 32-byte base64url-encoded nonce.
pub fn new_nonce() -> String {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 32];
    rng.fill(&mut buf).expect("ring RNG failure");
    URL_SAFE_NO_PAD.encode(buf)
}

/// Compute a SHA-256 fingerprint of a JWK (used as account ID).
pub fn jwk_fingerprint(jwk: &Jwk) -> String {
    jwk.thumbprint().unwrap_or_else(|_| "unknown".into())
}

// ===========================================================================
// ACME server state
// ===========================================================================

/// In-memory ACME server state. Holds nonces, accounts, orders, and
/// authorizations behind `RwLock`-guarded `HashMap`s. The CA is held as
/// `Arc<CaService>` and shared with the router.
pub struct AcmeState {
    pub base_url: String,
    pub ca: Arc<adrian_ca::CaService>,
    pub nonces: RwLock<HashMap<String, ()>>,
    pub accounts: RwLock<HashMap<String, AcmeAccount>>,
    pub orders: RwLock<HashMap<String, AcmeOrder>>,
    pub authz: RwLock<HashMap<String, AcmeAuthz>>,
    pub challenges: RwLock<HashMap<String, Challenge>>,
    pub certs: RwLock<HashMap<String, Vec<u8>>>,
    pub profile: String,
}

impl AcmeState {
    /// Build a new state with a freshly-generated CA and the given base URL.
    pub fn new(base_url: &str) -> Result<Self, AcmeError> {
        let ca = adrian_ca::CaService::new().map_err(AcmeError::from)?;
        Ok(Self::with_ca(base_url, Arc::new(ca)))
    }

    /// Build a new state with an externally-supplied CA (used by tests).
    pub fn with_ca(base_url: &str, ca: Arc<adrian_ca::CaService>) -> Self {
        AcmeState {
            base_url: base_url.to_string(),
            ca,
            nonces: RwLock::new(HashMap::new()),
            accounts: RwLock::new(HashMap::new()),
            orders: RwLock::new(HashMap::new()),
            authz: RwLock::new(HashMap::new()),
            challenges: RwLock::new(HashMap::new()),
            certs: RwLock::new(HashMap::new()),
            profile: "adrian-webserver".to_string(),
        }
    }

    /// Mint a fresh nonce and record it in the nonce cache.
    pub async fn mint_nonce(&self) -> String {
        let n = new_nonce();
        self.nonces.write().await.insert(n.clone(), ());
        n
    }

    /// Consume a nonce — removes it from the cache. Returns `true` if the
    /// nonce was known (and is now consumed).
    pub async fn consume_nonce(&self, nonce: &str) -> bool {
        self.nonces.write().await.remove(nonce).is_some()
    }

    /// Build the directory URL for `endpoint`.
    pub fn url(&self, endpoint: &str) -> String {
        format!("{}/{}", self.base_url, endpoint)
    }

    /// Account URL for a given account ID.
    pub fn acct_url(&self, acct_id: &str) -> String {
        self.url(&format!("acct/{acct_id}"))
    }

    /// Order URL for a given order ID.
    pub fn order_url(&self, order_id: &str) -> String {
        self.url(&format!("order/{order_id}"))
    }

    /// Authz URL for a given authz ID.
    pub fn authz_url(&self, authz_id: &str) -> String {
        self.url(&format!("authz/{authz_id}"))
    }

    /// Challenge URL for a given challenge ID.
    pub fn challenge_url(&self, chal_id: &str) -> String {
        self.url(&format!("challenge/{chal_id}"))
    }
}

// ===========================================================================
// Challenge verification (RFC 8555 §8.1-§8.4) — Domain-06 Wave 3
// ===========================================================================

/// Trait for http-01 challenge verification (RFC 8555 §8.1). The ACME
/// server fetches `http://{domain}/.well-known/acme-challenge/{token}` and
/// checks that the response body equals `{token}.{jwk_thumbprint}`.
///
/// Defining this as a trait lets tests inject a mock verifier (e.g. one
/// that reads from a local hyper server) without real DNS / network.
#[async_trait::async_trait]
pub trait Http01Verifier: Send + Sync {
    /// Fetch the URL and return the response body. Implementations should
    /// follow redirects per RFC 8555 §8.1 (the ACME server MAY follow
    /// redirects within the same host).
    async fn fetch(&self, url: &str) -> Result<String, AcmeError>;
}

/// Real http-01 verifier using `reqwest`. Follows redirects, returns the
/// response body as text. Used in production.
pub struct ReqwestHttp01Verifier {
    client: reqwest::Client,
}

impl ReqwestHttp01Verifier {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::limited(5))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl Default for ReqwestHttp01Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Http01Verifier for ReqwestHttp01Verifier {
    async fn fetch(&self, url: &str) -> Result<String, AcmeError> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AcmeError::Internal(format!("http-01 fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(AcmeError::Unauthorized(format!(
                "http-01 HTTP {}",
                resp.status()
            )));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| AcmeError::Internal(format!("http-01 body: {e}")))?;
        Ok(body)
    }
}

/// Verify an http-01 challenge (RFC 8555 §8.1). Fetches
/// `http://{domain}/.well-known/acme-challenge/{token}` and checks that
/// the response body equals `key_auth` (the expected
/// `{token}.{jwk_thumbprint}` value).
pub async fn verify_http_01_challenge(
    verifier: &dyn Http01Verifier,
    domain: &str,
    token: &str,
    key_auth: &str,
) -> Result<(), AcmeError> {
    let url = format!("http://{domain}/.well-known/acme-challenge/{token}");
    let body = verifier.fetch(&url).await?;
    // RFC 8555 §8.1: the server MUST verify that the response body equals
    // the expected key authorization. Trim trailing whitespace (some
    // servers add a newline).
    let body_trimmed = body.trim_end();
    let key_auth_trimmed = key_auth.trim_end();
    if body_trimmed == key_auth_trimmed {
        Ok(())
    } else {
        Err(AcmeError::Unauthorized(format!(
            "http-01 key authorization mismatch: expected {key_auth_trimmed}, got {body_trimmed}"
        )))
    }
}

/// Trait for dns-01 challenge verification (RFC 8555 §8.4). The ACME
/// server queries `_acme-challenge.{domain}` TXT records and checks that
/// at least one matches the expected value.
#[async_trait::async_trait]
pub trait Dns01Verifier: Send + Sync {
    /// Query TXT records for `name` and return all matching strings.
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AcmeError>;
}

/// Real dns-01 verifier using `hickory-resolver`.
pub struct HickoryDns01Verifier {
    resolver: std::sync::Arc<hickory_resolver::TokioAsyncResolver>,
}

impl HickoryDns01Verifier {
    pub fn new() -> Self {
        Self {
            resolver: std::sync::Arc::new(
                hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
                    .expect("hickory resolver"),
            ),
        }
    }
}

impl Default for HickoryDns01Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Dns01Verifier for HickoryDns01Verifier {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AcmeError> {
        let lookup = self
            .resolver
            .txt_lookup(name)
            .await
            .map_err(|e| AcmeError::Internal(format!("dns-01 lookup: {e}")))?;
        Ok(lookup.iter().map(|r| r.to_string()).collect::<Vec<_>>())
    }
}

/// Verify a dns-01 challenge (RFC 8555 §8.4). Queries
/// `_acme-challenge.{domain}` TXT records and checks that at least one
/// matches `expected` (the SHA-256 digest of the key authorization,
/// base64url-encoded).
pub async fn verify_dns_01_challenge(
    verifier: &dyn Dns01Verifier,
    domain: &str,
    expected: &str,
) -> Result<(), AcmeError> {
    let name = format!("_acme-challenge.{domain}");
    let txts = verifier.lookup_txt(&name).await?;
    if txts.iter().any(|t| t == expected) {
        Ok(())
    } else {
        Err(AcmeError::Unauthorized(format!(
            "dns-01: no TXT record for {name} matched {expected} (got {} records)",
            txts.len()
        )))
    }
}

/// Compute the dns-01 challenge response value (RFC 8555 §8.4: SHA-256
/// of the key authorization, base64url-encoded).
pub fn dns_01_response_value(key_auth: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, key_auth.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Compute the http-01 key authorization (`{token}.{jwk_thumbprint}`).
pub fn http_01_key_auth(token: &str, jwk: &Jwk) -> Result<String, AcmeError> {
    let thumb = jwk.thumbprint()?;
    Ok(format!("{token}.{thumb}"))
}

// ===========================================================================
// ARI (RFC 8823) — Renewal Information endpoint
// ===========================================================================

/// ARI renewal-info response (RFC 8823 §4). The suggested window is the
/// time range during which the client SHOULD attempt renewal.
#[derive(Clone, Debug, Serialize)]
pub struct AriRenewalInfo {
    /// Suggested renewal window (start, end) in RFC 3339 format.
    pub suggested_window: AriWindow,
    /// Optional explanation URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation_url: Option<String>,
}

/// ARI renewal window.
#[derive(Clone, Debug, Serialize)]
pub struct AriWindow {
    pub start: String,
    pub end: String,
}

/// Parse an ARI certID (RFC 8823 §4.1). The certID is the base64url-encoded
/// `issuerNameHash || issuerKeyHash || serialNumber` — specifically the
/// `keyIdentifier` of the AKI ext + serial. For simplicity, this Wave 3
/// implementation accepts a serial number directly and returns a default
/// renewal window.
pub fn parse_ari_cert_id(cert_id: &str) -> Result<u64, AcmeError> {
    // The RFC 8823 certID is the base64url of the CertID (same structure as
    // OCSP). For this implementation we accept either:
    // 1. A plain decimal serial number (test convenience), OR
    // 2. A base64url-encoded CertId (parsed via adrian_ca::OcspCertId).
    if let Ok(serial) = cert_id.parse::<u64>() {
        return Ok(serial);
    }
    // Try base64url decode + OCSP CertId parse.
    let bytes = URL_SAFE_NO_PAD
        .decode(cert_id)
        .map_err(|e| AcmeError::Malformed(format!("ari certId b64: {e}")))?;
    let cert_id: adrian_ca::OcspCertId = rasn::der::decode(&bytes)
        .map_err(|e| AcmeError::Malformed(format!("ari certId der: {e}")))?;
    u64::try_from(&cert_id.serial_number)
        .map_err(|_| AcmeError::Malformed("ari certId serial too large".into()))
}

/// Compute the ARI suggested renewal window for a certificate with the
/// given `not_after` (expiry). RFC 8823 §4.2 recommends renewing in the
/// last 1/3 of the certificate's validity period. For a 90-day cert, that's
/// the last 30 days.
pub fn ari_suggested_window(
    not_after: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> AriWindow {
    let window_start = not_after - chrono::Duration::days(30);
    let window_end = not_after;
    let _ = now;
    AriWindow {
        start: window_start.to_rfc3339(),
        end: window_end.to_rfc3339(),
    }
}

// ===========================================================================
// ACME server handle
// ===========================================================================

/// ACME server (RFC 8555). Mounted under `/acme/directory`.
pub struct AcmeServer {
    state: Arc<AcmeState>,
}

impl AcmeServer {
    /// Create a new ACME server with a freshly-generated CA and the given
    /// base URL (e.g. `"https://ca.adrian.dev/acme"`).
    pub fn new(base_url: &str) -> Result<Self, AcmeError> {
        let state = Arc::new(AcmeState::new(base_url)?);
        Ok(Self { state })
    }

    /// Create a new ACME server with an externally-supplied CA.
    pub fn with_ca(base_url: &str, ca: Arc<adrian_ca::CaService>) -> Self {
        let state = Arc::new(AcmeState::with_ca(base_url, ca));
        Self { state }
    }

    /// Return a reference to the ACME state (used by tests).
    pub fn state(&self) -> &Arc<AcmeState> {
        &self.state
    }

    /// Serve the ACME directory + endpoints on the given axum router.
    pub fn router(&self) -> Router {
        let state = self.state.clone();
        Router::new()
            .route("/directory", get(directory))
            .route("/new-nonce", head(new_nonce_handler))
            .route("/new-account", post(new_account))
            .route("/new-order", post(new_order))
            .route("/authz/{id}", post(authz_handler))
            .route("/challenge/{id}", post(challenge_handler))
            .route("/order/{id}/finalize", post(finalize_order))
            .route("/order/{id}/cert", get(get_cert))
            .with_state(state)
    }

    /// Serve ARI (RFC 8823) renewal-info endpoint.
    /// `GET /draft-ietf-acme-ari-03/renewal-info/{certID}` returns the
    /// suggested renewal window for the certificate identified by `certID`.
    /// The certID is either a plain decimal serial number (test convenience)
    /// or a base64url-encoded OCSP CertId.
    pub fn ari_router(&self) -> Router {
        let state = self.state.clone();
        Router::new()
            .route(
                "/draft-ietf-acme-ari-03/renewal-info/{cert_id}",
                get(ari_renewal_info_handler),
            )
            .with_state(state)
    }
}

impl Default for AcmeServer {
    fn default() -> Self {
        Self::new("https://ca.adrian.dev/acme").expect("default ACME server")
    }
}

// ===========================================================================
// Handlers
// ===========================================================================

/// `GET /directory` — return the ACME directory object (RFC 8555 §7.1.1).
async fn directory(State(state): State<Arc<AcmeState>>) -> impl IntoResponse {
    let dir = serde_json::json!({
        "newNonce": state.url("new-nonce"),
        "newAccount": state.url("new-account"),
        "newOrder": state.url("new-order"),
        "revokeCert": state.url("revoke-cert"),
        "keyChange": state.url("key-change"),
        "meta": {
            "termsOfService": "https://ca.adrian.dev/tos",
            "website": "https://adrian.dev",
        },
    });
    (StatusCode::OK, Json(dir))
}

/// `HEAD /new-nonce` — return a fresh nonce in the `Replay-Nonce` header.
async fn new_nonce_handler(State(state): State<Arc<AcmeState>>) -> impl IntoResponse {
    let nonce = state.mint_nonce().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "Replay-Nonce",
        HeaderValue::from_str(&nonce).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    headers.insert("Cache-Control", HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, "")
}

/// `POST /new-account` — create a new account (RFC 8555 §7.3).
async fn new_account(State(state): State<Arc<AcmeState>>, body: axum::body::Body) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let jws: JwsBody = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(e) => return AcmeError::Malformed(format!("jws body: {e}")).into_response(),
    };

    let expected = state.url("new-account");
    let jwk = match verify_jws(&jws, &expected) {
        Ok(j) => j,
        Err(e) => return e.into_response(),
    };
    // Replay-Nonce check (RFC 8555 §6.5).
    let header = match jws.decoded_header() {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    if !state.consume_nonce(&header.nonce).await {
        return AcmeError::Unauthorized(format!("bad nonce: {}", header.nonce)).into_response();
    }

    let payload = match jws.decoded_payload() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    #[derive(Deserialize)]
    struct NewAccountReq {
        contact: Vec<String>,
        #[serde(default, rename = "termsOfServiceAgreed")]
        terms_of_service_agreed: bool,
    }
    let req: NewAccountReq = match serde_json::from_slice(&payload) {
        Ok(r) => r,
        Err(e) => return AcmeError::Malformed(format!("payload: {e}")).into_response(),
    };
    if !req.terms_of_service_agreed {
        return AcmeError::Unauthorized("termsOfServiceAgreed is false".into()).into_response();
    }

    // Compute account ID from JWK thumbprint (RFC 7638). This makes account
    // lookups deterministic for the same key.
    let acct_id = jwk.thumbprint().unwrap_or_else(|_| "unknown".into());
    let kid = state.acct_url(&acct_id);
    let account = AcmeAccount {
        kid: kid.clone(),
        contact: req.contact,
        status: AccountStatus::Valid,
        jwk,
    };
    let mut accounts = state.accounts.write().await;
    let was_new = !accounts.contains_key(&acct_id);
    accounts.insert(acct_id.clone(), account);

    let nonce = state.mint_nonce().await;
    let body = Json(serde_json::json!({
        "status": "valid",
        "contact": accounts.get(&acct_id).map(|a| a.contact.clone()).unwrap_or_default(),
    }));
    let status = if was_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        "Location",
        HeaderValue::from_str(&kid).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp.headers_mut().insert(
        "Replay-Nonce",
        HeaderValue::from_str(&nonce).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

/// `POST /new-order` — create a new order (RFC 8555 §7.4).
async fn new_order(State(state): State<Arc<AcmeState>>, body: axum::body::Body) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let jws: JwsBody = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(e) => return AcmeError::Malformed(format!("jws body: {e}")).into_response(),
    };
    let header = match jws.decoded_header() {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    // Lookup the account by kid.
    let kid = match &header.kid {
        Some(k) => k.clone(),
        None => {
            return AcmeError::Unauthorized("kid required for new-order".into()).into_response();
        }
    };
    // Extract the acct_id from the kid URL.
    let acct_id = match kid.rsplit('/').next() {
        Some(s) => s.to_string(),
        None => return AcmeError::Malformed("bad kid url".into()).into_response(),
    };
    let accounts = state.accounts.read().await;
    let account = match accounts.get(&acct_id) {
        Some(a) => a.clone(),
        None => {
            return AcmeError::Unauthorized(format!("unknown account: {acct_id}")).into_response();
        }
    };
    drop(accounts);

    let expected = state.url("new-order");
    if let Err(e) = verify_jws_with_kid(&jws, &expected, &account.jwk) {
        return e.into_response();
    }
    if !state.consume_nonce(&header.nonce).await {
        return AcmeError::Unauthorized("bad nonce".into()).into_response();
    }

    let payload = match jws.decoded_payload() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    #[derive(Deserialize)]
    struct NewOrderReq {
        identifiers: Vec<Identifier>,
    }
    let req: NewOrderReq = match serde_json::from_slice(&payload) {
        Ok(r) => r,
        Err(e) => return AcmeError::Malformed(format!("payload: {e}")).into_response(),
    };
    if req.identifiers.is_empty() {
        return AcmeError::Malformed("identifiers is empty".into()).into_response();
    }

    let order_id = uuid::Uuid::now_v7().to_string();
    let authz_id = uuid::Uuid::now_v7().to_string();
    let chal_id = uuid::Uuid::now_v7().to_string();
    let expires = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
    let token = new_nonce(); // random token

    let challenge = Challenge {
        typ: "http-01".into(),
        url: state.challenge_url(&chal_id),
        status: ChallengeStatus::Pending,
        token: token.clone(),
    };
    let authz = AcmeAuthz {
        identifier: req.identifiers[0].clone(),
        status: AuthzStatus::Pending,
        expires: expires.clone(),
        challenges: vec![challenge.clone()],
    };

    let order = AcmeOrder {
        status: OrderStatus::Pending,
        expires: expires.clone(),
        identifiers: req.identifiers.clone(),
        authorizations: vec![state.authz_url(&authz_id)],
        finalize: state.url(&format!("order/{order_id}/finalize")),
        certificate: None,
    };

    state
        .challenges
        .write()
        .await
        .insert(chal_id.clone(), challenge);
    state.authz.write().await.insert(authz_id, authz);
    let order_snapshot = order.clone();
    state.orders.write().await.insert(order_id.clone(), order);

    let order_url = state.order_url(&order_id);
    let nonce = state.mint_nonce().await;
    let body = Json(serde_json::to_value(&order_snapshot).unwrap_or_default());
    let mut resp = (StatusCode::CREATED, body).into_response();
    resp.headers_mut().insert(
        "Location",
        HeaderValue::from_str(&order_url).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp.headers_mut().insert(
        "Replay-Nonce",
        HeaderValue::from_str(&nonce).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

/// `POST /authz/{id}` — return the authorization status.
async fn authz_handler(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: axum::body::Body,
) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let jws: JwsBody = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(e) => return AcmeError::Malformed(format!("jws body: {e}")).into_response(),
    };
    let header = match jws.decoded_header() {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    let kid = match &header.kid {
        Some(k) => k.clone(),
        None => {
            return AcmeError::Unauthorized("kid required".into()).into_response();
        }
    };
    let acct_id = match kid.rsplit('/').next() {
        Some(s) => s.to_string(),
        None => return AcmeError::Malformed("bad kid url".into()).into_response(),
    };
    let accounts = state.accounts.read().await;
    let account = match accounts.get(&acct_id) {
        Some(a) => a.clone(),
        None => {
            return AcmeError::Unauthorized(format!("unknown account: {acct_id}")).into_response();
        }
    };
    drop(accounts);

    let expected = state.authz_url(&id);
    if let Err(e) = verify_jws_with_kid(&jws, &expected, &account.jwk) {
        return e.into_response();
    }
    if !state.consume_nonce(&header.nonce).await {
        return AcmeError::Unauthorized("bad nonce".into()).into_response();
    }

    let authz = state.authz.read().await;
    let a = match authz.get(&id) {
        Some(a) => a.clone(),
        None => return AcmeError::NotFound(format!("authz {id}")).into_response(),
    };
    let nonce = state.mint_nonce().await;
    let mut resp = Json(serde_json::to_value(&a).unwrap_or_default()).into_response();
    resp.headers_mut().insert(
        "Replay-Nonce",
        HeaderValue::from_str(&nonce).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

/// `POST /challenge/{id}` — mark a challenge as ready (deactivate it as
/// `valid` for the Wave 3a simplified flow — a real implementation would
/// fetch the URL and verify the response).
async fn challenge_handler(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: axum::body::Body,
) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let jws: JwsBody = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(e) => return AcmeError::Malformed(format!("jws body: {e}")).into_response(),
    };
    let header = match jws.decoded_header() {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    let kid = match &header.kid {
        Some(k) => k.clone(),
        None => {
            return AcmeError::Unauthorized("kid required".into()).into_response();
        }
    };
    let acct_id = match kid.rsplit('/').next() {
        Some(s) => s.to_string(),
        None => return AcmeError::Malformed("bad kid url".into()).into_response(),
    };
    let accounts = state.accounts.read().await;
    let account = match accounts.get(&acct_id) {
        Some(a) => a.clone(),
        None => {
            return AcmeError::Unauthorized(format!("unknown account: {acct_id}")).into_response();
        }
    };
    drop(accounts);

    let expected = state.challenge_url(&id);
    if let Err(e) = verify_jws_with_kid(&jws, &expected, &account.jwk) {
        return e.into_response();
    }
    if !state.consume_nonce(&header.nonce).await {
        return AcmeError::Unauthorized("bad nonce".into()).into_response();
    }

    // Mark the challenge valid + the corresponding authz valid (Wave 3a
    // simplified: assume the client satisfies http-01).
    let mut challenges = state.challenges.write().await;
    let challenge = match challenges.get_mut(&id) {
        Some(c) => c,
        None => return AcmeError::NotFound(format!("challenge {id}")).into_response(),
    };
    challenge.status = ChallengeStatus::Valid;
    let chal_snapshot = challenge.clone();
    drop(challenges);

    // Find the authz containing this challenge and mark it valid.
    let mut authz = state.authz.write().await;
    for a in authz.values_mut() {
        if a.challenges.iter().any(|c| c.url == chal_snapshot.url) {
            a.status = AuthzStatus::Valid;
            // Mark the order ready/valid.
            break;
        }
    }
    drop(authz);

    // Mark any order that references this authz as ready.
    let mut orders = state.orders.write().await;
    for o in orders.values_mut() {
        let authz_url = state.authz_url(&id);
        if o.authorizations.contains(&authz_url) {
            o.status = OrderStatus::Ready;
        }
    }
    drop(orders);

    let nonce = state.mint_nonce().await;
    let mut resp = Json(serde_json::to_value(&chal_snapshot).unwrap_or_default()).into_response();
    resp.headers_mut().insert(
        "Replay-Nonce",
        HeaderValue::from_str(&nonce).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

/// `POST /order/{id}/finalize` — submit CSR and issue cert.
async fn finalize_order(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: axum::body::Body,
) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let jws: JwsBody = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(e) => return AcmeError::Malformed(format!("jws body: {e}")).into_response(),
    };
    let header = match jws.decoded_header() {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    let kid = match &header.kid {
        Some(k) => k.clone(),
        None => {
            return AcmeError::Unauthorized("kid required".into()).into_response();
        }
    };
    let acct_id = match kid.rsplit('/').next() {
        Some(s) => s.to_string(),
        None => return AcmeError::Malformed("bad kid url".into()).into_response(),
    };
    let accounts = state.accounts.read().await;
    let account = match accounts.get(&acct_id) {
        Some(a) => a.clone(),
        None => {
            return AcmeError::Unauthorized(format!("unknown account: {acct_id}")).into_response();
        }
    };
    drop(accounts);

    let expected = state.url(&format!("order/{id}/finalize"));
    if let Err(e) = verify_jws_with_kid(&jws, &expected, &account.jwk) {
        return e.into_response();
    }
    if !state.consume_nonce(&header.nonce).await {
        return AcmeError::Unauthorized("bad nonce".into()).into_response();
    }

    let payload = match jws.decoded_payload() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    #[derive(Deserialize)]
    struct FinalizeReq {
        csr: String,
    }
    let req: FinalizeReq = match serde_json::from_slice(&payload) {
        Ok(r) => r,
        Err(e) => return AcmeError::Malformed(format!("payload: {e}")).into_response(),
    };
    let csr_der = match URL_SAFE_NO_PAD.decode(&req.csr) {
        Ok(b) => b,
        Err(e) => return AcmeError::Malformed(format!("csr b64: {e}")).into_response(),
    };

    // Issue via the CA.
    let cert_der = match state.ca.issue(&state.profile, &csr_der).await {
        Ok(d) => d,
        Err(e) => return AcmeError::from(e).into_response(),
    };
    state.certs.write().await.insert(id.clone(), cert_der);

    // Update the order.
    let cert_url = state.url(&format!("order/{id}/cert"));
    let mut orders = state.orders.write().await;
    if let Some(o) = orders.get_mut(&id) {
        o.status = OrderStatus::Valid;
        o.certificate = Some(cert_url.clone());
    } else {
        return AcmeError::NotFound(format!("order {id}")).into_response();
    }
    let snapshot = orders.get(&id).cloned();
    drop(orders);

    let nonce = state.mint_nonce().await;
    let body = Json(serde_json::to_value(&snapshot).unwrap_or_default());
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        "Replay-Nonce",
        HeaderValue::from_str(&nonce).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

/// `GET /order/{id}/cert` — return the issued certificate (DER).
async fn get_cert(State(state): State<Arc<AcmeState>>, Path(id): Path<String>) -> Response {
    let certs = state.certs.read().await;
    let cert = match certs.get(&id) {
        Some(c) => c.clone(),
        None => return AcmeError::NotFound(format!("cert for order {id}")).into_response(),
    };
    drop(certs);
    let mut resp = cert.into_response();
    resp.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/pkix-cert"),
    );
    resp
}

/// `GET /draft-ietf-acme-ari-03/renewal-info/{certID}` (RFC 8823 §4).
/// Returns the suggested renewal window for the certificate identified by
/// `certID`. The certID is either a plain decimal serial or a base64url-
/// encoded OCSP CertId.
async fn ari_renewal_info_handler(
    State(state): State<Arc<AcmeState>>,
    Path(cert_id): Path<String>,
) -> Response {
    let serial = match parse_ari_cert_id(&cert_id) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    // Look up the issued cert by serial to find its not_after.
    let cert = match state.ca.issued_cert_by_serial(serial).await {
        Some(c) => c,
        None => {
            // RFC 8823 §4.2: if the cert is unknown, return a window that
            // suggests immediate renewal (start = now, end = now + 7 days).
            let now = chrono::Utc::now();
            let window = AriWindow {
                start: now.to_rfc3339(),
                end: (now + chrono::Duration::days(7)).to_rfc3339(),
            };
            let info = AriRenewalInfo {
                suggested_window: window,
                explanation_url: None,
            };
            let mut resp = Json(serde_json::to_value(&info).unwrap_or_default()).into_response();
            resp.headers_mut()
                .insert("Content-Type", HeaderValue::from_static("application/json"));
            return resp;
        }
    };
    let window = ari_suggested_window(cert.not_after, chrono::Utc::now());
    let info = AriRenewalInfo {
        suggested_window: window,
        explanation_url: None,
    };
    let mut resp = Json(serde_json::to_value(&info).unwrap_or_default()).into_response();
    resp.headers_mut()
        .insert("Content-Type", HeaderValue::from_static("application/json"));
    resp
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Wrapper to emit JSON with the correct content type.
struct Json<T>(T);

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self.0).unwrap_or_else(|_| b"null".to_vec());
        let mut resp = body.into_response();
        resp.headers_mut()
            .insert("Content-Type", HeaderValue::from_static("application/json"));
        resp
    }
}

/// Read an axum body to bytes.
async fn read_body(body: axum::body::Body) -> Result<Vec<u8>, AcmeError> {
    use http_body_util::BodyExt;
    body.collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .map_err(|e| AcmeError::Malformed(format!("body read: {e}")))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-acme-server`. Wave 3a covers directory, nonce,
    //! JWS verification, account creation, order creation + finalize, and
    //! certificate download. Tests use `tower::ServiceExt::oneshot` to drive
    //! the axum router without spawning a real HTTP server.

    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ring::signature::KeyPair as _;
    use tower::ServiceExt;

    /// Build a fresh ECDSA-P256 signing key for tests.
    fn test_keypair() -> ring::signature::EcdsaKeyPair {
        let rng = SystemRandom::new();
        let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap()
    }

    /// Sign a JWS request body.
    fn sign_jws(
        kp: &ring::signature::EcdsaKeyPair,
        protected: &JwsProtectedHeader,
        payload: &serde_json::Value,
    ) -> JwsBody {
        let protected_json = serde_json::to_string(protected).unwrap();
        let protected_b64 = URL_SAFE_NO_PAD.encode(protected_json.as_bytes());
        let payload_b64 = if payload == &serde_json::Value::Null {
            String::new()
        } else {
            let payload_json = serde_json::to_string(payload).unwrap();
            URL_SAFE_NO_PAD.encode(payload_json.as_bytes())
        };
        let mut signing_input = Vec::with_capacity(protected_b64.len() + 1 + payload_b64.len());
        signing_input.extend_from_slice(protected_b64.as_bytes());
        signing_input.push(b'.');
        signing_input.extend_from_slice(payload_b64.as_bytes());
        let rng = SystemRandom::new();
        let sig = kp.sign(&rng, &signing_input).unwrap();
        JwsBody {
            protected: protected_b64,
            payload: payload_b64,
            signature: URL_SAFE_NO_PAD.encode(sig.as_ref()),
        }
    }

    /// Build a Jwk from a ring key pair.
    fn jwk_from_kp(kp: &ring::signature::EcdsaKeyPair) -> Jwk {
        Jwk::from_sec1(kp.public_key().as_ref()).unwrap()
    }

    /// Send a request to the router and return (status, headers, body).
    async fn send(router: Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }

    #[test]
    fn acme_directory_returns_correct_urls() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        let router = server.router();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (status, _headers, body) = rt.block_on(async move {
            let req = Request::builder()
                .method("GET")
                .uri("/directory")
                .body(Body::empty())
                .unwrap();
            send(router, req).await
        });
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["newNonce"], "https://ca.example.com/acme/new-nonce");
        assert_eq!(v["newAccount"], "https://ca.example.com/acme/new-account");
        assert_eq!(v["newOrder"], "https://ca.example.com/acme/new-order");
    }

    #[test]
    fn acme_new_nonce_returns_fresh_nonce_in_header() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        let router = server.router();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (status, headers, _body) = rt.block_on(async move {
            let req = Request::builder()
                .method("HEAD")
                .uri("/new-nonce")
                .body(Body::empty())
                .unwrap();
            send(router, req).await
        });
        assert_eq!(status, StatusCode::OK);
        let nonce = headers.get("Replay-Nonce").unwrap().to_str().unwrap();
        assert!(!nonce.is_empty());
        // base64url of 32 bytes is 43 chars.
        assert_eq!(nonce.len(), 43);
    }

    #[test]
    fn new_nonce_helper_produces_base64url_43_chars() {
        let n = new_nonce();
        // 32 bytes -> base64url no pad -> 43 chars.
        assert_eq!(n.len(), 43);
        // Two calls produce different nonces.
        let n2 = new_nonce();
        assert_ne!(n, n2);
    }

    #[test]
    fn jwk_round_trips_through_sec1() {
        let kp = test_keypair();
        let pub_sec1 = kp.public_key().as_ref();
        let jwk = Jwk::from_sec1(pub_sec1).unwrap();
        let back = jwk.to_sec1().unwrap();
        assert_eq!(back.as_slice(), pub_sec1);
    }

    #[test]
    fn jwk_thumbprint_is_deterministic_and_base64url() {
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let t1 = jwk.thumbprint().unwrap();
        let t2 = jwk.thumbprint().unwrap();
        assert_eq!(t1, t2);
        // base64url of SHA-256 (32 bytes) is 43 chars.
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn verify_jws_accepts_valid_signature() {
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: Some(jwk.clone()),
            kid: None,
            nonce: "test-nonce".into(),
            url: "https://ca.example.com/acme/new-account".into(),
        };
        let payload = serde_json::json!({"contact":["mailto:a@b.c"]});
        let body = sign_jws(&kp, &protected, &payload);
        let verified = verify_jws(&body, "https://ca.example.com/acme/new-account");
        assert!(verified.is_ok());
        assert_eq!(verified.unwrap().x, jwk.x);
    }

    #[test]
    fn verify_jws_rejects_invalid_signature() {
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: Some(jwk),
            kid: None,
            nonce: "test-nonce".into(),
            url: "https://ca.example.com/acme/new-account".into(),
        };
        let payload = serde_json::json!({"contact":["mailto:a@b.c"]});
        let mut body = sign_jws(&kp, &protected, &payload);
        // Flip a bit in the signature.
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(&body.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        body.signature = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let err = verify_jws(&body, "https://ca.example.com/acme/new-account").unwrap_err();
        assert!(matches!(err, AcmeError::Unauthorized(_)));
    }

    #[test]
    fn verify_jws_rejects_wrong_url() {
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: Some(jwk),
            kid: None,
            nonce: "test-nonce".into(),
            url: "https://ca.example.com/acme/wrong-url".into(),
        };
        let payload = serde_json::json!({});
        let body = sign_jws(&kp, &protected, &payload);
        let err = verify_jws(&body, "https://ca.example.com/acme/new-account").unwrap_err();
        assert!(matches!(err, AcmeError::Unauthorized(_)));
    }

    #[test]
    fn acme_account_creation_with_valid_jws_returns_201() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        // Pre-seed a nonce.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let nonce = rt.block_on(async { server.state().mint_nonce().await });
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: Some(jwk),
            kid: None,
            nonce,
            url: "https://ca.example.com/acme/new-account".into(),
        };
        let payload = serde_json::json!({
            "contact": ["mailto:test@example.com"],
            "termsOfServiceAgreed": true,
        });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let (status, headers, body_bytes) = rt.block_on(async move {
            let req = Request::builder()
                .method("POST")
                .uri("/new-account")
                .header("Content-Type", "application/jose+json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            send(router, req).await
        });
        assert_eq!(status, StatusCode::CREATED);
        let location = headers.get("Location").unwrap().to_str().unwrap();
        assert!(location.starts_with("https://ca.example.com/acme/acct/"));
        let replay_nonce = headers.get("Replay-Nonce").unwrap().to_str().unwrap();
        assert!(!replay_nonce.is_empty());
        let body_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_val["status"], "valid");
    }

    #[test]
    fn acme_account_creation_rejects_invalid_jws() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let nonce = rt.block_on(async { server.state().mint_nonce().await });
        let kp = test_keypair();
        // Use a different key pair's jwk to forge.
        let bad_kp = test_keypair();
        let bad_jwk = jwk_from_kp(&bad_kp);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: Some(bad_jwk),
            kid: None,
            nonce,
            url: "https://ca.example.com/acme/new-account".into(),
        };
        let payload = serde_json::json!({
            "contact": ["mailto:test@example.com"],
            "termsOfServiceAgreed": true,
        });
        // Sign with `kp`, but the protected header's jwk is `bad_kp`'s —
        // signature verification should fail.
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let (status, _headers, body_bytes) = rt.block_on(async move {
            let req = Request::builder()
                .method("POST")
                .uri("/new-account")
                .header("Content-Type", "application/jose+json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            send(router, req).await
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_val["type"], "urn:ietf:params:acme:error:unauthorized");
    }

    /// Helper: create an account and return (kid, jwk, kp, nonce).
    async fn create_account(
        server: &AcmeServer,
    ) -> (String, Jwk, ring::signature::EcdsaKeyPair, String) {
        let nonce = server.state().mint_nonce().await;
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: Some(jwk.clone()),
            kid: None,
            nonce,
            url: format!("{}/new-account", server.state().base_url),
        };
        let payload = serde_json::json!({
            "contact": ["mailto:test@example.com"],
            "termsOfServiceAgreed": true,
        });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri("/new-account")
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (status, headers, _body) = send(router, req).await;
        assert_eq!(status, StatusCode::CREATED);
        let kid = headers
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let new_nonce = headers
            .get("Replay-Nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        (kid, jwk, kp, new_nonce)
    }

    /// Build a CSR via adrian_ca (using a fresh keypair) and return its DER.
    fn make_csr_der() -> Vec<u8> {
        // Reuse adrian_ca's test CSR builder via ring directly.
        let rng = SystemRandom::new();
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let kp = ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
        let pub_sec1 = kp.public_key().as_ref().to_vec();

        use rasn::prelude::*;
        use rasn_pkix::*;
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::new(&[1, 2, 840, 10045, 2, 1]).unwrap(),
                parameters: Some(Any::new(
                    rasn::der::encode(
                        &ObjectIdentifier::new(&[1, 2, 840, 10045, 3, 1, 7]).unwrap(),
                    )
                    .unwrap(),
                )),
            },
            subject_public_key: bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::from_vec(pub_sec1),
        };
        let cn = "host.adrian.dev";
        let ps = PrintableString::try_from(cn).unwrap();
        let atv = AttributeTypeAndValue {
            r#type: ObjectIdentifier::new(&[2, 5, 4, 3]).unwrap(),
            value: Any::new(rasn::der::encode(&ps).unwrap()),
        };
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![atv]));
        let info = adrian_ca::CertificationRequestInfo {
            version: Integer::from(0u32),
            subject: Name::RdnSequence(vec![rdn]),
            subject_pk_info: spki,
            attributes: SetOf::new(),
        };
        let info_der = rasn::der::encode(&info).unwrap();
        let sig = kp.sign(&rng, &info_der).unwrap();
        let csr = adrian_ca::CertificationRequest {
            certification_request_info: info,
            signature_algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::new(&[1, 2, 840, 10045, 4, 3, 2]).unwrap(),
                parameters: None,
            },
            signature: bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::from_vec(
                sig.as_ref().to_vec(),
            ),
        };
        rasn::der::encode(&csr).unwrap()
    }

    #[tokio::test]
    async fn acme_order_creation_returns_201_with_authorizations() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        let (kid, jwk, kp, nonce) = create_account(&server).await;

        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce,
            url: format!("{}/new-order", server.state().base_url),
        };
        let payload = serde_json::json!({
            "identifiers": [{"type":"dns","value":"host.adrian.dev"}],
        });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri("/new-order")
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (status, _headers, _body_bytes) = send(router, req).await;
        assert_eq!(status, StatusCode::CREATED);
        let body_val: serde_json::Value = serde_json::from_slice(&_body_bytes).unwrap();
        assert_eq!(body_val["status"], "pending");
        assert!(body_val["authorizations"].is_array());
        assert_eq!(body_val["authorizations"].as_array().unwrap().len(), 1);
        assert!(body_val["finalize"]
            .as_str()
            .unwrap()
            .ends_with("/finalize"));
        let _ = jwk;
    }

    #[tokio::test]
    async fn acme_order_finalize_and_cert_download_succeeds() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        let (kid, _jwk, kp, nonce) = create_account(&server).await;

        // Create order.
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce,
            url: format!("{}/new-order", server.state().base_url),
        };
        let payload = serde_json::json!({
            "identifiers": [{"type":"dns","value":"host.adrian.dev"}],
        });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri("/new-order")
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (status, headers, _body_bytes) = send(router, req).await;
        assert_eq!(status, StatusCode::CREATED);
        let order_url = headers
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let order_id = order_url.rsplit('/').next().unwrap().to_string();
        let new_nonce = headers
            .get("Replay-Nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Finalize the order with a real CSR.
        let csr_der = make_csr_der();
        let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce: new_nonce,
            url: format!("{}/order/{order_id}/finalize", server.state().base_url),
        };
        let payload = serde_json::json!({ "csr": csr_b64 });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/order/{order_id}/finalize"))
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (status, _headers, body_bytes) = send(router, req).await;
        assert_eq!(status, StatusCode::OK);
        let body_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_val["status"], "valid");
        let cert_url = body_val["certificate"].as_str().unwrap().to_string();

        // Download the cert.
        let cert_path = cert_url
            .strip_prefix(&format!("{}/", server.state().base_url))
            .unwrap();
        let cert_uri = format!("/{cert_path}");
        let router = server.router();
        let req = Request::builder()
            .method("GET")
            .uri(&cert_uri)
            .body(Body::empty())
            .unwrap();
        let (status, headers, body_bytes) = send(router, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("Content-Type").unwrap().to_str().unwrap(),
            "application/pkix-cert"
        );
        // The cert should be valid DER (SEQUENCE).
        assert!(!body_bytes.is_empty());
        assert_eq!(body_bytes[0], 0x30);
    }

    #[tokio::test]
    async fn acme_challenge_handler_marks_authz_valid() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        let (kid, _jwk, kp, nonce) = create_account(&server).await;

        // Create an order to get an authz.
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce,
            url: format!("{}/new-order", server.state().base_url),
        };
        let payload = serde_json::json!({
            "identifiers": [{"type":"dns","value":"chal.adrian.dev"}],
        });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri("/new-order")
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (_status, _headers, body_bytes) = send(router, req).await;
        let body_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let authz_url = body_val["authorizations"][0].as_str().unwrap().to_string();
        let authz_id = authz_url.rsplit('/').next().unwrap().to_string();

        // Get the authz to find the challenge URL.
        let nonce = server.state().mint_nonce().await;
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce,
            url: format!("{}/authz/{authz_id}", server.state().base_url),
        };
        let payload = serde_json::json!({});
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/authz/{authz_id}"))
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (status, _headers, body_bytes) = send(router, req).await;
        assert_eq!(status, StatusCode::OK);
        let authz_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let challenge_url = authz_val["challenges"][0]["url"]
            .as_str()
            .unwrap()
            .to_string();
        let chal_id = challenge_url.rsplit('/').next().unwrap().to_string();

        // POST to the challenge to mark it valid.
        let nonce = server.state().mint_nonce().await;
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce,
            url: format!("{}/challenge/{chal_id}", server.state().base_url),
        };
        let payload = serde_json::json!({});
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/challenge/{chal_id}"))
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (status, _headers, body_bytes) = send(router, req).await;
        assert_eq!(status, StatusCode::OK);
        let chal_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(chal_val["status"], "valid");
    }

    #[test]
    fn acme_error_status_codes_match_rfc_8555() {
        assert_eq!(
            AcmeError::Malformed("x".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::Unauthorized("x".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AcmeError::RateLimited.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            AcmeError::NotFound("x".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AcmeError::Conflict("x".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AcmeError::Ca("x".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn routers_construct_without_panic() {
        let server = AcmeServer::default();
        let _r1 = server.router();
        let _r2 = server.ari_router();
    }

    // ===== Domain-06 Wave 3: Real challenge verification + ARI tests =====

    /// Mock http-01 verifier that returns a pre-configured response body.
    /// Used to test `verify_http_01_challenge` without real network.
    struct MockHttp01 {
        response: String,
    }

    #[async_trait::async_trait]
    impl Http01Verifier for MockHttp01 {
        async fn fetch(&self, _url: &str) -> Result<String, AcmeError> {
            Ok(self.response.clone())
        }
    }

    /// http-01 challenge verification succeeds when the response body
    /// matches the expected key authorization (RFC 8555 §8.1).
    #[tokio::test]
    async fn http_01_challenge_succeeds_with_matching_key_auth() {
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let token = "test-token-12345";
        let key_auth = http_01_key_auth(token, &jwk).expect("key auth");
        let verifier = MockHttp01 {
            response: key_auth.clone(),
        };
        let result = verify_http_01_challenge(&verifier, "example.com", token, &key_auth).await;
        assert!(
            result.is_ok(),
            "http-01 should succeed with matching key auth"
        );
    }

    /// http-01 challenge verification fails when the response body does NOT
    /// match the expected key authorization (RFC 8555 §8.1).
    #[tokio::test]
    async fn http_01_challenge_fails_with_wrong_response() {
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let token = "test-token-12345";
        let key_auth = http_01_key_auth(token, &jwk).expect("key auth");
        let verifier = MockHttp01 {
            response: "wrong-response".to_string(),
        };
        let result = verify_http_01_challenge(&verifier, "example.com", token, &key_auth).await;
        let err = result.expect_err("http-01 should fail with wrong response");
        assert!(matches!(err, AcmeError::Unauthorized(_)), "{err:?}");
        assert!(err.to_string().contains("mismatch"), "{err}");
    }

    /// Mock dns-01 verifier that returns pre-configured TXT records.
    struct MockDns01 {
        txts: Vec<String>,
    }

    #[async_trait::async_trait]
    impl Dns01Verifier for MockDns01 {
        async fn lookup_txt(&self, _name: &str) -> Result<Vec<String>, AcmeError> {
            Ok(self.txts.clone())
        }
    }

    /// dns-01 challenge verification succeeds when a TXT record matches
    /// the expected value (RFC 8555 §8.4).
    #[tokio::test]
    async fn dns_01_challenge_succeeds_with_matching_txt() {
        let kp = test_keypair();
        let jwk = jwk_from_kp(&kp);
        let token = "dns-token-abc";
        let key_auth = http_01_key_auth(token, &jwk).expect("key auth");
        let expected = dns_01_response_value(&key_auth);
        let verifier = MockDns01 {
            txts: vec![expected.clone()],
        };
        let result = verify_dns_01_challenge(&verifier, "example.com", &expected).await;
        assert!(result.is_ok(), "dns-01 should succeed with matching TXT");
    }

    /// ARI endpoint returns a renewal window for an existing cert.
    /// We issue a cert via the ACME flow, then query ARI with its serial.
    #[tokio::test]
    async fn ari_returns_renewal_window_for_existing_cert() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        // Issue a cert to populate the CA's issued ledger.
        let (kid, _jwk, kp, nonce) = create_account(&server).await;
        // Create order + finalize to get a cert.
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce,
            url: format!("{}/new-order", server.state().base_url),
        };
        let payload = serde_json::json!({
            "identifiers": [{"type":"dns","value":"ari.adrian.dev"}],
        });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri("/new-order")
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (_status, headers, _body_bytes) = send(router, req).await;
        let order_url = headers
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let order_id = order_url.rsplit('/').next().unwrap().to_string();
        let new_nonce = headers
            .get("Replay-Nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Finalize.
        let csr_der = make_csr_der();
        let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
        let protected = JwsProtectedHeader {
            alg: "ES256".into(),
            jwk: None,
            kid: Some(kid.clone()),
            nonce: new_nonce,
            url: format!("{}/order/{order_id}/finalize", server.state().base_url),
        };
        let payload = serde_json::json!({ "csr": csr_b64 });
        let body = sign_jws(&kp, &protected, &payload);
        let router = server.router();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/order/{order_id}/finalize"))
            .header("Content-Type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let (_status, _headers, _body_bytes) = send(router, req).await;

        // Query ARI with serial 1 (the first issued cert).
        let ari_router = server.ari_router();
        let req = Request::builder()
            .method("GET")
            .uri("/draft-ietf-acme-ari-03/renewal-info/1")
            .body(Body::empty())
            .unwrap();
        let (status, _headers, body_bytes) = send(ari_router, req).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(v["suggested_window"]["start"].is_string());
        assert!(v["suggested_window"]["end"].is_string());
    }

    /// ARI endpoint for a non-existent cert returns a window suggesting
    /// immediate renewal (RFC 8823 §4.2).
    #[tokio::test]
    async fn ari_returns_immediate_window_for_unknown_cert() {
        let server = AcmeServer::new("https://ca.example.com/acme").unwrap();
        let ari_router = server.ari_router();
        let req = Request::builder()
            .method("GET")
            .uri("/draft-ietf-acme-ari-03/renewal-info/999999")
            .body(Body::empty())
            .unwrap();
        let (status, _headers, body_bytes) = send(ari_router, req).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(v["suggested_window"]["start"].is_string());
        assert!(v["suggested_window"]["end"].is_string());
        // The start time should be recent (within the last minute).
        let start = v["suggested_window"]["start"].as_str().unwrap();
        let start_dt = chrono::DateTime::parse_from_rfc3339(start).unwrap();
        let now = chrono::Utc::now();
        let delta = (now - start_dt.with_timezone(&chrono::Utc))
            .num_seconds()
            .abs();
        assert!(
            delta < 120,
            "ARI window start should be recent (delta={delta}s)"
        );
    }
}
