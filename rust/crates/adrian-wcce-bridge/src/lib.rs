//! # adrian-wcce-bridge
//!
//! MS-WCCE → ACME translation. Lets Windows autoenroll (certreq.exe,
//! autoenrollment.dll) keep working against the framework CA in AD-interop
//! mode by translating MS-WCCE DCOM calls into ACME orders.
//!
//! Gated by `ad-interop` feature flag.
//!
//! ## ADRs
//!
//! - ADR-095: ACME primary; MS-WCCE bridge for AD-interop
//! - ADR-097: Cross-platform autoenroll via ACME
//! - ADR-098: NDES/SCEP replacement bridge
//! - ADR-099: NTAUTHCertificates + PKINIT trust

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// MS-WCCE bridge error.
#[derive(Debug, Error)]
pub enum WcceError {
    /// DCOM transport error.
    #[error("dcom: {0}")]
    Dcom(String),
    /// ACME upstream error.
    #[error("acme upstream: {0}")]
    Acme(String),
    /// Translation error.
    #[error("translation: {0}")]
    Translation(String),
}

/// MS-WCCE request type (MS-WCCE §3.x).
#[derive(Debug, Clone, Copy)]
pub enum WcceRequestType {
    /// `CertServerRequest` Ping.
    Ping,
    /// `CertServerRequest` Request.
    Request,
    /// `CertServerRequest` GetCert.
    GetCert,
    /// `CertServerRequest` GetCACert.
    GetCaCert,
}

/// Bridge that accepts MS-WCCE DCOM calls and forwards as ACME orders.
pub struct WcceBridge {
    // TODO: hold Arc<AcmeServer>.
}

impl WcceBridge {
    /// Construct a new bridge.
    pub fn new() -> Self {
        Self {}
    }

    /// Translate a MS-WCCE Request into an ACME order.
    pub async fn translate_request(
        &self,
        _wcce_req: WcceRequestType,
        _csr_der: &[u8],
    ) -> Result<Vec<u8>, WcceError> {
        // TODO: implement MS-WCCE → ACME translation per ADR-095.
        Err(WcceError::Translation(
            "MS-WCCE → ACME translation not yet implemented".into(),
        ))
    }
}

impl Default for WcceBridge {
    fn default() -> Self {
        Self::new()
    }
}
