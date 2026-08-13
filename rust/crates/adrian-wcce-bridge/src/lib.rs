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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-wcce-bridge`. Per the task instructions
    //! these cover type construction, enum variants, error types and the
    //! loud-stub behaviour of `WcceBridge::translate_request` — no real
    //! DCOM transport or ACME upstream.

    use super::*;

    #[test]
    fn wcce_request_type_variants_are_copy() {
        // `WcceRequestType` is `Copy + Debug + Clone` — the bridge copies
        // the request type into multiple translation paths, so removing
        // `Copy` would break call sites silently.
        let r = WcceRequestType::Ping;
        let _r2 = r; // copy
        let _r3 = r; // copy again — would fail without `Copy`
                     // Verify all four MS-WCCE §3.x variants exist.
        assert!(matches!(WcceRequestType::Ping, WcceRequestType::Ping));
        assert!(matches!(WcceRequestType::Request, WcceRequestType::Request));
        assert!(matches!(WcceRequestType::GetCert, WcceRequestType::GetCert));
        assert!(matches!(
            WcceRequestType::GetCaCert,
            WcceRequestType::GetCaCert
        ));
    }

    #[test]
    fn wcce_error_variants_render_messages() {
        // Each variant maps to a distinct HTTP/DCOM status once the
        // bridge is wired — verify the `#[error("…")]` templates render
        // so log lines stay parseable.
        assert_eq!(
            WcceError::Dcom("rpc timeout".into()).to_string(),
            "dcom: rpc timeout"
        );
        assert_eq!(
            WcceError::Acme("upstream 500".into()).to_string(),
            "acme upstream: upstream 500"
        );
        assert_eq!(
            WcceError::Translation("unknown template".into()).to_string(),
            "translation: unknown template"
        );
    }

    #[tokio::test]
    async fn bridge_default_equals_new() {
        // Both constructors must yield a usable bridge. Catches the
        // common regression of adding a field to `WcceBridge` and
        // forgetting to update `Default`. No `Debug`/`PartialEq` on
        // `WcceBridge` (TODO fields), so we exercise the seam via
        // `translate_request` — if either constructor dropped an init
        // step, this would surface a different error variant than
        // `Translation`.
        let a = WcceBridge::default();
        let b = WcceBridge::new();
        let ea = a
            .translate_request(WcceRequestType::Request, &[])
            .await
            .unwrap_err();
        let eb = b
            .translate_request(WcceRequestType::Request, &[])
            .await
            .unwrap_err();
        assert!(matches!(ea, WcceError::Translation(_)));
        assert!(matches!(eb, WcceError::Translation(_)));
    }

    #[tokio::test]
    async fn translate_request_stub_returns_translation_error() {
        // Loud-stub contract: until MS-WCCE → ACME translation lands
        // (ADR-095 TODO), `translate_request` must surface
        // `WcceError::Translation` for every request type rather than
        // panic — this guards the seam for the Wave 4c integration.
        let bridge = WcceBridge::new();
        for req in [
            WcceRequestType::Ping,
            WcceRequestType::Request,
            WcceRequestType::GetCert,
            WcceRequestType::GetCaCert,
        ] {
            let err = bridge.translate_request(req, &[]).await.unwrap_err();
            assert!(matches!(err, WcceError::Translation(_)));
            assert!(err.to_string().contains("not yet implemented"));
        }
    }
}
