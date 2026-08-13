//! # adrian-operator
//!
//! Kubernetes operator — manages the `DomainController` CRD. Each CRD
//! instance reconciles to a StatefulSet pod running `adrian-dc`
//! (directory service + KDC + SMB + print). No primary/secondary semantics;
//! all DCs are stateless behind the FDB cluster (ADR-018, ADR-103).
//!
//! ## ADRs
//!
//! - ADR-058: Container-native DCs via operator
//! - ADR-018: KDC horizontal scaling (stateless pool)
//! - ADR-103: Keycloak StatefulSet (no primary/secondary)
//! - ADR-073: FoundationDB storage (operator deploys FDB sidecar)
//! - ADR-081: Multi-tenancy (per-tenant CRD namespace)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("kube: {0}")]
    Kube(String),
    #[error("reconcile: {0}")]
    Reconcile(String),
    #[error("crd validation: {0}")]
    CrdValidation(String),
}

/// `DomainController` CRD spec (sketch — full type derives CustomResource).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DomainControllerSpec {
    pub domain: String,
    pub realm: String,
    pub netbios_name: String,
    pub replicas: i32,
    pub fdb_cluster: String,
    pub features: Vec<String>,
}

/// Operator controller.
pub struct AdrianOperator {
    // TODO: hold kube::Client, CRD watch stream
}

impl AdrianOperator {
    pub fn new() -> Self {
        Self {}
    }

    /// Run the reconciliation loop until shutdown.
    pub async fn run(&self) -> Result<(), OperatorError> {
        // TODO: implement CRD watch + reconcile per ADR-058
        Err(OperatorError::Reconcile("not yet implemented".into()))
    }
}

impl Default for AdrianOperator {
    fn default() -> Self {
        Self::new()
    }
}
