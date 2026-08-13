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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-operator`. Per the task instructions these
    //! cover type construction (CRD spec), error types, serde round-trip of
    //! the `DomainController` CRD, and the loud-stub behaviour of
    //! `AdrianOperator::run` — no real `kube::Client` connection is made.

    use super::*;

    #[test]
    fn operator_error_variants_render_messages() {
        // Every `#[error("…")]` template must render — catches regressions
        // in the format strings used by the controller's event recorder
        // (ADR-058 reconcile status conditions).
        assert_eq!(
            OperatorError::Kube("api server unreachable".into()).to_string(),
            "kube: api server unreachable"
        );
        assert_eq!(
            OperatorError::Reconcile("statefulset rollout stuck".into()).to_string(),
            "reconcile: statefulset rollout stuck"
        );
        assert_eq!(
            OperatorError::CrdValidation("replicas must be > 0".into()).to_string(),
            "crd validation: replicas must be > 0"
        );
    }

    #[test]
    fn domain_controller_spec_constructs_with_expected_fields() {
        let spec = DomainControllerSpec {
            domain: "adrian.dev".into(),
            realm: "ADRIAN.DEV".into(),
            netbios_name: "ADRIAN".into(),
            replicas: 3,
            fdb_cluster: "adrian-fdb:4500".into(),
            features: vec!["kdc".into(), "ldap".into(), "smb".into()],
        };
        assert_eq!(spec.domain, "adrian.dev");
        assert_eq!(spec.realm, "ADRIAN.DEV");
        assert_eq!(spec.netbios_name, "ADRIAN");
        assert_eq!(spec.replicas, 3);
        assert_eq!(spec.fdb_cluster, "adrian-fdb:4500");
        assert_eq!(spec.features.len(), 3);
        assert_eq!(spec.features[0], "kdc");
    }

    #[test]
    fn domain_controller_spec_serde_round_trip_preserves_all_fields() {
        // The `DomainController` CRD spec must round-trip through serde
        // without loss — the operator's `kube::Api` reads/writes the spec
        // as JSON via `serde_json`, so any field drift between encode/decode
        // would silently corrupt the CRD persisted in etcd.
        let spec = DomainControllerSpec {
            domain: "adrian.dev".into(),
            realm: "ADRIAN.DEV".into(),
            netbios_name: "ADRIAN".into(),
            replicas: 5,
            fdb_cluster: "adrian-fdb-cluster:4500".into(),
            features: vec!["kdc".into(), "ldap".into(), "smb".into(), "print".into()],
        };
        let json = serde_json::to_string(&spec).expect("serialize spec");
        let back: DomainControllerSpec = serde_json::from_str(&json).expect("deserialize spec");
        assert_eq!(back.domain, spec.domain);
        assert_eq!(back.realm, spec.realm);
        assert_eq!(back.netbios_name, spec.netbios_name);
        assert_eq!(back.replicas, spec.replicas);
        assert_eq!(back.fdb_cluster, spec.fdb_cluster);
        assert_eq!(back.features, spec.features);
    }

    #[test]
    fn domain_controller_spec_serializes_to_expected_json_keys() {
        // The CRD field names are part of the operator's public API
        // (kubectl apply YAML). Verifying the JSON keys guards against
        // accidentally renaming a field without a serde `rename` attribute.
        let spec = DomainControllerSpec {
            domain: "d".into(),
            realm: "r".into(),
            netbios_name: "n".into(),
            replicas: 1,
            fdb_cluster: "f".into(),
            features: vec![],
        };
        let json = serde_json::to_value(&spec).expect("serialize spec");
        let obj = json
            .as_object()
            .expect("spec must serialize to a JSON object");
        for key in [
            "domain",
            "realm",
            "netbios_name",
            "replicas",
            "fdb_cluster",
            "features",
        ] {
            assert!(obj.contains_key(key), "spec JSON must contain key `{key}`");
        }
        assert_eq!(obj.len(), 6, "spec must have exactly 6 fields");
        // `replicas` is an i32 → JSON number, not a string.
        assert_eq!(obj.get("replicas").unwrap().as_i64(), Some(1));
    }

    #[test]
    fn run_stub_returns_reconcile_error() {
        // Loud-stub contract (ADR-058): until the CRD watch + reconcile
        // loop is implemented, `AdrianOperator::run` must surface
        // `OperatorError::Reconcile` rather than silently succeed or panic.
        let operator = AdrianOperator::new();
        let result = operator.run();
        // `run` is async — drive it on a minimal runtime. Using
        // `tokio::runtime::Runtime::new` here keeps the test self-contained
        // (no `#[tokio::test]` attribute needed, and no multi-thread pool
        // leak across the 5-test suite).
        let rt = tokio::runtime::Runtime::new().expect("build runtime");
        let err = rt
            .block_on(result)
            .expect_err("expected OperatorError::Reconcile");
        match err {
            OperatorError::Reconcile(msg) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            other => panic!("expected OperatorError::Reconcile, got {other:?}"),
        }
    }
}
