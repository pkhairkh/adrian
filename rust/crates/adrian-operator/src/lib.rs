#![forbid(unsafe_code)]
//! # adrian-operator
//!
//! Kubernetes operator — manages the `DomainController` CRD. Each CRD
//! instance reconciles to a StatefulSet pod running `adrian-dc`
//! (directory service + KDC + SMB + print). No primary/secondary
//! semantics; all DCs are stateless behind the FDB cluster (ADR-018,
//! ADR-103).
//!
//! ## ADRs
//!
//! - ADR-058: Container-native DCs via operator
//! - ADR-018: KDC horizontal scaling (stateless pool)
//! - ADR-103: Keycloak StatefulSet (no primary/secondary)
//! - ADR-073: FoundationDB storage (operator deploys FDB sidecar)
//! - ADR-081: Multi-tenancy (per-tenant CRD namespace)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

// ===========================================================================
// Legacy CRD spec (backward-compat with Wave 4c tests).
// ===========================================================================

/// `DomainController` CRD spec (sketch — full type derives CustomResource).
///
/// **Deprecated** in favour of [`DcSpec`] (per the Wave 5b task spec).
/// Retained so existing callers (Wave 4c tests) continue to compile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainControllerSpec {
    pub domain: String,
    pub realm: String,
    pub netbios_name: String,
    pub replicas: i32,
    pub fdb_cluster: String,
    pub features: Vec<String>,
}

// ===========================================================================
// New CRD types (Wave 5b — ADR-058 §Decision).
// ===========================================================================

/// Kubernetes-standard `ObjectMeta` (minimal subset — name, namespace,
/// labels, annotations). The full `k8s-openapi` type is more complex; this
/// subset covers the operator's YAML-generation needs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// Kubernetes resource name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Kubernetes namespace (defaults to "default" if omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Resource labels.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
    /// Resource annotations.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

/// The `DomainController` CRD spec — what the operator reconciles against.
/// Per ADR-058 §Decision: `spec.replicas`, `spec.domainDN`,
/// `spec.krbtgtHsmKeyId`, `spec.fdbClusterFile`, `spec.image`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DcSpec {
    /// Number of DC replicas to run.
    pub replicas: u32,
    /// Domain DN, e.g. `DC=adrian,DC=dev`.
    pub domain_dn: String,
    /// HSM key ID for the krbtgt account (ADR-065).
    pub krbtgt_hsm_key_id: String,
    /// FoundationDB cluster file path (ADR-073).
    pub fdb_cluster_file: String,
    /// Container image reference, e.g. `ghcr.io/adrian/dc:0.1.0`.
    pub image: String,
}

/// The `DomainController` CRD status — reported back by the operator after
/// each reconcile pass. Per ADR-058 §Decision: `status.replicas`,
/// `status.readyReplicas` (encoded as `ready: bool` here for simplicity),
/// `status.conditions`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DcStatus {
    /// True iff all replicas are Ready.
    pub ready: bool,
    /// Current observed replica count.
    pub replicas: u32,
    /// Kubernetes-standard status conditions.
    pub conditions: Vec<Condition>,
}

/// Kubernetes-standard `Condition` type (meta/v1).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Condition type, e.g. `Ready`, `Promoted`, `SchemaUpgraded`.
    #[serde(rename = "type")]
    pub type_: String,
    /// Condition status — `True`, `False`, or `Unknown`.
    pub status: String,
    /// Machine-readable reason (PascalCase, e.g. `AllReplicasReady`).
    pub reason: String,
    /// Human-readable message.
    pub message: String,
    /// Last transition timestamp.
    pub last_transition_time: DateTime<Utc>,
}

/// A complete `DomainController` CRD instance — the persisted intent +
/// observed status. Serialized as YAML for `kubectl apply`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainControllerCrd {
    /// API version — `"adrian.io/v1"`.
    pub api_version: String,
    /// Kind — `"DomainController"`.
    pub kind: String,
    /// Standard Kubernetes object metadata.
    pub metadata: ObjectMeta,
    /// The CRD spec (intent).
    pub spec: DcSpec,
    /// The CRD status (observed by the operator).
    #[serde(default)]
    pub status: DcStatus,
}

impl DomainControllerCrd {
    /// Construct a CRD instance with a default (empty) status.
    pub fn new(metadata: ObjectMeta, spec: DcSpec) -> Self {
        Self {
            api_version: "adrian.io/v1".to_string(),
            kind: "DomainController".to_string(),
            metadata,
            spec,
            status: DcStatus::default(),
        }
    }
}

/// Serialise a [`DomainControllerCrd`] to a `serde_json::Value`. The value
/// can then be converted to YAML (via `serde_yaml`) for `kubectl apply`.
pub fn serialize_crd(crd: &DomainControllerCrd) -> serde_json::Value {
    serde_json::to_value(crd).expect("CRD serialization should not fail")
}

/// Generate the `CustomResourceDefinition` YAML for the
/// `DomainController` CRD — the cluster-level object that registers the
/// CRD with the Kubernetes API server.
pub fn crd_definition() -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": "domaincontrollers.adrian.io"
        },
        "spec": {
            "group": "adrian.io",
            "names": {
                "kind": "DomainController",
                "plural": "domaincontrollers",
                "singular": "domaincontroller",
                "shortNames": ["dc", "dcs"]
            },
            "scope": "Namespaced",
            "versions": [{
                "name": "v1",
                "served": true,
                "storage": true,
                "schema": {
                    "openAPIV3Schema": {
                        "type": "object",
                        "properties": {
                            "spec": {
                                "type": "object",
                                "required": ["replicas", "domainDn", "krbtgtHsmKeyId", "fdbClusterFile", "image"],
                                "properties": {
                                    "replicas": {"type": "integer", "minimum": 1, "format": "int32"},
                                    "domainDn": {"type": "string"},
                                    "krbtgtHsmKeyId": {"type": "string"},
                                    "fdbClusterFile": {"type": "string"},
                                    "image": {"type": "string"}
                                }
                            },
                            "status": {
                                "type": "object",
                                "properties": {
                                    "ready": {"type": "boolean"},
                                    "replicas": {"type": "integer"},
                                    "conditions": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "type": {"type": "string"},
                                                "status": {"type": "string"},
                                                "reason": {"type": "string"},
                                                "message": {"type": "string"},
                                                "lastTransitionTime": {"type": "string", "format": "date-time"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }]
        }
    })
}

/// Generate the StatefulSet YAML for a given [`DcSpec`]. Per ADR-058
/// §Decision: `volumeClaimTemplates` with `accessModes: [ReadWriteOnce]`,
/// `storageClassName: <fast-ssd>`, `resources.requests.storage: 50Gi`;
/// `livenessProbe` on TCP/389 (LDAP), `readinessProbe` on TCP/88 (Kerberos),
/// `startupProbe` on TCP/389.
pub fn generate_statefulset(spec: &DcSpec) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "adrian-dc",
            "labels": {"app.kubernetes.io/name": "adrian-dc"}
        },
        "spec": {
            "replicas": spec.replicas,
            "serviceName": "adrian-dc",
            "selector": {
                "matchLabels": {"app.kubernetes.io/name": "adrian-dc"}
            },
            "template": {
                "metadata": {
                    "labels": {"app.kubernetes.io/name": "adrian-dc"}
                },
                "spec": {
                    "securityContext": {
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001
                    },
                    "containers": [{
                        "name": "adrian-dc",
                        "image": spec.image,
                        "ports": [
                            {"name": "ldap", "containerPort": 389},
                            {"name": "ldaps", "containerPort": 636},
                            {"name": "kerberos", "containerPort": 88},
                            {"name": "kpasswd", "containerPort": 464},
                            {"name": "dns", "containerPort": 53},
                            {"name": "smb", "containerPort": 445},
                            {"name": "metrics", "containerPort": 9100}
                        ],
                        "env": [
                            {"name": "ADRIAN_DOMAIN_DN", "value": spec.domain_dn},
                            {"name": "ADRIAN_KRBTGT_HSM_KEY_ID", "value": spec.krbtgt_hsm_key_id},
                            {"name": "ADRIAN_FDB_CLUSTER_FILE", "value": spec.fdb_cluster_file}
                        ],
                        "volumeMounts": [
                            {"name": "dit", "mountPath": "/var/lib/adrian/dit"},
                            {"name": "fdb-cluster", "mountPath": "/etc/foundationdb", "readOnly": true}
                        ],
                        "livenessProbe": {
                            "tcpSocket": {"port": "ldap"},
                            "initialDelaySeconds": 30,
                            "periodSeconds": 10,
                            "failureThreshold": 6
                        },
                        "readinessProbe": {
                            "tcpSocket": {"port": "kerberos"},
                            "periodSeconds": 5
                        },
                        "startupProbe": {
                            "tcpSocket": {"port": "ldap"},
                            "failureThreshold": 30,
                            "periodSeconds": 10
                        }
                    }]
                }
            },
            "volumeClaimTemplates": [{
                "name": "dit",
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": "fast-ssd",
                    "resources": {"requests": {"storage": "50Gi"}}
                }
            }]
        }
    })
}

/// A Helm chart — `Chart.yaml`, `values.yaml`, and a list of
/// `(template_path, template_content)` tuples. Generated by
/// [`generate_helm_chart`] for ad-hoc `helm template` runs.
pub struct HelmChart {
    /// `Chart.yaml` content.
    pub chart_yaml: String,
    /// `values.yaml` content.
    pub values_yaml: String,
    /// `(template_path, template_content)` tuples, e.g.
    /// `("templates/statefulset.yaml", "...")`.
    pub templates: Vec<(String, String)>,
}

/// Generate a Helm chart for a given [`DcSpec`]. The chart contains:
/// - `Chart.yaml` — chart metadata.
/// - `values.yaml` — default values for `domainDn`, `replicas`, `image`.
/// - `templates/statefulset.yaml` — the StatefulSet (from
///   [`generate_statefulset`]).
/// - `templates/crd.yaml` — the CustomResourceDefinition (from
///   [`crd_definition`]).
/// - `templates/service.yaml` — a headless Service for the StatefulSet.
pub fn generate_helm_chart(spec: &DcSpec) -> HelmChart {
    let chart_yaml = r#"apiVersion: v2
name: adrian-dc
description: Adrian DomainController Helm chart (ADR-058)
type: application
version: 0.1.0
appVersion: "0.1.0"
"#
    .to_string();
    let values_yaml = format!(
        r#"# Default values for adrian-dc (ADR-058).
replicas: {replicas}
domainDn: "{domain_dn}"
krbtgtHsmKeyId: "{krbtgt_hsm_key_id}"
fdbClusterFile: "{fdb_cluster_file}"
image: "{image}"
"#,
        replicas = spec.replicas,
        domain_dn = spec.domain_dn,
        krbtgt_hsm_key_id = spec.krbtgt_hsm_key_id,
        fdb_cluster_file = spec.fdb_cluster_file,
        image = spec.image,
    );
    // Render the StatefulSet + CRD + Service as YAML strings (pretty).
    let statefulset_yaml =
        serde_yaml::to_string(&generate_statefulset(spec)).unwrap_or_else(|e| format!("# error: {e}"));
    let crd_yaml =
        serde_yaml::to_string(&crd_definition()).unwrap_or_else(|e| format!("# error: {e}"));
    let service_yaml = r#"apiVersion: v1
kind: Service
metadata:
  name: adrian-dc
  labels:
    app.kubernetes.io/name: adrian-dc
spec:
  clusterIP: None
  selector:
    app.kubernetes.io/name: adrian-dc
  ports:
  - name: ldap
    port: 389
  - name: kerberos
    port: 88
  - name: metrics
    port: 9100
"#;
    let templates = vec![
        ("templates/statefulset.yaml".to_string(), statefulset_yaml),
        ("templates/crd.yaml".to_string(), crd_yaml),
        ("templates/service.yaml".to_string(), service_yaml.to_string()),
    ];
    HelmChart {
        chart_yaml,
        values_yaml,
        templates,
    }
}

// ===========================================================================
// Operator controller
// ===========================================================================

/// Operator controller.
///
/// **Loud stub** — the operator's reconcile loop is not yet wired to a
/// `kube::Client`. Per the Wave 5b task spec, the CRD / StatefulSet /
/// Helm generation functions ARE implemented; the actual watch-loop that
/// subscribes to CRD changes and drives reconciliation is deferred to a
/// future wave (it requires a running Kubernetes API server for
/// integration tests).
pub struct AdrianOperator {
    // Held empty intentionally — once the reconcile loop is wired, this
    // will hold `kube::Client` + the CRD watch stream. For now, the
    // CRD-generation surface (above) is what callers consume.
}

impl AdrianOperator {
    pub fn new() -> Self {
        Self {}
    }

    /// Run the reconciliation loop until shutdown.
    ///
    /// **Loud stub** — until the CRD watch + reconcile loop is wired to
    /// a `kube::Client`, this returns `OperatorError::Reconcile("not yet
    /// implemented")` so callers see the explicit "framework not yet
    /// implemented" signal. CRD / StatefulSet / Helm generation are
    /// implemented as standalone functions (see [`serialize_crd`],
    /// [`generate_statefulset`], [`generate_helm_chart`]).
    pub async fn run(&self) -> Result<(), OperatorError> {
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
    //! Unit tests for `adrian-operator`. Cover type construction (CRD
    //! spec), error types, serde round-trip of the `DomainController`
    //! CRD, the loud-stub behaviour of `AdrianOperator::run`, plus the
    //! new Wave 5b CRD / StatefulSet / Helm chart generation surface.

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
        // The CRD / StatefulSet / Helm generation surface IS implemented
        // as standalone functions; only the watch-loop is deferred.
        let operator = AdrianOperator::new();
        let result = operator.run();
        // `run` is async — drive it on a minimal runtime. Using
        // `tokio::runtime::Runtime::new` here keeps the test self-contained
        // (no `#[tokio::test]` attribute needed, and no multi-thread pool
        // leak across the test suite).
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

    // ========================================================================
    // New tests — Wave 5b CRD / StatefulSet / Helm chart generation.
    // ========================================================================

    #[test]
    fn dc_spec_constructs_with_expected_fields() {
        // The new `DcSpec` (per the Wave 5b task spec) — verify the field
        // set matches ADR-058 §Decision: replicas, domainDN,
        // krbtgtHsmKeyId, fdbClusterFile, image.
        let spec = DcSpec {
            replicas: 3,
            domain_dn: "DC=adrian,DC=dev".into(),
            krbtgt_hsm_key_id: "hsm:key/krbtgt:1".into(),
            fdb_cluster_file: "/etc/foundationdb/fdb.cluster".into(),
            image: "ghcr.io/adrian/dc:0.1.0".into(),
        };
        assert_eq!(spec.replicas, 3);
        assert_eq!(spec.domain_dn, "DC=adrian,DC=dev");
        assert_eq!(spec.krbtgt_hsm_key_id, "hsm:key/krbtgt:1");
        assert_eq!(spec.fdb_cluster_file, "/etc/foundationdb/fdb.cluster");
        assert_eq!(spec.image, "ghcr.io/adrian/dc:0.1.0");
    }

    #[test]
    fn serialize_crd_round_trips_through_serde() {
        // `serialize_crd` returns a `serde_json::Value`; round-tripping
        // through `DomainControllerCrd` must preserve all fields. This
        // is the same contract the operator's `kube::Api` relies on when
        // it serialises/deserialises the CRD to/from etcd.
        let spec = DcSpec {
            replicas: 5,
            domain_dn: "DC=adrian,DC=dev".into(),
            krbtgt_hsm_key_id: "hsm:key/krbtgt:2".into(),
            fdb_cluster_file: "/etc/foundationdb/fdb.cluster".into(),
            image: "ghcr.io/adrian/dc:0.1.0".into(),
        };
        let crd = DomainControllerCrd::new(
            ObjectMeta {
                name: Some("adrian-dc".into()),
                namespace: Some("adrian".into()),
                ..Default::default()
            },
            spec,
        );
        let value = serialize_crd(&crd);
        // Verify the top-level fields are present with the expected keys.
        assert_eq!(value.get("apiVersion").and_then(|v| v.as_str()), Some("adrian.io/v1"));
        assert_eq!(value.get("kind").and_then(|v| v.as_str()), Some("DomainController"));
        assert_eq!(
            value.get("metadata").and_then(|v| v.get("name")).and_then(|v| v.as_str()),
            Some("adrian-dc")
        );
        // Verify the spec round-trips.
        let back: DomainControllerCrd =
            serde_json::from_value(value).expect("deserialize round-trip should succeed");
        assert_eq!(back.api_version, "adrian.io/v1");
        assert_eq!(back.kind, "DomainController");
        assert_eq!(back.spec.replicas, 5);
        assert_eq!(back.spec.domain_dn, "DC=adrian,DC=dev");
        assert_eq!(back.metadata.name.as_deref(), Some("adrian-dc"));
    }

    #[test]
    fn crd_definition_registers_with_apiextensions() {
        // `crd_definition()` returns the cluster-level
        // CustomResourceDefinition that registers the CRD with the
        // Kubernetes API server. Verify the schema is well-formed.
        let def = crd_definition();
        assert_eq!(def.get("apiVersion").and_then(|v| v.as_str()), Some("apiextensions.k8s.io/v1"));
        assert_eq!(def.get("kind").and_then(|v| v.as_str()), Some("CustomResourceDefinition"));
        assert_eq!(
            def.get("metadata")
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str()),
            Some("domaincontrollers.adrian.io")
        );
        // Verify the spec group / names / scope / versions are present.
        let spec = def.get("spec").expect("CRD spec must be present");
        assert_eq!(spec.get("group").and_then(|v| v.as_str()), Some("adrian.io"));
        assert_eq!(spec.get("scope").and_then(|v| v.as_str()), Some("Namespaced"));
        let names = spec.get("names").expect("CRD names must be present");
        assert_eq!(names.get("kind").and_then(|v| v.as_str()), Some("DomainController"));
        assert_eq!(names.get("plural").and_then(|v| v.as_str()), Some("domaincontrollers"));
        // Verify the openAPIV3Schema includes the spec fields.
        let schema = spec
            .get("versions")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("schema"))
            .and_then(|v| v.get("openAPIV3Schema"))
            .and_then(|v| v.get("properties"))
            .and_then(|v| v.get("spec"))
            .and_then(|v| v.get("properties"))
            .expect("openAPIV3Schema.spec.properties must be present");
        for key in ["replicas", "domainDn", "krbtgtHsmKeyId", "fdbClusterFile", "image"] {
            assert!(schema.get(key).is_some(), "openAPIV3Schema must include `{key}`");
        }
    }

    #[test]
    fn generate_statefulset_includes_fdb_cluster_file_and_pvc() {
        // The StatefulSet MUST include the FDB cluster file as an env var
        // (per ADR-058 §Decision: FDB sidecar shares the cluster file via
        // configmap — encoded here as an env var for simplicity).
        let spec = DcSpec {
            replicas: 3,
            domain_dn: "DC=adrian,DC=dev".into(),
            krbtgt_hsm_key_id: "hsm:key/krbtgt:1".into(),
            fdb_cluster_file: "/etc/foundationdb/fdb.cluster".into(),
            image: "ghcr.io/adrian/dc:0.1.0".into(),
        };
        let ss = generate_statefulset(&spec);
        // Verify replicas + image are propagated from the spec.
        assert_eq!(
            ss.get("spec")
                .and_then(|v| v.get("replicas"))
                .and_then(|v| v.as_u64()),
            Some(3)
        );
        assert_eq!(
            ss.get("spec")
                .and_then(|v| v.get("template"))
                .and_then(|v| v.get("spec"))
                .and_then(|v| v.get("containers"))
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.get("image"))
                .and_then(|v| v.as_str()),
            Some("ghcr.io/adrian/dc:0.1.0")
        );
        // Verify the FDB cluster file env var is wired.
        let env = ss
            .get("spec")
            .and_then(|v| v.get("template"))
            .and_then(|v| v.get("spec"))
            .and_then(|v| v.get("containers"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("env"))
            .and_then(|v| v.as_array())
            .expect("env array must be present");
        let fdb_env = env.iter().find(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("ADRIAN_FDB_CLUSTER_FILE")
        });
        let fdb_env = fdb_env.expect("ADRIAN_FDB_CLUSTER_FILE env var must be present");
        assert_eq!(
            fdb_env.get("value").and_then(|v| v.as_str()),
            Some("/etc/foundationdb/fdb.cluster")
        );
        // Verify the volumeClaimTemplates include a 50Gi PVC (ADR-058).
        let vol_claims = ss
            .get("spec")
            .and_then(|v| v.get("volumeClaimTemplates"))
            .and_then(|v| v.as_array())
            .expect("volumeClaimTemplates must be present");
        assert_eq!(vol_claims.len(), 1, "exactly one PVC template expected");
        let pvc = &vol_claims[0];
        assert_eq!(pvc.get("name").and_then(|v| v.as_str()), Some("dit"));
        let access_modes = pvc
            .get("spec")
            .and_then(|v| v.get("accessModes"))
            .and_then(|v| v.as_array())
            .expect("accessModes must be present");
        assert_eq!(access_modes.len(), 1);
        assert_eq!(access_modes[0].as_str(), Some("ReadWriteOnce"));
        // Verify the liveness/readiness/startup probes (ADR-058 §Decision).
        let container = ss
            .get("spec")
            .and_then(|v| v.get("template"))
            .and_then(|v| v.get("spec"))
            .and_then(|v| v.get("containers"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .expect("container must be present");
        assert!(container.get("livenessProbe").is_some(), "livenessProbe required");
        assert!(container.get("readinessProbe").is_some(), "readinessProbe required");
        assert!(container.get("startupProbe").is_some(), "startupProbe required");
    }

    #[test]
    fn generate_helm_chart_produces_valid_files() {
        // The Helm chart MUST contain Chart.yaml, values.yaml, and at
        // least the StatefulSet + CRD + Service templates. Each template
        // MUST be valid YAML (parseable by `serde_yaml`).
        let spec = DcSpec {
            replicas: 3,
            domain_dn: "DC=adrian,DC=dev".into(),
            krbtgt_hsm_key_id: "hsm:key/krbtgt:1".into(),
            fdb_cluster_file: "/etc/foundationdb/fdb.cluster".into(),
            image: "ghcr.io/adrian/dc:0.1.0".into(),
        };
        let chart = generate_helm_chart(&spec);
        // Chart.yaml must contain the chart name + version.
        assert!(chart.chart_yaml.contains("name: adrian-dc"), "Chart.yaml must contain name");
        assert!(chart.chart_yaml.contains("apiVersion: v2"), "Chart.yaml must contain apiVersion");
        // values.yaml must contain the spec values.
        assert!(
            chart.values_yaml.contains("replicas: 3"),
            "values.yaml must contain replicas: {values}",
            values = chart.values_yaml
        );
        assert!(
            chart.values_yaml.contains("DC=adrian,DC=dev"),
            "values.yaml must contain domainDn"
        );
        // Templates: exactly 3 (statefulset, crd, service).
        assert_eq!(chart.templates.len(), 3, "expected 3 templates");
        let template_names: Vec<&str> =
            chart.templates.iter().map(|(n, _)| n.as_str()).collect();
        assert!(template_names.contains(&"templates/statefulset.yaml"));
        assert!(template_names.contains(&"templates/crd.yaml"));
        assert!(template_names.contains(&"templates/service.yaml"));
        // Each template must be valid YAML (parseable).
        for (name, content) in &chart.templates {
            let parsed: Result<serde_json::Value, _> = serde_yaml::from_str(content);
            assert!(
                parsed.is_ok(),
                "template `{name}` must be valid YAML: {content}"
            );
        }
    }

    #[test]
    fn condition_serializes_to_kubernetes_format() {
        // The `Condition` type MUST serialize with `type` (not `type_`)
        // and a `lastTransitionTime` in RFC 3339 format — this is the
        // format the Kubernetes API server expects.
        let condition = Condition {
            type_: "Ready".to_string(),
            status: "True".to_string(),
            reason: "AllReplicasReady".to_string(),
            message: "All replicas are ready".to_string(),
            last_transition_time: Utc::now(),
        };
        let json = serde_json::to_value(&condition).expect("serialize condition");
        // `type_` field is renamed to `type` via serde rename.
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("Ready"));
        assert_eq!(json.get("status").and_then(|v| v.as_str()), Some("True"));
        assert_eq!(json.get("reason").and_then(|v| v.as_str()), Some("AllReplicasReady"));
        // lastTransitionTime must be a string (RFC 3339 date-time).
        let ltt = json
            .get("lastTransitionTime")
            .and_then(|v| v.as_str())
            .expect("lastTransitionTime must be present");
        assert!(ltt.contains('T'), "lastTransitionTime must be RFC 3339: {ltt}");
        // Must NOT contain `type_` (the Rust field name) — serde renamed it.
        let json_str = serde_json::to_string(&condition).expect("serialize condition");
        assert!(
            !json_str.contains("type_"),
            "condition must NOT serialize `type_` as `type_`: {json_str}"
        );
    }
}
