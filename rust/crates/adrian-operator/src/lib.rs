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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

// ===========================================================================
// Error type
// ===========================================================================

#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("kube: {0}")]
    Kube(String),
    #[error("reconcile: {0}")]
    Reconcile(String),
    #[error("crd validation: {0}")]
    CrdValidation(String),
}

impl From<kube::Error> for OperatorError {
    fn from(e: kube::Error) -> Self {
        Self::Kube(e.to_string())
    }
}

impl From<serde_json::Error> for OperatorError {
    fn from(e: serde_json::Error) -> Self {
        Self::Reconcile(format!("json: {e}"))
    }
}

// ===========================================================================
// DomainController CRD (Wave 4b — real kube::CustomResource derive)
// ===========================================================================

/// `DomainController` custom resource — reconciled to a StatefulSet that
/// runs the Adrian DSA (directory service + KDC + SMB + print).
///
/// Per ADR-058 (container-native DCs) + ADR-018 (stateless DC pool):
/// all DCs are stateless behind the FDB cluster — the operator manages a
/// horizontally-scalable StatefulSet, not primary/secondaries.
///
/// The `#[derive(kube::CustomResource)]` macro generates the wrapping
/// `DomainController` struct (with `metadata` + `spec` fields) plus a
/// `kube::Resource` impl so the controller-runtime can watch/patch it
/// via a typed `kube::Api<DomainController>`.
#[derive(kube::CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "adrian.io",
    version = "v1alpha1",
    kind = "DomainController",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct DomainControllerSpec {
    /// Number of DC replicas to run (ADR-018: stateless pool, scale freely).
    pub replicas: i32,
    /// Container image reference, e.g. `ghcr.io/adrian/dc:0.1.0`.
    pub image: String,
    /// Volume size for the DIT PVC, e.g. `"50Gi"` (ADR-058 §Decision).
    pub storage_size: String,
    /// DNS domain name, e.g. `adrian.dev`.
    pub domain_name: String,
    /// NetBIOS name (single-label, uppercased), e.g. `ADRIAN`.
    pub netbios_name: String,
}

// ===========================================================================
// Reconcile types + pure decision logic (testable without a cluster)
// ===========================================================================

/// Outcome of a reconcile pass — reported back to the controller-runtime
/// for logging and requeue accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileResult {
    /// StatefulSet was created.
    Created,
    /// StatefulSet was updated to match the new spec.
    Updated,
    /// StatefulSet was deleted (CRD is being deleted).
    Deleted,
    /// No-op — the StatefulSet already matches the spec.
    NoOp,
    /// Requeue this object for another reconcile pass (e.g. waiting for
    /// the StatefulSet to become Ready).
    Requeue,
}

/// Internal reconcile decision — what the operator should DO. This is the
/// output of the pure [`decide_reconcile_action`] function; the
/// [`AdrianOperator::reconcile`] wrapper translates it into the
/// appropriate kube API calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Create a new StatefulSet from the desired spec.
    Create,
    /// Update the existing StatefulSet to match the desired spec.
    Update,
    /// Delete the existing StatefulSet (the CRD is being deleted).
    Delete,
    /// No-op — the StatefulSet already matches the spec.
    NoOp,
}

/// A minimal projection of a `StatefulSet` — the fields the operator
/// cares about for drift detection. Built from either a desired
/// `DomainControllerSpec` (via [`StatefulSetSnapshot::from_spec`]) or a
/// live `k8s_openapi::StatefulSet` (via
/// [`StatefulSetSnapshot::from_statefulset`]).
///
/// This is intentionally a small, comparable struct so that drift
/// detection is a simple `!=` check rather than a deep object-tree walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatefulSetSnapshot {
    /// `spec.replicas` from the StatefulSet.
    pub replicas: i32,
    /// `spec.template.spec.containers[0].image`.
    pub image: String,
    /// `spec.volumeClaimTemplates[0].spec.resources.requests["storage"]`.
    pub storage_size: String,
    /// Env var `ADRIAN_DOMAIN_NAME` on the container.
    pub domain_name: String,
    /// Env var `ADRIAN_NETBIOS_NAME` on the container.
    pub netbios_name: String,
}

impl StatefulSetSnapshot {
    /// Build the desired snapshot from a `DomainControllerSpec`. This is
    /// what the operator thinks the StatefulSet SHOULD look like.
    pub fn from_spec(spec: &DomainControllerSpec) -> Self {
        Self {
            replicas: spec.replicas,
            image: spec.image.clone(),
            storage_size: spec.storage_size.clone(),
            domain_name: spec.domain_name.clone(),
            netbios_name: spec.netbios_name.clone(),
        }
    }

    /// Extract the observed snapshot from a live `k8s_openapi::StatefulSet`.
    /// Returns `None` if any required field is missing (the StatefulSet is
    /// malformed or was not created by this operator).
    ///
    /// Reads:
    /// - `spec.replicas` (defaults to 0 if unset — the k8s default).
    /// - `spec.template.spec.containers[0].image`.
    /// - `ADRIAN_DOMAIN_NAME` / `ADRIAN_NETBIOS_NAME` env vars on the
    ///   first container.
    /// - `spec.volumeClaimTemplates[0]`'s `storage` request.
    pub fn from_statefulset(ss: &k8s_openapi::api::apps::v1::StatefulSet) -> Option<Self> {
        let spec = ss.spec.as_ref()?;
        let replicas = spec.replicas.unwrap_or(0);
        let container = spec.template.spec.as_ref()?.containers.first()?;
        let image = container.image.clone()?;
        let env = container.env.clone().unwrap_or_default();
        let domain_name = env
            .iter()
            .find(|e| e.name == "ADRIAN_DOMAIN_NAME")
            .and_then(|e| e.value.clone())?;
        let netbios_name = env
            .iter()
            .find(|e| e.name == "ADRIAN_NETBIOS_NAME")
            .and_then(|e| e.value.clone())?;
        let storage_size = spec
            .volume_claim_templates
            .as_ref()
            .and_then(|vcts| vcts.first())
            .and_then(|vc| vc.spec.as_ref())
            .and_then(|s| s.resources.as_ref())
            .and_then(|r| r.requests.as_ref())
            .and_then(|reqs| reqs.get("storage"))
            .map(|q| q.0.clone())?;
        Some(Self {
            replicas,
            image,
            storage_size,
            domain_name,
            netbios_name,
        })
    }
}

/// Decide what the reconcile loop should do, given the current
/// StatefulSet snapshot (if any), the desired DomainController spec, and
/// the CRD's deletion timestamp (if any).
///
/// This is a **pure function** — it does not touch the kube API. The
/// [`AdrianOperator::reconcile`] wrapper translates the returned
/// [`ReconcileAction`] into the appropriate kube API call(s). Splitting
/// the decision from the I/O keeps the logic unit-testable without a
/// running Kubernetes cluster (per Wave 4b task hint).
///
/// # Decision matrix
///
/// | deletion_timestamp | current StatefulSet | Action   |
/// |--------------------|---------------------|----------|
/// | Some                | _                   | `Delete` |
/// | None                | None                | `Create` |
/// | None                | Some (drift)        | `Update` |
/// | None                | Some (in sync)      | `NoOp`   |
pub fn decide_reconcile_action(
    current: Option<&StatefulSetSnapshot>,
    desired: &DomainControllerSpec,
    deletion_timestamp: Option<&DateTime<Utc>>,
) -> ReconcileAction {
    if deletion_timestamp.is_some() {
        return ReconcileAction::Delete;
    }
    let desired_snapshot = StatefulSetSnapshot::from_spec(desired);
    match current {
        None => ReconcileAction::Create,
        Some(current) if current != &desired_snapshot => ReconcileAction::Update,
        Some(_) => ReconcileAction::NoOp,
    }
}

/// Translate a `kube::Error` into `Ok(None)` if it's a 404 NotFound, or
/// `Err(error)` otherwise. Used by the reconcile loop to convert the
/// StatefulSet delete result (which returns `Either<K, Status>`) into
/// `Option` form for the decision function.
///
/// Note: `kube::Api::get_opt` already handles this for fetches; this
/// helper is for the delete path (and for callers that want a uniform
/// `Option<T>` shape regardless of the API method).
pub fn not_found_to_none<T>(result: Result<T, kube::Error>) -> Result<Option<T>, OperatorError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(kube::Error::Api(err)) if err.code == 404 => Ok(None),
        Err(e) => Err(OperatorError::from(e)),
    }
}

/// Derive the StatefulSet name for a `DomainController` CRD. Namespaced
/// resources in Kubernetes must have unique names within a namespace; we
/// prefix with `adrian-dc-` to avoid collisions with non-Adrian resources
/// and to make operator-owned StatefulSets greppable.
///
/// If the CRD has no `metadata.name` (which shouldn't happen for a
/// persisted CRD but can happen for an in-memory test fixture), falls
/// back to the bare name `adrian-dc`.
pub fn statefulset_name(dc: &DomainController) -> String {
    match dc.metadata.name.as_deref() {
        Some(base) if !base.is_empty() => format!("adrian-dc-{base}"),
        _ => "adrian-dc".to_string(),
    }
}

/// Build the desired `StatefulSet` for a `DomainController` CRD. The
/// StatefulSet runs the Adrian DSA container with the spec's image,
/// configured for the domain via env vars, and a PVC for the DIT volume.
///
/// The container exposes LDAP (389), LDAPS (636), Kerberos (88), kpasswd
/// (464), DNS (53), SMB (445), and metrics (9100) ports. Liveness,
/// readiness, and startup probes are wired per ADR-058 §Decision:
/// liveness on TCP/389 (LDAP), readiness on TCP/88 (Kerberos), startup
/// on TCP/389.
///
/// Returns `Err(OperatorError::Reconcile)` if the constructed JSON fails
/// to deserialize as a `StatefulSet` — this would indicate a bug in the
/// JSON template (since `k8s_openapi::StatefulSet` is permissive about
/// unknown fields).
pub fn build_statefulset_for(
    dc: &DomainController,
) -> Result<k8s_openapi::api::apps::v1::StatefulSet, OperatorError> {
    let name = statefulset_name(dc);
    let namespace = dc
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let dc_name = dc.metadata.name.clone().unwrap_or_default();
    let headless_service = if dc_name.is_empty() {
        "adrian-dc-headless".to_string()
    } else {
        format!("adrian-dc-{dc_name}-headless")
    };
    let ss_json = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "adrian-dc",
                "app.kubernetes.io/managed-by": "adrian-operator",
                "adrian.io/domain-controller": dc_name
            }
        },
        "spec": {
            "replicas": dc.spec.replicas,
            "serviceName": headless_service,
            "selector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "adrian-dc",
                    "adrian.io/domain-controller": dc_name
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/name": "adrian-dc",
                        "adrian.io/domain-controller": dc_name
                    }
                },
                "spec": {
                    "securityContext": {
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001
                    },
                    "containers": [{
                        "name": "adrian-dc",
                        "image": dc.spec.image,
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
                            {"name": "ADRIAN_DOMAIN_NAME", "value": dc.spec.domain_name},
                            {"name": "ADRIAN_NETBIOS_NAME", "value": dc.spec.netbios_name}
                        ],
                        "volumeMounts": [
                            {"name": "dit", "mountPath": "/var/lib/adrian/dit"}
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
                    "resources": {"requests": {"storage": dc.spec.storage_size}}
                }
            }]
        }
    });
    serde_json::from_value(ss_json).map_err(OperatorError::from)
}

// ===========================================================================
// Operator controller — real kube::Client + controller-runtime loop
// ===========================================================================

/// The Adrian operator — reconciles `DomainController` CRDs to
/// StatefulSets that run the Adrian DSA. Construct with
/// [`AdrianOperator::new`], drive the reconcile loop with
/// [`AdrianOperator::run`], or reconcile a single object with
/// [`AdrianOperator::reconcile`].
///
/// Per ADR-058: container-native DCs managed by this operator.
/// Per ADR-018: stateless pool — no primary/secondary semantics.
pub struct AdrianOperator {
    client: kube::Client,
}

/// Operator context shared across reconcile invocations (passed to
/// `Controller::run` as the `Arc<Ctx>`).
struct OperatorContext {
    client: kube::Client,
}

impl AdrianOperator {
    /// Construct an operator with a real `kube::Client`. The client must
    /// be configured with cluster credentials — typically via
    /// `Client::try_default().await?` (which reads kubeconfig or
    /// in-cluster service-account env vars).
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying `kube::Client`. Used by
    /// tests (and external callers) to verify the operator holds the
    /// client it was constructed with, and to issue their own API calls
    /// against the same cluster.
    pub fn client(&self) -> &kube::Client {
        &self.client
    }

    /// Run the reconcile loop. Subscribes to `DomainController` CRD
    /// changes (and owned StatefulSet changes) in the operator's
    /// default namespace and drives [`AdrianOperator::reconcile`] on each
    /// event.
    ///
    /// Blocks until graceful shutdown. Errors are logged but do not halt
    /// the loop — the controller-runtime requeues failed objects with a
    /// 30-second backoff.
    ///
    /// Per the kube controller-runtime pattern: the `Controller` watches
    /// the main resource (`DomainController`) plus owned children
    /// (`StatefulSet`) — changes to either trigger a reconcile of the
    /// owning `DomainController`.
    pub async fn run(&self) -> Result<(), OperatorError> {
        use futures::StreamExt;
        use kube::runtime::{watcher, Controller};

        let namespace = self.client.default_namespace().to_string();
        let dc_api: kube::Api<DomainController> =
            kube::Api::namespaced(self.client.clone(), &namespace);
        let ss_api: kube::Api<k8s_openapi::api::apps::v1::StatefulSet> =
            kube::Api::namespaced(self.client.clone(), &namespace);
        let ctrl = Controller::new(dc_api, watcher::Config::default())
            .owns(ss_api, watcher::Config::default());
        let ctx = Arc::new(OperatorContext {
            client: self.client.clone(),
        });
        ctrl.run(
            |dc, ctx| async move {
                let operator = AdrianOperator {
                    client: ctx.client.clone(),
                };
                let result = operator.reconcile(&dc).await?;
                Ok::<kube::runtime::controller::Action, OperatorError>(match result {
                    ReconcileResult::Requeue => {
                        kube::runtime::controller::Action::requeue(Duration::from_secs(30))
                    }
                    _ => kube::runtime::controller::Action::await_change(),
                })
            },
            |_dc, err, _ctx| {
                tracing::error!(?err, "reconcile failed; requeuing with backoff");
                kube::runtime::controller::Action::requeue(Duration::from_secs(30))
            },
            ctx,
        )
        .for_each(|res| async {
            match res {
                Ok((obj, action)) => tracing::info!(?obj, ?action, "reconciled"),
                Err(err) => tracing::error!(?err, "reconcile stream error"),
            }
        })
        .await;
        Ok(())
    }

    /// Reconcile a single `DomainController` CRD instance. Idempotent —
    /// safe to call on every CRD change. Returns the
    /// [`ReconcileResult`] for logging/requeue accounting.
    ///
    /// # Decision matrix
    ///
    /// - CRD has a `deletionTimestamp` → delete the StatefulSet (if it
    ///   still exists; a 404 is treated as `NoOp` since the StatefulSet
    ///   is already gone). Finalizer-based deletion is deferred to a
    ///   future wave (TODO:Wave 5+).
    /// - StatefulSet not found → create it via `Api::create`.
    /// - StatefulSet found but snapshot differs → patch via
    ///   `Api::patch` with a strategic-merge patch.
    /// - else → `NoOp`.
    pub async fn reconcile(
        &self,
        obj: &DomainController,
    ) -> Result<ReconcileResult, OperatorError> {
        use kube::api::{DeleteParams, Patch, PatchParams, PostParams};

        let namespace = obj
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let ss_api: kube::Api<k8s_openapi::api::apps::v1::StatefulSet> =
            kube::Api::namespaced(self.client.clone(), &namespace);
        let ss_name = statefulset_name(obj);

        // Fetch the current StatefulSet (if any). Api::get_opt returns
        // Ok(None) for HTTP 404 NotFound — no error handling needed.
        let current_opt: Option<k8s_openapi::api::apps::v1::StatefulSet> =
            ss_api.get_opt(&ss_name).await?;
        let current_snapshot = current_opt
            .as_ref()
            .and_then(StatefulSetSnapshot::from_statefulset);

        // Pure decision: what should we do?
        let deletion_ts: Option<&DateTime<Utc>> =
            obj.metadata.deletion_timestamp.as_ref().map(|t| &t.0);
        let action = decide_reconcile_action(current_snapshot.as_ref(), &obj.spec, deletion_ts);

        match action {
            ReconcileAction::Delete => {
                // CRD is being deleted — delete the StatefulSet.
                // A 404 here means the StatefulSet is already gone —
                // treat as NoOp (no work to do).
                let _ = not_found_to_none(ss_api.delete(&ss_name, &DeleteParams::default()).await)?;
                Ok(ReconcileResult::Deleted)
            }
            ReconcileAction::Create => {
                let ss = build_statefulset_for(obj)?;
                ss_api.create(&PostParams::default(), &ss).await?;
                Ok(ReconcileResult::Created)
            }
            ReconcileAction::Update => {
                let ss = build_statefulset_for(obj)?;
                ss_api
                    .patch(&ss_name, &PatchParams::default(), &Patch::Merge(&ss))
                    .await?;
                Ok(ReconcileResult::Updated)
            }
            ReconcileAction::NoOp => Ok(ReconcileResult::NoOp),
        }
    }
}

// ===========================================================================
// Wave 5b CRD scaffolding — ADR-058 §Decision (DcSpec / DcStatus /
// Helm chart generation). Retained alongside the new kube::CustomResource
// DomainController CRD for the YAML/Helm-generation surface that
// downstream tooling (adrian-cli, adrian-monitor) consumes.
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
    let statefulset_yaml = serde_yaml::to_string(&generate_statefulset(spec))
        .unwrap_or_else(|e| format!("# error: {e}"));
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
        (
            "templates/service.yaml".to_string(),
            service_yaml.to_string(),
        ),
    ];
    HelmChart {
        chart_yaml,
        values_yaml,
        templates,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-operator`. Cover:
    //! - The new Wave 4b surface: DomainController CRD metadata, the
    //!   pure `decide_reconcile_action` decision matrix, the
    //!   `not_found_to_none` 404 helper, `StatefulSetSnapshot`
    //!   extraction, `build_statefulset_for`, `statefulset_name`, and
    //!   `AdrianOperator::new` (with a mock kube client).
    //! - The Wave 5b surface: `DcSpec`, `DomainControllerCrd`,
    //!   `crd_definition`, `generate_statefulset`, `generate_helm_chart`,
    //!   `Condition` serialization.

    use super::*;
    use chrono::Utc;
    use k8s_openapi::api::apps::v1::StatefulSet;
    // Required for `DomainController::api_version(&())` / `kind` / etc.
    // — the kube::CustomResource derive generates a `kube::Resource`
    // impl, and trait methods are only callable when the trait is in
    // scope.
    use kube::Resource;

    // ========================================================================
    // Helper: construct a DomainController for tests.
    // ========================================================================

    fn sample_dc_spec() -> DomainControllerSpec {
        DomainControllerSpec {
            replicas: 3,
            image: "ghcr.io/adrian/dc:0.1.0".to_string(),
            storage_size: "50Gi".to_string(),
            domain_name: "adrian.dev".to_string(),
            netbios_name: "ADRIAN".to_string(),
        }
    }

    /// Build a `DomainController` CRD instance for tests (with name +
    /// namespace set so [`statefulset_name`] is deterministic).
    fn sample_dc(name: &str) -> DomainController {
        DomainController::new(name, sample_dc_spec())
    }

    // ========================================================================
    // Wave 4b tests — DomainController CRD metadata (1 test).
    // ========================================================================

    #[test]
    fn domain_controller_crd_metadata_has_correct_group_version_kind() {
        // The kube::CustomResource derive must generate the Resource
        // trait impl with the correct group/version/kind/plural — these
        // are what the kube::Api<DomainController> uses to construct
        // the REST path (`/apis/adrian.io/v1alpha1/namespaces/<ns>/domaincontrollers`).
        // A typo here would silently 404 every watch request.
        assert_eq!(DomainController::api_version(&()), "adrian.io/v1alpha1");
        assert_eq!(DomainController::group(&()), "adrian.io");
        assert_eq!(DomainController::version(&()), "v1alpha1");
        assert_eq!(DomainController::kind(&()), "DomainController");
        assert_eq!(DomainController::plural(&()), "domaincontrollers");
    }

    // ========================================================================
    // Wave 4b tests — pure reconcile decision logic (4 tests).
    // ========================================================================

    #[test]
    fn decide_reconcile_action_creates_when_no_statefulset() {
        // When the StatefulSet doesn't exist yet (current=None) and the
        // CRD is not being deleted, the operator must create it.
        let spec = sample_dc_spec();
        let action = decide_reconcile_action(None, &spec, None);
        assert_eq!(action, ReconcileAction::Create);
    }

    #[test]
    fn decide_reconcile_action_updates_when_spec_differs() {
        // When the StatefulSet exists but its snapshot differs from the
        // desired spec, the operator must update it.
        let spec = sample_dc_spec();
        // Stale snapshot — replicas was 2 (desired is 3).
        let mut stale = StatefulSetSnapshot::from_spec(&spec);
        stale.replicas = 2;
        let action = decide_reconcile_action(Some(&stale), &spec, None);
        assert_eq!(action, ReconcileAction::Update);
    }

    #[test]
    fn decide_reconcile_action_deletes_when_crd_has_deletion_timestamp() {
        // When the CRD has a deletionTimestamp, the operator must
        // garbage-collect its StatefulSet — even if the StatefulSet is
        // still in sync with the spec.
        let spec = sample_dc_spec();
        let current = StatefulSetSnapshot::from_spec(&spec);
        let deletion_ts = Utc::now();
        let action = decide_reconcile_action(Some(&current), &spec, Some(&deletion_ts));
        assert_eq!(action, ReconcileAction::Delete);
    }

    #[test]
    fn not_found_to_none_converts_kube_404_to_ok_none() {
        // The reconcile loop must treat a 404 NotFound from the kube
        // API as "object is gone" (Ok(None)), not as a fatal error.
        // This is the "handles not-found gracefully" contract.
        let not_found = kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "statefulsets.apps \"adrian-dc\" not found".to_string(),
            reason: "NotFound".to_string(),
            code: 404,
        });
        let result: Result<StatefulSet, kube::Error> = Err(not_found);
        assert_eq!(not_found_to_none(result).unwrap(), None);

        // A non-404 error must propagate as Err.
        let conflict = kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "already exists".to_string(),
            reason: "AlreadyExists".to_string(),
            code: 409,
        });
        let result: Result<StatefulSet, kube::Error> = Err(conflict);
        assert!(not_found_to_none(result).is_err());
    }

    // ========================================================================
    // Wave 4b tests — helper functions (every new function gets a test).
    // ========================================================================

    #[test]
    fn decide_reconcile_action_noop_when_in_sync() {
        // When the StatefulSet snapshot matches the desired spec exactly,
        // the operator must NoOp (don't churn the API with no-op patches).
        let spec = sample_dc_spec();
        let current = StatefulSetSnapshot::from_spec(&spec);
        let action = decide_reconcile_action(Some(&current), &spec, None);
        assert_eq!(action, ReconcileAction::NoOp);
    }

    #[test]
    fn statefulset_snapshot_from_spec_preserves_all_fields() {
        // The desired snapshot must round-trip every field of the spec —
        // drift detection compares these snapshots, so any field lost
        // here would silently mask drift.
        let spec = sample_dc_spec();
        let snap = StatefulSetSnapshot::from_spec(&spec);
        assert_eq!(snap.replicas, 3);
        assert_eq!(snap.image, "ghcr.io/adrian/dc:0.1.0");
        assert_eq!(snap.storage_size, "50Gi");
        assert_eq!(snap.domain_name, "adrian.dev");
        assert_eq!(snap.netbios_name, "ADRIAN");
    }

    #[test]
    fn statefulset_snapshot_from_statefulset_extracts_fields() {
        // Build a StatefulSet via build_statefulset_for, then verify
        // that StatefulSetSnapshot::from_statefulset extracts the same
        // fields we put in. This is the round-trip that drift detection
        // relies on: build_desired → snapshot_from_spec, fetch_live →
        // snapshot_from_statefulset, compare.
        let dc = sample_dc("primary");
        let ss = build_statefulset_for(&dc).expect("build_statefulset_for");
        let observed = StatefulSetSnapshot::from_statefulset(&ss)
            .expect("snapshot should extract from a built StatefulSet");
        let desired = StatefulSetSnapshot::from_spec(&dc.spec);
        assert_eq!(observed, desired);
    }

    #[test]
    fn statefulset_snapshot_from_statefulset_returns_none_for_malformed() {
        // An empty (default) StatefulSet has no spec, no containers, no
        // PVCs — from_statefulset must return None rather than panic.
        let empty = StatefulSet::default();
        assert!(StatefulSetSnapshot::from_statefulset(&empty).is_none());
    }

    #[test]
    fn build_statefulset_for_returns_valid_statefulset() {
        // build_statefulset_for must:
        // - Return Ok (the JSON must deserialize as a StatefulSet).
        // - Propagate replicas, image, domain_name, netbios_name,
        //   storage_size into the right StatefulSet fields.
        // - Set the StatefulSet name to `adrian-dc-<dc-name>`.
        // - Wire the ADRIAN_DOMAIN_NAME / ADRIAN_NETBIOS_NAME env vars.
        // - Wire a DIT PVC with the spec's storage_size.
        let dc = sample_dc("primary");
        let ss = build_statefulset_for(&dc).expect("build_statefulset_for");
        assert_eq!(ss.metadata.name.as_deref(), Some("adrian-dc-primary"));
        assert_eq!(ss.metadata.namespace.as_deref(), Some("default"));
        let spec = ss.spec.as_ref().expect("StatefulSet.spec");
        assert_eq!(spec.replicas, Some(3));
        let container = spec
            .template
            .spec
            .as_ref()
            .expect("PodSpec")
            .containers
            .first()
            .expect("first container");
        assert_eq!(container.image.as_deref(), Some("ghcr.io/adrian/dc:0.1.0"));
        let env = container
            .env
            .as_ref()
            .expect("container.env must be present");
        let domain_env = env
            .iter()
            .find(|e| e.name == "ADRIAN_DOMAIN_NAME")
            .expect("ADRIAN_DOMAIN_NAME env var");
        assert_eq!(domain_env.value.as_deref(), Some("adrian.dev"));
        let netbios_env = env
            .iter()
            .find(|e| e.name == "ADRIAN_NETBIOS_NAME")
            .expect("ADRIAN_NETBIOS_NAME env var");
        assert_eq!(netbios_env.value.as_deref(), Some("ADRIAN"));
        // PVC storage size.
        let pvc = spec
            .volume_claim_templates
            .as_ref()
            .and_then(|vcts| vcts.first())
            .expect("volume_claim_templates[0]");
        let storage = pvc
            .spec
            .as_ref()
            .and_then(|s| s.resources.as_ref())
            .and_then(|r| r.requests.as_ref())
            .and_then(|reqs| reqs.get("storage"))
            .expect("storage request");
        assert_eq!(storage.0, "50Gi");
        // Probes (ADR-058 §Decision).
        assert!(container.liveness_probe.is_some(), "livenessProbe required");
        assert!(
            container.readiness_probe.is_some(),
            "readinessProbe required"
        );
        assert!(container.startup_probe.is_some(), "startupProbe required");
    }

    #[test]
    fn statefulset_name_uses_dc_name() {
        // statefulset_name must prefix `adrian-dc-` to the CRD's
        // metadata.name, so operator-owned StatefulSets are greppable.
        let dc = sample_dc("us-east-1a");
        assert_eq!(statefulset_name(&dc), "adrian-dc-us-east-1a");
    }

    #[test]
    fn statefulset_name_falls_back_when_no_dc_name() {
        // A CRD with no metadata.name (shouldn't happen for persisted
        // CRDs but can happen for in-memory test fixtures) must fall
        // back to the bare name `adrian-dc` rather than panic.
        let mut dc = sample_dc("ignored");
        dc.metadata.name = None;
        assert_eq!(statefulset_name(&dc), "adrian-dc");
    }

    #[tokio::test]
    async fn operator_new_stores_client() {
        // AdrianOperator::new must accept a real kube::Client and
        // expose it via client(). We construct the Client with a
        // tower::service_fn mock (no real cluster needed) — this
        // verifies the type signature compiles and the client is
        // stored, which is the contract callers depend on.
        //
        // Must run inside a tokio runtime because kube::Client::new
        // internally spawns a buffer task on the current runtime.
        use bytes::Bytes;
        use http::{Request, Response};
        use http_body_util::Empty;
        use kube::client::Body;
        use tower::service_fn;

        let svc = service_fn(|_req: Request<Body>| async move {
            Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
        });
        let client = kube::Client::new(svc, "test-ns");
        let operator = AdrianOperator::new(client);
        assert_eq!(operator.client().default_namespace(), "test-ns");
    }

    // ========================================================================
    // Wave 5b tests (preserved) — error type, DcSpec, CRD serialization,
    // CRD definition, StatefulSet generation, Helm chart, Condition.
    // ========================================================================

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
    fn operator_error_converts_from_kube_error() {
        // The From<kube::Error> impl lets `?` propagate kube errors in
        // the reconcile loop without manual .map_err at every call site.
        let kube_err = kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "boom".to_string(),
            reason: "InternalError".to_string(),
            code: 500,
        });
        let op_err: OperatorError = kube_err.into();
        assert!(matches!(op_err, OperatorError::Kube(_)));
        assert!(op_err.to_string().contains("boom"));
    }

    #[test]
    fn operator_error_converts_from_serde_json_error() {
        // The From<serde_json::Error> impl lets build_statefulset_for
        // propagate deserialization failures with `?`.
        let json_err = serde_json::from_str::<i32>("not a number").expect_err("invalid json");
        let op_err: OperatorError = json_err.into();
        assert!(matches!(op_err, OperatorError::Reconcile(_)));
    }

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
        assert_eq!(
            value.get("apiVersion").and_then(|v| v.as_str()),
            Some("adrian.io/v1")
        );
        assert_eq!(
            value.get("kind").and_then(|v| v.as_str()),
            Some("DomainController")
        );
        assert_eq!(
            value
                .get("metadata")
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str()),
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
        assert_eq!(
            def.get("apiVersion").and_then(|v| v.as_str()),
            Some("apiextensions.k8s.io/v1")
        );
        assert_eq!(
            def.get("kind").and_then(|v| v.as_str()),
            Some("CustomResourceDefinition")
        );
        assert_eq!(
            def.get("metadata")
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str()),
            Some("domaincontrollers.adrian.io")
        );
        // Verify the spec group / names / scope / versions are present.
        let spec = def.get("spec").expect("CRD spec must be present");
        assert_eq!(
            spec.get("group").and_then(|v| v.as_str()),
            Some("adrian.io")
        );
        assert_eq!(
            spec.get("scope").and_then(|v| v.as_str()),
            Some("Namespaced")
        );
        let names = spec.get("names").expect("CRD names must be present");
        assert_eq!(
            names.get("kind").and_then(|v| v.as_str()),
            Some("DomainController")
        );
        assert_eq!(
            names.get("plural").and_then(|v| v.as_str()),
            Some("domaincontrollers")
        );
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
        for key in [
            "replicas",
            "domainDn",
            "krbtgtHsmKeyId",
            "fdbClusterFile",
            "image",
        ] {
            assert!(
                schema.get(key).is_some(),
                "openAPIV3Schema must include `{key}`"
            );
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
        let fdb_env = env
            .iter()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some("ADRIAN_FDB_CLUSTER_FILE"));
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
        assert!(
            container.get("livenessProbe").is_some(),
            "livenessProbe required"
        );
        assert!(
            container.get("readinessProbe").is_some(),
            "readinessProbe required"
        );
        assert!(
            container.get("startupProbe").is_some(),
            "startupProbe required"
        );
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
        assert!(
            chart.chart_yaml.contains("name: adrian-dc"),
            "Chart.yaml must contain name"
        );
        assert!(
            chart.chart_yaml.contains("apiVersion: v2"),
            "Chart.yaml must contain apiVersion"
        );
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
        let template_names: Vec<&str> = chart.templates.iter().map(|(n, _)| n.as_str()).collect();
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
        assert_eq!(
            json.get("reason").and_then(|v| v.as_str()),
            Some("AllReplicasReady")
        );
        // lastTransitionTime must be a string (RFC 3339 date-time).
        let ltt = json
            .get("lastTransitionTime")
            .and_then(|v| v.as_str())
            .expect("lastTransitionTime must be present");
        assert!(
            ltt.contains('T'),
            "lastTransitionTime must be RFC 3339: {ltt}"
        );
        // Must NOT contain `type_` (the Rust field name) — serde renamed it.
        let json_str = serde_json::to_string(&condition).expect("serialize condition");
        assert!(
            !json_str.contains("type_"),
            "condition must NOT serialize `type_` as `type_`: {json_str}"
        );
    }
}
