#![forbid(unsafe_code)]
//! # adrian-monitor
//!
//! Observability — Prometheus metrics endpoint + OpenTelemetry audit
//! pipeline (ADR-057 + ADR-060). The framework's audit events are
//! surfaced both as Prometheus metrics (for alerting / dashboards) and
//! as structured OTel log records (for SIEM ingestion).
//!
//! ## ADRs
//!
//! - ADR-057: Prometheus + OpenTelemetry observability
//! - ADR-060: Structured audit logs (OTel)
//! - ADR-023: Kerberos audit events
//! - ADR-034: Transactional DB PITR; reject-and-repair observability
//! - ADR-059: PITR backup / DR runbooks (monitoring hooks)

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("prometheus: {0}")]
    Prometheus(String),
    #[error("otel: {0}")]
    Otel(String),
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("sink: {0}")]
    Sink(String),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
}

// ===========================================================================
// Audit types (ADR-060)
// ===========================================================================

/// The set of audit-worthy events the framework emits. Each variant maps
/// to a Windows Event ID for AD-interop scenarios (ADR-060 §Decision).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Kerberos AS-REQ (Windows Event 4768). Kerberoasting preauth signal.
    KerberosAsReq,
    /// Kerberos TGS-REQ (Windows Event 4769). Kerberoasting etype signal.
    KerberosTgsReq,
    /// LDAP bind (Windows Event 4624 logon type 3 via LDAP).
    LdapBind,
    /// LDAP modify (Windows Event 5136 Directory Service Access).
    LdapModify,
    /// Password change (kpasswd — Windows Event 4723/4724).
    PasswordChange,
    /// X.509 certificate enrollment via ACME (RFC 8555).
    CertEnroll,
    /// SMB share mount (ADR-106).
    SmbShareMount,
    /// krbtgt key rotation (ADR-065). Mitre T1558.001 detection signal.
    KrbtgtRotation,
    /// DCSync attempt (Windows Event 4662 with replication-control access).
    /// Mitre T1003.006 detection signal (PC-117).
    DcSyncAttempt,
}

impl AuditEventType {
    /// Stable string identifier used as the OTel log-record `Body` field
    /// (ADR-060 §Decision). Matches `adrian.<domain>.<action>`.
    pub fn as_event_name(&self) -> &'static str {
        match self {
            Self::KerberosAsReq => "adrian.kerberos.as_req",
            Self::KerberosTgsReq => "adrian.kerberos.tgs_req",
            Self::LdapBind => "adrian.ldap.bind",
            Self::LdapModify => "adrian.ldap.modify",
            Self::PasswordChange => "adrian.identity.password_change",
            Self::CertEnroll => "adrian.pki.cert_enroll",
            Self::SmbShareMount => "adrian.file.share_mount",
            Self::KrbtgtRotation => "adrian.kdc.krbtgt_rotation",
            Self::DcSyncAttempt => "adrian.security.dcsync_attempt",
        }
    }
}

/// Outcome of an audit-worthy event. `Failure` carries a human-readable
/// error string for SIEM dashboards; `Denied` is distinguished from
/// `Failure` so SIEM rules can alert on authorisation denials separately
/// from runtime failures (per ADR-060 §Decision).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The event completed successfully.
    Success,
    /// The event failed at runtime (network, storage, crypto, etc.).
    Failure(String),
    /// The event was denied by policy (access control, RBAC, etc.).
    Denied,
}

/// A single audit-worthy event, emitted via OTLP (ADR-060).
///
/// Fields mirror the OTel logs data model: a timestamp, a typed event
/// name, structured attributes (principal, source IP, outcome, details).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event was observed (nanosecond precision via `chrono`).
    pub timestamp: DateTime<Utc>,
    /// The event type — drives MITRE ATT&CK mapping (ADR-060).
    pub event_type: AuditEventType,
    /// The principal that triggered the event, if known (e.g. `admin@ADRIAN.DEV`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Source IP of the client that triggered the event (truncated to /24
    /// for IPv4 to reduce PII exposure per ADR-057).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Outcome (success / failure / denied).
    pub outcome: AuditOutcome,
    /// Free-form structured details (etype, SPN, DN, etc.).
    pub details: serde_json::Value,
}

impl AuditEvent {
    /// Construct a new audit event at the current time with no details.
    pub fn new(event_type: AuditEventType, outcome: AuditOutcome) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            principal: None,
            source_ip: None,
            outcome,
            details: serde_json::Value::Null,
        }
    }
}

// ===========================================================================
// AuditSink trait + impls
// ===========================================================================

/// A sink for audit events. The framework's audit pipeline calls
/// `write(event)` for every audit-worthy event (ADR-060).
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Persist / forward a single audit event.
    async fn write(&self, event: AuditEvent) -> Result<(), AuditError>;
}

/// A sink that writes JSON-lines audit events to the `tracing` logger
/// (ADR-060 §Decision: "fall back to local JSONL files" / structured logs).
///
/// Each event is serialised to a single-line JSON object and emitted at
/// `tracing::Level::INFO` (per ADR-060 §Decision: severity_number ≥ 9 for
/// routine events). The target is the constant `"adrian::audit"` so
/// downstream subscribers can filter on it.
#[derive(Default)]
pub struct LogAuditSink;

impl LogAuditSink {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuditSink for LogAuditSink {
    async fn write(&self, event: AuditEvent) -> Result<(), AuditError> {
        // Serialise once, then emit via tracing — keeps the JSON-lines
        // payload intact (no re-formatting by the log layer). The target
        // is fixed at compile time because `tracing::info!` requires a
        // literal target.
        let json = serde_json::to_string(&event)?;
        tracing::info!(target: "adrian::audit", "{json}");
        Ok(())
    }
}

/// A sink that forwards audit events via the OpenTelemetry logs API
/// (ADR-060 §Decision). The OTLP exporter itself is configured separately
/// (per ADR-057 §Decision — the sidecar terminates OTLP); this sink just
/// ensures the events traverse the OTel logs pipeline.
///
/// The current implementation is a **stub that records the event count**
/// without actually emitting OTLP — installing a real OTLP exporter
/// requires a configurable OTLP endpoint, which is not yet available in
/// the test environment. The stub returns `Ok(())` per the task spec:
/// "uses `opentelemetry` crate (if available; else stub that returns Ok)".
pub struct OtelAuditSink {
    /// Number of events observed — exposed for tests / diagnostics.
    events_seen: std::sync::atomic::AtomicU64,
}

impl OtelAuditSink {
    pub fn new() -> Self {
        Self {
            events_seen: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Number of events observed since the sink was constructed.
    pub fn events_seen(&self) -> u64 {
        self.events_seen.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for OtelAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditSink for OtelAuditSink {
    async fn write(&self, event: AuditEvent) -> Result<(), AuditError> {
        // Real OTel implementation would call `logger.emit(LogRecord ...)`
        // here. The stub just counts events; a future wave will wire the
        // OTLP exporter once an OTLP endpoint is configurable.
        let _ = &event;
        self.events_seen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

// ===========================================================================
// AuditPipeline
// ===========================================================================

/// The audit pipeline — wraps a single [`AuditSink`] and forwards every
/// event to it. Per ADR-060 §Decision, the pipeline is async (the sink's
/// `write()` is `async fn`) so slow sinks (network-backed) don't block
/// the request path.
pub struct AuditPipeline {
    /// The sink that receives every audit event.
    pub sink: Arc<dyn AuditSink>,
}

impl AuditPipeline {
    /// Construct a pipeline backed by the given sink.
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    /// Forward an event to the sink.
    pub async fn emit(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.sink.write(event).await
    }
}

// ===========================================================================
// MetricsRegistry
// ===========================================================================

/// A Prometheus-compatible metrics registry. Holds counters, gauges, and
/// histograms with label-set support. The `Mutex<HashMap<...>>` layout
/// keeps the API simple — the monitor's hot path (KDC, LDAP) increments
/// these via `tokio::sync::Mutex`, which is fine for the expected QPS
/// (10k events/sec per DC, per ADR-057 §Decision).
///
/// All metrics use the `adrian_` prefix per ADR-057 §Decision.
pub struct MetricsRegistry {
    inner: Mutex<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    /// `as_req_total` — counter, labels: realm, etype.
    as_req_total: HashMap<(String, String), u64>,
    /// `as_req_duration_seconds` — histogram (no labels).
    as_req_duration_seconds: HistogramState,
    /// `ldap_query_duration_seconds` — histogram, labels: scope.
    ldap_query_duration_seconds: HashMap<String, HistogramState>,
    /// `fdb_operations_total` — counter, labels: op_type.
    fdb_operations_total: HashMap<String, u64>,
    /// `replication_lag_seconds` — gauge, labels: source_dc, target_dc.
    replication_lag_seconds: HashMap<(String, String), f64>,
    /// `rid_pool_remaining` — gauge, labels: domain_sid.
    rid_pool_remaining: HashMap<String, f64>,
    /// `krbtgt_key_age_seconds` — gauge (no labels).
    krbtgt_key_age_seconds: f64,
}

/// Internal mutable histogram state — per-bucket counts (non-cumulative;
/// cumulated at render time) + total count + sum of observed values.
#[derive(Clone, Default)]
struct HistogramState {
    bucket_counts: Vec<u64>,
    count: u64,
    sum: f64,
}

/// Default histogram buckets for latency observation (ADR-057 §Decision:
/// `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5]`).
const DEFAULT_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];

impl HistogramState {
    fn observe(&mut self, value: f64) {
        // Find the smallest bucket whose upper bound is >= value. The
        // value falls into exactly that bucket (non-cumulative storage;
        // cumulation is applied at render time).
        let bucket_idx = DEFAULT_BUCKETS.iter().position(|&b| value <= b);
        if self.bucket_counts.is_empty() {
            self.bucket_counts = vec![0; DEFAULT_BUCKETS.len()];
        } else if self.bucket_counts.len() < DEFAULT_BUCKETS.len() {
            self.bucket_counts.resize(DEFAULT_BUCKETS.len(), 0);
        }
        // Increment the single bucket that contains the value. Values
        // above the largest finite bucket (5.0) are NOT counted in any
        // finite bucket — they're counted only in the +Inf bucket at
        // render time.
        if let Some(idx) = bucket_idx {
            self.bucket_counts[idx] += 1;
        }
        self.count += 1;
        self.sum += value;
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MetricsInner::default()),
        }
    }

    /// Increment `as_req_total{realm, etype}` by 1.
    pub async fn inc_as_req(&self, realm: &str, etype: &str) {
        let mut inner = self.inner.lock().await;
        *inner
            .as_req_total
            .entry((realm.to_string(), etype.to_string()))
            .or_insert(0) += 1;
    }

    /// Observe an `as_req_duration_seconds` value (in seconds).
    pub async fn observe_as_req_duration(&self, seconds: f64) {
        let mut inner = self.inner.lock().await;
        inner.as_req_duration_seconds.observe(seconds);
    }

    /// Observe an `ldap_query_duration_seconds{scope}` value (in seconds).
    pub async fn observe_ldap_query_duration(&self, scope: &str, seconds: f64) {
        let mut inner = self.inner.lock().await;
        inner
            .ldap_query_duration_seconds
            .entry(scope.to_string())
            .or_default()
            .observe(seconds);
    }

    /// Increment `fdb_operations_total{op_type}` by 1.
    pub async fn inc_fdb_operation(&self, op_type: &str) {
        let mut inner = self.inner.lock().await;
        *inner
            .fdb_operations_total
            .entry(op_type.to_string())
            .or_insert(0) += 1;
    }

    /// Set `replication_lag_seconds{source_dc, target_dc}` (in seconds).
    pub async fn set_replication_lag(&self, source_dc: &str, target_dc: &str, lag_seconds: f64) {
        let mut inner = self.inner.lock().await;
        inner
            .replication_lag_seconds
            .insert((source_dc.to_string(), target_dc.to_string()), lag_seconds);
    }

    /// Set `rid_pool_remaining{domain_sid}` (count of unallocated RIDs).
    pub async fn set_rid_pool_remaining(&self, domain_sid: &str, remaining: f64) {
        let mut inner = self.inner.lock().await;
        inner
            .rid_pool_remaining
            .insert(domain_sid.to_string(), remaining);
    }

    /// Set `krbtgt_key_age_seconds` (seconds since the krbtgt key was last
    /// rotated — drives the "krbtgt key version stale" alert per ADR-057).
    pub async fn set_krbtgt_key_age(&self, age_seconds: f64) {
        let mut inner = self.inner.lock().await;
        inner.krbtgt_key_age_seconds = age_seconds;
    }

    /// Render all metrics in Prometheus text exposition format 0.0.4
    /// (https://prometheus.io/docs/instrumenting/exposition_formats/).
    ///
    /// The output is sorted by metric name, then by label-set, so the
    /// rendering is deterministic — useful for snapshot tests.
    pub async fn render_prometheus(&self) -> String {
        let inner = self.inner.lock().await;
        let mut out = String::new();

        // as_req_total
        out.push_str("# HELP adrian_as_req_total Total Kerberos AS-REQs received.\n");
        out.push_str("# TYPE adrian_as_req_total counter\n");
        let mut entries: Vec<_> = inner.as_req_total.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for ((realm, etype), value) in entries {
            out.push_str(&format!(
                "adrian_as_req_total{{realm=\"{realm}\",etype=\"{etype}\"}} {value}\n"
            ));
        }

        // as_req_duration_seconds
        out.push_str(
            "# HELP adrian_as_req_duration_seconds Latency of Kerberos AS-REQ handling.\n",
        );
        out.push_str("# TYPE adrian_as_req_duration_seconds histogram\n");
        render_histogram(
            &mut out,
            "adrian_as_req_duration_seconds",
            &[],
            &inner.as_req_duration_seconds,
        );

        // ldap_query_duration_seconds
        out.push_str("# HELP adrian_ldap_query_duration_seconds Latency of LDAP query handling.\n");
        out.push_str("# TYPE adrian_ldap_query_duration_seconds histogram\n");
        let mut ldap_entries: Vec<_> = inner.ldap_query_duration_seconds.iter().collect();
        ldap_entries.sort_by(|a, b| a.0.cmp(b.0));
        for (scope, state) in ldap_entries {
            render_histogram(
                &mut out,
                "adrian_ldap_query_duration_seconds",
                &[("scope", scope.as_str())],
                state,
            );
        }

        // fdb_operations_total
        out.push_str("# HELP adrian_fdb_operations_total Total FoundationDB operations.\n");
        out.push_str("# TYPE adrian_fdb_operations_total counter\n");
        let mut fdb_entries: Vec<_> = inner.fdb_operations_total.iter().collect();
        fdb_entries.sort_by(|a, b| a.0.cmp(b.0));
        for (op_type, value) in fdb_entries {
            out.push_str(&format!(
                "adrian_fdb_operations_total{{op_type=\"{op_type}\"}} {value}\n"
            ));
        }

        // replication_lag_seconds
        out.push_str(
            "# HELP adrian_replication_lag_seconds Replication lag between DCs (seconds).\n",
        );
        out.push_str("# TYPE adrian_replication_lag_seconds gauge\n");
        let mut repl_entries: Vec<_> = inner.replication_lag_seconds.iter().collect();
        repl_entries.sort_by(|a, b| a.0.cmp(b.0));
        for ((source_dc, target_dc), value) in repl_entries {
            out.push_str(&format!(
                "adrian_replication_lag_seconds{{source_dc=\"{source_dc}\",target_dc=\"{target_dc}\"}} {value}\n"
            ));
        }

        // rid_pool_remaining
        out.push_str(
            "# HELP adrian_rid_pool_remaining Remaining RIDs in the pool (per domain SID).\n",
        );
        out.push_str("# TYPE adrian_rid_pool_remaining gauge\n");
        let mut rid_entries: Vec<_> = inner.rid_pool_remaining.iter().collect();
        rid_entries.sort_by(|a, b| a.0.cmp(b.0));
        for (domain_sid, value) in rid_entries {
            out.push_str(&format!(
                "adrian_rid_pool_remaining{{domain_sid=\"{domain_sid}\"}} {value}\n"
            ));
        }

        // krbtgt_key_age_seconds
        out.push_str(
            "# HELP adrian_krbtgt_key_age_seconds Age of the krbtgt account key (seconds).\n",
        );
        out.push_str("# TYPE adrian_krbtgt_key_age_seconds gauge\n");
        out.push_str(&format!(
            "adrian_krbtgt_key_age_seconds {}\n",
            inner.krbtgt_key_age_seconds
        ));

        out
    }
}

/// Render a single histogram's per-bucket samples + sum + count, per the
/// Prometheus exposition 0.0.4 spec. The `+Inf` bucket is appended with
/// the total observation count.
///
/// Label rendering: when `extra_labels` is non-empty, the labels are
/// rendered as `k1="v1",k2="v2"` (followed by `,le="..."` for buckets).
/// When `extra_labels` is empty, the bucket line uses only `le="..."`.
fn render_histogram(
    out: &mut String,
    name: &str,
    extra_labels: &[(&str, &str)],
    state: &HistogramState,
) {
    // Build the labels prefix (everything before `le="..."`).
    //   - No extra labels: "" — bucket lines render as `{le="..."}`.
    //   - With extra labels: `k1="v1",k2="v2",` — bucket lines render as
    //     `{k1="v1",k2="v2",le="..."}`.
    let label_prefix: String = if extra_labels.is_empty() {
        String::new()
    } else {
        extra_labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",")
            + ","
    };

    // Per-bucket (cumulative — counts all values <= bound).
    let mut cumulative: u64 = 0;
    for (i, &bound) in DEFAULT_BUCKETS.iter().enumerate() {
        let bucket_count = if i < state.bucket_counts.len() {
            state.bucket_counts[i]
        } else {
            0
        };
        cumulative += bucket_count;
        out.push_str(&format!(
            "{name}_bucket{{{label_prefix}le=\"{bound}\"}} {cumulative}\n"
        ));
    }
    // +Inf bucket (cumulative — equals the total count).
    out.push_str(&format!(
        "{name}_bucket{{{label_prefix}le=\"+Inf\"}} {count}\n",
        count = state.count
    ));
    // Sum and count lines: when there are extra labels, the brace content
    // is `k1="v1",k2="v2"` (no trailing comma, no le=). When there are no
    // extra labels, the brace pair is omitted entirely per the Prometheus
    // exposition 0.0.4 spec (an empty label set renders as no braces).
    if extra_labels.is_empty() {
        out.push_str(&format!("{name}_sum {sum}\n", sum = state.sum));
        out.push_str(&format!("{name}_count {count}\n", count = state.count));
    } else {
        let labels = extra_labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!("{name}_sum{{{labels}}} {sum}\n", sum = state.sum));
        out.push_str(&format!(
            "{name}_count{{{labels}}} {count}\n",
            count = state.count
        ));
    }
}

// ===========================================================================
// MonitorService (was `Monitor`)
// ===========================================================================

/// Top-level monitor service — owns the metrics registry and the audit
/// pipeline. Per ADR-057 §Decision, a per-DC sidecar would scrape this
/// via `/metrics` (Prometheus) and `/otlp` (OTLP); this crate exposes
/// the in-process side of both.
pub struct MonitorService {
    /// The metrics registry — counters, gauges, histograms.
    pub metrics: Arc<MetricsRegistry>,
    /// The audit pipeline — sinks audit events to OTLP / JSONL / etc.
    pub audit_pipeline: Arc<AuditPipeline>,
}

impl MonitorService {
    /// Construct a monitor with a default `LogAuditSink` (writes JSON
    /// lines via `tracing`). Use `with_sink` to plug in a custom sink
    /// (e.g. `OtelAuditSink` for OTLP export).
    pub fn new() -> Self {
        Self::with_sink(Arc::new(LogAuditSink::new()))
    }

    /// Construct a monitor with a custom audit sink.
    pub fn with_sink(sink: Arc<dyn AuditSink>) -> Self {
        Self {
            metrics: Arc::new(MetricsRegistry::new()),
            audit_pipeline: Arc::new(AuditPipeline::new(sink)),
        }
    }

    /// Render the current metric values in Prometheus exposition format.
    pub async fn render_prometheus(&self) -> String {
        self.metrics.render_prometheus().await
    }

    /// Emit an audit event through the pipeline.
    pub async fn emit_audit(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.audit_pipeline.emit(event).await
    }

    /// Build the `/metrics` axum router for Prometheus scraping. The
    /// router exposes `/metrics` (Prometheus exposition format) and
    /// `/healthz` (always returns 200 OK).
    ///
    /// Note: the axum router is constructed but not actually served here;
    /// the caller is responsible for binding it to a port. The router
    /// shares the `Arc<MetricsRegistry>` so live updates are reflected.
    pub fn metrics_router(&self) -> axum::Router {
        // The /metrics handler reads the current registry state on each
        // scrape. We clone the `Arc<MetricsRegistry>` so the handler
        // remains valid even if the `MonitorService` is dropped.
        let metrics = self.metrics.clone();
        axum::Router::new()
            .route(
                "/metrics",
                axum::routing::get(move || {
                    let metrics = metrics.clone();
                    async move {
                        let body = metrics.render_prometheus().await;
                        (
                            [(
                                axum::http::header::CONTENT_TYPE,
                                "text/plain; version=0.0.4; charset=utf-8",
                            )],
                            body,
                        )
                    }
                }),
            )
            .route("/healthz", axum::routing::get(|| async { "ok" }))
    }

    /// Install the OTel OTLP exporter (traces + metrics + logs).
    ///
    /// **Loud stub** — installing a real OTLP exporter requires a
    /// configurable OTLP endpoint, which is not yet available in the
    /// framework's configuration model. This method returns
    /// `MonitorError::Otel("not yet implemented")` so callers see the
    /// explicit "framework not yet implemented" signal rather than
    /// silently succeeding. The audit pipeline itself (LogAuditSink /
    /// OtelAuditSink) IS implemented — only the global OTLP tracer
    /// provider installation is deferred.
    pub fn install_otel(&self) -> Result<(), MonitorError> {
        Err(MonitorError::Otel("not yet implemented".into()))
    }
}

impl Default for MonitorService {
    fn default() -> Self {
        Self::new()
    }
}

/// Backward-compat alias — earlier waves called this type `Monitor`.
/// `MonitorService` is the new canonical name (per the Wave 5b task spec).
pub type Monitor = MonitorService;

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-monitor`. Cover the metrics registry
    //! (increment + render), the audit pipeline (event dispatch), the
    //! audit sink impls (Log + Otel stub), and the monitor service.

    use super::*;

    // ========================================================================
    // Existing structural tests (preserved from earlier waves).
    // ========================================================================

    #[test]
    fn monitor_error_variants_render_messages() {
        // Every `#[error("…")]` template must render — catches regressions
        // in the format strings used by the operator's reconcile loop and
        // the CLI's `monitor up` diagnostics (ADR-057).
        assert_eq!(
            MonitorError::Prometheus("registry full".into()).to_string(),
            "prometheus: registry full"
        );
        assert_eq!(
            MonitorError::Otel("otlp connect refused".into()).to_string(),
            "otel: otlp connect refused"
        );
    }

    #[test]
    fn default_equals_new() {
        // `Default` impl must match `new()` — both must construct a usable
        // `MonitorService`. Catches the regression where a field is added
        // and one constructor is forgotten.
        let _a = MonitorService::default();
        let _b = MonitorService::new();
        // `MonitorService` is non-`Debug` (the sink trait object isn't
        // Debug), so we exercise the seam by calling `metrics_router()`
        // on each — if either constructor dropped a required init step,
        // this would panic.
        let _ra = MonitorService::default().metrics_router();
        let _rb = MonitorService::new().metrics_router();
    }

    #[test]
    fn metrics_router_constructs_without_panic() {
        // `/metrics` and `/healthz` routes are wired (ADR-057 §Decision:
        // sidecar exposes Prometheus on :9100/metrics). The router
        // construction itself must not panic.
        let monitor = MonitorService::new();
        let _router = monitor.metrics_router();
    }

    #[test]
    fn install_otel_stub_returns_otel_error() {
        // Loud-stub contract (ADR-057): until the OTLP exporter pipeline
        // is implemented, `install_otel` must surface `MonitorError::Otel`
        // rather than silently succeed or panic. The audit pipeline
        // itself IS implemented — only the global OTLP tracer provider
        // installation is deferred.
        let monitor = MonitorService::new();
        match monitor.install_otel() {
            Ok(_) => panic!("expected MonitorError::Otel, got Ok"),
            Err(MonitorError::Otel(msg)) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            Err(other) => panic!("expected MonitorError::Otel, got {other:?}"),
        }
    }

    #[test]
    fn error_variants_carry_distinct_messages() {
        // Two distinct `Prometheus` errors must not collapse to the same
        // string — the monitor's reconcile loop dispatches on `Display`
        // content for retry/backoff (ADR-034 reject-and-repair).
        let a = MonitorError::Prometheus("scrape timeout".into());
        let b = MonitorError::Prometheus("label cardinality".into());
        assert_ne!(a.to_string(), b.to_string());
        assert_ne!(a.to_string(), MonitorError::Otel("x".into()).to_string());
    }

    // ========================================================================
    // New tests — MetricsRegistry (ADR-057 metric set).
    // ========================================================================

    #[tokio::test]
    async fn metrics_registry_increments_as_req_total_and_renders() {
        // `as_req_total{realm, etype}` — verify the counter increments
        // and renders in Prometheus exposition 0.0.4 format with the
        // `# TYPE ... counter` line.
        let reg = MetricsRegistry::new();
        reg.inc_as_req("ADRIAN.DEV", "aes256-cts-hmac-sha1-96")
            .await;
        reg.inc_as_req("ADRIAN.DEV", "aes256-cts-hmac-sha1-96")
            .await;
        reg.inc_as_req("ADRIAN.DEV", "aes128-cts-hmac-sha1-96")
            .await;

        let out = reg.render_prometheus().await;
        assert!(
            out.contains("# TYPE adrian_as_req_total counter"),
            "missing TYPE line: {out}"
        );
        assert!(
            out.contains(
                r#"adrian_as_req_total{realm="ADRIAN.DEV",etype="aes256-cts-hmac-sha1-96"} 2"#
            ),
            "missing counter line for aes256 (expected count=2): {out}"
        );
        assert!(
            out.contains(
                r#"adrian_as_req_total{realm="ADRIAN.DEV",etype="aes128-cts-hmac-sha1-96"} 1"#
            ),
            "missing counter line for aes128 (expected count=1): {out}"
        );
    }

    #[tokio::test]
    async fn metrics_registry_renders_gauges_krbtgt_and_replication_lag() {
        // `krbtgt_key_age_seconds` (no labels) + `replication_lag_seconds`
        // (labels source_dc, target_dc) + `rid_pool_remaining` (labels
        // domain_sid) — all three must render as `# TYPE ... gauge` with
        // the `adrian_` prefix per ADR-057 §Decision.
        let reg = MetricsRegistry::new();
        reg.set_krbtgt_key_age(86_400.0).await;
        reg.set_replication_lag("dc01", "dc02", 12.5).await;
        reg.set_rid_pool_remaining("S-1-5-21-...", 999.0).await;

        let out = reg.render_prometheus().await;
        assert!(
            out.contains("# TYPE adrian_krbtgt_key_age_seconds gauge"),
            "{out}"
        );
        assert!(out.contains("adrian_krbtgt_key_age_seconds 86400"), "{out}");
        assert!(
            out.contains(
                r#"adrian_replication_lag_seconds{source_dc="dc01",target_dc="dc02"} 12.5"#
            ),
            "{out}"
        );
        assert!(
            out.contains(r#"adrian_rid_pool_remaining{domain_sid="S-1-5-21-..."} 999"#),
            "{out}"
        );
    }

    #[tokio::test]
    async fn metrics_registry_histogram_observes_buckets_and_count() {
        // `as_req_duration_seconds` + `ldap_query_duration_seconds{scope}`
        // — histograms must emit `_bucket{le="..."} N`, `_sum S`,
        // `_count C`, plus the `+Inf` cumulative bucket per exposition 0.0.4.
        let reg = MetricsRegistry::new();
        reg.observe_as_req_duration(0.0005).await; // falls in le=0.001 bucket
        reg.observe_as_req_duration(0.05).await; // falls in le=0.05 bucket
        reg.observe_as_req_duration(10.0).await; // falls in +Inf bucket (above 5.0)
        reg.observe_ldap_query_duration("subtree", 0.01).await;

        let out = reg.render_prometheus().await;
        // Check the +Inf bucket (cumulative = total count = 3).
        assert!(
            out.contains("adrian_as_req_duration_seconds_bucket{le=\"+Inf\"} 3"),
            "missing +Inf bucket with count=3: {out}"
        );
        assert!(
            out.contains("adrian_as_req_duration_seconds_count 3"),
            "missing _count line: {out}"
        );
        // Sum should be ~10.0505 (with float rounding).
        assert!(out.contains("adrian_as_req_duration_seconds_sum"), "{out}");
        // LDAP histogram with scope label — cumulative bucket at le=0.01
        // should be 1 (the 0.01 observation falls in le=0.01).
        assert!(
            out.contains(
                r#"adrian_ldap_query_duration_seconds_bucket{scope="subtree",le="0.01"} 1"#
            ),
            "missing LDAP cumulative le=0.01 bucket: {out}"
        );
        assert!(
            out.contains(
                r#"adrian_ldap_query_duration_seconds_bucket{scope="subtree",le="+Inf"} 1"#
            ),
            "missing LDAP +Inf bucket: {out}"
        );
    }

    #[tokio::test]
    async fn metrics_registry_fdb_operations_counter_renders() {
        // `fdb_operations_total{op_type}` — verify the counter increments
        // for multiple op types and renders with the op_type label.
        let reg = MetricsRegistry::new();
        reg.inc_fdb_operation("get").await;
        reg.inc_fdb_operation("get").await;
        reg.inc_fdb_operation("put").await;

        let out = reg.render_prometheus().await;
        assert!(
            out.contains(r#"adrian_fdb_operations_total{op_type="get"} 2"#),
            "{out}"
        );
        assert!(
            out.contains(r#"adrian_fdb_operations_total{op_type="put"} 1"#),
            "{out}"
        );
    }

    // ========================================================================
    // New tests — AuditPipeline + sinks (ADR-060).
    // ========================================================================

    #[tokio::test]
    async fn log_audit_sink_writes_event_without_error() {
        // The `LogAuditSink` writes a JSON-lines representation of the
        // event via `tracing`. The test exercises the sink directly —
        // success means no `AuditError` was raised and the event was
        // serialised without panicking.
        let sink = LogAuditSink::new();
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::KerberosAsReq,
            principal: Some("admin@ADRIAN.DEV".into()),
            source_ip: Some("10.0.0.1".into()),
            outcome: AuditOutcome::Success,
            details: serde_json::json!({"etype": "aes256-cts-hmac-sha1-96"}),
        };
        sink.write(event).await.expect("log sink should succeed");
    }

    #[tokio::test]
    async fn otel_audit_sink_stub_returns_ok_and_increments_count() {
        // The `OtelAuditSink` is a stub that records the event count
        // (per the task spec: "stub that returns Ok"). Verify the count
        // increments after each `write()` call.
        let sink = OtelAuditSink::new();
        assert_eq!(sink.events_seen(), 0, "fresh sink should have 0 events");
        let event = AuditEvent::new(AuditEventType::DcSyncAttempt, AuditOutcome::Denied);
        sink.write(event)
            .await
            .expect("otel sink stub should return Ok");
        assert_eq!(sink.events_seen(), 1, "sink should have seen 1 event");
        // Write a few more.
        for _ in 0..3 {
            let event = AuditEvent::new(AuditEventType::LdapBind, AuditOutcome::Success);
            sink.write(event)
                .await
                .expect("otel sink stub should return Ok");
        }
        assert_eq!(
            sink.events_seen(),
            4,
            "sink should have seen 4 events total"
        );
    }

    #[tokio::test]
    async fn audit_pipeline_dispatches_event_to_sink() {
        // The `AuditPipeline` forwards events to its sink. Verify by
        // plugging in an `OtelAuditSink` (which counts events) and
        // emitting through the pipeline. The typed `Arc<OtelAuditSink>`
        // is kept so the test can read `events_seen()` directly.
        let otel = Arc::new(OtelAuditSink::new());
        let pipeline = AuditPipeline::new(otel.clone());
        let event = AuditEvent::new(AuditEventType::KrbtgtRotation, AuditOutcome::Success);
        pipeline
            .emit(event)
            .await
            .expect("pipeline emit should succeed");
        assert_eq!(otel.events_seen(), 1, "otel sink should have seen 1 event");
    }

    #[tokio::test]
    async fn monitor_service_emit_audit_routes_through_pipeline() {
        // The `MonitorService` is the top-level facade — `emit_audit()`
        // MUST route through its `audit_pipeline` to the configured sink.
        // Verify by constructing a monitor with an `OtelAuditSink` and
        // emitting an event.
        let otel = Arc::new(OtelAuditSink::new());
        let monitor = MonitorService::with_sink(otel.clone());
        let event = AuditEvent::new(
            AuditEventType::SmbShareMount,
            AuditOutcome::Failure("permission denied".into()),
        );
        monitor
            .emit_audit(event)
            .await
            .expect("monitor emit_audit should succeed");
        assert_eq!(otel.events_seen(), 1);
    }

    #[test]
    fn audit_event_type_renders_stable_event_names() {
        // The OTel log-record `Body` field is `adrian.<domain>.<action>`
        // per ADR-060 §Decision. Verify every variant maps to a stable
        // name — SIEM rules key on these names.
        assert_eq!(
            AuditEventType::KerberosAsReq.as_event_name(),
            "adrian.kerberos.as_req"
        );
        assert_eq!(
            AuditEventType::KerberosTgsReq.as_event_name(),
            "adrian.kerberos.tgs_req"
        );
        assert_eq!(AuditEventType::LdapBind.as_event_name(), "adrian.ldap.bind");
        assert_eq!(
            AuditEventType::LdapModify.as_event_name(),
            "adrian.ldap.modify"
        );
        assert_eq!(
            AuditEventType::PasswordChange.as_event_name(),
            "adrian.identity.password_change"
        );
        assert_eq!(
            AuditEventType::CertEnroll.as_event_name(),
            "adrian.pki.cert_enroll"
        );
        assert_eq!(
            AuditEventType::SmbShareMount.as_event_name(),
            "adrian.file.share_mount"
        );
        assert_eq!(
            AuditEventType::KrbtgtRotation.as_event_name(),
            "adrian.kdc.krbtgt_rotation"
        );
        assert_eq!(
            AuditEventType::DcSyncAttempt.as_event_name(),
            "adrian.security.dcsync_attempt"
        );
    }

    #[test]
    fn audit_event_serde_round_trip_preserves_fields() {
        // The audit event MUST round-trip through serde without loss — the
        // OTel log pipeline serialises events to JSON before transport.
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::DcSyncAttempt,
            principal: Some("svc-drs$@ADRIAN.DEV".into()),
            source_ip: Some("10.0.0.50".into()),
            outcome: AuditOutcome::Denied,
            details: serde_json::json!({"control_access": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"}),
        };
        let json = serde_json::to_string(&event).expect("serialize audit event");
        let back: AuditEvent = serde_json::from_str(&json).expect("deserialize audit event");
        assert_eq!(back.event_type, AuditEventType::DcSyncAttempt);
        assert_eq!(back.principal.as_deref(), Some("svc-drs$@ADRIAN.DEV"));
        assert_eq!(back.outcome, AuditOutcome::Denied);
        assert_eq!(
            back.details.get("control_access").and_then(|v| v.as_str()),
            Some("{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}")
        );
    }
}
