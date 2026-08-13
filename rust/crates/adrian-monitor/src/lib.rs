//! # adrian-monitor
//!
//! Observability — Prometheus metrics endpoint + OpenTelemetry trace exporter.
//! Subscribes to KDC / LDAP / SMB / replication events; exposes framework-
//! specific metrics on top of the standard `prometheus` registry.
//!
//! ## ADRs
//!
//! - ADR-057: Prometheus + OpenTelemetry observability
//! - ADR-060: Structured audit logs (OTel)
//! - ADR-023: Kerberos audit events
//! - ADR-034: Transactional DB PITR; reject-and-repair observability
//! - ADR-059: PITR backup / DR runbooks (monitoring hooks)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("prometheus: {0}")]
    Prometheus(String),
    #[error("otel: {0}")]
    Otel(String),
}

/// Monitor service — owns the metrics registry and OTel exporter.
pub struct Monitor {
    // TODO: hold prometheus::Registry, OTel tracer provider
}

impl Monitor {
    pub fn new() -> Self {
        Self {}
    }

    /// Build the `/metrics` axum router for Prometheus scraping.
    pub fn metrics_router(&self) -> axum::Router {
        // TODO: wire /metrics, /healthz
        axum::Router::new()
    }

    /// Install the OTel OTLP exporter (traces + metrics).
    pub fn install_otel(&self) -> Result<(), MonitorError> {
        // TODO: install pipeline per ADR-057
        Err(MonitorError::Otel("not yet implemented".into()))
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-monitor`. Per the task instructions these
    //! cover type construction, error types, and the loud-stub behaviour of
    //! `Monitor::install_otel` — no real Prometheus scrape or OTel OTLP
    //! exporter is started.

    use super::*;

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
        // `Monitor`. Catches the regression where a field is added to
        // `Monitor` and one constructor is forgotten.
        let _a = Monitor::default();
        let _b = Monitor::new();
        // `Monitor` doesn't derive Debug/PartialEq (TODO fields), so we
        // exercise the seam by calling `metrics_router()` on each — if
        // either constructor dropped a required init step, this would panic.
        let _ra = Monitor::default().metrics_router();
        let _rb = Monitor::new().metrics_router();
    }

    #[test]
    fn metrics_router_constructs_without_panic() {
        // Until the `/metrics` and `/healthz` routes are wired in (TODO in
        // lib.rs), `metrics_router()` must return a usable empty
        // `axum::Router` rather than panic. Guards the seam so Wave 4c
        // integration only needs to swap the body.
        let monitor = Monitor::new();
        let _router = monitor.metrics_router();
    }

    #[test]
    fn install_otel_stub_returns_otel_error() {
        // Loud-stub contract (ADR-057): until the OTLP exporter pipeline is
        // implemented, `install_otel` must surface `MonitorError::Otel`
        // rather than silently succeed or panic.
        let monitor = Monitor::new();
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
}
