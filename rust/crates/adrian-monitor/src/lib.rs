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
