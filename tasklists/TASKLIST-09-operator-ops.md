# TASKLIST 09 — Operator, Monitor & Ops

**Domain**: K8s operator + monitoring/metrics + migration + GPO translation + test harness
**Branch**: `domain-09-operator-ops`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-operator/src/lib.rs`
- `rust/crates/adrian-operator/Cargo.toml`
- `rust/crates/adrian-monitor/src/lib.rs`
- `rust/crates/adrian-monitor/Cargo.toml`
- `rust/crates/adrian-migrate/src/lib.rs`
- `rust/crates/adrian-migrate/Cargo.toml`
- `rust/crates/adrian-gpo-translate/src/lib.rs`
- `rust/crates/adrian-gpo-translate/Cargo.toml`
- `rust/crates/adrian-test-harness/src/lib.rs`
- `rust/crates/adrian-test-harness/Cargo.toml`
- `rust/crates/adrian-test-harness/benches/*.rs`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `adrian-operator` (1507 lines): Real `kube::Client` + controller-runtime pattern. `DomainController` CRD (adrian.io/v1alpha1). Reconcile creates/updates/deletes StatefulSet. 22 tests.
- `adrian-monitor` (1005 lines): `MetricsRegistry` real with producers in KDC hot paths. No Prometheus export endpoint. 8 tests.
- `adrian-migrate` (202 lines): STUB. 1 TODO.
- `adrian-gpo-translate` (173 lines): STUB. 1 TODO.
- `adrian-test-harness` (1364 lines): In-process fixtures (DirectoryStore + KDC + kpasswd). Criterion benchmarks for AS-REQ/TGS-REQ/AES-CTS. 16 tests.

## Known Gaps

1. **No Prometheus metrics export** — `MetricsRegistry` collects metrics but doesn't expose them via HTTP `/metrics` endpoint.
2. **No OpenTelemetry tracing export** — `tracing` spans exist but no OTLP exporter configured.
3. **No health/readiness probes** — the operator's StatefulSet doesn't have liveness/readiness probes.
4. **Migration is a stub** — `adrian-migrate` doesn't migrate AD objects to Adrian.
5. **GPO translation is a stub** — `adrian-gpo-translate` doesn't convert ADMX/ADML to declarative JSON.
6. **No runbooks** — ADR-059 specifies PITR runbooks but none exist.
7. **No `cargo audit`** — supply chain vulnerability scanning not configured.
8. **Test harness lacks FDB fixtures** — only in-memory fixtures; no `TestFdbHarness` that spins up a real FDB cluster.

---

## Wave 1: Prometheus metrics export + OTLP tracing

**DoD**: `/metrics` endpoint serves Prometheus-format metrics. OTLP exporter sends traces to a collector.

### Tasks

- T-101: Implement `MetricsServer::serve(addr)` — axum HTTP server that serves `/metrics` returning Prometheus text format.
- T-102: Wire `MetricsRegistry::to_prometheus_text()` — render all counters/histograms as Prometheus format.
- T-103: Add OTLP exporter — `init_telemetry(otlp_endpoint)` sets up `tracing-opentelemetry` with OTLP gRPC exporter.
- T-104: Add metrics for: AS-REQ count + duration, TGS-REQ count + duration, LDAP search count, SMB read/write bytes, replication lag.
- T-105: Add 5 tests (metrics endpoint returns 200, metrics contain expected names, OTLP exporter initializes, counter increments, histogram observes values).
- T-106: Commit `Wave 1: Prometheus export + OTLP tracing (+5 tests)`

## Wave 2: Health/readiness probes + operator hardening

**DoD**: StatefulSet has liveness + readiness probes. Operator handles leader election (only one reconcile loop at a time).

### Tasks

- T-201: Implement `health_server::serve(addr)` — axum HTTP server with `/healthz` (liveness) and `/readyz` (readiness) endpoints.
- T-202: Add liveness probe — returns 200 if the process is alive.
- T-203: Add readiness probe — returns 200 if the DSA is ready to serve (KDC started, directory connected).
- T-204: Implement leader election — use `kube::runtime::leader_election` to ensure only one operator instance reconciles at a time.
- T-205: Add the probes to the StatefulSet manifest in `adrian-operator`.
- T-206: Add 4 tests (health endpoint returns 200, ready endpoint returns 503 when DSA not ready, leader election acquires lease, leader election releases lease on shutdown).
- T-207: Commit `Wave 2: Health/readiness probes + leader election (+4 tests)`

## Wave 3: AD migration + GPO translation

**DoD**: `adrian-migrate` reads AD objects via LDAP and writes them to Adrian. `adrian-gpo-translate` converts ADMX to declarative JSON.

### Tasks

- T-301: Implement `Migrator::from_ad(ldap_url, bind_dn, password)` — connects to an AD domain controller via LDAP.
- T-302: Implement `Migrator::migrate_users()` — reads all user objects, writes them to Adrian's directory store.
- T-303: Implement `Migrator::migrate_groups()` — reads all groups, writes them to Adrian.
- T-304: Implement `Migrator::migrate_gpos()` — reads GPOs from SYSVOL, translates them via `adrian-gpo-translate`.
- T-305: Implement `GpoTranslator::from_admx(admx_path, adml_path)` — parses ADMX/ADML and produces declarative JSON per ADR-090.
- T-306: Add 6 tests (migrate users round-trip, migrate groups, migrate GPOs, ADMX parse, ADMX→JSON translation, unknown ADMX template rejected).
- T-307: Commit `Wave 3: AD migration + GPO translation (ADMX→JSON) (+6 tests)`

## Wave 4: Runbooks + cargo audit + test harness FDB fixtures

**DoD**: Runbooks exist for common ops. `cargo audit` runs in CI. Test harness has FDB fixtures.

### Tasks

- T-401: Write `runbooks/01-join-domain.md` — how to join a Linux host to an Adrian domain.
- T-402: Write `runbooks/02-rotate-krbtgt.md` — how to rotate the krbtgt key.
- T-403: Write `runbooks/03-restore-from-backup.md` — how to restore from a snapshot + PITR.
- T-404: Write `runbooks/04-debug-replication.md` — how to diagnose replication lag.
- T-405: Add `cargo audit` to the dev workflow — `cargo install cargo-audit && cargo audit`.
- T-406: Implement `TestFdbHarness` in `adrian-test-harness` — starts a local FDB server, returns a `FdbDirectoryStore` connected to it.
- T-407: Add 3 tests (FDB harness starts, FDB harness write/read round-trip, FDB harness snapshot/restore).
- T-408: Commit `Wave 4: Runbooks + cargo audit + FDB test fixtures (+3 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-operator -p adrian-monitor -p adrian-migrate -p adrian-gpo-translate -p adrian-test-harness` — all tests pass
- `cargo clippy` clean for all 5 crates
- `cargo fmt --all --check` clean
- `cargo audit` passes (no vulnerabilities)
- Branch pushed, PR opened against `main`
