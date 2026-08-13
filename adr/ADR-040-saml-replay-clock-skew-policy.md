---
title: "ADR-040: SAML replay detection 60-min; per-RP skew policy"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-072
severity: low
tags: [adr, federation-gateway, saml, replay-detection, clock-skew, ntp]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../docs/06-federation-sso/02-saml-ws-fed.md
  - ../docs/06-federation-sso/01-adfs-architecture.md
  - ./ADR-022-ntp-via-chrony.md
  - ./ADR-038-jwks-endpoint-webhook-rollover.md
last_updated: 2026-08-13
---

# ADR-040: SAML replay detection 60-min; per-RP skew policy

## Status

Accepted — 2026-08-13.

## Context

Per [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), AD FS SAML replay detection caches assertion IDs (the `ID` attribute on `<saml2:Assertion>`) for 60 minutes. If the same assertion ID is submitted twice within the window, the second submission is rejected with `MSIS7029 — The SAML message has already been processed`. Clock skew tolerance is 5 minutes either side — if `IssueInstant` is outside the `NotBefore`/`NotOnOrAfter` window (with 5-min skew), the response is rejected with `MSIS7042 — The SAML request has expired`. Per-RP skew override is via `Set-AdfsRelyingPartyTrust -TargetName <name> -NotBeforeSkew 5` (minutes).

The 60-min replay window is too short for slow networks or async processing (e.g., a SAML response queued for retry after 70 minutes is rejected as replay). The 5-min clock skew is too tight for environments without NTP discipline (e.g., VMs with clock drift, IoT devices, legacy systems). Per the same KB, the `IssueInstant` outside the `NotBefore`/`NotOnOrAfter` window (default 60 min) is a top-3 SAML support case — typically caused by NTP misconfiguration on either IdP or SP, per [PC-072](../catalog/06-federation-gateway.md).

For the framework, the design should make both configurable per-RP and document the security/availability tradeoff: longer replay window = more vulnerable to replay attacks; tighter clock skew = more vulnerable to NTP drift. Per-RP skew policy (high-security RP = 0 min skew, legacy RP = 15 min skew) is the right granularity. Auto-sync clocks via NTP before SAML (a pre-SAML NTP check) is a defensive measure.

The framework must support per-RP skew override (`NotBeforeSkew`), configurable replay detection window (default 60 min, per-RP override), and NTP-based clock sync verification before SAML (defensive). ADR-022 (NTP via chrony) underpins the time-sync prerequisite for this ADR.

## Decision

The framework shall enforce SAML replay detection with a configurable per-RP window (default 60 minutes), per-RP clock skew policy (default 5 minutes, configurable per-RP including 0 min for high-security RPs and up to 15 min for legacy RPs), and a pre-SAML NTP sync verification as a defensive measure.

1. **Replay detection** — the framework caches every received SAML assertion ID (`<saml2:Assertion ID="...">`) in a per-RP replay cache for the configured window (default 60 minutes). If the same assertion ID is submitted twice within the window, the second submission is rejected with HTTP 400 and error code `saml_replay_detected`. The replay cache is per-RP (an assertion ID can be reused across RPs, since each RP validates independently) and per-federation-node (the cache is not shared across nodes in a cluster — each node maintains its own cache, with the assertion ID keyed by RP+node).
2. **Configurable replay window** — the replay window is configurable per-RP: `replay_window_minutes` (default 60, range 1–1440). High-security RPs use shorter windows (e.g., 10 min) to minimize replay attack surface; async-flow RPs use longer windows (e.g., 240 min) to accommodate queued retries.
3. **Per-RP clock skew policy** — each RP declares a `clock_skew_minutes` setting (default 5, range 0–15). The framework accepts SAML responses whose `IssueInstant` is within `NotBefore - clock_skew_minutes` to `NotOnOrAfter + clock_skew_minutes`. High-security RPs (e.g., financial apps) set `clock_skew_minutes = 0` for strict time validation; legacy RPs (e.g., old SharePoint) set `clock_skew_minutes = 15` for tolerance to clock drift.
4. **Pre-SAML NTP verification** — before processing a SAML response, the framework checks the local clock against an NTP source (per ADR-022 — chrony). If the local clock is off by more than 30 seconds from NTP, the framework logs a warning (`framework.federation.clock_drift_detected` OTel event) but does not reject the SAML response (the per-RP skew policy handles the drift). If the local clock is off by more than 5 minutes, the framework rejects the SAML response with `saml_clock_drift_excessive` (the per-RP skew policy cannot accommodate this much drift).
5. **Default replay window and skew** — the defaults match AD FS (60-min replay, 5-min skew) for migration compatibility. Operators migrating from AD FS can retain AD FS-equivalent settings or tighten per-RP.
6. **Audit logging** — every replay rejection, clock-skew rejection, and clock-drift warning is audit-logged (per ADR-060) with: RP ID, assertion ID, `IssueInstant`, `NotBefore`/`NotOnOrAfter`, local clock, NTP clock, rejection reason.
7. **OIDC `iat`/`exp` handling** — for OIDC, the framework applies the same per-RP clock skew policy to JWT `iat` (issued-at) and `exp` (expiry) claims: a JWT is valid if `iat - clock_skew_minutes <= current_time <= exp + clock_skew_minutes`. The OIDC replay detection uses the JWT `jti` (JWT ID) claim, cached per-RP for the same window as SAML.

**Concrete specification**:

- The replay cache is an in-memory LRU cache per federation node, with entries evicted at `replay_window_minutes` expiry. For clustered deployments, each node maintains its own cache (no cross-node sharing) — a SAML response submitted to node A and replayed to node B within the window would not be detected as replay. To mitigate, the framework supports an optional Redis-backed distributed replay cache (`adrian-federation --replay-cache redis://<host>:6379`).
- Per-RP configuration: `PUT /api/v1/rps/<rp-id>/saml-policy` with `{"replay_window_minutes": 60, "clock_skew_minutes": 5}`.
- The framework's `adrian-federation check-clock` CLI checks the local clock against NTP and reports drift; it exits non-zero if drift exceeds 5 minutes (for cron-based monitoring).
- The pre-SAML NTP verification uses chrony (per ADR-022) — the framework reads `chronyc tracking` output and parses `System time` (the offset between local clock and NTP).
- Audit log events: `saml.replay_detected`, `saml.clock_skew_exceeded`, `saml.clock_drift_warning`, `oidc.replay_detected`, `oidc.clock_skew_exceeded`.
- The framework's documentation includes a SAML troubleshooting guide: "If users see `saml.clock_skew_exceeded`, verify NTP sync on the IdP and SP hosts."

## Rationale

Three alternatives were considered.

**Alternative 1: Fixed replay window and skew (no per-RP override).** Match AD FS's defaults (60-min replay, 5-min skew) and do not allow per-RP override. Rejected because different RPs have different security and availability requirements. A high-security financial RP needs strict replay (10-min window) and strict skew (0 min); a legacy SharePoint RP needs loose replay (240-min window for async flows) and loose skew (15 min for clock drift). Fixed settings force a one-size-fits-all compromise that is either too strict for legacy RPs (causing availability issues) or too loose for high-security RPs (causing security issues).

**Alternative 2: Global replay window and skew (operator-configurable, not per-RP).** A single global setting for all RPs, configurable by the operator. Rejected because it does not solve the high-security-vs-legacy-RP tradeoff. A global setting is either strict (breaks legacy RPs) or loose (weakens high-security RPs). Per-RP policy is the only way to accommodate both.

**Alternative 3: Fail-open on replay detection (log warning, accept the response).** Do not reject replayed assertions; log a warning and accept. Rejected because replay detection is a security control — accepting replayed assertions defeats the purpose. A replayed assertion could be a captured response being reused by an attacker (e.g., a man-in-the-middle captured a SAML response and is replaying it to gain unauthorized access). Fail-closed (reject on replay) is the secure default; fail-open is a security vulnerability.

The decision aligns with industry practice: Auth0, Okta, and Keycloak all support per-RP clock skew configuration; Shibboleth IdP supports per-RP replay window; mod_auth_mellon supports per-RP skew. The framework's per-RP policy is the same shape.

Cost: ~3 person-weeks for the replay cache (in-memory LRU + optional Redis), the per-RP policy configuration, the pre-SAML NTP verification, and the audit logging.

## Consequences

**Positive**. Per-RP replay window and skew policy accommodate both high-security RPs (strict) and legacy RPs (loose) without compromise. Pre-SAML NTP verification surfaces clock-drift issues before they cause user-visible auth failures. Audit logging provides visibility into replay and clock-skew issues. OIDC `iat`/`exp` and `jti` handling is consistent with SAML.

**Negative**. Per-RP configuration adds operational complexity — operators must set replay window and skew per RP, not just globally. The optional Redis-backed distributed replay cache adds infrastructure (Redis) for clustered deployments. The pre-SAML NTP verification depends on chrony (per ADR-022) — if chrony is not deployed, the verification fails open (logs a warning, does not reject).

**Neutral**. The defaults (60-min replay, 5-min skew) match AD FS for migration compatibility. Operators migrating from AD FS can retain AD FS-equivalent settings without configuration changes.

**Implementation cost**. ~3 person-weeks for the replay cache, per-RP policy, NTP verification, and audit logging.

**Operational impact**. Operators configure per-RP replay window and skew during RP registration. The `adrian-federation check-clock` CLI is cron-monitored for clock drift. Replay and skew audit events flow into the Security capability's monitoring (per ADR-064).

## Alternatives Considered

### Alternative A: Fixed replay window and skew (no per-RP override)

Match AD FS's defaults (60-min replay, 5-min skew) and do not allow per-RP override. All RPs use the same settings.

Rejected because different RPs have different security and availability requirements. A high-security financial RP needs strict replay (10-min window) and strict skew (0 min) to minimize replay attack surface and enforce tight time validation. A legacy SharePoint RP needs loose replay (240-min window for async workflows where SAML responses are queued for retry) and loose skew (15 min for clock drift on legacy systems without NTP discipline). Fixed settings force a one-size-fits-all compromise: either too strict for legacy RPs (causing `saml.clock_skew_exceeded` and `saml.replay_detected` errors that break user auth) or too loose for high-security RPs (weakening replay protection and allowing clock-drifted assertions). Per-RP policy is the only way to accommodate both, and it matches industry practice (Auth0, Okta, Keycloak all support per-RP clock skew).

### Alternative B: Global replay window and skew (operator-configurable, not per-RP)

A single global setting for all RPs, configurable by the operator. Operators set the global replay window and skew to balance security and availability.

Rejected because it does not solve the high-security-vs-legacy-RP tradeoff. A global setting is either strict (breaks legacy RPs that need loose settings) or loose (weakens high-security RPs that need strict settings). The operator cannot satisfy both RP types with a single global value. Per-RP policy allows the operator to set strict settings for high-security RPs and loose settings for legacy RPs, accommodating both without compromise. The operational cost of per-RP configuration (one extra setting per RP at registration time) is acceptable given the flexibility gain.

### Alternative C: Fail-open on replay detection (log warning, accept the response)

Do not reject replayed assertions. Log a warning (`saml.replay_detected`) and accept the response, allowing the user to authenticate.

Rejected because replay detection is a security control — accepting replayed assertions defeats the purpose. A replayed assertion could be a captured response being reused by an attacker (e.g., a man-in-the-middle captured a SAML response and is replaying it to gain unauthorized access to the RP). Fail-closed (reject on replay) is the secure default; fail-open is a security vulnerability. The framework's design principle is "secure by default" — replay detection must fail-closed. Operators who need to accommodate async flows (where the same assertion may be legitimately submitted multiple times within the window) should increase the replay window per-RP, not disable replay detection. The audit log entry for `saml.replay_detected` provides visibility into legitimate vs. suspicious replays.

## Open Questions

- The optional Redis-backed distributed replay cache: should it be the default for clustered deployments, or opt-in? Current decision: opt-in (in-memory LRU is the default; Redis is for deployments that need cross-node replay detection); revisit if operators report cross-node replay attacks.
- The pre-SAML NTP verification: should it fail-closed (reject SAML response if NTP is unreachable, not just if drift is excessive)? Current decision: fail-open on NTP-unreachable (the per-RP skew policy handles drift; NTP-unreachable is an operational issue, not a security issue); revisit if operators report NTP-unreachable masking real drift.
- The default replay window (60 minutes): should it be shorter (30 min) for tighter security? Current decision: 60 min (matches AD FS for migration compatibility); revisit after migration completes.
- The OIDC `jti` replay detection: should it be enabled by default, or opt-in? Some OIDC clients do not send `jti`; enforcing replay detection would break them. Current decision: opt-in per-RP (the framework enables `jti` replay detection only for RPs that declare `oidc_replay_detection = true`).

## Cross-capability impact

- **Federation Gateway (PC-072)**: This ADR. PC-070 (cert rollover, ADR-038) — cert rollover interacts with clock skew (the overlap window must be longer than the maximum clock skew).
- **Auth Provider (PC-036..PC-042)**: ADR-022 (NTP via chrony) — underpins the time-sync prerequisite for SAML clock skew and OIDC `iat`/`exp` validation.
- **KDC (PC-023..PC-035)**: ADR-013 (Kerberos transited field) — Kerberos cross-realm also depends on clock sync; the same chrony infrastructure underpins both.
- **Operations (PC-106..PC-115)**: ADR-060 (audit logs) — SAML replay, clock-skew, and clock-drift events are audit-logged. ADR-057 (OTel instrumentation) — clock-drift and replay metrics are OTel events.
- **Security (PC-116..PC-123)**: ADR-064 (Kerberoast auto-detect) — SAML replay detection is a parallel security control for the federation layer.

## References

- [PC-072](../catalog/06-federation-gateway.md) — problem statement in the catalog
- [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md) — SAML assertion `Conditions/NotBefore`/`NotOnOrAfter`, replay detection 60-min cache, `MSIS7029`/`MSIS7042` errors
- [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md) — AD FS SAML endpoints, `Set-AdfsRelyingPartyTrust -NotBeforeSkew`, `SamlMessageSecureChannel.ReplayDetectionWindow`
- [SAML 2.0 Core (OASIS)](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) — SAML assertion `Conditions`, `IssueInstant`
- [RFC 7519 JWT](https://www.rfc-editor.org/rfc/rfc7519) — JWT `iat`, `exp`, `jti` claims
- [RFC 5905 NTP](https://www.rfc-editor.org/rfc/rfc5905) — NTP protocol (underpins ADR-022)
