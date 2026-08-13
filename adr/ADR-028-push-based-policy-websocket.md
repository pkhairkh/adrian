---
title: "ADR-028: Push-based policy updates via WebSocket"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-051
severity: medium
tags: [adr, policy-engine, push, websocket, real-time]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/02-gpo-processing-order.md
  - ../docs/04-group-policy/01-gpo-architecture.md
  - ./ADR-025-transactional-policy-rollback.md
  - ./ADR-027-http-head-slow-link-detection.md
last_updated: 2026-08-13
---

# ADR-028: Push-based policy updates via WebSocket

## Status

Accepted — 2026-08-13.

## Context

AD GPO background refresh defaults to 90 minutes + 0–30 minute jitter (registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\System\GroupPolicyRefreshRate = 90` and `GroupPolicyRefreshRateRand = 30`), per [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md). DCs have a separate setting (`GroupPolicyRefreshRateDC`). Some CSEs are excluded from background refresh entirely: Folder Redirection (logon only), Software Install (logon only), Scripts (boot/logon only). For these, an admin must either trigger `gpupdate /force` on each host or wait for the next boot/logon.

For security-sensitive policies — LAPS password rotation (when changed via GPO), account lockout threshold changes, audit policy updates, Windows Defender signature toggles — a 90–120 minute propagation window is too slow. An attacker who exploits a known vulnerability within that window benefits from the lag. Manual `gpupdate /force` is the workaround; in a 10,000-host fleet this is operationally infeasible, per [PC-051](../catalog/04-policy-engine.md).

The framework must support push-based refresh (webhook from server to client) for urgent security policies, per-policy priority (urgent security policy pushes immediately, routine policy batches), and per-policy TTL. For AD interop, the framework must preserve the 90-min + jitter pull model for legacy Windows clients running `gpsvc.dll` (not the framework's Client SDK).

Cross-platform considerations: macOS MDM has push (APNs) but only for MDM commands, not for arbitrary policy; Linux SSSD is pull-based at 30-second `ad_gpo_refresh_interval` with no push model. The framework's push model must work across all three platforms — WebSocket or gRPC stream is platform-agnostic, per [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

## Decision

The framework shall support push-based policy updates via WebSocket, with a hybrid model where push notification triggers immediate pull (server tells client "refresh now" and client pulls the actual policy payload). The framework shall retain background refresh (90 min + jitter) for non-urgent policies and per-policy TTL for change windows.

1. **Push transport** — the framework's Client SDK opens a WebSocket connection to `wss://<policy-distribution-host>/api/v1/push?client_id=<host-id>`. The connection is authenticated via the host's Kerberos credentials (GSS-API negotiation over the WebSocket handshake) or a client certificate. The connection is kept alive with a 30-second ping/pong; on disconnect, the client reconnects with exponential backoff (1s, 2s, 4s, ... capped at 60s).
2. **Push message format** — the server sends JSON messages over the WebSocket: `{"type": "refresh", "policy_id": "<uuid>", "priority": "urgent"|"normal", "version": "<git-sha>"}`. The client does not receive the policy payload over the WebSocket — it receives a refresh notification and then pulls the payload via HTTPS GET to the policy distribution endpoint.
3. **Per-policy priority** — each policy has a `priority` field: `urgent` (push immediately on change) or `normal` (batch into the next background refresh). Urgent policies trigger a push notification on commit; normal policies are picked up by the client's background refresh.
4. **Per-policy TTL** — each policy has an optional `ttl_seconds` field. If set, the policy auto-reverts after the TTL expires (per ADR-031). This supports change-window semantics ("apply this emergency policy for 4 hours, then revert").
5. **Hybrid model** — push notification triggers immediate pull. The server does not push the payload because: (a) the payload may be large (Software Install package), (b) the client may need to perform slow-link detection (per ADR-027) before deciding whether to apply, (c) the client may need to perform transactional snapshot (per ADR-025) before apply. The push is a "wake up and check" signal, not a "here is the policy" delivery.
6. **AD interop** — for legacy Windows hosts running `gpsvc.dll` (not the framework's Client SDK), the framework's policy distribution endpoint supports `Win32_NetworkAdapterConfiguration`-style triggers via the existing `gpupdate /force` RPC (MS-GPAC). The framework provides a CLI `adrian-policy push --host <name>` and `adrian-policy push --group <name>` that triggers immediate refresh on framework-aware clients via WebSocket and on legacy clients via `gpupdate /force` RPC.
7. **Background refresh retained** — the framework retains the 90-min + jitter background refresh for non-urgent policies and as a fallback when the WebSocket is disconnected. If the WebSocket is down, the client falls back to background refresh (with a warning logged).

**Concrete specification**:

- The WebSocket endpoint is `wss://<policy-distribution-host>/api/v1/push?client_id=<host-id>`.
- Authentication: GSS-API (Kerberos) on Windows and Linux; client certificate on macOS (where GSS-API is less common). Both options supported.
- Keepalive: 30-second ping/pong. If the server does not receive a pong within 60 seconds, it considers the client disconnected.
- Reconnect: exponential backoff (1s, 2s, 4s, ..., capped at 60s). After 10 failed reconnects, the client falls back to background refresh only and raises an alert.
- Push message JSON schema: `{"type": "refresh"|"invalidate"|"pong", "policy_id": "<uuid>", "priority": "urgent"|"normal", "version": "<git-sha>", "ttl_seconds": <int>}`.
- On receiving a `refresh` message, the client immediately initiates a policy pull (HTTPS GET to the policy distribution endpoint), performs slow-link detection (per ADR-027), performs transactional apply (per ADR-025), and reports apply status back to the server via a WebSocket message (`{"type": "apply_result", "policy_id": "<uuid>", "status": "success"|"failure", "error": "<string>"}`).
- The framework's policy authoring UI exposes `priority` (urgent/normal) and `ttl_seconds` as policy metadata fields.
- The framework's `adrian-policy push --policy <id>` CLI triggers a push to all clients subscribed to that policy; `adrian-policy push --host <name>` triggers a push to a single client.
- Push history is logged for audit (per ADR-060): which policy was pushed, to how many clients, success/failure counts.

## Rationale

Three alternatives were considered.

**Alternative 1: MQTT.** Rejected because MQTT requires a broker (Mosquitto, EMQX) as additional infrastructure. The framework's policy distribution endpoint is already an HTTPS server; adding WebSocket to it is a smaller incremental cost than deploying and operating a separate MQTT broker. MQTT is also less familiar to enterprise operators than HTTP/WebSocket.

**Alternative 2: gRPC server-streaming.** Rejected because gRPC server-streaming requires HTTP/2 (which is widely available but not universal in enterprise networks — some proxies and firewalls mangle HTTP/2). WebSocket works over HTTP/1.1 upgrade, which is universally supported. gRPC also requires protobuf schema management; WebSocket with JSON is simpler for the framework's internal protocol.

**Alternative 3: Push the policy payload over the push channel.** Rejected because the payload may be large (Software Install package can be hundreds of MB), the client may need to perform slow-link detection before deciding whether to apply, and the client may need to perform transactional snapshot before apply. Hybrid (push notification + pull payload) gives the client control over the apply flow.

The decision aligns with industry practice: Kubernetes uses WebSocket (`kubectl exec`, `kubectl port-forward`) and watch APIs (etcd watch) for push notifications; HashiCorp Consul uses long-poll and gRPC stream for service discovery; Jamf Pro uses APNs push for MDM commands. WebSocket is a well-understood push mechanism with broad client library support across all three platforms.

Cost: ~4 person-weeks for the WebSocket client (reconnect logic, authentication, message handling), the server-side push fan-out, and the CLI/UI exposure.

## Consequences

**Positive**. Urgent security policies propagate in seconds, not 90 minutes. Per-policy TTL supports change-window semantics ("apply for 4 hours, then revert") without operator intervention. Per-policy priority lets operators mark critical policies as urgent and routine policies as normal, avoiding push fatigue. The hybrid model (push notification + pull payload) gives the client control over apply flow (slow-link check, transactional snapshot, dry-run preview).

**Negative**. The WebSocket connection is a long-lived stateful connection on the server — at 10,000 hosts, the server maintains 10,000 WebSockets. This is a real operational cost (memory: ~50 KB per WebSocket = ~500 MB; file descriptors: 10,000; CPU: keepalive processing). The server must be horizontally scalable with WebSocket affinity (a load balancer that routes a host's WebSocket to a specific backend, or a shared pubsub layer like Redis for fan-out).

**Neutral**. The hybrid model (push + pull) means the push channel is not on the critical path for apply — if the WebSocket is down, the client falls back to background refresh. This is operationally robust but means push is best-effort, not guaranteed. For policies that must apply within seconds (e.g., "disable SMBv1 now"), the framework provides `adrian-policy push --policy <id> --wait` which blocks until all targeted clients acknowledge apply or timeout.

**Implementation cost**. ~4 person-weeks for the WebSocket client, server-side push fan-out, and CLI/UI. Server-side horizontal scaling with WebSocket affinity is additional effort (~2 person-weeks for the Redis pubsub integration).

**Operational impact**. Operators use `adrian-policy push --policy <id>` for urgent changes (replaces `gpupdate /force` fleet-wide). Push history is auditable (per ADR-060). WebSocket connection health is monitored (per ADR-057 OTel instrumentation); disconnected clients are alerted.

## Alternatives Considered

### Alternative A: MQTT

Use MQTT as the push transport. The framework's policy distribution service publishes to an MQTT broker; clients subscribe to their host-id topic.

Rejected because MQTT requires a broker (Mosquitto, EMQX) as additional infrastructure — deployment, configuration, monitoring, HA clustering. The framework's policy distribution endpoint is already an HTTPS server; adding WebSocket to it is a smaller incremental cost than operating a separate MQTT broker. MQTT is also less familiar to enterprise operators than HTTP/WebSocket, increasing the operational learning curve. MQTT's quality-of-service levels (QoS 0/1/2) add complexity that the framework does not need (the hybrid model means push is best-effort anyway).

### Alternative B: gRPC server-streaming

Use gRPC server-streaming for push. The client opens a long-lived gRPC stream; the server sends `RefreshNotification` messages.

Rejected because gRPC requires HTTP/2 (which is widely available but not universal in enterprise networks — some proxies and firewalls mangle HTTP/2). WebSocket works over HTTP/1.1 upgrade, which is universally supported. gRPC also requires protobuf schema management — every change to the push message format requires regenerating stubs in all client languages. WebSocket with JSON is simpler for the framework's internal protocol. gRPC is the right choice for high-throughput streaming (per ADR-061 for the framework's external API); WebSocket is the right choice for low-frequency push notifications.

### Alternative C: Push payload over the push channel

Send the full policy payload over the WebSocket, not just a refresh notification. The client applies immediately on receipt.

Rejected because (a) the payload may be large (Software Install package can be hundreds of MB), making WebSocket delivery inefficient (WebSocket framing overhead per message); (b) the client may need to perform slow-link detection (per ADR-027) before deciding whether to apply — pushing the payload over a slow link wastes bandwidth; (c) the client may need to perform transactional snapshot (per ADR-025) before apply, which requires local state preparation; (d) the hybrid model (push notification + pull payload) lets the client pull via HTTPS with HTTP/2 multiplexing, cache headers, and CDN distribution — none of which WebSocket provides. The push channel's job is "wake up and check," not "deliver the payload."

## Open Questions

- Should the framework support multiple push transports (WebSocket primary, MQTT optional, APNs for macOS MDM integration)? The current decision is WebSocket-only for simplicity; revisit if operators request MQTT (e.g., for IoT scenarios) or APNs integration.
- The server-side WebSocket fan-out: should it use Redis pubsub, NATS, or a custom Raft-based broker? Redis is the simplest; NATS is purpose-built; custom Raft is over-engineered. Current decision: Redis.
- The `adrian-policy push --wait` blocking call: what is the default timeout? 60 seconds is reasonable for urgent security policies; tunable per-call.
- Per-policy TTL: should TTL-expired policies auto-revert via push (server pushes "revert" notification) or via client-side TTL check (client reverts at TTL expiry even if disconnected)? Client-side TTL check is more robust (works offline); server-push is faster (immediate revert). Current decision: both — server pushes on TTL expiry, client falls back to client-side check if disconnected.

## Cross-capability impact

- **Policy Engine (PC-051)**: This ADR. PC-050 (slow-link, ADR-027) — push-triggered refreshes skip the slow-link probe (the push implies the link is up); pull refreshes perform the probe.
- **Policy Engine (PC-048)**: ADR-025 (transactional apply) — push-triggered applies go through the same transactional path as pull-triggered applies, with snapshot and rollback.
- **Policy Engine (PC-056)**: ADR-031 (Git-backed policy history) — push notifications carry the git SHA, enabling clients to verify they received the intended version.
- **Operations (PC-106..PC-115)**: ADR-057 (OTel instrumentation) — WebSocket connection health and push latency are OTel metrics.
- **Operations (PC-106..PC-115)**: ADR-060 (audit logs in OTel) — push history (who pushed what when, apply results) is an audit event.
- **Client SDK (PC-085..PC-093)**: The WebSocket client lives in the Client SDK; ORQ-169/170 (Client SDK architecture) gates the implementation language.

## References

- [PC-051](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md) — Background refresh interval, per-CSE refresh exclusions, `GroupPolicyRefreshRate` registry
- [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md) — `gpsvc.dll` notification timer, `gpupdate.exe` entry points
- [RFC 6455 WebSocket](https://www.rfc-editor.org/rfc/rfc6455) — WebSocket protocol
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol (for legacy `gpupdate /force` interop)
- [Kubernetes Watch API](https://kubernetes.io/docs/reference/using-api/api-concepts/) — industry precedent for push notifications over WebSocket
