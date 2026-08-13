---
title: "ADR-027: HTTP HEAD probe for slow-link detection"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-050
severity: low
tags: [adr, policy-engine, slow-link, network-detection, http]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/02-gpo-processing-order.md
  - ../docs/04-group-policy/01-gpo-architecture.md
  - ./ADR-028-push-based-policy-websocket.md
last_updated: 2026-08-13
---

# ADR-027: HTTP HEAD probe for slow-link detection

## Status

Accepted — 2026-08-13.

## Context

AD slow-link detection is performed by `gpsvc.dll!DetectSlowLink`, which pings the PDC emulator via ICMP three times with a default 64 KB packet, computes average RTT, and estimates link speed as `packet_size / avg_rtt`. If the estimated speed is below the `SlowLink` registry threshold (default 500 kbps at `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-...}\SlowLink`), the link is declared slow, per [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md). Slow-link triggers skip Folder Redirection (`{426031c0-...}`), Software Install (`{c6dc5466-...}`), Scripts (`{42B5FAAE-...}`) at background refresh, and most Preferences (`Files`, `Printers`, `Drives`, `Shortcuts`).

The algorithm is unreliable because ICMP is often blocked by firewalls. AWS Security Groups, Azure NSGs, and on-prem ACLs default-deny ICMP. When ICMP is blocked, `DetectSlowLink` either times out (default 60 seconds at `SlowLinkTimeOut`) and declares slow, or returns zero RTT and declares fast — depending on the failure mode. The result is that slow-link detection either always fires (causing Folder Redir / Software Install / Scripts to silently skip on every refresh) or never fires (causing these CSEs to attempt apply over saturated WAN links). Field reports of "Folder Redirection not working" frequently trace to ICMP blocked between branch and PDC, per [PC-050](../catalog/04-policy-engine.md).

The framework must support slow-link policy processing semantics for compat (the `SlowLink` registry value and per-CSE slow-link gating), and must use a more reliable detection mechanism. TCP RTT or HTTP HEAD probe is a modern alternative. Per-CSE slow-link policy (rather than all-or-nothing) is also an improvement — "skip Software Install on slow link but apply Scripts" is a common operator request.

Cross-platform considerations: macOS MDM has no slow-link concept (profiles are pushed when the device checks in); Linux SSSD has no slow-link detection (`ad_gpo_access` always attempts SMB fetch and fails-closed on timeout). The framework's slow-link model should be consistent across platforms, per [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

## Decision

The framework shall replace ICMP-based slow-link detection with HTTP HEAD probe to the framework's policy distribution endpoint, and shall support per-area slow-link policy (rather than AD's all-or-nothing per-CSE gating).

1. **Probe mechanism** — the framework's Client SDK performs an HTTP HEAD request to `https://<policy-distribution-host>/.well-known/adrian/policy-probe` with a 5-second timeout. The probe carries a small payload (a `Date` header from the server) and the client measures TTFB (time to first byte). The probe is performed three times; the median TTFB is used.
2. **Bandwidth estimation** — the framework performs one HTTP GET to `https://<policy-distribution-host>/.well-known/adrian/policy-probe?size=1MB` (a 1 MB payload) and measures throughput as `payload_size / transfer_time`. This is a more accurate bandwidth estimate than ICMP's `packet_size / rtt` because it actually transfers data.
3. **Slow-link threshold** — the framework uses a default threshold of 500 kbps (matching AD's default) but makes it per-policy-area configurable. Operators can set `slow_link_threshold_kbps` per area in the framework's policy configuration.
4. **Per-area slow-link policy** — each policy area declares its slow-link behavior: `apply_on_slow_link` (boolean, default `true` for `Security`, `AuditPolicy`, `PasswordPolicy`; default `false` for `SoftwareInstall`, `FolderRedirection`, `Preferences.Files`, `Preferences.Printers`). Operators can override per-area.
5. **Caching** — slow-link detection results are cached for 5 minutes (vs. AD's per-refresh evaluation). The cache is invalidated on network change events (the Client SDK listens for network state changes via the OS's network change notification API).
6. **Probe failure handling** — if the HTTP HEAD probe fails (timeout, connection refused, HTTP error), the framework treats the link as slow (fail-closed for bandwidth-intensive areas). This is the opposite of AD's behavior on ICMP failure (which is undefined — sometimes fast, sometimes slow). The framework's fail-closed-on-probe-failure behavior is safer: bandwidth-intensive areas skip, security areas still apply.
7. **AD interop** — for legacy Windows hosts running `gpsvc.dll` (not the framework's Client SDK), the framework's policy distribution endpoint supports ICMP ping responses (so `gpsvc.dll!DetectSlowLink` continues to work). The framework does not disable ICMP; it adds HTTP HEAD as the primary mechanism for framework-aware clients.

**Concrete specification**:

- The probe endpoint is `https://<policy-distribution-host>/.well-known/adrian/policy-probe`. The server returns HTTP 200 with a `Date` header and an empty body for HEAD, or a `size`-byte body for GET.
- The Client SDK performs the probe at the start of every policy refresh (pull or push-triggered per ADR-028).
- The probe is performed over the same TCP connection as policy retrieval (HTTP/2 multiplexing), so the connection-establishment cost is amortized.
- The framework defines a per-area `slow_link_policy` enum: `always_apply`, `skip_on_slow_link`, `warn_on_slow_link`. Defaults: `Security` → `always_apply`, `AuditPolicy` → `always_apply`, `SoftwareInstall` → `skip_on_slow_link`, `FolderRedirection` → `skip_on_slow_link`, `Preferences.Files` → `skip_on_slow_link`, `Preferences.Printers` → `skip_on_slow_link`, `Preferences.Shortcuts` → `warn_on_slow_link`.
- Slow-link detection results are exposed via `adrian-policy slow-link --host <name>` (CLI per ADR-063) and `GET /api/v1/hosts/<host>/slow-link` (REST per ADR-061).
- The framework's policy authoring UI exposes per-area slow-link policy as a drop-down.

## Rationale

Three alternatives were considered.

**Alternative 1: TCP RTT to a known port (e.g., TCP connect to port 443).** Rejected because TCP RTT measures only the handshake, not throughput. A link with low RTT but low bandwidth (e.g., satellite: 600 ms RTT, 1 Mbps) would be declared "fast" by TCP RTT alone. HTTP HEAD + HTTP GET with payload measures both latency and throughput.

**Alternative 2: Drop slow-link detection entirely; rely on per-policy TTL (per ADR-028).** Rejected because some policy areas (Software Install, Folder Redirection) genuinely should not run over slow links — a 500 MB software package over a 500 kbps link takes 8000 seconds (~2 hours), blocking the policy refresh. Slow-link detection is a real operational need; dropping it shifts the burden to operators to manually scope policies by site.

**Alternative 3: Use SMB RTT (since the framework's policy distribution uses SMB on Windows for compat).** Rejected because the framework's policy distribution is HTTP-primary (per ADR-028); SMB is a legacy compat path. Using SMB RTT would tie slow-link detection to the legacy path, defeating the framework's HTTP-first design.

The decision aligns with industry practice: cloud CDNs (Cloudflare, Akamai, Fastly) use HTTP-based latency and throughput probes for traffic routing; speed-test services (Speedtest.net, Fast.com) use HTTP download tests. ICMP is universally deprecated as a bandwidth estimation mechanism in modern network design.

Cost: ~2 person-weeks for the probe client, the per-area slow-link policy engine, and the UI/CLI exposure. The probe server endpoint is a simple addition to the framework's policy distribution service.

## Consequences

**Positive**. Slow-link detection becomes reliable: HTTP HEAD + GET probes work through firewalls that block ICMP. Per-area slow-link policy gives operators fine-grained control (apply Scripts but skip Software Install on slow links). The 5-minute cache reduces probe cost. Fail-closed-on-probe-failure behavior is safer than AD's undefined ICMP-failure behavior.

**Negative**. The probe adds ~1 second to every policy refresh (three HEAD probes + one GET). On a fast LAN this is negligible; on a slow WAN it's a small cost. The probe endpoint must be highly available — if the policy distribution host is down, every client treats every link as slow, which may cascade into "no Software Install anywhere" if the outage is widespread.

**Neutral**. The framework's slow-link model diverges from AD's per-CSE all-or-nothing model. Operators migrating from AD must re-author their slow-link policies per-area, but the migration tooling can default to AD-equivalent behavior (`skip_on_slow_link` for the same CSEs AD skips).

**Implementation cost**. ~2 person-weeks for the probe client, per-area policy engine, UI/CLI exposure.

**Operational impact**. Operators no longer debug "ICMP blocked, Folder Redir not working" — the framework's HTTP probe works through firewalls. Per-area slow-link policy is configured via the policy authoring UI, not registry edits.

## Alternatives Considered

### Alternative A: TCP RTT only

Measure TCP connect time to port 443 on the policy distribution host. Use this as the slow-link indicator.

Rejected because TCP RTT measures only the handshake, not throughput. A link with low RTT but low bandwidth (e.g., satellite: 600 ms RTT, 1 Mbps) would be declared "fast" by TCP RTT alone, causing Software Install to attempt a 500 MB download over a 1 Mbps link (taking ~70 minutes and blocking policy refresh). HTTP HEAD + GET measures both latency and throughput, producing a more accurate slow-link determination.

### Alternative B: Drop slow-link detection entirely

Eliminate slow-link detection; rely on per-policy TTL (per ADR-028) and operator-authored site scoping. If a host is at a branch site, the operator scopes bandwidth-intensive policies to not apply at that site.

Rejected because some policy areas (Software Install, Folder Redirection) genuinely should not run over slow links regardless of site. A host may be at a "fast" site but on a slow VPN connection; site scoping cannot capture this. Slow-link detection is a real operational need; dropping it shifts the burden to operators to manually scope policies by network condition, which is more fragile than automated detection.

### Alternative C: SMB RTT

Use SMB RTT to the policy distribution SMB share (which the framework exposes for Windows compat).

Rejected because the framework's policy distribution is HTTP-primary (per ADR-028); SMB is a legacy compat path. Using SMB RTT would tie slow-link detection to the legacy path, defeating the framework's HTTP-first design. Additionally, SMB RTT has the same throughput-measurement limitation as TCP RTT (Alternative A).

## Open Questions

- Should the probe cache be per-network-interface (e.g., a host with both Ethernet and Wi-Fi may have different link speeds on each)? The current decision is per-host (the slowest interface wins); revisit if mobile hosts report issues.
- The 1 MB GET probe: should the size be configurable? On metered connections (cellular), 1 MB per refresh is non-trivial. The framework should detect metered connections (via the OS's network capability API) and skip the GET probe on metered links (fall back to HEAD-only).
- The fail-closed-on-probe-failure behavior: should it be configurable per-deployment? Some operators may prefer fail-open (apply all policies on probe failure, accepting the bandwidth cost). The current decision is fail-closed for safety; revisit if operators report issues.

## Cross-capability impact

- **Policy Engine (PC-050)**: This ADR. PC-051 (background refresh, ADR-028) interacts with slow-link — push-triggered refreshes skip the slow-link probe (the push implies the link is up); pull refreshes perform the probe.
- **Operations (PC-106..PC-115)**: Slow-link detection results flow into the host's monitoring data (per ADR-057 OTel instrumentation).
- **Migration (PC-124..PC-130)**: The migration tooling translates AD's per-CSE slow-link registry settings to per-area framework policies, defaulting to AD-equivalent behavior.

## References

- [PC-050](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md) — `DetectSlowLink` algorithm, `SlowLink` registry threshold, per-CSE slow-link behavior table
- [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md) — `SlowLinkDetectEnabled`, `SlowLinkTimeOut` defaults, `GPNetworkName` PDC reference
- [RFC 9110 HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) — HTTP HEAD method
- [Cloudflare edge latency probing](https://blog.cloudflare.com/) — industry precedent for HTTP-based latency probing
