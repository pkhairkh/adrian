---
title: "ADR-043: Drop SMB1 Support Entirely"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: File Gateway
problem: PC-079
severity: blocker
tags: [adr, file-gateway, smb, smb1, security, eternal-blue, protocol-deprecation]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/07-file-gateway.md
  - ../docs/07-file-print/01-smb-shares-internals.md
  - ../docs/02-protocols/03-smb-cifs-protocol.md
last_updated: 2026-08-13
---

# ADR-043: Drop SMB1 Support Entirely

## Status

Accepted — 2026-08-13

## Context

SMB1 ("`NT LM 0.12`", advertised via the dialect string `PC NETWORK PROGRAM 1.0` and successors up through `LANMAN1.0`) is the 1985-era original SMB dialect. The framework's File Gateway capability cannot ship an SMB server that negotiates this dialect under any configuration, per [PC-079](../catalog/07-file-gateway.md#pc-079--smb1-must-be-dropped-security-liability-migration-is-automatic-on-modern-windows). The proximate cause is EternalBlue (MS17-010, CVE-2017-0144), which exploited `srvnet.sys!SrvNetWskReceiveComplete` reachable via SMB1 transaction commands; the structural cause is SMB1's lack of integrity protection (HMAC-MD5 only, with no pre-auth binding), reliance on MD4/MD5 MACs, oplock semantics incompatible with modern clustering, and dual-stack NetBIOS-over-TCP (TCP/139, UDP/137, UDP/138) alongside direct-hosted TCP/445, per the dialect-history table in [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md).

The industry has already moved on. Microsoft deprecated SMB1 server-side with Windows Server 2019 (default off, `EnableSMB1Protocol = 0` under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`) and disabled the client by default on Windows 10 1709. Samba 4.5 (2016) made `server min protocol = SMB2_02` the default. Apple's `smbfs.kext` was retired in macOS 10.14 in favor of SMBX (which negotiates SMB 2.x+ exclusively). Linux `cifs.ko` retains the `vers=1.0` mount option for legacy NAS appliances, but modern distros ship `/etc/modprobe.d/cifs.conf` with `vers=3.0` as the minimum. Microsoft's 2023 enterprise telemetry shows <0.1% of file-server traffic was SMB1, per the impact analysis in [PC-079](../catalog/07-file-gateway.md#pc-079--smb1-must-be-dropped-security-liability-migration-is-automatic-on-modern-windows).

The framework cannot retain SMB1 for "legacy compat" without inheriting a recurring source of wormable vulnerabilities. EternalBlue-class exploit tooling is still in active red-team circulation, and the SMB1 dispatch code path (`srv.sys`-equivalent in any reimplementation, or Samba's `source3/smbd/server.c` history) carries a multi-year tail of patch surface that the framework would have to re-litigate. Retaining SMB1 also forces the framework to ship NetBIOS name/datagram services (UDP/137, UDP/138) and the NetBIOS session service (TCP/139), adding attack surface and discovery-broadcast noise that violates the framework's modern-protocol-first posture. The cost of retention vastly exceeds the cost of dropping it: dropping is one configuration directive on each platform; retaining is a multi-year vulnerability maintenance commitment.

The constraints from [PC-079](../catalog/07-file-gateway.md#pc-079--smb1-must-be-dropped-security-liability-migration-is-automatic-on-modern-windows) are explicit. The framework must not negotiate SMB1. The framework must not enable NetBIOS name/datagram/session services in v1. The framework must document that legacy NAS appliances (NetApp ONTAP 7-mode, pre-DSM-7 Synology, Samba 3.x on old Linux) are out of scope. The framework must not break SYSVOL replication scenarios that previously depended on SMB1 fallback (this is a non-issue: Windows AD moved off this in Server 2008 R2 with the FRS-to-DFSR SYSVOL migration; the framework inherits DFSR-equivalent SYSVOL replication per [PC-080](../catalog/07-file-gateway.md#pc-080--dfs-n-namespace--dfs-r-replication-are-windows-only-no-linux-equivalent)).

Cross-platform consistency requires the framework's SMB server to refuse SMB1 Negotiate identically on every platform. Per [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md), Windows returns `STATUS_INVALID_PARAMETER` (0xC000000D) when the client lists only `0x00FF` / `PC NETWORK PROGRAM 1.0` as supported dialects; Samba returns the same NT status with `server min protocol = SMB2_02`. The framework's behavior must match this contract so that diagnostic tooling (`nmap --script smb-protocols`, `smbclient -L`) reports identical refusal on every framework-hosted share.

## Decision

The framework's File Gateway will not implement, advertise, or accept SMB1 (dialect `0x00FF` / `PC NETWORK PROGRAM 1.0` and successors `LANMAN1.0`, `Windows for Workgroups`, `NT LM 0.12`) in any configuration. The SMB server's dialect negotiation range will be bounded below by SMB 2.0.2 (`0x0202`) and above by SMB 3.1.1 (`0x0311`), per the operational floor established in [PC-078](../catalog/07-file-gateway.md#pc-078--smb-3-1-1-with-pre-auth-integrity--aes-gcm-is-required-for-modern-windows-interop) (deferred for SMB server implementation choice, but the dialect floor is independent). The framework will not bundle, ship, or auto-configure NetBIOS-over-TCP name/datagram/session services. The framework's documentation will explicitly mark SMB1-only NAS appliances as out of scope and recommend a Samba 4.7+ proxy appliance as the migration bridge for customers with stranded devices.

**Concrete specification**:

- The framework's SMB server's Negotiate response MUST NOT list any dialect below `0x0202` in the `DialectRevision` array of `SMB2_NEGOTIATE_RSP`.
- When a client's Negotiate request lists only dialects below `0x0202`, the server MUST return `STATUS_INVALID_PARAMETER` (0xC000000D) with no `NegotiateContextList`, terminating the connection. The refusal MUST be logged at `WARN` level with the client IP and offered-dialect list.
- The framework MUST NOT open TCP/139 (NetBIOS session), UDP/137 (NetBIOS name), or UDP/138 (NetBIOS datagram) listeners. The SMB server binds exclusively to TCP/445 (direct-hosted).
- The framework's `smb.conf`-equivalent configuration surface (if Samba is the underlying server) MUST set `server min protocol = SMB2_02` and `client min protocol = SMB2_02` as non-overridable defaults; the framework's installer MUST reject configurations that attempt to lower these bounds.
- The framework's documentation MUST include a "Legacy NAS appliance" out-of-scope statement covering NetApp ONTAP 7-mode, pre-DSM-7 Synology, Buffalo LinkStation, Samba 3.x servers, and any appliance advertising only `PC NETWORK PROGRAM 1.0`. The documented migration path is a Samba 4.7+ proxy appliance in front of the legacy NAS, exposing SMB 3.x to clients and speaking SMB1 to the NAS internally.
- The framework's automated test suite MUST include a regression test that issues a raw SMB1 Negotiate (`\xfdSMB` preamble, dialect string `PC NETWORK PROGRAM 1.0\0`) against the framework's SMB server port 445 and asserts the response is `STATUS_INVALID_PARAMETER` with no SMB1 negotiate reply.
- The framework's installer MUST detect and warn (not auto-remove) the presence of an existing Samba `smb.conf` with `server min protocol = NT1` or lower; the warning text MUST cite this ADR and recommend migration.
- The framework's Windows client policy MUST enforce `EnableSMB1Protocol = 0` and `EnableSMB1Client = 0` (where applicable) on framework-managed hosts via the Policy Engine; the macOS client MUST verify `com.apple.smb.server` does not enable SMB1 (no action required on stock macOS 10.14+); the Linux client MUST verify `/etc/samba/smb.conf` sets `server min protocol = SMB2_02`.

## Rationale

The decision is forced by security economics. EternalBlue demonstrated that SMB1 is a wormable liability: a single vulnerable host can be weaponized to propagate through an entire network in seconds. The framework cannot claim a "modern, secure AD replacement" posture while shipping the dialect that produced the largest Windows worm since Conficker. The 2023 Microsoft telemetry (<0.1% of enterprise file-server traffic) confirms there is no operational reason to retain SMB1; the migration cost on modern Windows is zero (Microsoft auto-disables), the cost on Linux is one Samba config line and a distro upgrade, and the cost on macOS is automatic. There is no enterprise audience that needs SMB1 in 2026.

The decision is also forced by attack-surface reduction. SMB1 carries the NetBIOS-over-TCP stack (UDP/137, UDP/138, TCP/139), which is itself a recurring source of broadcast-storm and NetBIOS-spoofing vulnerabilities. Dropping SMB1 lets the framework drop NetBIOS entirely, simplifying the network posture and removing a class of legacy discovery bugs. The framework's "single-port, single-protocol" story (TCP/445 only, modern SMB) is materially cleaner than any framework that retains the dual-stack.

The decision preserves wire compatibility with MS-SMB2. Microsoft's own SUT (System Under Test) guidance for SMB 3.x requires refusing SMB1 negotiation; the framework's behavior matches the Windows Server 2019+ default. The framework does not invent a dialect extension or non-standard refusal; it implements the documented Microsoft behavior verbatim.

The decision is consistent with the framework's broader AD-replacement posture: AD-on-Windows has been moving away from SMB1 since 2017, and a clean-slate framework inherits the end-state (SMB 2.0.2+ floor, SMB 3.1.1 ceiling) rather than the historical starting point. A greenfield framework has no installed base to support; it has only forward-going customers, all of whom are on Windows 10 1709+, macOS 10.14+, or RHEL 8+ / Ubuntu 18.04+ where SMB1 is already disabled by default at the OS level.

Finally, the decision is consistent with adjacent capabilities' dependencies. The Policy Engine's SYSVOL-equivalent distribution (per [PC-080](../catalog/07-file-gateway.md#pc-080--dfs-n-namespace--dfs-r-replication-are-windows-only-no-linux-equivalent)) will use SMB 3.x for share access; the File Gateway's CA-share design (per [PC-081](../catalog/07-file-gateway.md#pc-081--continuously-available-ca-shares-require-cluster--persistent-handles)) requires SMB 3.0+ for persistent handles. SMB1 retention would force the framework to maintain a parallel code path for SYSVOL access and would block CA-share adoption.

## Consequences

**Positive**. The framework eliminates a recurring class of wormable vulnerabilities from its attack surface. The framework eliminates NetBIOS-over-TCP from its network profile, simplifying firewall rules, broadcast hygiene, and discovery-protocol integration (mDNS / DNS-SD become the only discovery protocols). The framework's SMB server code path shrinks by an estimated 15-20% (the SMB1 dispatch table in Samba's `source3/smbd/` is ~25,000 lines; the framework's reimplementation would inherit similar complexity). The framework's automated test matrix shrinks (no SMB1 Negotiate/Session/TreeConnect tests, no NetBIOS name-resolution tests).

**Negative**. The framework cannot serve SMB1-only NAS appliances directly. Customers with stranded SMB1 appliances (NetApp ONTAP 7-mode end-of-life 2022, pre-DSM-7 Synology, Buffalo LinkStation) must either upgrade the appliance, replace it, or deploy a Samba 4.7+ proxy. The framework's documentation must explicitly call this out to avoid a "gotcha" during proof-of-concept deployment. Some regulated customers (DoD JITC-certified appliances, certain ICS/SCADA environments) may have SMB1-only devices they cannot upgrade; the framework must recommend the proxy path and accept that those customers will run a Samba proxy alongside the framework SMB server.

**Neutral**. The framework's wire-compatibility posture is identical to Windows Server 2019+ and Samba 4.5+, so customer expectations are already aligned. No customer running modern Windows/macOS/Linux clients will observe the SMB1 absence.

**Implementation cost**. Low. The decision is mostly a configuration hardcoding (`server min protocol = SMB2_02` if Samba is the underlying server) plus a regression test for the SMB1 refusal. Estimated engineering effort: 1-2 engineer-days for the configuration, the regression test, and the documentation. The Samba proxy recommendation requires only documentation, not framework code.

**Operational impact**. The framework's first-line support team must be trained to recognize the "client reports SMB1 negotiation failure" diagnostic pattern and direct the customer to either upgrade the legacy NAS appliance or deploy a Samba proxy. The framework's runbook must include the Samba proxy configuration template. The framework's Prometheus exporter MUST expose a `smb_negotiate_refused_dialect_total{dialect="0x00FF"}` counter so that operations teams can monitor attempted SMB1 connections (an early-warning indicator of legacy devices on the network).

## Alternatives Considered

**Alternative 1: SMB1-compat shim as an out-of-tree module.** The framework's mainline SMB server refuses SMB1, but a separately-versioned out-of-tree `framework-smb1-compat` module can be loaded by customers with stranded SMB1-only appliances. The shim would implement the SMB1 dispatch table by translating SMB1 requests to internal SMB 2.x calls against the framework's underlying share store. **Rejection rationale**: This alternative retains the entire SMB1 attack surface (the shim would have to be patched whenever a new EternalBlue-class CVE is disclosed in legacy SMB1 code), forces the framework to maintain the NetBIOS stack (the shim cannot speak raw SMB1 over TCP/445 without NetBIOS session setup on TCP/139), and creates a two-tier support posture where the framework team must respond to SMB1-related incidents for the shim. The proxy-appliance recommendation (Samba 4.7+ in front of the legacy NAS) achieves the same compat goal without framework code.

**Alternative 2: SMB1 negotiated down only when the underlying file system is a legacy NAS.** The framework's SMB server would detect "this share is backed by a legacy NAS appliance" (via a configuration flag) and enable SMB1 negotiation for that share only. **Rejection rationale**: This is operationally indistinguishable from "the framework's SMB server supports SMB1" — the configuration flag becomes the default for any customer with legacy NAS, and the framework inherits the SMB1 maintenance burden. Worse, the per-share SMB1 negotiation would require the framework's SMB server to speak SMB1 over TCP/445 to the legacy NAS internally while refusing SMB1 to clients externally, which is the Samba-proxy recommendation but with the framework itself in the middle. The clean separation (framework refuses SMB1; Samba proxy handles SMB1) is simpler and matches the Samba community's existing tooling.

**Alternative 3: Document SMB1 as "supported but deprecated; will be removed in v2."** The framework ships with SMB1 enabled by default, marked deprecated in documentation, with a v2 removal commitment. **Rejection rationale**: This is the Microsoft 2017-2019 trajectory, which the framework can compress to zero by simply not shipping SMB1 in v1. There is no installed base to support; there is no customer who requires SMB1 in 2026; there is no operational reason to defer. Deprecation timelines exist for installed-base migration; the framework has no installed base.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the SMB server implementation choice (Samba vs fresh vs platform-native, per ORQ-154/155), but that decision does not affect the SMB1-removal posture: every candidate server (Samba `smbd`, a fresh Rust/Go implementation, or platform-native SMBX/`srv2.sys`-equivalent) supports a `server min protocol = SMB2_02`-equivalent configuration.

## Cross-capability impact

- **Policy Engine** ([PC-052](../catalog/04-policy-engine.md)): Policy Engine's SYSVOL-equivalent distribution assumes SMB 2.0.2+; this ADR enforces that assumption.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): Client SDK's SMB client wrapper inherits the SMB 2.0.2+ floor; the SDK does not need to implement an SMB1 fallback path.
- **Migration** ([PC-128](../catalog/12-migration-and-coexistence.md)): Migration runbook must include the "legacy NAS appliance" detection step (probe SMB dialect support via `smbclient -L //appliance -m SMB1` from a Linux host) and the Samba-proxy remediation step.
- **Operations** ([PC-106](../catalog/10-operations.md)): Prometheus exporter exposes `smb_negotiate_refused_dialect_total{dialect="0x00FF"}` counter; OpenTelemetry trace events logged for every SMB1 refusal.

## References

- [PC-079](../catalog/07-file-gateway.md) — problem statement
- [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md) — SMB dialect history table, MS17-010 / EternalBlue context
- [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md) — `srv.sys` legacy SMB1 driver, `EnableSMB1Protocol` registry key
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2) — SMB2 protocol specification
- [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010) — EternalBlue security bulletin
- [RFC 1001/1002](https://www.rfc-editor.org/rfc/rfc1001) — NetBIOS-over-TCP (the framework refuses to implement these)
