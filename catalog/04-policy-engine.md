---
title: Policy Engine — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, policy-engine, framework-design, gap-analysis, gpo, group-policy]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./03-auth-provider.md
  - ./05-cert-service.md
  - ./07-file-gateway.md
  - ./09-cross-platform-parity.md
  - ./14-cross-platform-parity-matrix.md
  - ./13-open-research-questions.md
last_updated: 2026-08-13
---

# Policy Engine — Problem Catalog

## Capability definition

**Responsibility**: Distributes configuration policy to enrolled clients. Replaces GPO. Supports declarative policy (vs. INI/registry.pol), versioned policies, conflict resolution beyond last-writer-wins, rollback, partial application.

**Inherits from AD**: GPO (GPC in AD + GPT in SYSVOL + Group Policy Client service + CSEs).

**Public interfaces**: Policy retrieval (pull by enrolled client), Policy targeting (security filtering, WMI-equivalent, scope), Policy payload format (declarative, versioned), Policy reporting (live policy set per client), ADMX-equivalent schema for third-party policy definitions.

**Depends on**: Core Directory (stores policy objects), File Gateway (distributes policy files via SMB-equivalent or HTTPS).

**Consumed by**: Client SDK (applies policy on enrolled clients).

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-043 | GPC + GPT split is fragile; version mismatch common | high | Windows, cross-platform |
| PC-044 | LSDOU last-writer-wins; no semantic conflict resolution | medium | cross-platform |
| PC-045 | GPO Preferences XML have no macOS/Linux equivalent | blocker | Windows, macOS, Linux |
| PC-046 | ADMX schema Windows-specific; cross-platform equivalent fragmented | high | Windows, macOS, Linux |
| PC-047 | CSE model Windows-only; per-CSE GUIDs | high | Windows, macOS, Linux |
| PC-048 | GPO has no native rollback or transactional semantics | medium | cross-platform |
| PC-049 | WMI filters evaluated client-side; repository corruption fails GPOs | medium | Windows |
| PC-050 | Slow-link detection (ICMP ping to PDC) is unreliable | low | Windows |
| PC-051 | GPO background refresh interval (90 min + jitter) too slow for security policies | medium | cross-platform |
| PC-052 | Registry.pol PReg format is binary/UTF-16; needs explicit parser | medium | Windows, macOS, Linux |
| PC-053 | SSSD GPO access control only enforces `[Privilege Rights]` logon rights | high | Windows, macOS, Linux |
| PC-054 | GPO security filtering on `Authenticated Users` is fragile | medium | cross-platform |
| PC-055 | SYSVOL replication via DFS-R is Windows-only; FRS removed | blocker | cross-platform |
| PC-056 | No native policy versioning / history; reverting requires backup restore | medium | cross-platform |

Severity totals: 2 blocker, 3 high, 8 medium, 1 low.

## Detailed problem entries

### PC-043 — GPO architecture (GPC + GPT split) is fragile; version mismatch is common

**Capability**: Policy Engine
**Severity**: high
**Cross-platform**: Windows, cross-platform

**Problem statement**:

A Group Policy Object in AD is a two-part entity: the Group Policy Container (GPC), a `groupPolicyContainer` object (governsID `1.2.840.113556.1.5.108`) stored at `CN=Policies,CN=System,<domain-dn>` with attributes `gPCFileSysPath`, `gPCMachineExtensionNames`, `versionNumber` (combined: high 32 bits = user, low 32 = machine); and the Group Policy Template (GPT), a folder under `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\` carrying `GPT.INI`, `Registry.pol`, `GptTmpl.inf`, Preferences XML, scripts, per the architecture documented in [04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md). The two halves are linked by the GPC's `gPCFileSysPath` UNC and version-stamped together via `GPC.versionNumber` (OID `1.2.840.113556.1.4.1340`) — a 64-bit integer whose packing is `(userVersion << 32) | (machineVersion & 0xFFFFFFFF)` — and the matching `Version=` line in `GPT.INI`.

The split is fragile because the two stores replicate over independent channels: the GPC replicates via DRSUAPI (`IDL_DSABind` + `IDL_DRSGetNCChanges` opnum 3) inside the Configuration NC, while the GPT replicates via DFS-R (`dfsr.exe`, RPC UUID `91b7b931-c75a-4530-8258-1b3eb578c5d8`) using version vectors + RDC. When DFS-R lags (e.g., backlog on `dfsrdiag backlog`), or when admins hand-edit the GPT folder under SYSVOL, the GPC `versionNumber` and `GPT.INI Version` diverge. Per the analysis in [04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md), `gpsvc.dll` reads `GPT.INI` at every refresh, compares `Version` to the cached `versionNumber` from the GPC, and on mismatch falls back to the GPC value and re-reads the GPT files — but clients may briefly apply stale policy or skip the refresh entirely.

Samba AD-DC replicates SYSVOL via DRSUAPI on the SysVol directory (single-master per attribute) rather than via DFS-R, as documented in [07-file-print/02-dfs-n-dfs-r.md](../docs/07-file-print/02-dfs-n-dfs-r.md). This is a different mechanism that produces different failure modes: Samba's SYSVOL has no RDC bandwidth optimization, no conflict-and-deleted folder, and no `dfsrdiag` tooling. macOS and Linux clients see the same `\\<domain>\SYSVOL\...` UNC surface over SMB but the underlying replication topology is invisible to them.

For the framework, the GPC/GPT split forces a choice: (a) preserve the split and re-implement both DRSUAPI and DFS-R-equivalent replication for interop, (b) abandon the split and use a single source of truth, or (c) externalize policy distribution to Git/object-store and provide GPC/GPT views as a compat shim.

**Impact**:

GPO version mismatch causes clients to skip policy refresh or apply stale settings; in environments where security policy (LAPS rotation interval, account lockout threshold) is GPO-driven, a 5–15 minute SYSVOL replication lag window can mean a known-vulnerable configuration persists. `gpupdate /force` masks the symptom but does not fix the underlying divergence.

**Constraints**:

- Must support atomic GPO updates (the GPC write + GPT write must be transactional across the two replication channels).
- Must preserve `gPLink` (OID `1.2.840.113556.1.4.1361`) and `gPOptions` (block inheritance, enforced link) for LSDOU processing.
- For AD interop, the framework must expose a `groupPolicyContainer` AD object readable by `gpsvc.dll` on existing Windows clients.

**Cross-platform considerations**:

- **Windows**: `gpsvc.dll` (svchost -k netsvcs) is the only consumer that handles GPC/GPT divergence; if it cannot read either side, machine boot can stall waiting for policy.
- **macOS**: MDM profiles are monolithic — no equivalent split exists. The AD plugin on AD-bound Macs uses the same GPC/GPT fetch path as Windows.
- **Linux**: SSSD's `ad_gpo_child` reads `GptTmpl.inf` from SYSVOL via libsmbclient; if `versionNumber` and `GPT.INI Version` diverge, SSSD may apply stale `[Privilege Rights]` and lock out users.
- **Cross-platform consistency**: clients of all three OSes share the same SYSVOL and observe the same replication state — divergence affects every platform simultaneously.

**KB references**:

- [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) — GPC `groupPolicyContainer` schema, `versionNumber` packing, `gPCFileSysPath` UNC linkage.
- [`04-group-policy/05-gpt-gpc-structure.md`](../docs/04-group-policy/05-gpt-gpc-structure.md) — `GPT.INI` Version field, PReg format, divergence handling in `gpsvc.dll`.
- [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md) — DFS-R replication of SYSVOL, FRS removal in Server 2019.

**Open questions**:

- Single declarative YAML per GPO in a Git repo, replicated via Git pull to all DCs?
- Per-GPO CRDT for multi-master authoring without lock contention?
- Should the framework expose a synthetic GPC view over a non-AD backing store, or treat GPC as legacy and require a new client?

**Cross-capability impact**:

- Affects: PC-055 (SYSVOL replication via DFS-R), PC-056 (no native policy versioning).
- Affected by: PC-002 (replication model choice — state-based pull vs. consensus affects how the GPC and GPT stay in sync).

---

### PC-044 — LSDOU processing order is last-writer-wins; no conflict resolution beyond Enforced/Block

**Capability**: Policy Engine
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

GPO processing order is fixed at LSDOU (Local, Site, Domain, OU — parent-to-child within OU), with each container's `gPLink` list evaluated left-to-right (leftmost = highest priority). Two modifiers exist: `gPOptions = 1` (`GPO_BLOCK_INHERITANCE`, blocks inheritance from parent OUs and domain) and `gPLink Options = 0x2` (`GPO_LINK_ENFORCED`, formerly "No Override" — propagates downward and overrides child blocks). Conflict resolution is last-writer-wins: whichever GPO is last in the LSDOU chain wins, with no semantic awareness of what is being overridden, per [04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md).

There is no notion of "Registry value X wins over Registry value Y" or "Security setting from GPO A has precedence over Security setting from GPO B unless explicitly overridden." Two GPOs that both write `HKLM\Software\Contoso\App\Threshold` resolve to whichever GPO is later in LSDOU — typically the OU closest to the object, but indistinguishable from intentional policy once applied. The `gpresult /h` report shows the applied GPO list but not the precedence-per-setting trace. Windows does not record "setting X came from GPO Y" in the registry, so post-hoc attribution is impossible without `GPResultantSetOfPolicy` planning mode against a clean machine.

Samba `samba-gpupdate` and SSSD `ad_gpo_access` honor the LSDOU order for the limited subset of policy they consume (security filtering for SSSD, Registry.pol for `samba-gpupdate`), but neither exposes a conflict-resolution UI. macOS Configuration Profiles use a different precedence model (last-installed profile wins per-payload-key, with MDM able to mark profiles as forced) that does not map cleanly to LSDOU, per the matrix in [10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

For the framework, last-writer-wins is operationally hazardous for security-sensitive settings (e.g., a Domain Admins-only setting accidentally overridden by a downstream OU's broader policy) and for audit (you cannot answer "which GPO set this value?"). A declarative policy model with explicit per-setting `priority: N` or role-based binding would be safer, but breaks AD interop unless the framework also re-emits GPC objects in LSDOU form for legacy Windows clients.

**Impact**:

Policy conflicts are resolved by accident — whichever GPO is last in LSDOU. Debugging is hard: there is no per-setting attribution in the registry. Worst case: a high-privilege policy (e.g., "Domain Admins only can log on locally") is silently overridden by a downstream OU's broad policy ("Domain Users can log on locally"), and the override is invisible until an incident.

**Constraints**:

- Must preserve LSDOU + Enforced + Block Inheritance for AD interop with existing Windows `gpsvc.dll`.
- A declarative precedence model (`priority: N` per setting) is an enhancement, not a replacement.

**Cross-platform considerations**:

- **Windows**: `gpsvc.dll` enforces LSDOU strictly; `gpresult /r` shows applied and denied GPOs but not per-setting precedence.
- **macOS**: MDM profiles use last-installed-wins per payload key; no LSDOU concept. Mapping an AD GPO chain to a set of MDM profiles loses the precedence semantics.
- **Linux**: SSSD's `ad_gpo_evaluate_gpo` applies AND semantics across GPOs for `[Privilege Rights]` (user must be in every Allow list, no Deny) — different from Windows OR semantics for the same data.
- **Cross-platform consistency**: the same GPO chain produces different effective policy on each platform because each client honors a different subset of the model.

**KB references**:

- [`04-group-policy/02-gpo-processing-order.md`](../docs/04-group-policy/02-gpo-processing-order.md) — LSDOU ordering, `gPOptions` and `gPLink Options` bitmask, security filtering, slow-link impact per CSE.
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Cross-platform GPO setting equivalents showing where macOS MDM and Linux SSSD diverge from Windows semantics.

**Open questions**:

- Declarative policy with explicit `priority: N` per setting, with LSDOU preserved as a default for legacy interop?
- Per-setting attribution stored in the registry/value alongside the value itself (e.g., `HKLM\...\Value\GPOSource`)?

**Cross-capability impact**:

- Affects: PC-048 (no rollback — last-writer-wins makes rollback non-trivial because the "previous" value is not recorded).
- Affected by: PC-053 (SSSD's AND-vs-OR semantics already deviate from Windows LSDOU).

---

### PC-045 — GPO Preferences (XML files) have no macOS/Linux equivalent

**Capability**: Policy Engine
**Severity**: blocker
**Cross-platform**: Windows, macOS, Linux

**Problem statement**:

GPO Preferences (`Drive Maps`, `Files`, `Folders`, `Ini Files`, `Local Users and Groups`, `Printers`, `Scheduled Tasks`, `Services`, `Shortcuts`, `Environment`, `Registry`, `Internet Settings`) are 14+ XML files under `Machine\Preferences\` and `User\Preferences\` in the GPT, processed by `gppref.dll` (CSE GUIDs listed in [04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md)). Each file has a root `<Collection>` or area-specific root (`<DrivesCls>`, `<NTServices>`, etc.) and per-item actions with `action="C|U|R|D"` (Create/Update/Replace/Delete). These files are the most-used GPO feature in enterprise deployments.

SSSD does not parse any Preferences XML — its `ad_gpo_access` module reads only `[Privilege Rights]` from `GptTmpl.inf`, per [09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md). Samba's `samba-gpupdate` reads `Registry.pol` and translates a fixed set of keys to Linux config files (`/etc/krb5.conf`, `/etc/security/limits.conf`, `/etc/sudoers.d/`) but has no Preferences XML support. macOS MDM Configuration Profile payloads cover a subset of the same surface (drive maps via `autofs`, scheduled tasks via `launchd`, printers via `com.apple.mobileconfig.airprint`) but with different schemas and no common authoring format. The matrix in [10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) shows that for many Preferences areas the macOS equivalent is a `scripts` payload running shell commands — there is no native MDM payload at all.

The framework must support the full Preferences surface (drive maps, file deployment, scheduled tasks, local users/groups, registry/plist, environment variables) on all three platforms. Either the framework adopts OPA-style declarative policy with platform-specific executors, or it provides a per-platform translation layer that compiles a unified policy into platform-native forms (`.mobileconfig`, `pam.d` snippets, `launchd` plists, `systemd` units). Without this, the framework cannot claim cross-platform policy parity.

**Impact**:

Preferences are the most-used GPO feature; cross-platform parity is poor. Without solving this, the framework cannot deploy a single policy that maps a network drive, schedules a task, and creates a local user on Windows + macOS + Linux simultaneously. Customers with mixed-OS fleets fall back to Ansible/Chef/Salt alongside GPO, creating dual sources of truth.

**Constraints**:

- Must support drive maps (SMB mount on macOS/Linux, mapping on Windows), file deployment, scheduled tasks (`launchd` on macOS, `systemd` timers on Linux, Task Scheduler on Windows), local users/groups, registry/plist, environment variables.
- Must preserve Windows Preferences XML format for AD interop with existing `gppref.dll`.

**Cross-platform considerations**:

- **Windows**: `gppref.dll` processes all 14 Preferences XML files natively.
- **macOS**: MDM payloads cover ~30% of the Preferences surface; the rest requires `scripts` payloads or `launchd` plists. Per [10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md), Folder Redirection has no MDM-native equivalent.
- **Linux**: SSSD/Samba cover ~5% (Registry.pol translation only). FreeIPA has HBAC + sudo rules + automount but no Preferences equivalent.
- **Cross-platform consistency**: today the same GPO applied to Windows/macOS/Linux produces three different effective configurations because each platform consumes a different subset.

**KB references**:

- [`04-group-policy/05-gpt-gpc-structure.md`](../docs/04-group-policy/05-gpt-gpc-structure.md) — Preferences XML file locations, root element names, `action="C|U|R|D"` attribute, schema overview.
- [`04-group-policy/04-cse-client-side-extensions.md`](../docs/04-group-policy/04-cse-client-side-extensions.md) — `gppref.dll` CSE GUIDs, Preferences area → XML file mapping, CSE registry layout.
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Per-Preferences-area cross-platform migration matrix with macOS MDM payload type and Linux equivalent.

**Open questions**:

- Adopt OPA-style declarative policy with platform-specific executors?
- Per-platform translation layer that compiles a unified JSON policy into ADMX/MDM/SSSD-conf?
- Treat Preferences as out-of-scope and recommend Ansible for cross-platform config management?

**Cross-capability impact**:

- Affects: PC-046 (ADMX schema — Preferences are authored in GPMC via ADMX-driven UI, not the raw XML), PC-047 (CSE model — each Preferences area has its own CSE GUID).
- Affected by: PC-055 (SYSVOL replication — Preferences XML files add to SYSVOL storage and SMB chattiness on slow WANs).

---

### PC-046 — ADMX schema is Windows-specific; cross-platform equivalent is fragmented

**Capability**: Policy Engine
**Severity**: high
**Cross-platform**: Windows, macOS, Linux

**Problem statement**:

ADMX (Administrative Template XML, since Vista/Server 2008) defines policy settings via `<policyDefinitions>` XML with `<policy>` elements containing `<elements>` (text, decimal, boolean, enum, list, longDecimal, multilineText) backed by ADML localization files per-locale. ADMX files live either in the local `%SystemRoot%\PolicyDefinitions\` directory or the SYSVOL Central Store at `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\`, with ADML files in `<locale>\` subdirectories (e.g., `en-US\`, `de-DE\`), per [04-group-policy/03-admx-templates.md](../docs/04-group-policy/03-admx-templates.md). The schema is XML Schema Definition (`policyDefinitions.xsd` in the Windows SDK) and includes `<supportedOn>` definitions gating policy applicability by Windows product version (e.g., `SUPPORTED_Win10_1809`, `SUPPORTED_WinServer2022`).

macOS MDM uses per-payload schemas — there is no unified ADMX-equivalent. Each MDM payload type (`com.apple.mobileconfig.passwordpolicy`, `com.apple.systempolicy.managed`, `com.apple.mobileconfig.firewall`, etc.) has its own ad-hoc schema documented in Apple's Configuration Profile Reference. Linux SSSD has no ADMX parser — it consumes only the `[Privilege Rights]` subset of `GptTmpl.inf`, ignoring all ADMX-driven Registry.pol settings. Samba's `samba-gpupdate` reads `Registry.pol` but translates only a fixed set of known policy keys (`PolicyKey` → Linux file mapping); it does not parse ADMX. FreeIPA uses native LDAP attributes per-policy-area (`ipaPwpolicy`, `ipaHbacrule`, `ipaSudorule`) — no XML template concept. The matrix in [10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) shows the fragmentation: a single ADMX setting may map to an MDM payload on macOS, an SSSD config key on Linux, or have no equivalent at all.

For the framework, the choice is between (a) adopting a unified policy-definition format (JSON Schema, OPA Rego, or a new DSL) that compiles down to platform-native forms (ADMX for Windows, `.mobileconfig` schema for macOS, `sssd.conf` for Linux), (b) keeping ADMX as the source of truth and writing ADMX-to-MDM and ADMX-to-Linux compilers, or (c) accepting that each platform has its own authoring surface and providing no unified schema.

**Impact**:

Cross-platform policy authoring requires per-OS translation today. An admin authoring a policy in GPMC against an ADMX has no way to know which subset will apply to a Mac or Linux client. Templates written for Windows apps (Edge, Office, Defender ADMX) have zero portability.

**Constraints**:

- Must support ADMX for Windows interop (existing `gpedit.msc`/GPMC authoring workflow).
- Must support MDM payload schema for macOS (Configuration Profile reference).
- New framework policies authored in a unified format should compile to both.

**Cross-platform considerations**:

- **Windows**: ADMX + ADML is the canonical authoring surface; Central Store in SYSVOL is the distribution channel.
- **macOS**: No unified schema; each payload type has its own plist schema. MDM servers (Jamf, Intune, Kandji) author profiles per-payload.
- **Linux**: No ADMX parser exists in any open-source client. SSSD/Samba consume `Registry.pol` for a fixed key set.
- **Cross-platform consistency**: a unified schema is a greenfield requirement; nothing in the existing ecosystem provides it.

**KB references**:

- [`04-group-policy/03-admx-templates.md`](../docs/04-group-policy/03-admx-templates.md) — ADMX XML schema, `<policyElements>` element types, `<supportedOn>` definitions, Central Store layout.
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Per-ADMX-setting cross-platform equivalent showing fragmentation.

**Open questions**:

- Single policy DSL that compiles to ADMX/MDM/SSSD-conf?
- OPA Rego as the unified format with platform-specific executors?
- Treat ADMX as legacy and require new policies to be authored in the new format only?

**Cross-capability impact**:

- Affects: PC-045 (Preferences XML), PC-047 (CSE model — ADMX-driven settings invoke the Registry CSE).
- Affected by: PC-052 (Registry.pol PReg format is what ADMX settings compile into).

---

### PC-047 — CSE (Client-Side Extension) model is Windows-only; per-CSE GUIDs

**Capability**: Policy Engine
**Severity**: high
**Cross-platform**: Windows, macOS, Linux

**Problem statement**:

CSEs are DLLs registered under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<GUID>}` exporting `ProcessGroupPolicy` and `ProcessGroupPolicyEx` (prototype in `<userenv.h>` `PFNPROCESSGROUPPOLICYEX`). When `gpsvc.dll` processes a GPO, it iterates the CSE-GUID list in `gPCMachineExtensionNames`/`gPCUserExtensionNames` (format `[{CSE-GUID}{SnapIn-GUID}]...`) and invokes each CSE via `GetProcAddress`. There are 16+ CSEs covering Registry (`{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`, `userenv.dll`), Security (`{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`, `scecli.dll`), Scripts (`{42B5FAAE-6536-11D1-AE59-0000FED75982}`, `gptext.dll`), Folder Redirection (`{426031c0-0b47-4852-b0ca-ac3d37bfcb39}`, `fdeploy.dll`), AppLocker (`{16be69fa-4209-4250-9b8c-6539af50c92b}`, `appidsvc.dll`), Software Install (`{c6dc5466-785a-11d2-84ed-00c04fb1692f}`, `appmgmts.dll`), plus 14 Preferences CSEs all hosted in `gppref.dll`, per [04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md).

The CSE model is Windows-only: each CSE is a Windows DLL with Windows-specific entry points, registry writes, and security APIs. macOS and Linux have no equivalent — SSSD implements only the Security CSE subset (the `[Privilege Rights]` section of `GptTmpl.inf`) via `ad_gpo.c:ad_gpo_evaluate_gpo`. Samba `samba-gpupdate` implements a partial Registry CSE that translates a fixed set of known policy keys to Linux config files. macOS MDM uses monolithic `.mobileconfig` payloads — there is no per-CSE invocation; each payload type is a single "CSE-equivalent" applied atomically, per the matrix in [10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

For the framework, the CSE model must either be (a) preserved as a Windows-specific shim that maps CSE GUIDs to framework-native policy executors, or (b) replaced with a generic "policy executor" framework where each platform registers its own per-area plugins. Option (b) is cleaner but breaks the `gPCMachineExtensionNames` contract — Windows `gpsvc.dll` would need a synthetic CSE that delegates to the framework.

**Impact**:

Cross-platform policy enforcement is partial. Without a CSE-equivalent model, the framework can only deliver policy payloads but cannot enforce application on macOS/Linux. SSSD's 1/50th-of-Windows coverage is the current state of the art.

**Constraints**:

- Must support Windows CSE GUIDs for interop (existing `gpsvc.dll` invocation model).
- Must define platform-native equivalents on macOS (MDM payload types) and Linux (PAM/NSS/systemd/CUPS).
- CSE registration in registry `HKLM\...\CSEs\{GUID}` must be honored on Windows.

**Cross-platform considerations**:

- **Windows**: 16+ native CSEs registered in registry; `gpsvc.dll` invokes via `ProcessGroupPolicyEx`.
- **macOS**: No CSE concept; MDM payloads are atomic per payload type.
- **Linux**: SSSD implements one CSE-equivalent (Security); Samba `samba-gpupdate` implements a partial Registry CSE. No CSE for Scripts, Folder Redir, Software Install, AppLocker.
- **Cross-platform consistency**: the same GPO produces wildly different effective policy on each platform because each OS consumes only its CSE-equivalent subset.

**KB references**:

- [`04-group-policy/04-cse-client-side-extensions.md`](../docs/04-group-policy/04-cse-client-side-extensions.md) — Full CSE GUID table, `ProcessGroupPolicy` prototype, `gPCMachineExtensionNames` encoding, per-CSE files consumed from GPT.
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Cross-platform coverage per CSE-equivalent.

**Open questions**:

- Generic "policy executor" framework with per-platform plugins?
- Declarative policy that compiles to CSE invocations on Windows and shell scripts on Linux?
- Treat CSEs as legacy and ship a single "framework CSE" that delegates to platform-native executors?

**Cross-capability impact**:

- Affects: PC-045 (Preferences XML — each Preferences area is a separate CSE), PC-053 (SSSD's Security CSE is the only CSE ported to Linux).
- Affected by: PC-046 (ADMX-driven settings invoke the Registry CSE).

---

### PC-048 — GPO has no native rollback or transactional semantics

**Capability**: Policy Engine
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

GPO apply is best-effort: failed CSEs log Event 1090 (`Windows could not record the resultant set of policy (RSoP) information for Group Policy <CSE>`) in `Applications and Services Logs\Microsoft\Windows\GroupPolicy\Operational`, but processing continues with the next CSE. There is no atomic rollback. `Registry.pol` writes via `userenv.dll!ProcessRegistryPolicy` call `RegCreateKeyExW`/`RegSetValueExW` directly; reverting requires restoring from a `Backup-GPO` archive or a System Restore point. The Security CSE (`scecli.dll!SceProcessReturnedGPOs`) writes via `LsaQueryInformationPolicy`, `SceSetSecurityPolicyInfo`, and `LsaCreateAccount` — also non-transactional. Per [04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md), each CSE returns `ERROR_SUCCESS` or an error code; on error, `gpsvc` logs Event 1090 and continues — there is no per-CSE snapshot before apply and no automatic revert on failure.

Per [04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), `gpsvc` caches the last-applied version per CSE per GPO under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{<CSE-GUID>}\{<GPO-GUID>}\Version` — but this is a record of what was applied, not a snapshot to revert to. If a GPO deployment breaks hosts (e.g., a typo in a `GptTmpl.inf` `SeServiceLogonRight` denies service logon to all service accounts), the only recovery is `Restore-GPO -BackupId <guid>` from a `Backup-GPO -Path <path>` archive, followed by `gpupdate /force` on every affected host. There is no equivalent of Ansible's `--check` mode or `--diff` for preview.

For the framework, transactional policy apply with rollback on failure is a baseline expectation. This requires per-CSE snapshot before apply (registry hive export, file ACL backup, service config snapshot), per-CSE rollback on failure, and dry-run / preview support. The framework's CSE-equivalent plugins must export `Snapshot()`, `Apply()`, and `Rollback()` entry points.

**Impact**:

Bad GPO deployments can break hosts with no easy revert. In a 10,000-host enterprise, a bad GPO that denies logon to all users is a multi-hour outage while admins restore from backup and force `gpupdate` on every host. The absence of preview (`--check`) means changes go to production blind.

**Constraints**:

- Must support per-CSE rollback (snapshot before apply, revert on failure).
- Must support dry-run / preview mode (compute effective policy without applying).
- For AD interop, the framework must accept that `gpsvc.dll`'s call model is non-transactional and provide rollback as a wrapper.

**Cross-platform considerations**:

- **Windows**: `gpsvc.dll` apply is non-atomic; `gpresult /h` shows the post-apply state but not the pre-apply state. System Restore is the only OS-level snapshot.
- **macOS**: MDM profiles are atomic per profile (install or fail); removing a profile reverts its settings, but a profile that partially applies is undefined.
- **Linux**: SSSD/Samba apply is non-atomic; `/etc/krb5.conf` is rewritten in place. Recovery requires file backup.
- **Cross-platform consistency**: rollback semantics differ per platform; the framework must define a common contract.

**KB references**:

- [`04-group-policy/02-gpo-processing-order.md`](../docs/04-group-policy/02-gpo-processing-order.md) — `gpsvc.dll!ProcessGroupPolicyEx` phases, Event 1090 handling, `History\{CSE-GUID}\{GPO-GUID}\Version` cache layout.
- [`04-group-policy/04-cse-client-side-extensions.md`](../docs/04-group-policy/04-cse-client-side-extensions.md) — CSE entry-point prototype, error-code propagation, per-CSE history registry layout.

**Open questions**:

- Per-CSE snapshot before apply (registry hive export, file ACL backup)?
- Git-style revert (commit/rollback to a previous policy version)?
- Dry-run mode that computes effective policy without applying?

**Cross-capability impact**:

- Affects: PC-044 (last-writer-wins makes rollback non-trivial — the "previous" value is not recorded), PC-056 (no native versioning — rollback requires backup).
- Affected by: PC-043 (GPC/GPT split — transactional apply must span both halves).

---

### PC-049 — WMI filters are evaluated client-side; WMI repository corruption fails GPOs

**Capability**: Policy Engine
**Severity**: medium
**Cross-platform**: Windows

**Problem statement**:

GPO WMI filters are `msFTSI` objects under `CN=SOM,CN=WMIPolicy,CN=System,<domain-dn>` (SOM = Scope of Management). Each filter has one or more `msFTSI_Query` entries (WQL queries) ANDed together, attached to a GPO via `gPCWQLFilter` (LDAP URL). Per [04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), at GP processing time the client queries `root\cimv2` for each `msFTSI_Query`; if any query returns zero rows, the filter FAILS and the GPO is **not applied** (fail-closed). If the WMI service (`winmgmt`) is unavailable or the WMI repository is corrupted, the GPO is **not applied**.

WMI repository corruption is a well-known Windows operational pain point: symptoms include `WMI service is unavailable`, `0x80041006` (WMI out of memory), and partial CIM schema loss. The recovery is `rundll32 wbemdisp.dll, RepairWMISchema` or `winmgmt /salvagerepository` — both of which require admin rights and a service restart. Per the same KB file, WMI filter results are cached on the client for 60 minutes under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\WMIFilterCache`, but a cache miss during repository outage means GPOs silently stop applying.

The WMI filter model has no cross-platform equivalent: macOS has no WMI; Linux has `udevadm`/`hostnamectl`/`facts` (Ansible-style) but no WQL query language. For the framework, the choice is between (a) preserving WMI filter evaluation for AD interop (Windows-only feature, fail-closed on WMI outage), (b) replacing WMI filters with declarative host facts (OS, role, site, IP range, hostname pattern) evaluated by the framework client, or (c) keeping WMI for Windows-only and using facts for macOS/Linux.

**Impact**:

WMI repository corruption silently drops GPOs. A host with corrupted WMI may stop applying security policy (lockout threshold, LAPS rotation) without any visible error in `gpresult`. Detection requires per-host WMI health checks.

**Constraints**:

- Must preserve WMI filter eval for AD interop (existing `msFTSI_Query` WQL queries).
- A declarative host-fact-based filter model (Ansible-style facts: `os`, `role`, `site`, `ip_range`) is a modern alternative.

**Cross-platform considerations**:

- **Windows**: `winmgmt` service; WQL queries against `root\cimv2`. Fail-closed on outage.
- **macOS**: No WMI; MDM uses device scope (per-device assignment) instead.
- **Linux**: No WMI; SSSD's `ad_gpo_filter` does not honor WMI filters at all (they are ignored).
- **Cross-platform consistency**: a GPO with a WMI filter applies on Windows but is silently skipped on macOS/Linux because the filter cannot be evaluated — the framework must define what "WMI filter on non-Windows" means.

**KB references**:

- [`04-group-policy/02-gpo-processing-order.md`](../docs/04-group-policy/02-gpo-processing-order.md) — `msFTSI` object class, `msFTSI_Query` attribute, fail-closed behavior on WMI outage, `WMIFilterCache` 60-minute cache.
- [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) — `gPCWQLFilter` LDAP URL format, `msFTSI_ID` linkage to GPC.

**Open questions**:

- Replace WMI filters with declarative host facts (OS, role, site, IP range)?
- Keep WMI for Windows-only and use facts for macOS/Linux?
- Should fail-closed be the default, or should the framework fail-open with a warning?

**Cross-capability impact**:

- Affects: PC-050 (slow-link detection also uses client-side evaluation and is similarly fragile).
- Affected by: PC-047 (CSE model — WMI filters gate CSE invocation).

---

### PC-050 — Slow-link detection (ICMP ping to PDC) is unreliable

**Capability**: Policy Engine
**Severity**: low
**Cross-platform**: Windows

**Problem statement**:

Per [04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), `gpsvc.dll!DetectSlowLink` pings the PDC emulator via ICMP three times with a default 64 KB packet, computes average RTT, and estimates link speed as `packet_size / avg_rtt`. If estimated speed is below the `SlowLink` registry threshold (default 500 kbps at `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-...}\SlowLink`), the link is declared slow. Slow-link triggers skip Folder Redirection (`{426031c0-...}`), Software Install (`{c6dc5466-...}`), Scripts (`{42B5FAAE-...}`) at background refresh, and most Preferences (`Files`, `Printers`, `Drives`, `Shortcuts`).

The algorithm is unreliable because ICMP is often blocked by firewalls (AWS Security Groups, Azure NSGs, on-prem ACLs default-deny ICMP). When ICMP is blocked, `DetectSlowLink` either times out (default 60 seconds at `SlowLinkTimeOut`) and declares slow, or returns zero RTT and declares fast — depending on the failure mode. The result is that slow-link detection either always fires (causing Folder Redir/Software Install/Scripts to silently skip on every refresh) or never fires (causing these CSEs to attempt apply over saturated WAN links).

For the framework, slow-link detection should use TCP RTT to a known endpoint (e.g., the policy distribution URL) or HTTP HEAD probe with timing, not ICMP. Per-CSE slow-link policy (rather than all-or-nothing) would also be an improvement — e.g., "skip Software Install on slow link but apply Scripts."

**Impact**:

Slow-link detection is unreliable; either always-fires (skipping critical CSEs) or never-fires (over-saturating WAN links). Field reports of "Folder Redirection not working" frequently trace to ICMP blocked between branch and PDC.

**Constraints**:

- Must support slow-link policy processing semantics for compat (the `SlowLink` registry value and per-CSE slow-link gating).
- TCP RTT or HTTP HEAD probe is a modern alternative.

**Cross-platform considerations**:

- **Windows**: `gpsvc.dll!DetectSlowLink` via ICMP. Per-CSE slow-link gating in registry.
- **macOS**: MDM has no slow-link concept; profiles are pushed when the device checks in.
- **Linux**: SSSD has no slow-link detection; `ad_gpo_access` always attempts SMB fetch and fails-closed on timeout.
- **Cross-platform consistency**: the framework's slow-link model should be consistent across platforms.

**KB references**:

- [`04-group-policy/02-gpo-processing-order.md`](../docs/04-group-policy/02-gpo-processing-order.md) — `DetectSlowLink` algorithm, `SlowLink` registry threshold, per-CSE slow-link behavior table, override policies.
- [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) — `gpsvc.dll` registry layout including `SlowLinkDetectEnabled` and `SlowLinkTimeOut` defaults, `GPNetworkName` PDC reference.

**Open questions**:

- Replace ICMP with HTTP HEAD probe to policy distribution URL?
- Per-CSE slow-link policy (skip Software Install but apply Scripts)?
- Drop slow-link detection entirely and rely on per-policy TTL?

**Cross-capability impact**:

- Affects: PC-051 (background refresh interval — slow-link interacts with refresh frequency).
- Affected by: PC-049 (WMI filters also evaluated client-side with similar fragility).

---

### PC-051 — GPO background refresh interval (90 min + jitter) is too slow for security policies

**Capability**: Policy Engine
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Default GPO background refresh is 90 minutes + 0–30 minute jitter (registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\System\GroupPolicyRefreshRate = 90` and `GroupPolicyRefreshRateRand = 30`), per [04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md). DCs have a separate setting (`GroupPolicyRefreshRateDC`). Some CSEs are excluded from background refresh entirely: Folder Redirection (logon only), Software Install (logon only), Scripts (boot/logon only). For these, an admin must either trigger `gpupdate /force` on each host or wait for the next boot/logon.

For security-sensitive policies — LAPS password rotation (when changed via GPO), account lockout threshold changes, audit policy updates, Windows Defender signature toggles — a 90–120 minute propagation window is too slow. An attacker who exploits a known vulnerability within that window benefits from the lag. Manual `gpupdate /force` is the workaround; in a 10,000-host fleet this is operationally infeasible.

Push-based policy distribution (webhook from policy server to enrolled clients) would close the window. This requires the framework's client to expose a notification endpoint (WebSocket, MQTT, gRPC stream) that the policy server can call when a policy changes. Per-policy priority would allow urgent security policies to push immediately while routine policies batch on the normal refresh.

Samba `samba-gpupdate` and SSSD `ad_gpo_access` use SSSD's periodic refresh (`ad_gpo_refresh_interval = 30` seconds for SSSD's GPO cache, but the underlying GPO fetch is still pull-based). macOS MDM has push (APNs) but only for MDM commands, not for arbitrary policy.

**Impact**:

Security policies propagate slowly; urgent changes (e.g., "disable SMBv1 now") require manual `gpupdate` on every host. The 90–120 minute window is an attacker's friend.

**Constraints**:

- Must support push-based refresh (webhook from server to client).
- Must support per-policy priority (urgent security policy pushes immediately, routine policy batches).
- For AD interop, must preserve the 90-min + jitter pull model for legacy Windows clients.

**Cross-platform considerations**:

- **Windows**: `gpsvc.dll` pull-based at 90-min + jitter; `gpupdate /force` for manual trigger.
- **macOS**: MDM push via APNs is real-time for MDM commands but not for arbitrary policy.
- **Linux**: SSSD pull-based at 30-second `ad_gpo_refresh_interval`; no push model.
- **Cross-platform consistency**: push model must work across all three platforms; WebSocket or gRPC stream is platform-agnostic.

**KB references**:

- [`04-group-policy/02-gpo-processing-order.md`](../docs/04-group-policy/02-gpo-processing-order.md) — Background refresh interval, per-CSE refresh exclusions, `GroupPolicyRefreshRate` registry.
- [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) — `gpsvc.dll` notification timer setup (90-min interval + 0-30 min jitter), `gpupdate.exe` entry points (`RefreshPolicyEx`, `ProcessGroupPolicyEx`).

**Open questions**:

- WebSocket / MQTT push channel for policy updates?
- Per-policy TTL (urgent policy TTL = 30 seconds, routine = 90 minutes)?
- Hybrid: push notification triggers immediate pull (server tells client "refresh now" and client pulls)?

**Cross-capability impact**:

- Affects: PC-050 (slow-link interacts with refresh frequency), PC-055 (SYSVOL replication lag compounds the refresh delay).
- Affected by: PC-048 (no rollback — push model makes rollback-on-failure more urgent).

---

### PC-052 — Registry.pol PReg format is binary/UTF-16; needs explicit parser

**Capability**: Policy Engine
**Severity**: medium
**Cross-platform**: Windows, macOS, Linux

**Problem statement**:

`Registry.pol` is a binary file with a 6-byte signature `PReg\0` (literal bytes `0x50 0x52 0x65 0x67 0x00 0x00`) followed by UTF-16LE-encoded records, per [04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md). Each record is `[key;value;type;size;data;]` where `key` and `value` are UTF-16LE strings, `type` is decimal ASCII digits (1=REG_SZ, 2=REG_EXPAND_SZ, 3=REG_BINARY, 4=REG_DWORD, 7=REG_MULTI_SZ), `size` is decimal ASCII digits (byte length of decoded `data`), and `data` is hex-encoded ASCII. The Registry CSE (`userenv.dll!ProcessRegistryPolicy`) calls `PReg_ReadFile` to parse this format and writes to the registry via `RegCreateKeyExW`/`RegSetValueExW`.

The PReg format is opaque to non-Windows clients. SSSD does not parse `Registry.pol` at all — it only reads `GptTmpl.inf` for `[Privilege Rights]`. Samba's `samba-gpupdate` does parse PReg via `libndr` and translates a fixed set of known policy keys (`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\...` → `/etc/krb5.conf`, `/etc/security/limits.conf`, `/etc/sudoers.d/`) — but the mapping is hard-coded in `samba-gpupdate` source, not schema-driven. macOS has no PReg concept; MDM payloads are plist XML. Per the matrix in [10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md), there is no macOS equivalent for Registry.pol settings.

For the framework, the choice is between (a) keeping PReg for Windows interop and adding a PReg reader to the macOS/Linux client, (b) adopting a portable format (JSON/YAML) for new policies and providing a PReg compat reader for legacy, or (c) using per-platform native formats (Registry.pol on Windows, plist on macOS, YAML/INI on Linux). Option (b) is the cleanest but requires the framework's policy authoring surface to emit both PReg (for `gpsvc.dll`) and the new format.

**Impact**:

`Registry.pol` is opaque to non-Windows clients. The same GPO applied to Windows/macOS/Linux produces different effective configuration because only Windows consumes the Registry.pol settings.

**Constraints**:

- Must support PReg for Windows interop (existing `userenv.dll!PReg_ReadFile`).
- New framework policies should use JSON/YAML with a PReg adapter for Windows.

**Cross-platform considerations**:

- **Windows**: `userenv.dll!PReg_ReadFile` parses natively; writes to `HKLM\Software\Policies\` or `HKCU\Software\Policies\`.
- **macOS**: No PReg parser; MDM uses plist XML. Translation requires a per-key mapping table.
- **Linux**: Samba `samba-gpupdate` parses PReg but maps only a fixed key set. SSSD does not parse.
- **Cross-platform consistency**: a unified JSON format compiled to PReg/plist/YAML is the cross-platform path.

**KB references**:

- [`04-group-policy/05-gpt-gpc-structure.md`](../docs/04-group-policy/05-gpt-gpc-structure.md) — PReg binary format, `PReg\0` signature, record field encoding, Python/PowerShell decoder examples.
- [`04-group-policy/04-cse-client-side-extensions.md`](../docs/04-group-policy/04-cse-client-side-extensions.md) — Registry CSE `userenv.dll!ProcessRegistryPolicy` and `PReg_ReadFile` entry point.

**Open questions**:

- Single policy format (JSON) with PReg adapter for Windows?
- Per-platform native formats with a unified authoring surface that compiles to each?
- Treat PReg as legacy read-only (the framework reads but never writes PReg; new policies use JSON)?

**Cross-capability impact**:

- Affects: PC-046 (ADMX compiles to PReg), PC-047 (Registry CSE consumes PReg).
- Affected by: PC-053 (SSSD ignores PReg entirely).

---

### PC-053 — SSSD GPO access control only enforces `[Privilege Rights]` logon rights

**Capability**: Policy Engine
**Severity**: high
**Cross-platform**: Windows, macOS, Linux

**Problem statement**:

SSSD's GPO access control is a partial re-implementation of the Windows Security CSE (`scecli.dll!SceProcessReturnedGPOs`). Per [09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md), SSSD's `ad_gpo_access` module (in `src/providers/ad/ad_gpo.c` and `ad_gpo_child.c`) fetches `\\<sysvol>\<domain>\Policies\{<guid>}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` over SMB (libsmbclient, GSS-SPNEGO as the host machine account), parses only the `[Privilege Rights]` section, and maps the listed SIDs to the requesting PAM service. Supported rights: `SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeBatchLogonRight`, `SeServiceLogonRight` (plus their `Deny` counterparts) — 10 rights out of the ~50 in Windows User Rights Assignment.

All other GPO areas are ignored on Linux: Account Policies (password, lockout, Kerberos), Administrative Templates (Registry.pol), Scripts, Preferences (Drive Maps, Files, etc.), Audit Policy, Restricted Groups, Software Install, AppLocker. Per the matrix in [10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md), the only GPO area with SSSD support is User Rights Assignment logon rights. macOS MDM covers a different subset (password policy, account lockout, firewall, Gatekeeper) — also partial.

The semantic mismatch runs deeper than coverage: SSSD's `ad_gpo_evaluate_gpo` applies AND semantics across GPOs (the user must be in the Allow list of every applicable GPO in the chain) — whereas Windows applies OR semantics (the user must be in the Allow list of at least one GPO that grants the right). With `ad_gpo_implicit_deny = false` (default), `NO_APPLICABLE_POLICY` ⇒ allow; with `true`, ⇒ deny. The default Linux behavior diverges from Windows.

For the framework, the choice is between (a) extending SSSD's coverage to all GPO areas (significant engineering), (b) adopting FreeIPA HBAC semantics as the cross-platform access-control model and mapping GPO URA to HBAC at compile time, or (c) accepting that GPO coverage on non-Windows is partial and documenting the gap.

**Impact**:

GPO access control on Linux is ~1/50th of Windows scope. The same GPO applied to Windows and Linux produces vastly different effective access control. AND-vs-OR semantics divergence means a user allowed on Windows may be denied on Linux for the same right.

**Constraints**:

- Must support the 5 logon rights on Linux for AD interop.
- FreeIPA HBAC is a modern alternative (user × host × service × source-host evaluation).
- HBAC-to-URA mapping at compile time would unify the model.

**Cross-platform considerations**:

- **Windows**: Security CSE applies all ~50 User Rights + Account Policies + Audit Policy + Restricted Groups.
- **macOS**: MDM covers password policy + account lockout + Gatekeeper; no URA equivalent.
- **Linux**: SSSD covers 10 URA logon rights with AND semantics; nothing else.
- **Cross-platform consistency**: a unified access-control model (e.g., HBAC-style) is the only path to parity.

**KB references**:

- [`09-linux-equivalents/03-sssd-gpo-access.md`](../docs/09-linux-equivalents/03-sssd-gpo-access.md) — SSSD `ad_gpo.c` architecture, `GptTmpl.inf` parsing, AND-vs-OR semantics, `ad_gpo_implicit_deny` default.
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Cross-platform coverage per GPO area showing SSSD's 1/50th-of-Windows scope.

**Open questions**:

- Adopt FreeIPA HBAC semantics as the cross-platform access-control model?
- Map GPO URA to HBAC at compile time (SDDL SID list → HBAC user/group/host/service)?
- Extend SSSD to parse additional `GptTmpl.inf` sections (Account Policies, Audit)?

**Cross-capability impact**:

- Affects: PC-044 (AND-vs-OR semantics diverge from Windows LSDOU), PC-047 (CSE model — SSSD is the only Linux CSE-equivalent).
- Affected by: PC-052 (Registry.pol is opaque to SSSD).

---

### PC-054 — GPO security filtering on `Authenticated Users` is fragile

**Capability**: Policy Engine
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Default GPOs are ACLed for `Authenticated Users` (S-1-5-11, well-known group including every authenticated user AND computer in the forest) with `Read` + `Apply Group Policy` (extended-right GUID `edacfd8f-ffb3-11d1-b41d-00a0c968f939`). Per [04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), for a user/computer to apply a GPO, both `Read` permission on the GPC object (and GPT folder) AND `Apply Group Policy` ACE on the GPC must be present for the security principal or a group containing it; `Deny` ACEs always win.

A common operational footgun: an admin removes `Authenticated Users` from a GPO's ACL to scope it to a specific group (e.g., "Finance Users"), and forgets that the **computer account** needs `Read` at boot to fetch machine policy. The result: machine-side policy silently fails on every host whose computer account is not in the scoped group. The workaround is to add `Domain Computers` (S-1-5-21-...-515) explicitly with `Read`, but this is frequently missed. Per the same KB, the modern PowerShell is `Set-GPPermissions -TargetName "..." -PermissionLevel GpoApply -TargetName "DOMAIN Computers"` — but the GPMC UI does not make the computer-account requirement obvious.

On macOS and Linux, security filtering is honored differently. SSSD's `ad_gpo_evaluate_gpo` checks the GPC's `nTSecurityDescriptor` for the host's computer account SID and the user's PAC SIDs (`PAC_LOGON_INFO.GroupIds`, `ExtraSids`, `LogonDomainId`). If `Authenticated Users` is removed and the host's group is not added, SSSD silently skips the GPO. macOS AD plugin behaves similarly.

For the framework, the default ACL model should auto-include computer accounts (a `Domain Computers`-equivalent always gets `Read`) and document the security-filter model clearly. A role-based policy binding (policy → role → principals) would avoid the per-principal ACL footgun.

**Impact**:

Removing `Authenticated Users` silently breaks computer policy. Worst case: a security GPO scoped to "Finance Users" applies to user policy but silently fails on machine policy because the computer account lacks `Read`. The failure is invisible until `gpresult /scope computer` shows the GPO in the "Denied" list.

**Constraints**:

- Must support per-principal ACL on policy objects.
- Must include computer accounts by default (auto-add `Domain Computers`-equivalent with `Read`).
- For AD interop, must honor existing GPC `nTSecurityDescriptor` ACEs.

**Cross-platform considerations**:

- **Windows**: `Authenticated Users` (S-1-5-11) is the default; removing it breaks machine policy silently.
- **macOS**: AD plugin honors GPC ACL; same footgun applies.
- **Linux**: SSSD honors GPC ACL via `nTSecurityDescriptor` check; same footgun applies.
- **Cross-platform consistency**: the failure mode is consistent across platforms (all silently skip the GPO), but the diagnostic tooling differs.

**KB references**:

- [`04-group-policy/02-gpo-processing-order.md`](../docs/04-group-policy/02-gpo-processing-order.md) — Security filtering mechanics, `Apply Group Policy` extended-right GUID, `Authenticated Users` default and footgun, `Set-GPPermissions` cmdlet.
- [`09-linux-equivalents/03-sssd-gpo-access.md`](../docs/09-linux-equivalents/03-sssd-gpo-access.md) — SSSD's `nTSecurityDescriptor` check and PAC SID evaluation.

**Open questions**:

- Replace per-principal ACL with role-based policy binding (policy → role → principals)?
- Auto-include computer accounts with `Read` on every policy?
- Add a GPMC warning when `Authenticated Users` is removed without a computer-account replacement?

**Cross-capability impact**:

- Affects: PC-053 (SSSD honors the same ACL — same footgun).
- Affected by: PC-044 (security filtering interacts with LSDOU ordering).

---

### PC-055 — SYSVOL replication via DFS-R is Windows-only; FRS is removed

**Capability**: Policy Engine
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

SYSVOL replicates via DFS-R (`dfsr.exe`) using version vectors + RDC (Remote Differential Compression) over the wire and the USN journal (`$Extend\$UsnJrnl:$J`) for change detection. Per [07-file-print/02-dfs-n-dfs-r.md](../docs/07-file-print/02-dfs-n-dfs-r.md), the DFS-R RPC interface is UUID `91b7b931-c75a-4530-8258-1b3eb578c5d8`, version 1.0, with opnums for `EstablishConnection`, `GetVersionVector`, `RequestUpdates`. Server 2008 R2+ uses DFS-R for SYSVOL replication (FRS is deprecated); Server 2019 removed FRS entirely. Migration is via `dfsmig.exe` (`/setglobalstate 0→1→2→3`). SYSVOL is a special Replication Group `CN=SYSVOL Share,CN=DFSR-LocalSettings,CN=<dc>,OU=Domain Controllers,DC=...` linked to the `Domain System Volume` content set in `CN=DFSR-GlobalSettings,CN=System,DC=...`.

Samba AD-DC replicates SYSVOL via DRSUAPI on the SysVol directory (single-master per attribute) — a different mechanism, not DFS-R. Per the same KB, Samba's `source4/rpc_server/drsuapi/` is the only non-Microsoft implementation that answers DRSGetNCChanges as a server; Samba does NOT implement DFS-R. macOS SMBX does not host DFS-N namespaces or DFS-R. Linux `cifs.ko` and `mount.cifs` are DFS-N clients (referral-aware) but not DFS-R replication members.

For the framework, SYSVOL is the GPO + logon-script distribution channel; without it, GPO breaks. The choices are: (a) implement DFS-R-equivalent (write it — significant engineering, no open-source implementation exists), (b) Samba-style DRSUAPI-based SYSVOL (Samba's existing model), or (c) externalize to Git/object-store with auto-sync to DCs and provide SMB-read access for legacy clients.

**Impact**:

SYSVOL is the GPO + logon-script distribution channel; without it, GPO breaks entirely. Samba-only domains use DRSUAPI SYSVOL (works but different failure modes); mixed Windows+Samba domains can have replication conflicts between DFS-R and DRSUAPI SYSVOL.

**Constraints**:

- Must support GPO + script distribution to all clients via SMB (`\\<domain>\SYSVOL\...`).
- For AD interop with existing Windows DCs, must either speak DFS-R or operate in a non-mixed mode.
- For Samba interop, must support DRSUAPI-based SYSVOL.

**Cross-platform considerations**:

- **Windows**: DFS-R (`dfsr.exe`) for SYSVOL replication; FRS removed in Server 2019.
- **macOS**: SMBX client reads SYSVOL via SMB; does not host SYSVOL.
- **Linux**: Samba AD-DC hosts SYSVOL via DRSUAPI (not DFS-R); SSSD/Samba clients read via SMB.
- **Cross-platform consistency**: the client-side experience (`\\<domain>\SYSVOL\...`) is consistent; the server-side replication mechanism differs (DFS-R vs. DRSUAPI vs. Git).

**KB references**:

- [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md) — DFS-R architecture, RPC UUID, USN journal change detection, SYSVOL Replication Group, FRS-to-DFS-R migration.
- [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) — SYSVOL as the GPT distribution channel, `gPCFileSysPath` UNC linkage.

**Open questions**:

- Git-backed SYSVOL with auto-sync to DCs (write to Git → DCs pull on commit)?
- Samba-style DRSUAPI SYSVOL for non-Windows DCs?
- Implement DFS-R server-side for full AD interop (no open-source implementation exists)?

**Cross-capability impact**:

- Affects: PC-043 (GPC/GPT split — SYSVOL is the GPT side of the split), PC-051 (refresh interval — SYSVOL replication lag compounds the refresh delay).
- Affected by: PC-002 (replication model choice — DFS-R is state-based pull; DRSUAPI is also state-based pull with different opnums).

---

### PC-056 — No native policy versioning / history; reverting requires backup restore

**Capability**: Policy Engine
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

GPO has only `versionNumber` (OID `1.2.840.113556.1.4.1340`, combined machine+user 64-bit integer, per [04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md)). There is no history of past versions — only the current `versionNumber` and the previous one cached under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{<CSE-GUID>}\{<GPO-GUID>}\Version`. Reverting to a previous GPO state requires restoring from a `Backup-GPO -Path <path>` archive (which produces a `{<guid>}\GPO.xml` + `GPO_Backup.ini` snapshot) via `Restore-GPO -BackupId <guid>`. There is no Git-style history, no diff between versions, no per-setting change log.

Change management is manual: admins must run `Backup-GPO -All -Path \\backup\GPO-Backups\$(Get-Date)` on a schedule and trust the backup. There is no built-in audit trail of "who changed what when" beyond the AD object's `LastOriginatingChange` and the Group Policy Operational log (which is per-host, not per-GPO). The GPMC UI shows the current state only; comparing two versions requires exporting both and diffing with a third-party tool.

For the framework, Git-backed policies with full history and PR-based review would be a baseline expectation. Atomic rollback (per PC-048) and per-setting attribution (per PC-044) require versioning as a foundation. Auto-tag on apply (so a "known-good" version is always recoverable) and per-policy TTL for change windows are additional features.

**Impact**:

GPO change management is manual; revert is fragile. Without a `Backup-GPO` archive, a bad change is irreversible without System Restore. Audit ("who changed the LAPS policy last week?") requires scraping per-DC event logs.

**Constraints**:

- Must support policy version history (Git-style or equivalent).
- Must support atomic rollback to any prior version.
- For AD interop, must emit `versionNumber` increments on each change.

**Cross-platform considerations**:

- **Windows**: `Backup-GPO`/`Restore-GPO` PowerShell cmdlets; no built-in version history.
- **macOS**: MDM profiles have no version history; MDM servers (Jamf) keep revision history per-profile.
- **Linux**: SSSD/Samba have no policy version history; Ansible/Puppet/Salt provide versioning for their own configs but not for GPO consumption.
- **Cross-platform consistency**: Git-backed policies with cross-platform client support is the unified path.

**KB references**:

- [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) — `versionNumber` packing, GPC `versionNumber` attribute, `Backup-GPO`/`Restore-GPO` workflow.
- [`04-group-policy/04-cse-client-side-extensions.md`](../docs/04-group-policy/04-cse-client-side-extensions.md) — `History\{CSE-GUID}\{GPO-GUID}\Version` per-CSE per-GPO cache (only one prior version).

**Open questions**:

- Git-backed policies with PR-based review (every policy change is a PR, reviewed before merge)?
- Auto-tag on apply (so a "known-good" version is always recoverable)?
- Per-policy TTL for change windows (changes auto-revert after N hours if not confirmed)?

**Cross-capability impact**:

- Affects: PC-048 (rollback requires versioning as foundation).
- Affected by: PC-043 (GPC/GPT split — versioning must span both halves).

---

## Cross-capability impact

Problems in this capability affect and are affected by problems in other capabilities:

- **File Gateway (PC-078..PC-084)**: SYSVOL replication via DFS-R (PC-055) depends on the File Gateway's SMB server and replication implementation. The Policy Engine consumes the File Gateway's `\\<domain>\SYSVOL\...` UNC surface.
- **Core Directory (PC-001..PC-022)**: GPC objects live in AD (PC-043); `gPLink`/`gPOptions` are AD attributes on `site`/`domainDNS`/`organizationalUnit` objects. DRSUAPI replication of GPC (PC-043) is a Core Directory concern.
- **Client SDK (PC-085..PC-093)**: Policy application on enrolled clients is a Client SDK responsibility; the CSE-equivalent plugin model (PC-047) is the interface between Policy Engine and Client SDK.
- **Cross-Platform Parity (PC-094..PC-105)**: SSSD GPO access control coverage (PC-053) is the largest cross-platform parity gap in the Policy Engine.
- **Operations (PC-106..PC-115)**: GPO backup/restore (PC-056) is an Operations concern; `dfsrdiag`/`gpresult` tooling is Operations surface.
- **Security & Threat Model (PC-116..PC-123)**: GPO security filtering on `Authenticated Users` (PC-054) has a security dimension — over-broad ACLs are an attack surface.
- **Migration & Coexistence (PC-124..PC-130)**: ADMX-to-unified-schema translation (PC-046) and GPO-to-declarative-policy translation are Migration concerns.

## Open research questions specific to this capability

1. **Unified policy schema**: Should the framework adopt OPA Rego, Cedar, XACML, or invent a new DSL as the unified policy-definition format that compiles to ADMX/MDM/SSSD-conf? What are the trade-offs in expressiveness, auditability, and tooling support?

2. **Policy distribution model**: Pull (current GPO model) vs. push (webhook/MQTT) vs. hybrid (push notification triggers pull). What is the right model for urgent security policy propagation without sacrificing operability?

3. **CSE-equivalent plugin model**: Should the framework define a per-platform plugin interface (snapshot/apply/rollback) and ship reference plugins for each Preferences area? Or treat CSEs as legacy and ship a single "framework CSE" that delegates to platform-native executors?

4. **WMI filter replacement**: Declarative host facts (OS, role, site, IP range) vs. keeping WMI for Windows-only. What is the cross-platform filter model that preserves AD interop?

5. **SYSVOL replication strategy**: Git-backed SYSVOL vs. Samba-style DRSUAPI SYSVOL vs. implementing DFS-R server-side. What is the right trade-off between AD interop and operational simplicity?

6. **SSSD coverage expansion**: Should the framework extend SSSD to parse additional `GptTmpl.inf` sections (Account Policies, Audit), or adopt FreeIPA HBAC as the unified access-control model with URA-to-HBAC mapping?

7. **Transactional policy apply**: Per-CSE snapshot/rollback vs. Git-style revert vs. dry-run preview. What is the right contract for framework CSE-equivalent plugins?

8. **Policy attribution**: Per-setting attribution stored alongside values (e.g., `HKLM\...\Value\GPOSource`) for post-hoc debugging. Is this worth the storage overhead?

9. **Cross-platform slow-link detection**: TCP RTT vs. HTTP HEAD probe vs. per-policy TTL. What is the right model that works across Windows/macOS/Linux?

10. **Preferences XML on non-Windows**: Should the framework implement Preferences XML parsers for macOS/Linux, or treat Preferences as legacy and require new policies to use the unified format?
