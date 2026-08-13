---
title: Operations — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, operations, framework-design, gap-analysis, observability, kubernetes, dr]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./09-cross-platform-parity.md
  - ./11-security-threat-model.md
  - ./12-migration-and-coexistence.md
  - ./13-open-research-questions.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Operations — Problem Catalog

**Capability definition.** Operations is the deploy / configure / monitor / backup / restore / upgrade / troubleshoot layer of the framework. It inherits from AD the deployment model (dcpromo, deprecated; Server Manager), the operational CLI (`repadmin`, `dcdiag`, `ntdsutil`, `nltest`, `setspn`, `ksetup`), the audit pipeline (Windows Event Log XML), and Performance Monitor counters — all Windows-only, all imperative, none container-native. The framework's Operations capability must additionally provide Kubernetes-native deployment (StatefulSet + operator), Prometheus metrics, OpenTelemetry tracing, structured JSON/CEF audit events, a modern REST/gRPC management API, and one-command disaster recovery.

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-106 | No native Prometheus exporter / OpenTelemetry for AD | high | cross-platform |
| PC-107 | Schema upgrades are irreversible; `objectVersion` bump is one-way | high | Windows |
| PC-108 | Multi-region AD deployment has replication latency; PDC urgent replication | high | cross-platform |
| PC-109 | AD has no containerization; no Kubernetes-native deployment | high | cross-platform |
| PC-110 | Disaster recovery is manual (ntdsutil + metadata cleanup + IFM) | high | cross-platform |
| PC-111 | AD audit logs are Windows Event Log only; no structured logging | high | cross-platform |
| PC-112 | AD has no REST/gRPC API; only LDAP + PowerShell | high | cross-platform |
| PC-113 | AD functional level upgrades are one-way; mixed-version forests are fragile | medium | Windows |
| PC-114 | Trust password rotation (every 30 days) can desync; manual reset required | medium | cross-platform |
| PC-115 | `dcdiag` / `repadmin` / `ntdsutil` are Windows-only; cross-platform tooling is fragmented | medium | Windows, macOS, Linux |

---

## Detailed problem entries

### PC-106 — No native Prometheus exporter / OpenTelemetry for AD

**Capability**: Operations
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD emits two streams of operational signal: Windows Event Log XML records (security events 4768/4769 for AS-REQ/TGS-REQ, 5136 for Directory Service Access modifies, 4662 for object access, 4624 for logon; described in [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) and [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md)) and Performance Monitor counters exposed via the `NTDS` and `LDAP` perfmon objects (DC-side: `NTDS\DRA Inbound Bytes Total/sec`, `NTDS\LDAP Bind Time`, `NTDS\DS %  Read from DIT (% of total)`; LSASS-side: `LSASS\Estimated process count`, `LSASS\Context switches/sec`). Neither is wire-compatible with Prometheus' text-exposition format nor with the OpenTelemetry OTLP span/metric data model.

To bridge, organisations deploy Windows Event Forwarding (WEF) subscriptions from each DC to a collector running `WinLogBeat`, `nxlog`, or `Splunk_TA_windows`, then parse the XML in a downstream SIEM. Per-request distributed traces simply do not exist — an LDAP bind crosses LSASS, `ntdsa.dll`, the ESE layer, the schema cache, and the SD table; none of these emit a span. There is no equivalent of an HTTP `X-Request-ID` propagated through the stack. For Prometheus metrics, third-party exporters such as `wmi_exporter` (now `windows_exporter`) translate a curated subset of perfmon counters into Prometheus gauge/counter metrics, but the bridge is one-shot per scrape, has no histogram support for replication lag, and adds latency jitter on the DC. Samba AD-DC has `samba-tool eventlog` and the `smbd` internal `stat` counters but again no OTel exporter.

The framework gap is fundamental: any modern framework must be observable by default. SIEM-first architectures (Splunk, Elastic, Datadog, Chronicle) expect JSON or OTLP. Kubernetes operators expect Prometheus metrics with `_total` counter suffixes and histogram buckets for latency. Without these, the framework cannot be monitored by modern stacks without bespoke adapters, and per-request tracing across the KDC + DSA + Auth-Provider boundary is invisible.

**Impact**:

Modern SIEMs require Windows Event Forwarding + XML parsing, adding 5-30 second latency and breaking structured queries. Prometheus-only monitoring stacks (Prometheus + Grafana + Alertmanager) cannot scrape AD without `windows_exporter`, and the exporter covers <40% of the perfmon surface that matters for AD (no replication-lag histogram, no per-realm AS-REQ rate, no `DRSGetNCChanges` byte-count counter). Per-request tracing is impossible.

**Constraints**:

- Must emit Prometheus metrics (auth rate, replication lag, KDC errors, ESE cache hit ratio, FSMO holder changes).
- Must emit OTel traces (per LDAP request, per Kerberos exchange, per replication cycle).
- Must keep the perfmon counter path (`\\<DC>\NTDS\...`) intact for AD-interop scenarios.
- Must not introduce measurable latency on the request path (<1% overhead at 10k req/s).

**Cross-platform considerations**:

- **Windows**: DC-side observability stays perfmon + Event Log; add a sidecar exporter (Windows service) emitting Prometheus + OTLP.
- **macOS**: Apple's unified logging (`log show`) lacks structured field extraction; OTLP must be emitted by the framework client SDK and PSSO Extension.
- **Linux**: SSSD logs to syslog/journald with structured fields; Samba logs to its own logfiles; both need OTLP adapters.
- **Cross-platform consistency**: Without a unified OTLP emission story, cross-platform correlation of a single user's auth path (Mac → framework DC → file share on Linux) is impossible.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Kerberos event IDs 4768/4769/4771 and Wireshark display filters for AS-REQ/TGS-REQ diagnostics.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — ESE transaction commit path, event 5136 raise, registry keys (`Strict Replication Consistency`, `LDAPClientIntegrity`) that should be metrics.

**Open questions**:

- Adopt OTel semantic conventions for AD/Kerberos? Per-DC metrics or per-realm aggregation?

**Cross-capability impact**:

- Affects: PC-111 (audit logs), PC-117 (DCSync detection — needs Event 4662 stream), PC-122 (AdminSDHolder audit).
- Affected by: PC-112 (REST/gRPC API would naturally emit OTel spans per request).

---

### PC-107 — Schema upgrades are irreversible; `objectVersion` bump is one-way

**Capability**: Operations
**Severity**: high
**Cross-platform**: Windows

**Problem statement**:

AD's schema version is encoded as a single integer `objectVersion` attribute on the Schema NC head (`CN=Aggregate,CN=Schema,CN=Configuration,...`). It has stepped monotonically: 13 = Windows 2000, 30 = Server 2003, 44 = Server 2008, 47 = Server 2008 R2, 56 = Server 2012, 61 = Server 2012 R2, 69 = Server 2016, 72 = Server 2019, 88 = Server 2022. Each release ships an `adprep /forestprep` action that adds new `attributeSchema` and `classSchema` objects, increments `objectVersion`, and refreshes the schema cache by writing `schemaUpdateNow = 1` to `CN=Aggregate,CN=Schema,...` per [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md).

Once extended, the schema cannot be rolled back. Attributes and classes can be marked `isDefunct = TRUE` (effectively tombstoned) but the OID arc and `governsID` are burned forever; the schema cache reload still walks them. There is no `adprep /forestrollback`. A failed `adprep` that died mid-extension leaves the schema in a partial state that Microsoft support can sometimes clean up by hand but the operation is unsupported. Real-world consequence: organisations stage schema upgrades in a separate lab forest, run them in prod during maintenance windows, and delay upgrades by years. The Windows Server 2022 schema upgrade (`objectVersion = 88`) was rolled out to many enterprises 2-3 years after release because of this risk.

The framework gap is that any schema-as-code (Git-backed typed-schema with versioned migrations) approach must contend with: (a) AD-interop requires the literal `objectVersion = 88` schema, (b) the framework must replicate the exact `attributeSchema` set so AD DCs that consume the framework's schema via DRSUAPI do not see missing attributes, and (c) migration from a typed schema back to AD's LDAP schema (for rollback) is lossy. There is no framework today that does schema migrations safely; the closest analog is Django's `makemigrations` + `migrate`, but AD's schema NC has 1,400+ classes and 2,800+ attributes that cannot be auto-migrated.

**Impact**:

Schema upgrades are the single most operationally risky AD change. Failed upgrades leave the forest in an unrecoverable state. Orgs delay upgrades by 2-3 years, missing security fixes (e.g. Server 2019 schema enabled claims-based Kerberos hardening).

**Constraints**:

- Must support forward migration of the schema.
- Must support defunct-attribute cleanup without removing OIDs.
- Must remain wire-compatible with MS-ADTS §3.1.1.2 schema objects.
- Must support schema-cache reload without restarting the DSA (`schemaUpdateNow = 1` semantics).

**Cross-platform considerations**:

- **Windows**: AD-interop scenarios require exact `objectVersion` matching with Microsoft's schema; the framework's typed-schema migration must emit `attributeSchema`/`classSchema` objects with identical OIDs.
- **macOS**: No native directory; OpenDirectory's schema is Apple-specific and unrelated.
- **Linux**: Samba AD-DC ships schema templates in `source4/setup/AD/`; FreeIPA's 389-DS uses RFC 4512 `attributeTypes`/`objectClasses` syntax — neither matches AD's schema verbatim.
- **Cross-platform consistency**: A framework that supports Windows + macOS + Linux clients must serve the same schema to all three. Typed-schema migration must produce identical LDAP-exposed schema.

**KB references**:

- [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md) — `objectVersion` table, schema update procedure, `schemaUpdateNow` semantics, OID allocation arcs.
- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — Schema NC replication; the schema is the first NC replicated on a fresh DC.

**Open questions**:

- Schema-as-code (Git-backed)? Typed-schema with versioned migrations?

**Cross-capability impact**:

- Affects: PC-113 (functional levels depend on schema version), PC-125 (GPO translation requires schema for ADMX back-mapping).
- Affected by: PC-001 (DRSUAPI replication of schema NC must be byte-compatible), PC-002 (USN/UTD vector applies to schema replication).

---

### PC-108 — Multi-region AD deployment has replication latency; PDC urgent replication

**Capability**: Operations
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD replication topology is computed by the KCC every 15 minutes (`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\KCC Idle Duration Between Runs = 1800` sec). Intra-site replication is change-notification-driven (15-second default). Inter-site replication is scheduled, compressed (LZ77+Huffman via `ntdsa.dll!MDSCompressionCompress`), and bounded by the site-link cost and schedule window — defaults to 15-180 seconds per hop. For a 3-region deployment (US-East, US-West, EU), an originating write at US-East propagates to EU in 30-360 seconds depending on schedule and link utilisation, per the analysis in [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) and [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md).

Password changes are special: they trigger urgent replication. The DC that accepted the change immediately single-replicates the new `unicodePwd` to the PDC emulator FSMO holder (within 15 seconds). Every DC, on a failed logon with the old password, falls back to the PDC before rejecting. This mechanism is what makes "user changed password 30 seconds ago in EU; user is now in US and logs in" work — but it only works for password changes, not for general attribute writes. A new group membership added in EU takes the normal replication interval to reach US; a user in US logging in immediately after will not see the new group in their PAC.

The framework gap: modern multi-region systems expect active-active with sub-second convergence. CRDTs (last-writer-wins with vector clocks, or operation-based CRDTs) can converge in milliseconds. AD's pull-based state replication with UTD vectors converges in tens of seconds to minutes. The framework must either (a) accept AD's convergence semantics for interop, (b) layer a faster convergence protocol on top for cross-region password/group changes, or (c) implement an entirely different replication model and lose AD-interop. Option (b) is what Microsoft did for Azure AD Domain Services (separate replica set with convergent consistency), but the on-prem AD product has never gained it.

**Impact**:

Cross-region password-change propagation is bounded by PDC urgent replication (15 sec) which works for passwords but not for group membership, ACL, or attribute changes. Multi-region logon failures after administrative changes have a 30-360 second window. Globally distributed apps see ~5 minutes of inconsistency on average.

**Constraints**:

- Must support per-region DC pools with explicit PDC pinning.
- Must support urgent replication for password changes (matching AD's 15-second SLA).
- Must support multi-region failover (PDC emulator FSMO seizure in <60 sec).
- For AD-interop: must preserve `DRSGetNCChanges` semantics including `EXOP_REPL_SECRETS` for password replication.

**Cross-platform considerations**:

- **Windows**: AD-interop scenario requires the framework's DC to participate in the same forest and replicate via DRSUAPI; cross-region convergence is bounded by AD's scheduler.
- **macOS**: Mac clients are not DCs; they observe PDC convergence via `kpasswd` (RFC 3244) which redirects to the PDC emulator for password changes.
- **Linux**: Samba AD-DC participates in inter-site replication as a DC; FreeIPA uses 389-DS MMR with its own convergence model (faster, but not AD-compatible).
- **Cross-platform consistency**: Without PDC-pinning for password changes, a Mac user changing password in EU and immediately logging in in US will fail.

**KB references**:

- [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) — PDC emulator role, urgent replication for password changes, fallback-to-PDC on logon failure.
- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — UTD vector, `DRSGetNCChanges` request/response, inter-site compression.

**Open questions**:

- Per-region PDC? Active-active multi-region with conflict-free replicated data types?

**Cross-capability impact**:

- Affects: PC-114 (trust password rotation hits the same replication-latency problem), PC-110 (DR across regions depends on convergence model).
- Affected by: PC-001 (DRSUAPI replication protocol), PC-002 (USN/UTD vector model).

---

### PC-109 — AD has no containerization; no Kubernetes-native deployment

**Capability**: Operations
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

An AD DC is a Windows Server VM running `lsass.exe` with the DSA loaded as a DLL, the `ntds.dit` ESE database on local disk (`%SystemRoot%\NTDS\ntds.dit`), the SYSVOL share on NTFS, and the DNS server in `dns.exe` under a `svchost -k NetworkService` host per [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) and [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md). Deployment historically used `dcpromo` (deprecated in Server 2012); modern deployment uses Server Manager or `Install-ADDSDomainController` PowerShell cmdlet. There is no container image of AD DS. The `ntds.dit` file is held open exclusively by `lsass.exe` and cannot be shared between container instances. SYSVOL replication requires DFS-R (`dfsr.exe`), which expects persistent NTFS storage. There is no Helm chart, no operator, no StatefulSet template.

Samba 4 as AD-DC has experimental container images (`istrict/samba-dc`, `ghcr.io/elementaryos/samba-server`) but these are community-maintained, run a single DC per container, and require manual DRS replication setup. FreeIPA is similarly VM-centric; the upstream project explicitly does not support containerized replicas. Microsoft's Azure AD Domain Services is a managed service but the DC instances are not customer-visible containers — it is a PaaS abstraction.

The framework gap is fundamental to cloud-native deployment. Modern identity platforms (Keycloak, Authentik, Ory, Zitadel) ship as Docker images with Helm charts and Kubernetes operators. They scale horizontally with StatefulSets, store state in external databases (Postgres, CockroachDB, FoundationDB), and integrate with CSI for persistent volumes. An AD-equivalent framework must do the same: container image per DC, StatefulSet with PVC-backed DIT, operator for promote/demote/backup, rolling upgrades with schema-version checks. The DIT being on a PVC is straightforward; the harder part is the LSASS-equivalent process model — the framework cannot use Windows LSASS as the KDC/DSA host in a container, so it must run a multi-process or multi-threaded daemon that exposes the same wire protocols (LDAP, Kerberos, DRSUAPI, SAMR, LSARPC, Netlogon).

**Impact**:

AD deployment is VM-centric; cloud-native deployment is manual. Provisioning a new DC takes 30-60 minutes via dcpromo/Server Manager. Container-based provisioning could be 30-60 seconds. Auto-scaling DCs based on auth rate is impossible in AD.

**Constraints**:

- Must support StatefulSet with PVC-backed DIT (ReadWriteOnce).
- Must support rolling upgrades with schema-version compatibility checks.
- Must support operator-driven lifecycle: promote, demote, backup, restore, schema-upgrade, FSMO transfer.
- Must support `livenessProbe` / `readinessProbe` on LDAP / Kerberos / DNS ports.
- Must NOT share the DIT file across containers (ESE file locking).

**Cross-platform considerations**:

- **Windows**: Container-based Windows DCs require Windows Server Core base image + process isolation (not Hyper-V isolation, due to LSASS). Windows containers are 5-10× larger than Linux containers.
- **macOS**: Not a DC platform; irrelevant.
- **Linux**: Samba-based DCs run as Linux containers naturally; the framework's reference implementation should target Linux containers first.
- **Cross-platform consistency**: The framework's DC image should build for both Windows Server Core and Linux (Ubuntu/UBI) with identical operational semantics.

**KB references**:

- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — AD DS service binary, listening ports, deployment model.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — LSASS process model, ESE database file locking, registry-based configuration keys.

**Open questions**:

- Container image per DC? Operator for DC lifecycle (promote/demote/backup)?

**Cross-capability impact**:

- Affects: PC-110 (DR runbooks become operator-driven), PC-115 (CLI tooling must run inside the container).
- Affected by: PC-007 (storage engine choice — RocksDB/FoundationDB are container-friendly, ESE is not), PC-020 (backup model affects container storage layout).

---

### PC-110 — Disaster recovery is manual (ntdsutil + metadata cleanup + IFM)

**Capability**: Operations
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD disaster recovery is a multi-step manual procedure documented in [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) and [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md). The canonical runbook for a dead-DC scenario:

1. `ntdsutil → metadata cleanup → remove selected server <DC>` — removes the NTDS Settings object and the computer account from AD (otherwise the dead DC lingers as a replication partner).
2. `repadmin /removelingeringobjects` — cleans up objects on other DCs that were deleted on the dead DC but not yet replicated (tombstone-lifetime-exceeded scenarios, event 2042).
3. `IFM` (Install From Media) — `ntdsutil → ifm → create full <path>` produces an offline DIT snapshot used to seed a new DC without pulling the full DIT over the WAN.
4. `Restore-ADObject` (Active Directory Recycle Bin, requires forest functional level ≥ 2008 R2) — restores deleted objects from the recycled-object state.
5. USN rollback recovery — if a DC was restored from a non-VSS-aware snapshot, the partner detects the rollback via `CheckUsnRollback` in `ntdsa.dll`, logs event 2095, and refuses replication; the only safe recovery is `dcpromo /forceremoval` + metadata cleanup + re-promotion.

Every step is interactive. `ntdsutil` is a Windows-only CLI with a nested menu interface (not scriptable without `ntdsutil.exe … < input.txt` hacks). Recovery Time Objective (RTO) for a single-DC failure is typically 2-4 hours with an experienced operator; for a forest-root failure (all DCs in the forest root domain lost), RTO is 8-24 hours because schema restoration from backup + cross-domain trust re-establishment + Group Policy re-link is required.

The framework gap: modern systems provide one-command restore. CockroachDB has `cockroach dump` + `cockroach restore`. PostgreSQL has Point-In-Time Recovery (PITR) via WAL archiving. Kubernetes operators (e.g. the Postgres-operator) automate backup, restore, and failover. The framework should provide an operator that handles: per-DC backup (PVC snapshot of the DIT + WAL archiving), point-in-time restore, automated metadata cleanup when a DC pod is terminated, Recycle Bin equivalent by default (no forest-functional-level gate), and USN-rollback-equivalent detection via Raft term numbers (a partitioned-then-rejoined node simply rejoins the quorum, no manual cleanup).

**Impact**:

AD DR requires expert operators; RTO is hours for a single DC, days for a forest-root failure. Forest-root recovery without a current backup is forest-rebuild (weeks).

**Constraints**:

- Must support point-in-time restore (PITR) of the DIT.
- Must support automated metadata cleanup when a DC is permanently removed (pod deletion triggers NTDS-Settings cleanup).
- Must enable Recycle Bin by default (no functional-level gate).
- Must detect "USN rollback" automatically (snapshot-restored DC) and refuse to serve.
- Must support `IFM`-equivalent: seed a new DC from an offline DIT snapshot.

**Cross-platform considerations**:

- **Windows**: `ntdsutil` and `repadmin` are the canonical tools; the framework must preserve their behaviour for AD-interop.
- **macOS**: Not a DC platform; DR is client-side (rejoin).
- **Linux**: Samba AD-DC ships `samba-tool drs` and `samba-tool domain demote --remove-other-dead-server`; these are Linux-native but lack the polish of an operator.
- **Cross-platform consistency**: An operator-driven DR runbook should work identically for Windows-container DCs and Linux-container DCs.

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — USN rollback detection (`ntdsa.dll!CheckUsnRollback`), tombstone-lifetime handling, ESE -1018/-1022 errors.
- [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md) — Event 2095 (USN rollback), event 2042 (tombstone lifetime exceeded), `repadmin /removelingeringobjects`.

**Open questions**:

- Per-DC backup with PITR? Operator-driven DR runbooks?

**Cross-capability impact**:

- Affects: PC-109 (container deployment must integrate with PVC snapshot backup), PC-115 (CLI must expose DR commands).
- Affected by: PC-001 (DRSUAPI replication must support IFM seeding), PC-007 (storage engine choice — LSM-tree with WAL enables PITR; ESE does not natively).

---

### PC-111 — AD audit logs are Windows Event Log only; no structured logging

**Capability**: Operations
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD audit events are emitted via LSASS!AuthzReportSecurityEvent into the Windows Event Log, specifically the `Security` log (events 4624 logon, 4625 failed logon, 4662 object access, 4768 AS-REQ, 4769 TGS-REQ, 4771 pre-auth failed, 5136 Directory Service Access modify, 5137 directory object created, 5138 directory object modified, 5139 directory object moved, 5141 directory object deleted) and the `Directory Service` log (events 2095 USN rollback, 2042 tombstone lifetime exceeded, 1425 schema cache reload failure). Each event is XML-serialised per the Windows Event Log schema (`http://schemas.microsoft.com/win/2004/08/events/event`), with the audit data buried in `EventData` fields that are integer-indexed (`Data Name="AuthenticationPackageName"`) rather than keyed by semantic name.

Per [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) and [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md), Event 4768 (AS-REQ) carries the target user, the etype used for pre-auth, the source IP, and the result code; Event 4769 (TGS-REQ) carries the requested SPN, the service ticket etype, and the source IP. These are the primary signals for Kerberoasting detection (4769 with etype 0x17 = RC4) and AS-REP roasting detection (4768 with `0x0` pre-auth type). But the XML structure makes them painful to query: SIEM analysts must write XPATH or Regex over the `EventData` block to extract fields.

Windows Event Forwarding (WEF) is the canonical aggregation mechanism: a collector DC subscribes to all DCs' Security logs, re-emits them as `ForwardedEvents`. Third-party agents (`WinLogBeat`, `Splunk_TA_windows`, `nxlog`) parse the XML and re-emit as JSON/CEF. The pipeline adds 5-30 seconds of latency and breaks under event bursts (a 10k-user login storm can overflow WEF queues).

The framework gap is fundamental: modern systems emit structured JSON logs by default (Postgres JSON logs, Envoy access logs, OpenTelemetry log records). The framework should emit per-event JSON with full context (user, source, action, result, etype, SPN, IP, MITRE ATT&CK technique ID) directly to an OTel collector. SIEM integration should be one config stanza, not a custom XML parser.

**Impact**:

SIEM integration requires WEF + XML parsing, adding 5-30 second latency and breaking under event bursts. MITRE ATT&CK mapping is manual (analyst reads 4769, looks up T1558.003 in ATT&CK navigator). Real-time detection of Kerberoasting (4769 etype 0x17 storm) is gated by WEF latency.

**Constraints**:

- Must emit per-event JSON with full context (user, source, action, result, etype, SPN, IP).
- Must support OTel log records (OTLP/HTTP).
- Must preserve the Windows Event ID → framework-event-name mapping for AD-interop (e.g., framework event `kerberos.tgs.request` corresponds to Windows 4769).
- Must include MITRE ATT&CK technique IDs in event metadata for SIEM correlation.

**Cross-platform considerations**:

- **Windows**: AD DCs must continue to emit Event Log records for AD-interop; the framework adds a parallel JSON/OTLP stream.
- **macOS**: Apple unified logging (`os_log`) is structured but Apple-specific; the framework client SDK should emit OTLP directly.
- **Linux**: SSSD logs to syslog/journald; Samba logs to `/var/log/samba/`; both need OTel adapters or direct OTLP emission.
- **Cross-platform consistency**: A single user auth path (Mac client → framework DC → Linux file share) must produce a single trace ID spanning all three logs.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Kerberos event IDs and Wireshark display filters for AS-REQ/TGS-REQ diagnostics.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — Event 5136 raised inside the ESE transaction commit path via LSASS!AuthzReportSecurityEvent.

**Open questions**:

- OTel semantic conventions for AD/Kerberos/GPO? MITRE ATT&CK technique IDs in event metadata?

**Cross-capability impact**:

- Affects: PC-106 (Prometheus + OTel story is incomplete without structured logs), PC-117 (DCSync detection needs Event 4662 stream), PC-119 (silver-ticket detection needs 4769 with PAC validation failure).
- Affected by: PC-042 (Auth Provider audit events overlap with Operations audit).

---

### PC-112 — AD has no REST/gRPC API; only LDAP + PowerShell

**Capability**: Operations
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD's programmatic surface is three-tiered, all Windows-centric. (a) LDAP (RFC 4511) on TCP/389 / 636 / 3268 / 3269 with AD-specific controls (`LDAP_SERVER_SD_FLAGS_OID`, `LDAP_SERVER_NOTIFICATION_OID`, `LDAP_SERVER_TREE_DELETE_OID`, `LDAP_SERVER_DIRSYNC_OID`, `LDAP_SERVER_ASQ_OID`), as documented in [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md). (b) PowerShell `ActiveDirectory` module (`Microsoft.ActiveDirectory.Management.dll`) which wraps ADWS (Active Directory Web Services, `Microsoft.ActiveDirectory.WebServices.exe`) — ADWS exposes a SOAP interface (the `ADWS` endpoint on TCP/9389) that the cmdlets call. ADWS is itself a wrapper around LDAP + SAMR + DRSUAPI. (c) Direct DCE/RPC: SAMR (`12345778-1234-ABCD-EF00-0123456789AC`), LSARPC, DRSUAPI (`E3514235-8B63-11D0-A26C-00A0C92B955C`), Netlogon (`12345678-1234-ABCD-EF00-0123456789AC`).

There is no REST. No gRPC. No GraphQL. Modern applications that want to query "give me all members of the Engineering group" must either speak LDAP (requires an LDAP client library, Kerberos auth setup, and an LDAP search filter syntax), or shell out to PowerShell (Windows-only). The `Microsoft.Graph` PowerShell SDK talks to Azure AD / Microsoft Graph, not on-prem AD. Microsoft's own modern management tooling (Microsoft Graph, Intune Graph API) explicitly avoids on-prem AD because there is no clean API.

The framework gap: modern apps expect REST/JSON or gRPC/protobuf. A Kubernetes operator that wants to provision a new user should call `POST /api/v1/users` not `ldapadd -x -D cn=admin -w ...`. The framework should provide a modern API layer over the directory: REST CRUD on objects, gRPC for streaming (replication status, event tail), GraphQL for flexible queries. LDAP should remain as a compatibility shim for legacy apps; the new API is the primary surface.

**Impact**:

Modern app integration is LDAP-only; cloud-native apps require a custom LDAP client or PowerShell. Kubernetes operators, Terraform providers, and Pulumi components cannot natively manage AD objects — they need an LDAP provider that is brittle and slow.

**Constraints**:

- Must support LDAP for legacy (indefinitely).
- Add REST/gRPC for new apps.
- Must expose identical semantics: `POST /users` ↔ `ldapadd` with the same `user` class.
- Must support OAuth2 bearer token auth on the new API (not just Kerberos/LDAP bind).
- Must support pagination, filtering, and partial attribute retrieval (like LDAP `pagedResults` control).

**Cross-platform considerations**:

- **Windows**: AD-interop requires the REST API to map onto LDAP/PowerShell semantics; the framework's REST API must co-exist with ADWS on the same DC.
- **macOS**: Mac developers have no native AD library; a REST API unlocks `curl`-based management from macOS.
- **Linux**: Linux developers have `ldap3` (Python), `ldapsearch` (CLI), but no native high-level AD SDK; REST/gRPC dramatically lowers the barrier.
- **Cross-platform consistency**: A single REST API surface must work identically against Windows, macOS, and Linux clients.

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — LDAP server front-end (`dsamain.dll`), DRSUAPI interface UUID, AD-specific LDAP controls.
- [`11-code-examples/01-powershell-ad-cmdlets.md`](../docs/11-code-examples/01-powershell-ad-cmdlets.md) — `ActiveDirectory` PowerShell module wraps ADWS (SOAP on TCP/9389); the cmdlet surface is the closest existing "high-level API" for AD.

**Open questions**:

- REST over directory (CRUD on objects)? gRPC for streaming (replication status)? GraphQL for flexible queries?

**Cross-capability impact**:

- Affects: PC-106 (REST API naturally emits OTel spans per request), PC-085 (Client SDK can wrap REST/gRPC).
- Affected by: PC-017 (typed-schema vs LDAP schema — REST/gRPC needs a typed projection).

---

### PC-113 — AD functional level upgrades are one-way; mixed-version forests are fragile

**Capability**: Operations
**Severity**: medium
**Cross-platform**: Windows

**Problem statement**:

AD domain and forest functional levels gate feature availability. Domain modes: Windows 2000 mixed, Windows 2000 native, Windows Server 2003 interim, Windows Server 2003, Windows Server 2008, Windows Server 2008 R2, Windows Server 2012, Windows Server 2012 R2, Windows Server 2016, Windows Server 2019, Windows Server 2022. Forest modes mirror the Windows Server release version. `Set-ADDomainMode -Identity <domain> -DomainMode <year>` raises the domain functional level; `Set-ADForestMode -Identity <forest> -ForestMode <year>` raises the forest functional level. Both operations are one-way: once raised, cannot be lowered.

Functional levels gate features by (a) requiring all DCs to be at-or-above that version (so a 2012-functional-level domain cannot host a 2008 R2 DC), (b) enabling or disabling legacy protocols (2008 R2 forest functional level disables NTLM fallback on trusts with `TRUST_ATTRIBUTE_UPLEVEL_ONLY`), and (c) gating schema features (claims-based Kerberos requires 2012 forest functional level + `objectVersion = 56+`). Mixed-version forests (e.g. 2012 + 2022 DCs) work but with feature constraints — the 2012 DCs do not understand `msDS-AllowedToActOnBehalfOfOtherIdentity` (resource-based constrained delegation, 2012 R2+), so writes to that attribute replicate but are silently ignored on 2012 DCs.

Per [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md), `objectVersion` on the Schema NC head must match the forest functional level. A 2012 forest functional level requires `objectVersion >= 56`; a 2022 forest functional level requires `objectVersion = 88`. The forest functional level is the lowest-common-denominator across all DCs in the forest; raising it requires demoting any DC below the new level.

The framework gap: functional levels are an artifact of Microsoft's release cadence. A modern framework with continuous deployment (CD) should not have "levels" — it should have feature flags. Newer DCs should advertise new capabilities via a capabilities-exchange (similar to `DRS_EXTENSIONS` in `DRSBind`); older DCs should gracefully degrade. The framework should either drop functional levels entirely (always-latest schema, capabilities-exchange) or document the equivalent (per-feature flags gating per-DC behaviour).

**Impact**:

Functional-level upgrades are high-risk because they are one-way and require all DCs to be upgraded first. Orgs delay forest-wide upgrades by 3-5 years, missing security features (claims-based Kerberos, AES-only etype enforcement).

**Constraints**:

- Must support mixed-version DCs during upgrade (no "big bang" required).
- Must support feature gating by DC version (capabilities exchange in `DRSBind`).
- Must remain compatible with AD's `msDS-Behavior-Version` attribute on the domain NC head.

**Cross-platform considerations**:

- **Windows**: AD-interop requires matching forest functional level; the framework's DCs must advertise the same `msDS-Behavior-Version` as the AD forest they replicate with.
- **macOS**: Not a DC platform.
- **Linux**: Samba AD-DC publishes `msDS-Behavior-Version` but its feature surface is approximately Windows Server 2012 R2 (no claims, no compound identity).
- **Cross-platform consistency**: The framework's DC version advertisement must be consistent across Windows-container and Linux-container DCs.

**KB references**:

- [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md) — `objectVersion` table, schema update procedure.
- [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md) — Forest-wide replication, forest root, schema master FSMO role.

**Open questions**:

- Drop functional levels entirely (always-latest schema)? Per-feature flags instead?

**Cross-capability impact**:

- Affects: PC-107 (schema version is gated by functional level), PC-110 (DR procedures reference functional-level requirements).
- Affected by: PC-014 (FSMO roles — schema master gates functional-level raises).

---

### PC-114 — Trust password rotation (every 30 days) can desync; manual reset required

**Capability**: Operations
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Trust passwords rotate every 30 days by default. The rotation is performed by the trusting domain's PDC emulator via `netlogon.dll!I_NetServerPasswordSet2` (per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md)). The `trustAuthBlob` attribute on the `trustedDomain` object holds both the current and the previous password (for overlap, so a replication-lagged DC can still authenticate using the old password). The `LastUpdateTime` field on each `LSA_AUTH_INFORMATION` entry in the blob records when each password was set.

If the PDC emulator is offline during the rotation window (e.g. PDC seized during the 30-day cycle, or replication is broken for >30 days), the trust can desync: one side has the new password, the other still has the old. Symptoms: `nltest /verify` returns "Trust verification failed"; cross-trust Kerberos referrals fail with `KDC_ERR_S_PRINCIPAL_UNKNOWN (6)` or `KRB_AP_ERR_MODIFIED (41)`. Detection is manual (`nltest /verify` run by an admin) or implicit (user complains about cross-domain auth failures). Fix is `netdom trust <trusting> /d:<trusted> /reset /pd /po /ud:admin /pd:*` which sets both sides to a new shared password.

The framework gap: trust password rotation is operationally fragile. The framework should automate (a) health-check (continuous `nltest /verify` equivalent, alert on desync), (b) auto-reset on detection (no admin intervention), (c) per-trust rotation policy (some trusts need 7-day rotation, others 90-day). The overlap-window design (current + previous password) should be preserved; ideally extend to current + previous + next (3 passwords) to handle longer replication lag.

**Impact**:

Trust desync causes cross-domain auth failures. Without monitoring, desync can persist for days until users complain. Recovery requires Domain Admin intervention.

**Constraints**:

- Must support dual-password overlap (current + previous).
- Must support automated health check (continuously verify trust).
- Must support automated reset on desync detection.
- Must support per-trust rotation policy (custom intervals).

**Cross-platform considerations**:

- **Windows**: AD-interop requires the framework to participate in `I_NetServerPasswordSet2` rotation; the framework's DC must accept the rotated password from the AD PDC.
- **macOS**: Not a DC platform; consumes trusts via Kerberos referral.
- **Linux**: Samba AD-DC implements trust password rotation in `source4/rpc_server/lsa/`; FreeIPA uses `ipa trust-add` which writes a static trust secret (no rotation).
- **Cross-platform consistency**: The framework's trust-management CLI must work identically for Windows, Linux, and macOS admin workstations.

**KB references**:

- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `trustAuthBlob` structure, `LSA_AUTH_INFORMATION` array, trust password rotation via `I_NetServerPasswordSet2`, `nltest /verify` and `netdom trust /reset`.
- [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) — PDC emulator FSMO role receives urgent replication for password changes including trust password rotation.

**Open questions**:

- Auto-reset on desync detection? Per-trust rotation policy?

**Cross-capability impact**:

- Affects: PC-126 (client switchover during migration depends on stable trust), PC-129 (cross-realm Kerberos setup depends on trust password).
- Affected by: PC-108 (PDC urgent replication is the mechanism for trust password propagation), PC-028 (cross-realm TGT referral uses the trust key).

---

### PC-115 — `dcdiag` / `repadmin` / `ntdsutil` are Windows-only; cross-platform tooling is fragmented

**Capability**: Operations
**Severity**: medium
**Cross-platform**: Windows, macOS, Linux

**Problem statement**:

The canonical AD operational CLI is Windows-only: `dcdiag.exe` (DC health check, 30+ test categories), `repadmin.exe` (replication administration: `/showrepl`, `/syncall`, `/kcc`, `/showutdvec`, `/removelingeringobjects`), `ntdsutil.exe` (metadata cleanup, IFM, semantic database analysis, FSMO seizure), `nltest.exe` (`/dsgetdc`, `/sc_query`, `/domain_trusts`, `/verify`), `ksetup.exe` (Kerberos realm configuration), `setspn.exe` (SPN registration and duplicate detection). All are shipped in RSAT (Remote Server Administration Tools) and run only on Windows. There is no macOS or Linux port. The Microsoft `ActiveDirectory` PowerShell module similarly requires Windows (it wraps ADWS SOAP).

The cross-platform alternatives are fragmented per [`10-comparison-matrices/03-tool-function-matrix.md`](../docs/10-comparison-matrices/03-tool-function-matrix.md). Samba ships `samba-tool drs showrepl` (subset of `repadmin /showrepl`), `samba-tool domain demote`, `samba-tool fsmo show`, `samba-tool dns` — but no equivalent of `dcdiag`'s 30+ tests, no `ntdsutil` semantic database analysis, no `nltest /sc_query`. FreeIPA ships `ipa-replica-manage status`, `ipa-csreplica-manage status`, `ipa dnszone-show` — but these manage IPA-specific concepts (replica agreements, IPA-managed DNS zones), not the AD-interop surface. Python `impacket` provides low-level DRSUAPI/SAMR/LSARPC clients (`secretsdump.py` for DCSync, `GetUserSPNs.py` for Kerberoasting) but these are offensive-security oriented, not operational.

There is no unified operational CLI that runs on any OS and provides the full `dcdiag`/`repadmin`/`ntdsutil` surface against an AD or framework DC. A macOS admin working on a framework-managed forest must SSH into a Windows box to run `dcdiag`. A Linux admin must install Samba tooling (`samba-tool`) which covers ~30% of `repadmin` and ~0% of `dcdiag`.

The framework gap: a unified operational CLI written in Go or Rust, distributed as a single static binary for Windows/macOS/Linux, providing the full operational surface: replication status, FSMO queries, metadata cleanup, SPN management, dcdiag-equivalent health checks, IFM generation, semantic database analysis. This CLI should speak DRSUAPI/SAMR/LSARPC directly (not require ADWS) so it works against any framework DC.

**Impact**:

Cross-platform AD operations require Windows admin workstations. Linux/macOS admins must context-switch to a Windows VM to run `dcdiag` or `ntdsutil`. SSO-managed macOS fleets cannot self-service operational queries.

**Constraints**:

- Must support replication status (repadmin /showrepl equivalent).
- Must support FSMO queries and transfers.
- Must support metadata cleanup (ntdsutil metadata cleanup equivalent).
- Must support SPN management (setspn equivalent with duplicate detection).
- Must run as a single static binary on Windows, macOS, Linux.
- Must speak DRSUAPI/SAMR/LSARPC directly (no dependency on ADWS).

**Cross-platform considerations**:

- **Windows**: The CLI must coexist with the existing `dcdiag`/`repadmin`/`ntdsutil` — same DC target, same output where possible.
- **macOS**: Apple ships no equivalent tools; the framework CLI fills the gap entirely.
- **Linux**: Samba's `samba-tool` is the closest existing tool but covers a subset; the framework CLI must supersede it.
- **Cross-platform consistency**: Identical CLI behaviour across all three platforms — same flags, same output format (JSON for scripting, human-readable for interactive).

**KB references**:

- [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) — FSMO role holders, transfer/seizure procedures (which `ntdsutil` and the framework CLI must expose).
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `repadmin /showrepl` output, USN vector inspection, replication metadata.
- [`10-comparison-matrices/03-tool-function-matrix.md`](../docs/10-comparison-matrices/03-tool-function-matrix.md) — Function × Tool matrix showing Windows-only tools and their partial Linux/macOS equivalents.

**Open questions**:

- Adopt `samba-tool` as the base? Write fresh CLI in Go/Rust?

**Cross-capability impact**:

- Affects: PC-110 (DR commands must be exposed via this CLI), PC-114 (trust management via this CLI).
- Affected by: PC-085 (Client SDK may share the same Go/Rust core as the CLI).

---

## Cross-capability impact

The Operations capability is a horizontal concern: every other capability exposes operational surface. Key cross-capability impacts:

- **Core Directory (PC-001 through PC-022)**: Replication health, schema cache reload, USN rollback detection, ESE backup — all surface as Operations problems. PC-110 (DR) and PC-115 (CLI) directly consume Core Directory's DRSUAPI and ESE internals.
- **KDC (PC-023 through PC-035)**: krbtgt rotation (PC-030), gMSA key distribution (PC-035), KDC error rates — surface as Operations metrics. PC-106 (Prometheus) and PC-111 (audit logs) must capture KDC events 4768/4769.
- **Auth Provider (PC-036 through PC-042)**: NTLM relay detection, time-sync skew — all need audit + metrics. PC-041 (W32Time) directly affects Kerberos operations.
- **Policy Engine (PC-043 through PC-056)**: GPO version mismatch, GPC/GPT sync — surface as Operations. PC-111 must capture GPO apply events 5136/4662.
- **Cert Service (PC-057 through PC-067)**: CA database corruption (PC-062), CRL distribution failures — surface as Operations DR. PC-110 must include CA backup.
- **Federation Gateway (PC-068 through PC-077)**: AD FS farm health, token-signing cert rotation — surface as Operations monitoring.
- **File Gateway (PC-078 through PC-084)**: SYSVOL replication health, DFS-R backlog — surface as Operations. PC-110 DR must include SYSVOL restore.
- **Client SDK (PC-085 through PC-093)**: Client-side logging must integrate with Operations' OTel pipeline.
- **Cross-Platform Parity (PC-094 through PC-105)**: macOS/Linux operational tooling gaps directly motivate PC-115.
- **Security (PC-116 through PC-123)**: DCSync, Kerberoasting, golden-ticket detection all require the Operations audit + metrics pipeline (PC-106, PC-111).
- **Migration (PC-124 through PC-130)**: Migration runbooks are Operations tasks; the framework's operator must automate migration steps.

## Open research questions specific to Operations

- Should the framework adopt OpenTelemetry semantic conventions for AD/Kerberos event fields, or define its own?
- Is a per-DC metrics granularity sufficient, or should metrics be aggregated per-realm for multi-tenant deployments?
- Is schema-as-code (Git-backed, versioned migrations) feasible for AD-interop, or only for greenfield deployments?
- Can the framework replace PDC urgent replication with active-active CRDTs for password changes without breaking AD-interop?
- Is a single Helm chart sufficient for the framework's DC deployment, or are separate Windows/Linux charts needed?
- What is the operator's blast radius — can a misconfigured operator corrupt the DIT across multiple DCs simultaneously?
- Should the framework's audit log preserve Windows Event IDs verbatim, or remap to a new schema with a compatibility layer?
- Should the REST API be a 1:1 mapping to LDAP semantics, or a higher-level abstraction (e.g. `POST /users` instead of `POST /objects/{dn}`)?
- Should functional levels be dropped entirely, or retained as a compatibility shim for AD-interop?
- Is dual-password overlap (current + previous) sufficient for trust rotation, or should the framework use 3+ passwords for longer replication-lag tolerance?
- Should the unified CLI be a thin wrapper over `samba-tool` + `impacket`, or a fresh Go/Rust implementation that speaks DRSUAPI directly?
