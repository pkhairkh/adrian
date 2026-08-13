---
title: "ADR-058: Container-Native DCs + Kubernetes Operator"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-109
severity: high
tags: [adr, operations, kubernetes, containers, operator, statefulset, devops]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-059-pitr-backup-dr-runbooks.md
  - ./ADR-063-unified-cross-platform-cli.md
last_updated: 2026-08-13
---

# ADR-058: Container-Native DCs + Kubernetes Operator

## Status

Accepted — 2026-08-13

## Context

An AD DC is a Windows Server VM running `lsass.exe` with the DSA loaded as a DLL, the `ntds.dit` ESE database on local disk (`%SystemRoot%\NTDS\ntds.dit`), the SYSVOL share on NTFS, and the DNS server in `dns.exe` under a `svchost -k NetworkService` host. Deployment historically used `dcpromo` (deprecated in Server 2012); modern deployment uses Server Manager or `Install-ADDSDomainController` PowerShell cmdlet. There is no container image of AD DS. The `ntds.dit` file is held open exclusively by `lsass.exe` and cannot be shared between container instances. SYSVOL replication requires DFS-R (`dfsr.exe`), which expects persistent NTFS storage. There is no Helm chart, no operator, no StatefulSet template.

Samba 4 as AD-DC has experimental container images but these are community-maintained, run a single DC per container, and require manual DRS replication setup. FreeIPA is similarly VM-centric; the upstream project explicitly does not support containerized replicas. Microsoft's Azure AD Domain Services is a managed service but the DC instances are not customer-visible containers — it is a PaaS abstraction. The result: every modern identity platform (Keycloak, Authentik, Ory, Zitadel) ships as Docker images with Helm charts and Kubernetes operators; AD does not.

The framework gap is fundamental to cloud-native deployment. The framework cannot use Windows LSASS as the KDC/DSA host in a container, so it must run a multi-process or multi-threaded daemon that exposes the same wire protocols (LDAP, Kerberos, DRSUAPI, SAMR, LSARPC, Netlogon). The DIT-on-a-PVC pattern is straightforward; the harder part is operator-driven lifecycle — promote, demote, backup, restore, schema-upgrade, FSMO transfer — that previously required a human running `ntdsutil` or PowerShell cmdlets. Auto-scaling DCs based on auth rate is impossible in AD; the framework must make it possible.

The constraint set includes: support StatefulSet with PVC-backed DIT (ReadWriteOnce, since ESE-equivalent file locking forbids shared access); support rolling upgrades with schema-version compatibility checks; support operator-driven lifecycle (promote, demote, backup, restore, schema-upgrade, FSMO transfer); support `livenessProbe` / `readinessProbe` on LDAP / Kerberos / DNS ports; must NOT share the DIT file across containers (concurrent ESE-equivalent file access corrupts the database). Windows-container DCs require Windows Server Core base image + process isolation; Linux-container DCs are the natural target for Samba-derived or fresh-implementation frameworks.

## Decision

Deploy the framework's DCs as container images, one DC per Pod, managed by a Kubernetes `StatefulSet` with PVC-backed DIT storage and a custom `DomainController` CRD driven by the `adrian-operator`. The operator implements the full DC lifecycle: `promote` (seeds a new DC from an existing DIT snapshot via the IFM-equivalent path), `demote` (gracefully drains replication partners, removes `nTDSDSA` object), `backup` (triggers a PVC snapshot or a logical-export dump), `restore` (PVC restore + USN-rollback-equivalent detection), `schema-upgrade` (atomic, with rollback to the previous schema version), and `fsmo-transfer` (graceful) or `fsmo-seize` (forcible). Container-native deployment is the primary deployment model; bare-metal/VM deployment is documented but not the reference path.

The DC container image is built from a Linux base (Ubuntu or Red Hat Universal Base Image) for the reference implementation; a Windows Server Core variant is published for Windows-container environments. The image runs a single supervisor process (`adrian-dc`) that spawns the KDC, DSA, Auth-Provider, DNS, and SMB child processes (or threads, depending on language) and exposes LDAP/389, LDAPS/636, GC/3268, Kerberos/88, kpasswd/464, DNS/53, SMB/445, DRSUAPI/135 (endpoint mapper) + dynamic RPC ports. The supervisor is PID 1; it handles graceful shutdown on SIGTERM (drain in-flight requests, flush ESE-equivalent WAL, exit).

**Concrete specification**:

- The `DomainController` CRD MUST define `spec.replicas`, `spec.domainDN`, `spec.site`, `spec.pvcSize`, `spec.image`, `spec.configVersion`, and `status.replicas`, `status.readyReplicas`, `status.fsmoHolders`, `status.lastBackup`, `status.schemaVersion`.
- The `adrian-operator` MUST implement reconcile loops for: `Promote` (new Pod joins an existing domain), `Demote` (Pod removed from domain), `Backup` (cron-triggered or manual), `Restore` (manual, requires confirmation), `SchemaUpgrade` (manual, requires version compatibility check), `FSMOTransfer` (manual, target DC specified), `FSMOSeize` (manual, source DC presumed dead).
- The StatefulSet MUST use `volumeClaimTemplates` with `accessModes: [ReadWriteOnce]`, `storageClassName: <fast-ssd>`, and a minimum `resources.requests.storage: 50Gi`.
- The Pod MUST expose `livenessProbe` on TCP/389 (LDAP) with `initialDelaySeconds: 30`, `periodSeconds: 10`, `failureThreshold: 6` (1-minute grace), and `readinessProbe` on TCP/88 (Kerberos) with `periodSeconds: 5`.
- The Pod MUST expose `startupProbe` on TCP/389 with `failureThreshold: 30`, `periodSeconds: 10` (5-minute startup grace — DIT load can be slow).
- Rolling upgrades MUST be gated by a `schemaVersion` compatibility check: the operator refuses to upgrade a Pod whose `spec.configVersion` requires a schema version newer than the current schema NC head.
- The operator MUST support `spec.updateStrategy.rollingUpdate.partition` for canary upgrades (upgrade N Pods, pause, upgrade the rest).
- The operator MUST emit Kubernetes events on every lifecycle operation (`PromoteStarted`, `PromoteCompleted`, `BackupCompleted`, `FSMOTransferred`, `SchemaUpgradeCompleted`).
- The operator MUST refuse to demote the last DC in a domain (would orphan the domain).
- The operator MUST refuse to demote an FSMO holder without explicit `force: true` (which triggers a seize on another DC).
- The DC container image MUST be signed (see [ADR-067](./ADR-067-sigstore-supply-chain.md)); the operator MUST verify the signature before pulling.
- The DC container image MUST run as `non-root` user `adrian` (UID 10001); the DIT PVC is chown'd to `adrian:adrian` on first mount.
- The operator MUST expose a `metrics` Service on TCP/9100 (Prometheus) and a `debug` Service on TCP/6060 (pprof-equivalent, opt-in via annotation).
- The framework MUST ship a Helm chart (`adrian-dc`) with values for `domainDN`, `site`, `image.tag`, `pvc.size`, and `replicas`.
- Provisioning a new DC (Pod added to StatefulSet) MUST complete in <120 seconds; auto-scaling based on `adrian_ldap_requests_total` rate (per [ADR-057](./ADR-057-prometheus-otel-observability.md)) is supported via KEDA `ScaledObject` or a built-in HPA on a custom metric.

## Rationale

Container-native deployment is the dominant pattern for new infrastructure in 2026. The Kubernetes operator pattern has been proven by Postgres-operator, Cockroach-operator, Cassandra-operator, and others for stateful workloads with complex lifecycle. An identity system without an operator is, in 2026, a system that requires a human SRE on call for every DC lifecycle event — a non-starter for any organisation operating at scale.

The `DomainController` CRD is the natural abstraction: it captures the intent ("3 DCs in domain X, site Y, schema version Z, PVC 100Gi") and lets the operator handle the mechanics. The alternative — Helm-only deployment with imperative post-install `ntdsutil`-equivalent commands — works for greenfield but breaks on any lifecycle event (backup, restore, schema upgrade, FSMO transfer).

ReadWriteOnce PVCs are mandatory because the framework's storage engine (ESE-equivalent or chosen storage engine per the deferred PC-007 decision) holds the DIT file with an exclusive lock; multi-attach would corrupt. This means horizontal scaling is by adding Pods (each with its own PVC), not by sharing a PVC across Pods. Replication between Pods handles data synchronisation.

The 120-second provisioning SLA is achievable because (a) the framework's storage engine loads the DIT in <30 seconds for a 10 GB DIT, (b) the IFM-equivalent seed (per [ADR-059](./ADR-059-pitr-backup-dr-runbooks.md)) copies a recent snapshot, (c) the KDC, DSA, Auth Provider startup is parallel. AD's `dcpromo` takes 30–60 minutes primarily because of replication seeding; the framework's operator uses a snapshot.

The non-root user requirement is a Kubernetes pod-security baseline (restricted). Running as root is forbidden in most production clusters; the framework must comply.

Signature verification on the container image is required to close the supply-chain attack surface (see [ADR-067](./ADR-067-sigstore-supply-chain.md)). Without it, a compromised registry could push a malicious DC image that exfiltrates password hashes — exactly the SolarWinds pattern.

## Consequences

**Positive**: DC provisioning drops from 30–60 minutes to <120 seconds. Auto-scaling becomes possible (HPA on auth rate). Backups, restores, schema upgrades, and FSMO transfers are one `kubectl apply` or one CLI command. GitOps (Argo CD, Flux) can manage DC fleet configuration declaratively. Disaster recovery runbooks become operator invocations, not runbook pages.

**Negative**: The framework acquires a hard dependency on Kubernetes for the primary deployment path. Organisations running on VMs (still common in regulated industries) must install K3s or kind on each VM to use the reference deployment, or use the documented bare-metal path which is secondary. The operator becomes a critical control plane component — operator bugs can affect every DC simultaneously (the "blast radius" concern surfaced in the catalog's open questions). StatefulSet + PVC + ReadWriteOnce means each DC's DIT is bound to a specific PVC; PVC migration across nodes requires care.

**Neutral**: The operator does not preclude bare-metal deployment; the same `adrian-dc` binary runs on a VM. The Helm chart and the operator can target any Kubernetes distribution (EKS, GKE, AKS, OpenShift, k3s, kind).

**Implementation cost**: ~6 person-months for the operator (reconcile loops, CRD, status reporting, FSMO logic, schema upgrade orchestration); ~3 person-months for the container image build pipeline (multi-arch, multi-distro, Sigstore signing); ~2 person-months for the Helm chart and the documentation. Total: ~11 person-months for v1.

**Operational impact**: SREs familiar with the operator pattern can operate the framework's DCs with no AD-specific training; SREs familiar with AD must learn the operator pattern. The framework's runbook replaces `ntdsutil` invocations with `kubectl apply -f promote.yaml`.

## Alternatives Considered

**Alternative A: VM-only deployment with Ansible playbooks.** Deploy DCs as VMs, manage with Ansible or Chef. This is the AD-interop model. Rejected because (a) provisioning latency is 30–60 minutes, (b) auto-scaling is impossible, (c) GitOps does not work cleanly with imperative VM provisioning, (d) the framework's reference implementation cannot be tested in CI with VMs (containerised test environments are mandatory for CI at scale).

**Alternative B: Serverless / function-per-protocol.** Deploy the KDC as a Lambda, the DSA as a separate Lambda, etc. Rejected because (a) the framework's hot path is a synchronous LDAP bind crossing KDC + DSA + Auth Provider — function-call latency between Lambdas (50–200 ms) is unacceptable, (b) stateful workloads (the DIT) are anti-pattern for serverless, (c) the ESE-equivalent file lock requires persistent storage.

**Alternative C: Docker Compose only (no Kubernetes).** Simpler than Kubernetes for single-DC deployments. Rejected as the primary path because (a) Docker Compose does not support rolling upgrades with PVC affinity, (b) the operator pattern is what enables auto-scaling, FSMO transfer automation, and schema upgrade orchestration — without an operator, these are manual again, (c) production deployments in 2026 are predominantly Kubernetes. Docker Compose is documented as a dev/test path.

## Open Questions

None — this is an ADR-ELIGIBLE decision. Open research questions remain about the exact storage engine (PC-007, gated by Tier-1 ORQ-011/012/013/014) which affects the PVC profile (RocksDB tolerates ReadWriteOnce; FoundationDB tolerates ReadWriteMany), but the operator pattern and the StatefulSet architecture are stable regardless of storage choice.

## Cross-capability impact

- **Core Directory (PC-001 through PC-022)**: DRSUAPI replication must work over the Pod network; the operator must configure NetworkPolicy to allow DRSUAPI traffic between DC Pods.
- **Operations (PC-110)**: DR runbooks (ADR-059) are operator-driven; the operator's `Restore` reconcile loop implements the DR procedure.
- **Operations (PC-112)**: REST/gRPC API (ADR-061) is exposed via a Kubernetes Service in front of the StatefulSet.
- **Operations (PC-115)**: Unified CLI (ADR-063) must work both inside the container (for exec'd debug sessions) and outside (for operator invocations).
- **Cert Service (PC-057 through PC-067)**: AD CS-equivalent CA must be containerised on the same pattern; the operator manages both DC and CA lifecycles.
- **File Gateway (PC-078 through PC-084)**: SYSVOL-equivalent share runs in the same Pod (sidecar) or a separate StatefulSet.
- **Migration (PC-126)**: Client switchover during AD→framework migration uses the operator to scale up framework DCs in parallel with AD DCs.
- **Security (PC-123)**: Container image signing (ADR-067) is verified by the operator before pulling.

## References

- [PC-109](../catalog/10-operations.md) — problem statement (AD has no containerization; no Kubernetes-native deployment)
- [AD overview](../docs/00-overview/01-active-directory-overview.md) — AD DS service binary, listening ports, deployment model
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — LSASS process model, ESE database file locking, registry-based configuration keys
- [Kubernetes Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
- [Kubernetes StatefulSet](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)
- [Open Container Initiative (OCI) Image Spec](https://github.com/opencontainers/image-spec)
- [Helm Charts](https://helm.sh/docs/topics/charts/)
