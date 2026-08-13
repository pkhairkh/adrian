---
title: "ADR-053: Support Both Per-Computer Key Escrow and NBDE"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-097
severity: medium
tags: [adr, cross-platform-parity, disk-encryption, bitlocker, filevault, luks, nbde, clevis, tang, key-escrow]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/09-cross-platform-parity.md
  - ../docs/10-comparison-matrices/01-feature-os-matrix.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
last_updated: 2026-08-13
---

# ADR-053: Support Both Per-Computer Key Escrow and NBDE

## Status

Accepted — 2026-08-13

## Context

Windows BitLocker recovery password backs up to AD as a child object of the computer account: `CN=<GUID>,CN=<computer>,CN=BitLocker Recovery,CN=<domain>,DC=...` (the BitLocker Recovery container, created by the BitLocker ADM schema extension). The recovery password (a 48-digit number) is stored as a `msFVE-RecoveryPassword` attribute on a `msFVE-RecoveryInformation` object. The GPO "Choose how BitLocker-protected operating system drives can be recovered" (Computer Config → Administrative Templates → Windows Components → BitLocker Drive Encryption → Operating System Drives) controls backup behavior; "Save BitLocker recovery information to AD DS" must be enabled for the backup to occur, per the BitLocker row in [docs/10-comparison-matrices/01-feature-os-matrix.md](../docs/10-comparison-matrices/01-feature-os-matrix.md) and the BitLocker section in [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

macOS FileVault recovery key escrow goes to Apple (iCloud account recovery) or to the MDM server (Jamf, Intune, Kandji, Mosyle), not to AD. The MDM payload `com.apple.security.FDERecoveryKeyEscrow` specifies the escrow location (URL + cert); the MDM payload `com.apple.security.FDE` enables FileVault. On FileVault enablement, the recovery key is generated, encrypted to the escrow server's public key (from the cert in the payload), and POSTed to the escrow URL. The MDM server stores the recovery key in its own database, with retrieval gated by the MDM vendor's RBAC (Jamf uses Jamf Pro's computer object; Intune uses the device object in Entra ID). There is no AD-integrated FileVault recovery key escrow. Linux LUKS has no AD recovery. The standard alternative is NBDE (Network-Bound Disk Encryption) via Clevis + Tang: Tang server (typically FreeIPA-managed) holds the decryption key; the Clevis client (on the Linux host) needs network access to Tang to decrypt the LUKS volume at boot. If the network is unavailable, the LUKS passphrase is the fallback.

The parity gap is fragmentation: disk-encryption recovery is fragmented. Windows backs up to AD; macOS backs up to Apple or MDM; Linux uses NBDE (Clevis/Tang). Per [PC-097](../catalog/09-cross-platform-parity.md#pc-097--macos-filevault-recovery-key-escrow-goes-to-apple-or-mdm-not-ad)'s impact analysis, a typical enterprise helpdesk handles ~5-10 disk-encryption recovery requests per week per 10,000 devices; with three platforms, each request requires the helpdesk to identify the platform, locate the right tool, retrieve the key, and assist the user — total time ~15-30 minutes per incident. The framework must provide a unified disk-encryption recovery escrow: per-computer recovery key in the framework directory, with rotation, ACL-gated retrieval, and audit logging.

The constraints from [PC-097](../catalog/09-cross-platform-parity.md#pc-097--macos-filevault-recovery-key-escrow-goes-to-apple-or-mdm-not-ad) require the framework to: support per-computer recovery key in the framework directory; support recovery key rotation (on schedule, on demand, on enrollment); support ACL-gated retrieval (only helpdesk group can read; the user cannot read their own recovery key); support audit logging of all retrieval events; support Windows BitLocker interop (read existing `msFVE-RecoveryPassword` from AD; write new keys to AD for BitLocker clients during migration); support macOS FileVault recovery key escrow via MDM payload `com.apple.security.FDERecoveryKeyEscrow` pointing at the framework's escrow endpoint; support Linux LUKS recovery via NBDE (Clevis/Tang) with the framework managing the Tang server.

## Decision

The framework will support two disk-encryption key-escrow mechanisms, with deployments choosing one or both: (1) per-computer recovery key stored in the framework directory with ACL-gated read access (the AD-interop model, supporting BitLocker on Windows and FileVault on macOS via MDM `com.apple.security.FDERecoveryKeyEscrow` payload pointing at the framework's escrow endpoint); (2) NBDE (Network-Bound Disk Encryption) via Clevis + Tang for cloud-native deployments where the framework manages the Tang server and Linux hosts use Clevis clients to decrypt LUKS volumes at boot when the network is available. The framework's directory will support a `recoveryKey` attribute (or `msFVE-RecoveryInformation`-equivalent child object) on computer objects, with ACLs gating read access to the helpdesk group only. The framework's Policy Engine will deploy per-platform code that writes the recovery key to the directory (Windows: BitLocker GPO + ADM schema extension; macOS: MDM `com.apple.security.FDERecoveryKeyEscrow` + `com.apple.security.FDE` payloads; Linux: Clevis + Tang NBDE with framework-managed Tang server).

**Concrete specification**:

- The framework's Core Directory MUST support a `recoveryKey` attribute on computer objects (or `msFVE-RecoveryInformation`-equivalent child object) for storing disk-encryption recovery keys. The attribute MUST be encrypted at rest using the framework's KMS (or an HSM-bound key per ADR-032, depending on the secrets-management tier).
- The framework's Core Directory MUST enforce ACL-gated read access on the `recoveryKey` attribute: only the helpdesk group (and the framework's LAPS-rotation service principal) can read the attribute; the computer object's own account can write the attribute but cannot read it after writing; standard users cannot read the attribute.
- The framework's Policy Engine MUST deploy the Windows BitLocker ADM schema extension to the framework's Core Directory. The schema extension adds the `msFVE-RecoveryInformation` object class and the `msFVE-RecoveryPassword`, `msFVE-KeyPackage`, `msFVE-VolumeGuid` attributes. The framework's Windows client writes `msFVE-RecoveryInformation` child objects on BitLocker enablement, matching the Windows-native behavior.
- The framework's Policy Engine MUST deploy a Windows GPO (compiled from the unified policy format per PC-095 deferred) that enables "Save BitLocker recovery information to AD DS" with "Backup to AD DS before enabling BitLocker" required. The GPO MUST be applied to all framework-managed Windows hosts.
- The framework's Policy Engine MUST deploy a macOS MDM Configuration Profile (`com.apple.security.FDERecoveryKeyEscrow` payload) that points at the framework's escrow HTTPS endpoint (`https://framework-mdm.example.com/escrow/filevault`). The payload MUST include the framework's escrow cert (issued by the framework's Cert Service per ADR-037). The framework's escrow endpoint MUST accept the FileVault recovery key POSTed from the Mac, encrypt it with the framework's KMS, and store it in the framework directory's `recoveryKey` attribute on the computer object.
- The framework's Policy Engine MUST deploy a macOS MDM Configuration Profile (`com.apple.security.FDE` payload) that enables FileVault. The payload MUST configure FileVault to use the institutional recovery key (the framework's escrow cert) for recovery.
- The framework's Policy Engine MUST deploy Linux Clevis + Tang NBDE configuration on framework-managed Linux hosts that opt into NBDE. The configuration: (a) installs `clevis-luks` and `clevis-pin-tang` packages; (b) runs `clevis luks bind -d <device> tang '{"url":"http://framework-tang.example.com","thp":"<tang-key-thumbprint>"}'` to bind the LUKS volume to the Tang server; (c) configures the Linux host's initramfs to bring up networking before LUKS unlock (via `dracut` `--add-network` or `initramfs-tools` `NETWORKING=yes`).
- The framework's Policy Engine MUST manage the Tang server (deployment, key rotation, monitoring). The Tang server MUST run in HA mode (multiple Tang instances behind a load balancer) for availability. The Tang server's key MUST be rotated every 90 days; the rotation MUST be transparent to Clevis clients (Clevis clients re-fetch the Tang key advertisement on each LUKS unlock).
- The framework's macOS client MUST implement a `framework-recover-filevault` CLI that the helpdesk uses to retrieve a Mac's FileVault recovery key from the framework directory. The CLI authenticates to the framework directory via Kerberos, queries the `recoveryKey` attribute on the computer object, decrypts the key with the framework's KMS, and displays the key. The CLI MUST log every retrieval event to the framework's audit log (per ADR-060) with the helpdesk user, the computer object, the timestamp, and the reason.
- The framework's Linux client MUST implement a `framework-recover-luks` CLI for helpdesk LUKS recovery (the non-NBDE fallback). The CLI retrieves the LUKS passphrase from the framework directory (stored as a `recoveryKey` attribute on the computer object, identical to the FileVault flow) and displays it. The CLI MUST log every retrieval event to the framework's audit log.
- The framework's Windows client MUST support reading existing `msFVE-RecoveryPassword` from AD for migration scenarios (customer migrating from AD to the framework). The framework's installer MUST detect existing BitLocker recovery information in AD and migrate it to the framework directory's `recoveryKey` attribute (or to the framework's `msFVE-RecoveryInformation` child objects if the framework uses the BitLocker schema) on first enrollment.
- The framework's documentation MUST include a "Disk-encryption recovery" section explaining the two mechanisms (per-computer key escrow + NBDE), the per-platform deployment (BitLocker GPO on Windows, MDM payloads on macOS, Clevis+Tang on Linux), the helpdesk retrieval workflow (per-platform CLI), and the audit logging.
- The framework's automated test suite MUST include end-to-end disk-encryption recovery tests: enable BitLocker on a Windows host, verify recovery key is written to the framework directory, retrieve via the helpdesk CLI, verify the key matches; enable FileVault on a macOS host via the MDM profile, verify recovery key is POSTed to the framework's escrow endpoint and stored in the framework directory, retrieve via the helpdesk CLI; deploy Clevis+Tang on a Linux host, verify LUKS volume decrypts when the Tang server is reachable, verify LUKS volume does not decrypt when the Tang server is unreachable (NBDE security property).

## Rationale

The decision to support both per-computer key escrow and NBDE is forced by the operational diversity of framework deployments. Traditional on-prem enterprises want per-computer key escrow (matching the Windows BitLocker-to-AD model); cloud-native enterprises want NBDE (matching the Linux Clevis+Tang model with no central key repository). The framework supports both, with deployments choosing based on their security posture: per-computer key escrow provides central key storage (helpdesk can retrieve any key), at the cost of central key compromise risk; NBDE provides no central key storage (the Tang server provides a decryption factor, not the key itself), at the cost of network dependency (no network = no decryption). The two mechanisms are not mutually exclusive; deployments can use both (BitLocker-to-directory on Windows + NBDE on Linux + FileVault-to-directory on macOS).

The decision to use the framework's directory as the per-computer key escrow (rather than the MDM server) is forced by the framework's commitment to a single source of truth for directory data. Per [PC-097](../catalog/09-cross-platform-parity.md#pc-097--macos-filevault-recovery-key-escrow-goes-to-apple-or-mdm-not-ad), macOS FileVault recovery key escrow currently goes to the MDM server (Jamf, Intune), not to AD. The framework's macOS client POSTs the recovery key to the framework's escrow endpoint, which stores it in the framework directory; the framework's directory is the single source of truth, regardless of MDM vendor. This eliminates the "Jamf vs Intune vs Mosyle" recovery key fragmentation problem.

The decision to support the BitLocker ADM schema extension (rather than a fresh schema) is forced by Windows interop. Windows BitLocker GPO + CSE expects `msFVE-RecoveryInformation` child objects; the framework's Core Directory must support this schema for Windows-native BitLocker to work without modification. The framework's directory uses the same schema for cross-platform storage (`msFVE-RecoveryInformation`-equivalent for macOS FileVault and Linux LUKS, with the platform indicated by an attribute on the object).

The decision to manage the Tang server is forced by the need for HA and key rotation. Tang is a simple HTTP service, but it must be HA (a single Tang server is a single point of failure for NBDE-enabled Linux hosts), and the Tang key must be rotated (per NBDE security guidance, the Tang key should be rotated every 90 days to limit the impact of key compromise). The framework's Policy Engine deploys Tang in HA mode (multiple instances behind a load balancer) and rotates the Tang key automatically.

The decision to log every retrieval event is forced by the security-sensitivity of recovery keys. A recovery key retrieval is a high-privilege action (the helpdesk user gains access to the disk-encryption recovery key for a specific computer); every retrieval must be auditable. The framework's audit log (per ADR-060) records the helpdesk user, the computer object, the timestamp, and the reason for retrieval; the audit log is reviewed periodically to detect abuse.

## Consequences

**Positive**. The framework gains a unified disk-encryption recovery escrow across Windows, macOS, and Linux, eliminating the per-platform tool fragmentation that costs ~15-30 minutes per helpdesk incident today. The framework's directory is the single source of truth for recovery keys, regardless of MDM vendor (the macOS FileVault escrow endpoint is framework-managed). The framework's NBDE support gives cloud-native deployments a no-central-key-storage option. The framework's audit logging provides accountability for every retrieval.

**Negative**. The framework's Core Directory must support the `recoveryKey` attribute (or `msFVE-RecoveryInformation` schema extension) and enforce ACLs; this is a schema change with migration considerations. The framework's macOS client must operate an HTTPS escrow endpoint (adding operational surface). The framework's Linux NBDE support requires Tang server management (HA, key rotation, monitoring). The framework's helpdesk must use per-platform CLIs (`framework-recover-filevault` on macOS, `framework-recover-luks` on Linux, and the Windows-native BitLocker recovery via Active Directory Users and Computers or PowerShell) for recovery — the framework does not provide a single unified CLI (this is left for a future ADR).

**Neutral**. The framework's per-platform deployment (BitLocker GPO + FileVault MDM payloads + Clevis/Tang) is invisible to end users (they see disk encryption enabled, not the deployment mechanism). The framework's NBDE support is invisible to operations teams on Windows/macOS deployments (NBDE is Linux-only).

**Implementation cost**. Medium-high. Estimated 12-16 engineer-weeks for: the `recoveryKey` attribute (or `msFVE-RecoveryInformation` schema extension), the ACL enforcement, the macOS escrow endpoint, the Tang server deployment and management, the per-platform CLIs, the audit logging integration, the migration logic for existing BitLocker recovery information in AD, the end-to-end tests, and the documentation.

**Operational impact**. Operations teams gain a unified disk-encryption recovery workflow via per-platform CLIs. Operations teams gain HA Tang server management (deployed by the Policy Engine). Operations teams gain audit logging of every retrieval event. Operations teams lose the Jamf/Intune/Mosyle recovery key consoles for framework-managed Macs (the framework directory is the source of truth, accessed via the framework's CLI). The framework's runbook must include a "Disk-encryption recovery" section explaining the two mechanisms, the per-platform CLIs, and the audit log review process.

## Alternatives Considered

**Alternative 1: Per-computer key escrow only (no NBDE).** The framework supports only per-computer key escrow; Linux LUKS recovery is via the framework directory's `recoveryKey` attribute (a LUKS passphrase stored encrypted in the directory, retrieved by the helpdesk). **Rejection rationale**: This forces cloud-native deployments (which prefer NBDE for its no-central-key-storage property) to use per-computer key escrow, which is operationally and philosophically wrong for that segment. The framework supports both to accommodate the operational diversity of framework deployments.

**Alternative 2: NBDE only (no per-computer key escrow).** The framework supports only NBDE; Windows BitLocker and macOS FileVault recovery keys are not stored in the framework directory. **Rejection rationale**: NBDE is Linux-only (no equivalent for Windows BitLocker or macOS FileVault). Windows and macOS deployments require per-computer key escrow. NBDE-only is not viable for the framework's cross-platform parity commitment.

**Alternative 3: Delegate to MDM vendor (Jamf/Intune/Mosyle) for macOS FileVault recovery, use framework directory only for Windows and Linux.** The framework's macOS client uses the MDM vendor's recovery key escrow (Jamf Pro, Intune, etc.); the framework's directory stores Windows BitLocker and Linux LUKS recovery keys. **Rejection rationale**: This perpetuates the per-MDM-vendor fragmentation that [PC-097](../catalog/09-cross-platform-parity.md#pc-097--macos-filevault-recovery-key-escrow-goes-to-apple-or-mdm-not-ad) identifies as the problem. The framework's macOS client should POST the recovery key to the framework's escrow endpoint, not to the MDM vendor's; this gives the framework a single source of truth regardless of MDM vendor and eliminates the Jamf/Intune/Mosyle recovery key fragmentation.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the identity model choice (SID vs UUID, per ORQ-026/027), which affects the computer object's identifier but not the disk-encryption recovery escrow design (the recovery key is stored on the computer object regardless of identifier type).

## Cross-capability impact

- **Cross-Platform Parity** ([PC-098](../catalog/09-cross-platform-parity.md)): LAPS (per ADR-054) shares the directory-storage model with this ADR; both use ACL-gated retrieval of secrets from the framework directory.
- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): The directory must support the `recoveryKey` attribute (or `msFVE-RecoveryInformation` schema extension) with appropriate ACLs.
- **Cert Service** ([PC-065](../catalog/05-cert-service.md)): The macOS escrow endpoint's TLS certificate is issued by the framework's Cert Service.
- **Policy Engine** ([PC-050](../catalog/04-policy-engine.md)): The Policy Engine deploys the BitLocker GPO (Windows), FileVault MDM payloads (macOS), and Clevis+Tang configuration (Linux).
- **Operations** ([PC-106](../catalog/10-operations.md)): The audit log (per ADR-060) records every recovery key retrieval; Prometheus exporter exposes `disk_encryption_recovery_retrieval_total{platform="...",result="..."}`.

## References

- [PC-097](../catalog/09-cross-platform-parity.md) — problem statement
- [docs/10-comparison-matrices/01-feature-os-matrix.md](../docs/10-comparison-matrices/01-feature-os-matrix.md) — BitLocker row showing Win10/11 native, macOS, Linux, FreeIPA coverage
- [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — BitLocker PIN enforcement row, LAPS row, FreeIPA partial Clevis/Tang coverage
- [Microsoft BitLocker Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/) — BitLocker architecture and AD backup
- [NBDE Project (Clevis + Tang)](https://github.com/latchset/clevis) — Clevis + Tang NBDE implementation
- [Apple FileVault Recovery Key Escrow](https://developer.apple.com/documentation/devicemanagement/fderecoverykeyescrow) — FileVault recovery key escrow payload
- [RFC 7525](https://www.rfc-editor.org/rfc/rfc7525) — Recommendations for Secure Use of TLS (escrow endpoint uses TLS 1.3 per RFC 8446)
