---
title: Migration & Coexistence — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, migration, coexistence, framework-design, admt, sidhistory, gpo-migration]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./09-cross-platform-parity.md
  - ./10-operations.md
  - ./11-security-threat-model.md
  - ./13-open-research-questions.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Migration & Coexistence — Problem Catalog

**Capability definition.** Migration & Coexistence is the framework's path from AD to itself. The framework inherits nothing from AD here — AD is the source, the framework is the target. The capability covers: sIDHistory migration via `DRSAddSidHistory` (opnum 20 on DRSUAPI), GPO translation from ADMX/ADML/Registry.pol/GptTmpl.inf/Preferences XML to the framework's native policy format, client switchover via parallel-run mode with cross-realm Kerberos trust + LDAP referrals, password hash migration (sIDHistory / password-sync agent / require-reset), DNS namespace sharing via zone delegation, Kerberos cross-realm setup via `trustedDomain` objects + `[capaths]` in `krb5.conf`, and SYSVOL migration (logon scripts + GPO files) via SMB share compatibility or HTTP-based distribution.

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-124 | sidHistory migration requires `DRSAddSidHistory` + SeEnableDelegationPrivilege | high | cross-platform |
| PC-125 | GPO translation from AD to framework-native requires manual mapping | high | cross-platform |
| PC-126 | Client switchover from AD to framework requires parallel-run support | high | cross-platform |
| PC-127 | Password hash migration requires either sIDHistory or password-sync agent | high | cross-platform |
| PC-128 | DNS namespace sharing during migration requires careful zone delegation | medium | cross-platform |
| PC-129 | Kerberos cross-realm with AD during migration requires `capaths` + trust object | medium | cross-platform |
| PC-130 | SYSVOL migration (logon scripts, GPO files) requires SMB share compatibility | medium | cross-platform |

---

## Detailed problem entries

### PC-124 — sidHistory migration requires `DRSAddSidHistory` + SeEnableDelegationPrivilege

**Capability**: Migration
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

The Active Directory Migration Tool (ADMT) and equivalent migration workflows use `DRSAddSidHistory` (opnum 20 on the DRSUAPI interface `E3514235-8B63-11D0-A26C-00A0C92B955C`) to inject the source-domain user's old SID into the target-domain user's `sIDHistory` attribute. Per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) and [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md), this opnum is documented in MS-DRSR §4.1.29 and requires `SeEnableDelegationPrivilege` on the source domain (held by Domain Admins by default).

The mechanism: ADMT, running in the target domain, binds to a source-domain DC via DRSUAPI. It calls `DRSAddSidHistory` with the source user's SID and the target user's DN. The source DC verifies the caller has `SeEnableDelegationPrivilege`, retrieves the source user's `objectSid` and `sIDHistory`, packages them, and returns. The target DC then writes the returned SIDs into the target user's `sIDHistory`. The target user now has both their new SID (in the target domain) and the old SID (from the source domain) in `sIDHistory`.

When the target user authenticates across a within-forest trust (`TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20`), the source-domain KDC preserves the `sIDHistory` in the PAC's `ExtraSids` array (per MS-KILE §3.4.5). Resources that have ACLs referencing the source-domain SID continue to grant access — the user's token contains both SIDs, and the SRM (Security Reference Monitor) checks both against the ACL. This is what makes "user migrated from old.corp to new.corp can still access file shares in old.corp that referenced the user's old SID" work without ACL re-write.

The problem: `DRSAddSidHistory` is the only mechanism that preserves both the SID (for ACL continuity) and the password (via ADMT's password-copy, which uses a separate DCSync-like call). The alternative is claims-based migration — the framework issues claims (assertions about the user) that the source domain's resources trust, replacing the SID-based access check. But claims-based access control requires Server 2012+ forest functional level, claim-type definitions published in AD, and resource-side central access policies. Most orgs have not deployed this. sIDHistory remains the practical migration mechanism.

The framework gap: the framework must either (a) implement `DRSAddSidHistory` (opnum 20 on its DRSUAPI surface) for ADMT interop, (b) provide an alternative migration tool that does the equivalent (e.g. via LDAP modify on `sIDHistory` directly — which requires the same `SeEnableDelegationPrivilege` and is operationally equivalent), or (c) document claims-based migration as the only supported path (which limits AD-interop scenarios where the source domain is below 2012 functional level).

**Source state**: AD forest with users having SIDs in source domain, ACLs on resources referencing those SIDs, ADMT installed in target domain.

**Target state**: Framework-native users with current SIDs and `sIDHistory` containing source-domain SIDs. Framework DCs serve the target domain. Cross-realm trust to source AD forest is in place.

**Coexistence period**: 30-180 days typical. During this window, target-domain users access source-domain resources via sIDHistory passthrough. After coexistence, source-domain ACLs are rewritten to reference target-domain SIDs (or source resources are migrated to the target domain).

**Cutover trigger**: When 100% of source-domain ACLs have been rewritten (or source resources decommissioned), the within-forest trust can be converted to an external trust (sIDHistory filtering ON), and sIDHistory can be removed from target users.

**Rollback path**: If migration fails, sIDHistory can be cleared on target users (LDAP modify replacing `sIDHistory` with empty value). Users lose access to source-domain resources until ACLs are re-written to reference the target SIDs (one-time batch operation).

**Impact**:

Migration without sIDHistory breaks ACLs referencing old-domain SIDs. Every file share, SQL database, sharepoint site, and registry ACL that references source-domain SIDs must be re-written. For a 50,000-user / 10,000-server migration, this is 1-5 million ACL entries — weeks of batch work.

**Constraints**:

- Must support `DRSAddSidHistory` (opnum 20 on DRSUAPI) for ADMT interop.
- Must support sIDHistory filtering on external trusts (default ON).
- Must support `SeEnableDelegationPrivilege` check on the source side.
- Must audit every sIDHistory write (Event 4662-equivalent with the sIDHistory attribute GUID `5905e5c0-c1bb-11d3-99a7-0000f81a86c8`).
- Must support claims-based migration as an alternative.

**Cross-platform considerations**:

- **Windows**: ADMT is Windows-only and the canonical tool. The framework must interop with ADMT for migrations from existing AD forests.
- **macOS**: Mac clients consume the cross-trust Kerberos referral + PAC `ExtraSids` transparently.
- **Linux**: Samba AD-DC implements `DRSAddSidHistory` in `source4/rpc_server/drsuapi/`. FreeIPA's `ipa trust-add --range-type=ipa-ad-trust` creates an ID range for AD users but does not migrate sIDHistory.
- **Cross-platform consistency**: The framework's `DRSAddSidHistory` implementation must produce identical `sIDHistory` semantics regardless of which platform hosts the framework DC.

**KB references**:

- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `sIDHistory` attribute, within-forest trust sIDHistory passthrough, `TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20`, `TRUST_ATTRIBUTE_QUARANTINED = 0x4` for filtering.
- [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI interface UUID `E3514235-8B63-11D0-A26C-00A0C92B955C`, opnum 20 `DRSAddSidHistory` row in the method table.

**Open questions**:

- Replace sIDHistory with claims-based migration? Document ADMT as the only migration path?

**Cross-capability impact**:

- Affects: PC-120 (sIDHistory abuse attack — the same mechanism that enables migration enables the attack), PC-126 (client switchover depends on sIDHistory for resource access continuity), PC-127 (password hash migration is often paired with sIDHistory migration in ADMT).
- Affected by: PC-117 (DCSync is the underlying replication mechanism ADMT uses for password copy), PC-001 (DRSUAPI implementation must include opnum 20).

---

### PC-125 — GPO translation from AD to framework-native requires manual mapping

**Capability**: Migration
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD GPOs are a multi-format assemblage per [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) and [`04-group-policy/03-admx-templates.md`](../docs/04-group-policy/03-admx-templates.md): (a) ADMX/ADML files (XML) defining policy schema and localised strings, (b) `Registry.pol` (PReg binary format) holding the actual registry value settings, (c) `GptTmpl.inf` (INI-style) holding the Security CSE settings (User Rights Assignment, Restricted Groups, Security Options), (d) Preferences XML files (Files.xml, Services.xml, ScheduledTasks.xml, Registry.xml, DriveMaps.xml, etc.) for Preferences CSE, (e) `Scripts` directories containing logon/logoff/startup/shutdown batch/PowerShell scripts, (f) `GPT.INI` with the version number. Each GPO is split into GPC (in AD) and GPT (in SYSVOL).

The framework's native policy format (whether YAML, JSON, Rego, or something else) will be different. Migration requires translating each AD format into the framework's native format. There is no automated tool today per the KB's comparison matrix — every migration is manual, per-setting.

The translation surface: a typical enterprise has 100-500 GPOs, each containing 10-100 settings. Total: 1,000-50,000 settings to translate. Each translation requires: (1) read the ADMX to understand the policy intent, (2) read the Registry.pol to get the current value, (3) find the equivalent framework policy key (if one exists), (4) translate the value (some values map 1:1, others require semantic translation — e.g. Windows `SeInteractiveLogonRight` → FreeIPA HBAC rule with `--services=login`), (5) review manually for fit (some Windows policies have no Linux/macOS equivalent — e.g. BitLocker PIN enforcement has no macOS equivalent).

The framework gap: the framework should provide a GPO-import tool that: (a) parses ADMX/ADML/Registry.pol/GptTmpl.inf/Preferences XML automatically, (b) translates known settings to native policy using a curated mapping table (built from the analysis in `10-comparison-matrices/05-gpo-equivalents-matrix.md`), (c) flags unknown or no-equivalent settings for manual review, (d) produces a native policy file per GPO, (e) supports per-setting review UI (admin sees each translation, can accept/modify/reject). The tool should also support rollback (re-translate from AD on demand).

**Source state**: AD with 100-500 GPOs in ADMX/Registry.pol/GptTmpl.inf/Preferences XML format. SYSVOL replication active.

**Target state**: Framework-native policies (declarative YAML/JSON) per GPO. Framework's Policy Engine serves the translated policies to enrolled clients.

**Coexistence period**: 90-180 days. During this window, both AD GPO and framework policies may apply to clients (Windows clients still receive AD GPO; framework-enrolled clients receive framework policies). Per-setting translation is staged.

**Cutover trigger**: When 100% of GPOs have been translated and validated on a pilot group of framework-enrolled clients for ≥30 days, the AD GPOs can be disabled (`Set-GPLink -LinkEnabled No`).

**Rollback path**: Re-enable AD GPOs (`Set-GPLink -LinkEnabled Yes`) on the affected OUs. Framework policies can be disabled or deleted. The translation table is preserved for re-translation if needed.

**Impact**:

GPO migration is manual per-setting. A 50,000-user org with 300 GPOs averaging 50 settings each = 15,000 settings to translate. At 5-10 minutes per setting (read ADMX, find equivalent, translate, review), that's 1,250-2,500 person-hours = 8-16 person-months of work.

**Constraints**:

- Must parse ADMX/ADML/Registry.pol/GptTmpl.inf/Preferences XML automatically.
- Must produce native policy in the framework's declarative format.
- Must flag unknown or no-equivalent settings for manual review.
- Must support per-setting review UI.
- Must preserve AD-interop (Windows clients still receiving AD GPO during coexistence).
- Must support rollback (re-translate from AD on demand).

**Cross-platform considerations**:

- **Windows**: Windows clients continue to consume AD GPO during coexistence. The framework's translated policies may apply on top (via the framework's Windows client SDK) or replace AD GPO after cutover.
- **macOS**: MDM Configuration Profiles (`.mobileconfig`) are the target format. The translation maps GPO settings to MDM payload keys per `10-comparison-matrices/05-gpo-equivalents-matrix.md`.
- **Linux**: SSSD `sssd.conf` keys + Ansible/Puppet manifests are the target. The translation maps GPO settings to SSSD config + Ansible modules.
- **Cross-platform consistency**: A single AD GPO may translate to different native formats per platform — the framework must produce per-platform policy files from one source GPO.

**KB references**:

- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Full ADMX setting × cross-platform equivalent matrix (Password policy, Account lockout, User Rights Assignment, Security Options, Firewall, AppLocker, Drive Maps, File preference, Registry preference, Scheduled Tasks, Folder Redirection, Scripts, Printers, BitLocker, LAPS, Audit Policy, Kerberos Policy, NTP, Power Management, Defender).
- [`04-group-policy/03-admx-templates.md`](../docs/04-group-policy/03-admx-templates.md) — ADMX XML schema, `<policyElements>` (text, decimal, boolean, enum, list, longDecimal, multilineText), `<supportedOn>` definitions, registry value types (REG_SZ, REG_DWORD, REG_MULTI_SZ, etc.).

**Open questions**:

- Auto-translate known ADMX settings to native? Per-setting review UI?

**Cross-capability impact**:

- Affects: PC-043 through PC-056 (Policy Engine capabilities — the translation produces native policies that the Policy Engine must serve), PC-107 (schema migration may be required for new policy types).
- Affected by: PC-052 (Policy payload format — the framework's native format determines the translation target), PC-045 (per-platform executors — translation must produce per-platform output).

---

### PC-126 — Client switchover from AD to framework requires parallel-run support

**Capability**: Migration
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

Migrating clients (Windows workstations, macOS laptops, Linux servers) from AD to the framework requires a parallel-run period during which the client is joined to both AD (for legacy resource access) and the framework (for new resource access). The client's Kerberos ccache contains TGTs for both realms; LDAP queries can be referred between directories; SPN lookups can resolve in either. Per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) and [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md), this is enabled by a cross-realm Kerberos trust between AD and the framework's KDC.

The Kerberos referral flow during parallel run: client (joined to AD) requests a service ticket for `cifs/file01.example.com@CORP.EXAMPLE.COM`. The AD KDC, on TGS-REQ, sees that the SPN is owned by the framework's realm (via `trustedDomain` object) and returns a referral TGT `krbtgt/FRAMEWORK.COM@CORP.EXAMPLE.COM`. The client uses this referral TGT to TGS-REQ the framework's KDC, which issues the service ticket. The client presents the service ticket to file01 (which is framework-joined). Authentication succeeds.

For LDAP, the parallel-run uses LDAP referrals. The AD DC has crossRef objects pointing to the framework's NC head; on a query for an object in the framework's NC, AD returns a referral (`SearchResultReference` with the framework's LDAP URL). The LDAP client (e.g. `ldap3`) follows the referral, rebinds to the framework's DC using Kerberos cross-realm, and retrieves the object.

The migration granularity options: (a) per-SPN migration (move one service at a time — e.g. migrate `cifs/file01` SPN from AD to the framework; the AD KDC stops issuing tickets for that SPN; the framework's KDC starts), (b) per-user migration (move one user at a time — the user's account is created in the framework with sIDHistory referencing the AD SID; the user's workstation is re-joined to the framework; AD account is disabled), (c) per-host migration (move one workstation at a time — the workstation is un-joined from AD and joined to the framework; user accounts still in AD continue to authenticate via cross-trust).

Each granularity has tradeoffs. Per-SPN is the lowest-risk (one service at a time, easy rollback) but slowest (must repeat for every service). Per-user is medium-risk (one user at a time, manageable blast radius) and medium-speed. Per-host is fastest (one workstation at a time, simple workflow) but highest-risk (if the user's AD account is in a different domain than the workstation's framework join, cross-trust must work flawlessly).

The framework gap: the framework must support all three granularities with explicit tooling. Per-SPN: SPN migration tool that moves an SPN from AD to the framework's directory, updates the framework's KDC to issue tickets for it, and removes the SPN from AD (after a coexistence period). Per-user: user migration tool that uses `DRSAddSidHistory` (PC-124) and password copy (PC-127). Per-host: host re-join tool that un-joins from AD and joins to the framework, preserving the host's identity (SID, keytab).

**Source state**: AD forest with users, computers, services. Clients are AD-joined.

**Target state**: Framework-native directory with users, computers, services. Clients are framework-joined. Cross-realm trust to AD forest is in place.

**Coexistence period**: 90-365 days for full migration. Per-SPN/per-user/per-host migration is staged. Both directories serve queries during coexistence.

**Cutover trigger**: When 100% of users, computers, and services have been migrated (or decommissioned) and the cross-realm trust has had no traffic for ≥30 days, the trust can be removed and AD decommissioned.

**Rollback path**: Re-join migrated clients to AD. Re-create migrated users in AD (with sIDHistory reversed, if needed). Re-register migrated SPNs in AD. The framework's migration tool should produce a rollback plan for each migration batch.

**Impact**:

Big-bang migration is high-risk; parallel-run reduces risk but requires dual-identity infrastructure (both AD and framework DCs running, both directories authoritative for their respective objects). Cost: 2× DC infrastructure during coexistence.

**Constraints**:

- Must support cross-realm trust with AD (Kerberos `trustedDomain` object both directions).
- Must support LDAP referrals between AD and framework directories.
- Must support per-SPN migration (move one service at a time).
- Must support per-user migration (move one user at a time, with sIDHistory).
- Must support per-host migration (move one workstation at a time, with identity preservation).
- Must support rollback for each granularity.

**Cross-platform considerations**:

- **Windows**: Windows clients support multiple Kerberos realms via `ksetup /AddRealm <realm>`. Cross-realm TGT referral works natively.
- **macOS**: PSSO Extension supports a single realm per profile payload; parallel-run requires multiple profiles or a profile generator that swaps realms.
- **Linux**: SSSD supports multiple domains in `sssd.conf` with `[domain/ad]` and `[domain/framework]` sections; per-domain access control. Parallel-run is straightforward.
- **Cross-platform consistency**: The framework's parallel-run tooling must produce platform-specific join configurations for each client OS.

**KB references**:

- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `trustedDomain` object structure, cross-realm TGT referral flow (RFC 4120 §3.3.3), trust password rotation during coexistence.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Kerberos TGS-REQ/TGS-REP message flow, referral TGT mechanism, `KDC_ERR_S_PRINCIPAL_UNKNOWN (6)` triggering referral.

**Open questions**:

- Per-SPN migration (move one service at a time)? Per-user migration (move one user at a time)?

**Cross-capability impact**:

- Affects: PC-128 (DNS namespace sharing is required for parallel-run), PC-129 (cross-realm Kerberos setup is the trust foundation), PC-130 (SYSVOL migration is required for client policy continuity).
- Affected by: PC-028 (cross-realm TGT referral mechanism in KDC), PC-124 (sIDHistory migration is the per-user mechanism).

---

### PC-127 — Password hash migration requires either sIDHistory or password-sync agent

**Capability**: Migration
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

User password migration from AD to the framework has three options, each with tradeoffs:

(a) **sIDHistory + password copy via ADMT**: ADMT's Password Export Server (PES) runs on a source-domain DC, captures password hashes as they are set (via a `dll` hook into LSASS), and pushes them to the target domain. The target domain writes the hash into the user's `unicodePwd` and `supplementalCredentials` (Kerberos AES keys). This preserves both the SID (via sIDHistory, PC-124) and the password — the user experiences no disruption. ADMT is Windows-only and was deprecated by Microsoft (last release 3.2, supports up to Server 2012 R2 source domains); many orgs still use it.

(b) **Password-sync agent**: Microsoft Identity Manager (MIM) or Entra Connect (Azure AD Connect) runs a sync agent that periodically pulls password hashes from AD (via DCSync-equivalent mechanism) and pushes them to a target directory. The target can be Azure AD, a third-party IdP, or (theoretically) the framework's directory. The sync agent uses a proprietary protocol (Microsoft's `PasswordHashSync` API for Azure AD Connect; MIM uses its own). For non-Microsoft targets, the framework would need to implement a sync-agent protocol or use a standard like LDAP `modify` on `unicodePwd` over TLS.

(c) **Require password reset on migration**: Users are migrated with a temporary password and forced to reset on first login to the framework. Simplest operationally but most disruptive — every user must reset their password on cutover day. For a 50,000-user org, the helpdesk load is enormous.

The framework gap: the framework should support all three options. (a) requires implementing the ADMT PES protocol or equivalent — non-trivial, requires reverse-engineering of the proprietary PES-server DLL. (b) requires either implementing a sync-agent protocol that MIM/Entra Connect can target, or providing a framework-side agent that pulls from AD on a schedule (DCSync-equivalent). (c) is straightforward — the framework's user-create flow supports a "must change password at next login" flag.

The most practical path is likely (b) with a framework-side agent. The agent runs on a framework DC, binds to an AD DC via DRSUAPI with `EXOP_REPL_SECRETS` (the same mechanism impacket's `secretsdump.py` uses, PC-117), pulls the password hashes for a batch of users, and writes them to the framework's directory via LDAP `modify` on `unicodePwd`. The agent runs on a schedule (e.g. every 15 minutes) during the migration coexistence period. After cutover, the agent is decommissioned.

**Source state**: AD with user accounts and password hashes in `unicodePwd` (NTLM hash) and `supplementalCredentials` (Kerberos AES keys).

**Target state**: Framework-native users with password hashes populated. Users can authenticate to the framework with their AD password (no reset required).

**Coexistence period**: 30-90 days. During this window, the sync agent runs on a schedule, propagating password changes from AD to the framework. Users who change their AD password during this window have the new password automatically synced to the framework.

**Cutover trigger**: When 100% of users have been migrated and the sync agent has run with no new changes for ≥7 days, the agent is decommissioned and AD password authority is revoked.

**Rollback path**: If migration fails, the framework's user accounts can be disabled. Users continue to authenticate via AD. The sync agent can be re-started if a re-migration is attempted. No data loss — AD remains the source of truth throughout.

**Impact**:

Password migration without reset preserves UX. With reset, helpdesk load spikes (50,000 users × 5-10 min per reset = 4,000-8,000 helpdesk hours over a cutover week). Without sync (option c only), productivity loss is 1-2 days per user.

**Constraints**:

- Must support `DRSAddSidHistory` for ADMT interop (option a).
- Must support password-sync agent protocol (option b) — either proprietary (MIM/Entra Connect) or standard (LDAP modify on `unicodePwd` over TLS).
- Must support password-reset on migration (option c) as fallback.
- Must not store plaintext passwords (only hashes: NTLM, AES-128, AES-256).
- Must preserve password complexity policy from AD during migration.

**Cross-platform considerations**:

- **Windows**: ADMT is Windows-only. MIM and Entra Connect are Windows-only. The framework's sync agent should run cross-platform but bind to AD via DRSUAPI (works from any platform).
- **macOS**: Not a sync agent platform. Mac users benefit from the synced password via Kerberos cross-realm.
- **Linux**: Samba's `samba-tool domain passwordsync` provides a partial sync agent. The framework can build on this or implement a fresh agent in Go/Rust.
- **Cross-platform consistency**: The framework's sync agent should run identically on Windows, macOS, and Linux hosts, binding to AD via DRSUAPI.

**KB references**:

- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `trustAuthBlob` structure, cross-realm trust key (used by ADMT to write sIDHistory), `DRSAddSidHistory` (opnum 20) dependency.
- [`11-code-examples/05-python-impacket-examples.md`](../docs/11-code-examples/05-python-impacket-examples.md) — `secretsdump.py -just-dc` recipe demonstrating DRSUAPI-based password hash extraction (the same mechanism a sync agent would use, but for migration rather than attack).

**Open questions**:

- Password-sync agent protocol (proprietary or standard)? Per-batch migration?

**Cross-capability impact**:

- Affects: PC-124 (sIDHistory migration is the SID-equivalent of password migration), PC-126 (client switchover depends on synced passwords for UX continuity).
- Affected by: PC-117 (DCSync mechanism is the underlying replication primitive — same DRSUAPI call, different authorisation context), PC-035 (gMSA password distribution uses a similar DRSUAPI mechanism).

---

### PC-128 — DNS namespace sharing during migration requires careful zone delegation

**Capability**: Migration
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

During AD→framework migration, both directories may serve the same DNS namespace (e.g. `corp.example.com`). AD-integrated DNS zones replicate via DRSUAPI as `dnsNode` objects in the `DomainDnsZones` and `ForestDnsZones` application partitions per [`02-protocols/05-dns-dynamic-updates.md`](../docs/02-protocols/05-dns-dynamic-updates.md). The framework's DNS may use CoreDNS, BIND, or a cloud DNS service. Two directories serving the same zone = split-brain DNS, with no inherent conflict resolution.

The conflict scenarios: (a) both directories claim to be authoritative for `_ldap._tcp.dc._msdcs.corp.example.com` SRV records — clients resolve to whichever DNS server they query first, leading to inconsistent DC discovery; (b) host A records created by AD dynamic updates (RFC 2136) may conflict with framework-managed A records — last-writer-wins, but the writer is non-deterministic; (c) GSS-TSIG authenticated dynamic updates (RFC 3645) require the client to have a TGT for the DNS server's realm — during parallel-run, a client may have TGTs for both AD and the framework, but each DNS server only accepts GSS-TSIG from its own realm.

The standard solution is zone delegation: split the namespace into `ad.corp.example.com` (served by AD) and `new.corp.example.com` (served by the framework) during the coexistence period. Clients that need to find AD DCs query `_ldap._tcp.dc._msdcs.ad.corp.example.com`; clients that need to find framework DCs query `_ldap._tcp.dc._msdcs.new.corp.example.com`. The forest-root zone `corp.example.com` is served by a neutral DNS that delegates each subdomain to the appropriate directory. After migration, the `ad.corp.example.com` subdomain is decommissioned and `corp.example.com` is fully managed by the framework.

The alternative is per-record migration: keep the same namespace but migrate records one at a time from AD-managed to framework-managed. Each A/SRV record migration requires: (a) stop AD dynamic updates for the record, (b) delete the record from AD DNS, (c) create the record in framework DNS, (d) verify resolution. This is operationally tedious for large namespaces (10,000+ records) but allows gradual migration without changing the namespace.

The framework gap: the framework must support both zone delegation and per-record migration. The framework's DNS server (whether CoreDNS, BIND, or custom) must support GSS-TSIG authenticated dynamic updates for AD-interop scenarios. The framework must provide a DNS-migration tool that automates per-record migration with conflict detection.

**Source state**: AD-integrated DNS zone `corp.example.com` with `_ldap._tcp.dc._msdcs` SRV records pointing to AD DCs. AD clients query this zone for DC discovery.

**Target state**: Framework-managed DNS zone `corp.example.com` (after cutover) with `_ldap._tcp.dc._msdcs` SRV records pointing to framework DCs.

**Coexistence period**: 90-365 days. During this window, zone delegation (`ad.corp.example.com` for AD, `new.corp.example.com` for framework) or per-record migration is used.

**Cutover trigger**: When 100% of DNS records have been migrated (per-record) or when the AD subdomain has had no queries for ≥30 days (zone delegation), the AD DNS zone is decommissioned and the framework's DNS becomes authoritative for `corp.example.com`.

**Rollback path**: Re-delegate the zone back to AD DNS. Re-create any migrated records in AD DNS. The framework's DNS-migration tool should preserve a rollback record-set for each migrated record.

**Impact**:

DNS namespace conflict breaks client resolution. AD clients may resolve to framework DCs (and fail Kerberos auth because the framework's KDC has no record of them) or vice versa. DC-discovery SRV records are particularly critical.

**Constraints**:

- Must support zone delegation (subdomain per directory).
- Must support split-brain DNS during migration.
- Must support per-record migration with conflict detection.
- Must support GSS-TSIG authenticated dynamic updates for AD-interop.
- Must preserve `_ldap._tcp.dc._msdcs.<domain>` SRV records for DC discovery.

**Cross-platform considerations**:

- **Windows**: AD-integrated DNS is the source. Windows clients use the DNS Client service (`dnscache`) which honours SRV records.
- **macOS**: macOS uses `mDNSResponder` for DNS resolution; supports SRV records. No native dynamic-update client but `nsupdate -g` works with GSS-TSIG.
- **Linux**: `systemd-resolved` or `dnsmasq` for resolution; `nsupdate -g` (BIND utilities) for GSS-TSIG dynamic updates.
- **Cross-platform consistency**: The framework's DNS server must speak the standard DNS protocols (RFC 1035 for resolution, RFC 2136 for dynamic update, RFC 3645 for GSS-TSIG) so all client platforms work uniformly.

**KB references**:

- [`02-protocols/05-dns-dynamic-updates.md`](../docs/02-protocols/05-dns-dynamic-updates.md) — AD-integrated DNS zone storage (`DomainDnsZones` and `ForestDnsZones` application partitions), `dnsNode` object schema, RFC 2136 dynamic update protocol, RFC 3645 GSS-TSIG authentication.
- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `trustedDomain` object that the framework's DCs and AD DCs use to discover each other; DNS SRV records drive DC-discovery which the trust depends on.

**Open questions**:

- Subdomain per directory (`ad.corp.example.com` + `new.corp.example.com`)? Per-record migration?

**Cross-capability impact**:

- Affects: PC-126 (client switchover depends on DNS for DC discovery), PC-129 (cross-realm Kerberos uses DNS SRV for KDC discovery).
- Affected by: PC-019 (DNS in-directory vs external CoreDNS — choice affects migration path).

---

### PC-129 — Kerberos cross-realm with AD during migration requires `capaths` + trust object

**Capability**: Migration
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Cross-realm Kerberos trust between AD and the framework requires three components per [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md), [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md), and [`09-linux-equivalents/08-freeipa-trust.md`](../docs/09-linux-equivalents/08-freeipa-trust.md): (a) a `trustedDomain` object on both sides (AD has one for the framework's realm; the framework's directory has one for AD's realm), (b) a `krbtgt/<other-realm>@<this-realm>` cross-realm principal on both sides, with the same password (the cross-realm key), (c) `[capaths]` configuration in `krb5.conf` on KDCs and clients, encoding the trust graph so the KDC knows the referral path.

The `trustedDomain` object carries `trustDirection`, `trustType`, `trustAttributes`, `flatName`, `securityIdentifier`, and `trustAuthBlob` (containing the encrypted cross-realm key). Setting this up requires admin intervention on both sides: `netdom trust <framework-realm> /d:<ad-realm> /add /twoway /password:<cross-realm-password>` on the AD side; equivalent on the framework side.

The `[capaths]` section in `krb5.conf` encodes the realm-trust graph. For a direct trust between AD (`CORP.EXAMPLE.COM`) and the framework (`FRAMEWORK.COM`):

```
[capaths]
  CORP.EXAMPLE.COM = {
    FRAMEWORK.COM = .
  }
  FRAMEWORK.COM = {
    CORP.EXAMPLE.COM = .
  }
```

The `.` means "direct trust exists". For indirect trusts (e.g. framework trusts an intermediate realm that trusts AD), the path must be listed explicitly:

```
[capaths]
  FRAMEWORK.COM = {
    CORP.EXAMPLE.COM = INTERMEDIATE.COM
  }
```

Manual `capaths` configuration is error-prone. A typo or missing entry causes referral failures (`KDC_ERR_S_PRINCIPAL_UNKNOWN (6)` with no clear root cause). The Kerberos client libraries do not auto-discover the trust graph — they require explicit configuration.

The framework gap: the framework should automate cross-realm setup end-to-end. The framework's trust-management CLI should: (a) create the `trustedDomain` object on the framework side, (b) prompt the admin to run the equivalent `netdom` command on the AD side (or, if the admin has credentials, run it remotely via PowerShell remoting), (c) verify both sides have the trust, (d) auto-generate `[capaths]` for both MIT krb5 and Heimdal clients, (e) publish the trust graph via DNS TXT records so clients can auto-discover (similar to `Realms` DNS SRV per RFC 4120 §7.2.1, but for trust paths).

**Source state**: AD forest at `CORP.EXAMPLE.COM` with no trust to the framework.

**Target state**: Framework realm at `FRAMEWORK.COM` with bidirectional cross-realm trust to AD. `[capaths]` configured on all KDCs and clients. Referral TGTs flow between realms.

**Coexistence period**: 90-365 days. During this window, users in either realm can access resources in the other realm via cross-realm referral.

**Cutover trigger**: When 100% of users, computers, and services have been migrated (PC-126), the cross-realm trust can be removed. AD's `trustedDomain` object for the framework is deleted; the framework's `trustedDomain` object for AD is deleted; `[capaths]` entries are removed from client configs.

**Rollback path**: Re-establish the cross-realm trust via `netdom trust /add` (or framework equivalent). Re-add `[capaths]` entries to client configs. The framework's trust-management tool should preserve a rollback configuration for each trust.

**Impact**:

Cross-realm setup is manual and error-prone. A misconfigured `[capaths]` causes authentication failures with cryptic error codes. For a 10-realm migration (multiple child domains + framework realm), the `[capaths]` matrix is 90 entries.

**Constraints**:

- Must support RFC 4120 §3.3.3 cross-realm referral.
- Must support `capaths` config generation for MIT krb5 and Heimdal.
- Must support bidirectional, transitive, and external trust types.
- Must support per-realm KDC discovery via DNS SRV (`_kerberos._tcp.<realm>`).
- Must automate trust creation end-to-end (both sides).

**Cross-platform considerations**:

- **Windows**: AD handles `capaths` implicitly via the `trustedDomain` object graph — no explicit `krb5.conf` needed on Windows clients. The framework's Windows client should behave the same way.
- **macOS**: PSSO Extension uses a Kerberos profile payload that can include `[capaths]`. The framework's MDM profile generator must produce this.
- **Linux**: MIT krb5 reads `[capaths]` from `/etc/krb5.conf` or `/etc/krb5.conf.d/`. SSSD can auto-generate `[capaths]` from `ad_trusts` config but only for direct trusts.
- **Cross-platform consistency**: The framework's `[capaths]` generator must produce platform-specific config files (Windows: none; macOS: PSSO payload; Linux: `krb5.conf` snippet).

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Kerberos cross-realm referral flow (RFC 4120 §3.3.3), TGT referral TGS-REQ/TGS-REP message exchange.
- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `trustedDomain` object, `trustAuthBlob` structure containing the cross-realm key, `trustDirection`/`trustType`/`trustAttributes` semantics.
- [`09-linux-equivalents/08-freeipa-trust.md`](../docs/09-linux-equivalents/08-freeipa-trust.md) — FreeIPA's `ipa trust-add` flow that automates cross-realm setup, including the `[capaths]` configuration written to `/var/kerberos/krb5kdc/kdc.conf` and `/etc/krb5.conf`.

**Open questions**:

- Auto-generate `capaths` from trust graph? Per-realm KDC discovery via DNS SRV?

**Cross-capability impact**:

- Affects: PC-126 (client switchover depends on cross-realm trust), PC-128 (DNS namespace sharing must align with cross-realm trust boundaries).
- Affected by: PC-028 (cross-realm TGT referral in KDC), PC-023 (KDC must implement MS-KILE referral profile).

---

### PC-130 — SYSVOL migration (logon scripts, GPO files) requires SMB share compatibility

**Capability**: Migration
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Clients read SYSVOL via `\\<domain>\SYSVOL\...` SMB share per [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) and [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md). The GPT half of every GPO lives at `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\` with `Machine\Registry.pol`, `User\Registry.pol`, `Machine\Scripts\`, `User\Scripts\`, `Machine\Preferences\`, etc. Logon scripts (`*.bat`, `*.ps1`) are stored under `\\<domain>\SYSVOL\<domain>\scripts\` and executed by the Group Policy Scripts CSE at user logon. The `NETLOGON` share (`\\<domain>\NETLOGON\`) holds older logon scripts and is the canonical location for AD-integrated scripts.

SYSVOL is replicated between DCs via DFS-R (`dfsr.exe`), a multi-master replication protocol using RDC (Remote Differential Compression) over the wire and the USN journal for change detection. The replication topology is defined by `msDFSR-ReplicationGroup`, `msDFSR-Member`, `msDFSR-Connection`, and `msDFSR-ContentSet` objects in `CN=DFSR-GlobalSettings,CN=System,DC=...`. Conflict resolution is last-writer-wins by `LastWriteTime`; losers are moved to `ConflictAndDeleted`.

During migration, both AD and the framework must serve SYSVOL (or one must redirect). Options:

(a) **Per-domain SYSVOL with DFS-N referral**: keep AD's SYSVOL on `\\corp.example.com\SYSVOL` and add a DFS-N referral for `\\corp.example.com\NEW-SYSVOL` pointing to the framework's SMB share. Windows clients that need AD GPO access `\\corp\SYSVOL`; framework-enrolled clients access `\\corp\NEW-SYSVOL`. The GPO version mismatch between AD and framework is handled by per-OU staging (one OU at a time, the framework's GPO applies to framework-enrolled clients in that OU; AD GPO is disabled for that OU after cutover).

(b) **Migrate to HTTP-based policy distribution**: replace SMB SYSVOL with an HTTPS endpoint served by the framework. Clients fetch policies via `GET https://policy.framework.com/v1/<machine-id>/`. This eliminates the SMB dependency entirely but requires every client to support HTTP policy fetch (Windows does via the Group Policy Client service with a custom CSE; macOS via the framework's client SDK; Linux via SSSD's `ipa_selinux` equivalent). This is a greenfield approach — does not preserve AD-interop.

The framework gap: the framework must support `SYSVOL`-style SMB share (interop with Windows clients expecting `\\<domain>\SYSVOL\...`) AND a modern HTTPS-based policy distribution path (for new clients). The DFS-N referral approach (a) preserves AD-interop but requires the framework's SMB server to honour `\\<domain>\...` UNC paths. The HTTP approach (b) is cleaner but requires client-side changes.

**Source state**: AD SYSVOL share at `\\corp.example.com\SYSVOL\corp.example.com\` with GPO files, logon scripts, GPT.INI files. DFS-R replication between AD DCs.

**Target state**: Framework-native policy distribution. Either SMB share at `\\corp.example.com\NEW-SYSVOL\` (per-domain with DFS-N referral) or HTTPS endpoint at `https://policy.framework.com/v1/`.

**Coexistence period**: 90-180 days. During this window, both AD SYSVOL and the framework's policy distribution are active. Windows clients still receive AD GPO; framework-enrolled clients receive framework policies.

**Cutover trigger**: When 100% of clients are framework-enrolled and AD GPO has been disabled for ≥30 days, the AD SYSVOL share is decommissioned.

**Rollback path**: Re-enable AD SYSVOL share. Re-link AD GPOs to OUs (`Set-GPLink -LinkEnabled Yes`). Framework policies can be disabled or deleted. The framework's policy-migration tool should preserve a rollback set of framework policies.

**Impact**:

SYSVOL migration disrupts GPO + logon-script distribution. If the framework's SMB share has different metadata semantics (e.g. no DFS-R replication), GPO version mismatches between GPC (in AD) and GPT (in SYSVOL) cause GPO processing failures.

**Constraints**:

- Must support `SYSVOL` and `NETLOGON` shares at `\\<domain>\...` UNC paths.
- Must support DFS-N-style referral for `\\<domain>\...` (the framework's SMB server must respond to DFS referral requests).
- Must support GPO file format (Registry.pol, GptTmpl.inf, Preferences XML, Scripts).
- Must support HTTPS-based policy distribution (for new clients).
- Must support rollback to AD SYSVOL.

**Cross-platform considerations**:

- **Windows**: Windows clients use the Group Policy Client service (`gpsvc.dll`) which expects `\\<domain>\SYSVOL\<domain>\Policies\...` SMB paths. The framework's SMB server must honour this path layout for Windows client compat.
- **macOS**: macOS does not natively consume SYSVOL. PSSO Extension can fetch policies via HTTPS — the framework's HTTP endpoint is the natural target.
- **Linux**: SSSD can fetch GPO from `\\<domain>\SYSVOL\...` via Samba client libraries (`libsmbclient`). Alternatively, SSSD can use an HTTPS endpoint if configured.
- **Cross-platform consistency**: The framework's policy-distribution path must produce identical policy content regardless of transport (SMB or HTTPS).

**KB references**:

- [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) — GPO two-part structure (GPC in AD + GPT in SYSVOL), `gPCFileSysPath` UNC link, `versionNumber` atomic pairing, `gpsvc.dll` SMB read flow.
- [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md) — DFS-N referral flow (`NetrDfsGetReferral` / `DfsGetReferrals` via the `NETDFS` RPC interface), pKT (Path Knowledge Table), `msDFS-TargetList` binary blob, site-aware referral costing.

**Open questions**:

- Per-domain SYSVOL with DFS-N referral? Migrate to HTTP-based policy distribution?

**Cross-capability impact**:

- Affects: PC-125 (GPO translation produces the files that go into SYSVOL), PC-126 (client switchover depends on policy continuity).
- Affected by: PC-055 (SYSVOL replication model — DFS-R equivalent is required if the framework serves SYSVOL via SMB), PC-078 (SMB server implementation — the framework's File Gateway must support `SYSVOL` share semantics).

---

## Cross-capability impact

Migration is the most cross-cutting of the cross-cutting capabilities: it touches every server-side capability (the framework must interop with the AD equivalent) and every client-side capability (clients must work in both AD and framework environments during coexistence). Key cross-capability impacts:

- **Core Directory (PC-001 through PC-022)**: DRSUAPI replication of `DRSAddSidHistory` (PC-124), schema compatibility (PC-107), trust objects (PC-129).
- **KDC (PC-023 through PC-035)**: Cross-realm TGT referral (PC-129), krbtgt cross-realm principal setup, etype compat between AD and framework.
- **Auth Provider (PC-036 through PC-042)**: NTLM interop during coexistence (some legacy apps still use NTLM against AD); time-sync (PC-041) between AD and framework KDCs.
- **Policy Engine (PC-043 through PC-056)**: GPO translation (PC-125) produces native policies that the Policy Engine serves; SYSVOL migration (PC-130) changes the distribution path.
- **Cert Service (PC-057 through PC-067)**: AD CS migration (CA database, templates, issued certs) is a separate migration workstream not in this catalog's scope but is implied.
- **Federation Gateway (PC-068 through PC-077)**: AD FS to framework IdP migration (relying-party trusts, claims rules, token-signing cert) is a separate migration workstream.
- **File Gateway (PC-078 through PC-084)**: SYSVOL migration (PC-130) depends on the File Gateway's SMB server supporting `SYSVOL` share semantics.
- **Client SDK (PC-085 through PC-093)**: Parallel-run client support — clients must work in both AD and framework environments (PC-126).
- **Cross-Platform Parity (PC-094 through PC-105)**: macOS and Linux clients must support the parallel-run mode (multiple realms, multiple directories).
- **Operations (PC-106 through PC-115)**: Migration runbooks are Operations tasks; the framework's operator must automate migration steps. Per-platform migration tooling (PC-115) is required.
- **Security (PC-116 through PC-123)**: sIDHistory migration (PC-124) directly enables the sIDHistory abuse attack (PC-120); parallel-run trust (PC-126) is a temporary attack surface; krbtgt rotation (PC-118) is part of the cutover.

## Open research questions specific to Migration

- Should the framework replace sIDHistory with claims-based migration, or document ADMT as the only migration path?
- Should the framework auto-translate known ADMX settings to native, or require per-setting review via a UI?
- Should the framework support per-SPN migration (one service at a time) or per-user migration (one user at a time) as the primary granularity?
- Should the password-sync agent protocol be proprietary (MIM/Entra Connect-compatible) or standard (LDAP modify on `unicodePwd` over TLS)?
- Should the framework use subdomain per directory (`ad.corp.example.com` + `new.corp.example.com`) or per-record migration for DNS namespace sharing?
- Should the framework auto-generate `[capaths]` from the trust graph, or require manual configuration?
- Should the framework use per-realm KDC discovery via DNS SRV (RFC 4120 §7.2.1) as the primary discovery mechanism?
- Should the framework use per-domain SYSVOL with DFS-N referral, or migrate to HTTP-based policy distribution as the primary path?
