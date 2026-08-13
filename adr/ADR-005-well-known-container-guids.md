---
title: "ADR-005: Reserve and Honor Well-Known Container GUIDs"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-011
severity: medium
tags: [adr, core-directory, well-known-guids, wkguid, ad-interop]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/02-ous-containers.md
  - ../docs/00-overview/01-active-directory-overview.md
last_updated: 2026-08-13
---

# ADR-005: Reserve and Honor Well-Known Container GUIDs

## Status

Accepted — 2026-08-13

## Context

Active Directory binds a fixed set of well-known containers to NC heads via the `wellKnownObjects` and `msDS-WellKnownObjects` multi-valued attributes (both on the NC head object). Each entry is `B:32:<WKGUID>:<DN>`. The GUIDs are published in MS-ADTS §6.1.1 and are identical across all forests. Examples: `CN=Users` = `aa312825-683f-11d2-8d6c-001999999999`; `CN=Computers` = `a361b2bf-661b-4092-a59c-6e8ab9b9d919`; `CN=Deleted Objects` = `18e2ea80-84f1-11d2-9d4b-00c04f79f889`; `CN=System` = `30000000-66d7-4b81-bb2c-8e9b98f7d3f0`; `CN=LostAndFound` = `e458b0b0-ff42-4718-aa9b-df6e7c7a9a9a`; `CN=ForeignSecurityPrincipals` = `221ac1a7-6f24-4c89-8e68-26d2bf7822bb`; `CN=Infrastructure` = `2fbac1870ade11d297c400c04fd8d5cd`; `CN=Program Data` = `4bdf36c0-92f1-11d2-aee2-00c04f8e3c7f`; `CN=NTDS Quotas` = `a8d7a478-9f6b-4ea2-8d20-3a51e9f7a7e5`; `CN=Managed Service Accounts` = `1eb93889-e40c-46aa-bb97-fa32b925c1e0`, per [PC-011](../catalog/01-core-directory.md#pc-011--well-known-container-guids-are-forest-wide-constants) and [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md).

AD-aware clients use `<WKGUID=<guid>,<NC-dn>>` LDAP URLs to locate these containers portably without hardcoding the DN. Example: `ldap://dc01/<WKGUID=aa312825-683f-11d2-8d6c-001999999999,DC=corp,DC=example,DC=com>` resolves to `CN=Users,DC=corp,DC=example,DC=com`. This indirection matters because admins can rename `CN=Users` (technically possible, though rarely done) and the WKGUID binding still works. Tools that use WKGUID bindings include `dsquery`, ADUC, `redirusr` / `redircmp` (which redirect default user/computer creation containers by manipulating `wellKnownObjects`), Exchange System Manager, and many third-party tools that locate `CN=System` for service-connection-point lookups, per [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md).

Without WKGUID support, these tools fall back to hardcoded DN guesses (`CN=Users,DC=...`), which fail when the admin has restructured the tree. The framework would break Exchange's mailbox-provisioning workflow, ADUC's "New User" dialog (which defaults to the `wellKnownObjects`-redirected container), and any custom LDAP script that uses WKGUID.

Constraints from [PC-011](../catalog/01-core-directory.md#pc-011--well-known-container-guids-are-forest-wide-constants):

- WKGUID lookup must be supported at the DSA level — the LDAP server must resolve `<WKGUID=...,<NC-dn>>` to the actual DN before search.
- The `wellKnownObjects` and `msDS-WellKnownObjects` attributes must be writable by admins (to allow container redirection).
- For AD interop, the GUIDs must be the MS-ADTS §6.1.1 published values.

## Decision

The framework SHALL reserve and honor the MS-ADTS §6.1.1 well-known container GUIDs as forest-wide constants. The framework's DSA SHALL resolve `<WKGUID=<guid>,<NC-dn>>` LDAP URLs to the actual DN by reading the `wellKnownObjects` (or `msDS-WellKnownObjects`) attribute on the NC head and matching the GUID portion of each `B:32:<WKGUID>:<DN>` entry. The framework SHALL populate the `wellKnownObjects` attribute on every NC head at forest-creation time with the standard MS-ADTS §6.1.1 GUIDs.

The framework SHALL support WKGUID redirection: administrators SHALL be able to modify `wellKnownObjects` on an NC head to point a WKGUID at a different DN (e.g., redirect `CN=Users` to `OU=Corp Users,DC=...`). The DSA SHALL honor the redirected DN in WKGUID lookups. The framework SHALL expose the `redirusr`-equivalent and `redircmp`-equivalent CLI commands for redirection.

The framework's LDAP server SHALL accept `<WKGUID=<guid>,<NC-dn>>` as the base DN of an LDAP search operation and SHALL resolve it before performing the search. The WKGUID resolution SHALL be transparent to the client — the search response uses the resolved DN, not the WKGUID form.

For clean-slate deployments that do not require AD interop, the framework SHALL additionally expose a REST API endpoint (`/api/v1/well-known/<name>`) that returns the DN (or REST URL) of the well-known container by name (e.g., `/api/v1/well-known/Users` → `CN=Users,DC=corp,DC=example,DC=com`). This REST endpoint is a convenience for non-LDAP clients; the LDAP WKGUID lookup remains the canonical mechanism for AD-interop clients.

**Concrete specification**:

- The framework SHALL populate `wellKnownObjects` on every NC head at forest-creation time with the standard MS-ADTS §6.1.1 GUID→DN bindings.
- The DSA SHALL resolve `<WKGUID=<guid>,<NC-dn>>` in LDAP search base DN by: (1) reading `wellKnownObjects` on `<NC-dn>`; (2) finding the entry whose first 32 hex chars (after `B:32:`) match `<guid>`; (3) using the remaining `<DN>` portion as the resolved base DN.
- The DSA SHALL reject WKGUID lookups for GUIDs not present in `wellKnownObjects` with `noSuchObject (32)`.
- The framework SHALL expose `redirusr`-equivalent and `redircmp`-equivalent CLI commands that modify `wellKnownObjects` on the domain NC head to redirect the `CN=Users` and `CN=Computers` WKGUIDs.
- The framework SHALL expose a REST API endpoint `/api/v1/well-known/<name>` for non-LDAP clients; `<name>` is one of `Users`, `Computers`, `DeletedObjects`, `System`, `LostAndFound`, `ForeignSecurityPrincipals`, `Infrastructure`, `ProgramData`, `NTDSQuotas`, `ManagedServiceAccounts`.
- The `wellKnownObjects` attribute SHALL be writable by Domain Admins (and the framework's equivalent of Domain Admins in clean-slate mode).
- For AD-interop mode, the WKGUID values SHALL be byte-identical to MS-ADTS §6.1.1.
- The framework SHALL honor WKGUID redirection at runtime — no DSA restart required.

## Rationale

The MS-ADTS §6.1.1 GUIDs are forest-wide constants that every AD-aware tool depends on. Replacing them with new framework-specific GUIDs would break every AD-aware client without any compensating benefit. The original GUIDs are arbitrary (Microsoft-assigned, embedded in the binary); the framework has no reason to invent new ones. Honoring the existing GUIDs is the lowest-risk, highest-interop path.

Three alternatives were considered:

**Alternative A — Replace WKGUID with REST URLs (`/api/v1/well-known/Users`).** The REST endpoint is cleaner for greenfield deployments and non-LDAP clients. The disadvantage is that every AD-aware LDAP tool (`dsquery`, ADUC, Exchange System Manager) uses WKGUID over LDAP, not REST URLs. Replacing WKGUID breaks them all. ADOPTED as an *additional* endpoint for non-LDAP clients; the LDAP WKGUID mechanism remains canonical.

**Alternative B — Document WKGUID as legacy LDAP-only.** New clients use the REST API; AD-aware clients use WKGUID over LDAP. This is essentially what the Decision section specifies — both mechanisms coexist. The "legacy LDAP-only" framing was rejected because WKGUID is not legacy; it's the current AD-interop standard.

**Alternative C — Drop WKGUID entirely and require clients to use hardcoded DNs.** This is the simplest implementation but breaks every AD-aware tool that uses WKGUID indirection. Rejected because the framework targets AD-interop deployments.

External evidence: [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) publishes the WKGUID table; Samba 4 implements WKGUID resolution in its LDAP server; [RFC 4516 §3](https://www.rfc-editor.org/rfc/rfc4516#section-3) defines the LDAP URL format that AD extends with WKGUID. The pattern is AD-specific but well-documented and interoperable.

The cost of this decision is minimal — WKGUID resolution is a small LDAP-server code path (~200 lines) plus a one-time schema-NC initialization that populates `wellKnownObjects`. The benefit is full AD-interop for every tool that uses WKGUID.

## Consequences

**Positive**: AD-aware tools (Exchange, ADUC, `dsquery`, third-party LDAP apps) work without modification. WKGUID indirection enables container redirection (`redirusr` / `redircmp`), which is a documented best practice for new-forest creation. The REST endpoint provides a modern alternative for non-LDAP clients.

**Negative**: The framework inherits the MS-ADTS §6.1.1 GUIDs as permanent constants — they cannot be changed without breaking interop. This is a minor constraint; the GUIDs are arbitrary and stable.

**Neutral**: The WKGUID mechanism is invisible to clients that don't use it; they can hardcode DNs and the framework doesn't care. The REST endpoint is additive; deployments that don't use it pay no cost.

**Implementation cost**: ~1.5 person-weeks for the LDAP-server WKGUID resolver, schema-NC initialization, CLI commands, and REST endpoint. The work is straightforward.

**Operational impact**: `redirusr` / `redircmp`-equivalent commands work identically to AD; admins can redirect default user/computer creation containers without changes to their workflow. The REST endpoint enables modern automation (Ansible, Terraform) to discover well-known containers without LDAP parsing.

## Alternatives Considered

### Alternative 1: Replace WKGUID with REST URLs only

REST URLs are cleaner for greenfield deployments but break every AD-aware LDAP tool. ADOPTED as an *additional* endpoint for non-LDAP clients; the LDAP WKGUID mechanism remains canonical.

### Alternative 2: Document WKGUID as legacy LDAP-only

Both mechanisms coexist (LDAP WKGUID + REST endpoint). The "legacy" framing was rejected because WKGUID is the current AD-interop standard, not legacy.

### Alternative 3: Drop WKGUID entirely; require hardcoded DNs

Simplest implementation; breaks every AD-aware tool that uses WKGUID indirection. Rejected because the framework targets AD-interop deployments.

## Open Questions

- Should the framework support WKGUID on the Configuration NC and Schema NC heads in addition to Domain NC heads? AD does; the framework should match. Confirm in implementation.
- For the REST endpoint, should the framework accept the GUID (`/api/v1/well-known/aa312825-683f-11d2-8d6c-001999999999`) in addition to the name? Useful for programmatic clients that have the GUID but not the name. Defer to the Client SDK ADR.
- Cross-reference PC-022 (multi-tenancy, DEFERRED) — does each tenant NC head have its own `wellKnownObjects`? Yes, per the Decision (WKGUID is per-NC, not per-forest).

## Cross-capability impact

- **Cert Service**: `NTAuthCertificates` lives under `CN=Public Key Services,CN=Services,CN=Configuration,...`, located via WKGUID on the Configuration NC head. WKGUID support is required for PKINIT (cross-reference PC-027).
- **Client SDK**: Client API must expose well-known container lookup for both LDAP (WKGUID) and REST (`/api/v1/well-known/`).
- **Operations**: `redirusr` / `redircmp`-equivalent CLI commands are standard ops tasks.
- **Migration**: AD-to-framework migration preserves WKGUID bindings; no client reconfiguration required.

## References

- [PC-011](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md) — Full WKGUID table, `wellKnownObjects` / `msDS-WellKnownObjects` attribute format, WKGUID binding syntax
- [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) — well-known containers and AD structure
- [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Well-Known Object GUIDs table
- [RFC 4516 §3](https://www.rfc-editor.org/rfc/rfc4516#section-3) — LDAP URL format
