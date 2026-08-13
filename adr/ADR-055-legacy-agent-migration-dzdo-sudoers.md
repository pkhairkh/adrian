---
title: "ADR-055: Document Migration Paths; dzdo to sudoers Import"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-104
severity: low
tags: [adr, cross-platform-parity, migration, centrify, pbis, admitmac, dave, dzdo, sudoers]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/09-cross-platform-parity.md
  - ../docs/08-macos-equivalents/07-third-party-agents-mac.md
  - ../docs/08-macos-equivalents/04-platform-sso-extension.md
last_updated: 2026-08-13
---

# ADR-055: Document Migration Paths; dzdo to sudoers Import

## Status

Accepted — 2026-08-13

## Context

Four third-party macOS AD agents predate Apple's first-party Kerberos SSO Extension (macOS 10.15+) and Platform SSO (macOS 13+) and survive in legacy/regulated deployments where the Apple-bundled OD AD plug-in is insufficient. Centrify DirectControl (now CyberArk since the 2024 acquisition, `/usr/local/share/centrifydc/bin/adjoin` + `/usr/local/share/centrifydc/sbin/adclient` + `dzdo` sudo replacement + Centrify Heimdal fork) — most invasive, ships its own Kerberos implementation for deterministic behavior across macOS/Linux/AIX/HP-UX/Solaris. BeyondTrust PBIS (formerly Likewise, deprecated macOS 2022, `/opt/pbis/bin/domainjoin-cli` + `/opt/pbis/sbin/lwsmd` + `lwreg`/`lwsm` + `libnss_pbis.dylib` shim) — ports the Linux stack to macOS, deprecated in favor of Apple PSSO. Thursby AdmitMac (legacy, `/Library/Filesystems/AdmitMac.fs/` kernel extension + `pam_admitmac.so` PAM module + Thursby Kerberos) — alternative SMB/Kerberos stack, predates Apple's AD plug-in. Thursby DAVE (legacy, `/Library/Filesystems/DAVE.fs/` kernel extension) — SMB-client-only (no AD authentication), predates SMBX, per [docs/08-macos-equivalents/07-third-party-agents-mac.md](../docs/08-macos-equivalents/07-third-party-agents-mac.md).

All four are being superseded by Apple PSSO + Jamf Connect. Centrify is the only actively-maintained agent (under CyberArk); PBIS macOS is EOL (2022); AdmitMac and DAVE are maintenance-only. The framework cannot depend on these; the framework's macOS strategy is PSSO-first (per ADR-048). For migration, the framework must document paths from each legacy agent to PSSO, including: (a) Centrify `adjoin`-bound Macs → `dsconfigad` or PSSO enrollment, with `dzdo` rules → `/etc/sudoers.d/` migration; (b) PBIS `domainjoin-cli`-bound Macs → `dsconfigad` or PSSO enrollment, with `/opt/pbis/config/reg.dat` settings → MDM Configuration Profile translation; (c) AdmitMac/DAV-E → native SMBX (already default since macOS 10.14), no migration needed for SMB; AdmitMac AD auth → PSSO.

Per [PC-104](../catalog/09-cross-platform-parity.md#pc-104--centrify--pbis--admitmac--dave-are-legacy-third-party-macos-agents)'s impact analysis, ~10-15% of enterprise macOS deployments still run Centrify (the only actively-maintained agent); ~5% still run PBIS (deprecated); <1% still run AdmitMac/DAVE (maintenance-only). The framework's macOS strategy cannot depend on these agents. The framework must provide first-party macOS support via PSSO (per ADR-048) and document migration paths for customers currently on legacy agents.

The constraints from [PC-104](../catalog/09-cross-platform-parity.md#pc-104--centrify--pbis--admitmac--dave-are-legacy-third-party-macos-agents) are: out of scope (the framework should not depend on legacy third-party macOS agents); must provide first-party macOS support via PSSO; must document migration paths from Centrify/PBIS/AdmitMac/DAVE to PSSO.

## Decision

The framework will document migration paths from each legacy third-party macOS agent (Centrify, PBIS, AdmitMac, DAVE) to the framework's first-party PSSO-based macOS client (per ADR-048), and will provide import tooling for Centrify `dzdo` rules → `/etc/sudoers.d/` files. The framework will not depend on any legacy third-party macOS agent; the framework's macOS strategy is PSSO-first. The framework's documentation will include a per-agent migration runbook covering detection, configuration translation, agent removal, and verification. The `dzdo`-to-`sudoers` import tooling will read Centrify's AD-stored RBAC rules (in `dzdoCommandRights` / `dzdoRole` auxiliary classes on AD user/group objects) and generate `/etc/sudoers.d/<role-name>` files that produce equivalent sudo behavior.

**Concrete specification**:

- The framework's macOS client MUST NOT depend on, install, or configure any of: Centrify DirectControl, BeyondTrust PBIS, Thursby AdmitMac, Thursby DAVE. The framework's installer MUST detect these agents and refuse to proceed until they are removed (or, optionally, the installer can be invoked with `--force` to proceed alongside, but this is documented as unsupported).
- The framework's documentation MUST include a "Legacy macOS agent migration" section with per-agent runbooks:
  - **Centrify DirectControl migration**: (1) detect via `adinfo` CLI presence and `/usr/local/share/centrifydc/` directory; (2) read existing Centrify config from `/etc/centrifydc/centrifydc.conf` and `dzinfo` output; (3) read Centrify RBAC rules from AD (`dzdoCommandRights` and `dzdoRole` auxiliary classes on user/group objects); (4) run the framework's `framework-import-dzdo` tool (see below) to generate `/etc/sudoers.d/<role-name>` files; (5) run `adleave` to unbind the Mac from Centrify AD; (6) remove Centrify packages (`pkgutil --forget com.centrify.centrifydc`); (7) enroll the Mac in the framework via the framework's macOS client installer (per ADR-048); (8) verify PSSO is functional via `sso_util cache -l`; (9) verify sudo via `sudo -l` showing the imported `dzdo` rules.
  - **PBIS migration**: (1) detect via `/opt/pbis/bin/domainjoin-cli` presence and `/opt/pbis/config/reg.dat` file; (2) read existing PBIS config from `reg.dat` (via `/opt/pbis/bin/lwreg`) and `domainjoin-cli query` output; (3) translate PBIS settings to MDM Configuration Profile equivalents (e.g. PBIS `RequireMembershipOf` → PSSO `AuthenticationClient` group claim; PBIS `LocalAdmins` → PSSO group-to-admin mapping); (4) run `/opt/pbis/bin/domainjoin-cli leave` to unbind the Mac; (5) remove PBIS packages (`pkgutil --forget com.pbis.*`); (6) enroll the Mac in the framework; (7) verify PSSO is functional; (8) verify group-to-admin mapping via `dseditgroup -o checkmember -m <user> admin`.
  - **AdmitMac migration**: (1) detect via `/Library/Filesystems/AdmitMac.fs/` directory; (2) verify SMB share access via macOS native SMBX (already default since macOS 10.14) — no SMB migration needed; (3) for AD auth, run the framework's installer to enroll the Mac in the framework; (4) remove AdmitMac kext (`kextunload /Library/Filesystems/AdmitMac.fs/AdmitMac.kext` and delete the bundle); (5) verify PSSO is functional.
  - **DAVE migration**: (1) detect via `/Library/Filesystems/DAVE.fs/` directory; (2) verify SMB share access via macOS native SMBX (already default since macOS 10.14) — no SMB migration needed; (3) remove DAVE kext; (4) DAVE does not handle AD auth, so no auth migration is needed (the framework's PSSO enrollment is a fresh install, not a migration).
- The framework MUST ship `framework-import-dzdo`, a CLI tool that reads Centrify's AD-stored `dzdo` RBAC rules and generates `/etc/sudoers.d/<role-name>` files. The tool: (1) authenticates to the framework directory (or to AD via the framework's AD-interop adapter) via Kerberos; (2) queries `dzdoCommandRights` and `dzdoRole` auxiliary classes on user and group objects via LDAP; (3) for each `dzdoRole`, generates a `/etc/sudoers.d/<role-name>` file with the equivalent sudo ruleset (translating Centrify's command-match syntax to sudoers syntax — e.g. Centrify's `dzdoCommandRights = "/usr/bin/systemctl restart nginx"` → sudoers `<role> ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx`); (4) writes the files with mode 0440 and owner `root:wheel`; (5) verifies the sudoers syntax via `visudo -c -f /etc/sudoers.d/<role-name>`; (6) logs the import to `/var/log/framework-import-dzdo.log` with each translated rule.
- The framework's documentation MUST include a "Centrify `dzdo` to sudoers translation" reference table covering the most common `dzdoCommandRights` patterns and their sudoers equivalents: command exact match, command prefix match, command with arguments, command with environment variables, command denied (via `dzdoDenyCommandRights`), role-with-elevated-privilege (via `dzdoRole` with `RunAsUser`), and role-with-no-password (via `dzdoRole` with `Authenticate=false`).
- The framework's macOS client MUST include a `framework-migrate-centrify` CLI that automates the Centrify migration runbook: detect Centrify, run `framework-import-dzdo`, run `adleave`, remove Centrify packages, enroll the Mac in the framework, verify PSSO, verify sudo. The CLI MUST be idempotent (re-running it after a successful migration is a no-op) and reversible (the `--rollback` flag re-installs Centrify and restores the original `dzdo` rules; this is documented as last-resort only).
- The framework's documentation MUST explicitly state that PBIS macOS is EOL (2022) and the framework's PBIS migration is a one-way operation (no rollback); customers migrating from PBIS should test on a non-production Mac first.
- The framework's automated test suite MUST include migration tests: deploy Centrify on a test Mac with a known `dzdo` ruleset, run `framework-migrate-centrify`, verify the generated `/etc/sudoers.d/` files produce equivalent sudo behavior, verify PSSO is functional, verify `adinfo` is no longer present. The test MUST cover the most common `dzdoCommandRights` patterns from the translation reference table.
- The framework's Prometheus exporter MUST expose `legacy_agent_migration_total{agent="centrify|pbis|admitmac|dave",result="..."}` metrics so operations teams can monitor migration progress.

## Rationale

The decision to document migration paths (rather than ship automated migration tools for all four agents) is forced by the framework's v1 economics. Centrify is the only agent with non-trivial migration complexity (`dzdo` rules are AD-stored and require translation); the framework ships `framework-import-dzdo` and `framework-migrate-centrify` for Centrify. PBIS migration is straightforward (detect, unbind, remove, enroll) and is documented as a runbook; an automated tool is feasible for v2 if customer demand warrants. AdmitMac and DAVE migrations are trivial (detect, remove, enroll) and are documented as runbooks.

The decision to ship `framework-import-dzdo` for Centrify `dzdo` rules is forced by the operational reality of Centrify deployments. Centrify's `dzdo` is a sudo replacement with AD-stored RBAC rules; customers have hundreds or thousands of `dzdo` rules in AD. Manual translation to `/etc/sudoers.d/` files is infeasible at scale. The `framework-import-dzdo` tool automates the translation, with a reference table covering the most common patterns. The tool is conservative: where a `dzdo` rule cannot be unambiguously translated to sudoers (e.g. Centrify's environment-variable-based command match, which has no sudoers equivalent), the tool logs a warning and skips the rule, leaving manual translation as a follow-up step.

The decision to provide a translation reference table (rather than a fully-automated tool that handles every `dzdo` pattern) is forced by the semantic gap between `dzdo` and sudoers. Centrify's `dzdo` has features that sudoers does not (e.g. environment-variable-based command match, AD-stored role hierarchy with inheritance); sudoers has features that `dzdo` does not (e.g. `Defaults` settings, `Host_Alias` patterns). A fully-automated translation is not possible; the reference table covers the common cases and documents the gaps.

The decision to make `framework-migrate-centrify` reversible (via `--rollback`) is forced by the operational risk of migration. Centrify is actively maintained (under CyberArk) and customers may have business-critical `dzdo` rules that the import tool cannot translate. The rollback flag re-installs Centrify and restores the original `dzdo` rules, providing a safety net for failed migrations. The rollback is documented as last-resort only; the recommended workflow is to test on a non-production Mac first.

The decision to document PBIS migration as a one-way operation (no rollback) is forced by PBIS's EOL status (2022). PBIS is no longer actively maintained; reinstalling PBIS after migration is unsupported and may fail on newer macOS versions. The framework's documentation explicitly states this and recommends testing on a non-production Mac first.

## Consequences

**Positive**. The framework gains documented migration paths for customers currently on legacy third-party macOS agents, eliminating the "we cannot migrate because of Centrify/PBIS/AdmitMac/DAVE" objection. The `framework-import-dzdo` tool and `framework-migrate-centrify` CLI automate the most complex migration (Centrify), reducing migration effort from days to hours per Mac. The framework's macOS strategy (PSSO-first, per ADR-048) is reinforced by making PSSO the clear endpoint of every legacy-agent migration path.

**Negative**. The framework's macOS client installer refuses to proceed if legacy agents are detected (or proceeds with `--force` as documented-unsupported), which may inconvenience customers in mixed-agent transitional states. The `framework-import-dzdo` tool cannot handle every `dzdo` pattern (Centrify's environment-variable-based command match, role hierarchy with inheritance); manual translation is required for these cases, adding migration effort for customers with complex `dzdo` rulesets. The framework's documentation must be maintained as Centrify/PBIS evolve (Centrify is actively maintained; PBIS is EOL but may have residual patches).

**Neutral**. The framework's migration paths are invisible to end users (they see PSSO after migration, not the migration process). The framework's PSSO-first strategy is invisible to operations teams on greenfield deployments (no legacy agents to migrate).

**Implementation cost**. Low-medium. Estimated 6-8 engineer-weeks for: `framework-import-dzdo` tool (with translation reference table), `framework-migrate-centrify` CLI (with rollback), per-agent migration runbooks (Centrify, PBIS, AdmitMac, DAVE), the migration test matrix (Centrify with common `dzdo` patterns), and the documentation. The `framework-import-dzdo` tool is the largest single component (~3-4 engineer-weeks for a correct, well-tested implementation).

**Operational impact**. Operations teams gain a clear migration path from each legacy agent to the framework's PSSO-based macOS client. Operations teams gain automation for the most complex migration (Centrify `dzdo` to sudoers). Operations teams lose the legacy agent management surfaces (Centrify Access Manager Console, PBIS LWI registry); the framework's CLI and the macOS-native `sudo`/`/etc/sudoers.d/` are the replacements. The framework's runbook must include a "Legacy macOS agent migration" section with per-agent runbooks.

## Alternatives Considered

**Alternative 1: Document migration paths only; do not ship automation tooling.** The framework provides documentation for each legacy-agent migration; customers perform the migration manually. **Rejection rationale**: Centrify `dzdo` to sudoers translation is infeasible at scale without automation (customers have hundreds or thousands of `dzdo` rules). The framework's `framework-import-dzdo` tool is necessary to make Centrify migration practical. The other three agents (PBIS, AdmitMac, DAVE) are simple enough that documentation-only is acceptable, but the framework ships `framework-migrate-centrify` as a complete CLI for the most complex case.

**Alternative 2: Ship automation tooling for all four legacy agents.** The framework ships `framework-migrate-pbis`, `framework-migrate-admitmac`, and `framework-migrate-dave` in addition to `framework-migrate-centrify`. **Rejection rationale**: PBIS, AdmitMac, and DAVE migrations are simple enough (detect, unbind, remove, enroll) that a runbook is sufficient. The engineering effort to ship and maintain three additional automated tools is not justified by the migration complexity. Customers who want automation can write their own scripts based on the framework's documented runbooks.

**Alternative 3: Support Centrify as a first-class macOS client (do not require migration).** The framework supports Centrify as one of several macOS client options alongside PSSO. **Rejection rationale**: This conflicts with the framework's PSSO-first macOS strategy (per ADR-048). Centrify is actively maintained under CyberArk, but it is a third-party commercial product; the framework's commitment to first-party macOS support via PSSO means Centrify is a migration source, not a supported client. Supporting Centrify as a first-class client would require ongoing compatibility testing with each Centrify release, adding maintenance burden without strategic value.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the Client SDK architecture choice (Rust core vs per-platform wrappers, per ORQ-169/170/175/176), but the migration tooling is independent of the SDK architecture: `framework-import-dzdo` and `framework-migrate-centrify` are CLIs that can be written in any language.

## Cross-capability impact

- **Client SDK** ([PC-086](../catalog/08-client-sdk.md)): PSSO Extension (per ADR-048) is the migration target for all four legacy agents.
- **Cross-Platform Parity** ([PC-105](../catalog/09-cross-platform-parity.md)): The macOS system Heimdal fork (per ADR-056) is inherited by PSSO; the framework's unified PAC validator (per ADR-049) closes the fork's limitations.
- **Migration** ([PC-128](../catalog/12-migration-and-coexistence.md)): The migration runbook includes the legacy-agent migration paths documented in this ADR.
- **Operations** ([PC-106](../catalog/10-operations.md)): Prometheus exporter exposes `legacy_agent_migration_total` metrics.

## References

- [PC-104](../catalog/09-cross-platform-parity.md) — problem statement
- [docs/08-macos-equivalents/07-third-party-agents-mac.md](../docs/08-macos-equivalents/07-third-party-agents-mac.md) — Centrify DirectControl, BeyondTrust PBIS, Thursby AdmitMac, Thursby DAVE architecture and maintenance status
- [docs/08-macos-equivalents/04-platform-sso-extension.md](../docs/08-macos-equivalents/04-platform-sso-extension.md) — PSSO Extension as the modern replacement for all four legacy agents
- [sudoers Manual](https://www.sudo.ws/docs/man/sudoers.man/) — sudoers file format reference
- [Centrify DirectControl Documentation](https://docs.centrify.com/) — Centrify `dzdo` and `dzdoCommandRights` reference (migration source)
- [BeyondTrust PBIS Documentation](https://www.beyondtrust.com/docs/) — PBIS LWI registry reference (migration source)
