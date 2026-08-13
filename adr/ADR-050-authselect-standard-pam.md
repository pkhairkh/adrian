---
title: "ADR-050: Adopt authselect as Standard PAM Profile Mechanism"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-092
severity: medium
tags: [adr, client-sdk, linux, pam, authselect, pam-auth-update, pam-config, sssd]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/08-client-sdk.md
  - ../docs/09-linux-equivalents/10-pam-nss-stack.md
  - ../docs/10-comparison-matrices/04-auth-flow-comparison.md
last_updated: 2026-08-13
---

# ADR-050: Adopt authselect as Standard PAM Profile Mechanism

## Status

Accepted — 2026-08-13

## Context

Linux PAM (Pluggable Authentication Modules, configured in `/etc/pam.d/<service>` or `/etc/pam.conf`) runs four phases — `auth` (verify identity), `account` (check account validity), `password` (update password), `session` (pre/post-login setup) — across a stack of modules (`pam_sss.so` for SSSD, `pam_winbind.so` for Winbind, `pam_krb5.so` for MIT Kerberos, `pam_ldap.so`/`pam_ldapd.so` for nslcd, `pam_unix.so` for local, `pam_mkhomedir.so`/`pam_oddjob_mkhomedir.so` for home creation, `pam_faillock.so` for account lockout, `pam_access.so` for host-based access). The three major distro families generate these stacks via different tools with different file layouts, per [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md).

Debian/Ubuntu uses `pam-auth-update` (`/usr/sbin/pam-auth-update` from the `libpam-runtime` package), which reads profile metadata from `/usr/share/pam-configs/*` (e.g. `/usr/share/pam-configs/sssd` with `Name: SSS authentication`, `Priority: 254`, `Auth-Type: Primary`, `Auth: [success=ok default=ignore] pam_sss.so use_first_pass`, etc.) and writes `/etc/pam.d/common-auth`, `common-account`, `common-password`, `common-session`. Each service file (`/etc/pam.d/login`, `/etc/pam.d/sshd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`, etc.) uses `@include common-auth` to pull in the shared config. RHEL/Fedora/Rocky uses `authselect` (`/usr/bin/authselect` from the `authselect` package), which ships profiles in `/usr/share/authselect/default/` (`sssd`, `winbind`, `nis`, `minimal`, `local`) and writes `/etc/pam.d/system-auth`, `/etc/pam.d/password-auth`, `/etc/pam.d/postlogin`, `/etc/pam.d/fingerprint-auth`, `/etc/pam.d/smartcard-auth`, plus `/etc/nsswitch.conf`. Profile features are added via `with-*` flags (`with-mkhomedir`, `with-sudo`, `with-fingerprint`, `with-smartcard`, `with-smartcard-required`, `with-silent-lastlog`, `with-faillock`, `with-pamaccess`, `with-nullok`). SUSE/openSUSE uses `pam-config` (`/usr/sbin/pam-config`), which writes `/etc/pam.d/common-{auth,account,password,session}-pc`.

The differences that bite are: (a) file layout — Debian's `common-*` vs RHEL's `system-auth`/`password-auth` vs SUSE's `common-*-pc`; a tool that edits `common-auth` on Debian breaks SUSE and is ignored on RHEL; (b) module ordering — Debian's `pam_sss.so` is `[success=1 default=ignore]` after `pam_unix.so`; RHEL's is `sufficient` after `pam_unix.so nullok try_first_pass`; SUSE's is `[success=ok default=ignore]` — the control values produce different fallback behavior when SSSD is unreachable; (c) feature flags — Debian's `pam-auth-update` uses debconf-driven profile selection; RHEL's `authselect` uses `with-*` flags; SUSE's `pam-config` uses `--add --<feature>` syntax — the same logical feature (e.g. "enable smartcard") requires three different invocations; (d) home directory creation — Debian uses `pam_mkhomedir.so` (runs in user session); RHEL uses `pam_oddjob_mkhomedir.so` (D-Bus `oddjobd` running as root, required for SELinux enforcing); SUSE uses `pam_mkhomedir.so` with `umask=0022 skel=/etc/skel` — three different mechanisms for the same feature.

Per [PC-092](../catalog/08-client-sdk.md#pc-092--pam-stack-varies-by-distro-debianubuntu-vs-rhelfedora-vs-suse)'s impact analysis, a typical enterprise Ansible role for "join Linux to AD and configure PAM" contains ~150 lines of per-distro logic for 3 distro families, and the logic must be re-tested on every distro upgrade. The framework cannot ship a per-distro PAM configuration tool for each of the three distro families; this would triple the framework's Linux PAM maintenance surface and create the same drift problem the framework is trying to solve. The framework must pick one PAM profile mechanism as the standard and document the others as legacy.

The constraints from [PC-092](../catalog/08-client-sdk.md#pc-092--pam-stack-varies-by-distro-debianubuntu-vs-rhelfedora-vs-suse) require the framework to: support `pam_sss.so` (or framework-equivalent module) on all three distro families; support `pam_mkhomedir.so` (Debian/SUSE) and `pam_oddjob_mkhomedir.so` (RHEL with SELinux); generate distro-correct PAM files via the distro-native tool — direct file editing is fragile and breaks on package updates; support `pam_faillock.so` for account lockout (the Linux equivalent of AD's "Account lockout threshold" GPO); support `pam_access.so` (`/etc/security/access.conf`) for host-based access control as an alternative to SSSD's GPO access.

## Decision

The framework will adopt `authselect` as the standard PAM profile mechanism on Linux across all three supported distro families (RHEL/Fedora/Rocky, Debian/Ubuntu, SUSE/openSUSE). The framework's Linux installer will install the `authselect` package on Debian/Ubuntu and SUSE (where it is not the distro default) and use `authselect select sssd with-mkhomedir with-faillock with-pamaccess` as the standard profile invocation. The framework's Linux client will ship a framework-supplied PAM module (`pam_framework.so`) as a drop-in replacement for `pam_sss.so` on framework-managed hosts, with `authselect` profile metadata installed at `/usr/share/authselect/default/framework/`. Per-distro legacy PAM generators (`pam-auth-update` on Debian, `pam-config` on SUSE) will be documented as legacy; the framework's installer will detect them and migrate to `authselect` automatically.

**Concrete specification**:

- The framework's Linux installer MUST install `authselect` (version 1.2+ minimum) on all supported Linux distros: RHEL/Fedora/Rocky (already installed by default), Debian/Ubuntu (apt package `authselect`), SUSE/openSUSE (zypper package `authselect`). The installer MUST verify `authselect --version` returns 1.2 or later.
- The framework's Linux installer MUST invoke `authselect select sssd with-mkhomedir with-faillock with-pamaccess` (or the framework-equivalent profile `authselect select framework with-mkhomedir with-faillock with-pamaccess` when `pam_framework.so` is installed) as the standard PAM profile configuration. The `with-mkhomedir` flag enables home directory creation; `with-faillock` enables account lockout per `pam_faillock.so`; `with-pamaccess` enables host-based access control per `pam_access.so`.
- The framework's Linux client MUST ship `pam_framework.so` (a framework-supplied PAM module) as a drop-in replacement for `pam_sss.so` on framework-managed hosts. The module MUST implement the four PAM phases (`auth`, `account`, `password`, `session`) with behavior identical to `pam_sss.so` for SSSD-compat mode and additional framework-specific features (policy application, audit logging) when framework mode is enabled. The module MUST be installable alongside `pam_sss.so` (no conflict) so customers can choose either.
- The framework's Linux client MUST ship `authselect` profile metadata at `/usr/share/authselect/default/framework/` with `frameworkAuthSelectProfile`, `frameworkAuthSelectProfileFeatures`, and per-phase PAM module stacks. The profile metadata MUST follow the `authselect` profile format documented at `/usr/share/doc/authselect/profiles/`.
- The framework's Linux installer MUST detect the existing PAM generator on the host: if `/usr/sbin/pam-auth-update` is present (Debian/Ubuntu) or `/usr/sbin/pam-config` is present (SUSE), the installer MUST invoke `authselect select` (overwriting the legacy generator's output) and document the migration in the installer log. The installer MUST NOT delete the legacy generator (`pam-auth-update` / `pam-config`) — they remain available for fallback if the customer needs to revert.
- The framework's Linux client MUST support `pam_oddjob_mkhomedir.so` on RHEL/Fedora/Rocky (required for SELinux enforcing mode) by adding `oddjob-mkhomedir` package installation to the framework's installer preflight check. The `authselect` profile's `with-mkhomedir` flag MUST select `pam_oddjob_mkhomedir.so` on RHEL-family distros and `pam_mkhomedir.so` on Debian/SUSE.
- The framework's Linux client MUST support `pam_faillock.so` for account lockout, configured via the framework's Policy Engine to map AD's "Account lockout threshold" GPO setting to `pam_faillock.so`'s `deny`, `fail_interval`, and `unlock_time` parameters. The mapping MUST be documented in the framework's GPO-equivalents matrix.
- The framework's Linux client MUST support `pam_access.so` (`/etc/security/access.conf`) for host-based access control as an alternative to SSSD's GPO access. The framework's Policy Engine MUST compile host-based access rules to `/etc/security/access.conf` entries when `with-pamaccess` is enabled.
- The framework's documentation MUST include a "PAM profile migration" section for each distro family: Debian/Ubuntu `pam-auth-update` → `authselect`, SUSE `pam-config` → `authselect`, RHEL/Fedora/Rocky native `authselect` (no migration needed). The migration section MUST include rollback procedures (reverting to the legacy generator if `authselect` fails).
- The framework's automated test suite MUST include PAM profile integration tests on all three distro families: install the framework on a clean Debian/Ubuntu, SUSE/openSUSE, and RHEL/Fedora/Rocky host; verify `authselect current` reports the framework profile; verify `pamtester login <user> auth` succeeds; verify `pamtester login <user> account` succeeds; verify home directory creation; verify `pam_faillock` lockout after N failed attempts; verify `pam_access` denies access for a non-allowed user.
- The framework's Prometheus exporter MUST expose `pam_auth_total{service="...",result="..."}`, `pam_account_total{service="...",result="..."}`, `pam_faillock_lockout_total{user="..."}` metrics so operations teams can monitor PAM stack health.

## Rationale

The decision to standardize on `authselect` is forced by `authselect`'s technical superiority over `pam-auth-update` and `pam-config`. `authselect` is the only PAM generator that supports profile composition via `with-*` feature flags (the others use opaque debconf/profile-metadata mechanisms that cannot be composed), the only one with a comprehensive `authselect current` introspection command, and the only one with a documented profile format (`/usr/share/authselect/default/<profile>/README` describing each profile's behavior). `authselect` is available on all three distro families (apt package on Debian/Ubuntu, zypper package on SUSE, native on RHEL/Fedora/Rocky), so the framework can standardize on one tool without requiring customers to switch distros.

The decision is also forced by Red Hat's influence. Red Hat employs the `authselect` maintainers and ships `authselect` as the default PAM generator on RHEL 8+, Fedora, and Rocky Linux. RHEL-family distros are ~40-50% of enterprise Linux deployments; aligning with Red Hat's choice gives the framework the largest single-distro compatibility surface. Debian/Ubuntu and SUSE can install `authselect` alongside their native generators; the migration is one command (`authselect select sssd with-mkhomedir with-faillock with-pamaccess`).

The decision to ship `pam_framework.so` as a drop-in replacement for `pam_sss.so` is forced by the framework's need to add framework-specific features (policy application, audit logging) to the PAM stack without forking SSSD. SSSD's `pam_sss.so` is a mature, well-tested module; the framework's `pam_framework.so` can wrap or replace it depending on the customer's needs. The drop-in design lets customers choose: SSSD-only (use `pam_sss.so` with the `sssd` `authselect` profile) or framework-managed (use `pam_framework.so` with the `framework` `authselect` profile). The framework's installer defaults to SSSD-only for compat with existing SSSD deployments; new deployments can opt into `pam_framework.so` for the framework-specific features.

The decision to migrate from `pam-auth-update` (Debian) and `pam-config` (SUSE) to `authselect` is forced by the framework's commitment to a single PAM profile mechanism. Maintaining three PAM generators' worth of framework-specific profile metadata would triple the framework's PAM maintenance surface; standardizing on one (`authselect`) lets the framework maintain one set of profile metadata. The migration is non-destructive (the legacy generators remain installed for rollback); the framework's installer handles the migration automatically.

The decision to map AD's "Account lockout threshold" GPO to `pam_faillock.so` is forced by the framework's GPO-parity commitment. Linux does not have a native AD-equivalent account lockout; `pam_faillock.so` (Linux-PAM 1.4+) is the modern standard, replacing the older `pam_tally2.so`. The framework's Policy Engine compiles the GPO setting to `pam_faillock.so` parameters; the `authselect` `with-faillock` flag enables the module in the PAM stack.

## Consequences

**Positive**. The framework gains a single PAM profile mechanism across all supported Linux distros, eliminating the per-distro PAM logic that today consumes ~150 lines of Ansible role per distro family. The framework's `pam_framework.so` adds framework-specific features (policy application, audit logging) without forking SSSD. The framework's `authselect` profile metadata is composable (via `with-*` flags), letting the framework enable features incrementally. The framework's `pam_faillock` mapping closes the AD "Account lockout threshold" parity gap on Linux.

**Negative**. Debian/Ubuntu and SUSE customers must accept `authselect` as a non-distro-default PAM generator; the framework's installer handles the migration but the customer's existing PAM customizations (e.g. site-specific `pam-config` profiles on SUSE) may need manual translation to `authselect` profile format. The framework's `pam_framework.so` is a new PAM module that must be maintained and patched as PAM evolves (e.g. new Linux-PAM releases, new SELinux policies). The `pam_oddjob_mkhomedir.so` dependency on RHEL adds an `oddjob-mkhomedir` package installation requirement.

**Neutral**. The framework's PAM profile metadata at `/usr/share/authselect/default/framework/` is invisible to end users (they interact with `authselect select`). The framework's `pam_faillock` mapping is invisible to AD administrators (they configure "Account lockout threshold" via GPO as usual).

**Implementation cost**. Medium. Estimated 8-12 engineer-weeks for: `pam_framework.so` module (with SSSD-compat mode and framework mode), `authselect` profile metadata, installer migration logic for Debian/Ubuntu and SUSE, `pam_faillock` GPO mapping, `pam_access` host-based access rules, the test matrix (3 distro families × multiple PAM scenarios), and the documentation.

**Operational impact**. Operations teams gain a single PAM management command (`authselect current` to inspect, `authselect select` to modify) across all distros. Operations teams lose the distro-native PAM generators (`pam-auth-update`, `pam-config`) for framework-managed hosts (the generators remain installed but are not used by the framework). The framework's runbook must include a "PAM troubleshooting on `authselect`" section. The framework's Prometheus metrics let operations teams monitor PAM stack health and detect lockout storms.

## Alternatives Considered

**Alternative 1: Use distro-native PAM generators (`pam-auth-update` on Debian, `authselect` on RHEL, `pam-config` on SUSE), with framework-specific profile metadata for each.** The framework ships three sets of profile metadata (one per distro family) and uses the distro-native generator on each. **Rejection rationale**: This triples the framework's PAM maintenance surface (three sets of profile metadata to keep in sync) and perpetuates the per-distro PAM logic that the framework is trying to eliminate. The framework's commitment to a single PAM profile mechanism cannot be met with three generators.

**Alternative 2: Use Ansible/Puppet as the PAM configuration layer, accepting that PAM stack management remains distro-specific at the Ansible role level.** The framework does not ship a PAM profile mechanism; instead, the framework's Ansible collection includes per-distro roles that manage PAM files directly. **Rejection rationale**: Direct PAM file editing is fragile and breaks on package updates (the distro's PAM package overwrites the files on upgrade). The framework's `authselect` approach uses the distro's PAM-management primitive (which is upgrade-safe) rather than fighting it.

**Alternative 3: Write a fresh framework-native PAM profile generator that targets all three distro families.** The framework ships `framework-pam-config`, a fresh PAM profile generator that produces distro-correct PAM files. **Rejection rationale**: This duplicates `authselect` functionality with less maturity. `authselect` is actively maintained by Red Hat, has a documented profile format, and is available on all three distro families. The framework cannot match Red Hat's investment in `authselect`, and the result would be a worse PAM generator than what already exists for free.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the Linux tier strategy (SSSD vs FreeIPA vs native client, per ORQ-202/203), but the PAM profile mechanism is independent of the Linux tier choice: `authselect` works with SSSD (via the `sssd` profile), with FreeIPA (via the `sssd` profile with FreeIPA-specific extensions), and with native client (via the `framework` profile using `pam_framework.so`).

## Cross-capability impact

- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The framework's Linux client SDK installs `pam_framework.so` and the `authselect` profile; the SDK's `framework-join` command invokes `authselect select` as part of the join flow.
- **Client SDK** ([PC-088](../catalog/08-client-sdk.md)): SSSD GPO access (`ad_gpo_access_control`) runs via `pam_sss.so account` phase; the framework's `pam_framework.so` account phase integrates with the framework's policy application API.
- **Policy Engine** ([PC-050](../catalog/04-policy-engine.md)): The Policy Engine's distribution model determines whether PAM config is pulled via SMB (GPO-style), HTTPS (modern), or D-Bus (local agent); the `authselect` profile is the application target regardless of distribution channel.
- **Operations** ([PC-106](../catalog/10-operations.md)): Prometheus exporter exposes `pam_auth_total` and `pam_faillock_lockout_total` metrics; OpenTelemetry traces log PAM phase events.

## References

- [PC-092](../catalog/08-client-sdk.md) — problem statement
- [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md) — `pam-auth-update` (Debian), `authselect` (RHEL), `pam-config` (SUSE), `pam_sss.so` parameter reference
- [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) — 8-phase login flow side-by-side showing Windows LSASS, macOS PAM, Linux SSSD PAM, Linux Winbind PAM
- [authselect Documentation](https://github.com/authselect/authselect) — authselect source and profile format documentation
- [Linux-PAM Documentation](https://linux-pam.org/) — Linux-PAM module developers' guide
- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) — OAuth 2.0 Device Authorization Grant (used by `pam_framework.so` for OAuth2-based login flows if needed)
