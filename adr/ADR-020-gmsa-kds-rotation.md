---
title: "ADR-020: gMSA with HSM-Bound KDS Root Key and Automatic 30-Day Rotation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-035
severity: high
tags: [adr, kdc, kerberos, gmsa, kds, service-accounts, rotation, hsm]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/00-overview/04-fsmo-roles.md
  - ./ADR-011-rc4-deprecation-aes-default.md
  - ./ADR-015-krbtgt-hsm-rotation.md
last_updated: 2026-08-13
---

# ADR-020: gMSA with HSM-Bound KDS Root Key and Automatic 30-Day Rotation

## Status

Accepted — 2026-08-13

## Context

Group Managed Service Accounts (gMSAs) are a special account type (`msDS-GroupMSAMembership` ACL on the gMSA object) with automatic 30-day password rotation computed by KDS (Key Distribution Service) using a forest-wide root key. The KDS root key is created via `Add-KdsRootKey` and must be created 10+ hours before use (the effective-time trick — KDS refuses to use a root key whose `EffectiveTime` is in the future, preventing key-recovery attacks where an admin creates a root key with a past EffectiveTime and computes historical gMSA passwords), per [PC-035](../catalog/02-kdc.md#pc-035--group-managed-service-accounts-gmsa-require-kds-root-key--automatic-password-rotation), [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md), and [docs/00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md).

Service hosts fetch the gMSA password via `NetrServerAuthenticate3` + `NetrServerRetrieveBaseDelta` (MS-NRPC) or via `Get-ADServiceAccount` (PowerShell, which calls the same RPC). The host must be a member of the gMSA's `msDS-GroupMSAMembership` group. The host caches the gMSA password for 30 days (until the next rotation); on cache expiry, the host fetches the new password from a DC.

The KDS root key is stored in `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,<forest-root-dn>` as `msKds-ProvRootKey` objects. The KDS uses the root key + the gMSA's SID + the current time (rounded to 30-day intervals) to derive the gMSA password via a PBKDF2-like derivation. All DCs compute the same password (same root key, same SID, same time interval) — no replication of the gMSA password itself, only of the root key.

Without gMSA-equivalent, service-account passwords are static (Kerberoast risk — see PC-024) or operator-managed (ops burden — rotate every N days manually). gMSA solves both: passwords rotate automatically every 30 days; the service host fetches the password without operator intervention; the password is never visible to operators. The 30-day rotation limits the Kerberoast window — an attacker who captures a TGS for the gMSA has 30 days to crack it before the password changes.

Constraints from [PC-035](../catalog/02-kdc.md#pc-035--group-managed-service-accounts-gmsa-require-kds-root-key--automatic-password-rotation):

- Must support automatic rotation (default 30 days, configurable).
- Must support host ACL (`msDS-GroupMSAMembership`).
- Must support the KDS root key (forest-wide secret used for password derivation).
- For AD interop, must implement the MS-NRPC password-fetch protocol (`NetrServerRetrieveBaseDelta`).
- The KDS root key derivation must be deterministic (all DCs compute the same password).

## Decision

The framework SHALL support group Managed Service Accounts (gMSAs) with automatic password rotation. The default rotation interval SHALL be 30 days (configurable per-deployment: minimum 1 day, maximum 90 days). The gMSA password SHALL be derived from: (a) the KDS root key, (b) the gMSA's SID, (c) the current time rounded to the rotation interval. The derivation SHALL be deterministic — all DCs compute the same password for the same gMSA at the same point in time.

The KDS root key SHALL be bound to an HSM (per ADR-015's HSM pattern). The root key SHALL NEVER leave the HSM in plaintext — the KDS service fetches the root key from the HSM and uses the HSM for all derivation operations. The root key SHALL NOT be stored in the directory's `msKds-ProvRootKey` object in plaintext; the directory SHALL store only an HSM key reference (key handle / key ID).

The framework SHALL create the KDS root key with an `EffectiveTime` set to `now + 10 hours` (the effective-time trick) — the KDS refuses to use a root key whose `EffectiveTime` is in the future, preventing key-recovery attacks. The framework SHALL expose a CLI command (`adrian-krb5 kds-add-root-key`) that creates the root key with the correct `EffectiveTime`.

The framework SHALL support host ACL (`msDS-GroupMSAMembership` on the gMSA object). Service hosts that are members of the ACL'd group SHALL be able to fetch the gMSA password; non-members SHALL be refused with `ERROR_ACCESS_DENIED (5)`.

The framework SHALL implement the MS-NRPC password-fetch protocol (`NetrServerAuthenticate3` + `NetrServerRetrieveBaseDelta`) for AD-interop mode, byte-identical to AD's `Netlogon` implementation. Service hosts use this protocol to fetch the gMSA password from a DC.

The framework SHALL expose a CLI command (`adrian-krb5 gmsa-create <name>`) that creates a gMSA object with the standard schema attributes (`msDS-ManagedPasswordIntervalDays = 30`, `msDS-GroupMSAMembership = <group-DN>`, `servicePrincipalName = <SPN>`). The framework SHALL expose `adrian-krb5 gmsa-install <name>` (install the gMSA on a service host — fetches the password and caches it locally) and `adrian-krb5 gmsa-fetch <name>` (manually fetch the current gMSA password — for testing).

The root-key distribution mechanism (KDS-derived as in AD vs. Vault-backed secrets as in HashiCorp Vault) is DEFERRED to Tier 3. The v1 implementation SHALL use KDS-derived (matching AD) for AD-interop; Vault-backed may be adopted later as an alternative for clean-slate deployments.

**Concrete specification**:

- The framework SHALL support gMSA objects with standard schema attributes: `msDS-ManagedPasswordIntervalDays` (default 30, configurable 1–90), `msDS-GroupMSAMembership` (host ACL), `servicePrincipalName` (the gMSA's SPN).
- The gMSA password SHALL be derived deterministically from: (a) the KDS root key, (b) the gMSA's SID, (c) the current time rounded to the rotation interval.
- The KDS root key SHALL be bound to an HSM (per ADR-015's HSM pattern); the root key SHALL NEVER leave the HSM in plaintext.
- The directory SHALL store only an HSM key reference for the KDS root key (in `msKds-ProvRootKey` object); the `EffectiveTime` attribute SHALL be set to `now + 10 hours` on creation.
- The framework SHALL enforce host ACL (`msDS-GroupMSAMembership`) on every password fetch; non-members SHALL be refused with `ERROR_ACCESS_DENIED (5)`.
- For AD-interop mode, the framework SHALL implement the MS-NRPC password-fetch protocol (`NetrServerAuthenticate3` + `NetrServerRetrieveBaseDelta`), byte-identical to AD.
- The framework SHALL expose `adrian-krb5 kds-add-root-key`, `adrian-krb5 gmsa-create <name>`, `adrian-krb5 gmsa-install <name>`, and `adrian-krb5 gmsa-fetch <name>` CLI commands.
- Performance target: gMSA password fetch SHALL complete in <100 ms (the derivation is CPU-bound, not network-bound).
- The framework SHALL support shorter rotation intervals (e.g. 1 hour, like Kubernetes service-account tokens) for high-security deployments. The derivation algorithm SHALL handle arbitrary intervals correctly (round the current time to the interval boundary).

## Rationale

gMSAs solve two operational problems: (a) static service-account passwords (Kerberoast risk) — gMSA rotation limits the crack window to the rotation interval; (b) operator-managed password rotation (ops burden) — gMSA rotation is automatic and invisible to operators. The 30-day default matches AD and is a reasonable balance between security (shorter is better) and operational overhead (longer is easier on service-host caches).

Three alternatives were considered:

**Alternative A — Static service-account passwords with operator-managed rotation.** Operators rotate passwords every N days via scripts. The advantage is simplicity (no KDS, no derivation). The disadvantages are: (a) operator error (forgot to rotate, weak new password); (b) ops burden (rotation is a recurring task); (c) static window between rotations (if rotation is monthly, the crack window is 30 days — same as gMSA but without the automation). Rejected as the primary mechanism; ADOPTED as a fallback for service accounts that cannot use gMSA (e.g. accounts that need plain-text password for legacy auth).

**Alternative B — HashiCorp Vault integration for service-account secrets.** Vault handles secret rotation, access control, audit logging. The framework's KDC issues short-lived tokens to service hosts, who use the tokens to fetch secrets from Vault. The advantages are: (a) Vault is a mature, widely-deployed secret manager; (b) Vault handles audit logging and access control natively. The disadvantages are: (a) Vault is an external dependency; (b) Vault does not interoperate with AD (AD uses KDS, not Vault); (c) Vault's secret-fetch protocol is HTTP, not MS-NRPC. Rejected as the primary mechanism for v1 (KDS-derived is AD-interop); may be adopted as an alternative for clean-slate deployments (deferred to Tier 3).

**Alternative C — Short-lived Kerberos tickets without long-term keys (Kubernetes service-account token model).** The service host obtains a short-lived Kerberos ticket (e.g. 1 hour) from the KDC via a host-identity-based auth (no service-account password at all). The advantage is no long-term key to crack. The disadvantage is breaking AD interop (AD uses long-term keys for service accounts; the KDC's TGS-REQ processing depends on the service account's long-term key to encrypt the service ticket). Rejected for v1; may be considered for a future clean-slate-only deployment mode.

External evidence: [MS-ADTS §3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents gMSA schema; [MS-NRPC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/) documents `NetrServerRetrieveBaseDelta`; Microsoft's [Group Managed Service Accounts Overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview) covers the operational model. Samba 4 supports gMSA since 4.15. The framework's design matches AD's behavior and is interoperable.

The cost of this decision is the KDS service (a new component co-located with the KDC), the HSM integration for the root key (shared with ADR-015), the MS-NRPC password-fetch protocol (for AD-interop), and the CLI commands. The bulk of the work is the KDS derivation algorithm and the MS-NRPC implementation.

## Consequences

**Positive**: Service-account passwords rotate automatically every 30 days (or shorter for high-security deployments). The rotation is invisible to operators. The KDS root key is HSM-bound (never on disk, never in LSASS memory). AD-interop is preserved via MS-NRPC. The Kerberoast crack window is bounded by the rotation interval.

**Negative**: The KDS service is a new component that must be deployed alongside the KDC. The HSM is a shared dependency (also used for the krbtgt key per ADR-015). The MS-NRPC implementation adds complexity for AD-interop.

**Neutral**: The root-key distribution mechanism (KDS vs. Vault) is deferred to Tier 3. The v1 implementation uses KDS-derived (AD-interop); Vault may be adopted later for clean-slate deployments.

**Implementation cost**: ~6 person-weeks for the KDS service, the derivation algorithm, the HSM integration (shared with ADR-015), the MS-NRPC password-fetch protocol, and the CLI commands. The bulk of the work is the KDS derivation and the MS-NRPC implementation.

**Operational impact**: gMSA creation is a CLI command (`adrian-krb5 gmsa-create`); installation on a service host is a CLI command (`adrian-krb5 gmsa-install`). Password rotation is automatic and invisible. SIEM queries for gMSA password fetches (per ADR-023) detect unauthorized hosts attempting to fetch gMSA passwords.

## Alternatives Considered

### Alternative 1: Static service-account passwords with operator-managed rotation

Simplicity; operator error, ops burden, static crack window. Rejected as primary; ADOPTED as fallback for service accounts that cannot use gMSA.

### Alternative 2: HashiCorp Vault integration for service-account secrets

Mature secret manager; external dependency, no AD interop, HTTP not MS-NRPC. Rejected as primary for v1 (KDS-derived is AD-interop); may be adopted as alternative for clean-slate deployments (deferred to Tier 3).

### Alternative 3: Short-lived Kerberos tickets without long-term keys (Kubernetes model)

No long-term key to crack; breaks AD interop. Rejected for v1; may be considered for a future clean-slate-only deployment mode.

## Open Questions

- For the KDS root key derivation algorithm, what is the exact PBKDF2-like derivation? AD uses a proprietary derivation; the framework SHALL match AD byte-for-byte for AD-interop. Defer to implementation — the algorithm is documented in MS-ADTS but requires careful reverse-engineering.
- For the root-key distribution mechanism (KDS vs. Vault), when is the Tier 3 decision expected? Defer to the KDS vs. Vault research spike (gated by Tier-3 ORQ).
- Should the framework support shorter rotation intervals (e.g. 1 hour, like Kubernetes service-account tokens)? Yes — the Decision section specifies configurable interval (1–90 days). The derivation algorithm SHALL handle arbitrary intervals.
- Cross-reference ADR-015 (krbtgt HSM) — the KDS root key uses the same HSM as the krbtgt key. The framework's HSM interface is shared.
- Cross-reference ADR-011 (RC4 deprecation) — gMSAs use Kerberos only (no NTLM fallback), so RC4 deprecation does not affect gMSAs.

## Cross-capability impact

- **Core Directory**: The gMSA object is a Core Directory object (standard schema). The KDS root key reference is stored in the Configuration NC.
- **Auth Provider**: gMSAs use Kerberos only (no NTLM fallback). The Auth Provider's Kerberos SSPI-equivalent handles gMSA-based service authentication.
- **Operations**: gMSA creation, installation, and monitoring are standard ops tasks. SIEM queries for gMSA password fetches detect unauthorized hosts.
- **Migration**: AD-to-framework migration preserves gMSAs (same schema, same MS-NRPC protocol). Service hosts continue to fetch gMSA passwords without modification.
- **Security**: gMSA rotation limits the Kerberoast crack window to the rotation interval. The HSM-bound KDS root key prevents root-key extraction attacks.
- **Client SDK**: Client SDK exposes `gmsa-create`, `gmsa-install`, `gmsa-fetch` CLI commands for service-account management.

## References

- [PC-035](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — gMSA schema attributes, KDS root key storage, password derivation algorithm
- [docs/00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md) — KDS as a forest-wide service, root key creation, `Add-KdsRootKey` effective-time trick
- [MS-ADTS §3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — gMSA schema
- [MS-NRPC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/) — `NetrServerRetrieveBaseDelta`
- [Microsoft Group Managed Service Accounts Overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
