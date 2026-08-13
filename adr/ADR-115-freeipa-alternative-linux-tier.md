---
title: "ADR-115: FreeIPA as Supported Alternative Linux Tier via Cross-Realm Trust"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-100
severity: medium
unblocked_by: [workshop-decision-12]
tags: [adr, cross-platform-parity, freeipa, linux, cross-realm-trust, hbac, idoverride, sssd, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-013-cross-realm-tgt-referral.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-062-trust-password-auto-rotation.md
  - ./ADR-069-cross-realm-capaths.md
  - ./ADR-114-linux-identity-stack-sssd-primary.md
  - ../catalog/09-cross-platform-parity.md
  - ../workshop/decision-12-linux-tier.md
  - ../docs/09-linux-equivalents/08-freeipa-trust.md
  - ../docs/03-directory-schema/04-trusts-topology.md
last_updated: 2026-08-14
---

# ADR-115: FreeIPA as Supported Alternative Linux Tier via Cross-Realm Trust

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 12](../workshop/decision-12-linux-tier.md) (SSSD primary + FreeIPA alt). Resolves the medium-severity problem [PC-100](../catalog/09-cross-platform-parity.md) (FreeIPA is a separate Linux identity platform with AD cross-forest trust — the framework's posture toward FreeIPA as an alternative Linux tier). Locks the `adrian-cli trust establish --peer freeipa` and `adrian-cli trust sync-hbac` tooling and the cross-realm trust topology between FreeIPA and the framework's directory.

## Context

FreeIPA is the de facto Linux domain controller (389-DS directory + MIT krb5 KDC + BIND DNS + Dogtag PKI + certmonger cert enrollment + SSSD client + HBAC host-based access control + sudo rules + ID views + `ipa-extdom-plugin` extended operation for AD SID lookups). FreeIPA is widely deployed in enterprises with significant Linux footprints (Red Hat Identity Management is FreeIPA-based). FreeIPA supports cross-forest trust with AD via MS-LSAD `LsaCreateTrustedDomainEx3` opnum 44 with `TRUST_ATTRIBUTE_FOREST_TRANSITIVE`, allowing FreeIPA-managed Linux hosts to authenticate AD users (and vice versa). FreeIPA's `ipa-extdom-plugin` (extended operation OID `2.16.840.1.113730.3.8.10.4`) proxies AD SID lookups to the AD Global Catalog, allowing FreeIPA-managed Linux hosts to resolve AD users via SSSD's `ipa` provider, per [docs/09-linux-equivalents/08-freeipa-trust.md](../docs/09-linux-equivalents/08-freeipa-trust.md) and [docs/03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md).

Per [PC-100](../catalog/09-cross-platform-parity.md) (and catalog [PC-101](../catalog/09-cross-platform-parity.md)), the framework must decide its posture toward FreeIPA. Three options: (a) adopt FreeIPA as the framework's Linux identity platform (rejected per Decision 12 §Rationale §Candidate A — FreeIPA's schema and release cadence are incompatible with the framework's directory); (b) build a native IPA-equivalent in the framework (rejected per Decision 12 §ORQ-203 — ~2-3 years of engineering effort to re-implement HBAC, sudo rules, ID views, cert management); (c) support FreeIPA as an alternative Linux tier via cross-realm trust (chosen per Decision 12 §3). The cross-realm trust approach preserves FreeIPA customers' investment in HBAC, sudo rules, ID views, and `certmonger` while giving them access to the framework's directory, KDC, policy engine, and cert service.

Workshop Decision 12 ([workshop/decision-12-linux-tier.md](../workshop/decision-12-linux-tier.md)) §3 resolved the gating ORQs ORQ-202/203 in favor of: "Customers who want a full Linux domain controller (with FreeIPA's CA, DNS, HBAC, and `idoverride` integration) deploy FreeIPA alongside the framework, with a cross-realm trust between FreeIPA and the framework's directory." This ADR locks the concrete cross-realm trust topology, the `adrian-cli trust establish --peer freeipa` and `adrian-cli trust sync-hbac` tooling, and the framework's posture toward FreeIPA-managed hosts.

## Decision

The framework's posture toward FreeIPA is: **FreeIPA is a supported alternative Linux tier**, deployed alongside the framework via a cross-realm trust between FreeIPA and the framework's directory. FreeIPA-managed Linux hosts use FreeIPA's own client tooling (`ipa-client-install`, `sssd-ipa` provider) for PAM/NSS/Kerberos; they do not use the framework's Client SDK directly. The framework's policy and cert services are accessible to FreeIPA-managed hosts via the framework's REST/gRPC API (per [ADR-061](./ADR-061-rest-grpc-api.md)), but the native FreeIPA client experience is preserved. The framework does not build a native IPA-equivalent (per Decision 12 §ORQ-203); HBAC, sudo rules, ID views, and `certmonger` remain FreeIPA-managed for FreeIPA-managed hosts.

**Concrete specification**:

- **Cross-realm trust establishment** (`adrian-cli trust establish --peer freeipa --realm <freeipa-realm>`, per Decision 12 §3). The command performs:
  - Creates the trust object in the framework's directory (per [docs/03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md)) under `CN=<freeipa-realm>,CN=TrustedDomain,CN=System,<domain DN>` with `trustDirection = 0x03` (inbound + outbound), `trustType = 0x02` (uplevel/Mit-style), `trustAttributes = 0x08` (`TRUST_ATTRIBUTE_FOREST_TRANSITIVE`), `trustAuthIncoming` and `trustAuthOutgoing` set to the trust password (randomly generated, 32 bytes, base64-encoded).
  - Configures the framework's KDC to issue cross-realm TGTs (per [ADR-013](./ADR-013-cross-realm-tgt-referral.md)) for the FreeIPA realm, with the `krbtgt/<freeipa-realm>@<framework-realm>` and `krbtgt/<framework-realm>@<freeipa-realm>` cross-realm principals (the trust password is the same for both).
  - Configures the framework's directory to expose the FreeIPA realm's users/groups via the `altSecurityIdentities` attribute (so framework-managed Windows/macOS hosts can resolve FreeIPA users when needed — rare scenario, but supported).
  - Configures FreeIPA's `idoverride` to map FreeIPA users to framework-directory users (via the framework's UUID, exposed in the `ipaAnchorUUID` attribute — the `ipaAnchorUUID` value is `ipa:<uuid>`, the framework's UUID for the corresponding framework-directory user). The `adrian-cli trust establish --peer freeipa` command calls FreeIPA's JSON-RPC API (via `reqwest`) to create the `idoverride` entries.
  - Configures the framework's directory to expose framework users to FreeIPA via `ipa-extdom-plugin` extended operation (OID `2.16.840.1.113730.3.8.10.4`). FreeIPA's `ipa-extdom-plugin` proxies AD SID lookups to the AD Global Catalog; the framework's directory implements the equivalent extended operation, allowing FreeIPA-managed Linux hosts to resolve framework-directory users via SSSD's `ipa` provider.
  - Writes `/etc/krb5.conf` `[capaths]` section on the framework's KDC hosts to enable cross-realm TGT referral (per [ADR-069](./ADR-069-cross-realm-capaths.md)). The `[capaths]` section maps `<framework-realm> = { <freeipa-realm> = . }` and `<freeipa-realm> = { <framework-realm> = . }` (direct trust, no transitive path through other realms).

- **Trust password auto-rotation** (per [ADR-062](./ADR-062-trust-password-auto-rotation.md)). The framework's `adrian-trust-rotate` daemon rotates the trust password every 180 days (the framework's default, matching AD's default). The daemon generates a new 32-byte random password, updates the trust object's `trustAuthIncoming` and `trustAuthOutgoing` in the framework's directory, updates the cross-realm `krbtgt` principals in the framework's KDC, and calls FreeIPA's JSON-RPC API to update the trust password on the FreeIPA side (via `ipa trustmod --trust-secret`). The daemon verifies that the new trust password works by attempting a cross-realm TGS-REQ (`kvno krbtgt/<freeipa-realm>@<framework-realm>`) before completing the rotation; on failure, the daemon rolls back to the previous password.

- **HBAC sync from framework to FreeIPA** (`adrian-cli trust sync-hbac`, per Decision 12 §6). The framework's `Security` PolicyArea's `PermitHosts` and `PermitGroups` settings (per Decision 7 §1) are translated to FreeIPA HBAC rules via the `adrian-cli trust sync-hbac` command. The command:
  - Reads the framework's `Security` PolicyArea policy (via the framework's WebSocket push per [ADR-028](./ADR-028-push-based-policy-websocket.md)).
  - For each `PermitHosts` rule (allowing user U to authenticate to host H), creates or updates a FreeIPA HBAC rule `adrian-<policy-id>-<host>` with `host = H`, `user = U`, `service = all` (FreeIPA HBAC is per-host-per-user-per-service; the framework's policy is per-host-per-user, so `service = all`).
  - For each `PermitGroups` rule (allowing group G to authenticate to host H), creates or updates a FreeIPA HBAC rule `adrian-<policy-id>-<group>` with `host = H`, `usergroup = G`, `service = all`.
  - Calls FreeIPA's JSON-RPC API (`ipa hbacrule-add`, `ipa hbacrule-add-host`, `ipa hbacrule-add-user`) via `reqwest`.
  - Deletes FreeIPA HBAC rules with the `adrian-*` prefix that no longer correspond to a framework policy (the sync is idempotent; running it twice produces the same FreeIPA HBAC state).

- **FreeIPA-managed Linux hosts do not use the framework's Client SDK.** FreeIPA-managed Linux hosts use FreeIPA's own client tooling (`ipa-client-install`, `sssd-ipa` provider) for PAM/NSS/Kerberos. The framework's `pam_adrian.so` / `nss_adrian.so.2` modules (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §PAM/NSS provider) are NOT installed on FreeIPA-managed hosts. The framework's policy enforcement on FreeIPA-managed hosts is via FreeIPA's HBAC (for `Security` PolicyArea) and via the framework's REST/gRPC API (per [ADR-061](./ADR-061-rest-grpc-api.md)) for other PolicyAreas. The framework's cert enrollment on FreeIPA-managed hosts is via FreeIPA's `certmonger` (against FreeIPA's Dogtag CA, not the framework's CA per Decision 8). The framework's federation tokens are accessible to FreeIPA-managed hosts via the framework's OIDC/SAML endpoints (per Decision 9), but the framework's `FederationModule` (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §Federation) is not installed.

- **The framework does not build a native IPA-equivalent.** Per Decision 12 §ORQ-203, the framework does not re-implement HBAC, sudo rules, ID views, or `certmonger` in the framework's Core Directory + Policy Engine. Customers who want these features use FreeIPA as the alternative Linux tier. The framework's `Security` PolicyArea's `PermitHosts`/`PermitGroups` settings (per Decision 7 §1) provide HBAC-equivalent functionality for framework-managed hosts (via the `adrian-sssd-gpo` library per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md) §2 or the `adrian-policy-daemon` per [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md)), but the framework does not expose a native HBAC API or a native `certmonger`-equivalent.

- **`adrian-cli trust establish --peer freeipa`** and **`adrian-cli trust sync-hbac`** Rust crate dependencies:
  - `clap = "4"` (CLI argument parsing)
  - `tokio = "1"` (async runtime)
  - `ldap3 = "0.11"` (directory trust-object creation)
  - `gss-api = "0.1"` (Kerberos cross-realm configuration via `libgssapi_krb5`)
  - `reqwest = "0.12"` (FreeIPA JSON-RPC API calls)
  - `serde_json = "1"` (JSON-RPC payload serialization)
  - `rand = "0.8"` (trust password generation)
  - `tracing = "0.1"` (structured logging)

- **Audit logging**: every `trust establish --peer freeipa`, `trust sync-hbac`, and trust password rotation operation emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "sdk_trust_op"`, `op` (`establish`/`sync_hbac`/`rotate_password`), `peer_realm`, `peer_type = "freeipa"`, `result`, `platform`.

## Rationale

The choice to support FreeIPA as an alternative Linux tier (rather than adopting it as the sole Linux tier or building a native IPA-equivalent) is forced by Decision 12 §Rationale. FreeIPA is a separate Linux domain controller with its own CA (Dogtag), DNS (Bind), and HBAC — adopting FreeIPA as the sole Linux tier (Candidate A) means the framework's directory is not the source of truth for Linux identity, which breaks the framework's "one directory, one identity" model. FreeIPA's directory schema (`ipa*` object classes, `ipaConfigString` attribute, `cn=etc,<suffix>` configuration container) is incompatible with the framework's directory schema (per Day 1 schema decision). FreeIPA's release cadence is controlled by the FreeIPA project (Red Hat), not by the framework. Building a native IPA-equivalent (Candidate B, ORQ-203) requires ~2-3 years of engineering effort to re-implement HBAC, sudo rules, ID views, and `certmonger` — unacceptable for the framework's v1 timeline. Supporting FreeIPA as an alternative tier (Candidate C, chosen) preserves FreeIPA customers' investment while giving them access to the framework's directory, KDC, policy engine, and cert service.

The choice to preserve the native FreeIPA client experience on FreeIPA-managed hosts (rather than replacing `ipa-client-install` with `adrian-cli join` on FreeIPA-managed hosts) is forced by the framework's "do not break platform-native" posture (per Decision 11 §Trade-offs accepted). FreeIPA-managed Linux hosts have FreeIPA-specific tooling (`ipa user-add`, `ipa group-add`, `ipa hbacrule-add`) that does not work against the framework's directory; requiring FreeIPA customers to abandon this tooling is a non-starter for adoption. The framework's `adrian-cli join` is the join path for framework-managed hosts; FreeIPA-managed hosts continue to use `ipa-client-install`.

The choice to sync the framework's `Security` PolicyArea's `PermitHosts`/`PermitGroups` to FreeIPA's HBAC (rather than requiring FreeIPA customers to manage HBAC separately) is forced by the framework's unified-policy commitment (per Decision 7). Customers who deploy FreeIPA alongside the framework want their framework-defined access-control policies to apply to FreeIPA-managed hosts; the `adrian-cli trust sync-hbac` command automates the translation. The sync is one-way (framework → FreeIPA); changes made directly in FreeIPA's HBAC are NOT synced back to the framework's policy (the framework's policy is the source of truth for `Security` PolicyArea).

The choice to use FreeIPA's `idoverride` for user mapping (rather than relying on SSSD's `ipa` provider's default user lookup) is forced by the need to preserve framework-directory UUIDs across the trust boundary. The framework's UUID-primary identity model (per Decision 3) requires that the framework's UUID is preserved when a framework-directory user is resolved on a FreeIPA-managed host. FreeIPA's `idoverride` allows per-host or per-user overrides of POSIX attributes (`uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, `gecos`); the framework's `adrian-cli trust establish --peer freeipa` command creates `idoverride` entries that map FreeIPA users to framework-directory UUIDs (via the `ipaAnchorUUID` attribute).

The choice to implement the `ipa-extdom-plugin` extended operation (OID `2.16.840.1.113730.3.8.10.4`) in the framework's directory is forced by the need for FreeIPA-managed Linux hosts to resolve framework-directory users via SSSD's `ipa` provider. SSSD's `ipa` provider calls the `ipa-extdom-plugin` extended operation to look up AD users (in an AD-trust scenario) by SID, UID, or name; the framework's directory implements the equivalent extended operation, allowing SSSD's `ipa` provider to resolve framework-directory users transparently. The implementation is ~1K lines of Rust in the framework's directory server, handling the `extdomRequest` ASN.1 structure (input type, request choice: name/sid/uid/gid) and returning the `extdomResponse` (user/group info, POSIX attributes, SID).

## Consequences

**Positive**. The framework gains FreeIPA as a supported alternative Linux tier, preserving FreeIPA customers' investment in HBAC, sudo rules, ID views, and `certmonger` while giving them access to the framework's directory, KDC, policy engine, and cert service. The `adrian-cli trust establish --peer freeipa` and `adrian-cli trust sync-hbac` commands automate the cross-realm trust setup and HBAC sync, reducing the operational complexity of running FreeIPA alongside the framework. The framework's UUID-primary identity model is preserved across the trust boundary via FreeIPA's `idoverride`. The framework's `Security` PolicyArea is the unified source of truth for access-control, with HBAC synced to FreeIPA for FreeIPA-managed hosts.

**Negative**. The cross-realm trust between FreeIPA and the framework's directory is operationally complex (trust password rotation per [ADR-062](./ADR-062-trust-password-auto-rotation.md), Kerberos capaths per [ADR-069](./ADR-069-cross-realm-capaths.md), name-suffix routing). The framework's `adrian-cli trust establish --peer freeipa` and `adrian-cli trust sync-hbac` commands automate the setup, but customers must understand the operational implications. The framework's runbook includes a "FreeIPA cross-realm trust operations guide" that explains the trust lifecycle, troubleshooting, and rollback. FreeIPA is Java + Python + C (Dogtag CA is Java; FreeIPA framework is Python; Bind DNS and SSSD are C); customers choosing the FreeIPA alternative tier inherit this stack. The HBAC sync is one-way (framework → FreeIPA); customers who make HBAC changes directly in FreeIPA must manually update the framework's policy to match.

**Neutral**. The framework's FreeIPA alternative tier is invisible to framework-managed hosts (they use SSSD-primary per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md)). The framework's FreeIPA alternative tier is invisible to end users on FreeIPA-managed hosts (they use FreeIPA's native client experience). The framework's FreeIPA alternative tier is visible to operators who manage both FreeIPA and the framework (they run `adrian-cli trust establish --peer freeipa` and `adrian-cli trust sync-hbac`).

**Implementation cost**. ~6 person-weeks. Breakdown: `adrian-cli trust establish --peer freeipa` tool (2 pw, including FreeIPA JSON-RPC API integration), `adrian-cli trust sync-hbac` tool (1 pw), `ipa-extdom-plugin` extended operation implementation in the framework's directory server (1.5 pw), `adrian-trust-rotate` daemon FreeIPA integration (1 pw), audit logging integration (0.5 pw).

**Operational impact**. Operations teams gain automated cross-realm trust setup and HBAC sync via `adrian-cli trust`. Operations teams must understand the operational implications of running FreeIPA alongside the framework (the runbook includes a "FreeIPA cross-realm trust operations guide"). Operations teams gain unified audit logging of trust operations (`sdk_trust_op` event type) across the framework's directory, KDC, and FreeIPA.

## Alternatives Considered

**Alternative 1: FreeIPA as the sole Linux tier.** Adopt FreeIPA as the framework's Linux identity platform; the framework's directory trusts FreeIPA, and Linux hosts join FreeIPA (not the framework). **Rejection rationale**: Per Decision 12 §Rationale §Candidate A rejection, FreeIPA is a separate Linux domain controller with its own CA, DNS, and HBAC — adopting FreeIPA as the sole Linux tier means the framework's directory is not the source of truth for Linux identity, which breaks the framework's "one directory, one identity" model. FreeIPA's directory schema is incompatible with the framework's directory schema; FreeIPA's release cadence is controlled by the FreeIPA project (Red Hat), not by the framework. FreeIPA does not support Windows or macOS at all, so the framework would still need separate Windows and macOS clients — same three-codebase problem.

**Alternative 2: Build native IPA-equivalent in the framework.** Re-implement HBAC, sudo rules, ID views, and `certmonger` in the framework's Core Directory + Policy Engine. **Rejection rationale**: Per Decision 12 §ORQ-203 rejection, this requires ~2-3 years of engineering effort to re-implement the full FreeIPA feature set. The framework's v1 timeline cannot accommodate this effort. The framework's `Security` PolicyArea's `PermitHosts`/`PermitGroups` settings provide HBAC-equivalent functionality for framework-managed hosts (per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md) §2 and [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md)); customers who want the full FreeIPA feature set use FreeIPA as the alternative tier.

**Alternative 3: Direct AD-join for all Linux hosts (no FreeIPA in the picture).** Linux hosts join the framework's directory directly via SSSD (per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md)); FreeIPA is out of scope. **Rejection rationale**: Per Decision 12 §ORQ-202 resolution, FreeIPA is supported as an alternative for customers who want a full Linux domain controller. Customers with existing FreeIPA deployments cannot abandon FreeIPA without losing HBAC, sudo rules, ID views, and `certmonger`; the framework's SSSD-primary path does not provide these features natively (per Alternative 2 rejection). Documenting FreeIPA as out of scope would force FreeIPA customers to choose between abandoning FreeIPA (losing features) or not adopting the framework (losing the framework's modern directory, KDC, policy engine, and cert service).

## Open Questions

None. The decision is fully specified by Decision 12 §3, §6, and §7. The implementation details (FreeIPA JSON-RPC API integration, `ipa-extdom-plugin` extended operation implementation) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): The framework's directory implements the `ipa-extdom-plugin` extended operation (OID `2.16.840.1.113730.3.8.10.4`) for FreeIPA SSSD `ipa` provider compatibility. The directory's trust object (per [docs/03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md)) stores the FreeIPA cross-realm trust.
- **KDC** ([PC-023](../catalog/02-kdc.md)): The framework's KDC issues cross-realm TGTs for the FreeIPA realm (per [ADR-013](./ADR-013-cross-realm-tgt-referral.md)) and supports `[capaths]` per [ADR-069](./ADR-069-cross-realm-capaths.md).
- **Auth Provider** ([PC-029](../catalog/03-auth-provider.md)): FreeIPA-managed Linux hosts authenticate via SSSD's `ipa` provider (which delegates to FreeIPA's KDC, not the framework's KDC); framework-managed Windows/macOS hosts authenticate via the framework's KDC. Cross-realm TGTs allow FreeIPA users to authenticate to framework services and vice versa.
- **Policy Engine** (Decision 7): The `adrian-cli trust sync-hbac` command syncs the framework's `Security` PolicyArea's `PermitHosts`/`PermitGroups` to FreeIPA's HBAC rules.
- **Cert Service** (Decision 8): FreeIPA-managed hosts use FreeIPA's `certmonger` (against FreeIPA's Dogtag CA); framework-managed hosts use the framework's `adrian-cert-agent` (against the framework's CA per Decision 8). The two CA hierarchies are independent; cross-recognition is via the framework's trust manager (per [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md)).
- **Federation Gateway** (Decision 9): FreeIPA-managed hosts access the framework's OIDC/SAML endpoints via standard OIDC/SAML clients (not via the framework's SDK `FederationModule`).
- **Operations** ([ADR-062](./ADR-062-trust-password-auto-rotation.md)): Trust password auto-rotation covers the FreeIPA cross-realm trust.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): Customers migrating from FreeIPA-only to framework+FreeIPA run `adrian-cli trust establish --peer freeipa` to establish the cross-realm trust; existing FreeIPA-managed hosts continue to use FreeIPA's client tooling.

## References

- [PC-100](../catalog/09-cross-platform-parity.md) — problem statement (macOS OpenDirectory AD plug-in gaps; FreeIPA as separate platform covered in catalog PC-101)
- [PC-101](../catalog/09-cross-platform-parity.md) — FreeIPA as separate Linux identity platform with AD cross-forest trust
- [Workshop Decision 12 — Linux Tier](../workshop/decision-12-linux-tier.md) — SSSD primary + FreeIPA alt
- [docs/09-linux-equivalents/08-freeipa-trust.md](../docs/09-linux-equivalents/08-freeipa-trust.md) — FreeIPA architecture, `ipa trust-add` creation flow, `ipa-extdom-plugin` extended operation (OID `2.16.840.1.113730.3.8.10.4`), HBAC vs URA mapping, ID views
- [docs/03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md) — Trusts topology, `trustedDomain` object class, `TRUST_ATTRIBUTE_FOREST_TRANSITIVE`
- [ADR-013](./ADR-013-cross-realm-tgt-referral.md) — cross-realm TGT referral
- [ADR-036](./ADR-036-trust-manager-cross-cert-interop.md) — trust manager (cross-recognition of FreeIPA's Dogtag CA)
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-061](./ADR-061-rest-grpc-api.md) — REST/gRPC API (FreeIPA-managed hosts access framework services via REST)
- [ADR-062](./ADR-062-trust-password-auto-rotation.md) — trust password auto-rotation
- [ADR-069](./ADR-069-cross-realm-capaths.md) — cross-realm capaths
- [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md) — GPO Preferences and cross-platform policy compilation (HBAC-equivalent for framework-managed hosts)
- [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md) — Linux identity stack (SSSD primary, FreeIPA alt)
- [FreeIPA Documentation](https://www.freeipa.org/page/Documentation) — FreeIPA project documentation
- [ipa-extdom-plugin OID](https://www.freeipa.org/page/V4/AD_TRUST) — `ipa-extdom-plugin` extended operation specification
- [reqwest Rust crate](https://docs.rs/reqwest) — HTTP client (FreeIPA JSON-RPC API)
