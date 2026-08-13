---
title: "ADR-088: Unified Token Abstraction via adrian-sdk AuthModule (Windows LSA / Linux PAM / macOS OpenDirectory)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Auth Provider
problem: PC-040
severity: high
unblocked_by: Workshop Decision 11 (ORQ-169/170/175/176)
tags: [adr, auth-provider, token, lsa, pam, opendirectory, sspi, gss-api, sdk, cross-platform, authmodule]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/03-auth-provider.md
  - ../catalog/08-client-sdk.md
  - ../docs/10-comparison-matrices/04-auth-flow-comparison.md
  - ../docs/09-linux-equivalents/10-pam-nss-stack.md
  - ../docs/09-linux-equivalents/09-sssd-internals.md
  - ../workshop/decision-11-client-sdk.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-050-authselect-standard-pam.md
  - ./ADR-056-psso-modern-macos-kerberos-path.md
  - ./ADR-061-rest-grpc-api.md
  - ./ADR-085-ntlm-client-only-rust-crate.md
last_updated: 2026-08-14
---

# ADR-088: Unified Token Abstraction via adrian-sdk AuthModule (Windows LSA / Linux PAM / macOS OpenDirectory)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 11](../workshop/decision-11-client-sdk.md) which resolved Tier-1 ORQ-169 (gRPC-based SDK), ORQ-170 (per-language bindings with Rust core), ORQ-175 (extend SSSD or new client), and ORQ-176 (adopt FreeIPA client as base) in favor of a unified Rust core library `adrian-sdk` with platform-specific bindings (C ABI, JNI, Swift, Python, Go). This ADR specifies the framework's unified token abstraction — the `AuthModule` of `adrian-sdk` — that hides the architectural differences between Windows LSA token construction, Linux PAM/NSS stack, and macOS OpenDirectory Authorization Framework. The abstraction is the "third option" listed as an open question in [PC-040](../catalog/03-auth-provider.md): define a higher-level abstraction and translate to platform-native at the edges.

## Context

Windows builds a token (user SID + group SIDs + privileges) in LSASS via `LsaLogonUser`. The token is a kernel object — an opaque handle passed to processes via `CreateProcessAsUser`. The token contains: user SID, group SIDs (from `tokenGroups` — recursive group expansion), restricted SIDs, privileges (from `msDS-Privilege` and local SAM LSA policy), default DACL, primary group, logon SID, logon type. The token is immutable for the process's lifetime; group membership changes require a new logon per [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) and [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md).

Linux uses PAM (Pluggable Authentication Modules) — a stack of modules invoked in four phases: `auth` (authenticate), `account` (account validity), `password` (password change), `session` (session setup/teardown). PAM has no token concept; the kernel knows only UID/GID. Group memberships are resolved via NSS (Name Service Switch) — `getent group <group>` returns the member list; `id <user>` returns the user's groups. There is no equivalent of Windows's immutable kernel token — group membership changes take effect on the next NSS lookup.

macOS uses PAM (BSD-derived) + OpenDirectory. The PAM stack is similar to Linux; OpenDirectory provides the directory service. The kernel knows UID/GID (BSD-style); group memberships are resolved via `getgrgid` / `getgrnam` (BSD libc). The Authorization Framework (`AuthorizationCreate`, `AuthorizationCopyRights`) provides privileged-operation authorization (sudo-equivalent).

The fundamental difference: Windows has an immutable kernel-resident token; Linux/macOS have mutable userspace-resolved UID/GID + supplementary groups. A framework that wants to expose "who is the user, what groups are they in, what can they do" to applications needs an abstraction that produces equivalent results on all three platforms. The framework cannot implement a Windows-style token on Linux/macOS without a kernel module (invasive); cannot implement a Linux-style PAM/NSS layer on Windows (Windows has no PAM/NSS); so the abstraction must be higher-level.

Constraints from [PC-040](../catalog/03-auth-provider.md):

- Must support Kerberos + NTLM + cert auth.
- Must expose token/group info to apps ("who is the user?" and "what groups are they in?").
- Must support credential delegation (the app needs to delegate the user's identity to a backend service).
- Must support audit log emission (security events).

## Decision

The framework's unified token abstraction lives in the `AuthModule` of the `adrian-sdk` Rust core library (per [Decision 11](../workshop/decision-11-client-sdk.md)). The abstraction exposes a `Principal` type that captures the user's identity, group memberships, privileges, and credential-handle, translated to/from platform-native at the edges.

### Principal type

```rust
pub struct Principal {
    pub sid: Sid,                       // Framework canonical SID (per Decision 3)
    pub upn: String,                    // User Principal Name
    pub display_name: String,
    pub group_sids: Vec<Sid>,           // Recursive group expansion (tokenGroups equivalent)
    pub primary_group_sid: Sid,
    pub privileges: Vec<Privilege>,     // Privilege names (e.g. "SeBackupPrivilege")
    pub logon_type: LogonType,          // Interactive, Network, Batch, Service
    pub logon_time: SystemTime,
    pub logon_server: String,           // KDC instance that issued the TGT
    pub credential_handle: CredentialHandle,  // Opaque handle to Kerberos TGT / NT hash / cert
    pub delegation_allowed: bool,       // From UAC TRUSTED_FOR_DELEGATION
}

pub enum CredentialHandle {
    KerberosTgt(TgtCache),              // Points to the host's KCM/ccache
    NtlmHash(NtlmHashHandle),           // Platform-secure-store-backed (per ADR-085)
    Certificate(CertHandle),            // Platform cert store (per Decision 11 §11)
    OAuth2Token(OAuth2TokenHandle),     // Federation Gateway-issued (per ADR-039)
}
```

### Platform adapters

The `AuthModule` constructs `Principal` instances via platform-specific adapters:

- **Windows adapter** (`crates/adrian-sdk/src/auth/windows.rs`): wraps `LsaLogonUser` (per [Decision 11](../workshop/decision-11-client-sdk.md) §7), `GetTokenInformation`, `AllocateLocallyUniqueId`. The Windows LSA Authentication Package (`adrianlsa.dll` per [Decision 11](../workshop/decision-11-client-sdk.md) §7) calls `LsaLogonUser` with the framework's Kerberos TGT as the auth buffer; LSA constructs the kernel token; the SDK reads the token via `OpenThreadToken` + `GetTokenInformation` and constructs a `Principal`. Group memberships come from the token's `TokenGroups` (populated by LSA from `tokenGroups` in the directory at logon time). Privileges come from `TokenPrivileges` (populated by LSA from `msDS-Privilege`).

- **Linux adapter** (`crates/adrian-sdk/src/auth/linux.rs`): wraps `pam_authenticate` (via the framework's `pam_adrian.so` per [ADR-050](./ADR-050-authselect-standard-pam.md)), `getpwnam` / `getpwuid` (NSS via the framework's `nss_adrian.so.2` per [Decision 11](../workshop/decision-11-client-sdk.md) §8), `getgrnam` / `getgrgid` (NSS), `getgroups` (kernel supplementary groups). The `pam_adrian.so` module calls the Rust core's `AuthModule::authenticate(creds)` which validates via Kerberos (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) or NTLM (per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)); on success, the module sets the UID/GID via `setuid`/`setgid` (the calling process is the PAM consumer, e.g. `login`, `sshd`). The `Principal` is constructed from `getpwuid(getuid())` + `getgroups()` + `getgrouplist(user, ...)`. Group memberships are resolved at each call (no immutable token); the `Principal` captures the resolution at construction time and the consumer treats it as immutable for its scope.

- **macOS adapter** (`crates/adrian-sdk/src/auth/macos.rs`): wraps OpenDirectory (`ODNodeCopyRecord`, `ODRecordCopyDetails`), PAM (BSD-derived, via `pam_adrian.so`), `getpwnam` / `getgrnam` (BSD libc), `getgroups` (BSD kernel supplementary groups), and the Authorization Framework (`AuthorizationCreate` for privileged operations). The framework's OpenDirectory plugin (`adrian-opendirectory.bundle` per [Decision 11](../workshop/decision-11-client-sdk.md) §7) handles the OpenDirectory side; the SDK reads the resolved identity via `getpwuid(getuid())` + `getgroups()`.

### Concrete specification

- The framework's `adrian-sdk` Rust core SHALL expose a `Principal` type with the fields specified above. The `Principal` is immutable for its lifetime in the consumer's scope.
- The `AuthModule::authenticate(credentials) -> Principal` method SHALL construct a `Principal` via the platform adapter.
- The `AuthModule::whoami() -> Principal` method SHALL construct a `Principal` from the current process's identity (no authentication; reads the existing token/UID).
- The `AuthModule::delegate(principal, target_service) -> DelegatedCredential` method SHALL perform credential delegation: on Windows, returns a `WINNT_AUTHENTICATON_DATA` via `LsaGetLogonSessionData`; on Linux/macOS, returns a delegated GSS credential via `gss_init_delegated_cred` (per [Decision 11](../workshop/decision-11-client-sdk.md) §7 Linux integration).
- The `Principal::has_privilege(name) -> bool` method SHALL check privileges: on Windows, via `PrivilegeCheck` against the token's `TokenPrivileges`; on Linux/macOS, via the framework's `sudoers`-equivalent (per [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md)) lookup against `msDS-Privilege` on the principal's directory object.
- The framework's `AuthModule` SHALL emit audit events per [ADR-023](./ADR-023-kerberos-audit-events.md): `auth.success` (principal SID, logon type, source IP, audit ID), `auth.failed` (principal SID, source IP, reason), `delegation.success/failed`, `privilege_check.elevated` (when a privilege is granted).
- The C ABI binding (`adrian-sdk-c`) SHALL expose `Principal` as an opaque `AdrianPrincipal*` handle with accessor functions (`adrian_principal_get_sid`, `adrian_principal_get_upn`, `adrian_principal_get_group_sids`, etc.). The C ABI is the foundation for JNI, Swift, Python, and Go bindings per [Decision 11](../workshop/decision-11-client-sdk.md).
- The framework's `pam_adrian.so` PAM module (Linux/macOS) SHALL call the Rust core's `AuthModule::authenticate()` in `pam_sm_authenticate`; `AuthModule::whoami()` in `pam_sm_acct_mgmt` (account validity); `AuthModule::change_password()` in `pam_sm_chauthtok` (per [ADR-007](./ADR-007-password-change-protocol.md)).
- The framework's `adrianlsa.dll` LSA Authentication Package (Windows) SHALL call the Rust core's `AuthModule::authenticate()` in `LsaApLogonUser`, returning the `LSA_TOKEN_INFORMATION` struct that LSA uses to construct the kernel token.
- The framework's `adrian-opendirectory.bundle` OpenDirectory plugin (macOS) SHALL delegate authentication to the Rust core's `AuthModule::authenticate()` via the C ABI.

### Rust crates used

- `adrian-sdk` (framework crate, per [Decision 11](../workshop/decision-11-client-sdk.md)) — the Rust core's `AuthModule`; platform adapters in `src/auth/{windows,linux,macos}.rs`.
- `windows` (v0.54+) for Win32 LSA / SSPI / Token APIs (`LsaConnectUntrusted`, `LsaLogonUser`, `GetTokenInformation`, `AllocateLocallyUniqueId`, `InitializeSecurityContext`, `AcceptSecurityContext`).
- `gss-api` (v0.1+) for Linux GSSAPI binding (`gss_init_sec_context`, `gss_accept_sec_context`, `gss_init_delegated_cred`) via `libgssapi_krb5`.
- `pam-bindings` (v0.1+) for the `pam_adrian.so` PAM module (`pam_sm_authenticate` etc.).
- `libc` (v0.2+) for `getpwnam`/`getpwuid`/`getgrnam`/`getgrgid`/`getgroups`/`setuid`/`setgid` POSIX calls.
- `core-foundation` (v0.10+) and `objc2` (v0.5+) for macOS OpenDirectory / Authorization Framework integration.
- `ldap3` (v0.11+) for `tokenGroups` recursive group expansion reads from Core Directory.
- `tokio` (v1.40+) for async I/O inside the Rust core (the public API exposes both async and blocking methods per [Decision 11](../workshop/decision-11-client-sdk.md) §1).
- `tracing` + `opentelemetry` for audit emission per [ADR-023](./ADR-023-kerberos-audit-events.md).
- `adrian-ntlm-client` (framework crate, per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)) for NTLM fallback authentication.
- `adrian-sid` (framework crate, per Decision 3) for canonical SID representation.

## Rationale

Three arguments drive the higher-level abstraction choice.

**1. The architectural difference is fundamental; the abstraction must be higher-level.** Windows's immutable kernel token and Linux's mutable UID/GID + NSS are structurally different. A Windows-style token on Linux would require a kernel module (invasive, distro-specific); a Linux-style PAM/NSS layer on Windows is impossible (Windows has no PAM/NSS). The higher-level `Principal` type captures the common semantic ("who is the user, what groups, what privileges") and translates to platform-native at the edges. This is Option C from [PC-040](../catalog/03-auth-provider.md)'s open questions.

**2. The Rust core + platform bindings model from [Decision 11](../workshop/decision-11-client-sdk.md) is the right substrate.** [Decision 11](../workshop/decision-11-client-sdk.md) committed to a unified Rust core with platform-specific bindings (C ABI, JNI, Swift, Python, Go). The `AuthModule` is a Rust module within that core; the platform adapters are Rust modules within `adrian-sdk`. This gives the framework: (a) a single source of truth for auth behavior; (b) platform-native integration via FFI where required (LSA, PAM, OpenDirectory, GSS-API); (c) cross-language support via the C ABI foundation. No SSSD reuse (Candidate B from [Decision 11](../workshop/decision-11-client-sdk.md) §Rationale — rejected for SSSD's C coupling and missing framework-policy support). No FreeIPA reuse (Candidate C — rejected for FreeIPA's Python and schema coupling).

**3. The abstraction supports credential delegation uniformly.** Credential delegation (an app forwarding the user's identity to a backend service) is the trickiest cross-platform problem: Windows uses `Delegate` flag in `InitializeSecurityContext`; Linux uses `gss_init_delegated_cred`; macOS uses GSS-API delegation (via `gss_init_sec_context` with `GSS_C_DELEG_FLAG`). The `AuthModule::delegate(principal, target)` method hides these differences and returns a `DelegatedCredential` that the consumer passes to the framework's `FileModule` (SMB), `DirectoryModule` (LDAP), or `FederationModule` (OIDC OBO) — all of which consume the credential via the framework's internal Kerberos/GSS-API layer.

External evidence: [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) documents the Windows/Linux/macOS auth flow differences; [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md) documents the Linux PAM/NSS stack; [docs/09-linux-equivalents/09-sssd-internals.md](../docs/09-linux-equivalents/09-sssd-internals.md) documents SSSD's architecture (which the framework's SDK replaces per [Decision 11](../workshop/decision-11-client-sdk.md)); [Microsoft LSA Authentication documentation](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication) documents LSA token construction; [RFC 2743](https://www.rfc-editor.org/rfc/rfc2743) defines GSS-API (the Linux/macOS Kerberos API).

## Consequences

**Positive**: Framework-managed services (any language consuming `adrian-sdk` via C ABI, JNI, Swift, Python, or Go per [Decision 11](../workshop/decision-11-client-sdk.md)) get a unified `Principal` abstraction — no per-platform auth code. The `Principal` captures identity, groups, privileges, and credential-handle in a single immutable type. Credential delegation is uniform across platforms. Audit emission is uniform (`auth.success/failed`, `delegation.success/failed`). The framework's PAM/NSS modules (`pam_adrian.so`, `nss_adrian.so.2`) and LSA Authentication Package (`adrianlsa.dll`) and OpenDirectory plugin (`adrian-opendirectory.bundle`) all delegate to the same Rust core, eliminating cross-platform drift.

**Negative**: The Rust core's `AuthModule` is the single point of failure for all auth on framework-managed hosts. A bug in `AuthModule::authenticate` could prevent login on all three platforms. Mitigation: the framework's CI runs the `AuthModule` against `authselect`'s test suite (Linux), `opendirectoryd` (macOS), and `lsass.exe` crash detection (Windows) per [Decision 11](../workshop/decision-11-client-sdk.md) §"Implementation impact". The `Principal` is immutable for its lifetime in the consumer's scope, but on Linux/macOS the underlying group memberships can change between `whoami()` calls (NSS resolution); the consumer must call `whoami()` again to refresh. The Windows LSA Authentication Package is the highest-risk item per [Decision 11](../workshop/decision-11-client-sdk.md) — bugs can crash `lsass.exe` and force Windows reboot.

**Neutral**: The abstraction does NOT make Windows apps portable to Linux (Windows apps using SSPI directly do not benefit; they must be rewritten to use the SDK's C ABI). The abstraction makes framework-native apps (apps written against `adrian-sdk`) portable across all three platforms. Existing AD-aware Windows apps that use SSPI continue to work via the Windows LSA — the SDK is opt-in.

**Implementation cost**: 8 person-weeks (included in the 30 person-weeks SDK budget per [Decision 11](../workshop/decision-11-client-sdk.md)). Rust core `AuthModule` + `Principal` type: 2 pw. Windows adapter (LSA + Token APIs): 2 pw (highest-risk per [Decision 11](../workshop/decision-11-client-sdk.md)). Linux adapter (PAM + NSS + GSS-API): 2 pw. macOS adapter (OpenDirectory + Authorization Framework): 1.5 pw. Audit emission + CLI: 0.5 pw. The Windows LSA is on the critical path (LSA bugs block Windows logon).

## Alternatives Considered

### Alternative 1: Implement a Windows-style token on Linux (kernel module)

Inject a kernel module that maintains an immutable token-like object per process; the framework's PAM module writes the token at logon. Rejected: invasive (requires a kernel module per Linux distro kernel version); breaks the BSD-style UID/GID model; Linux kernel upstream would not accept the module. The higher-level `Principal` type achieves the same immutability property in userspace.

### Alternative 2: Implement a Linux-style PAM/NSS layer on Windows

Run a PAM-equivalent on Windows that translates Windows LSA tokens to PAM-style phases. Rejected: Windows has no PAM/NSS; Windows LSA is the platform-native auth stack. The framework's LSA Authentication Package integrates with LSA natively; a PAM-equivalent layer would duplicate LSA's functionality with worse integration.

### Alternative 3: Use OAuth2-style access tokens as the unified abstraction

Issue short-lived OAuth2 access tokens at logon; apps use the access token for all auth (no platform-native token). Rejected: (a) requires online validation against the Federation Gateway for every auth (defeats Kerberos's offline-validation property); (b) breaks AD-interop (AD-aware services expect Kerberos tickets, not OAuth2 tokens); (c) introduces a Federation Gateway dependency at every host (single point of failure). The framework's `Principal` is a local abstraction; the underlying credential (`CredentialHandle`) can be a Kerberos TGT (offline-validatable) or an OAuth2 token (online-validation) depending on the auth mechanism used.

### Alternative 4: Use SSSD as the unified abstraction on Linux; wrap platform-native on Windows/macOS

Extend SSSD to support the framework's `Principal` semantics; use Windows LSA on Windows; use OpenDirectory on macOS. Rejected per [Decision 11](../workshop/decision-11-client-sdk.md) §Rationale (Candidate B): SSSD is C, tightly coupled to its internal architecture, does not extend to the framework's full PolicyArea enum, and the framework cannot ship SDK fixes on the framework's release cadence if SSSD is the substrate. The framework's `pam_adrian.so` + `nss_adrian.so.2` provide a faster, simpler Linux client than SSSD.

## Open Questions

- For the `Principal::has_privilege` method on Linux/macOS: should the framework map Windows privilege names (`SeBackupPrivilege`, `SeDebugPrivilege`) to Linux/macOS equivalents? Yes — the framework SHALL maintain a privilege-name mapping table (e.g. `SeBackupPrivilege` → Linux `CAP_DAC_READ_SEARCH`); the mapping is best-effort and the framework SHALL document the semantic differences (Linux capabilities are kernel-enforced; Windows privileges are LSA-enforced).
- For the `Principal::group_sids` field on Linux: should the framework include the supplementary GIDs from `getgroups()` (which may include local groups not in the directory) or only the directory-resolved groups? Decision: include both — `group_sids` contains the union of directory-resolved groups (`getgrouplist`) and local supplementary groups (`getgroups`); the consumer can filter as needed.
- For credential delegation on macOS: the macOS GSS-API implementation (via `Kerberos.framework`) supports delegation but with quirks (delegated credentials are stored in a separate ccache). The framework's macOS adapter SHALL handle this transparently by wrapping the delegated ccache in a `KerberosTgt` variant of `CredentialHandle`.
- Cross-reference [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md) — the `NtlmHashHandle` variant of `CredentialHandle` references the NTLM client crate.
- Cross-reference [Decision 11](../workshop/decision-11-client-sdk.md) — this ADR is the auth-stack specification for the SDK architecture Decision 11 commits to.

## Cross-capability impact

- **KDC** ([Decision 5](../workshop/decision-05-kdc-implementation.md)): the `AuthModule::authenticate` method acquires Kerberos TGTs via MIT krb5 (per [ADR-049](./ADR-049-standardize-mit-krb5.md)); the KDC's PAC (per [ADR-082](./ADR-082-ms-kile-pac-generation.md)) is the source of `group_sids` and `primary_group_sid`.
- **Auth Provider** ([ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)): the NTLM client is one of the `CredentialHandle` variants; the AuthModule's NTLM fallback path uses it.
- **Core Directory**: `tokenGroups` recursive group expansion (per [ADR-009](./ADR-009-constructed-attributes.md)) is the source of `group_sids` for the `Principal`.
- **Policy Engine** ([Decision 7](../workshop/decision-07-policy-engine.md)): the SDK's `PolicyModule` reads the `Principal` to evaluate CEL selectors (per ADR-026); the `Principal`'s `group_sids` and `privileges` are the policy-evaluation inputs.
- **Cert Service** ([Decision 8](../workshop/decision-08-cert-service.md)): the SDK's `CertModule` uses the `Principal` to determine which cert profiles the host is authorized for; the `CertificateHandle` variant of `CredentialHandle` references the platform cert store.
- **Federation Gateway** ([ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md)): the `OAuth2TokenHandle` variant of `CredentialHandle` references the Federation Gateway-issued token; the SDK's `FederationModule` validates and refreshes it.
- **File Gateway** ([Decision 7](../workshop/decision-07-smb-implementation.md)): the SDK's `FileModule` uses the `Principal`'s `credential_handle` to acquire a Kerberos service ticket for the SMB server.
- **Operations** ([ADR-058](./ADR-058-container-native-dcs-operator.md)): the SDK's container image (per ADR-058) ships with the `AuthModule` for use in sidecar containers.
- **Security** ([ADR-023](./ADR-023-kerberos-audit-events.md)): `auth.success/failed`, `delegation.success/failed`, `privilege_check.elevated` events feed auth-monitoring SIEM queries.
- **Migration** ([ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md)): the framework's `sudoers`-equivalent maps Windows privileges to Linux capabilities; the `Principal::has_privilege` method is the unified check.

## References

- [PC-040](../catalog/03-auth-provider.md) — problem statement in the catalog
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — unblocking decision; unified Rust core + platform bindings architecture
- [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) — Windows LSASS token vs Linux PAM/NSS vs macOS OpenDirectory comparison
- [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md) — PAM stack phases, NSS configuration, SSSD integration
- [docs/09-linux-equivalents/09-sssd-internals.md](../docs/09-linux-equivalents/09-sssd-internals.md) — SSSD architecture (rejected in favor of framework's PAM/NSS modules per Decision 11)
- [catalog/08-client-sdk.md](../catalog/08-client-sdk.md) — Client SDK problem statements (PC-085/086/091)
- [ADR-007](./ADR-007-password-change-protocol.md) — `pam_sm_chauthtok` integration
- [ADR-009](./ADR-009-constructed-attributes.md) — `tokenGroups` recursive group expansion
- [ADR-023](./ADR-023-kerberos-audit-events.md) — `auth.success/failed`, `delegation.success/failed` audit events
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization (the Kerberos implementation the AuthModule uses)
- [ADR-050](./ADR-050-authselect-standard-pam.md) — authselect standard PAM
- [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md) — privilege mapping (Windows → Linux)
- [ADR-058](./ADR-058-container-native-dcs-operator.md) — container-native SDK deployment
- [ADR-061](./ADR-061-rest-grpc-api.md) — REST/gRPC API (for remote admin, contrasted with in-process SDK)
- [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md) — NTLM client crate (one of the `CredentialHandle` variants)
- [RFC 2743](https://www.rfc-editor.org/rfc/rfc2743) — GSS-API (Linux/macOS Kerberos API)
- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) — Kerberos V5
- [Microsoft LSA Authentication](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)
- [Apple Authorization Framework](https://developer.apple.com/documentation/security/authorization) — macOS privileged-operation API
- [Linux-PAM Application Developers' Guide](http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_APPL.html)
