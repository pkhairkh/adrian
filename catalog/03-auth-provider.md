---
title: Auth Provider (NTLM, SASL, SSPI-equivalent) — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, auth-provider, ntlm, sasl, sspi, framework-design, gap-analysis]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./01-core-directory.md
  - ./02-kdc.md
  - ./04-policy-engine.md
  - ./13-open-research-questions.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Auth Provider (NTLM, SASL, SSPI-equivalent) — Problem Catalog

**Capability definition**: Provides authentication mechanisms other than Kerberos. NTLM (if maintained), SASL, certificate-based auth, smart-card logon, OAuth2/OIDC bearer tokens (for HTTP), TLS channel binding. Inherits from AD's `msv1_0.dll` (NTLM), `kerberos.dll` (Kerberos SSPI provider), `schannel.dll` (TLS), `pku2u.dll` (peer-to-peer), `wdigest.dll` (deprecated). Depends on KDC (for Kerberos), Core Directory (for account lookup), Cert Service (for smart-card trust). Consumed by File Gateway (SMB auth), Federation Gateway (for non-Kerberos auth), and Client SDK (auth API).

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-036 | NTLM must be supported for legacy interop; deprecation is operationally difficult | high | Windows, Linux, cross-platform |
| PC-037 | NTLM relay attacks require LDAP signing + channel binding + EPA enforcement | blocker | cross-platform |
| PC-038 | Pass-the-hash (PtH) defense requires LSASS protection / Credential Guard | blocker | Windows, cross-platform |
| PC-039 | S4U2Self + S4U2Proxy constrained delegation semantics are complex | high | cross-platform |
| PC-040 | Windows Token construction (LSASS-side) vs Linux PAM stack are architecturally different | high | Windows, macOS, Linux |
| PC-041 | Time sync (W32Time + MS-SNTP) is fragile; 5-minute Kerberos skew window breaks auth | high | Windows, macOS, Linux |
| PC-042 | Kerberos audit events (4768/4769/4771) need framework equivalent | high | cross-platform |

---

## Detailed problem entries

### PC-036 — NTLM must be supported for legacy interop; deprecation is operationally difficult

**Capability**: Auth Provider
**Severity**: high
**Cross-platform**: Windows / Linux / cross-platform

**Problem statement**:

NTLM (MS-NLMP) is deprecated but widely deployed. Apps that hard-require NTLM (legacy SQL drivers, old IIS-integrated apps, third-party appliances, embedded devices, network printers) fail when NTLM is blocked. The protocol's wire format is the three-message NTLMSSP handshake: Type 1 NEGOTIATE (client → server, carries NegotiateFlags), Type 2 CHALLENGE (server → client, carries 8-byte `ServerChallenge` + `TargetInfo` AV_PAIRs), Type 3 AUTHENTICATE (client → server, carries NTLMv2 response computed via `HMAC-MD5(NTOWFv2, ServerChallenge + ClientBlob)` where `NTOWFv2 = HMAC-MD5(NT-hash, UPPER(user) + Domain)` per [02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md).

Microsoft's "Restrict NTLM" GPOs allow audit→enforce migration: audit mode logs events 8001–8004 (NTLM client/server activity) without blocking; enforce mode blocks NTLM by category (Outbound, Inbound, Audit). Most shops stay in audit mode indefinitely because the audit logs are noisy (every NTLM auth generates an event) and identifying which apps to fix is a multi-month investigation. The GPOs are at `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`: "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers", "Network security: Restrict NTLM: Incoming NTLM traffic", "Network security: Restrict NTLM: Audit ...".

A framework should (a) support NTLM as opt-in for compat (NTLMv2 only, NTLMv1 disabled by default per `LmCompatibilityLevel = 5`), (b) default to Kerberos-only (the SPNEGO negotiation picks Kerberos when both are available), (c) provide migration tooling (audit-log parser that identifies NTLM-using apps and suggests fixes) per [10-comparison-matrices/01-feature-os-matrix.md](../docs/10-comparison-matrices/01-feature-os-matrix.md).

The migration challenge: many apps hard-code NTLM via SSPI's `Negotiate` package and fall back to NTLM when Kerberos fails (no SPN, no TGT, etc.). The fallback is silent — the app reports "auth succeeded" without indicating which protocol was used. Fixing requires identifying the root cause (missing SPN, DNS mismatch, etc.) and either configuring Kerberos or replacing the app.

**Impact**:

Legacy app compat blocks NTLM removal in most enterprises. Government / defense deployments (FISMA, NIST 800-63) require NTLM deprecation but enforcement is years behind schedule. Pass-the-hash (PC-038) and NTLM relay (PC-037) remain the dominant lateral-movement techniques precisely because NTLM cannot be removed.

**Constraints**:

- Must support NTLMv2 (NTLMv1 disabled by default; `LmCompatibilityLevel >= 3`).
- Must support channel binding (RFC 5929) for relay defense (see PC-037).
- Must support SPNEGO negotiation (Kerberos preferred, NTLM fallback).
- For AD interop, must implement the full MS-NLMP wire format (Type 1/2/3, MIC, channel binding, `MsvAvChannelBindings` AV_PAIR).

**Cross-platform considerations**:

- **Windows**: `msv1_0.dll` native; SSPI's `Negotiate` package wraps Kerberos + NTLM. `secedit /configure` for `LmCompatibilityLevel` policy.
- **macOS**: No native NTLM. Samba's `winbind` provides NTLMSSP; built-in `smbx.kext` for SMB connections to legacy servers.
- **Linux**: Samba's `winbind` and `ntlm_auth` helper implement NTLMSSP. SSSD's `ad` provider uses NTLM as fallback when Kerberos fails. `pysmbc`, `impacket-smbclient`, `smbclient` all implement the NTLMSSP client for SMB.
- **Cross-platform consistency**: Wire format is MS-NLMP — platform-independent. The auth-API wrapping (SSPI on Windows, GSS-API on Linux/macOS) differs.

**KB references**:

- [`02-protocols/04-ntlm-internals.md`](../docs/02-protocols/04-ntlm-internals.md) — Full NTLMSSP message structures, NTLMv2 response computation, NTOWFv2, session key derivation, MIC, channel binding.
- [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) — Cross-platform NTLM support matrix, Samba / SSSD / OpenDirectory coverage.

**Open questions**:

- Provide NTLM-emulation via Kerberos with downgrade-friendly client SDK? The SDK issues a Kerberos ticket but presents it as an NTLM token to legacy apps — eliminating NTLM on the wire while preserving app compat.
- Hard cut-off date for NTLM (e.g. framework v3.0 removes NTLM)?
- Migration tool: audit-log parser that identifies NTLM-using apps and suggests fixes (missing SPN, DNS mismatch, etc.)?

**Cross-capability impact**:

- Affects: PC-037 (NTLM relay) — relay defense requires NTLM to implement signing + channel binding.
- Affects: PC-038 (pass-the-hash) — PtH defense requires LSASS protection; without NTLM, no PtH.
- Affects: File Gateway (PC-085, not in this catalog) — SMB auth uses NTLM as fallback.
- Affected by: KDC PC-023 (Kerberos) — when Kerberos fails, NTLM is the fallback.

---

### PC-037 — NTLM relay attacks require LDAP signing + channel binding + EPA enforcement

**Capability**: Auth Provider
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

NTLM relay places an attacker in the middle: the attacker opens a connection to a target service, then诱使 a victim to authenticate to the attacker (e.g. via malicious SMB share, HTTP page, or coerce-auth via PetitPotam / ShadowCoerce / PrinterBug). The attacker forwards the victim's Type 1 / 2 / 3 messages verbatim to the target service. The target service validates against the victim's NT hash (which the attacker doesn't need). End result: the attacker is authenticated to the target as the victim per [02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md).

Mitigations: (a) SMB signing required — relayed SMB traffic fails signature check because the attacker cannot recompute signatures without the session key (the attacker never has the session key — it's derived from the victim's NT hash via `HMAC-MD5(SessionBaseKey, ServerChallenge ++ ClientChallenge)`); (b) LDAP signing + channel binding (EPA) — same mechanism for LDAP; (c) `Restrict NTLM` GPOs (audit→enforce); (d) Extended Protection for Authentication (EPA) — channel binding for HTTP / LDAPS / RPC. The famous AD CS LDAP endpoint relay (PetitPotam) used NTLM relay to coerce DCs to authenticate to the attacker's NTLM relay, then to the AD CS HTTP endpoint, then request a DC certificate — leading to full forest compromise via AD CS.

Channel binding works as follows: when NTLM is layered under TLS (e.g. LDAPS, HTTPS, SMB 3.1.1), the client computes `MsvAvChannelBindings` (AV_PAIR ID 0x000B) as `SHA-256(channel_bindings)` where `channel_bindings` is the `initiator_address_type || initiator_address || acceptor_address_type || acceptor_address || application_data`. For TLS, this is the `tls-server-end-point` channel binding type (RFC 5929): `SHA-256(server_cert_signature_algorithm_oid || server_cert_signature)`. The server includes `MsvAvChannelBindings` in its Type 2 TargetInfo (with the expected hash precomputed from its TLS cert), and the client includes the same in its Type 3. If the hashes differ (MITM with their own cert), the server rejects per [02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md).

A framework should default to LDAP signing required + channel binding required and document the EPA posture. The defaults should be security-first; legacy apps that don't support channel binding must either be upgraded or run in an isolated legacy zone.

**Impact**:

NTLM relay is a common lateral-movement vector. Mandiant M-Trends 2023 reports NTLM relay is used in ~40% of AD compromises that involve lateral movement. The PetitPotam attack (2021) used NTLM relay to coerce DCs to authenticate to AD CS, then request DC certificates — leading to full forest compromise in <30 minutes from initial access. Without LDAP signing + channel binding required by default, the framework's DCs are vulnerable to the same attack.

**Constraints**:

- Must support `MsvAvChannelBindings` (SHA-256 of TLS channel bindings) in NTLMSSP Type 2 / Type 3.
- Must support `EPHEMERAL` flag (`AvFlags & 0x04`) for non-delegatable sessions.
- Must support LDAP signing required (server-side enforcement; `LDAPClientIntegrity = 2` registry).
- Must support SMB signing required (server-side enforcement; `srvsigning = mandatory`).
- For AD interop, must implement RFC 5929 channel binding for NTLM-over-TLS.

**Cross-platform considerations**:

- **Windows**: `msv1_0.dll` channel binding support (Windows 7+); `LDAPSChannelBinding = 1` registry; `LdapEnforceChannelBinding = 2` (Server 2019+).
- **macOS**: Samba's `winbind` supports channel binding; macOS's `smbx.kext` does not (legacy).
- **Linux**: Samba 4 supports channel binding; OpenLDAP supports channel binding via `olcTLSProtocolMin` and `olcTLSCRLCheck` (with the `TLSChannelBinding` overlay). Most Linux LDAP clients (ldap-utils, python-ldap) support channel binding.
- **Cross-platform consistency**: Channel binding must be enforced server-side; clients that don't support it must be rejected.

**KB references**:

- [`02-protocols/04-ntlm-internals.md`](../docs/02-protocols/04-ntlm-internals.md) — Full NTLM relay attack description, MIC mechanism, channel binding computation, `MsvAvChannelBindings` AV_PAIR.

**Open questions**:

- Disable NTLM by default with audit-mode migration? Audit logs identify which apps use NTLM; enforce after migration.
- Mandate EPA across all protocols (LDAP, HTTP, SMB, RPC) — no exceptions for legacy apps?
- Replace NTLM with Kerberos-only via SPNEGO — when Kerberos fails, no fallback to NTLM (force fix the Kerberos config)?

**Cross-capability impact**:

- Affects: PC-036 (NTLM compat) — relay defense requires NTLM to implement signing + channel binding.
- Affects: PC-038 (PtH) — relay and PtH are the two main NTLM attack vectors.
- Affects: Cert Service (PC-060, not in this catalog) — AD CS HTTP endpoint is the famous relay target (PetitPotam).

---

### PC-038 — Pass-the-hash (PtH) defense requires LSASS protection / Credential Guard

**Capability**: Auth Provider
**Severity**: blocker
**Cross-platform**: Windows / cross-platform

**Problem statement**:

The NT hash is the entire secret for NTLM. An attacker with the NT hash (e.g. from a `lsass.exe` memory dump via `mimikatz sekurlsa::pth /user:jdoe /domain:EXAMPLE /ntlm:<hex> /service:cifs /target:dc01`) can construct valid NTLMv2 responses without ever knowing the plaintext password. Tools: `mimikatz`, `impacket/psexec.py -hashes :<nt-hash>`, `evil-winrm -H <nt-hash>`. The hash is reusable until the password changes per [02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md).

Microsoft's defenses: (a) LSA Protected Mode (`RunAsPPL = 1` registry) — LSASS runs as Protected Process Light, which prevents non-admin processes from reading LSASS memory; (b) Credential Guard (virtualization-based LSASS isolation using VSM / Virtual Secure Mode) — NT hashes are stored in `LSAIso.exe` (a separate process in the secure enclave), and `lsass.exe` proxies NTLM operations to LSAIso via VMBus; (c) LAPS (Local Administrator Password Solution) — rotates local admin passwords periodically so dump+PtH lateral movement doesn't span machines; (d) Restricted Admin mode (RDP) — RDP client doesn't send credentials to the target, forcing Kerberos per [00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md).

On Windows, the framework needs LSASS protection; on Linux/macOS the equivalent is SSSD's `krb5_child` setuid isolation (separate process for Kerberos operations, no shared memory with the calling process). The framework's auth provider must never store the NT hash in process memory accessible to administrators — must use a separate protected process or kernel keyring.

**Impact**:

PtH is the dominant lateral-movement technique. Mandiant M-Trends 2023 reports PtH is used in ~80% of AD compromises that involve lateral movement. Without LSASS protection, an attacker with local admin on a single host can extract hashes for every user who has logged into that host, then PtH to any service those users can access — including Domain Admins (if a DA has logged into the host).

**Constraints**:

- Must not store NT hash in process memory accessible to administrators (use Protected Process, kernel keyring, or HSM).
- Must support LAPS-equivalent for local accounts (rotate local admin passwords periodically).
- Must support Restricted Admin mode for RDP-equivalent remote access.
- For AD interop, must support Credential Guard (VSM-based isolation) on Windows DCs.

**Cross-platform considerations**:

- **Windows**: `RunAsPPL = 1` (LSA Protected Mode); Credential Guard (VSM, requires Windows 10 Enterprise+); LAPS (Microsoft's solution, integrated into Windows since 2022); `mimikatz` is the canonical attack tool.
- **macOS**: No native equivalent of LSASS protection. The framework's macOS auth provider must implement isolation (separate process, kernel keyring, or TEE — Apple's Secure Enclave).
- **Linux**: SSSD's `krb5_child` setuid isolation; `pam_krb5` similar. Linux kernel keyring for secret storage. TEE (ARM TrustZone, Intel SGX) for hardware-backed isolation.
- **Cross-platform consistency**: The NT hash isolation model must work on all platforms — Windows VSM, Linux TEE, macOS Secure Enclave.

**KB references**:

- [`02-protocols/04-ntlm-internals.md`](../docs/02-protocols/04-ntlm-internals.md) — PtH attack description, NT hash as the entire secret, `mimikatz sekurlsa::pth`, mitigation mechanisms.
- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — AD security posture, LSA Protected Mode, Credential Guard, LAPS, Restricted Admin.

**Open questions**:

- Drop NTLM entirely (eliminates PtH)? The trade-off is breaking legacy apps (PC-036).
- Use VSM-equivalent on Linux (TEE — ARM TrustZone, Intel SGX)? TEE is not universally available; SGX is deprecated on consumer Intel chips.
- HSM-bound NT hash? The auth provider fetches the hash from an HSM at auth time; the hash never resides in process memory.
- Should the framework store only Kerberos keys (no NT hash) and use Kerberos exclusively? This eliminates PtH but breaks NTLM-dependent apps.

**Cross-capability impact**:

- Affects: PC-036 (NTLM compat) — PtH defense and NTLM compat are in tension.
- Affects: PC-037 (NTLM relay) — relay and PtH are the two main NTLM attack vectors.
- Affects: KDC PC-024 (Kerberoasting) — same NT hash, same Kerberoasting risk.
- Affects: Security (PC-115, not in this catalog) — PtH detection via event 4624 with `LogonProcess = NtLmSsp`.

---

### PC-039 — S4U2Self + S4U2Proxy constrained delegation semantics are complex

**Capability**: Auth Provider
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

S4U2Self (Service-for-User-to-Self, PA-FOR-USER, RFC 4120 extension) lets a service obtain a TGS for itself on behalf of a user — no user password needed. The service specifies the user (by UPN or SID) in the `PA-FOR-USER` padata; the KDC issues a TGT-like ticket for the service with the user's identity in the `cname` field, marked `TRANSITIVE_POLICY` and `FOR_USER`. The service account must have the `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (0x100000) set per [02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) and [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

S4U2Proxy (Service-for-User-to-Proxy) lets the service exchange the S4U2Self ticket for a TGS to a backend service, constrained by `msDS-AllowedToDelegateTo` on the service account. The KDC checks the requested SPN against the `msDS-AllowedToDelegateTo` list; if present, the KDC issues a TGS for the backend service with the user's identity. The backend service sees the user's identity (in the PAC), not the front-end service's identity — enabling delegation without password forwarding.

Resource-based constrained delegation (RBCD, Server 2012+) flips the ACL: instead of the front-end service declaring who it can delegate to (`msDS-AllowedToDelegateTo`), the backend service declares who can delegate to it (`msDS-AllowedToActOnBehalfOfOtherIdentity`, a binary SD). This is more secure — the backend service controls its own trust list. But it's also more complex: the front-end service still does S4U2Self, then S4U2Proxy with a special flag indicating RBCD; the KDC checks the backend's `msDS-AllowedToActOnBehalfOfOtherIdentity` SD.

A framework must implement all three (S4U2Self, S4U2Proxy with `msDS-AllowedToDelegateTo`, RBCD with `msDS-AllowedToActOnBehalfOfOtherIdentity`) or document the delegation limitations. Constrained delegation is widely used for service-to-service auth (IIS → SQL Server, web app → backend API, etc.). Without it, services must use password-based delegation (insecure — the front-end service has the user's password) or unconstrained delegation (very insecure — the front-end service has a TGT for the user, reusable for any service).

**Impact**:

Constrained delegation is widely used for service-to-service auth (IIS → SQL, web app → backend API, SharePoint → Exchange). Without S4U2Self/S4U2Proxy, these scenarios break — services must fall back to password-based delegation (insecure) or unconstrained delegation (very insecure). RBCD is the modern best practice (Server 2012+); without it, admins must use the older `msDS-AllowedToDelegateTo` model, which is harder to manage.

**Constraints**:

- Must support `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (0x100000) on service accounts.
- Must support `msDS-AllowedToDelegateTo` (multi-valued SPN list).
- Must support `msDS-AllowedToActOnBehalfOfOtherIdentity` (binary SD, RBCD).
- Must support PA-FOR-USER padata (S4U2Self) and the S4U2Proxy ticket exchange.
- For AD interop, must implement MS-SFU protocol extensions.

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` implements S4U2Self/S4U2Proxy; `Set-ADUser -TrustedToAuthForDelegation`, `Set-ADUser -PrincipalsAllowedToDelegateToAccount` for management. IIS, SQL Server, Exchange all support constrained delegation.
- **macOS**: No native S4U support. The framework's macOS services would need a custom S4U client.
- **Linux**: MIT krb5 1.10+ supports S4U2Self/S4U2Proxy via `krb5_s4u_pa_data()`; Samba 4 supports S4U for AD interop. Apache mod_auth_gssapi supports S4U2Proxy.
- **Cross-platform consistency**: Wire format must be MS-SFU-compatible for interop.

**KB references**:

- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity` schema attributes, RBCD SD format.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — S4U2Self PA-FOR-USER padata, S4U2Proxy ticket exchange, KDC option `constrained-delegation` (bit 14).

**Open questions**:

- Replace with OAuth2 client-credentials flow? The service obtains an OAuth2 token for the user (via the IdP's token endpoint) and presents it to the backend. The trade-off: OAuth2 is HTTP-only; S4U works for any Kerberos-aware protocol (SMB, LDAP, RPC, HTTP).
- Maintain S4U for AD interop, use OAuth2 for new services? Hybrid model — S4U for legacy, OAuth2 for new.
- RBCD abuse detection: RBCD is vulnerable to `msDS-AllowedToActOnBehalfOfOtherIdentity` tampering (an attacker with write access to the backend service account can add themselves to the SD). How does the framework detect this?

**Cross-capability impact**:

- Affects: KDC PC-023 (MS-KILE) — S4U2Self/S4U2Proxy are MS-KILE extensions.
- Affects: Federation Gateway (PC-070, not in this catalog) — federation services use S4U for OAuth2-on-behalf-of flow.
- Affected by: Core Directory PC-004 (`member`/`memberOf` back-link) — `msDS-AllowedToActOnBehalfOfOtherIdentity` is a linked attribute (linkID-paired).

---

### PC-040 — Windows Token construction (LSASS-side) vs Linux PAM stack are architecturally different

**Capability**: Auth Provider
**Severity**: high
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

Windows builds a token (user SID + group SIDs + privileges) in LSASS via `LsaLogonUser`. The token is a kernel object — an opaque handle passed to processes via `CreateProcessAsUser`. The token contains: user SID, group SIDs (from `tokenGroups` — recursive group expansion), restricted SIDs, privileges (from `msDS-Privilege` and local SAM LSA policy), default DACL, primary group, logon SID, logon type (interactive, network, batch, service). The token is immutable for the process's lifetime; group membership changes require a new logon per [10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) and [09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md).

Linux uses PAM (Pluggable Authentication Modules) — a stack of modules invoked in four phases: `auth` (authenticate), `account` (account validity — expired, locked, etc.), `password` (password change), `session` (session setup / teardown). PAM has no token concept; the kernel knows only UID/GID. Group memberships are resolved via NSS (Name Service Switch) — `getent group <group>` returns the member list; `id <user>` returns the user's groups. There is no equivalent of Windows's immutable kernel token — group membership changes take effect on the next NSS lookup.

macOS uses PAM (BSD-derived) + OpenDirectory. The PAM stack is similar to Linux; OpenDirectory provides the directory service. The kernel knows UID/GID (BSD-style); group memberships are resolved via `getgrgid` / `getgrnam` (BSD libc).

A framework needs a unified auth API that abstracts these differences. On Windows, the framework's Client SDK should wrap SSPI (`InitializeSecurityContext`, `AcceptSecurityContext`, `EncryptMessage`, `DecryptMessage`) and expose a unified API. On Linux, the framework should wrap GSS-API (RFC 2743) + PAM + NSS. On macOS, the framework should wrap the Authorization Framework (`AuthorizationCreate`, `AuthorizationCopyRights`) + PAM + OpenDirectory.

The abstraction must handle: (a) token construction (Windows) vs UID/GID assignment (Linux/macOS); (b) group membership resolution (Windows token vs Linux NSS); (c) privilege evaluation (Windows token privileges vs Linux `sudo` / `polkit`); (d) credential delegation (Windows `Delegate` flag vs Linux `gss_init_delegated_cred`); (e) audit log emission (Windows Event Log 4624 vs Linux `/var/log/auth.log` vs macOS Unified Log).

**Impact**:

Cross-platform client SDK requires per-OS auth abstraction. A unified API that hides these differences is non-trivial — the underlying concepts (kernel token vs UID/GID, immutable token vs NSS lookup) are fundamentally different. The framework's Client SDK must either: (a) implement a Windows-style token on Linux/macOS (kernel module? user-space token cache?); (b) implement a Linux-style PAM/NSS layer on Windows (impossible — Windows doesn't have a PAM/NSS equivalent); (c) define a higher-level abstraction (e.g. OAuth2-style access token + refresh token) and translate to platform-native at the edges.

**Constraints**:

- Must support Kerberos + NTLM + cert auth.
- Must expose token/group info to apps (the app needs to know "who is the user?" and "what groups are they in?").
- Must support credential delegation (the app needs to delegate the user's identity to a backend service).
- Must support audit log emission (security events).

**Cross-platform considerations**:

- **Windows**: LSASS token, kernel object, immutable for process lifetime. `OpenThreadToken`, `GetTokenInformation`, `SetThreadToken` for inspection / modification. SSPI for auth.
- **macOS**: BSD-style UID/GID; PAM + OpenDirectory. `getuid`, `getgid`, `getgroups` for inspection. Authorization Framework for privileged operations.
- **Linux**: BSD-style UID/GID; PAM + NSS. `getuid`, `getgid`, `getgroups` for inspection. `sudo` / `polkit` for privileged operations. GSS-API for auth.
- **Cross-platform consistency**: The unified API must produce equivalent results on all platforms (same user identity, same group memberships, same privilege evaluation).

**KB references**:

- [`10-comparison-matrices/04-auth-flow-comparison.md`](../docs/10-comparison-matrices/04-auth-flow-comparison.md) — Windows LSASS token vs Linux PAM/NSS vs macOS OpenDirectory comparison, auth flow diagrams.
- [`09-linux-equivalents/10-pam-nss-stack.md`](../docs/09-linux-equivalents/10-pam-nss-stack.md) — PAM stack phases, NSS configuration, SSSD integration, `pam_krb5`, `pam_sss`.

**Open questions**:

- Adopt WebAuthn-style token-binding as the unified abstraction? WebAuthn tokens are platform-independent (the same assertion works on Windows, macOS, Linux); the framework translates to platform-native at the edges.
- Per-platform adapters with a unified core? The core handles Kerberos / cert / OAuth2; the adapters handle Windows SSPI / Linux GSS-API / macOS Authorization Framework.
- Should the framework expose a Linux-style PAM/NSS interface on Windows (so Linux apps ported to Windows work)? Or a Windows-style SSPI interface on Linux (so Windows apps ported to Linux work)? Or both?

**Cross-capability impact**:

- Affects: Client SDK (PC-080, not in this catalog) — the Client SDK wraps the unified auth API.
- Affects: Policy Engine (PC-043, not in this catalog) — policy enforcement reads the user's token / group memberships.
- Affected by: KDC PC-023 (MS-KILE) — Kerberos auth depends on the KDC.

---

### PC-041 — Time sync (W32Time + MS-SNTP) is fragile; 5-minute Kerberos skew window breaks auth

**Capability**: Auth Provider
**Severity**: high
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

Kerberos requires clocks within 5 minutes (`clockskew` parameter, RFC 4120 §5.3). PA-ENC-TIMESTAMP pre-auth fails with `KRB_AP_ERR_SKEW (37)` if outside the window. AD uses W32Time + MS-SNTP (Microsoft's authenticated NTP extension) — the Netlogon secure channel key signs NTP responses, so DCs can authenticate time to clients. chrony / ntpd do not support MS-SNTP per [02-protocols/07-ntp-time-sync.md](../docs/02-protocols/07-ntp-time-sync.md).

VM time drift via Hyper-V / VMware integration services is a common cause of skew. When a VM is paused / resumed / live-migrated, its clock jumps; if the jump exceeds 5 minutes, Kerberos auth fails until W32Time catches up (typically 5–15 minutes). Linux VMs without `pti` (Page Table Isolation) mitigation can drift faster; macOS VMs on Apple Silicon drift due to TSC differences.

The MS-SNTP authentication extension uses the Netlogon secure channel key to sign NTP packets: the Key ID field in the NTP packet (offset 48) is set to the security context ID; the MAC (offset 52+) is an MD5 HMAC of the NTP packet keyed with the session key derived from the Netlogon secure channel. The client validates the MAC to ensure the time came from a trusted DC. Without MS-SNTP, an attacker could MITM the NTP response and force clock skew, causing auth failures or replay attacks.

A framework should default to chrony (no MS-SNTP), rely on KDC skew enforcement, and provide monitoring for skew. The 5-minute skew window is the protocol's defense against replay (after 5 minutes, the authenticator's `ctime + cusec` is stale); the framework cannot relax this without breaking Kerberos. For AD interop, MS-SNTP support is required for legacy Windows DCs that use it.

**Impact**:

Time skew is the most common cause of Kerberos auth failures in mixed environments. Microsoft Premier Support reports ~30% of all Kerberos support cases are time-skew-related. The 5-minute window is unforgiving — a 6-minute skew causes auth failure with a cryptic error code. VM environments are especially vulnerable (live migration, snapshot revert, host clock drift). Without monitoring, skew builds up silently until auth fails en masse.

**Constraints**:

- Must support RFC 5905 NTP.
- Consider MS-SNTP only for legacy AD interop (chrony/ntpd do not support MS-SNTP).
- Must monitor skew and alert on >2 minute drift.
- For AD interop, must accept MS-SNTP-signed NTP responses from Windows DCs.

**Cross-platform considerations**:

- **Windows**: W32Time service (`w32time.dll` in `svchost -k LocalService`); `w32tm /query /status`, `w32tm /resync`. Forest-root PDC emulator is the stratum-1 source.
- **macOS**: `timed` (system time daemon); `systemsetup -setusingnetworktime on`. macOS uses unauthenticated NTP by default (no MS-SNTP).
- **Linux**: chrony (modern, recommended) or ntpd (legacy); `chronyc tracking`, `chronyc sources`. Neither supports MS-SNTP.
- **Cross-platform consistency**: Time sync must work cross-platform — Windows DCs running W32Time, Linux DCs running chrony, macOS DCs running timed. The framework's DCs must speak standard NTP (RFC 5905) to interop with all clients.

**KB references**:

- [`02-protocols/07-ntp-time-sync.md`](../docs/02-protocols/07-ntp-time-sync.md) — W32Time architecture, MS-SNTP authentication extension, NTP packet structure, Kerberos 5-minute skew window.

**Open questions**:

- Drop MS-SNTP entirely? Modern AD deployments increasingly use chrony on DCs; the MS-SNTP layer is legacy.
- Mandatory chrony with monitoring alerting on >2 min skew?
- Should the framework's KDC advertise a skew-monitor endpoint (HTTP `/health/skew`) that clients can poll?

**Cross-capability impact**:

- Affects: KDC PC-023 (MS-KILE) — KDC's 5-minute skew window is the protocol-level constraint.
- Affects: KDC PC-026 (FAST) — FAST armoring depends on time sync (the armor TGT's `authtime` must be within skew).
- Affects: Operations (PC-094, not in this catalog) — time sync monitoring is an ops task.

---

### PC-042 — Kerberos audit events (4768/4769/4771) need framework equivalent

**Capability**: Auth Provider
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD logs Kerberos events to Windows Event Log: 4768 (TGT issued), 4769 (TGS issued), 4771 (pre-auth failed), 4768/4769 with `Ticket Encryption Type: 0x17` is the Kerberoasting signal (an attacker is requesting RC4 TGS tickets for offline cracking). The events include: etype (RC4 vs AES — RC4 is the Kerberoast signal), SPN (the requested service principal), requester SID (the user), source IP (the client), request ID (for correlation). SIEM queries (Splunk, QRadar, Sentinel) assume Windows event IDs per [11-code-examples/05-python-impacket-examples.md](../docs/11-code-examples/05-python-impacket-examples.md) and [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Kerberoasting detection: query for events 4769 where `Ticket Encryption Type = 0x17` (RC4) AND `ServiceName` matches a service account (not `krbtgt` or a computer account). A high count of RC4 TGS-REQs for a single service account in a short window is a strong Kerberoasting signal. Microsoft's Advanced Threat Analytics (ATA) and Defender for Identity both use this pattern.

Golden ticket detection: query for events 4768 where the requesting user's SID is in `Enterprise Admins` but the source IP is unusual, or where the TGT was issued by a DC that's not the user's home DC. Both are weak signals (false positives from legitimate admin activity).

A framework should emit equivalent structured events (JSON / CEF — Common Event Format) to OpenTelemetry / SIEM, including etype, SPN, requester SID, source IP, request ID for correlation. The events must be compatible with existing SIEM queries — either by mapping to Windows event IDs (4768/4769/4771) or by providing a translation layer.

**Impact**:

Kerberoasting / DCSync detection depends on these events. SIEM queries assume Windows event IDs — without equivalent events, the framework's KDC is invisible to existing SIEM deployments. Security teams cannot detect Kerberoasting, golden ticket, AS-REP roasting, or DCSync attacks without these events. Compliance mandates (PCI DSS, HIPAA, SOC 2) require Kerberos audit logging — without it, the framework cannot be deployed in regulated environments.

**Constraints**:

- Must include etype (RC4 vs AES — Kerberoast signal), SPN (the requested service), requester SID (the user), source IP (the client), request ID (for correlation).
- Must emit events in real-time (not batched — Kerberoasting can complete in minutes).
- Must support OpenTelemetry / CEF / JSON output formats.
- For AD interop, must support Windows Event Log format (so Windows SIEM agents can ingest).

**Cross-platform considerations**:

- **Windows**: Event Log 4768/4769/4771/4770 (Kerberos); Windows Event Forwarding (WEF) for SIEM ingestion.
- **macOS**: Unified Log (`log show --predicate 'subsystem == "com.apple.kerberos"'`); `os_log` API for event emission.
- **Linux**: journald / syslog; `journalctl -t kerberos`; structured logging via `journald`'s JSON output.
- **Cross-platform consistency**: The events must be equivalent across platforms — same fields, same semantics, same correlation IDs.

**KB references**:

- [`11-code-examples/05-python-impacket-examples.md`](../docs/11-code-examples/05-python-impacket-examples.md) — Impacket Kerberoasting examples (requesting TGS for offline cracking), DCSync via `secretsdump.py`, detection patterns.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Kerberos message types, etypes, Wireshark display filters for Kerberoasting detection.

**Open questions**:

- Map to MITRE ATT&CK technique IDs in the event metadata? (T1558.003 Kerberoasting, T1558.001 Golden Ticket, T1003.006 DCSync.)
- OpenTelemetry semantic conventions for Kerberos events? Currently no standard conventions exist.
- Should the framework emit events to a local log (Windows Event Log / journald / Unified Log) AND a remote SIEM (via OTel / Syslog / CEF), or just one?
- Real-time alerting on Kerberoasting patterns (high count of RC4 TGS-REQs in a short window)?

**Cross-capability impact**:

- Affects: Security (PC-115, not in this catalog) — Kerberoasting / golden ticket detection.
- Affects: Operations (PC-094, not in this catalog) — audit log retention, SIEM integration.
- Affected by: KDC PC-024 (RC4 deprecation) — RC4 events are the Kerberoasting signal.

---

## Cross-capability impact

Problems in this capability affect and are affected by problems in other capabilities:

- **Core Directory** is the account-lookup source. PC-036 (NTLM compat) and PC-038 (PtH defense) require Core Directory to store `unicodePwd` securely (PC-013). PC-039 (S4U2Self/S4U2Proxy) requires Core Directory to store `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity` (linked attributes, PC-004 linkID pairing).
- **KDC** is the Kerberos foundation. PC-039 (S4U2Self/S4U2Proxy) is implemented by the KDC (`kdcsvc.dll`) — S4U is a KDC concern but is consumed by the Auth Provider. PC-041 (time sync) directly affects the KDC's 5-minute skew window.
- **Cert Service** is required for smart-card auth. PC-027 (PKINIT) requires Enterprise CA issuing smart-card certs.
- **Federation Gateway** uses S4U2Proxy for OAuth2 on-behalf-of flow. PC-039 affects the federation service's ability to delegate.
- **File Gateway** uses NTLM as a fallback when Kerberos fails. PC-036 (NTLM compat) and PC-037 (NTLM relay) directly affect SMB auth.
- **Client SDK** wraps the unified auth API (PC-040). The SDK must expose a consistent API across Windows, macOS, Linux.
- **Operations** depends on audit log emission (PC-042). SIEM integration requires the framework's events to be compatible with existing SIEM queries.
- **Security & Threat Model** covers NTLM relay (PC-037), PtH (PC-038), Kerberoasting (KDC PC-024), golden ticket (KDC PC-030), AS-REP roasting (KDC PC-026). The Auth Provider's audit events (PC-042) feed SIEM detection.
- **Migration & Coexistence** depends on NTLM interop during migration. PC-036 (NTLM compat) is critical for legacy app migration.

## Open research questions specific to this capability

1. **NTLM deprecation path**: Hard cut-off date, migration mode with audit warnings, or NTLM-emulation via Kerberos with downgrade-friendly client SDK? The choice affects every legacy app.

2. **PtH defense on non-Windows**: Linux TEE (ARM TrustZone, Intel SGX — deprecated on consumer), HSM-bound NT hash, or eliminate NTLM entirely (use Kerberos-only)? The choice affects the framework's Linux DC support.

3. **S4U2Self/S4U2Proxy vs OAuth2 client-credentials**: Maintain S4U for AD interop, use OAuth2 for new services, or hybrid? S4U is Kerberos-native; OAuth2 is HTTP-only.

4. **Cross-platform token abstraction**: WebAuthn-style token-binding, per-platform adapters with unified core, or higher-level OAuth2-style abstraction? Each has trade-offs in API consistency and platform-native feel.

5. **Time sync protocol**: Drop MS-SNTP entirely (modern), mandate chrony with monitoring, or maintain MS-SNTP for legacy AD interop? The choice affects Windows DC interop.

6. **Audit event format**: Map to Windows event IDs (4768/4769/4771) for SIEM compat, use OpenTelemetry semantic conventions (which don't exist for Kerberos yet), or define a new CEF-based format? The choice affects SIEM integration effort.

7. **Channel binding default enforcement**: Default to LDAP signing + channel binding required (security-first, breaks legacy apps), or opt-in (compat-first, leaves relay risk)?

8. **NTLM audit-log parser tool**: Provide a tool that ingests NTLM audit logs, identifies NTLM-using apps, and suggests fixes (missing SPN, DNS mismatch, etc.)? This is the missing piece for NTLM deprecation.

9. **Restricted Admin mode for non-RDP protocols**: Extend Restricted Admin to SSH (Linux), VNC (macOS), and other remote-access protocols? This eliminates credential forwarding for remote access.

10. **Passwordless migration**: When does the framework drop password support entirely (no `unicodePwd`, no kpasswd, no NTLM)? The trade-off is breaking every legacy client.
