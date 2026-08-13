---
title: "ADR-086: Pass-the-Hash Defense via NTLM Server Drop + HSM-Bound PEK + Platform Isolation"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Auth Provider
problem: PC-038
severity: blocker
unblocked_by: Workshop Decision 6 (ORQ-072/074/075)
tags: [adr, auth-provider, pass-the-hash, pth, nt-hash, hsm, pek, lsass, credential-guard, stride, mitre-t1075]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/03-auth-provider.md
  - ../docs/02-protocols/04-ntlm-internals.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ../workshop/decision-06-ntlm-decision.md
  - ./ADR-011-rc4-deprecation-aes-default.md
  - ./ADR-015-krbtgt-hsm-rotation.md
  - ./ADR-021-ldap-signing-channel-binding.md
  - ./ADR-023-kerberos-audit-events.md
  - ./ADR-054-per-host-laps-rotation.md
  - ./ADR-085-ntlm-client-only-rust-crate.md
last_updated: 2026-08-14
---

# ADR-086: Pass-the-Hash Defense via NTLM Server Drop + HSM-Bound PEK + Platform Isolation

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 6](../workshop/decision-06-ntlm-decision.md) which resolved Tier-1 ORQ-072/074/075 in favor of dropping NTLM server-side while preserving NTLM client-only via the Rust crate ([ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)). This ADR specifies the framework's pass-the-hash (PtH) defense posture, layered across three controls: (1) **server-side elimination** — no framework service accepts NTLM tokens, so PtH against framework infrastructure is structurally impossible; (2) **HSM-bound PEK encryption** for AD-interop users' NT hashes, the strongest possible protection short of elimination; (3) **platform isolation** — Linux kernel keyring / `systemd-creds`, macOS Secure Enclave, Windows DPAPI + Credential Guard — so NT hashes held client-side never sit in process memory accessible to administrators. Together these controls reduce the PtH attack surface from "any framework service, any AD-interop user hash" to "the HSM, and only the HSM".

## Threat model (STRIDE)

| STRIDE category | Attack vector | Framework mitigation |
|---|---|---|
| **Spoofing** | Attacker with stolen NT hash spoofs user against NTLM-accepting service | No framework service accepts NTLM (per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)); spoofing target does not exist |
| **Tampering** | Attacker tampers with NT hash in directory storage (e.g. via direct DIT write) | Directory enforces PEK-encryption invariant; plaintext NT hash never present in DIT; HSM-bound PEK key |
| **Repudiation** | Attacker uses stolen hash; legitimate user is blamed for actions | Audit event `ntlm_client_auth` per [ADR-023](./ADR-023-kerberos-audit-events.md) captures source IP + target service; framework Kerberos auth is always audited with the requester SID |
| **Information disclosure** | LSASS-dump / DIT-extraction leaks NT hash for offline use | Pure-framework users have no NT hash (per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md)); AD-interop users' NT hashes are HSM-PEK-encrypted |
| **Denial of service** | Attacker floods HSM with NT hash decryption requests (DC-side) | Per-caller rate limit on HSM operations (default 100/sec per KDC instance); PEK is cached for 5 seconds after first use, capped at 5% of CPU budget |
| **Elevation of privilege** | Local admin on a framework-managed host extracts cached NT hash from process memory | Platform isolation: NT hashes are held in Linux kernel keyring / `systemd-creds` / macOS Keychain / Windows DPAPI + Cred Guard, NOT in the framework's auth-provider process memory |

**Primary attack vector (Mandiant M-Trends 2023)**: PtH is used in ~80% of AD compromises that involve lateral movement. The attacker: (1) compromises one host via phishing or exploit; (2) dumps `lsass.exe` memory with `mimikatz sekurlsa::logonpasswords` or `procdump`; (3) extracts NT hashes for every user who has logged into that host; (4) uses `mimikatz sekurlsa::pth /user:jdoe /domain:EXAMPLE /ntlm:<hex> /service:cifs /target:dc01` or `impacket/psexec.py -hashes :<nt-hash>` or `evil-winrm -H <nt-hash>` to authenticate to downstream services as the victim — including Domain Admins if a DA has logged into the compromised host. The framework's three-layer defense breaks this chain at: step 2 (no LSASS-equivalent memory contains NT hashes — they are in platform-secure stores); step 4 (no framework service accepts NTLM — the PtH token is rejected).

## Context

The NT hash (MD4 of UTF-16LE password, 16 bytes) is the entire secret for NTLM. AD stores it in `unicodePwd` on every user object, replicated to every DC, and decrypted into LSASS memory at every interactive logon. Microsoft's PtH defenses are Windows-centric: (a) LSA Protected Mode (`RunAsPPL = 1`) — LSASS runs as Protected Process Light; (b) Credential Guard (VSM-based LSASS isolation) — NT hashes stored in `LSAIso.exe` in the secure enclave; (c) LAPS — rotates local admin passwords periodically; (d) Restricted Admin mode (RDP) — RDP client doesn't send credentials, forces Kerberos.

On Linux/macOS, the equivalent isolation is SSSD's `krb5_child` setuid helper and the kernel keyring for secret storage. There is no native Credential Guard equivalent on Linux/macOS — TEE (ARM TrustZone, Intel SGX) is hardware-dependent and SGX is deprecated on consumer Intel chips.

The framework's posture ([Decision 6](../workshop/decision-06-ntlm-decision.md)) is sharper than AD's: pure-framework users have no NT hash at all (PtH impossible); AD-interop users' NT hashes are HSM-PEK-encrypted; framework-managed clients hold NT hashes only in platform-secure stores (never in the framework's auth-provider process memory); no framework service accepts NTLM (no PtH target). The framework's three-layer defense is strictly stronger than AD's because: (a) AD's Credential Guard is bypassable (CVE-2020-1017, CVE-2022-37966); the framework's NTLM-server-drop has no bypass; (b) AD's LSASS-stored NT hashes are extractable via kernel-mode exploits; the framework's HSM-PEK encryption requires HSM compromise; (c) AD's DC-side NT hashes are replicated to every DC; the framework's PEK is single-HSM-bound (no DC has the PEK in process memory).

Constraints from [PC-038](../catalog/03-auth-provider.md):

- Must not store NT hash in process memory accessible to administrators (use Protected Process, kernel keyring, or HSM).
- Must support LAPS-equivalent for local accounts (rotate local admin passwords periodically).
- Must support Restricted Admin mode for RDP-equivalent remote access.
- For AD interop, must support Credential Guard (VSM-based isolation) on Windows DCs.

## Decision

The framework SHALL implement PtH defense as three layered controls, each specified below. The combined posture: pure-framework users have no NT hash (PtH impossible); AD-interop users' NT hashes are HSM-PEK-encrypted at rest and never in process memory in plaintext; framework-managed clients hold NT hashes only in platform-secure stores; no framework service accepts NTLM.

### Control 1 — Server-side elimination (no PtH target)

Per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md), the framework SHALL NOT implement an NTLM acceptor on any framework-hosted service. PtH against framework infrastructure is structurally impossible — the attacker's `mimikatz sekurlsa::pth` or `impacket/psexec.py -hashes :<nt-hash>` produces an NTLM token that the framework service rejects with `strongAuthRequired (8)` (LDAP), `401 Unauthorized` (HTTP), or protocol equivalent. This is the over-arching control: even if the attacker has the NT hash, they cannot use it against the framework. AD-interop services running in a parallel AD forest remain vulnerable to PtH (the framework does not protect services it does not host), but framework-hosted services are PtH-free.

### Control 2 — HSM-bound PEK encryption for AD-interop users' NT hashes

The framework's Core Directory SHALL store NT hashes in `unicodePwd` (matching AD's schema) but encrypted with a Password Encryption Key (PEK) bound to the framework's HSM (the same HSM that holds the krbtgt key per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)). The PEK is generated at forest-setup time in the HSM; the PEK SHALL NEVER leave the HSM in plaintext. The directory stores `unicodePwd = AES-256-CTS-PEK-Encrypt(NT_hash)` — the encrypted blob is what replication carries between DCs; the PEK is not replicated (it is fetched from the HSM on demand).

When the KDC (per [Decision 5](../workshop/decision-05-kdc-implementation.md)) needs an AD-interop user's NT hash (for RC4 audit path per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md), or for NTLM-client auth per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)), the KDC reads the encrypted `unicodePwd` from the directory, sends it to the HSM via PKCS#11 `C_DecryptInit` / `C_Decrypt`, receives the plaintext NT hash in HSM-protected memory, performs the cryptographic operation (PBKDF2 for AES keys, HMAC-MD5 for NTLMv2 response), and zeroizes the plaintext NT hash from HSM-protected memory. The plaintext NT hash SHALL NEVER be in the KDC process's normal heap memory; the HSM-protected memory window is ≤1 ms per operation.

For pure-framework users (users created in the framework, not migrated from AD), the framework SHALL NOT derive or store an NT hash at all. Pure-framework users have only AES Kerberos keys (per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md)) — PBKDF2-HMAC-SHA1 with 4096 iterations. PtH against pure-framework users is impossible.

### Control 3 — Platform isolation for client-side NT hash holding

When a framework-managed client (per [Decision 11](../workshop/decision-11-client-sdk.md)) holds an NT hash for outbound NTLM authentication (per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)), the hash SHALL be stored in the platform's secure credential store — NEVER in the framework's auth-provider process memory in plaintext. The framework's `crates/adrian-ntlm-client` integrates with:

- **Linux**: kernel keyring (`keyctl add user <key> <hash> @s`) for in-kernel storage, or `systemd-creds` for encrypted-at-rest storage with TPM2 binding. The framework's PAM module (`pam_adrian.so` per [ADR-050](./ADR-050-authselect-standard-pam.md)) fetches the hash on demand via `keyctl read` and immediately zeroizes its copy after the NTLMv2 response computation.
- **macOS**: Keychain (`SecItemAdd` with `kSecClassGenericPassword` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). The framework's OpenDirectory plugin (`adrian-opendirectory.bundle` per [Decision 11](../workshop/decision-11-client-sdk.md)) fetches the hash on demand via `SecItemCopyMatching` with `kSecReturnData`, immediately zeroizes after NTLMv2 computation. For Touch ID-equipped Macs, the framework MAY use the Secure Enclave for hash storage (per `CryptoTokenKit` framework) — the hash never leaves the Secure Enclave; the NTLMv2 computation is performed inside the SEP via `SecKeyCreateDecryptedData`.
- **Windows**: DPAPI (`CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE` flag off — the hash is encrypted to the user's logon credentials) for at-rest storage, and Windows Credential Guard (`LSAIso.exe` in VSM) for in-memory isolation. The framework's LSA Authentication Package (`adrianlsa.dll` per [Decision 11](../workshop/decision-11-client-sdk.md)) proxies NTLMv2 computations to LSAIso when Credential Guard is enabled; the hash never sits in `lsass.exe` normal heap memory.

### LAPS-equivalent and Restricted Admin mode

The framework's per-host LAPS rotation (every 30 days, configurable) is specified in [ADR-054](./ADR-054-per-host-laps-rotation.md) — rotated password stored in `msDs-ManagedPassword` encrypted with the PEK per Control 2; only the host can fetch it. Restricted Admin mode for remote access (SSH GSSAPI default on Linux; RDP `RESTRICTED_ADMIN` flag on Windows; Kerberos-authenticated Screen Sharing on macOS) ensures the client does not send NT hashes to the target — the target authenticates via Kerberos service ticket.

### Concrete specification

- Pure-framework users SHALL NOT have NT hashes derived or stored; only AES Kerberos keys per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md). PtH against pure-framework users is structurally impossible.
- AD-interop users SHALL have NT hashes stored in `unicodePwd` encrypted with HSM-bound PEK. The PEK SHALL NEVER leave the HSM in plaintext; the PEK SHALL NOT be replicated between DCs (each DC fetches the PEK from the HSM on demand).
- The KDC's RC4 audit path ([ADR-011](./ADR-011-rc4-deprecation-aes-default.md)) and the NTLM client ([ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)) SHALL decrypt NT hashes via HSM; plaintext NT hashes SHALL be confined to HSM-protected memory windows ≤1 ms.
- Framework-managed clients SHALL hold NT hashes only in platform-secure stores (Linux `keyctl` / `systemd-creds`, macOS Keychain / Secure Enclave, Windows DPAPI / Credential Guard); the framework's auth-provider process SHALL NEVER hold NT hashes in normal heap memory in plaintext.
- The framework SHALL rotate per-host LAPS passwords every 30 days per [ADR-054](./ADR-054-per-host-laps-rotation.md).
- The framework SHALL support Restricted Admin mode in remote-access tooling (SSH GSSAPI default; RDP `RESTRICTED_ADMIN` flag; macOS Screen Sharing via Kerberos).
- The framework SHALL emit audit events per [ADR-023](./ADR-023-kerberos-audit-events.md): `nt_hash_access` (every HSM decrypt operation: principal, caller, source IP, timestamp — this is the forensic trail if HSM-protected memory is somehow compromised); `laps_rotation.success/failed`; `restricted_admin.used`.
- The framework SHALL expose `adrian-auth audit-pth` CLI command (scan audit log for PtH-relevant signals: NT hash accesses, LAPS rotation failures, non-restricted-admin remote sessions).

### Rust crates used

- `adrian-ntlm-client` (framework crate, per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)) — NTLMv2 client; PEK integration for AD-interop hash fetch.
- `cryptoki` (v0.6+) for PKCS#11 v3.0 HSM access — PEK decrypt for NT hash retrieval (per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)).
- `md4` (v0.10+) for NT hash derivation (only for users with passwords — pure-framework users skip this entirely).
- `keyring` (v3.0+) for platform-secure credential store access (Linux `keyctl`, macOS Keychain, Windows DPAPI).
- `windows` (v0.54+) for Windows Credential Guard integration.
- `systemd` (v0.10+) for `systemd-creds` integration on Linux.
- `security-framework` (v2.10+) for macOS Keychain and `CryptoTokenKit` Secure Enclave access.
- `zeroize` (v1.7+) for explicit zeroization of NT hash memory after use; the framework wraps all NT hash handling in `Zeroizing<Vec<u8>>` so the hash is zeroed on drop.
- `tracing` + `opentelemetry` for `nt_hash_access` audit emission per [ADR-023](./ADR-023-kerberos-audit-events.md).

## Rationale

Three arguments drive the layered defense.

**1. Server-side elimination is the over-arching control.** AD's PtH defenses (Credential Guard, LSA Protected Mode, LAPS) are band-aids over the structural problem: AD services accept NTLM. The framework's NTLM-server-drop ([Decision 6](../workshop/decision-06-ntlm-decision.md), [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)) eliminates the structural problem — there is no PtH target in framework infrastructure. The remaining controls (PEK encryption, platform isolation, LAPS) are defense-in-depth: they protect against the residual attack surface (AD-interop services running in parallel forests, client-side hash theft, local-admin credential reuse).

**2. HSM-bound PEK is the strongest possible at-rest protection for AD-interop users' NT hashes.** AD stores NT hashes in `unicodePwd` encrypted with the PEK, but the PEK is in the directory (replicated to every DC, decryptable by any DC). AD's PEK is decryptable by anyone with read access to the DIT (which is every DC). The framework's PEK is HSM-bound — decrypting an NT hash requires HSM access. This closes the DIT-extraction attack (stealing a DIT backup is no longer sufficient; the attacker also needs the HSM).

**3. Platform isolation eliminates the LSASS-dump attack vector on framework-managed clients.** AD's Credential Guard uses VSM (virtualization-based isolation) on Windows; Linux/macOS have no native equivalent. The framework's per-platform integration (kernel keyring on Linux, Keychain + Secure Enclave on macOS, DPAPI + Credential Guard on Windows) gives each platform its strongest available isolation. The `zeroize` crate ensures that even the brief in-process window during NTLMv2 computation is zeroized after use — no forensic trace in core dumps.

External evidence: [Microsoft Credential Guard documentation](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) documents AD's VSM-based defense (multiple CVE bypasses published); [Mandiant M-Trends 2023](https://www.mandiant.com/resources/blog/m-trends-2023) quantifies PtH at ~80% of AD lateral-movement compromises; [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md) documents the NT hash as PtH's single secret; [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) documents AD's PtH defense posture; [MITRE ATT&CK T1075](https://attack.mitre.org/techniques/T1075/) catalogs PtH as a documented adversary technique.

## Consequences

**Positive**: PtH against framework-hosted services is structurally impossible (no NTLM acceptor). PtH against AD-interop users requires HSM compromise (DIT extraction is insufficient). Client-side NT hash theft is mitigated by platform isolation. Local-admin credential reuse across the fleet is mitigated by per-host LAPS rotation. The `nt_hash_access` audit event provides forensic trail for HSM-side investigations.

**Negative**: AD-interop users' NT hashes are still present in the directory (encrypted with PEK) — pure-framework mode is the only zero-NT-hash posture. The HSM dependency is now load-bearing for the KDC's RC4 audit path and the NTLM client; HSM unavailability blocks NTLM client auth. The PEK is single-HSM-bound; PEK rotation (re-encrypting every `unicodePwd`) is a multi-hour operation on large directories — deferred to maintenance windows. The `zeroize` integration adds ~5% CPU overhead to NTLMv2 computations (negligible at typical client load). Windows Credential Guard integration requires Windows 10 Enterprise+ on the client side; clients without Credential Guard fall back to DPAPI.

**Neutral**: The framework's PtH defense is strictly stronger than AD's because the framework has no NTLM server. AD-interop customers running parallel AD forests retain AD's PtH defense posture for those forests.

**Implementation cost**: 6 person-weeks total. PEK encryption + HSM integration in Core Directory: 2 pw. Platform isolation in `crates/adrian-ntlm-client` (Linux keyring, macOS Keychain + Secure Enclave, Windows DPAPI + Credential Guard): 2 pw. `zeroize` integration across the KDC and NTLM client: 0.5 pw. Restricted Admin mode in remote-access tooling: 0.5 pw. `nt_hash_access` audit event + `adrian-auth audit-pth` CLI: 1 pw. LAPS rotation covered by Client SDK budget per [ADR-054](./ADR-054-per-host-laps-rotation.md).

## Alternatives Considered

### Alternative 1: Drop NTLM entirely (no client-side, no NT hash storage)

Eliminates PtH completely. Rejected per [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md): framework-managed clients cannot authenticate to legacy NTLM-requiring services (5–10% of enterprise apps per Spike 4).

### Alternative 2: VSM-equivalent on Linux (TEE — ARM TrustZone, Intel SGX)

Use hardware TEE for NT hash isolation on Linux/macOS. Rejected: TEE is not universally available; SGX is deprecated on consumer Intel chips; TrustZone is ARM-specific. The framework's per-platform integration achieves equivalent isolation without TEE dependency. TEE MAY be added as a future optimization for TEE-equipped hardware.

### Alternative 3: HSM-bound NT hash (no PEK layer)

Store NT hashes directly in the HSM, not in the directory. Rejected: breaks AD-interop — AD stores NT hashes in `unicodePwd` and replicates them to every DC; the framework's directory must do the same. The PEK layer is the bridge: directory-stored, HSM-encrypted, replication-compatible.

### Alternative 4: Store NT hashes in directory, encrypted with a per-DC key (not HSM-bound)

Each DC has its own key for encrypting `unicodePwd`. Rejected: each DC's key is in LSASS-equivalent process memory; an LSASS dump on any DC yields that DC's key. HSM-bound PEK is strictly stronger.

## Open Questions

- For PEK rotation: should the framework rotate the PEK on the krbtgt rotation schedule (per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md))? Yes — but PEK rotation is expensive (re-encrypt every `unicodePwd`); schedule for maintenance windows; provide `adrian-cli rotate-pek --start --dry-run` CLI.
- For Secure Enclave integration on macOS: the Secure Enclave can store keys but cannot perform MD4 (NT hash derivation). The framework's macOS NTLM client must derive the NT hash in software (`md4` crate), then store the derived hash in the Secure Enclave (not the password). The Secure Enclave performs the HMAC-MD5 (NTLMv2 response) operation. This is the strongest available isolation on macOS.
- Cross-reference [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md) (PC-036) — the NTLM client crate that this ADR's platform isolation protects.
- Cross-reference [ADR-054](./ADR-054-per-host-laps-rotation.md) — LAPS rotation is a complementary control for local-admin PtH.

## Cross-capability impact

- **KDC** ([Decision 5](../workshop/decision-05-kdc-implementation.md)): the KDC's RC4 audit path decrypts AD-interop users' NT hashes via HSM-PEK; the KDC's S4U2Self credential-data extraction uses the same path.
- **Auth Provider** ([ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)): the NTLM client integrates with platform-secure stores; `nt_hash_access` audit event emitted on every HSM decrypt.
- **Core Directory**: `unicodePwd` storage with HSM-PEK encryption; PEK not replicated; PEK fetched from HSM on demand.
- **Client SDK** ([Decision 11](../workshop/decision-11-client-sdk.md)): the SDK's `AuthModule` integrates with platform-secure stores; `pam_adrian.so` and `adrian-opendirectory.bundle` fetch NT hashes on demand.
- **Operations** ([ADR-054](./ADR-054-per-host-laps-rotation.md)): LAPS rotation runs on the SDK's daemon; `adrian-auth audit-pth` CLI provides PtH-relevant signal inventory.
- **Security** ([ADR-023](./ADR-023-kerberos-audit-events.md)): `nt_hash_access`, `laps_rotation.success/failed`, `restricted_admin.used` events feed PtH-detection SIEM queries.
- **Migration**: AD users migrating to the framework retain their NT hash (encrypted with PEK) for AD-interop; pure-framework migration path discards the NT hash.

## References

- [PC-038](../catalog/03-auth-provider.md) — problem statement in the catalog
- [Workshop Decision 6 — NTLM Decision](../workshop/decision-06-ntlm-decision.md) — unblocking decision
- [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md) — PtH attack description, NT hash, `mimikatz sekurlsa::pth`, mitigations
- [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) — AD security posture, LSA Protected Mode, Credential Guard, LAPS, Restricted Admin
- [ADR-011](./ADR-011-rc4-deprecation-aes-default.md) — pure-framework users have AES keys only, no NT hash
- [ADR-015](./ADR-015-krbtgt-hsm-rotation.md) — HSM binding for PEK; same HSM as krbtgt
- [ADR-023](./ADR-023-kerberos-audit-events.md) — `nt_hash_access`, `laps_rotation`, `restricted_admin` audit events
- [ADR-054](./ADR-054-per-host-laps-rotation.md) — LAPS rotation for local-admin PtH
- [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md) — NTLM client crate that this ADR's platform isolation protects
- [Microsoft Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [MITRE ATT&CK T1075](https://attack.mitre.org/techniques/T1075/) — Pass the Hash adversary technique
- [Mandiant M-Trends 2023](https://www.mandiant.com/resources/blog/m-trends-2023) — PtH used in ~80% of AD lateral-movement compromises
- [zeroize crate](https://docs.rs/zeroize) — Rust crate for secure memory zeroization
