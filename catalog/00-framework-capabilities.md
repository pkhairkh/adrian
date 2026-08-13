---
title: Framework Capabilities Taxonomy
audience: architects-and-engineers
tags: [taxonomy, capabilities, framework-design, problem-catalog]
related:
  - ./README.md
  - ./01-core-directory.md
  - ./02-kdc.md
  - ./03-auth-provider.md
  - ./04-policy-engine.md
  - ./05-cert-service.md
  - ./06-federation-gateway.md
  - ./07-file-gateway.md
  - ./08-client-sdk.md
  - ./09-cross-platform-parity.md
  - ./10-operations.md
  - ./11-security-threat-model.md
  - ./12-migration-and-coexistence.md
last_updated: 2026-08-13
---

# Framework Capabilities Taxonomy

Before enumerating problems, we define what the framework is. The framework is decomposed into **12 capabilities**, each with a clear responsibility, a public interface, and a set of dependencies on other capabilities. Every problem in the catalog is assigned to exactly one primary capability; cross-capability impacts are noted in the problem description.

## Why these 12 capabilities?

The decomposition follows three principles:

1. **Mirror AD's own decomposition** where it makes sense (DS, CS, FS, LDS, RMS map to Core Directory, Cert Service, Federation Gateway, Core Directory-variant, File Gateway-RMS). This keeps the catalog greppable against the KB.
2. **Split cross-cutting concerns** that AD conflates. AD bundles authentication into LSASS; we split it into KDC (Kerberos) + Auth Provider (NTLM/SASL/everything else). AD bundles policy into GPO; we split it into Policy Engine. AD bundles management into Windows Server Manager; we split it into Operations.
3. **Surface platform abstraction** as a first-class capability. AD's client story is Windows-only; the framework must explicitly design for cross-platform clients. Hence: Client SDK and Cross-Platform Parity are their own capabilities.

## The 12 capabilities

### 1. Core Directory Service

**Responsibility**: Stores identity, configuration, and policy objects in a replicated, multi-master directory. Exposes query/modify via LDAP. Exposes replication via DRSUAPI (if AD-interop) or a new protocol (if clean-slate).

**Inherits from AD**: AD DS (the `ntdsa.dll` DSA + ESE database + DRSUAPI replication + LDAP server + GC).

**Public interfaces**:
- LDAP (RFC 4511) — query, modify, bind, controls, extended ops
- LDAPS (TLS) and StartTLS
- Global Catalog on port 3268/3269
- DRSUAPI RPC (if AD-interop) for inbound replication
- DRSUAPI RPC client for outbound replication
- Schema management (read/write schema NC)
- Replication metadata query (USN, UTD vector, InvocationID)

**Depends on**: nothing (this is the foundation)

**Consumed by**: KDC (reads principal data), Auth Provider (reads account data), Policy Engine (reads GPO data), Cert Service (publishes certs), Federation Gateway (reads user/group data), File Gateway (reads ACLs), Client SDK (LDAP wrapper).

**Catalog**: [01-core-directory.md](./01-core-directory.md) — 22 problems.

### 2. KDC (Kerberos Key Distribution Center)

**Responsibility**: Issues Kerberos tickets. Implements AS-REQ/AS-REP, TGS-REQ/TGS-REP, kpasswd, cross-realm referral, PAC generation/signing, PKINIT for smart-card logon, FAST for pre-auth hardening.

**Inherits from AD**: `kdcsvc.dll` running in LSASS on every DC.

**Public interfaces**:
- Kerberos V5 (RFC 4120) — TCP/UDP 88
- kpasswd (RFC 3244) — TCP/UDP 464
- MS-KILE profile extensions — PAC, FAST, PKINIT, S4U2Self/S4U2Proxy
- KDC proxy (MS-KKDCP) — HTTPS tunnel for Kerberos

**Depends on**: Core Directory (reads principal data, krbtgt account, service principals).

**Consumed by**: Auth Provider (Kerberos SSPI-equivalent), Federation Gateway (for Kerberos-constrained delegation), Client SDK (kinit-equivalent).

**Catalog**: [02-kdc.md](./02-kdc.md) — 13 problems.

### 3. Auth Provider

**Responsibility**: Provides authentication mechanisms other than Kerberos. NTLM (if maintained), SASL, certificate-based auth, smart-card logon, OAuth2/OIDC bearer tokens (for HTTP), TLS channel binding.

**Inherits from AD**: `msv1_0.dll` (NTLM), `kerberos.dll` (Kerberos SSPI provider), `schannel.dll` (TLS), `pku2u.dll` (peer-to-peer), `wdigest.dll` (deprecated).

**Public interfaces**:
- SSPI-equivalent: `InitializeSecurityContext`, `AcceptSecurityContext`, `EncryptMessage`, `DecryptMessage`
- GSS-API (RFC 2743) on non-Windows platforms
- NTLMSSP (if maintained)
- SASL mechanisms: GSS-SPNEGO, GSSAPI, EXTERNAL, ANONYMOUS

**Depends on**: KDC (for Kerberos), Core Directory (for account lookup), Cert Service (for smart-card trust).

**Consumed by**: File Gateway (SMB auth), Federation Gateway (for non-Kerberos auth), Client SDK (auth API).

**Catalog**: [03-auth-provider.md](./03-auth-provider.md) — 7 problems.

### 4. Policy Engine

**Responsibility**: Distributes configuration policy to enrolled clients. Replaces GPO. Supports declarative policy (vs. INI/registry.pol), versioned policies, conflict resolution beyond last-writer-wins, rollback, partial application.

**Inherits from AD**: GPO (GPC in AD + GPT in SYSVOL + Group Policy Client service + CSEs).

**Public interfaces**:
- Policy retrieval (pull by enrolled client) — replaces Group Policy Client
- Policy targeting (security filtering, WMI-equivalent, scope)
- Policy payload format (declarative, versioned)
- Policy reporting (live policy set per client)
- ADMX-equivalent schema for third-party policy definitions

**Depends on**: Core Directory (stores policy objects), File Gateway (distributes policy files via SMB-equivalent or HTTPS).

**Consumed by**: Client SDK (applies policy on enrolled clients).

**Catalog**: [04-policy-engine.md](./04-policy-engine.md) — 14 problems.

### 5. Cert Service

**Responsibility**: X.509 PKI. Issues, revokes, publishes certificates. Supports autoenrollment, key archival, OCSP, CRL, multi-tier CA hierarchy.

**Inherits from AD**: AD CS (`certsvc.exe` + policy/exit modules + CA database + MS-WCCE/MS-XCEP enrollment endpoints + NDES for SCEP).

**Public interfaces**:
- Certificate enrollment — MS-WCCE/MS-XCEP (interop) or ACME (RFC 8555) or EST (RFC 7030) or SCEP (RFC 8894)
- CRL distribution — HTTP / LDAP
- OCSP responder — RFC 6960
- CA admin — certificate templates, revocation, key archival
- NDES-equivalent for network devices

**Depends on**: Core Directory (publishes certs, templates, CRLs).

**Consumed by**: KDC (PKINIT), Auth Provider (smart-card logon, TLS client cert), Federation Gateway (token signing), File Gateway (SMB encryption).

**Catalog**: [05-cert-service.md](./05-cert-service.md) — 11 problems.

### 6. Federation Gateway

**Responsibility**: Identity provider for web/HTTP apps. SAML 2.0, WS-Federation, OAuth2/OIDC. Issues tokens, manages relying-party trusts, exposes metadata, supports home-realm discovery.

**Inherits from AD**: AD FS (`Microsoft.IdentityServer.ServiceHost.exe` + WID/SQL config DB + WAP reverse proxy + MS-ADFSPIP).

**Public interfaces**:
- SAML 2.0 endpoints — `/saml2/ls/`, `/saml2/slo/`
- WS-Federation endpoints — `/wsfed/`
- OAuth2/OIDC endpoints — `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/.well-known/openid-configuration`
- Federation metadata — `/FederationMetadata/2007-06/FederationMetadata.xml`
- WS-Trust endpoints (active clients) — `/trust/2005/usernamemixed`

**Depends on**: Core Directory (claims source), KDC (Kerberos-constrained delegation), Cert Service (token-signing cert).

**Consumed by**: Web apps, OAuth2/OIDC clients, SaaS apps.

**Catalog**: [06-federation-gateway.md](./06-federation-gateway.md) — 10 problems.

### 7. File Gateway

**Responsibility**: File and print services. SMB shares, DFS-N, DFS-R-equivalent, print spooler-equivalent, offline-files-equivalent.

**Inherits from AD**: lanmanserver (srv2.sys + srv.sys + srvnet.sys), DFS-N (dfssvc.exe), DFS-R (dfsr.exe), Print Spooler (spoolsv.exe), Offline Files (cscsvc.dll + csc.sys).

**Public interfaces**:
- SMB 2/3 server — TCP 445, MS-SMB2
- SMB client — `mount_smbfs` / `New-SmbMapping` / `mount.cifs`
- DFS-N referral — MS-DFSN
- Print spooler — MS-RPRN (with PrintNightmare mitigations) or new print protocol
- Offline files / sync engine

**Depends on**: Core Directory (publishes shares, printers, DFS topology), Auth Provider (SMB auth).

**Consumed by**: Client SDK (file/print client), Policy Engine (uses SYSVOL-equivalent for policy distribution).

**Catalog**: [07-file-gateway.md](./07-file-gateway.md) — 7 problems.

### 8. Client SDK

**Responsibility**: Cross-platform library that lets client applications authenticate, query the directory, apply policy, mount shares, request certificates, and federate. Replaces SSPI+Wldap32+NetAPI on Windows, SSSD+PAM+NSS+LDAP on Linux, OpenDirectory framework on macOS.

**Inherits from AD**: SSPI (`secur32.dll`), Wldap32 (`wldap32.dll`), NetAPI (`netapi32.dll`), Group Policy Client (`gpsvc.dll`).

**Public interfaces**:
- Authentication API (unified across Kerberos, NTLM, cert, OAuth2 token)
- Directory query API (LDAP wrapper with idiomatic language bindings)
- Policy application API (subscribes to policy, applies, reports)
- File/print client API (SMB client wrapper)
- Cert enrollment API (autoenroll-equivalent)
- Federation client API (token cache, refresh)

**Depends on**: All server-side capabilities (consumes their APIs).

**Consumed by**: Applications on Windows, macOS, Linux.

**Catalog**: [08-client-sdk.md](./08-client-sdk.md) — 9 problems.

### 9. Cross-Platform Parity

**Responsibility**: Ensure that every feature works equivalently on Windows, macOS, and Linux. Track parity gaps. Define platform-specific implementations where required.

**Not inherited from AD**: AD is Windows-only; parity is a new requirement for the framework.

**Public interfaces**: none (this is a cross-cutting concern, not a service).

**Depends on**: All capabilities (defines parity requirements for each).

**Consumed by**: All capabilities (each capability must satisfy parity requirements).

**Catalog**: [09-cross-platform-parity.md](./09-cross-platform-parity.md) — 12 problems.

### 10. Operations

**Responsibility**: Deploy, configure, monitor, backup, restore, upgrade, troubleshoot the framework. Container-native deployment, Kubernetes operators, Prometheus metrics, OpenTelemetry tracing, structured logging.

**Inherits from AD**: dcpromo (deprecated), Server Manager (Windows-only), repadmin/dcdiag/ntdsutil (Windows-only), Windows Event Log, Performance Monitor.

**Public interfaces**:
- Deployment API (provision new DC, decommission DC, promote/demote)
- Health API (per-DC, per-capability status)
- Backup/restore API
- Upgrade API (rolling, schema migration)
- Observability (Prometheus, OpenTelemetry, structured logs)

**Depends on**: All capabilities (operates each).

**Consumed by**: Operators, automation (Terraform, Ansible, Kubernetes).

**Catalog**: [10-operations.md](./10-operations.md) — 10 problems.

### 11. Security & Threat Model

**Responsibility**: Define the threat model, enumerate attacks, specify mitigations, audit the framework. Cover Kerberoasting, DCSync, golden/silver ticket, NTLM relay, Pass-the-hash, PrintNightmare analogs, supply chain, side channels.

**Inherits from AD**: Mostly gaps — AD's threat model is implicit; mitigations are scattered across registry keys, group policies, and KB articles.

**Public interfaces**: none (this is a cross-cutting concern).

**Depends on**: All capabilities (each must implement mitigations).

**Consumed by**: All capabilities.

**Catalog**: [11-security-threat-model.md](./11-security-threat-model.md) — 8 problems.

### 12. Migration & Coexistence

**Responsibility**: Migrate from AD to the framework. Coexist with AD during migration. Handle sidHistory, GPO translation, client switchover, password hash migration, Kerberos cross-realm, DNS namespace sharing.

**Not inherited from AD**: AD is the source; migration is a framework responsibility.

**Public interfaces**:
- AD-to-framework migration tool
- Coexistence mode (framework DC and AD DC both active, replicating)
- GPO translation tool (ADMX → framework policy schema)
- Client switchover tool

**Depends on**: All capabilities (must interop with AD equivalents during migration).

**Consumed by**: Migration projects.

**Catalog**: [12-migration-and-coexistence.md](./12-migration-and-coexistence.md) — 7 problems.

## Capability dependency graph

```
                     ┌──────────────────┐
                     │  Core Directory  │ ← foundation
                     │  (LDAP, DRSUAPI) │
                     └────────┬─────────┘
                              │
            ┌─────────────────┼──────────────────┬────────────────┐
            │                 │                  │                │
            ▼                 ▼                  ▼                ▼
       ┌────────┐        ┌────────┐         ┌────────┐       ┌────────┐
       │  KDC   │        │  Auth  │         │ Policy │       │  Cert  │
       │(Kerb)  │        │Provider│         │ Engine │       │Service │
       └───┬────┘        └───┬────┘         └────┬───┘       └───┬────┘
           │                 │                   │               │
           │                 │                   │               │
           └────────┬────────┘                   │               │
                    │                            │               │
                    ▼                            ▼               ▼
              ┌──────────┐                 ┌──────────┐    ┌──────────┐
              │ Federation│                 │   File   │    │          │
              │ Gateway   │                 │ Gateway  │    │ ...      │
              └──────────┘                 └──────────┘    └──────────┘

                    Cross-cutting (consumed by all):
                    ┌──────────────────────────────────┐
                    │ Client SDK | Operations |        │
                    │ Security | Cross-Platform Parity │
                    │ Migration & Coexistence          │
                    └──────────────────────────────────┘
```

## Problem-to-capability assignment rules

Every problem in the catalog is assigned to exactly one primary capability. The rules:

1. If the problem is about storing/replicating/serving directory data → **Core Directory**.
2. If the problem is about issuing Kerberos tickets → **KDC**.
3. If the problem is about non-Kerberos authentication (NTLM, SASL, smart-card) → **Auth Provider**.
4. If the problem is about GPO/policy distribution and application → **Policy Engine**.
5. If the problem is about certificates, CA, OCSP, enrollment → **Cert Service**.
6. If the problem is about SAML/OIDC/WS-Fed/federation → **Federation Gateway**.
7. If the problem is about SMB/DFS/print/offline files → **File Gateway**.
8. If the problem is about the client-side library/SDK → **Client SDK**.
9. If the problem is about platform-specific gaps (macOS/Linux missing feature X) → **Cross-Platform Parity**.
10. If the problem is about deployment/backup/monitoring → **Operations**.
11. If the problem is about an attack or security mitigation → **Security & Threat Model**.
12. If the problem is about moving from AD to the framework → **Migration & Coexistence**.

When a problem spans multiple capabilities (e.g., krbtgt rotation touches KDC + Security + Operations), it is assigned to its primary capability and the cross-capability impact is described in the problem's "Cross-capability impact" section.

## Per-capability file conventions

Each per-capability file follows this structure:

1. **Capability definition** (one paragraph, lifted from this file).
2. **Summary of problems** (table: PC-NNN × title × severity).
3. **Detailed problem entries** (one per problem, ~500-1000 words each).
4. **Cross-capability impact** (problems from other capabilities that affect this one).
5. **Open research questions specific to this capability**.

## Next: read the per-capability files

Start with [01-core-directory.md](./01-core-directory.md) and work through to [12-migration-and-coexistence.md](./12-migration-and-coexistence.md). Then read [13-open-research-questions.md](./13-open-research-questions.md) and [14-cross-platform-parity-matrix.md](./14-cross-platform-parity-matrix.md).
