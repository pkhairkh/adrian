---
title: Microsoft Open Specifications (MS-*) Reference
audience: senior-engineers
tags: [ms-protocols, open-specifications, reference, ms-adts, ms-kile, ms-drsr]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../01-ad-core/02-ad-cs-cert-services.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../01-ad-core/05-ad-rms-rights.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/07-ntp-time-sync.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../04-group-policy/01-gpo-architecture.md
  - ./02-rfcs-standards.md
  - ./03-source-code-references.md
last_updated: 2026-08-13
---

# Microsoft Open Specifications (MS-*) Reference

Canonical reference for the Microsoft Open Specifications documents relevant to Active Directory. All URLs point to the Microsoft Learn "Open Specifications" library. Each entry: protocol name, current revision / latest published date, URL, primary purpose, and KB files that cite it.

## Microsoft Open Specifications — AD-relevant protocols

| Protocol | Latest revision | URL | Primary purpose | KB files |
|---|---|---|---|---|
| **MS-ADTS** | 31.0 (2026-06) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ Active Directory Technical Specification | Defines the AD data model, schema (attributeSchema/classSchema), DS behavior versions, NC structure, object naming, well-known GUIDs, SPN/UPN rules, PAC format, security descriptor propagation, replication topology concepts | [../01-ad-core/01-ad-ds-internals.md](../01-ad-core/01-ad-ds-internals.md), [../03-directory-schema/01-schema-attributes.md](../03-directory-schema/01-schema-attributes.md), [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| **MS-KILE** | 11.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ | Microsoft's Kerberos protocol extensions (RFC 4120 profile) — PAC usage, FAST, PKINIT, Group Managed Service Accounts, claims-based Kerberos, compound identity | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| **MS-DRSR** | 16.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/ | Directory Replication Service Remote protocol — DRSUAPI interface (UUID `E3514235-8B63-11D0-A26C-00A0C92B955C`), opnums 0-24, DRSGetNCChanges, DRSBind, DRSCrackNames, replication semantics, USN vectors, UTD vectors | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md), [../03-directory-schema/05-replication-internals.md](../03-directory-schema/05-replication-internals.md) |
| **MS-LSAD** | 16.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/ | Local Security Authority (Domain Policy) Remote Protocol — LSA policy enumeration, trust enumeration, secret retrieval | [../03-directory-schema/04-trusts-topology.md](../03-directory-schema/04-trusts-topology.md) |
| **MS-LSARPC** | 16.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsarpc/ | LSA RPC subset — same as MS-LSAD; older name retained for compatibility | [../03-directory-schema/04-trusts-topology.md](../03-directory-schema/04-trusts-topology.md) |
| **MS-NRPC** | 17.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ | Netlogon Remote Protocol — `NetrServerAuthenticate3`, machine secure channel, MS-SNTP authentication, `NetrSamLogon`, NetrLogonGetCapabilities, AES-CFB8 + HMAC-MD5 signing | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md), [../02-protocols/07-ntp-time-sync.md](../02-protocols/07-ntp-time-sync.md), [../10-comparison-matrices/04-auth-flow-comparison.md](../10-comparison-matrices/04-auth-flow-comparison.md) |
| **MS-NLMP** | 36.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/ | NT LAN Manager (NTLM) Authentication Protocol — Type 1/2/3 messages, NTLMv2 response computation, channel binding, MIC, AV_PAIRs, session key derivation | [../02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |
| **MS-SAML** | 1.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-saml/ | Microsoft's profile of SAML 2.0 used by AD FS — token format, claim rules, RP-STS conventions | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **MS-ADFSPIP** | 28.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adfspip/ | AD FS Proxy Integration Protocol — Web Application Proxy (WAP) to AD FS trust establishment, `EstablishProxyTrust` RPC, ADFS token relay | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **MS-RPCE** | 25.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ | Remote Procedure Call Extensions — DCE/RPC common header, PFC_FLAGS, Bind/BindAck, security trailer, auth_type/auth_level, NDR20/NDR64 transfer syntax | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| **MS-SMB2** | 79.0 (2026-06) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ | Server Message Block (SMB) Protocol Versions 2 and 3 — Negotiate, Session Setup, TreeConnect, Create, Read, Write, Close, oplock/lease, signing/encryption (AES-CCM/GCM), pre-auth integrity, multichannel, SMB Direct | [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| **MS-SRVS** | 28.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/ | Server Service Remote Protocol — share enumeration, share creation, NetrShareEnum, NetrShareGetInfo; legacy SRVSVC interface | [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| **MS-WCCE** | 17.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ | Windows Client Certificate Enrollment Protocol — ICertPassage RPC interface (UUID `91b9b93a-57b4-11d0-8f16-00a0484d6c9c`) for cert request/response with AD CS | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **MS-XCEP** | 6.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/ | X.509 Certificate Enrollment Protocol — HTTP-based policy retrieval (CEP endpoint), CEP/CES infrastructure for key-based renewal | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **MS-WSTEP** | 12.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/ | Windows Secure Transaction Enrollment Protocol — HTTP-based cert request/response (CES endpoint), SOAP/WS-Trust, RA-signed cert delivery | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **MS-OCSP** | 18.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ocsp/ | OCSP HTTP-based revocation status protocol — Microsoft profile of RFC 6960, used by AD CS Online Responder | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **MS-DNSP** | 22.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ | Domain Name Service (DNS) Management Protocol — RPC interface for zone/RR management on AD-integrated DNS, dnsNode object storage in DomainDnsZones/ForestDnsZones NCs, `IDnsRpc` interface | [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| **MS-DTYP** | 28.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/ | Windows Data Types — common NDR type definitions (SID, SECURITY_DESCRIPTOR, FILETIME, LARGE_INTEGER, GUID, ACL, SDDL strings) referenced by all other MS-* protocols | [../03-directory-schema/02-ous-containers.md](../03-directory-schema/02-ous-containers.md), [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| **MS-ERREF** | 19.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/ | Windows Error Reporting Reference — common NTSTATUS, Win32 error code, HRESULT definitions | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| **MS-OAPX** | 18.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapx/ | Outlook Access Protocol Extensions — Exchange-related (referenced for legacy RMS-aware mail flow) | (Exchange-only; out of scope) |
| **MS-PAC** | 11.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/ | Privilege Attribute Certificate Data Structure — full PAC_INFO_BUFFER type table, KERB_VALIDATION_INFO, PAC_SIGNATURE_DATA signature types (HMAC-MD5, AES), PAC_UPN_DNS_INFO, PAC_REQUESTER, PAC_BUFFER_TICKET_CHECKSUM (Server 2016+), PAC_FULL_CHECKSUM | [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md), [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| **MS-APDS** | 11.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/ | Authentication Protocol Domain Support — LSA Authentication APIs, Kerberos/NTLM SSP interactions, logon process tokens,`LsaLogonUser` semantics | [../10-comparison-matrices/04-auth-flow-comparison.md](../10-comparison-matrices/04-auth-flow-comparison.md) |
| **MS-RPRN** | 19.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/ | Print System Remote Protocol — `RpcAddPrinter`, `RpcEnumPrinters`, print spooler RPC; relevant for PrintNightmare and AD-integrated print queues | (Print services) |
| **MS-RPCH** | 21.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpch/ | RPC Protocol Extensions — HTTP transport for DCE/RPC (used by Outlook Anywhere, RDP gateway); not central to AD but referenced by AD FS proxy | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **MS-ADFSPIP (repeated above)** | (see above) | (see above) | (see above) | (see above) |

## Additional protocols (referenced by AD core / cross-platform agents)

| Protocol | Latest revision | URL | Purpose | KB files |
|---|---|---|---|---|
| **MS-GPOLINK** | 7.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpolink/ | Group Policy Link Protocol — gPLink attribute format, options bitmask, linking semantics across site/domain/OU | [../04-group-policy/01-gpo-architecture.md](../04-group-policy/01-gpo-architecture.md), [../04-group-policy/02-gpo-processing-order.md](../04-group-policy/02-gpo-processing-order.md) |
| **MS-GPOD** | 22.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpod/ | Group Policy: Directory Access Protocol — GPC object schema (groupPolicyContainer class), gPCFileSysPath, gPCMachineExtensionNames, versionNumber packing | [../04-group-policy/01-gpo-architecture.md](../04-group-policy/01-gpo-architecture.md) |
| **MS-GPFAS** | 5.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/ | Group Policy: Firewall and Advanced Security Protocol — Windows Firewall with Advanced Security GPO schema | [../04-group-policy/04-cse-client-side-extensions.md](../04-group-policy/04-cse-client-side-extensions.md) |
| **MS-RPEFN** | 11.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpefn/ | Replication Policy: Forest Namespace — application partitions (DomainDnsZones, ForestDnsZones), NC head objects | [../03-directory-schema/05-replication-internals.md](../03-directory-schema/05-replication-internals.md) |
| **MS-LSA** | (subset of MS-LSAD) | (subset of MS-LSAD) | LSA core APIs — often bundled with MS-LSAD | [../03-directory-schema/04-trusts-topology.md](../03-directory-schema/04-trusts-topology.md) |
| **MS-SWN** | 9.0 (2024-09) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/ | Service Watchdog Notification Protocol — service failure actions, AD service recovery interactions | (Server role) |
| **MS-WMI** | 17.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/ | WMI Remote Protocol — DCOM interface for WMI queries (used by GPO WMI filters) | [../04-group-policy/02-gpo-processing-order.md](../04-group-policy/02-gpo-processing-order.md) |
| **MS-DCOM** | 24.0 (2025-07) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/ | Distributed Component Object Model Protocol — DCOM extension over MS-RPCE; foundational for WMI, ADUC, AD CS | (many) |
| **MS-WCCE (see above)** | (see above) | (see above) | (see above) | (see above) |

## Subset protocols commonly mislabeled

| Term | Clarification |
|---|---|
| "ADFSPIP" | Alias for MS-ADFSPIP |
| "DRSR" | Alias for MS-DRSR (Directory Replication Service Remote) |
| "DRSUAPI" | Interface name within MS-DRSR; UUID `E3514235-8B63-11D0-A26C-00A0C92B955C` |
| "KILE" | Alias for MS-KILE (Kerberos protocol extensions) |
| "LSARPC" | Interface name within MS-LSAD; UUID `12345778-1234-abcd-ef00-0123456789ab` |
| "NRPC" | Alias for MS-NRPC (Netlogon Remote Protocol) |
| "NLMP" | Alias for MS-NLMP (NTLM) |
| "PAC" | Data structure defined in MS-PAC, embedded in MS-KILE-issued Kerberos tickets |

## Notes on revision history

- Microsoft publishes revision history at each protocol's main page (right-hand "Revision History" tab). The latest revision date in the table above reflects the most recent published revision as of 2026-08-13. Always check the live page for current revision.
- Versions typically change when Windows Server ships a new semi-annual channel or when Microsoft adds new MS-KILE PAC buffer types (e.g., PAC_FULL_CHECKSUM in Server 2016, PAC_REQUESTER in Server 2019).
- The "latest revision date" is the document-level revision date, NOT the protocol version supported by a given Windows Server release. Server 2012 may implement MS-DRSR 12.0; Server 2022 implements 16.0. Backward compatibility is preserved by versioned message structures (e.g., `DRS_MSG_GETCHGREQ_V11` vs `_V8` vs `_V5`).

## How to cite in this KB

When a protocol detail is asserted in any KB file, link to its MS-* document:
```markdown
Per [MS-DRSR §4.1.27](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/...), DRSGetNCChanges (opnum 3) takes ...
```

## See also

- [./02-rfcs-standards.md](./02-rfcs-standards.md) — IETF RFCs and OASIS/ISO standards.
- [./03-source-code-references.md](./03-source-code-references.md) — Open-source implementations of these protocols.
- [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) — Kerberos protocol details (cites MS-KILE, MS-PAC, RFC 4120).
- [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI wire format (cites MS-DRSR, MS-RPCE).
- [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) — PAC structure (cites MS-PAC, MS-KILE).

## How to navigate the Open Specifications library

Each protocol's main page has:

1. **Overview / Abstract** — high-level purpose.
2. **Table of Contents** — section structure (typically: Message Syntax, Message Processing, Protocol Details, Data Model, Examples).
3. **Sections** — every section has its own URL fragment (e.g. `ms-drsr/...dc49770b-1f1c-432d-9bf3-8f1c4adc2a17` for `DRSGetNCChanges`).
4. **Revision History** — right-hand panel; documents every change with date and section link.
5. **Products reaching this protocol** — list of Microsoft products and versions that implement this protocol.

## Reading order recommendations

For each protocol category, the recommended reading order to build mental model:

### Kerberos / PAC
1. RFC 4120 (Kerberos V5) — foundational.
2. MS-KILE — Microsoft's profile (FAST, PKINIT, PAC).
3. MS-PAC — PAC data structure.
4. RFC 4556 (PKINIT) — smart-card logon.
5. RFC 6806 (FAST) — armoring.

### LDAP / Schema
1. RFC 4510-4519 — base LDAPv3 spec.
2. MS-ADTS §3 — LDAP message processing details.
3. MS-ADTS §3.1.1 — LDAP controls and extensions.
4. MS-DTYP — common data types referenced.

### DRS / Replication
1. MS-RPCE — DCE/RPC common header, Bind, auth.
2. MS-DRSR — DRSUAPI interface (opnums 0-24).
3. MS-ADTS §3 — NC structure, USN, InvocationID.

### SMB
1. MS-SMB2 — SMB2/3 wire format.
2. MS-SRVS — share enumeration (legacy SRVSVC).
3. MS-RPCE — DCE/RPC over SMB (used by SRVSVC, SPOOLSS, etc.).
4. MS-DTYP — common data types (SID, SD, FILETIME).

### Trusts / Cross-forest
1. MS-ADTS §6.1.6 — trust attribute semantics.
2. MS-LSAD — trust enumeration (LSA RPC).
3. RFC 4120 §3.3.3 — cross-realm TGT referral.
4. MS-KILE — claims, compound identity.

### Certificate Services
1. RFC 5280 — X.509 base.
2. MS-WCCE — ICertPassage RPC (request/response).
3. MS-XCEP — CEP (policy) HTTP endpoint.
4. MS-WSTEP — CES (enrollment) HTTP endpoint.
5. RFC 6960 — OCSP.

### Federation
1. SAML 2.0 Core/Protocols/Bindings/Metadata (OASIS).
2. MS-SAML — Microsoft's profile.
3. WS-Federation 1.2 (OASIS).
4. MS-ADFSPIP — Web Application Proxy trust.

## Common protocol interdependencies

| Protocol | Depends on | Used by |
|---|---|---|
| MS-DRSR | MS-RPCE, MS-DTYP, MS-ERREF | DRSUAPI replication; impacket `secretsdump.py` |
| MS-NRPC | MS-RPCE, MS-DTYP | Machine secure channel; DCSync (for NetrServerAuthenticate3) |
| MS-KILE | RFC 4120, RFC 4121, MS-PAC | AD Kerberos; AD authentication |
| MS-PAC | MS-DTYP | AD Kerberos tickets; authorization |
| MS-SMB2 | MS-DTYP, MS-RPCE (over SMB), MS-SRVS (legacy) | File shares, IPC$ (named pipes), DCE/RPC transport |
| MS-WCCE | MS-RPCE, RFC 5280 | AD CS cert enrollment; certmonger (via custom protocol) |
| MS-XCEP | RFC 5280, HTTPS | CEP HTTP endpoint; certmonger CEP plugin |
| MS-WSTEP | RFC 5280, HTTPS, WS-Trust | CES HTTP endpoint; key-based renewal |
| MS-ADFSPIP | MS-RPCE, MS-SAML, WS-Federation | AD FS proxy trust; WAP |
| MS-ADTS | MS-DTYP, MS-DRSR, MS-KILE, MS-PAC | All AD core |
| MS-GPOD | MS-ADTS, MS-GPOLINK | Group Policy container (GPC) |
| MS-GPOLINK | MS-ADTS | gPLink attribute format |
| MS-DNSP | MS-ADTS, RFC 2136, RFC 3645 | AD-integrated DNS management |

## Frequently-confused pairs

| Confused terms | Distinction |
|---|---|
| MS-LSAD vs MS-LSARPC | Same protocol, two names. MS-LSAD is current canonical; MS-LSARPC is legacy. Both cover LSA policy + trust enumeration. |
| MS-WCCE vs MS-XCEP | MS-WCCE is the legacy ICertPassage RPC (cert request). MS-XCEP is the HTTP policy retrieval (CEP). |
| MS-XCEP vs MS-WSTEP | MS-XCEP retrieves CA policy (CEP). MS-WSTEP actually requests the cert (CES). Both HTTP-based, paired. |
| MS-DRSR vs DRSUAPI | MS-DRSR is the protocol document; DRSUAPI is the interface name within it (the IDL). |
| MS-RPCE vs DCE/RPC | MS-RPCE is Microsoft's extensions to OSF DCE/RPC. Wire-compatible at the base layer. |
| MS-PAC vs PAC | PAC is the data structure (originally in RFC 4120); MS-PAC is Microsoft's profile with extended buffer types. |
| MS-SMB2 vs SMB2 | Same. MS-SMB2 is the Open Specifications document; "SMB2" is the protocol name. |
| MS-ADFSPIP vs MS-ADFS | Only MS-ADFSPIP exists (proxy integration). "MS-ADFS" is informal for the AD FS feature. |

## Document-level revision tracking

The Microsoft Open Specifications library publishes a revision history tab per protocol. The revision dates in this document reflect the latest published revision as of 2026-08-13. To track changes:

1. Subscribe to RSS feeds at the Open Specifications blog: https://learn.microsoft.com/en-us/openspecs/blog
2. Watch for "[MS-XXX] revision published" announcements.
3. For per-protocol changelog, see each protocol's "Revision History" tab.

Significant recent (2024-2026) revisions worth tracking:
- MS-SMB2 added SMB 3.1.1 dialect changes (encryption algorithm negotiation).
- MS-KILE added claims-based Kerberos support and PAC_FULL_CHECKSUM.
- MS-DRSR updated DRSUAPI opnum 27 (`DRSUpgradeViewInfo2`) for newer schema.
- MS-PAC added PAC_REQUESTER (0x12) and PAC_FULL_CHECKSUM (0x13) buffers.
- MS-WCCE maintained backward compatibility for Server 2008 R2 → Server 2022 mixed CA hierarchies.
