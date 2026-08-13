---
title: Active Directory Knowledge Base
audience: Senior Engineers
depth: Implementation-level (protocol + source-code + registry/IDL)
tags: [active-directory, kerberos, ldap, smb, gpo, pki, adfs, sssd, winbind, opendirectory, freeipa, cross-platform]
last_updated: 2026-08-13
---

# Active Directory Knowledge Base

An exhaustive, implementation-level reference covering **Microsoft Active Directory** — its services, protocols, schema, GPO, PKI, federation, and file/print stacks — and the **equivalent stacks on macOS and Linux/UNIX** (OpenDirectory, SSSD, Winbind, Realmd, PBIS, FreeIPA, Jamf, Platform SSO, and pure open-source bundles).

Every file is written for **senior engineers**. We assume you already know what an SPN is; we will instead tell you the exact `attributeID` of `servicePrincipalName` (1.2.840.113556.1.4.14), the IDL of `DRSBind` (`[uuid(2) ...]`), the SSSD source file that handles the GPO access-control check (`src/providers/ad/ad_gpo.c`), and the Wireshark display filter that proves a ticket was encrypted with RC4-HMAC (`kerberos.etype == 0x17`).

---

## How to use this KB

- **Start here:** [`00-overview/01-active-directory-overview.md`](./00-overview/01-active-directory-overview.md)
- **Acronyms:** [`00-overview/05-glossary.md`](./00-overview/05-glossary.md)
- **Feature → OS lookup:** [`10-comparison-matrices/01-feature-os-matrix.md`](./10-comparison-matrices/01-feature-os-matrix.md)
- **Protocol → implementation lookup:** [`10-comparison-matrices/02-protocol-implementation-matrix.md`](./10-comparison-matrices/02-protocol-implementation-matrix.md)
- **Working code:** [`11-code-examples/`](./11-code-examples/)
- **Authoritative specs:** [`12-references/`](./12-references/)
- **Framework design problems:** [`13-problem-catalog/`](../catalog/) — 130 problems across 12 capabilities, with cross-platform parity matrix and 262 open research questions

Every MD file carries YAML frontmatter with `tags:` and `related:` fields. Use GitHub's tag-search or follow `related:` links to traverse.

---

## Directory layout

### `00-overview/` — Foundational context
| File | What it covers |
|------|----------------|
| [01-active-directory-overview.md](./00-overview/01-active-directory-overview.md) | What AD is, what it supplies, the five AD roles (DS/CS/FS/LDS/RMS), threat model |
| [02-ad-architecture.md](./00-overview/02-ad-architecture.md) | LSASS, NTDS.DIT, ESE/JET blue, the AD driver stack, RPC dispatcher |
| [03-domains-forests-trees.md](./00-overview/03-domains-forests-trees.md) | Domain tree topology, trust directions/transitivity, forest boundaries |
| [04-fsmo-roles.md](./00-overview/04-fsmo-roles.md) | The 5 FSMO roles, seizure semantics, `netdom query fsmo`, MS-DRSR binding |
| [05-glossary.md](./00-overview/05-glossary.md) | Every acronym: SPN, UPN, TGT, TGS, PAC, KDC, GPO, GPC, GPT, GC, IGCA, RODC, … |

### `01-ad-core/` — The five AD server roles
| File | What it covers |
|------|----------------|
| [01-ad-ds-internals.md](./01-ad-core/01-ad-ds-internals.md) | AD DS internals: DSA, DSAUNICODE, INTID, DRSUAPI interface, DRSR replication |
| [02-ad-cs-cert-services.md](./01-ad-core/02-ad-cs-cert-services.md) | AD CS: CA types, CA database, policy + exit modules, CertSrv Request RPC |
| [03-ad-fs-federation.md](./01-ad-core/03-ad-fs-federation.md) | AD FS: farm topology, trust proxy, claims pipeline, ADFS service principals |
| [04-ad-lds-adam.md](./01-ad-core/04-ad-lds-adam.md) | AD LDS (formerly ADAM): instance isolation, application partitions, no GC |
| [05-ad-rms-rights.md](./01-ad-core/05-ad-rms-rights.md) | AD RMS: licensing pipeline, use licenses, CLC, IL, machine activation |

### `02-protocols/` — Wire-level deep dives
| File | What it covers |
|------|----------------|
| [01-kerberos-internals.md](./02-protocols/01-kerberos-internals.md) | RFC 4120 + MS-KILE: AS-REQ/AS-REP/TGS-REQ/TGS-REP, etypes, PA-DATA, FAST |
| [02-ldap-protocol.md](./02-protocols/02-ldap-protocol.md) | RFC 4511 + MS-ADTS: controls (SD flags, paged, tree-delete), extended ops |
| [03-smb-cifs-protocol.md](./02-protocols/03-smb-cifs-protocol.md) | SMB 1/2/3 dialects, dialect 0x311, signing, encryption, multichannel |
| [04-ntlm-internals.md](./02-protocols/04-ntlm-internals.md) | NTLMv1/v2, NTLMSSP, challenge/response, channel binding, EPHEMERAL |
| [05-dns-dynamic-updates.md](./02-protocols/05-dns-dynamic-updates.md) | RFC 2136 + MS-DNSP: AD-integrated zones, scavenging, _msdcs, secure updates |
| [06-rpc-dcerpc-ms-drsr.md](./02-protocols/06-rpc-dcerpc-ms-drsr.md) | DCE/RPC over SMB/TCP, IDL, MS-DRSR (DRSBind/DRSGetNCChanges/DRSUAPI) |
| [07-ntp-time-sync.md](./02-protocols/07-ntp-time-sync.md) | W32Time, MS-SNTP, auth'd NTP, the 5-minute Kerberos skew window |
| [08-spn-upn-pac.md](./02-protocols/08-spn-upn-pac.md) | SPN uniqueness, UPN routing, PAC structures (LOGON_INFO, PAC_SIGNATURE) |

### `03-directory-schema/` — Logical directory model
| File | What it covers |
|------|----------------|
| [01-schema-attributes.md](./03-directory-schema/01-schema-attributes.md) | attributeSchema, classSchema, OID allocations, systemFlags, searchFlags |
| [02-ous-containers.md](./03-directory-schema/02-ous-containers.md) | OU vs container, `instanceType`, `systemFlags`, well-known GUIDs |
| [03-global-catalog.md](./03-directory-schema/03-global-catalog.md) | GC partial attribute set, isMemberOfPartialAttributeSet, GC locator |
| [04-trusts-topology.md](./03-directory-schema/04-trusts-topology.md) | trustedDomain objects, trustAuthBlob, SID filtering, selective auth |
| [05-replication-internals.md](./03-directory-schema/05-replication-internals.md) | USN, DSA InvocationID, high-watermark, UTD vector, USN rollback |

### `04-group-policy/` — GPO architecture
| File | What it covers |
|------|----------------|
| [01-gpo-architecture.md](./04-group-policy/01-gpo-architecture.md) | GPC in AD, GPT in SYSVOL, gPLink/gPOptions, version mismatch |
| [02-gpo-processing-order.md](./04-group-policy/02-gpo-processing-order.md) | LSDOU, WMIFilters, security filtering, slow-link, async reboot |
| [03-admx-templates.md](./04-group-policy/03-admx-templates.md) | ADMX vs ADM, central store, language-neutral policyElement, RSAT |
| [04-cse-client-side-extensions.md](./04-group-policy/04-cse-client-side-extensions.md) | Each CSE GUID, Registry, Security, Scripts, Folder Redir, AppLocker |
| [05-gpt-gpc-structure.md](./04-group-policy/05-gpt-gpc-structure.md) | GPT.INI, Machine/User, Registry.pol format, scripts.ini |

### `05-pki-certs/` — AD Certificate Services
| File | What it covers |
|------|----------------|
| [01-ad-cs-architecture.md](./05-pki-certs/01-ad-cs-architecture.md) | Enterprise vs Standalone CA, root/intermediate, CA database, registry |
| [02-certificate-templates.md](./05-pki-certs/02-certificate-templates.md) | Version 1/2/3 templates, ACLs, application policies, subject name rules |
| [03-autoenrollment.md](./05-pki-certs/03-autoenrollment.md) | GRP-Autoenroll, XCEP, MS-WCCE, MS-XCEP, key archival, renewal |
| [04-ocsp-crl.md](./05-pki-certs/04-ocsp-crl.md) | CRL/ΔCRL, AIA/CDP, OCSP responder, nonce, ID-PKIX-OCSP-NoCheck |

### `06-federation-sso/` — AD FS and modern federation
| File | What it covers |
|------|----------------|
| [01-adfs-architecture.md](./06-federation-sso/01-adfs-architecture.md) | Farm internals, ADFS service account, Artifact DB, Config DB, WAP |
| [02-saml-ws-fed.md](./06-federation-sso/02-saml-ws-fed.md) | SAML 2.0 + WS-Federation, passives, RST/RSTR, metadata exchange |
| [03-claims-rules.md](./06-federation-sso/03-claims-rules.md) | Claims rule language, Issuance Transform, Regex, custom attribute stores |
| [04-oidc-oauth.md](./06-federation-sso/04-oidc-oauth.md) | ADFS 2016+ OAuth2/OIDC endpoints, scope/claim mapping, refresh tokens |

### `07-file-print/` — File and print services
| File | What it covers |
|------|----------------|
| [01-smb-shares-internals.md](./07-file-print/01-smb-shares-internals.md) | srvnet, srv2, lanmanserver, share ACLs, AccessBasedEnumeration |
| [02-dfs-n-dfs-r.md](./07-file-print/02-dfs-n-dfs-r.md) | DFS-N PKT cache, DFS-R version vectors, USN journal, RDC |
| [03-print-services.md](./07-file-print/03-print-services.md) | Print Spooler RPC, MS-RPRN, PrintNightmare, driver isolation |
| [04-offline-files.md](./07-file-print/04-offline-files.md) | CSC, sync center, transparent caching, conflict resolution |

### `08-macos-equivalents/` — macOS integration
| File | What it covers |
|------|----------------|
| [01-opendirectory-internals.md](./08-macos-equivalents/01-opendirectory-internals.md) | opendirectoryd, OD nodes, plug-in architecture, OD schema |
| [02-dscl-dsconfigad.md](./08-macos-equivalents/02-dscl-dsconfigad.md) | dscl/dscacheutil, dsconfigad, Directory Utility, /LDAPv3 binding |
| [03-jamf-connect-pro.md](./08-macos-equivalents/03-jamf-connect-pro.md) | Jamf Connect auth pipeline, Kerberos extension, PSSO hooks |
| [04-platform-sso-extension.md](./08-macos-equivalents/04-platform-sso-extension.md) | macOS 13+ PSSO Extension, Device Registration, SEP key storage |
| [05-kerberos-sso-extension.md](./08-macos-equivalents/05-kerberos-sso-extension.md) | Apple's Kerberos MDM payload, keychain ticket storage, auto-renew |
| [06-enterprise-connect-nomad.md](./08-macos-equivalents/06-enterprise-connect-nomad.md) | Enterprise Connect, NoMAD, NoLoAD, NoMAD Login AD adapter |
| [07-third-party-agents-mac.md](./08-macos-equivalents/07-third-party-agents-mac.md) | Centrify DirectControl, BeyondTrust PBIS for Mac, AdmitMac, DAVE |
| [09-mac-mdm-gpo-equivalents.md](./08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) | Configuration Profiles as GPO equivalent, MCX legacy, DDM |

### `09-linux-equivalents/` — Linux/UNIX integration
| File | What it covers |
|------|----------------|
| [01-sssd-ad-provider.md](./09-linux-equivalents/01-sssd-ad-provider.md) | sssd.conf `[domain/ad]`, ad_domain, ad_server, id_provider=ad |
| [02-sssd-id-mapping.md](./09-linux-equivalents/02-sssd-id-mapping.md) | Range allocation, ldap_idmap_range, slice algorithm, RID compat |
| [03-sssd-gpo-access.md](./09-linux-equivalents/03-sssd-gpo-access.md) | ad_gpo_access_control, ini file parser, CSE Computer\WindowsSecurity |
| [04-winbind-internals.md](./09-linux-equivalents/04-winbind-internals.md) | winbindd architecture, idmap backends, wbinfo, rpc_pipe_open |
| [05-samba-tool-net-ads.md](./09-linux-equivalents/05-samba-tool-net-ads.md) | `net ads join`, `samba-tool domain`, keytab generation, MS-DRSR client |
| [06-realmd-join-flow.md](./09-linux-equivalents/06-realmd-join-flow.md) | realmd DBus service, realm command, auto-config of SSSD/PAM/NSS |
| [07-pbis-powerbroker.md](./09-linux-equivalents/07-pbis-powerbroker.md) | PBIS Open architecture, lwsmd, domainjoin-cli, lwreg, eventlog |
| [08-freeipa-trust.md](./09-linux-equivalents/08-freeipa-trust.md) | FreeIPA-AD cross-forest trust, two-way transitive, SID mapping |
| [09-openldap-mit-kerberos.md](./09-linux-equivalents/09-openldap-mit-kerberos.md) | Manual: slapd + krb5 + nslcd, no AD-specific glue |
| [10-pam-nss-stack.md](./09-linux-equivalents/10-pam-nss-stack.md) | PAM stack, pam_sss, pam_winbind, nsswitch.conf, systemd-homed |

### `10-comparison-matrices/` — Side-by-side lookups
| File | What it covers |
|------|----------------|
| [01-feature-os-matrix.md](./10-comparison-matrices/01-feature-os-matrix.md) | AD feature × {macOS, Linux SSSD, Linux Winbind, FreeIPA, PBIS} |
| [02-protocol-implementation-matrix.md](./10-comparison-matrices/02-protocol-implementation-matrix.md) | Protocol × {Windows Heimdal, MIT, Apple Heimdal, Samba, MS} |
| [03-tool-function-matrix.md](./10-comparison-matrices/03-tool-function-matrix.md) | Function (find user / reset password / join) × OS-specific tool |
| [04-auth-flow-comparison.md](./10-comparison-matrices/04-auth-flow-comparison.md) | Step-by-step auth flow side-by-side: Win / Mac / Linux |
| [05-gpo-equivalents-matrix.md](./10-comparison-matrices/05-gpo-equivalents-matrix.md) | ADMX setting × {mcx, Profiles, SSSD, FreeIPA HBAC, Ansible} |

### `11-code-examples/` — Working code and config
| File | What it covers |
|------|----------------|
| [01-powershell-ad-cmdlets.md](./11-code-examples/01-powershell-ad-cmdlets.md) | RSAT-AD-PowerShell recipes, Get-ADUser, replication, GPO |
| [02-sssd-conf-recipes.md](./11-code-examples/02-sssd-conf-recipes.md) | sssd.conf / krb5.conf / smb.conf / realmd.conf commented examples |
| [03-macos-cli-recipes.md](./11-code-examples/03-macos-cli-recipes.md) | dscl, dsconfigad, profiles, klist, configurator, plutil |
| [04-wireshark-tshark-filters.md](./11-code-examples/04-wireshark-tshark-filters.md) | Display filters for Kerberos / LDAP / SMB / DRSR, tshark CLI |
| [05-python-impacket-examples.md](./11-code-examples/05-python-impacket-examples.md) | ldap3, impacket, pywin32, gssapi, pyspnego recipes |

### `12-references/` — Authoritative sources
| File | What it covers |
|------|----------------|
| [01-ms-protocols-reference.md](./12-references/01-ms-protocols-reference.md) | MS-ADTS, MS-KILE, MS-DRSR, MS-WCCE, MS-LSAD, MS-RPCE, … |
| [02-rfcs-standards.md](./12-references/02-rfcs-standards.md) | RFC 4120/4511/4512/4513/5280/6750/7515/7636/2136/… |
| [03-source-code-references.md](./12-references/03-source-code-references.md) | Samba, SSSD, Heimdal, MIT, Apple CFNetwork, OpenDirectory paths |

### `13-problem-catalog/` — Framework design problem catalog
| File | What it covers |
|------|----------------|
| [README.md](../catalog/README.md) | Master index — 130 problems across 12 capabilities |
| [00-framework-capabilities.md](../catalog/00-framework-capabilities.md) | Capability taxonomy, dependency graph, problem-to-capability map |
| [01-core-directory.md](../catalog/01-core-directory.md) | 22 problems: DRSUAPI, replication, storage, schema, FSMO, multi-tenancy |
| [02-kdc.md](../catalog/02-kdc.md) | 13 problems: MS-KILE, PAC, FAST, PKINIT, krbtgt rotation, kpasswd |
| [03-auth-provider.md](../catalog/03-auth-provider.md) | 7 problems: NTLM deprecation, smart-card, token abstraction |
| [04-policy-engine.md](../catalog/04-policy-engine.md) | 14 problems: GPO format, ADMX, CSEs, declarative policy |
| [05-cert-service.md](../catalog/05-cert-service.md) | 11 problems: AD CS, templates, autoenroll, OCSP, key archival |
| [06-federation-gateway.md](../catalog/06-federation-gateway.md) | 10 problems: AD FS, SAML, OIDC, claims, WAP replacement |
| [07-file-gateway.md](../catalog/07-file-gateway.md) | 7 problems: SMB, DFS-N, DFS-R, print, offline files |
| [08-client-sdk.md](../catalog/08-client-sdk.md) | 9 problems: unified SDK, SSPI-equivalent, ticket cache, keytab |
| [09-cross-platform-parity.md](../catalog/09-cross-platform-parity.md) | 12 problems: macOS/Linux gaps, identity stack fragmentation |
| [10-operations.md](../catalog/10-operations.md) | 10 problems: deploy, monitor, backup, schema upgrade, DR |
| [11-security-threat-model.md](../catalog/11-security-threat-model.md) | 8 problems with STRIDE: Kerberoasting, DCSync, golden ticket, NTLM relay |
| [12-migration-and-coexistence.md](../catalog/12-migration-and-coexistence.md) | 7 problems: sidHistory, GPO translation, client switchover |
| [13-open-research-questions.md](../catalog/13-open-research-questions.md) | 262 ORQs consolidated across all 130 problems, 3-tier prioritization |
| [14-cross-platform-parity-matrix.md](../catalog/14-cross-platform-parity-matrix.md) | 130-row matrix: every problem × {Windows, macOS, Linux, cross-platform} |

---

## Cross-reference conventions

Every file's YAML frontmatter includes:

```yaml
---
title: ...
audience: senior-engineers
tags: [list, of, lowercase, tags]
related:
  - ../02-protocols/01-kerberos-internals.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
---
```

- `tags` drives GitHub-style tag search.
- `related` provides curated "see also" links.
- All relative paths are POSIX-style from the file's own directory.

---

## Standards for every file in this KB

1. **Depth floor.** Every file is implementation-level: protocol messages with hex offsets, source-file paths in `path/to/file.c:function()` form, registry keys with full paths, IDL fragments where relevant.
2. **Code blocks.** Every protocol/service file has at least: (a) a Wireshark display filter, (b) a config or PowerShell example, (c) a Python snippet where appropriate.
3. **Cross-platform bridge.** Every AD-side file ends with a "Equivalents" subsection linking to the macOS and Linux counterpart files.
4. **References.** Every file ends with a "References" section linking to MS-* / RFC / source-wiki.
5. **No filler.** No "in this article we will learn" boilerplate. First sentence states what the component does at implementation level.

---

## License & maintenance

This KB is research material for an internal project. It is a living document — when Microsoft publishes a new MS-ADTS revision or Samba lands a new dialect, update the relevant file and bump its `last_updated` field.
