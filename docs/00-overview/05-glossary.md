---
title: Glossary — Active Directory and Cross-Platform Identity
audience: senior-engineers
tags: [glossary, reference, acronyms]
related:
  - ./01-active-directory-overview.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
---

# Glossary

Compact definitions for every acronym used across the KB. Where the acronym expands to a Microsoft protocol name (MS-*), the MS-* short name is also given; see [`../12-references/01-ms-protocols-reference.md`](../12-references/01-ms-protocols-reference.md) for the full document list.

## A

- **AAGL** — Azure AD Gallery (pre-integrated SaaS app templates).
- **ABE** — Access-Based Enumeration. SMB feature that hides files the caller has no NTFS access to. Implemented in `srv2.sys`.
- **ACE** — Access Control Entry. Element of an ACL; identified by `ACEType` + `Mask` + `Trustee` (see MS-DTYP §2.4.4).
- **ACL** — Access Control List. DACL or SACL.
- **AD** — Active Directory.
- **ADAM** — Active Directory Application Mode (renamed AD LDS in Server 2008).
- **AD CS** — Active Directory Certificate Services.
- **AD DS** — Active Directory Domain Services.
- **AD FS** — Active Directory Federation Services.
- **AD LDS** — Active Directory Lightweight Directory Services.
- **ADMT** — Active Directory Migration Tool.
- **AD RMS** — Active Directory Rights Management Services.
- **AdminSDHolder** — Object in the system container that holds the security descriptor template applied to protected groups (every 60 min by SDPROP).
- **ADM** — Legacy Administrative Template file (UTF-16 INI format).
- **ADMX** — XML-based Administrative Template (introduced Vista/Server 2008).
- **AIA** — Authority Information Access. X.509 extension pointing to the issuer's cert; specified as URL in CA config.
- **AP** — Application Proxy (used as shorthand for Web Application Proxy, WAP).
- **AS-REP** — Kerberos Authentication Service Reply (RFC 4120 §5.4.2).
- **AS-REQ** — Kerberos Authentication Service Request (RFC 4120 §5.4.1).
- **ATQ** — Atomic Time Queue. Internal LSASS timer list used by the KDC service.

## B

- **BCC** — Branch Cache Content. SMB-derived content distribution; mostly superseded by DFS-R.
- **BGL** — Background Garbage List. ESE term.
- **BNO** — Base Named Objects. Object namespace under `\BaseNamedObjects`.

## C

- **CA** — Certificate Authority.
- **CAPI** — CryptoAPI (the older CNG predecessor).
- **CDP** — CRL Distribution Point. X.509 v3 extension listing URLs to fetch the CRL from.
- **CER** — DER- or Base64-encoded X.509 certificate (.cer file).
- **CIFS** — Common Internet File System; pre-SMB2 marketing name.
- **CLC** — Client Licensor Certificate. AD RMS artifact issued to a user; signs all use licenses for that user.
- **CNG** — Cryptography Next Generation. The Windows Vista+ crypto stack replacing CryptoAPI.
- **CredSSP** — Credential Security Support Provider. Used in RDP NLA and CredSSP-based delegation.
- **CRL** — Certificate Revocation List.
- **CSE** — Client-Side Extension. Per-GPO-category handler DLL registered under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{GUID}`.
- **CSP** — Cryptographic Service Provider. CAPI-era crypto module.
- **CSType** — Cryptographic Service Type (PROV_RSA_FULL etc.).

## D

- **DAC** — Discretionary Access Control (in SD terms) or **Dynamic Access Control** (introduced Server 2012, central access rules).
- **DACL** — Discretionary ACL.
- **DC** — Domain Controller.
- **DC locator** — DNS-driven DC discovery via `_ldap._tcp.dc._msdcs.<domain>` SRV records.
- **DCOM** — Distributed COM.
- **DDNS** — Dynamic DNS (RFC 2136).
- **DES** — Data Encryption Standard. Disabled for Kerberos by default since Server 2008.
- **DFSR** — DFS Replication (the modern DFS-R; replaces FRS for SYSVOL since Server 2008 R2).
- **DFSN** — DFS Namespaces (a.k.a. DFS-N).
- **DIT** — Directory Information Tree. The on-disk file is `ntds.dit`.
- **DN** — Distinguished Name (RFC 4514).
- **DNS** — Domain Name System.
- **DRA** — Directory Replication Agent (internal LSASS replicator component).
- **DRSBind** — RPC method that establishes a replication context. See MS-DRSR §4.1.10.
- **DRSGetNCChanges** — RPC method that returns one replication packet. See MS-DRSR §4.1.27.
- **DRSUAPI** — DRS UAPI interface; primary MS-DRSR interface (`[uuid(35) ...]`).
- **DSA** — Directory System Agent. The actual DS process (NTDS.DIT + LSASS-side worker).
- **DSHEUR** — DS heuristic flag, stored on `cn=Directory Service,cn=Windows NT,...,cn=Services,cn=Configuration`.
- **DSRUN** — DS RUN key for service boot-time tasks.

## E

- **EAP** — Extensible Authentication Protocol.
- **ESE** — Extensible Storage Engine (a.k.a. JET Blue). NTDS.DIT database engine.
- **EFS** — Encrypting File System.
- **EPHEMERAL** — NTLMSSP flag indicating the session key is not exported (see MS-NLMP §3.2.5.1.2).

## F

- **FAST** — Flexible Authentication Secure Tunneling (RFC 6806, a.k.a. Kerberos armoring).
- **FIDO2** — Fast IDentity Online v2; supports WebAuthn. Apple Platform SSO supports FIDO2 since macOS 14.
- **FSMO** — Flexible Single Master Operations. The five single-master roles. See [`./04-fsmo-roles.md`](./04-fsmo-roles.md).
- **FRS** — File Replication Service (legacy; deprecated Server 2012 R2, removed Server 2019).

## G

- **GC** — Global Catalog. Partial-attribute read-only copy of every domain in the forest.
- **GCSPN** — Global Catalog Service Principal Name (a non-standard short form, the SPN is `GC/dc.forest/root` form).
- **GPO** — Group Policy Object.
- **GPC** — Group Policy Container (the AD-side half of a GPO; under `cn=Policies,cn=System,<DN>`).
- **GPT** — Group Policy Template (the SYSVOL-side half; `\\<domain>\SYSVOL\<domain>\Policies\{GUID}`).
- **gPLink** — Multivalued attribute on a container linking to one or more GPOs.

## H

- **HBAC** — Host-Based Access Control. FreeIPA term equivalent to "GPO user-targeting + security filtering".
- **HSM** — Hardware Security Module.
- **HWK** — High-WaterMark. USN value sent in replication indicating "give me everything after this".

## I

- **IAG** — Identity Awareness Gateway (proprietary term, not AD-standard).
- **IDB** — Information Database (ESE internal).
- **IL** — Issuance License. AD RMS artifact bound to protected content; lists rights + authorized users.
- **IPC** — Inter-Process Communication.
- **IPSec** — IP Security.

## J

- **JET** — Joint Engine Technology. Microsoft's database engine family (Blue = ESE; Red = Exchange).

## K

- **KCC** — Knowledge Consistency Checker. Runs every 15 min on every DC to compute the replication topology.
- **KDC** — Key Distribution Center. In AD, the KDC service runs in LSASS on every DC.
- **Kerberos** — Network authentication protocol (RFC 4120). AD implements MS-KILE profile.
- **KILE** — Kerberos Interoperability Licensing Extension (Microsoft's Kerberos profile name in MS-KILE).
- **KPASSWD** — Set/change password protocol (RFC 3244). Port 464.
- **KRB5** — MIT Kerberos V5.
- **KRB-AP-REP / AP-REQ** — Application-layer Kerberos messages.

## L

- **LAPS** — Local Administrator Password Solution.
- **LDAP** — Lightweight Directory Access Protocol (RFC 4510-4519).
- **LDP** — Microsoft's LDAP browsing utility (`ldp.exe`).
- **LFS** — Log File Service. ESE component.
- **LKD** — Live Kernel Dump.
- **LPC** — Local Procedure Call (in-process RPC variant).
- **LsaLogonUser** — LSASS API entry point for all interactive/network logons (`secur32.dll`/`ksecdd.sys`).
- **LSA** — Local Security Authority.
- **LSASS** — LSA Subsystem Service (`lsass.exe`).

## M

- **MAPI** — Messaging Application Programming Interface.
- **mcx** — Managed Client Extensions (legacy macOS managed preferences mechanism, replaced by `Profiles`).
- **MDM** — Mobile Device Management.
- **MFA** — Multi-Factor Authentication.
- **MS-ADTS** — Microsoft Active Directory Technical Specification ([MS-ADTS]).
- **MS-DRSR** — Directory Replication Service Remote Protocol.
- **MS-KILE** — Kerberos Protocol Extensions.
- **MS-NLMP** — NT LAN Manager (NTLM) protocol spec.
- **MS-RPCE** — Remote Procedure Call Extensions.
- **MS-SMB2** — Server Message Block 2.x.
- **MS-WCCE** — Windows Client Certificate Enrollment Protocol.
- **MS-XCEP** — X.509 Certificate Enrollment Protocol.
- **MSA** — Managed Service Account (sMSA) or Group Managed Service Account (gMSA).

## N

- **NC** — Naming Context. A contiguous subtree that replicates independently (Domain NC, Configuration NC, Schema NC, Application NC).
- **NDR** — Network Data Representation (DCE/RPC wire format).
- **NDIS** — Network Driver Interface Specification.
- **NDES** — Network Device Enrollment Service (SCEP for network gear).
- **Netlogon** — Service implementing MS-NRPC; runs secure channel to DC.
- **NFS** — Network File System.
- **NGC** — Next Generation Credentials (Microsoft Passport for Work).
- **NLTEST** — Netlogon test utility (`nltest.exe`).
- **NPS** — Network Policy Server (Microsoft RADIUS).
- **NRPC** — Netlogon Remote Protocol. MS-NRPC.
- **NSS** — Name Service Switch (Linux `/etc/nsswitch.conf`).
- **NTDS.DIT** — NT Directory Services Database (the on-disk AD store).
- **NTFS** — New Technology File System.
- **NTLM** — NT LAN Manager (challenge-response authentication, see MS-NLMP).
- **NTLMSSP** — NTLM Security Support Provider.

## O

- **OCSP** — Online Certificate Status Protocol (RFC 6960).
- **OD** — OpenDirectory (macOS directory service).
- **OID** — Object Identifier (e.g., 1.2.840.113556 = Microsoft).
- **OU** — Organizational Unit.
- **OVAL** — Open Vulnerability and Assessment Language.

## P

- **PAC** — Privilege Attribute Certificate. Embedded in Kerberos tickets; signed KDC-supplied authorization data (LOGON_INFO, LOGON_INFO2, PAC_CLIENT_INFO, PAC_SIGNATURE_DATA, UPN_DNS_INFO, REQUESTER, FULL_PKT-CHECKSUM).
- **PAM** — Pluggable Authentication Modules (Linux).
- **PDC** — Primary Domain Controller (legacy SAM term) or PDC Emulator (FSMO role).
- **PFX** — Personal Information Exchange (.pfx, PKCS#12 archive of cert + private key).
- **PKI** — Public Key Infrastructure.
- **PKINIT** — Public Key Cryptography for Initial Authentication in Kerberos (RFC 4556).
- **PRT** — Primary Refresh Token (Azure AD).
- **PSSO** — Platform Single Sign-On (macOS 13+, sometimes called PSSO Ext).

## R

- **RADIUS** — Remote Authentication Dial-In User Service (RFC 2865).
- **RBAC** — Role-Based Access Control.
- **RDC** — Remote Differential Compression. DFS-R bandwidth optimizer.
- **RDP** — Remote Desktop Protocol.
- **REF** — Referral (LDAP).
- **REP** — Response.
- **REPADMIN** — Replication Administration utility.
- **REQ** — Request.
- **RID** — Relative Identifier (the S-1-5-21-domain-rid form).
- **RODC** — Read-Only Domain Controller.
- **ROPC** — Resource Owner Password Credentials (OAuth2 grant; deprecated).
- **RPC** — Remote Procedure Call. Microsoft's DCE/RPC variant.
- **RPCE** — RPC Extensions (MS-RPCE).

## S

- **S4U** — Service-for-User (Kerberos protocol extension: S4U2Self + S4U2Proxy; constrained delegation).
- **SACL** — System ACL (audit ACEs).
- **SAML** — Security Assertion Markup Language.
- **SCEP** — Simple Certificate Enrollment Protocol (RFC 8894).
- **SCM** — Service Control Manager.
- **SD** — Security Descriptor (DACL + SACL + Owner + Group; see MS-DTYP §2.4.6).
- **SDPROP** — Security Descriptor Propagator. LSASS thread applying AdminSDHolder every 60 min.
- **SEP** — Secure Enclave Processor (Apple T2/M-series).
- **SID** — Security Identifier.
- **SIDHistory** — Attribute used during migrations; carries old-domain SIDs.
- **SMB** — Server Message Block.
- **SME** — Subject Mapping Engine (used by DAC).
- **SMSO** — Single Master Scope Operation (synonym for FSMO).
- **SPN** — Service Principal Name. Format `service/host@REALM`. Stored on `servicePrincipalName` attribute (OID 1.2.840.113556.1.4.14).
- **SPNEGO** — Simple and Protected GSSAPI Negotiation Mechanism (RFC 4178).
- **SQL** — Structured Query Language.
- **SRV** — Service DNS record (RFC 2782).
- **SSO** — Single Sign-On.
- **SSSD** — System Security Services Daemon (Linux).
- **StaleCS** — Stale Client-Side (an internal AD GPO state, not standardized).
- **SYSVOL** — Domain-wide share replicated via DFS-R; holds GPT, logon scripts.

## T

- **TACACS+** — Terminal Access Controller Access-Control System Plus (Cisco AAA protocol).
- **TGS** — Ticket-Granting Service (RFC 4120 §5.5).
- **TGT** — Ticket-Granting Ticket (returned by AS-REP).
- **TLS** — Transport Layer Security.
- **TLV** — Type-Length-Value.
- **TPM** — Trusted Platform Module.

## U

- **UDC** — Universal Group Caching (alternative to GC for branch sites).
- **UDV** — Up-To-Dateness Vector. Per-DC per-NC vector of ` InvocationID → USN` indicating "I have all changes from this DC up to this USN".
- **UPN** — User Principal Name (`user@forest-root`). Stored on `userPrincipalName` (OID 1.2.840.113556.1.4.666).
- **USN** — Update Sequence Number. Monotonic per-DC counter; persisted in the DSA object.

## V

- **VSS** — Volume Shadow Copy Service.

## W

- **WAP** — Web Application Proxy (Server 2012 R2+ replacement for UAG; ADFS reverse proxy).
- **WCCE** — Windows Client Certificate Enrollment (MS-WCCE).
- **WMI** — Windows Management Instrumentation.
- **WS-Fed** — Web Services Federation (passive profile for SSO).
- **WS-Trust** — Web Services Trust (active profile; issues token via RST/RSTR).

## X

- **X.509** — The PKI certificate standard (RFC 5280 profile).
- **XCEP** — X.509 Certificate Enrollment Protocol (MS-XCEP).

## Y / Z

- **YubiKey** — Hardware OTP/FIDO2 key.
- **ZFS** — Zettabyte File System (Linux/macOS alternative file system).

---

## See also

- Microsoft Open Specifications: <https://learn.microsoft.com/en-us/openspecs/>
- IETF RFCs: <https://www.rfc-editor.org/>
- Samba source: <https://github.com/samba-team/samba>
- SSSD source: <https://github.com/SSSD/sssd>
- Heimdal source: <https://github.com/heimdal/heimdal>
- MIT Kerberos source: <https://github.com/krb5/krb5>
