---
title: RFCs and Standards Reference
audience: senior-engineers
tags: [rfc, ietf, oasis, iso, kerberos, ldap, smb, x509, saml, jwt, reference]
related:
  - ../01-ad-core/02-ad-cs-cert-services.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ../02-protocols/07-ntp-time-sync.md
  - ../02-protocols/08-spn-upn-pac.md
  - ./01-ms-protocols-reference.md
  - ./03-source-code-references.md
last_updated: 2026-08-13
---

# RFCs and Standards Reference

IETF RFCs, OASIS standards, and ISO/ITU-T recommendations that AD implements or interoperates with. Each entry: number, title, status, relevance to AD, and KB files that cite it.

## IETF RFCs

### Kerberos family

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| **RFC 4120** | The Kerberos Network Authentication Service (V5) | Internet Standard (STD 39, 2005-07) | Core Kerberos V5 protocol — AS-REQ/AS-REP/TGS-REQ/TGS-REP/AP-REQ/AP-REP, KDC-REQ-BODY, etypes, ticket flags, KRB-ERROR. MS-KILE is Microsoft's profile of this. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../10-comparison-matrices/02-protocol-implementation-matrix.md](../10-comparison-matrices/02-protocol-implementation-matrix.md) |
| **RFC 4121** | The Kerberos Version 5 GSS-API Mechanism: Version 2 | Internet Standard (STD 40, 2005-07) | GSS-API Kerberos mechanism — token formats (`krb5` OID 1.2.840.113554.1.2.2), per-message MIC/wrap tokens, session key derivation. Underlies SASL GSSAPI, SMB Session Setup, DCE/RPC auth. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| **RFC 4556** | Public Key Cryptography for Initial Authentication in Kerberos (PKINIT) | Proposed Standard (2006-06) | Smart-card / cert-based Kerberos logon. AD supports via `AuthPack` and `KDC_ENCRYPTION_KEY` from cert EKU `Kerberos Authentication` (1.3.6.1.5.2.3.5). | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **RFC 6806** | Kerberos FAST Pre-Authentication Framework | Proposed Standard (2012-11) | Kerberos armoring — TGT-wrapped AS-REQ. AD Server 2012+ supports. `PA-FX-FAST` padata type 149. Armor key derived from TGT session key. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| **RFC 3244** | Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols | Informational (2002-02) | `kpasswd` protocol on TCP/UDP 464 — `KRB-PRIV`-wrapped password change. Used by `kpasswd`, `setspn -c`, AD user password change from Linux. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../11-code-examples/03-macos-cli-recipes.md](../11-code-examples/03-macos-cli-recipes.md) |
| **RFC 4517** | LDAP: Syntaxes and Matching Rules | Proposed Standard (2006-06) | LDAP attribute syntaxes — `1.3.6.1.4.1.1466.115.121.1.x` OID tree. AD's `objectGuid` is `OctetString`, `objectSid` is `SID` (Microsoft extension), `userCertificate` is `Binary`. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 6680** | Generic Security Service Application Program Interface (GSS-API) Naming Extensions | Proposed Standard (2012-08) | GSS-API name attributes — used by AD claims (compound identity). | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| **RFC 6111** | Additional Kerberos Referral Tests | Proposed Standard (2011-04) | Cross-realm TGT referral tests — KDC MUST verify that the realm is canonical. Affects AD forest-trust TGT referral flow. | [../03-directory-schema/04-trusts-topology.md](../03-directory-schema/04-trusts-topology.md) |
| **RFC 6112** | Anonymity Support for Kerberos Password Change Operations | Proposed Standard (2011-04) | Anonymous kpasswd — not widely deployed in AD. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| **RFC 6251** | Using Kerberos Version 5 over the Transport Layer Security (TLS) Protocol | Informational (2011-05) | Kerberos-over-TLS — not deployed in AD but referenced for completeness. | (none) |

### LDAP family

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| **RFC 4510** | LDAP: Technical Specification Road Map | Internet Standard (STD 45, 2006-06) | Roadmap for the 9-document LDAPv3 spec (4510-4519). | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 4511** | LDAP: The Protocol | Internet Standard (STD 45, 2006-06) | LDAPMessage wire format, Bind/Search/Modify/Add/Del/Compare/Extended operations, controls, result codes. AD is conformant with extensions (see MS-ADTS §3.1.1). | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 4512** | LDAP: Directory Information Models | Internet Standard (STD 45, 2006-06) | Schema model — attributeType, objectClass, subentry. AD's schema is RFC 4512-compatible at the LDAP layer (with attributeID/governsID instead of numeric OID alone). | [../03-directory-schema/01-schema-attributes.md](../03-directory-schema/01-schema-attributes.md) |
| **RFC 4513** | LDAP: Authentication Methods and Security Mechanisms | Internet Standard (STD 45, 2006-06) | SASL mechanisms — GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5. AD supports GSSAPI, GSS-SPNEGO, simple. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 4514** | LDAP: String Representation of Distinguished Names | Internet Standard (STD 45, 2006-06) | DN string format — `CN=jsmith,OU=Users,DC=corp,DC=example,DC=com`. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 4515** | LDAP: String Representation of Search Filters | Internet Standard (STD 45, 2006-06) | LDAP filter syntax — `(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`. Extensible match rules (1.2.840.113556.1.4.803 = bitwise AND, .805 = bitwise OR, .1941 = LDAP_MATCHING_RULE_IN_CHAIN). | [../11-code-examples/01-powershell-ad-cmdlets.md](../11-code-examples/01-powershell-ad-cmdlets.md) |
| **RFC 4516** | LDAP: Uniform Resource Locator | Internet Standard (STD 45, 2006-06) | `ldap://` URLs — scope, filter, attributes, extensions. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 4517** | LDAP: Syntaxes and Matching Rules | Internet Standard (STD 45, 2006-06) | (see Kerberos family section above) | (see above) |
| **RFC 4519** | LDAP: Schema for User Applications | Proposed Standard (2006-06) | inetOrgPerson and related classes. AD's `user` class extends `person` (RFC 4519) → `top` (X.501). | [../03-directory-schema/01-schema-attributes.md](../03-directory-schema/01-schema-attributes.md) |
| **RFC 2696** | LDAP Control Extension for Simple Paged Results Manipulation | Proposed Standard (1999-09) | LDAP paged control OID `1.2.840.113556.1.4.319` — implemented by AD with 1000-row default page size. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 2830** | LDAP Extension for TLS | Proposed Standard (2000-05) | `StartTLS` extended operation OID `1.3.6.1.4.1.1466.20037`. AD supports on port 389. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **RFC 4752** | The Kerberos V5 ("GSSAPI") SASL Mechanism | Proposed Standard (2006-11) | SASL GSSAPI mechanism — wraps RFC 4121 GSS-API. AD supports for LDAP bind. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |

### DNS family

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| **RFC 2136** | Dynamic Updates in the Domain Name System (DNS UPDATE) | Proposed Standard (1997-04) | Dynamic DNS update protocol — Zone/Prerequisite/Update/Additional sections, RCODEs. AD-integrated DNS zones accept dynamic updates from clients. | [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| **RFC 2782** | A DNS RR for specifying the location of services (DNS SRV) | Proposed Standard (2000-02) | SRV record type — `_service._proto.name TTL class SRV priority weight port target`. AD uses for DC discovery (`_ldap._tcp.dc._msdcs`). | [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| **RFC 3645** | Generic Security Service Algorithm for DNS Secret Key Transaction Authentication (GSS-TSIG) | Proposed Standard (2003-10) | TSIG with Kerberos/GSS-API MAC — Algorithm name `gss-tsig.`. Used by AD-integrated DNS dynamic updates from non-Windows clients (`nsupdate -g`). | [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| **RFC 2845** | Secret Key Transaction Authentication for DNS (TSIG) | Proposed Standard (2000-05) | Base TSIG mechanism — GSS-TSIG extends this with RFC 3645. | [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| **RFC 1035** | Domain Names — Implementation and Specification | Internet Standard (STD 13, 1987-11) | Base DNS wire format. AD-integrated DNS is RFC 1035-compliant with extensions (dnsNode storage, zone transfer disabled by default). | [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |

### PKI / TLS family

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| **RFC 5280** | Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | Proposed Standard (2008-05) | X.509 v3 cert format, CRL format, path validation. AD CS issues RFC 5280-conformant certs; AD-integrated Kerberos uses cert EKUs per RFC 5280 §4.2.1.12. | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **RFC 6960** | X.509 Internet Public Key Infrastructure Online Certificate Status Protocol — OCSP | Proposed Standard (2013-06) | OCSP request/response over HTTP. AD CS Online Responder implements this. | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **RFC 5246** | The Transport Layer Security (TLS) Protocol Version 1.2 | Proposed Standard (2008-08, obsoleted by RFC 8446) | TLS 1.2 — used for LDAPS, SMB over TLS (indirectly), AD CS CES endpoint. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md), [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **RFC 8446** | The Transport Layer Security (TLS) Protocol Version 1.3 | Proposed Standard (2018-08) | TLS 1.3 — modern AD CS / LDAPS deployments support. SMB 3.1.1 pre-auth integrity is independent of TLS. | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md), [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **RFC 8449** | Ticket Extension for TLS 1.3 | Proposed Standard (2023-03) | TLS ticket extensions — used by modern AD CS for resumption. | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **RFC 5929** | Channel Bindings for TLS | Proposed Standard (2010-07) | `tls-server-end-point` channel binding — used by NTLM `MsvAvChannelBindings` AV_PAIR to prevent relay attacks. | [../02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |

### Federation / OAuth / JWT family

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| **RFC 6749** | The OAuth 2.0 Authorization Framework | Proposed Standard (2012-10, obsoleted by RFC 9700) | OAuth 2.0 — AD FS implements as authorization server / OpenID Connect Provider. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **RFC 7636** | Proof Key for Code Exchange by OAuth Public Clients (PKCE) | Proposed Standard (2015-09) | PKCE — AD FS 2019+ supports for public clients. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **RFC 7515** | JSON Web Signature (JWS) | Proposed Standard (2015-05) | JWS — signing format for JWTs issued by AD FS. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **RFC 7516** | JSON Web Encryption (JWE) | Proposed Standard (2015-05) | JWE — encrypting JWTs (less common in AD FS). | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **RFC 7519** | JSON Web Token (JWT) | Proposed Standard (2015-05) | JWT — token format for OAuth 2.0 / OpenID Connect issued by AD FS. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **RFC 7517** | JSON Web Key (JWK) | Proposed Standard (2015-05) | JWK — AD FS FederationMetadata publishes signing certs as JWK. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **RFC 7033** | WebFinger | Proposed Standard (2013-09) | WebFinger — used by OIDC issuer discovery. AD FS 2016+ supports `/.well-known/webfinger`. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |

### NTP family

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| **RFC 5905** | Network Time Protocol Version 4: Protocol and Algorithms Specification | Internet Standard (STD 68, 2010-06) | NTPv4 — AD W32Time follows for client-server mode. Forest-root PDC is stratum-2 to external stratum-1. | [../02-protocols/07-ntp-time-sync.md](../02-protocols/07-ntp-time-sync.md) |
| **RFC 5906** | Network Time Protocol Version 4: Autokey Specification | Informational (2010-06) | NTP Autokey — AD does NOT use; AD uses MS-SNTP authentication extension (separate from Autokey). | [../02-protocols/07-ntp-time-sync.md](../02-protocols/07-ntp-time-sync.md) |
| **RFC 4330** | Simple Network Time Protocol (SNTP) Version 4 for IPv4, IPv6 and OSI | Informational (2006-01, obsoleted by RFC 5905) | SNTP — legacy reference for older AD W32Time implementations. | [../02-protocols/07-ntp-time-sync.md](../02-protocols/07-ntp-time-sync.md) |

### SMB family

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| (none directly) | — | — | SMB is not IETF-standardized. Microsoft publishes MS-SMB2; SNIA published earlier CIFS spec (1996). | [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |

### Other

| RFC | Title | Status | Relevance to AD | KB files |
|---|---|---|---|---|
| **RFC 2617** | HTTP Authentication: Basic and Digest Access Authentication | Draft Standard (1999-06, obsoleted by RFC 7235) | HTTP Basic/Digest — referenced for AD FS forms auth. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **RFC 7515 / 7516 / 7519** | (see Federation family above) | (see above) | (see above) | (see above) |
| **RFC 4519** | (see LDAP family above) | (see above) | (see above) | (see above) |
| **RFC 7235** | HTTP/1.1: Authentication | Proposed Standard (2014-06) | HTTP authentication framework — referenced by AD FS. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |

## OASIS Standards

| Standard | Version | URL | Relevance to AD | KB files |
|---|---|---|---|---|
| **SAML 2.0 Core** | 2.0 (2005-03) | https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf | Assertion format, NameID, conditions, statements. AD FS issues SAML 2.0 tokens to RP-STS. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **SAML 2.0 Protocols** | 2.0 (2005-03) | https://docs.oasis-open.org/security/saml/v2.0/saml-protocol-2.0-os.pdf | `AuthnRequest`, `Response`, `LogoutRequest`. AD FS as IdP accepts `AuthnRequest` from SP-initiated flows. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **SAML 2.0 Bindings** | 2.0 (2005-03) | https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf | HTTP-Redirect, HTTP-POST, HTTP-Artifact, SOAP bindings. AD FS supports all four. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **SAML 2.0 Metadata** | 2.0 (2005-03) | https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf | EntityDescriptor, IDPSSODescriptor, SPSSODescriptor. AD FS publishes `/FederationMetadata/2007-06/FederationMetadata.xml`. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **WS-Federation 1.2** | 1.2 (2009-12) | http://docs.oasis-open.org/wsfed/federation/v1.2/ws-federation.html | Federation passive (browser) sign-in flow — `wctx`, `wresult`, `wa=wsignin1.0`. AD FS supports for legacy Office 365 / SharePoint. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **WS-Trust 1.4** | 1.4 (2009-02) | http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html | SOAP-based token issuance — `RequestSecurityToken`, `RequestSecurityTokenResponse`. AD FS active (SOAP) flow uses this. | [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| **XACML 3.0** | 3.0 (2013-01) | https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html | Attribute-based access control policy language. Not used by AD FS directly; mentioned for cross-reference with AD claims. | (out of scope) |

## ISO / ITU-T Standards

| Standard | Year | Title | Relevance to AD | KB files |
|---|---|---|---|---|
| **X.509** | 2008 (with 2016 errata) | Information technology — Open Systems Interconnection — The Directory: Public-key and attribute certificate frameworks | Base X.509 v3 cert format. AD CS PKI implements X.509 with RFC 5280 Internet profile. | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **X.500** | 1993 (revised 2019) | Information technology — Open Systems Interconnection — The Directory: Overview of concepts, models and services | Conceptual directory model — DSA, DUA, naming. AD's LDAP gateway is a X.500-model directory. | [../01-ad-core/01-ad-ds-internals.md](../01-ad-core/01-ad-ds-internals.md), [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **X.501** | 1993 (revised 2019) | Information technology — Open Systems Interconnection — The Directory: Models | Information model — entries, attributes, DIT, schema subentry. | [../03-directory-schema/01-schema-attributes.md](../03-directory-schema/01-schema-attributes.md) |
| **X.511** | 1993 (revised 2019) | Information technology — Open Systems Interconnection — The Directory: Abstract Service Definition | Abstract service — operations (Read, List, Search, Modify, Add, Remove). | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| **X.520** | 1993 (revised 2016) | Information technology — Open Systems Interconnection — The Directory: Selected attribute types | Standard attribute types (`commonName`, `organizationalUnitName`, etc.). | [../03-directory-schema/01-schema-attributes.md](../03-directory-schema/01-schema-attributes.md) |
| **X.521** | 1993 (revised 2016) | Information technology — Open Systems Interconnection — The Directory: Selected object classes | Standard object classes (`person`, `organizationalPerson`, `organizationalUnit`). | [../03-directory-schema/01-schema-attributes.md](../03-directory-schema/01-schema-attributes.md) |
| **X.680** | 2008 (revised 2021) | Information technology — Abstract Syntax Notation One (ASN.1): Specification of basic notation | ASN.1 base — used to define Kerberos, LDAP, X.509, CMS structures. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **X.681** | 2008 (revised 2021) | Information technology — ASN.1: Information object specification | ASN.1 information objects — used in CMS, PKCS. | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| **X.682** | 2008 (revised 2021) | Information technology — ASN.1: Constraint specification | ASN.1 constraints. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| **X.683** | 2008 (revised 2021) | Information technology — ASN.1: Parameterization of ASN.1 specifications | ASN.1 parameterization. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| **X.690** | 2008 (revised 2021) | Information technology — ASN.1 encoding rules: BER, CER, DER | Encoding rules — LDAP uses BER; Kerberos uses DER; X.509 uses DER. | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md), [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |

## Microsoft profiles of IETF standards

| IETF standard | Microsoft profile document |
|---|---|
| RFC 4120 (Kerberos V5) | MS-KILE |
| RFC 4511 (LDAP) | MS-ADTS §3.1.1 |
| RFC 5280 (X.509) | MS-WCCE, MS-WSTEP |
| RFC 2136 (DNS UPDATE) | MS-DNSP |
| RFC 6960 (OCSP) | MS-OCSP |
| RFC 5905 (NTP) | MS-SNTP (subsumed in MS-NRPC §3.4) |

## See also

- [./01-ms-protocols-reference.md](./01-ms-protocols-reference.md) — Microsoft Open Specifications reference.
- [./03-source-code-references.md](./03-source-code-references.md) — Open-source implementations of these standards.
- [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) — Kerberos wire format.
- [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) — LDAP protocol.
- [../01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) — AD FS federation (SAML/WS-Fed/OIDC).
- [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) — AD CS (X.509 / OCSP).

## RFC status definitions

| Status | Meaning |
|---|---|
| Internet Standard (STD) | Highest maturity; widely deployed; ready for production. |
| Proposed Standard | Likely to become Internet Standard; spec is stable. |
| Informational | Not a standard; provides context or documents practice. |
| Historic | Superseded or no longer recommended. |
| Draft Standard | Intermediate maturity (no longer assigned to new RFCs since 2006). |
| Best Current Practice (BCP) | Operational best practice, not a wire protocol. |

## RFC citation patterns in this KB

When citing an RFC in a KB file, use this pattern:
```markdown
Per [RFC 4120 §3.3.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3), the KDC ...
```

Or for group citations:
```markdown
The Kerberos protocol family (RFC 4120, RFC 4121, RFC 4556, RFC 6806) underlies MS-KILE.
```

## Related drafts and newer RFCs to watch

These drafts/RFCs are not yet widely implemented in AD but worth tracking:

| Draft / RFC | Title | Status | Why it matters for AD |
|---|---|---|---|
| draft-ietf-krb-wg-des-dies-die-die | Deprecate DES for Kerberos | Long-since RFC (RFC 6649) | AD removed DES in Server 2008 R2 |
| RFC 6649 | Deprecate DES and RC4-Weak in Kerberos | Proposed Standard (2012) | AD: RC4 disabled by default Server 2022 |
| draft-ietf-kitten-rfc6680bis | GSS-API Naming Attributes Revision | Active draft | May affect claims-based Kerberos interop |
| RFC 8009 | AES Encryption with HMAC-SHA-2 for Kerberos 5 | Proposed Standard (2016) | AD: supported in Server 2012 R2+ (etype 0x13) |
| RFC 8453 | Framework for Abstraction and Control of Optical Networks | (Out of scope) | (irrelevant) |
| RFC 9700 | OAuth 2.0 Security Best Current Practice | BCP (2024-11) | Affects AD FS OAuth flows |
| RFC 9449 | OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) | Proposed Standard (2023-08) | Future AD FS hardening |
| RFC 9126 | Verifiable Credentials Data Model v1.1 | (Out of scope) | Decentralized identity direction |

## Standards body reference

| Body | Acronym | Domain | URL |
|---|---|---|---|
| Internet Engineering Task Force | IETF | Internet protocols (RFC) | https://www.ietf.org/ |
| Internet Assigned Numbers Authority | IANA | Protocol registries (Kerberos etypes, SASL mechanisms, etc.) | https://www.iana.org/ |
| OASIS | OASIS | SAML, WS-Federation, WS-Trust, KMIP | https://www.oasis-open.org/ |
| World Wide Web Consortium | W3C | XML, SOAP, WebCrypto | https://www.w3.org/ |
| International Organization for Standardization | ISO | X.500, X.509, X.680 series | https://www.iso.org/ |
| International Telecommunication Union - Telecommunication Standardization Sector | ITU-T | X.500, X.509, X.680 series (joint with ISO) | https://www.itu.int/ |
| National Institute of Standards and Technology | NIST | FIPS PUBS (FIPS 140-2/3, FIPS 197 AES) | https://csrc.nist.gov/ |

## FIPS publications relevant to AD

| FIPS PUB | Title | Relevance to AD |
|---|---|---|
| FIPS 140-3 | Cryptographic Module Security Requirements | AD CS, AD RMS crypto modules validated under FIPS 140-2/3 |
| FIPS 197 | Advanced Encryption Standard (AES) | Kerberos AES-128/256 etypes (0x11, 0x12) use AES |
| FIPS 180-4 | Secure Hash Standard (SHA-1, SHA-2 family) | Kerberos AES per RFC 3961 uses HMAC-SHA-1 (0x11, 0x12) or HMAC-SHA-2 (0x13 per RFC 8009) |
| FIPS 198-1 | The Keyed-Hash Message Authentication Code (HMAC) | Kerberos MAC algorithm base |
| FIPS 186-5 | Digital Signature Standard (DSS) | ECDSA / RSA for cert signing (AD CS) |
| FIPS 201-3 | Personal Identity Verification (PIV) of Federal Employees and Contractors | Smart-card logon (PKINIT) uses PIV certs |

## Common RFC reference mistakes

| Mistake | Correct usage |
|---|---|
| "RFC 1510" | Obsolete; superseded by RFC 4120 in 2005. Always cite RFC 4120. |
| "RFC 2251" for LDAPv3 | Obsolete; superseded by RFC 4511 in 2006. |
| "RFC 2255" for LDAP URL format | Obsolete; superseded by RFC 4516 in 2006. |
| "RFC 1777" for LDAPv2 | Historic; not deployed in AD. |
| "RFC 2696" for paged control | Still valid; not obsoleted. |
| "RFC 4510" as a single spec | RFC 4510 is the roadmap; the actual spec is RFC 4511 (Protocol), 4512 (Models), etc. |
| "RFC 5280 vs X.509" | RFC 5280 is the Internet profile of X.509; both apply. Cite both. |
| "OID 1.2.840.113549" for Kerberos | Wrong — that's RSA. Kerberos etypes are IANA-registered integers. |
| "PKINIT = RFC 4557" | Wrong — PKINIT is RFC 4556. RFC 4557 is irrelevant. |
