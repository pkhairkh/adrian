---
title: Protocol × Implementation Matrix
audience: senior-engineers
tags: [matrix, protocol, implementation, kerberos, ldap, smb, drsr, nrpc, wcce, dns]
related:
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/07-ntp-time-sync.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../09-linux-equivalents/08-freeipa-trust.md
  - ../09-linux-equivalents/09-openldap-mit-kerberos.md
  - ../12-references/01-ms-protocols-reference.md
  - ../12-references/03-source-code-references.md
  - ./01-feature-os-matrix.md
last_updated: 2026-08-13
---

# Protocol × Implementation Matrix

Wire-level protocol support across the implementations senior engineers actually deploy. Each cell is `✓ native` (in-tree, default), `✓ via shim` (works through a translation layer), `partial` (subset), or `✗`. The implementation-reference column points to source.

## Legend

| Symbol | Meaning |
|---|---|
| ✓ native | Built into the implementation; default code path |
| ✓ via shim | Implemented through a wrapper around another lib |
| partial | Subset of spec; gaps documented |
| ✗ | Not implemented |

## Matrix

| Protocol (RFC/MS-) | Win Server DC | MIT krb5 | Heimdal Kerberos | Apple Heimdal (macOS) | Samba (adclient + winbindd) | SSSD | OpenLDAP client | FreeIPA server | Reference |
|---|---|---|---|---|---|---|---|---|---|
| Kerberos AS-REQ (RFC 4120 §3.1) | ✓ native (kdcsvc) | ✓ native (`src/kdc/`) | ✓ native (`kdc/`) | ✓ native (`kdc/`, fork) | ✓ via shim (uses Heimdal or MIT) | ✓ via shim (consumes krb5 libs) | ✗ | ✓ native (bundled MIT) | [02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| Kerberos TGS-REQ (RFC 4120 §3.3) | ✓ native | ✓ native | ✓ native | ✓ native | ✓ via shim | ✓ via shim | ✗ | ✓ native | [02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| Kerberos PAC (MS-PAC) | ✓ native (KDC signs) | partial (verify only, no emit) | partial | partial | ✓ via shim (validates + reads PAC) | ✓ via shim (reads PAC for groups) | ✗ | partial (uses MS-PAC for AD trusts only) | [02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| NTLMv2 (MS-NLMP) | ✓ native (lsass NEGOTIATE/CHALLENGE/AUTH) | ✗ | ✗ | ✗ | ✓ native (`source3/libsmb/ntlmssp.c`) | ✗ (delegates to winbind) | ✗ | ✗ | [02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |
| LDAP simple bind (RFC 4511 §4.2) | ✓ native (lsa) | ✗ | ✗ | ✗ | ✓ via shim (`libcli/ldap/`) | ✓ via shim (`src/providers/ldap/`) | ✓ native (`libraries/libldap/`) | ✓ native (389DS) | [02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| LDAP SASL GSSAPI/GSS-SPNEGO (RFC 4752) | ✓ native | ✓ native (via gssapi_krb5) | ✓ native (via gssapi) | ✓ native | ✓ via shim | ✓ via shim | ✓ via shim (cyrus-sasl) | ✓ native | [02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| LDAP paged control (1.2.840.113556.1.4.319) | ✓ native | ✗ | ✗ | ✗ | ✓ via shim | ✓ native (`src/providers/ldap/ldap_paged.c`) | ✓ native (`ldap_paged.c`) | ✓ native (389DS) | [02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| SMB 2 Negotiate (MS-SMB2 §2.2.3) | ✓ native (srv2.sys) | ✗ | ✗ | ✗ | ✓ native (`source3/libsmb/clisp.c`) | ✗ (uses libsmbclient) | ✗ | ✗ (uses Samba) | [02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| SMB 3.1.1 encryption (MS-SMB2 §3.1.4.1) | ✓ native | ✗ | ✗ | ✗ | ✓ native (`source3/libsmb/smb2_*`) | ✗ | ✗ | ✗ | [02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| DRSUAPI replication (MS-DRSR) | ✓ native (ntdsa.dll) | ✗ | ✗ | ✗ | ✓ native (`source4/rpc_server/drsuapi/`) | ✗ | ✗ | partial (IPA consumes trusts, doesn't repl) | ✗ (AD-AD only) | [02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| MS-DRSR DRSGetNCChanges (opnum 3) | ✓ native | ✗ | ✗ | ✗ | ✓ native (`source4/rpc_server/drsuapi/getncchanges.c`) | ✗ | ✗ | ✗ | ✗ | [02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| MS-NRPC NetrServerAuthenticate3 (opnum 26) | ✓ native (netlogon) | ✗ | ✗ | ✗ | ✓ native (`source3/rpc_server/netlogon/`) | ✗ (relies on Samba) | ✗ | ✗ | ✗ | [02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| MS-WCCE request (ICertPassage RPC) | ✓ native (certsvc.exe) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | partial (Dogtag has own RA protocol) | ✗ | [01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| MS-XCEP / MS-WSTEP (CEP/CES HTTP) | ✓ native | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | partial (certmonger SCEP client) | [01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| OCSP (RFC 6960) | ✓ native (Online Responder) | ✗ | ✗ | ✓ native (Security framework) | ✗ | ✓ via shim (certmonger/nss) | ✗ | ✓ native (Dogtag OCSP) | ✓ via shim (openssl) | [01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| DNS dynamic update (RFC 2136) | ✓ native (dns.exe) | ✗ | ✗ | ✗ | ✓ native (`source4/torture/drs/`) | ✓ native (`src/providers/ad/ad_dyndns.c`) | ✗ | ✓ native (BIND + `ipa-dnskeysync`) | ✓ native (BIND `nsupdate`) | [02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| GSS-TSIG (RFC 3645) | ✓ native | ✓ native (`src/lib/gssapi/`) | ✓ native (`lib/gssapi/`) | ✓ native | ✓ native (`source4/torture/dns/`) | ✓ via shim (uses nsupdate -g) | ✗ | ✓ via shim (BIND plugin) | ✓ via shim (BIND `nsupdate -g`) | [02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| NTP with MS-SNTP auth | ✓ native (w32time) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | [02-protocols/07-ntp-time-sync.md](../02-protocols/07-ntp-time-sync.md) |
| NTP client (RFC 5905 unauthenticated) | ✓ native (w32tm) | ✗ | ✗ | ✓ native (timed) | ✗ | ✗ | ✗ | ✓ native (chrony) | ✓ native (chrony/ntpd) | [02-protocols/07-ntp-time-sync.md](../02-protocols/07-ntp-time-sync.md) |
| SPN registration (MS-ADTS §3.1.1) | ✓ native (setspn/DRSWriteSPN) | ✗ | ✗ | ✗ | ✓ native (`net ads keytab add`) | ✓ via shim (`adcli`) | ✗ | ✓ native (`ipa service-add`) | ✓ via shim (`adcli`) | [02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| PKINIT (RFC 4556) | ✓ native (smart-card logon) | ✓ native (`src/lib/krb5/krb/pkinit.c`) | ✓ native | ✓ native (PIV/CAC) | ✗ | ✗ | ✗ | ✓ native (ipa-certmap) | ✓ native (MIT krb5) | [02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| Kerberos FAST (RFC 6806) | ✓ native (Server 2012+) | ✓ native | ✓ native | ✓ native | ✓ via shim | ✓ via shim | ✗ | ✓ native | ✓ native | [02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| kpasswd (RFC 3244) | ✓ native (kpasswd) | ✓ native (`src/kadmin/`) | ✓ native | ✓ native | ✓ via shim | ✓ via shim (`adcli change-password`) | ✗ | ✓ native | ✓ native | [02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| LDAP_SERVER_TREE_DELETE (1.2.840.113556.1.4.529) | ✓ native | ✗ | ✗ | ✗ | ✓ via shim | ✗ | ✗ | ✗ | ✗ | [02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| LDAP_SERVER_DIRSYNC (1.2.840.113556.1.4.1339) | ✓ native | ✗ | ✗ | ✗ | ✓ via shim | ✗ | ✗ | ✗ | ✗ | [02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| LDAP_SERVER_SD_FLAGS (1.2.840.113556.1.4.801) | ✓ native | ✗ | ✗ | ✗ | ✗ | ✓ native (sssd-sd) | ✓ native | ✓ native | ✓ native | [02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |

## Cross-implementation notes

### Kerberos
- MIT krb5 (`src/kdc/`) is the reference for everything except Windows. Heimdal (`kdc/`) is a separate, mostly-compatible implementation; Apple ships a fork that hasn't tracked upstream Heimdal since ~2014.
- SSSD and Samba both *use* MIT or Heimdal as libraries — they don't re-implement. SSSD on RHEL uses MIT; Samba on Debian uses Heimdal; you can flip via build flags.
- PKINIT is enabled on Windows by default for smart-card logon; on Linux it requires explicit `pkinit_anchors` and a CA chain.
- FAST armoring is automatic in Win10+; on MIT krb5 you must set `default_tkt_enctypes` and use `kinit -T` or `preauth_required = true` with FAST.

### LDAP
- AD controls (TREE_DELETE, DIRSYNC, ASQ, NOTIFICATION) are Microsoft extensions — only AD DCs answer them. Samba can *receive* some on its AD-DC role but not as a client; OpenLDAP and 389DS ignore them silently.
- `LDAP_SERVER_SD_FLAGS_OID` is critical for reading `nTSecurityDescriptor` efficiently — without it, AD returns every SD piece. SSSD and OpenLDAP both set it explicitly when reading SDs.

### SMB
- SMB1 is disabled by default on Server 2016+; Samba also disables it (`server min protocol = SMB2_10`).
- SMB 3.1.1 encryption requires AES-GCM (preferred) or AES-CCM. Samba added this in 4.3 (2015); macOS didn't gain client-side SMB3.1.1 encryption until macOS 11.
- Pre-authentication integrity (SHA-512) is SMB 3.1.1 only — older dialects rely on signing.

### DRSR / NRPC / WCCE
- These are DC-side protocols. Samba's AD-DC (`source4/rpc_server/drsuapi/`) is the only non-Microsoft implementation that answers DRSGetNCChanges as a server. Clients (impacket, ldap3, PowerView) consume them.
- MS-NRPC's NetrServerAuthenticate3 establishes the machine secure channel — only Samba implements this for non-Windows domain members. SSSD relies on Samba's libnetjoin.
- MS-WCCE (Windows Client Certificate Enrollment) is RPC-based. Microsoft added MS-XCEP/MS-WSTEP (HTTP) for key-based renewal. Linux clients talk to AD CS via certmonger + SCEP (different protocol) or via third-party agents (Centrify, PBIS).

### DNS dynamic update
- GSS-TSIG requires a Kerberos service principal `DNS/<server>@REALM`. AD DCs register this automatically; Linux BIND servers must have it manually via `ktpass`/`ipa service-add`.
- SSSD's `dyndns_update = true` uses `nsupdate -g` under the hood — same code path as FreeIPA's `ipa-client-automount`.

### NTP with MS-SNTP
- Microsoft's MS-SNTP authentication extension (signed NTP using the Netlogon secure channel key) is AD-only. Linux `chrony`/`ntpd` cannot authenticate against an AD DC's NTP service — they fall back to unauthenticated NTP. This is usually fine because Kerberos time-skew is enforced separately by the KDC.
- The forest-root PDC emulator is the authoritative time source for the forest. Linux clients should point to it (or a stratum-1 upstream) for the 5-minute skew window.

## Source path reference

| Project | Repo | AD-relevant subpath |
|---|---|---|
| Samba | github.com/samba-team/samba | `source3/winbindd/`, `source3/libsmb/`, `source4/rpc_server/drsuapi/`, `libcli/ldap/`, `lib/krb5_wrap/` |
| SSSD | github.com/SSSD/sssd | `src/providers/ad/`, `src/providers/ldap/`, `src/responder/`, `src/db/` |
| MIT krb5 | github.com/krb5/krb5 | `src/lib/krb5/`, `src/lib/gssapi/`, `src/kdc/`, `src/kadmin/` |
| Heimdal | github.com/heimdal/heimdal | `lib/krb5/`, `lib/gssapi/`, `lib/hdb/`, `kdc/` |
| FreeIPA | github.com/freeipa/freeipa | `daemons/ipa-slapi-plugins/`, `ipaclient/`, `ipaserver/` |
| OpenLDAP | github.com/openldap/openldap-portable | `servers/slapd/`, `clients/tools/`, `libraries/libldap/` |
| impacket | github.com/fortra/impacket | `impacket/spnego/`, `impacket/krb5/`, `impacket/ldap/`, `impacket/dcerpc/v5/` |

Full per-file path detail in [../12-references/03-source-code-references.md](../12-references/03-source-code-references.md).

## Per-implementation nuance table

| Implementation | Bundle / packaging | Default backend storage | Notable divergences from spec |
|---|---|---|---|
| Windows Server DC | Server role (AD DS, AD CS, AD FS, etc.) | `ntds.dit` (ESE/JET blue) | MS-KILE profile of RFC 4120; PAC buffer types beyond RFC 4120 (PAC_BUFFER_TICKET_CHECKSUM 0x0E, PAC_FULL_CHECKSUM 0x13, PAC_REQUESTER 0x12) |
| MIT krb5 | Linux distro package (`krb5-*`) | KDB backend (default: db2/LDBM file) | No PAC generation as KDC (verifies only); PKINIT via plugin (`plugins/preauth/pkinit/`); FAST armoring supported |
| Heimdal Kerberos | Linux distro package (`heimdal-*`) | HDB (db2/SQLite/LDAP backend) | PAC generation native; bundled with Samba for AD-DC role |
| Apple Heimdal (macOS) | Bundled with macOS; not packaged separately | API: (in-memory) | Fork tracks upstream ~2014; missing PAC_FULL_CHECKSUM, claims-based Kerberos; replaced by PSSO Extension (macOS 13+) |
| Samba (adclient + winbindd) | Distro package (`samba`/`samba-winbind`) | TDB files (`winbindd_cache.tdb`, `secrets.tdb`) | Includes its own Heimdal fork in `source4/heimdal/`; KDC available only in AD-DC role |
| SSSD | Distro package (`sssd`) | LDB-backed cache (`/var/lib/sss/db/cache.ldb`) | Pure consumer of MIT krb5 and OpenLDAP libs; no KDC, no LDAP server |
| OpenLDAP client | Distro package (`openldap-clients`/`ldap-utils`) | n/a (client only) | Strict RFC 4511; lacks MS-ADTS extensions (DIRSYNC, ASQ, NOTIFICATION) |
| FreeIPA server | Distro package (`freeipa-server`) | 389DS (`/var/lib/dirsrv/slapd-*/`) + MIT krb5 KDB | Custom `ipa_kdb` plugin to translate between MIT KDB and 389DS schema; MS-PAC issuance for AD trusts via `ipa_kdb_mspac.c` |

## KDC availability

| Implementation | Can act as KDC? | Can be AD-DC? | Notes |
|---|---|---|---|
| Windows Server | ✓ (kdcsvc) | ✓ (primary) | Full AD-DC role including MS-DRSR server side |
| Samba (AD-DC build) | ✓ (Heimdal fork in `source4/kdc/`) | ✓ (functional equivalent) | Field-proven but not bit-compatible; supports common ops, some advanced (claims, Fine-Grained Password Policy) incomplete |
| MIT krb5 standalone | ✓ (`krb5kdc`) | ✗ (no AD schema, no MS-DRSR) | Use for non-AD Kerberos realms (FreeIPA server side, legacy HPC) |
| Heimdal standalone | ✓ (`kdc`) | ✗ | Historically used by BSD-derived systems; less common today |
| Apple Heimdal (macOS) | ✗ (KDC binary removed in macOS 10.12+) | ✗ | Apple's deprecated local KDC for Spotlight; no AD-DC capability |
| FreeIPA server | ✓ (MIT krb5 + `ipa_kdb` plugin) | partial (cross-forest trust only — not a substitute for AD-DC) | IPA KDC issues MS-PAC for cross-forest trust users, allowing Windows clients to interoperate |

## Protocol coverage gap analysis

The matrix above shows where each implementation lands. The practical coverage gap analysis:

1. **Full AD-DC replacement on Linux**: only Samba's AD-DC role (`samba-tool domain provision`). Limitations: no DNS server GUI integration, no Group Policy Management Console equivalent, no Fine-Grained Password Policy GUI, partial claims/compound-identity support.
2. **AD-integrated DNS alternatives**: BIND with `dlz_bind` (Samba's DNS backend), FreeIPA DNS (389DS-backed). Neither supports AD-integrated zone scavenging logic exactly.
3. **AD CS replacement**: FreeIPA CA (Dogtag) is the closest functional equivalent — supports SCEP, EST, cert autoenrollment via certmonger. Does NOT speak MS-WCCE / MS-XCEP / MS-WSTEP.
4. **AD FS replacement**: Keycloak (open source), Authentik, PingFederate (commercial). All support SAML 2.0 + OIDC; only Keycloak has substantive WS-Federation support.
5. **AD RMS replacement**: none open-source. Microsoft's Azure Information Protection (AIP) is the migration target for on-prem AD RMS.

## See also

- [01-feature-os-matrix.md](01-feature-os-matrix.md) — feature × OS matrix.
- [03-tool-function-matrix.md](03-tool-function-matrix.md) — function-to-tool mapping.
- [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) — Kerberos wire format.
- [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) — LDAP protocol.
- [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) — SMB protocol.
- [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) — DCE/RPC + DRSUAPI.
- [../12-references/01-ms-protocols-reference.md](../12-references/01-ms-protocols-reference.md) — Microsoft Open Specifications.
- [../12-references/02-rfcs-standards.md](../12-references/02-rfcs-standards.md) — IETF RFCs and OASIS standards.
- [../12-references/03-source-code-references.md](../12-references/03-source-code-references.md) — open-source repos.

## Per-protocol detail

### Kerberos AS-REQ / AS-REP

| Implementation | Behavior |
|---|---|
| Windows Server DC | Receives AS-REQ on TCP/UDP 88; pre-auth via PA-ENC-TIMESTAMP (etype per `msDS-SupportedEncryptionTypes`); PAC included by default (`KERB_VALIDATION_INFO` + `PAC_SIGNATURE_DATA` + `PAC_UPN_DNS_INFO` + Server 2016+ `PAC_BUFFER_TICKET_CHECKSUM` + `PAC_FULL_CHECKSUM`). |
| MIT krb5 KDC | Same wire protocol; PAC NOT generated by default (unless KDB plugin like FreeIPA's `ipa_kdb`); PKINIT and FAST supported; default etypes AES-256/128 + optionally RC4. |
| Heimdal KDC | PAC generated natively when KDB indicates it; bundled with Samba AD-DC for full AD-DC role. |
| Apple Heimdal (macOS) | Client only — receives AS-REP, stores in CCACHE (`/tmp/krb5cc_<uid>` or `API:`). No KDC binary shipped since macOS 10.12. |
| Samba (as AD-DC) | Full AS-REQ/AS-REP service via Heimdal fork in `source4/kdc/`. PAC generation via `pac-glue.c`. |
| SSSD | Client only — calls `krb5_get_init_creds_password()` in `krb5_child`. |
| OpenLDAP client | n/a — not a Kerberos implementation. |
| FreeIPA server | Issues AS-REP via MIT krb5 KDC + `ipa_kdb` plugin; PAC included when cross-forest trust is established. |

### NTLMv2

| Implementation | Behavior |
|---|---|
| Windows Server DC | Validating side: receives Type 3 AUTHENTICATE via MS-NRPC `NetrSamLogon` or via LSASS for local auth; checks NTLMv2 response against stored hash; issues session key. |
| MIT krb5 | ✗ — no NTLM. |
| Heimdal | ✗ — no NTLM (Heimdal's NTLM lib is used only for SPNEGO negotiation fallback). |
| Apple Heimdal (macOS) | ✗ — no native NTLM. Third-party (Admit, Centrify) provide. |
| Samba (`libsmbclient` + winbind) | Full NTLMv2 client (Type 1/2/3 messages in `source3/libsmb/ntlmssp.c`) and validator (`source3/rpc_server/netlogon/`). |
| SSSD | ✗ — relies on Samba if NTLM is needed (rare). |
| OpenLDAP client | ✗ — LDAP simple bind only, not NTLM. |
| FreeIPA server | ✗ — IPA is Kerberos-only. |

### LDAP SASL GSSAPI

| Implementation | Behavior |
|---|---|
| Windows Server DC | Server side: WLDAP32 accepts GSS-SPNEGO and GSSAPI; SASL via SSPI. |
| MIT krb5 | Client side only: `gssapi_krb5` mechanism provided; `ldap3` / `ldapsearch -Y GSSAPI` uses it. |
| Heimdal | Client + server: `lib/gssapi/` provides both. |
| Apple Heimdal (macOS) | Client side via `GSS.framework` (deprecated) or via `ldapsearch -Y GSSAPI`. |
| Samba | Client + server (AD-DC role): `libcli/ldap/` client; `source4/dsdb/samdb/ldb_modules/` server. |
| SSSD | Client side only: `src/providers/ldap/sdap.c` wraps OpenLDAP's `ldap_sasl_bind_s()` with GSSAPI. |
| OpenLDAP client | Full SASL GSSAPI support via cyrus-sasl; `libraries/libldap/sasl.c`. |
| FreeIPA server | 389DS server side: full SASL GSSAPI support; uses MIT krb5 GSS-API. |

### DRSUAPI / MS-DRSR DRSGetNCChanges

| Implementation | Behavior |
|---|---|
| Windows Server DC | Originating implementation. `ntdsa.dll` `DRSGetNCChanges` (opnum 3) compresses with LZ (NTFS/LZNT1), returns `REPLENTIN_V3` array. |
| MIT krb5 | ✗ — no replication. |
| Heimdal | ✗ — no replication. |
| Apple Heimdal (macOS) | ✗ — no replication. |
| Samba | ✓ — both server (`source4/rpc_server/drsuapi/getncchanges.c`) and client (`source4/torture/drs/`). The only open-source DRSUAPI server implementation. |
| SSSD | ✗ — relies on Samba for join (`libnetjoin`) but not for replication. |
| OpenLDAP client | ✗ — no replication. |
| FreeIPA server | ✗ — IPA uses its own replication protocol (389DS Multi-Master Replication over LDAP), not MS-DRSR. Cross-forest trust pulls a one-time snapshot via LDAP. |

### MS-WCCE (cert enrollment)

| Implementation | Behavior |
|---|---|
| Windows Server DC (AD CS) | Originating ICertPassage RPC server (UUID `91b9b93a-57b4-11d0-8f16-00a0484d6c9c`); MS-XCEP/MS-WSTEP HTTP endpoints for CEP/CES. |
| All other implementations | ✗ — no open-source MS-WCCE server. FreeIPA/Dogtag CA uses its own RA protocol. |

### DNS dynamic update (RFC 2136) + GSS-TSIG (RFC 3645)

| Implementation | Behavior |
|---|---|
| Windows Server DC (AD-integrated DNS) | Receives dynamic updates on TCP/UDP 53; GSS-TSIG with Kerberos context derived from `DNS/<server>` SPN; updates `dnsNode` objects in DomainDnsZones/ForestDnsZones NC. |
| BIND (with `dlz_bind` Samba plugin) | ✓ — supports GSS-TSIG via Samba's `lib/krb5_wrap/`. |
| FreeIPA DNS (BIND + `ipa-dnskeysync` + `ldap-zone2ldap`) | ✓ — supports GSS-TSIG; zones stored in 389DS. |
| SSSD client | ✓ via `nsupdate -g` — generates GSS-TSIG-signed dynamic updates from joined clients. |
| macOS client | ✓ via `nsupdate -g` (shipped with macOS) — same mechanism as Linux. |
| OpenLDAP client | ✗ — not a DNS implementation. |
