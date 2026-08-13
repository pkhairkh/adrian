---
title: Open-Source Code Repository Reference
audience: senior-engineers
tags: [source-code, open-source, samba, sssd, heimdal, mit-krb5, freeipa, openldap, impacket, reference]
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
  - ./01-ms-protocols-reference.md
  - ./02-rfcs-standards.md
  - ../11-code-examples/05-python-impacket-examples.md
last_updated: 2026-08-13
---

# Open-Source Code Repository Reference

For each major open-source project relevant to AD, the canonical repo URL, primary language, key source paths for AD-relevant code, and license. Use this to navigate to source when the KB files reference a specific implementation detail.

## Projects

### Samba
- **Repo:** https://github.com/samba-team/samba (mirror; canonical: https://gitlab.com/samba-team/samba)
- **Primary language:** C (with Python glue)
- **License:** GPL-3.0-or-later
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `source3/winbindd/` | `winbindd` daemon — the Linux Winbind idmap/auth engine; `winbindd_pam.c`, `winbindd_cache.c`, `winbindd_ads.c` | [../09-linux-equivalents/04-winbind-internals.md](../09-linux-equivalents/04-winbind-internals.md), [../10-comparison-matrices/04-auth-flow-comparison.md](../10-comparison-matrices/04-auth-flow-comparison.md) |
| `source3/libsmb/` | SMB client library — `clisp.c` (SMB2 Negotiate), `ntlmssp.c` (NTLMSSP client), `krb5.c` (Kerberos client) | [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md), [../02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |
| `source3/passdb/` | Passdb backend — `pdb_ldap.c` (LDAP-based SAM), `pdb_samba4.c` (Samba4 AD DC integration) | [../01-ad-core/01-ad-ds-internals.md](../01-ad-core/01-ad-ds-internals.md) |
| `source4/libnet/` | `libnetjoin` — domain-join logic; `libnet_join.c` (machine secure channel establishment via MS-NRPC) | [../10-comparison-matrices/04-auth-flow-comparison.md](../10-comparison-matrices/04-auth-flow-comparison.md) |
| `source4/rpc_server/drsuapi/` | DRSUAPI server side — `getncchanges.c` (opnum 3), `drsuapi.c` (Bind), `repl_executor.c` | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md), [../03-directory-schema/05-replication-internals.md](../03-directory-schema/05-replication-internals.md) |
| `source4/rpc_server/netlogon/` | MS-NRPC server side — `netlogon.sreg` (NetrServerAuthenticate3, NetrSamLogon), `netlogon_pac.c` (PAC validation) | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md), [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| `source4/kdc/` | Heimdal-based KDC for Samba AD-DC — `hdb-samba4.c` (SAM backend as HDB), `pac-glue.c` | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `source4/dsdb/` | Directory DB layer — `samdb.c` (LDB wrapper), `repl/replicated.c` (replication application) | [../03-directory-schema/05-replication-internals.md](../03-directory-schema/05-replication-internals.md) |
| `libcli/ldap/` | LDAP client lib — `ldap_message.c` (BER encode/decode), `ldap_client.c` | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `lib/krb5_wrap/` | Kerberos wrapper — `krb5_samba.c` (handles Heimdal/MIT differences) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `librpc/idl/drsuapi.idl` | DRSUAPI IDL — interface UUID, opnum table, NDR type definitions | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| `librpc/idl/netlogon.idl` | MS-NRPC IDL | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| `libds/common/` | LDB (LDAP-like local DB) — used by Samba AD-DC as the directory store | [../01-ad-core/01-ad-ds-internals.md](../01-ad-core/01-ad-ds-internals.md) |

### SSSD
- **Repo:** https://github.com/SSSD/sssd
- **Primary language:** C
- **License:** GPL-3.0-or-later
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `src/providers/ad/` | AD provider — `ad_access.c` (GPO access control), `ad_id.c` (id lookup), `ad_dyndns.c` (GSS-TSIG updates), `ad_pac.c` (PAC processing), `ad_subdomains.c` (forest trust enumeration) | [../09-linux-equivalents/01-sssd-ad-provider.md](../09-linux-equivalents/01-sssd-ad-provider.md), [../09-linux-equivalents/03-sssd-gpo-access.md](../09-linux-equivalents/03-sssd-gpo-access.md), [../02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md), [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| `src/providers/ldap/` | LDAP provider (AD is a subclass) — `ldap_auth.c`, `ldap_id.c`, `ldap_id_cleanup.c`, `sdap.c` (SDAP library wrapper) | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `src/providers/ldap/sdap.c` | SDAP (Smart LDAP) — wraps libldap-2.4 with paging, dereferencing, async | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `src/providers/krb5/` | Kerberos provider — `krb5_auth.c`, `krb5_utils.c`, `krb5_child.c` (the helper that calls MIT krb5) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/responder/` | Per-responder code — `nss/` (NSS responder), `pam/` (PAM responder), `ssh/` (SSH known_hosts), `sudo/` (sudoers), `autofs/` (automount maps), `pac/` (PAC responder for `pac` service) | [../09-linux-equivalents/01-sssd-ad-provider.md](../09-linux-equivalents/01-sssd-ad-provider.md) |
| `src/db/` | Local cache backend — `sysdb.c` (LDB-backed cache; user/group/override entries) | [../09-linux-equivalents/01-sssd-ad-provider.md](../09-linux-equivalents/01-sssd-ad-provider.md) |
| `src/external/` | Bundled `adcli` source (subproject) — `adcli/adcli.c`, `adcli/adconn.c` (LDAP connection), `adcli/adjoin.c` (domain-join), `adcli/adpasswd.c` (kpasswd integration) | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |
| `src/util/` | Common utilities — `find_uid.c`, `sss_krb5.c` (Kerberos helpers), `sss_ldap.c` (LDAP helpers) | (cross-cutting) |
| `src/sss_client/` | NSS + PAM client libraries — `nss_sss.c`, `pam_sss.c` (loaded by NSS/PAM via nsswitch.conf and authselect) | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |
| `src/confdb/` | Config DB — parses `sssd.conf`, stores parsed config in LDB | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |
| `src/monitor/` | `sssd` monitor process — supervisor that spawns responders and providers | [../09-linux-equivalents/01-sssd-ad-provider.md](../09-linux-equivalents/01-sssd-ad-provider.md) |

### Heimdal Kerberos
- **Repo:** https://github.com/heimdal/heimdal
- **Primary language:** C
- **License:** BSD-3-Clause (and Heimdal-specific permissive license)
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `lib/krb5/` | Kerberos library — `krb5_init_context.c`, `init_creds.c` (AS-REQ flow), `creds.c` (TGS-REQ), `mk_req.c` (AP-REQ), `rd_req.c` (AP-REP verify), `pac.c` (PAC processing), `fast.c` (FAST armoring) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| `lib/gssapi/` | GSS-API implementation — `mech/krb5/`, `ntlm/` (NTLM via SPNEGO) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |
| `lib/hdb/` | HDB (Heimdal Database) — `hdb-ldap.c` (LDAP backend), `hdb-keytab.c` (keytab backend), `hdb.c` (front-end) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `kdc/` | KDC daemon — `kdc.c` (main), `kdc_locl.h`, `connect.c` (TCP/UDP listener), `kerberos5.c` (AS-REQ/TGS-REQ handling), `pkinit.c` (PKINIT) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `lib/kadm5/` | kadmin protocol — `client.c` (kpasswd / chpass), `server.c` | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `lib/ntlm/` | NTLM implementation — `ntlm.c` (Type 1/2/3 messages), `ntlm_decode.c` | [../02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |
| `lib/wind/` | IDNA / Unicode normalization | (cross-cutting) |

### MIT Kerberos
- **Repo:** https://github.com/krb5/krb5
- **Primary language:** C
- **License:** MIT (with some BSD-licensed components)
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `src/lib/krb5/` | Kerberos library — `krb/init_creds.c` (AS-REQ flow), `krb/get_in_tkt.c` (pre-auth dispatch), `krb/chpw.c` (kpasswd), `krb/conv_princ.c` (cross-realm referral), `krb/gc_via_tkt.c` (TGS-REQ) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/lib/krb5/krb/preauth_otp.c` | OTP pre-auth plugin (RFC 6560) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/lib/krb5/krb/pkinit.c` | PKINIT plugin (RFC 4556) — `pa_pkinit_gen_req`, `pa_pkinit_process_rep` | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/lib/krb5/krb/fast.c` | FAST armoring (RFC 6806) — `krb5int_fast_prep_req_body`, `krb5int_fast_verify` | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/lib/gssapi/` | GSS-API implementation — `krb5/`, `spnego/` (SPNEGO), `generic/` | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| `src/kdc/` | KDC daemon — `kdc_util.c`, `do_as_req.c` (AS-REQ), `do_tgs_req.c` (TGS-REQ), `kdc_preauth.c` (pre-auth plugin dispatch) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/kadmin/` | kadmin protocol — `client/client.c` (kpasswd), `server/srvproc.c` (chpass RPC) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/plugins/preauth/pkinit/` | PKINIT plugin (separate from `krb/pkinit.c` which is the wrapper) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/lib/krb5/os/` | OS layer — `locate_kdc.c` (DNS SRV lookup), `sendto_kdc.c` (transport), `changepw.c` (kpasswd client) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| `src/lib/krb5/asn.1/` | ASN.1 generated code — `krb5_asn1.h` (Kerberos message types) | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |

### FreeIPA
- **Repo:** https://github.com/freeipa/freeipa
- **Primary language:** Python (server + client) + C (slapi plugins) + JS (Web UI)
- **License:** GPL-3.0-or-later
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `daemons/ipa-slapi-plugins/` | 389DS plugins — `ipa-pwd-extop/` (Password Modify extop, AD-compatible password policy), `ipa-cldap/` (CLDAP listener for Netlogon), `ipa-extdom-extop/` (External Domain Resolution extop — translates AD SIDs to POSIX IDs for NFS clients) | [../09-linux-equivalents/08-freeipa-trust.md](../09-linux-equivalents/08-freeipa-trust.md), [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `daemons/ipa-slapi-plugins/ipa-cldap/` | CLDAP (Connectionless LDAP) — implements `NetLogon` attribute queries for AD-DC discovery from Linux | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `daemons/ipa-slapi-plugins/ipa-extdom-extop/` | External Domain Resolution — returns POSIX info for AD-trusted users, allowing NFSv4 and other NSS-dependent services to resolve them | [../09-linux-equivalents/08-freeipa-trust.md](../09-linux-equivalents/08-freeipa-trust.md) |
| `daemons/ipa-kdb/` | KDB plugin for MIT krb5 — `ipa_kdb.c` (principal lookup against 389DS), `ipa_kdb_mspac.c` (PAC generation — IPA issues MS-PAC for cross-forest trust users), `ipa_kdb_delegation.c` | [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md), [../09-linux-equivalents/08-freeipa-trust.md](../09-linux-equivalents/08-freeipa-trust.md) |
| `daemons/ipa-sra/` | SRA (Smart Card CA Registration Authority) — integrates IPA-issued certs with AD CS | [../01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| `ipaclient/` | Client-side code — `ipaclient/install/ipa_client.py` (ipa-client-install), `ipaclient/plugins/` (CLI plugin tree: user, group, host, hbacrule, sudorule, dnsrecord, service, cert) | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |
| `ipaserver/` | Server-side code — `ipaserver/install/` (ipa-server-install, ipa-replica-install, ipa-adtrust-install — sets up cross-forest trust), `ipaserver/plugins/` (server-side plugin tree mirroring client) | [../09-linux-equivalents/08-freeipa-trust.md](../09-linux-equivalents/08-freeipa-trust.md) |
| `ipalib/` | Common library — `ipalib/errors.py` (exception hierarchy), `ipalib/krb_utils.py` (Kerberos helpers), `ipalib/util.py` (DN, certificate parsing) | (cross-cutting) |
| `ipapython/` | Python utilities — `ipapython/dn.py` (DN class), `ipapython/ipautil.py` (run_external_command wrapper) | (cross-cutting) |
| `ipaplatform/` | Platform-specific (RedHat/Debian/Suse paths, services, package managers) — used by install scripts | (cross-cutting) |
| `ipatests/` | Test suite (not relevant for AD ops but useful as reference for code paths) | (out of scope) |

### OpenLDAP
- **Repo:** https://github.com/openldap/openldap-portable (mirror; canonical: https://git.openldap.org/openldap/openldap)
- **Primary language:** C
- **License:** OLDAP-2.8 (custom permissive)
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `servers/slapd/` | `slapd` server — `bind.c` (BindRequest handling), `search.c` (SearchRequest), `modify.c`, `add.c`, `delete.c`, `controls.c` (controls dispatcher), `frontend.c` | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `servers/slapd/overlays/` | Overlay modules — `syncprov.c` (RFC 4533 syncrepl), `ppolicy.c` (Password Policy), `auditlog.c` | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `servers/slapd/back-mdb/` | MDB backend (default) — `search.c`, `modify.c`, `add.c` | [../01-ad-core/04-ad-lds-adam.md](../01-ad-core/04-ad-lds-adam.md) |
| `servers/slapd/back-ldap/` | LDAP backend (proxy to AD) — useful for AD LDS-style mirroring | [../01-ad-core/04-ad-lds-adam.md](../01-ad-core/04-ad-lds-adam.md) |
| `clients/tools/` | CLI clients — `ldapsearch.c`, `ldapmodify.c`, `ldapadd.c`, `ldapdelete.c`, `ldapcompare.c` | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md), [../11-code-examples/03-macos-cli-recipes.md](../11-code-examples/03-macos-cli-recipes.md) |
| `libraries/libldap/` | LDAP client library — `bind.c` (SASL bind dispatcher), `sasl.c` (GSSAPI), `search.c`, `controls.c` (paged control), `tls.c` (StartTLS) | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md), [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |
| `libraries/liblber/` | BER (Basic Encoding Rules) library — `encode.c`, `decode.c`, `io.c` | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `contrib/slapd-modules/` | Optional modules — `adpp.c` (AD password policy), `passwd/pbkdf2.c`, `nssov.c` (NSS overlay) | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |

### impacket
- **Repo:** https://github.com/fortra/impacket
- **Primary language:** Python
- **License:** Apache-2.0 (recent versions); earlier BSD-style
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `impacket/spnego/` | SPNEGO implementation — `spnego.py` (NegTokenInit/NegTokenResp), `smbserver.py` (server-side SPNEGO) | [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) |
| `impacket/krb5/` | Kerberos client — `kerberosv5.py` (getKerberosTGT, getKerberosTGS), `pac.py` (PAC structures), `ccache.py` (CCACHE parser), `types.py` (Principal, Ticket), `constants.py` (etypes, error codes) | [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md), [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md), [../02-protocols/08-spn-upn-pac.md](../02-protocols/08-spn-upn-pac.md) |
| `impacket/ldap/` | LDAP client (independent of `ldap3`) — `ldap.py` (LDAPConnection), `ldapasn1.py` (ASN.1 message definitions) | [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| `impacket/dcerpc/v5/` | DCE/RPC client — `drsuapi.py` (DRSUAPI interface, all opnums), `netlogon.py` (MS-NRPC), `lsa.py` (MS-LSAD), `samr.py` (MS-SAMR), `srvs.py` (MS-SRVS), `scmr.py` (Service Control Manager), `spnego.py` (SPNEGO over DCE/RPC), `transport.py` (transport factory for `ncacn_ip_tcp`, `ncacn_np`, etc.) | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| `impacket/dcerpc/v5/drsuapi.py` | DRSUAPI Python bindings — `MSRPC_UUID_DRSUAPI`, `DRSBind`, `DRSGetNCChanges`, `DRSCrackNames`, `DRSUnbind` | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md), [../03-directory-schema/05-replication-internals.md](../03-directory-schema/05-replication-internals.md) |
| `impacket/dcerpc/v5/dtypes.py` | Common NDR types — `SID`, `SECURITY_DESCRIPTOR`, `FILETIME`, `GUID` (mirrors MS-DTYP) | [../02-protocols/06-rpc-dcerpc-ms-drsr.md](../02-protocols/06-rpc-dcerpc-ms-drsr.md) |
| `impacket/smbconnection.py` | SMB2/3 connection class — `SMBConnection.login`, `kerberosLogin`, `listShares`, `listPath`, `getFile`, `putFile` | [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md), [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) |
| `impacket/smb3structs.py` | SMB2/3 packet structures — `SMB2Header`, `SMB2Negotiate`, `SMB2SessionSetup`, `SMB2Create` | [../02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| `impacket/ntlm.py` | NTLMSSP client — Type 1/2/3 messages, NTLMv2 response computation | [../02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |
| `examples/GetUserSPNs.py` | Kerberoasting tool | [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) |
| `examples/secretsdump.py` | DCSync + SAM extraction tool | [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) |
| `examples/ticketer.py` | Ticket forging (golden / silver / diamond) | [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) |
| `examples/getST.py` | S4U2Self + S4U2Proxy (constrained delegation) | [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) |
| `examples/wmiexec.py`, `psexec.py`, `smbclient.py`, `atexec.py`, `dcomexec.py` | Remote execution tools | [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) |

### realmd
- **Repo:** https://gitlab.freedesktop.org/realmd/realmd
- **Primary language:** C
- **License:** LGPL-2.1-or-later
- **Key subpaths for AD-relevant code:**

| Path | Contents | KB files |
|---|---|---|
| `service/` | `realmd` D-Bus service — `realm-daemon.c` (main), `realm-invocation.c` (D-Bus method dispatch), `realm-provider.c` (provider abstraction) | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |
| `service/realm-ad-provider.c` | AD provider — wraps `adcli` for join, `sssd` for config generation | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |
| `service/realm-ipa-provider.c` | FreeIPA provider — wraps `ipa-client-install` | [../09-linux-equivalents/08-freeipa-trust.md](../09-linux-equivalents/08-freeipa-trust.md) |
| `service/realm-samba-provider.c` | Samba/Winbind provider — wraps `net ads join` | [../09-linux-equivalents/04-winbind-internals.md](../09-linux-equivalents/04-winbind-internals.md) |
| `tools/` | CLI client — `realm-tool.c` (`realm join`, `realm leave`, `realm list`, `realm permit`, `realm deny`) | [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) |

### Apple OpenDirectory (not open-source)

Apple's OpenDirectory framework is closed-source. The closest open-source reference is:
- **Public headers:** `/System/Library/Frameworks/OpenDirectory.framework/Headers/` on macOS SDK (OpenDirectory, OpenDirectoryConsts, CFOpenDirectory, etc.)
- **CLT binaries:** `dscl`, `dsconfigad`, `dsmemberutil`, `sso_util`, `dsimport`, `dsexport` — closed-source but documented in `man` pages.
- **Heimdal fork:** Apple's Heimdal Kerberos fork is closed-source but tracks upstream closely. Best reference for behavior is upstream Heimdal: https://github.com/heimdal/heimdal
- **Samba macOS client:** Apple's SMBX/SMB client is closed-source. Reference for SMB3.1.1 wire behavior is upstream Samba: https://github.com/samba-team/samba

See:
- Apple OpenDirectory framework reference: https://developer.apple.com/documentation/opendirectory
- Apple Platform SSO Extension API: https://developer.apple.com/documentation/authenticationservices/asauthorizationazssocredentialprovider (PSSO Extension is a SSO Extension type added in macOS 13)
- Apple Network Services Framework (Kerberos): https://developer.apple.com/documentation/foundation/urlsession?language=occ (Foundation wraps Kerberos via `URLCredential`)

## License compatibility quick reference

| Project | License | Compatible with AD closed-source extension? |
|---|---|---|
| Samba | GPL-3.0+ | No (viral — extensions must also be GPL) |
| SSSD | GPL-3.0+ | No (viral) |
| Heimdal | BSD-3-Clause | Yes |
| MIT krb5 | MIT | Yes |
| FreeIPA | GPL-3.0+ | No (viral) |
| OpenLDAP | OLDAP-2.8 | Yes (BSD-like) |
| impacket | Apache-2.0 (recent) / BSD (older) | Yes |
| realmd | LGPL-2.1+ | Yes (LGPL allows dynamic linking) |

> ⚠ Embedding GPL-licensed code (Samba, SSSD, FreeIPA) into a closed-source product is generally not allowed. For commercial AD integration products, MIT krb5, Heimdal, OpenLDAP, and impacket are the safe choices.

## Build / install quick reference

| Project | Debian/Ubuntu | RHEL/Fedora | macOS | Windows |
|---|---|---|---|---|
| Samba | `apt install samba smbclient libsmbclient-dev` | `dnf install samba samba-client samba-devel` | Homebrew: `brew install samba` (not officially packaged) | Native SMB client (no port) |
| SSSD | `apt install sssd` | `dnf install sssd` | n/a (use Apple Samba or PSSO Extension) | n/a |
| Heimdal | `apt install heimdal-dev` | `dnf install heimdal-devel` | Bundled (fork) | n/a |
| MIT krb5 | `apt install krb5-{user,kdc,admin,multidev}` | `dnf install krb5-{workstation,server,libs,devel}` | Homebrew: `brew install krb5` | MIT Kerberos for Windows: https://web.mit.edu/kerberos/ |
| FreeIPA | `apt install freeipa-client` (only client on Debian; server not officially supported) | `dnf install freeipa-client freeipa-server freeipa-server-dns` | n/a | n/a |
| OpenLDAP | `apt install slapd ldap-utils libldap2-dev` | `dnf install openldap-servers openldap-clients openldap-devel` | Bundled | OpenLDAP for Windows (community port) |
| impacket | `pip install impacket` | `pip install impacket` | `pip install impacket` | `pip install impacket` |
| realmd | `apt install realmd adcli` | `dnf install realmd adcli` | n/a | n/a |

## See also

- [./01-ms-protocols-reference.md](./01-ms-protocols-reference.md) — Microsoft Open Specifications.
- [./02-rfcs-standards.md](./02-rfcs-standards.md) — IETF RFCs and OASIS / ISO standards.
- [../09-linux-equivalents/01-sssd-ad-provider.md](../09-linux-equivalents/01-sssd-ad-provider.md) — SSSD AD provider internals.
- [../09-linux-equivalents/04-winbind-internals.md](../09-linux-equivalents/04-winbind-internals.md) — Winbind internals.
- [../09-linux-equivalents/08-freeipa-trust.md](../09-linux-equivalents/08-freeipa-trust.md) — FreeIPA cross-forest trust.
- [../09-linux-equivalents/09-openldap-389ds.md](../09-linux-equivalents/09-openldap-mit-kerberos.md) — OpenLDAP / 389DS.
- [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) — impacket recipes.
