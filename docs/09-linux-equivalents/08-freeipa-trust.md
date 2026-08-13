---
title: FreeIPA and AD Cross-Forest Trust — Architecture, ID Views, HBAC
audience: senior-engineers
tags: [freeipa, ipa, trust, ad, krb5, cross-realm, hbac, extdom, sssd, id-views]
related:
  - ./01-sssd-ad-provider.md
  - ./02-sssd-id-mapping.md
  - ./03-sssd-gpo-access.md
  - ./09-openldap-mit-kerberos.md
  - ../02-protocols/01-kerberos-internals.md
  - ../03-directory-schema/04-trusts-topology.md
  - ../08-macos-equivalents/01-opendirectory-internals.md
last_updated: 2026-08-13
---

FreeIPA is a Linux-side identity and policy platform that bundles 389-DS LDAP, MIT Kerberos (KDC + kadmin), BIND DNS (with a custom LDAP-backed zone store via the `bind-dyndb-ldap` plugin), Dogtag PKI (CA + KRA), certmonger for certificate lifecycle, and SSSD for client-side integration; when configured with a cross-forest trust to Active Directory via `ipa trust-add`, the FreeIPA KDC establishes Kerberos cross-realm TGT-referral routing (RFC 4120 §3.3.3) and the FreeIPA directory server exposes AD users and groups to POSIX clients through the `ipa-extdom-plugin` (LDAP extended operation 2.16.840.1.113730.3.8.10.4) which proxies lookups to Samba's `libads`/`librpc` to resolve SIDs from the AD Global Catalog.

## Architecture

```
              AD Forest CORP.EXAMPLE.COM                  FreeIPA Realm EXAMPLE.COM
              ─────────────────────────                  ──────────────────────────
        ┌───────────────────────────┐                ┌──────────────────────────┐
        │ DC01  KDC + GC + LDAP     │ cross-realm    │ ipa01                    │
        │ DC02  KDC + GC + LDAP     │◄──────────────►│   389-DS (LDAP)          │
        │                           │ trust          │   krb5kdc + kadmin       │
        │ CN=Users,…                │                │   BIND (dns)             │
        │   user1 S-1-5-21-…        │                │   Dogtag CA              │
        │                           │                │   ipa-extdom-plugin      │
        │ CN=System,CN=…            │                │   sssd (IPA provider)    │
        │   trustedDomain EXAMPLE.COM│                │                          │
        └───────────────────────────┘                └──────────────────────────┘
                                                            │
                                                            │ ipa trust-add writes
                                                            ▼
                                                    cn=ad,cn=trusts,…              (trust container)
                                                    cn=<SID>,cn=ad,…               (per-trusted-domain)
                                                    ipaNTTrustedDomainSID         (AD forest SID)
                                                    ipaNTSupportedEncryptionTypes (AES256+AES128)
                                                    ipaNTTrustDirection           (1=in,2=out,3=bi)
                                                    ipaNTTrustType                (2=uplevel=AD)
                                                    ipaNTTrustAttributes          (0x8=FOREST_TRANSITIVE)
                                                    ipaNTAdditionalSettings
                                                    ipaNTTrustForestTrustInfo     (domain map / TLN)
```

### Components

| Component | Source path / binary | Role |
|---|---|---|
| 389-DS LDAP | `ns-slapd` (RHEL: `389-ds-base` package) | FreeIPA's directory backend; stores users, groups, hosts, HBAC, sudo rules, ID views, trust objects. Source: https://github.com/389ds/389-ds-base |
| MIT Kerberos KDC | `krb5kdc` (MIT krb5 + FreeIPA KDB plugin) | Issues TGTs for EXAMPLE.COM; supports cross-realm referral to CORP.EXAMPLE.COM via `capaths` configuration. Source: https://github.com/krb5/krb5 (KDB plugin in `src/plugins/kdb/ldap/`) |
| BIND DNS | `named` + `bind-dyndb-ldap` plugin | DNS for the FreeIPA zone; stores zone data in LDAP. Source: https://github.com/freeipa/bind-dyndb-ldap |
| Dogtag PKI | `pki-tomcatd` (Dogtag CA + KRA) | Issues host and service certificates; NTP-signed cert auth for `ipa host-add`. Source: https://github.com/dogtagpki/pki |
| certmonger | `certmonger` | Watches host certs, renews via Dogtag. Source: https://pagure.io/certmonger |
| `ipa-extdom-plugin` | 389-DS plugin `libipa_extdom.so` | The LDAP extended operation `ipa-extdom-lookup` (OID 2.16.840.1.113730.3.8.10.4) that resolves AD SIDs/names by calling Samba `libads`/`librpc` against the AD GC. Source: `daemons/ipa-extdom-extop/ipa_extdom.h:c:ipa_extdom_extop` in https://github.com/freeipa/freeipa |
| `ipa-smbd` | (none — IPA ships Samba tools, not smbd) | `ipa trust-add` calls `smbpasswd` + `net ads` internally to write the trust secret. |
| SSSD (client side) | `sssd_be` with `id_provider = ipa` | FreeIPA-enrolled clients talk to their IPA server, which proxies AD subdomain lookups via `ipa-extdom-plugin` |
| HBAC service | `ipa_hbac` SSSD responder + server-side rules in LDAP | Host-Based Access Control — equivalent of GPO logon restrictions but stored in IPA |

### Trust creation flow

`ipa trust-add --type=ad corp.example.com --admin admin --password` runs:

1. **Kerberos credentials** — `kinit admin@CORP.EXAMPLE.COM` with the supplied password (so the IPA server has a TGT in the AD realm).
2. **AD-side trust creation** — calls `net rpc trust create` (Samba `source3/librpc/cli_lsa.c:cli_lsa_create_trust`) which:
   - Opens LSA policy on a DC of `corp.example.com` (`LsaOpenPolicy3`).
   - Calls `LsaCreateTrustedDomainEx3` with `TRUST_ATTRIBUTE_FOREST_TRANSITIVE` (0x8) and `TRUST_TYPE_UPLEVEL` (2) — see `../03-directory-schema/04-trusts-topology.md` for the `trustAttributes` bitmask.
   - Sets the trust password (a randomly generated 32-char string).
3. **IPA-side trust object** — adds `ipaNTTrustedDomain` object under `cn=corp.example.com,cn=ad,cn=trusts,cn=ipa,cn=etc,dc=example,dc=com` with attributes:
   - `ipaNTTrustedDomainSID: S-1-5-21-...` (forest SID of corp.example.com)
   - `ipaNTTrustDirection: 3` (two-way)
   - `ipaNTTrustType: 2` (uplevel — AD)
   - `ipaNTTrustAttributes: 8` (FOREST_TRANSITIVE)
   - `ipaNTTrustPartner: corp.example.com`
   - `ipaNTFlatName: CORP`
   - `ipaNTAuthTrustBlob: <binary>` (LSA_AUTH_INFORMATION array — see `../03-directory-schema/04-trusts-topology.md`)
   - `ipaNTAdditionalSettings: ...`
4. **Kerberos cross-realm principals** — `krbtgt/CORP.EXAMPLE.COM@EXAMPLE.COM` and `krbtgt/EXAMPLE.COM@CORP.EXAMPLE.COM` are created in the MIT KDB with the same password as the AD-side trust secret.
5. **KDC capaths** — `/var/kerberos/krb5kdc/kdc.conf` is updated with `[capaths]` section so the KDC knows to issue referral TGTs (`EXAMPLE.COM → CORP.EXAMPLE.COM` direct).
6. **ID range allocation** — `ipa idrange-add` creates a `ipaIDRange` object containing the algorithmic mapping parameters for AD users:
   - `ipaBaseID` (e.g. 1000000) — equivalent to SSSD's `ldap_idmap_range_min` for this domain
   - `ipaIDRangeSize` (e.g. 200000)
   - `ipaRangeType: ipa-ad-trust`
   - `ipaNTTrustedDomainSID: S-1-5-21-...` — the domain SID used to compute slice
7. **AD subdomain refresh** — SSSD on the IPA server (`sssd_be` with `id_provider = ipa`) runs the `ipa_subdomains_refresh` task that calls the `ipa_extdom_extop` to enumerate trusted domains (`CN=Configuration,…,CN=Partitions` LDAP query against AD).

### Cross-realm TGT referral

When `user1@CORP.EXAMPLE.COM` SSHs to `host01.example.com`:

1. `user1` runs `kinit user1@CORP.EXAMPLE.COM` → AD KDC issues `krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM` TGT (RFC 4120 §3.3.3 referral path).
2. SSH client `ssh user1@CORP.EXAMPLE.COM@host01.example.com` requests a service ticket `host/host01.example.com@EXAMPLE.COM` from the AD KDC.
3. AD KDC sees the target realm is in a trusted forest → issues a referral TGT `krbtgt/EXAMPLE.COM@CORP.EXAMPLE.COM` (encrypted with the cross-realm trust key).
4. Client uses that referral TGT to TGS-REQ the IPA KDC → IPA KDC issues `host/host01.example.com@EXAMPLE.COM` service ticket.
5. SSH presents the service ticket; `sshd` calls `pam_sss.so`; SSSD `pam_sss` validates the PAC by sending it to the IPA server's `ipa-extdom-extop` plugin which calls AD's `NetrLogonSamLogonEx` for PAC validation.
6. IPA server's SSSD `ipa` provider runs HBAC check (`ipa_hbac_evaluate_rules`) — if a rule allows `user1@CORP.EXAMPLE.COM` from any source host to `sshd` on `host01`, allow.

### `ipa-extdom-plugin` extended operation

OID: `2.16.840.1.113730.3.8.10.4`. Request payload (BER-encoded `SEQUENCE`):

```
extdomRequest ::= SEQUENCE {
    input     InputType,        -- 1=name, 2=sid, 3=uid, 4=gid
    request   CHOICE {
        name    [0] SEQUENCE { domain OCTET STRING, name OCTET STRING },
        sid     [1] OCTET STRING,
        uid     [2] INTEGER,
        gid     [3] INTEGER
    },
    extended  BOOLEAN           -- if true, return full struct with all groups
}
```

Response carries `ExtdomRes` (user/group struct with name, SID, uidNumber, gidNumber, gecos, home, shell, list of groups). The plugin invokes `wbcGetpwnam` / `wbcGetpwuid` from `libwbclient` which talks to a Samba `winbindd` instance co-located on the IPA server (special `ipa-server-trust-ad` setup runs `winbindd` configured for AD use only — not for NSS).

## Configuration

### `/etc/sssd/sssd.conf` on a FreeIPA-enrolled client

```
[domain/example.com]
id_provider = ipa
auth_provider = ipa
access_provider = ipa
chpass_provider = ipa
ipa_domain = example.com
ipa_server = _srv_, ipa01.example.com, ipa02.example.com
ipa_hostname = host01.example.com

# Trust-aware settings
ipa_server_mode = false                # true only on IPA servers (enables subdomain handling)

# Subdomain (AD users) settings
subdomain_inherit = ignore_group_members, use_fully_qualified_names
subdomain_homedir = /home/%d/%u
default_shell = /bin/bash
use_fully_qualified_names = true
fallback_homedir = /home/%u@%d

# Kerberos
krb5_realm = EXAMPLE.COM
krb5_renewable_lifetime = 7d
krb5_lifetime = 10h
krb5_renew_interval = 1h
krb5_use_fast = try
krb5_store_password_if_offline = true
krb5_ccachedir = /run/user/%u/krb5cc

# Cache
cache_credentials = true
entry_cache_timeout = 5400

# HBAC
ipa_hbac_refresh = 60                  # seconds between HBAC rule refreshes
ipa_hbac_treat_deny_as_deny = true

# GPO — disabled by default in IPA provider; HBAC is the preferred access control
ad_gpo_access_control = disabled

[sssd]
services = nss, pam, sudo, ssh, ifp, pac
domains = example.com
config_file_version = 2

[pam]
pam_id_timeout = 10
offline_credentials_expiration = 60

[nss]
filter_users = root, dirsrv
filter_groups = root
memcache_timeout = 5400
```

### `/etc/krb5.conf` on a FreeIPA-enrolled client

```ini
includedir /var/lib/sss/pubconf/krb5.include.d/
includedir /etc/krb5.conf.d/

[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/kadmind.log

[libdefaults]
 default_realm = EXAMPLE.COM
 dns_lookup_realm = true
 dns_lookup_kdc = true
 rdns = false
 ticket_lifetime = 24h
 forwardable = yes
 renew_lifetime = 7d

[realms]
 EXAMPLE.COM = {
  kdc = ipa01.example.com:88
  kdc = ipa02.example.com:88
  admin_server = ipa01.example.com:749
  default_domain = example.com
  pkinit_anchors = FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem
  pkinit_pool = FILE:/var/lib/ipa-client/pki/ca-bundle.pem
 }

[domain_realm]
 .example.com = EXAMPLE.COM
 example.com = EXAMPLE.COM

[capaths]
 EXAMPLE.COM = {
   CORP.EXAMPLE.COM = .
 }
 CORP.EXAMPLE.COM = {
   EXAMPLE.COM = .
 }
```

The `.` in `[capaths]` means "direct trust exists" — KDCs will issue cross-realm referral TGTs without intermediate hops. For indirect trust (e.g. `EXAMPLE.COM` trusts `EXAMPLE.ORG` which trusts `CORP.EXAMPLE.COM`), list the path explicitly:

```
[capaths]
 EXAMPLE.COM = {
   CORP.EXAMPLE.COM = EXAMPLE.ORG
 }
```

## Commands / examples

```bash
# Establish trust (from an IPA admin session)
kinit admin
ipa trust-add --type=ad corp.example.com --admin admin --password
# Output: --------------------------------------------------------
#         Realm name: corp.example.com
#         Domain NetBIOS name: CORP
#         Domain Security Identifier: S-1-5-21-...
#         Trust direction: Two-way trust
#         Trust type: Active Directory
#         --------------------------------------------------------

# Verify
ipa trust-show corp.example.com
ipa trust-fetch-domains corp.example.com           # pull list of child domains
ipa trustdomain-find corp.example.com

# ID range
ipa trustconfig-find
ipa idrange-find
ipa idrange-add CORP.EXAMPLE.COM_id_range --base-id=1000000 --range-size=200000 \
  --rid-base=0 --secondary-rid-base=0 --type=ipa-ad-trust

# Allow AD users to log in to a host (HBAC)
ipa hbacrule-add allow_ad_ssh
ipa hbacrule-add-user --groups='ad_admins@corp.example.com' allow_ad_ssh
ipa hbacrule-add-host --hosts=host01.example.com allow_ad_ssh
ipa hbacrule-add-service --hbacsvcs=sshd allow_ad_ssh

# Default HBAC rule "allow_all" is created at install; disable for explicit policy
ipa hbacrule-disable allow_all

# Test HBAC evaluation
ipa hbactest --user=user1@corp.example.com --host=host01.example.com --service=sshd

# ID view (per-host or per-user overrides)
ipa idview-add override_host01
ipa idoverrideuser-add override_host01 'user1@corp.example.com' --uid=10042 --gid=10042 \
  --homedir=/home/user1 --shell=/bin/zsh --gecos='User One'
ipa idview-apply override_host01 --hosts=host01.example.com

# Sudo rules (sudoers stored in IPA LDAP)
ipa sudorule-add admin-commands
ipa sudorule-add-user --groups='ad_admins@corp.example.com' admin-commands
ipa sudorule-add-host --hosts=host01.example.com admin-commands
ipa sudorule-add-allow-command --sudocmds='/usr/bin/su, /usr/sbin/visudo' admin-commands
ipa sudorule-add-option admin-commands --sudooption='!authenticate'

# From a client (after ipa-client-install):
ipa-client-install --domain=example.com --realm=EXAMPLE.COM --server=ipa01.example.com -U

# Verify AD user can resolve
getent passwd user1@corp.example.com
id user1@corp.example.com

# Test cross-realm Kerberos
kinit user1@CORP.EXAMPLE.COM
kvno host/host01.example.com@EXAMPLE.COM

# Tear down
ipa trust-del corp.example.com
```

## Wireshark / tshark

```
# Kerberos cross-realm referral TGT (TGS-REP from AD KDC with krbtgt/EXAMPLE.COM@CORP.EXAMPLE.COM)
kerberos.msg_type == 13 && kerberos.SName contains "krbtgt/EXAMPLE.COM"

# Service ticket from IPA KDC (host/host01.example.com@EXAMPLE.COM)
kerberos.msg_type == 13 && kerberos.SName contains "host/host01"

# ipa-extdom-extop LDAP extended operation (OID 2.16.840.1.113730.3.8.10.4)
ldap.extop.opcode == "2.16.840.1.113730.3.8.10.4"

# LsaCreateTrustedDomainEx3 (during ipa trust-add)
dcerpc.lsa.opnum == 44

# LSA queries from ipa-extdom-plugin
dcerpc.lsa.opnum == 15 || dcerpc.lsa.opnum == 14   # LookupSids / LookupNames

# LDAP search for trusted domains (ipa_subdomains_refresh)
ldap.messageCode == 3 && ldap.filter contains "trustedDomain"
```

## FreeIPA-AD trust vs intra-forest AD trust

| Aspect | AD intra-forest trust | FreeIPA-AD cross-forest trust |
|---|---|---|
| Trust type | `trustAttributes & WITHIN_FOREST (0x20)` | `trustAttributes & FOREST_TRANSITIVE (0x8)` only — NOT `WITHIN_FOREST` |
| Automatic GC | Yes — every DC in the forest hosts GC; trusts inherit | No — FreeIPA servers must independently query AD GC via `ipa-extdom-plugin` |
| Automatic SID history | Yes — SID filtering within forest is implicit | Sid filtering enforced (trustAttributes does NOT have `QUARANTINED` cleared) |
| Universal group membership | Universal groups visible across the forest via GC | AD Universal groups only visible if SSSD resolves them via GC LDAP |
| KCC topology | Yes — automatic | No — manual trust |
| ID range | Auto-allocated by RID pool master | Manual `ipa idrange-add` |
| Trust password rotation | Auto (every 30 days) | Manual `ipa trust-fetch-domains` and `ipa trust-mod --shared-secret` |
| PAC validation | On DC (Netlogon secure channel) | Via `ipa-extdom-plugin` proxying to AD |
| Selective authentication | Optional | Mandatory equivalent via HBAC |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ipa trust-add` fails with `Operation denied` | Admin account lacks `Domain Admins` in AD | Use AD account that is member of `Domain Admins` |
| `ipa trust-add` succeeds but `ipa trust-fetch-domains` returns 0 | AD DNS not resolvable from IPA server; or firewall blocking IPA server → AD GC TCP/3268 | `dig SRV _ldap._tcp.gc._msdcs.corp.example.com +short` from IPA server; open TCP/3268, TCP/3269, TCP/135, dynamic RPC range |
| `id user1@corp.example.com` from IPA client returns nothing | IPA server's `sssd_be` failed to refresh subdomains | On IPA server: `systemctl restart sssd; ipa trust-fetch-domains corp.example.com`; check `/var/log/sssd/sssd_ipa.log` |
| AD user can `kinit` but cannot SSH | HBAC denies; or `subdomain_inherit` missing | `ipa hbactest --user=user1@corp.example.com --host=host01.example.com --service=sshd` |
| AD user SSH works but `id` shows wrong UID | ID range mismatch between IPA and a previous SSSD-only config | `ipa idrange-find`; ensure no overlap with SSSD algorithmic range on the same host |
| `kvno host/host01.example.com` returns `KDC has no support for encryption type` | AD KDC refuses AES; trust encryption types not set | `ipa trust-mod corp.example.com --shared-secret` to refresh; verify `ipaNTSupportedEncryptionTypes` on the trust object includes `0x18` (AES128+AES256) |
| PAC validation fails (`PAC signature verification failed`) | Trust secret out of sync | `ipa trust-add corp.example.com --admin admin --password` (re-establish) |
| Slow logins (5+ seconds) | `ipa-extdom-plugin` repeatedly querying AD GC | Ensure `cache_credentials = true`; check `ipaHBACattrParams` cache; tune `entry_cache_timeout` |
| `ipa hbactest` returns `Rule(s) not found` | HBAC service name doesn't match PAM service | IPA HBAC `sshd` matches PAM service `sshd`; check `/etc/pam.d/sshd` |
| Cross-realm TGS-REQ fails with `KDC_ERR_S_PRINCIPAL_UNKNOWN` | Service principal exists in wrong realm; or DNS canonicalization confusing the client | `kinit -S host/host01.example.com@EXAMPLE.COM user1@CORP.EXAMPLE.COM` to test directly; set `rdns = false` in `krb5.conf` |

Logs:
- IPA server: `/var/log/dirsrv/slapd-EXAMPLE-COM/errors`, `/var/log/krb5kdc.log`, `/var/log/sssd/sssd_ipa.log`, `/var/log/sssd/sssd_pac.log`
- IPA client: `/var/log/sssd/sssd_ipa.log`, `/var/log/sssd/sssd_pam.log`, `/var/log/sssd/sssd_nss.log`

## Cross-platform comparison

- **AD-side counterpart:** The cross-realm trust topology is identical to AD-AD forest trusts at the Kerberos level (RFC 4120 §3.3.3 + MS-KILE profile) — see `../02-protocols/01-kerberos-internals.md` for the referral TGT mechanics and `../03-directory-schema/04-trusts-topology.md` for the `trustedDomain` AD object schema, `trustDirection`/`trustType`/`trustAttributes` semantics, and `LsaCreateTrustedDomainEx3` parameters. IPA's `ipa-extdom-plugin` performs the role that the AD GC normally performs (resolving SIDs across the forest), so the FreeIPA-AD trust is functionally similar to a cross-forest trust but with the GC role externalized.
- **Native AD-join alternative:** A Linux host that joins AD directly via SSSD (`./01-sssd-ad-provider.md`) sees AD as the only identity source; with FreeIPA, the host sees the IPA server as the identity source and AD as a trust partner. FreeIPA adds: per-host sudo rules, per-host ID overrides, HBAC, host-based cert management, and SSO across all IPA-enrolled services.
- **OpenLDAP + MIT Kerberos alternative:** See `./09-openldap-mit-kerberos.md` for the "build your own" stack that FreeIPA bundles up and operationalizes.
- **macOS counterpart:** Apple's OpenDirectory is the conceptual analog of FreeIPA — a Linux/macOS-native directory service that can bridge to AD via trusts — see `../08-macos-equivalents/01-opendirectory-internals.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- FreeIPA source — https://github.com/freeipa/freeipa (see `daemons/ipa-extdom-extop/`, `daemons/ipa-sam/`, `ipaserver/plugins/trust.py`).
- 389-DS source — https://github.com/389ds/389-ds-base.
- MIT Kerberos source — https://github.com/krb5/krb5 (LDAP KDB plugin in `src/plugins/kdb/ldap/`).
- Samba source (used for trust creation and PAC validation) — https://github.com/samba-team/samba (see `source3/librpc/cli_lsa.c`, `source4/libnet/libnet_vampire.cc`).
- FreeIPA documentation — https://www.freeipa.org/page/Documentation.
- `ipa(1)`, `ipa-trust-add(1)`, `ipa-hbacrule-add(1)`, `ipa-idrange-add(1)`, `ipa-idoverrideuser-add(1)`, `sssd-ipa(5)`.
- RFC 4120 §3.3.3 — Cross-realm TGT referral; MS-KILE profile.
- MS-LSAD — `LsaCreateTrustedDomainEx3` (opnum 44).
