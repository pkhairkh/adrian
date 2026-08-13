---
title: OpenLDAP + MIT Kerberos — The Roll-Your-Own AD Alternative
audience: senior-engineers
tags: [openldap, slapd, mit-kerberos, krb5kdc, kadmin, nslcd, pam_krb5, pam_ldap, bind]
related:
  - ./08-freeipa-trust.md
  - ./01-sssd-ad-provider.md
  - ./10-pam-nss-stack.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/01-kerberos-internals.md
  - ../01-ad-core/04-ad-lds-adam.md
  - ../08-macos-equivalents/01-opendirectory-internals.md
last_updated: 2026-08-13
---

The roll-your-own alternative to AD is a manually composed stack of OpenLDAP `slapd` (the directory service), MIT Kerberos `krb5kdc` + `kadmind` (the KDC + admin server), BIND DNS (the dynamic-update-aware name service), `nslcd` (the NSS LDAP daemon), and `pam_krb5.so` + `pam_ldap.so` (the PAM auth/account modules), with the KDC reading its principal database from LDAP via the `kldap` plugin (`dbmodules = { LDAP = { db_library = kldap; … } }`) and the LDAP directory extended with `kerberos.schema` so that principal keys live in `krbPrincipalKey` attributes on the user objects — historically popular in academic and research environments for avoiding vendor lock-in, today mostly supplanted by FreeIPA which bundles the same components into a managed product.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ slapd (OpenLDAP, /usr/sbin/slapd)                                    │
│  - Listens: ldap://0.0.0.0:389, ldaps://0.0.0.0:636                 │
│  - Backend: mdb (or hdb, the Berkeley DB variant)                    │
│  - Schema: core.schema, cosine.schema, nis.schema, kerberos.schema   │
│  - Stores user objects with krbPrincipalName + krbPrincipalKey       │
└────────────┬─────────────────────────────────────────────────────────┘
             │ via /etc/krb5.conf dbmodules LDAP + krb5kdc -dbplugin kldap
             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ krb5kdc + kadmind (MIT Kerberos, /usr/sbin/krb5kdc, /usr/sbin/kadmind)│
│  - KDC listens: tcp/88, udp/88                                       │
│  - kadmin listens: tcp/464 (chpass), tcp/749 (kadmin)                │
│  - KDB backend: kldap → slapd                                        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ named (BIND, /usr/sbin/named)                                        │
│  - Listens: tcp/53, udp/53                                           │
│  - Zones: example.com (master) — dynamic update from dhcpd / nsupdate│
│  - TSIG-keyed updates (no GSS-TSIG unless bind9 compiled with        │
│    --with-gssapi)                                                    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ nslcd (NSS LDAP daemon, /usr/sbin/nslcd)                             │
│  - /etc/nslcd.conf maps NSS passwd/group/shadow to LDAP filters      │
│  - Listens: /var/run/nslcd/socket (Unix domain)                      │
│  - NSS module libnss_ldap.so.2 (or libnss_ldapd.so.2) → nslcd        │
└─────────────────────────────────────────────────────────────────────┘

PAM stack:
  auth     sufficient  pam_krb5.so try_first_pass
  auth     required    pam_ldap.so use_first_pass
  account  sufficient  pam_krb5.so
  account  required    pam_ldap.so
  password sufficient  pam_krb5.so
  password required    pam_ldap.so use_authtok
  session  required    pam_mkhomedir.so umask=0022 skel=/etc/skel
  session  required    pam_unix.so
```

## OpenLDAP `slapd`

Source: https://github.com/openldap/openldap. The server binary is `servers/slapd/slapd.c:main`. Configuration lives in `/etc/openldap/slapd.conf` (legacy) or `cn=config` (online config, stored in `/etc/openldap/slapd.d/cn=config.ldif`). Modern deployments use `cn=config` exclusively.

### Schema files

```
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/nis.schema
include /etc/openldap/schema/inetorgperson.schema
include /etc/openldap/schema/kerberos.schema    # ships with MIT Kerberos, in /usr/share/doc/krb5-server-ldap*/
```

`kerberos.schema` defines:

| ObjectClass / Attribute | OID | Purpose |
|---|---|---|
| `krbPrincipal` (AUXILIARY) | 1.3.6.1.4.1.5322.10.2.1 | Mixin for `krbPrincipalName`, `krbPrincipalKey`, etc. on inetOrgPerson or account |
| `krbPrincipalName` | 1.3.6.1.4.1.5322.10.1.1 | `user@REALM` syntax; case-sensitive |
| `krbPrincipalKey` | 1.3.6.1.4.1.5322.10.1.2 | BER-encoded `TangentKey` set (one per enctype + kvno) |
| `krbPrincipalEncryptionKvno` | 1.3.6.1.4.1.5322.10.1.3 | kvno integer |
| `krbPrincipalRealm` | 1.3.6.1.4.1.5322.10.1.4 | DN of `krbRealmContainer` |
| `krbPwdPolicyReference` | 1.3.6.1.4.1.5322.10.1.5 | DN of password policy object |
| `krbMaxTicketLife` / `krbMaxRenewableAge` | …:1.6 / …:1.7 | Per-principal ticket lifetime |
| `krbPrincipalFlags` | …:1.9 | Bitmask of `KRB5_KDB_DISALLOW_TGT_BASED`, `REQUIRES_PRE_AUTH`, etc. |

The schema is loaded once at startup; subsequent adds via `cn=config` use the `cn=schema,cn=config` subtree.

### Sample `slapd.conf` (legacy) or equivalent `cn=config`

```
# /etc/openldap/slapd.conf (legacy syntax; same options are in olcDatabase entries under cn=config)
pidfile         /var/run/openldap/slapd.pid
argsfile        /var/run/openldap/slapd.args

include         /etc/openldap/schema/core.schema
include         /etc/openldap/schema/cosine.schema
include         /etc/openldap/schema/nis.schema
include         /etc/openldap/schema/inetorgperson.schema
include         /etc/openldap/schema/kerberos.schema

TLSCACertificateFile    /etc/pki/tls/certs/ca-bundle.crt
TLSCertificateFile      /etc/pki/tls/certs/slapd.crt
TLSCertificateKeyFile   /etc/pki/tls/private/slapd.key
TLSVerifyClient         never

# SASL mapping: map Kerberos principal user@REALM to LDAP DN
authz-policy    to
sasl-secprops   noanonymous,noplain,minssf=56
saslRegexp      uid=([^,]*),cn=GSSAPI,cn=auth
                uid=$1,ou=people,dc=example,dc=com
saslRegexp      uid=([^,]*),cn=example.com,cn=GSSAPI,cn=auth
                uid=$1,ou=people,dc=example,dc=com

# Access: Kerberos keys readable only by the KDC service account
access to attrs=krbPrincipalKey
        by dn.exact="uid=kdc-service,dc=example,dc=com" read
        by dn.exact="uid=kadmin-service,dc=example,dc=com" write
        by * none

# Standard POSIX attrs readable by authenticated users
access to attrs=userPassword,shadowLastChange
        by self write
        by anonymous auth
        by * none

access to *
        by * read

database        mdb
maxsize         1073741824
suffix          "dc=example,dc=com"
rootdn          "cn=Manager,dc=example,dc=com"
rootpw          {SSHA}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
directory       /var/lib/ldap

index   objectClass,uid,uidNumber,gidNumber,memberUid    eq
index   cn,mail,surname,givenname                         eq,sub
index   krbPrincipalName,krbPrincipalRealm                eq
```

## MIT Kerberos with LDAP KDB backend

### `/etc/krb5.conf`

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true
    forwardable = true
    proxiable = true
    renewable = true
    ticket_lifetime = 10h
    renew_lifetime = 7d
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    EXAMPLE.COM = {
        kdc = kdc01.example.com:88
        kdc = kdc02.example.com:88
        admin_server = kdc01.example.com:749
        default_domain = example.com
        kpasswd_server = kdc01.example.com:464
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM

[dbmodules]
    DB = {
        db_library = kldap
        ldap_kerberos_container_dn = cn=kerberos,dc=example,dc=com
        ldap_kdc_dn = uid=kdc-service,dc=example,dc=com
        ldap_kadmind_dn = uid=kadmin-service,dc=example,dc=com
        ldap_servers = ldaps://ldap01.example.com ldaps://ldap02.example.com
        ldap_conns_per_server = 5
    }

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log
    default = SYSLOG:NOTICE:DAEMON
```

The KDC service account `uid=kdc-service,dc=example,dc=com` (with password in `/etc/krb5.keytab` as `kdc/example.com@EXAMPLE.COM` principal) is the only principal that can read `krbPrincipalKey`. The `kadmin-service` DN can write (rotate) keys.

### `/var/kerberos/krb5kdc/kdc.conf`

```ini
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
    kadmind_port = 749
    kpasswd_port = 464

[realms]
    EXAMPLE.COM = {
        master_key_type = aes256-cts-hmac-sha1-96
        acl_file = /var/kerberos/krb5kdc/kadm5.acl
        dict_file = /usr/share/dict/words
        admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab
        database_module = DB                  # references [dbmodules] DB in krb5.conf
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        default_principal_flags = +preauth
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
    }

[logging]
    kdc = FILE:/var/log/krb5kdc.log
```

### `/var/kerberos/krb5kdc/kadm5.acl`

```
*/admin@EXAMPLE.COM    *                        # full admin
kadmin/admin@EXAMPLE.COM *                      # kadmin service principal
*/admin@EXAMPLE.COM    il                        # inquire + list (for helpdesk)
```

### Bootstrap the LDAP KDB

```bash
# 1. Create the kerberos container in LDAP
ldapadd -x -D cn=Manager,dc=example,dc=com -W <<'LDIF'
dn: cn=kerberos,dc=example,dc=com
objectClass: krbContainer
cn: kerberos
LDIF

# 2. Create the KDC and kadmin service accounts
ldapadd -x -D cn=Manager,dc=example,dc=com -W <<'LDIF'
dn: uid=kdc-service,dc=example,dc=com
objectClass: account
objectClass: simpleSecurityObject
uid: kdc-service
userPassword: {SSHA}...

dn: uid=kadmin-service,dc=example,dc=com
objectClass: account
objectClass: simpleSecurityObject
uid: kadmin-service
userPassword: {SSHA}...
LDIF

# 3. Initialize the realm (writes the master key into LDAP)
kdb5_ldap_util -D cn=Manager,dc=example,dc=com create \
  -subtrees ou=people,dc=example,dc=com -r EXAMPLE.COM -s -H ldaps://ldap01.example.com
# (-s creates the stash file /var/kerberos/krb5kdc/.k5.EXAMPLE.COM with the master key)

# 4. Stash the KDC service account password into a keytab
kdb5_ldap_util stashsrvpw -f /etc/krb5.keytab.kdc uid=kdc-service,dc=example,dc=com
kdb5_ldap_util stashsrvpw -f /etc/krb5.keytab.kadmin uid=kadmin-service,dc=example,dc=com

# 5. Start the services
systemctl enable --now krb5kdc
systemctl enable --now kadmin
```

### `/etc/nslcd.conf`

```
uid nslcd
gid ldap

uri ldap://ldap01.example.com ldap://ldap02.example.com
base dc=example,dc=com

binddn uid=nslcd-reader,dc=example,dc=com
bindpw __password__

bindpw_strftime_modify off

ssl start_tls
tls_reqcert demand
tls_cacertfile /etc/pki/tls/certs/ca-bundle.crt

# NSS filter mapping
filter passwd  (objectClass=posixAccount)
filter group   (objectClass=posixGroup)
filter shadow  (objectClass=shadowAccount)

map    passwd  uid              uid
map    passwd  uidNumber        uidNumber
map    passwd  gidNumber        gidNumber
map    passwd  gecos            gecos
map    passwd  homeDirectory    homeDirectory
map    passwd  loginShell       loginShell

map    group   gidNumber        gidNumber
map    group   memberUid        memberUid

map    shadow  shadowLastChange shadowLastChange

# Timeouts
bind_timelimit 5
timelimit 5
idle_timelimit 60

# Cache
cache no
```

### PAM stack (`/etc/pam.d/system-auth`, RHEL-style)

```
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        sufficient    pam_krb5.so try_first_pass
auth        sufficient    pam_ldap.so use_first_pass
auth        required      pam_deny.so

account     required      pam_unix.so broken_shadow
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     [default=bad success=ok user_unknown=ignore] pam_ldap.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass retry=3
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient    pam_krb5.so use_authtok
password    sufficient    pam_ldap.so use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     optional      pam_mkhomedir.so umask=0022 skel=/etc/skel
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
```

### BIND DNS

`/etc/named.conf` ( BIND — https://gitlab.isc.org/isc-projects/bind9 ):

```namedconf
options {
    directory "/var/named";
    dnssec-validation auto;
    auth-nxdomain no;
    listen-on-v6 { any; };
    allow-query { any; };
    allow-update { key "dhcp-update-key"; };
};

key "dhcp-update-key" {
    algorithm hmac-sha256;
    secret "<base64>";
};

zone "example.com" IN {
    type master;
    file "dynamic/example.com.zone";
    allow-update { key "dhcp-update-key"; localnets; };
};

zone "1.0.10.in-addr.arpa" IN {
    type master;
    file "dynamic/1.0.10.in-addr.arpa.zone";
    allow-update { key "dhcp-update-key"; localnets; };
};
```

BIND can also do GSS-TSIG dynamic updates (RFC 3645, same as AD-integrated DNS — see `../02-protocols/05-dns-dynamic-updates.md`) if compiled with `--with-gssapi` and configured with `tkey-gssapi-keytab /etc/named.keytab;`. Most roll-your-own setups use plain TSIG only.

## Commands / examples

```bash
# Create a new principal (writes to LDAP via kldap)
kadmin.local -q "addprinc -randkey host/host01.example.com@EXAMPLE.COM"
kadmin.local -q "addprinc user1"
# Equivalent non-local (uses kadmin protocol over tcp/749):
kadmin -p admin/admin@EXAMPLE.COM -q "addprinc user1"

# List principals
kadmin.local -q "listprincs"

# Generate a keytab for a service
kadmin.local -q "ktadd -k /etc/krb5.keytab host/host01.example.com@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab nfs/host01.example.com@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab HTTP/host01.example.com@EXAMPLE.COM"

# Add POSIX attributes to an LDAP user
ldapadd -x -D cn=Manager,dc=example,dc=com -W <<'LDIF'
dn: uid=user1,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: krbPrincipalAux
uid: user1
cn: User One
sn: One
givenName: User
uidNumber: 10042
gidNumber: 10042
homeDirectory: /home/user1
loginShell: /bin/bash
gecos: User One
krbPrincipalName: user1@EXAMPLE.COM
userPassword: {SSHA}...
LDIF

# Reset a user's Kerberos password
kadmin.local -q "cpw user1"

# Test the stack
getent passwd user1
kinit user1
kvno host/host01.example.com

# Update DNS via nsupdate
nsupdate -y dhcp-update-key:base64-secret <<'EOF'
update add host01.example.com. 3600 A 10.0.0.10
update add 10.0.0.10.in-addr.arpa. 3600 PTR host01.example.com.
send
EOF

# Or with GSS-TSIG (if BIND compiled with GSSAPI):
nsupdate -g <<'EOF'
update add host01.example.com. 3600 A 10.0.0.10
send
EOF
```

## Wireshark / tshark

```
# Kerberos AS-EXCHANGE / TGS-EXCHANGE
kerberos && (kerberos.msg_type == 10 || kerberos.msg_type == 11 || kerberos.msg_type == 12 || kerberos.msg_type == 13)

# LDAP bind from krb5kdc to slapd (kldap plugin)
ldap.messageCode == 0 && (ldap.authentication.mechanism == "simple" || ldap.authentication.mechanism == "GSS-SPNEGO")

# LDAP search for principal lookup
ldap.messageCode == 3 && (ldap.filter contains "krbPrincipalName" || ldap.filter contains "krbPrincipalRealm")

# LDAP modify from kadmind (cpw)
ldap.messageCode == 6 && ldap.attribute.name == "krbPrincipalKey"

# nslcd's lookups
ldap.messageCode == 3 && (ldap.filter contains "posixAccount" || ldap.filter contains "posixGroup")

# DNS dynamic update from nsupdate -y
dns.flags.response == 0 && dns.count.updates > 0

# GSS-TSIG signed DNS dynamic update
dns && dns.tsig.algorithm_name == "gss-tsig."
```

## Limitations vs AD / FreeIPA

| Capability | OpenLDAP + MIT Kerberos | AD DS | FreeIPA |
|---|---|---|---|
| Multi-master replication | MirrorMode (2 nodes) or N-Way Multi-Master (limited) | Yes (KCC + USN) | Yes (389-DS Multi-Master Replication) |
| Group Policy | None | Yes | HBAC + sudo rules + cert policy (no GP-equivalent for arbitrary machine config) |
| Authentication protocols | Kerberos only (no NTLM fallback unless Samba is added) | Kerberos + NTLM | Kerberos only |
| DNS | BIND with separate config | AD-integrated DNS (MS-DRSR DNSServer RPC) | BIND + `bind-dyndb-ldap` (LDAP-backed zones) |
| PKI integration | Manual cert distribution; certmonger optional | AD CS (MS-WCCE / MS-WSTEP) — see `../01-ad-core/02-ad-cs-cert-services.md` | Dogtag CA integrated |
| Computer accounts | Manual (host principal + keytab) | Automatic | `ipa-client-install` automatic |
| Schema extensibility | Yes (LDIF) but no formal schema FSMO | Yes (`schemaUpdateNow` trigger; FSMO-protected — see `../03-directory-schema/01-schema-attributes.md`) | Yes (via `ipa` commands) |
| Site awareness | None | Yes (sites + subnets + replication topology) | Limited (location-aware DNS SRV) |
| Forest / trusts | Cross-realm trusts only (no forest transitive) | Yes (forest + external trusts — `../03-directory-schema/04-trusts-topology.md`) | Cross-forest trusts to AD |
| Group nesting | `memberOf` plugin (not standard) | `memberOf` linked-attribute constructed | `memberOf` plugin |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `kinit` returns `Client not found in Kerberos database (6)` | Principal not in LDAP, or KDC can't bind to LDAP | `ldapsearch -x -D uid=kdc-service,… -W uid=user1 krbPrincipalName`; check `/var/log/krb5kdc.log` for `kldap` errors |
| `kadmind` returns `Operation requires "get" privilege` | ACL not configured for admin principal | Edit `/var/kerberos/krb5kdc/kadm5.acl`, `systemctl restart kadmin` |
| `nslcd` returns `no such object` for known user | Filter mismatch (e.g. `posixAccount` not on the user object); or wrong base | `ldapsearch -x -D uid=nslcd-reader,… -W -b dc=example,dc=com uid=user1`; check `/etc/nslcd.conf` filter |
| `pam_krb5.so` fails with `Preauthentication failed` | Clock skew > 5 min against KDC | `chronyc sources`; `timedatectl set-ntp true` — see `../02-protocols/07-ntp-time-sync.md` |
| `krb5kdc` won't start with `Database mode! (Operation not permitted)` | Master key stash file missing or wrong perms | `kdb5_ldap_util -D cn=Manager,… stashsrvpw -f /etc/krb5.keytab.kdc uid=kdc-service,…`; verify `chmod 600 /var/kerberos/krb5kdc/.k5.EXAMPLE.COM` |
| `pam_ldap.so: Unable to contact LDAP server` after TLS hardening | CA cert not in `/etc/pki/tls/certs/ca-bundle.crt` | `trust anchor /path/to/ca.crt` (RHEL) / `update-ca-certificates` (Debian) |
| BIND dynamic updates fail with `update failed: REFUSED` | `allow-update` ACL doesn't include the source IP; or TSIG key mismatch | Add IP/key to `allow-update`; verify `key "dhcp-update-key" { algorithm hmac-sha256; secret …; };` matches on both ends |
| `kadmin.local -q "listprincs"` returns fewer principals than LDAP search | Some user objects lack `krbPrincipalAux` | `ldapmodify` to add `objectClass: krbPrincipalAux` and `krbPrincipalName` |

Logs:
- `slapd`: `/var/log/slapd.log` (debug via `olcLogLevel` in `cn=config`)
- `krb5kdc`: `/var/log/krb5kdc.log`
- `kadmind`: `/var/log/kadmind.log`
- `nslcd`: `/var/log/nslcd.log` (or syslog `daemon` facility)
- `named`: `/var/log/messages` or `/var/named/data/named.run`

## Cross-platform comparison

- **AD-side counterpart:** OpenLDAP plays the role of AD LDS (LDAP directory without domain controller functions) — see `../01-ad-core/04-ad-lds-adam.md`. MIT Kerberos plays the role of the AD KDC (`lsass.exe` kdcsvc.dll) — see `../02-protocols/01-kerberos-internals.md` for the MS-KILE profile and the wire format. The `kerberos.schema` and `krbPrincipalKey` attribute are the LDAP-DIT analog of how AD stores principal keys in `samAccountName` + `unicodePwd` + `msDS-KeyVersionNumber`. Cross-realm trusts to AD are possible (`ksetup /addkdc` on Windows side; `capaths` in `krb5.conf` on Linux side) but lack the `FOREST_TRANSITIVE` semantics that make AD-AD and FreeIPA-AD trusts work seamlessly.
- **FreeIPA alternative:** FreeIPA bundles the exact same components (`389-DS` = OpenLDAP-derived, MIT Kerberos, BIND, Dogtag PKI) into a managed product with web UI, CLI, and a full schema for hosts/HBAC/sudo — see `./08-freeipa-trust.md`. Migrating OpenLDAP+MIT Kerberos → FreeIPA is a documented path via `ipa-replica-prepare` from a snapshot of the LDAP DIT.
- **SSSD alternative:** SSSD can run against OpenLDAP as `id_provider = ldap` and `auth_provider = krb5` (without an AD domain) — same effect but with SSSD's superior caching and PAM integration. Recommended over `nslcd` for new deployments.
- **macOS counterpart:** Apple's OpenDirectory is a similar concept (LDAP + Kerberos + custom plugin model) bundled into macOS Server — see `../08-macos-equivalents/01-opendirectory-internals.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- OpenLDAP source — https://github.com/openldap/openldap (see `servers/slapd/`, `servers/slapd/back-mdb/`, `servers/slapd/overlays/memberof.c`).
- MIT Kerberos source — https://github.com/krb5/krb5 (see `src/plugins/kdb/ldap/`, `src/kdc/`, `src/kadmin/`).
- `nslcd` source — https://github.com/arthurdejong/nss-pam-ldapd (formerly `nss-ldapd`).
- BIND source — https://gitlab.isc.org/isc-projects/bind9.
- RFC 4510-4519 — LDAPv3 technical specification (RFC 4511 wire protocol in `../02-protocols/02-ldap-protocol.md`).
- RFC 4120 — Kerberos network authentication service; RFC 6806 (FAST), RFC 4556 (PKINIT).
- `slapd.conf(5)`, `slapd-config(5)`, `krb5.conf(5)`, `kdc.conf(5)`, `kadm5.acl(5)`, `kdb5_ldap_util(8)`, `nslcd.conf(5)`, `pam_krb5(5)`, `pam_ldap(8)`.
- "MIT Kerberos with LDAP Backend" — official MIT Kerberos documentation.
