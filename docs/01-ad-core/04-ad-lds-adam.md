---
title: AD LDS / ADAM — Lightweight Directory Services Internals
audience: senior-engineers
tags: [ad-lds, adam, instance-exe, adamntds-dit, ldap, application-partition]
related:
  - ./01-ad-ds-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/01-kerberos-internals.md
last_updated: 2026-08-13
---

AD LDS (Active Directory Lightweight Directory Services, formerly ADAM — Active Directory Application Mode) is a standalone LDAPv3 server shipped as a per-instance executable (`%SystemRoot%\ADAM\<instance>\instance.exe` plus `adamdsa.dll`) backed by its own Jet Blue database (`adamntds.dit`) without a KDC, without Netlogon, without a Global Catalog, without the `computer`/`user` AD-schema prerequisites, and without DC-DC replication — the only sync path is import/export via `ldifde` or, on Server 2019+, AD LDS-to-AD LDS replication via a configurable `nTDSDSA` instance peer-link.

## Architecture

### Instance model

Unlike AD DS (one DSA per DC, mandatory per-machine), AD LDS supports multiple instances on one host. Each instance is fully isolated: separate schema, separate config, separate ports, separate service.

```
services.msc per instance: "ADAM [<instance>]" → e.g. "ADAM [SharePoint-UPS]"
 ├── process: %SystemRoot%\ADAM\ADAMInstance.exe
 │    │           (renamed copy of adamdsa.dll's host binary; runs as a child of
 │    │            a single shared svchost.exe -k netsvcs)
 │    ├── adamdsa.dll   (DSA implementation; mirrors ntdsa.dll APIs but reduced)
 │    ├── adamntds.dll  (schema cache, name resolution)
 │    ├── ldapsvc.dll   (LDAP server front-end; same source as AD DS dsamain.dll)
 │    ├── esent.dll     (Jet Blue — same engine as AD DS, different DB file)
 │    └── msvcrt.dll / Windows system DLLs
 │
 ├── Service account: NT AUTHORITY\NETWORK SERVICE (default) or DOMAIN\service-account
 ├── Files at: %SystemRoot%\ADAM\<instance>\
 │      adamntds.dit       (the database, page size 32 KB)
 │      edb.log            (transaction log)
 │      edb.chk            (checkpoint)
 │      edbres00001.jrs    (reserved logs)
 │      instance-name.ldif (initial import file used by setup)
 │      ms-adamschemacat.txt  (schema additions for this instance, only at setup time)
 │      *.ldf              (auto-generated schema delta logs from setup)
 └── Registry under: HKLM\SYSTEM\CurrentControlSet\Services\ADAM_<Instance>\
        ├── ImagePath        = "%SystemRoot%\ADAM\ADAMInstance.exe /svc <Instance>"
        ├── ObjectName       = "NT AUTHORITY\NetworkService"
        ├── Description      = "ADAM_<Instance>"
        └── Parameters\
              ├── DSA Database File           = %SystemRoot%\ADAM\<Instance>\adamntds.dit
              ├── Database log files path     = %SystemRoot%\ADAM\<Instance>
              ├── LDAPPort                    = 389 or 50000 (configurable; default first free)
              ├── SSLPort                     = 636 or 50001 (or 0 = disabled)
              ├── LDAPPolicies\
              │     ├── MaxPoolConnections   = 50
              │     ├── MaxDatagramRecv      = 1024
              │     └── MaxConnIdleTime      = 900  (sec)
              ├── ServiceDll                  = %SystemRoot%\ADAM\ADAMdsa.dll
              └── SchemaDN                    = CN=Schema,CN=Configuration,...
```

### Schema differences vs AD DS

AD LDS ships with the same AD schema (so `user`, `group`, `organizationalUnit`, `nTSecurityDescriptor` all exist), but with these constraints:

- `user` class does **not** require `sAMAccountName` — uses only `cn` + `userPrincipalName` if you want a UPN-style login.
- `computer` class is **not** registered (no domain join), and `dNSHostName` is not enforced.
- The `domainDNS` class is present (used as the application partition head) but lacks `fSMORoleOwner` semantics — there is no PDC, RID master, etc.
- No `msDS-NCReplCursors`, no `msDS-IsDomainFor`, no `nTDSDSA` cross-DC references (unless multi-instance replication is configured; even then it's instance-to-instance, not domain-controller-to-domain-controller).
- `pKIExtendedKeyUsage`, `displayName`, `servicePrincipalName` all work normally; LDAP bind with `userPrincipalName` is supported.
- No Netlogon, so no Machine Account Channel, no SC-based NTLM fallback to DC.
- No Kerberos KDC, so auth is delegated to the underlying OS via `SASL/GSS-SPNEGO` (i.e., the client gets a TGT from the AD DS DC for `ldap/<ldds-host>` and binds with that).

### AD LDS to AD LDS replication

Single-master replication: one instance is the "master", others replicate. Configured via `dsmgmt.exe` or PowerShell:

```powershell
# On the master: enable replication
ntdsutil "schema maintenance" "configure replication" "yes" quit quit
# On a replica: add a repsFrom pointing at the master
repadmin /add <instance-name> <master-hostname> <NC-dn>
```

Replication uses DRSUAPI just like AD DS but over the AD LDS-specific port (e.g., 50000). The interface UUID is the same (`e3514235-8b63-11d0-a26c-00a0c92b955c`); the `dwRepsEpoch` differs. This is mostly used for read-scale-out scenarios (e.g., a portal front-end that needs many directory reads but no writes).

### AD LDS setup (`adamsetup.exe`)

`%SystemRoot%\ADAM\adamsetup.exe` is invoked by `Install-ADLDSInstance` (the `ADDSAdministration` PowerShell module) or by the wizard `%SystemRoot%\System32\ldifde.exe` driven `Adaminstall.exe`. The flow:

1. Allocate instance ID (next free `ADAM_<Instance>` service name).
2. Create the service directory `%SystemRoot%\ADAM\<Instance>`.
3. Initialize a new Jet Blue DB (`adamntds.dit`) by calling `JetCreateDatabase`.
4. Apply schema LDIF — `%SystemRoot%\ADAM\Microsoft-ADAM-Updates-*` (cumulative update LDIFs). The full schema is the AD DS schema delta from Windows Server 2003 + every subsequent version. Optional: include `MS-ADAM-adschema-50.LDF` (full base) or `MS-AD-LDS-DisplaySpecifiers.LDF`.
5. Apply `ms-adamschemacat.txt` (instance-specific extensions, if any).
6. Import user-supplied LDIF (`<Instance>.ldif`) — typically the application's base entries (OUs, initial service accounts).
7. Register service + start.
8. Reserve ports via `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ReservedPorts` (or rely on dynamic allocation).

### Use cases

| Use case | Driver |
|---|---|
| SharePoint User Profile Service | SharePoint requires an LDAP directory for profile sync; AD DS works but admins prefer isolating non-AD attributes (skills, prior roles) in LDS. |
| SCOM (System Center Operations Manager) | SCOM's AD Integration Account publishes mgmt pack metadata to LDS. |
| ADRMS Connector | RMS connector stores licensing-side cluster config in LDS. |
| HPC Pack | Head node stores job queue in LDS. |
| Custom app needing LDAP, but not AD security model | Apps want LDAP semantics, schema extension, and self-managed users; LDS allows this without schema change in the forest root. |
| DMZ-exposed directory | LDS in a perimeter host with one-way trust; isolated from the corporate DC. |
| AD DS development / staging | Restore a copy of AD DS into LDS via `ldifde` (drop AD-specific attributes). |

## Configuration / code examples

### Wireshark filter — capture LDS bind

```
tcp.port == 50000 && ldap && (ldap.messageType == 0 || ldap.messageType == 1)  # BindRequest / BindResponse
# SASL GSS-SPNEGO over LDAP to LDS
ldap && ldap.bindMechanism == "GSS-SPNEGO"
```

### PowerShell — install an AD LDS instance

```powershell
Import-Module ActiveDirectory
$params = @{
    Name              = "SharePoint-UPS"
    LdapPort          = 50000
    SslPort           = 50001
    LogPath           = "C:\ADAM-Logs\SharePoint-UPS"
    DataPath          = "C:\ADAM-Data\SharePoint-UPS"
    ServiceAccount    = "EXAMPLE\LdsService"
    ServicePassword   = (Read-Host -AsSecureString)
    Administrator     = "EXAMPLE\ad-admin"
    DatabaseName      = "adamntds.dit"
    SourceDatabase    = ""    # blank = new
}
Install-ADLDSInstance @params -NoRebootOnCompletion
```

### Python — bind via ldap3 to an AD LDS instance

```python
from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS

# Option 1: Simple bind with DN + password (no AD integration)
server = Server('ldaps.example.com', port=50001, use_ssl=True,
                get_info=ALL)
conn = Connection(server,
                  user='CN=admin,DC=app,DC=example,DC=com',
                  password='P@ss', auto_bind=True)
print(conn.extend.standard.who_am_i())

# Option 2: SASL GSS-SPNEGO (uses host's Kerberos TGT, AD-backed)
server = Server('ldap.example.com', port=50000, get_info=ALL)
conn = Connection(server, auto_bind=True,
                  authentication=SASL, sasl_mechanism='GSS-SPNEGO')
print(conn.extend.standard.who_am_i())

# Create a new OU and a user
conn.add('OU=Apps,DC=app,DC=example,DC=com', 'organizationalUnit')
conn.add('CN=svc1,OU=Apps,DC=app,DC=example,DC=com',
         ['top', 'person', 'organizationalPerson', 'user'],
         {'userPrincipalName': 'svc1@app.example.com',
          'displayName': 'svc1 service account',
          'userPassword': 'P@ssw0rd!'})
```

### ldifde import / export

```cmd
:: Export the schema of an instance
ldifde -f schema.ldf -s localhost:50000 -b EXAMPLE\admin password ^
       -d "CN=Schema,CN=Configuration,DC=app,DC=example,DC=com" ^
       -p subtree -r "(objectClass=attributeSchema)" -l cn,attributeID,attributeSyntax

:: Import into a fresh instance
ldifde -i -f schema.ldf -s localhost:50000 -b EXAMPLE\admin password -j C:\logs
```

### Registry — adjust LDAP server policies

```
HKLM\SYSTEM\CurrentControlSet\Services\ADAM_<Instance>\Parameters\LDAPPolicies
 ├── MaxPoolConnections       = 100   (REG_DWORD, default 50)
 ├── MaxReceiveBuffer         = 10485760   (10 MB, default 1 MB)
 ├── MaxConnIdleTime          = 1800  (sec)
 ├── MaxActiveQueries         = 100
 ├── MaxQueryDuration         = 120   (sec; long queries raise event 1644)
 ├── MaxPageSize              = 1000  (default — same as AD DS)
 └── MaxValRange              = 1500
```

Restart the service for changes to take effect.

## Troubleshooting

- **Event 1644 (LDAP query slow)** — look at `MaxQueryDuration` and the index state of the attributes in the filter. Same `searchFlags` bit-1 semantics as AD DS. Use `ldifde -d ... -l searchFlags` to inspect.
- **SASL GSS-SPNEGO bind fails with "Invalid credentials"** — usually missing SPN `ldap/<host>` on the service account. Run `setspn -S ldap/lds01.example.com EXAMPLE\LdsService`.
- **SSL bind fails with `TLS` alerts** — install the SSL cert in `LocalMachine\My`, ensure private key is exportable to the service account, set `HKLM\...\ADAM_<Instance>\Parameters\Certificate` to the SHA-1 thumbprint, and verify subject name matches the host name clients use. `certutil -store my <thumbprint>` confirms.
- **Instance stuck at "Starting"** — Jet Blue recovery. Inspect `%SystemRoot%\ADAM\<Instance>\edb.log` for `-1018`/`-1022` errors. Last-resort: `esentutl /r edb /l<logdir> /d` (soft recovery) or `/d` for hard recovery.
- **Schema modification denied** — by default, only members of `BUILTIN\Administrators` can modify the schema of an LDS instance. To enable a non-admin: grant the user `Write` on `CN=Schema,CN=Configuration,...` and add them to the `Schema Admins` group inside the instance (`CN=Schema Admins,CN=Configuration,...`).
- **Cross-instance replication fails with "Target DSA does not exist"** — the replica instance's `nTDSDSA` object has not been added to the master's `CN=Sites,CN=Configuration,...` topology. Configure via `dsmgmt` "configure replication partners".

## Cross-platform equivalents

- **Linux**: OpenLDAP (`slapd`) — the closest analog. Per-instance, schema-extension-friendly, no replication by default but `syncrepl` (RFC 4533) provides multimaster-style sync. 389-DS (`dirsrv`) is more AD-like (extensible schema via `98user.ldif`, fractional replication, native plugin API in C). See `../09-linux-equivalents/09-openldap-389ds.md` (when present).
- **Linux**: FreeIPA uses 389-DS as the backing store; this is closer to AD DS than AD LDS because it includes Kerberos + DNS + CA. For pure LDAP-as-app-store use 389-DS directly.
- **macOS**: Open Directory (`slapd`-derived, with Apple's password server). Functionally closer to AD LDS than AD DS (no KDC integration per instance). See `../08-macos-equivalents/06-open-directory.md` (when present).

## References

- MS-ADTS §3 (applies to AD LDS with caveats — the protocol spec defines AD-LDS as a profile of AD DS).
- "AD LDS Getting Started" — MS Learn. <https://learn.microsoft.com/windows-server/identity/ad-ds/ad-ds-getting-started>
- RFC 4511 — LDAPv3 protocol.
- RFC 4533 — LDAP Content Synchronization Operation (syncrepl, used by OpenLDAP).
- `install-adldsinstance` cmdlet reference, MS Learn.
