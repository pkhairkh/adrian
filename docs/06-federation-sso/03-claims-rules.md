---
title: ADFS Claims Rule Language — DSL Syntax, Rule Types, Attribute Stores, Issuance Engine Internals
audience: senior-engineers
tags: [ad-fs, claims-rules, claim-pipeline, attribute-stores, policy-engine, ldap-attribute-store, sql-attribute-store]
related:
  - ./01-adfs-architecture.md
  - ./02-saml-ws-fed.md
  - ./04-oidc-oauth.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

AD FS's claims pipeline is driven by a custom DSL expressed in `Microsoft.IdentityServer.ClaimsPolicy` where each rule uses the syntax `c:[Type == "...", Value == "...", ...] => issue(Type = "...", Value = c.Value);` and is evaluated in one of four phases (Acceptance Transform, Issuance Authorization, Issuance Transform, Delegation) by `Microsoft.IdentityServer.dll!PolicyEngine`, with rule bodies optionally executing LDAP, SQL, or custom .NET attribute store queries to enrich outgoing claims.

## Claim pipeline architecture

### Five phases (per ADFS R2 / 2016+)

```
Incoming identity (from Claims Provider Trust)
   │
   ▼
[1] Acceptance Transform Rules   (per-CPT)  →  filter / map claims from upstream IdP
   │
   ▼
[2] Issuance Authorization Rules (per-RPT)  →  Permit / Deny decision
   │
   ▼
[3] Issuance Transform Rules     (per-RPT)  →  map claims to RP's expected vocabulary
   │
   ▼
[4] Delegation Rules             (per-RPT)  →  ActAs / OnBehalfOf token issuance
   │
   ▼
[5] Token Serialization                     →  Sign + serialize (SAML / JWT)
```

Each phase has its own rule list attached to either a Claims Provider Trust (CPT) or a Relying Party Trust (RPT). The pipeline is evaluated left-to-right, top-to-bottom; rule outputs accumulate in the claim set passed to the next rule.

### Trust scoping

| Trust | Where configured | Rules applied |
|---|---|---|
| Claims Provider Trust | `Get-AdfsClaimsProviderTrust` | Acceptance Transform Rules only |
| Relying Party Trust | `Get-AdfsRelyingPartyTrust` | Issuance Authorization + Issuance Transform + Delegation Rules |

The Active Directory CPT (built-in, non-removable) always supplies claims of `windowsaccountname`, `upn`, `objectGUID`, `objectSid`, and `primarysid`. Additional LDAP attributes are fetched via the "Send LDAP Attributes as Claims" rule template — this template does an implicit attribute store lookup, not a claim mapping.

## Claims Rule Language (CRL)

### Lexical structure

```
<rule>           := [<description>] <condition> <action>;
<description>    := "@" "RuleName" "=" <string>
<condition>      := <variable> ":" "[" <condition_list> "]"
<condition_list> := <constraint> {"," <constraint>}
<constraint>     := <property> <op> <literal>
                   | "Exists" "[" <condition> "]"
<action>         := "issue" "(" <claim_pattern> ")"
                   | "special_issue" "(" <claim_pattern> "," "Issuer" "=" ... ")"
                   | "add" "(" <claim_pattern> ")"
                   | "c1" "[" ... "]" "&&" "c2" "[" ... "]" "=>" ...
<claim_pattern>  := <property_assignment> {"," <property_assignment>}
<property_assignment> := <property> "=" <expr>
<property>       := "Type" | "Value" | "Issuer" | "OriginalIssuer" | "ValueType" | "Properties[..]"
```

Property names on claims:

| Property | Type | Notes |
|---|---|---|
| `Type` | URI string | The claim type, e.g. `http://schemas.xmlsoap.org/claims/UPN` |
| `Value` | string | The claim value |
| `ValueType` | URI string | Default `http://www.w3.org/2001/XMLSchema#string`; numeric types use `integer` / `boolean` |
| `Issuer` | string | Who issued the claim (transitive: original issuer name propagated through transforms) |
| `OriginalIssuer` | string | The first trust that issued the claim |
| `Properties` | name/value map | Free-form metadata; rarely used directly |

### Condition operators

`==` (equal), `!=` (not equal), `~=` (regex match — Perl-style).

### Rule types (action verbs)

| Action | Effect |
|---|---|
| `issue(Type = ..., Value = ...)` | Adds a claim to the outgoing set (will be in the issued token) |
| `add(Type = ..., Value = ...)` | Adds a claim to the working set but NOT to the issued token (intermediate) |
| `special_issue(..., Issuer = "AD FS Authority")` | Issue with explicit issuer name |
| `permit` | Authorization: allow issuance |
| `deny` | Authorization: stop pipeline, deny the request |

### Common patterns

#### Pass-through

```
@RuleName = "Pass UPN"
c:[Type == "http://schemas.xmlsoap.org/claims/UPN"]
=> issue(claim = c);
```

#### Regex transform

```
@RuleName = "Strip domain from group"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/group", Value =~ "(?i)^CORP\\\\(.+)$"]
=> issue(Type = c.Type, Value = RegExReplace(c.Value, "(?i)^CORP\\\\", ""));
```

#### Conditional issuance based on group

```
@RuleName = "Issuance for Engineers only"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/group", Value == "Engineers"]
=> issue(Type = "http://schemas.corp.example.com/claims/accesslevel", Value = "high");
```

#### Combine two claims

```
@RuleName = "Issue combined claim if both UPN and Role present"
c1:[Type == "http://schemas.xmlsoap.org/claims/UPN"]
&& c2:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"]
=> issue(Type = "http://schemas.corp.example.com/claims/principal",
         Value = c1.Value + ":" + c2.Value);
```

#### Group-to-role mapping (chained)

```
@RuleName = "Engineers → admin"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/group", Value == "Engineers"]
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "admin");

@RuleName = "Finance → finance-user"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/group", Value == "Finance"]
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "finance-user");
```

#### Authorization — permit only specific group

```
@RuleName = "Permit Engineers"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/group", Value == "Engineers"]
=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "PermitUsersWithClaim");

@RuleName = "Deny everyone else"
=> issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "Deny");
```

`PermitUsersWithClaim` and `Deny` are special ADFS authorization claim values recognized by the authorization phase.

### Built-in claim types

| URI | Source |
|---|---|
| `http://schemas.xmlsoap.org/claims/UPN` | AD CPT default |
| `http://schemas.xmlsoap.org/claims/Role` | mapped from group |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | displayName |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | mail |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | givenName |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | sn |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid` | objectSid |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid` | tokenGroups |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` | tokenGroups (resolved to sAMAccountName) |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod` | set after auth |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant` | set after auth |
| `http://schemas.microsoft.com/identity/claims/identityprovider` | IdP identifier |
| `http://schemas.microsoft.com/claims/authnmethodsreferences` | MFA references |

## Rule templates

ADFS ships with built-in rule templates surfaced in the ADFS MMC and `Add-AdfsClaimRule` cmdlet. Templates expand into raw CRL.

| Template | Generates |
|---|---|
| Pass Through or Filter an Incoming Claim | `c:[Type == "<X>"] => issue(claim = c);` or with condition |
| Transform an Incoming Claim | `c:[Type == "<X>"] => issue(Type = "<Y>", Value = c.Value);` |
| Send LDAP Attributes as Claims | Implicit attribute store query; emits claims like `c:[Type == "http://...emailaddress", Value = "mail"]` from AD |
| Send Group Membership as a Claim | For specific group SID, issue a single claim |
| Send Claims Using a Custom Rule | Raw CRL passthrough |
| Permit or Deny Users Based on an Incoming Claim | Authorization rules |
| Permit All Users | Default authorization rule (`=> issue(Type = "...permit", Value = "PermitAllUsers");`) |

### "Send LDAP Attributes as Claims" internals

This template compiles to an `add`-style rule that uses the AD attribute store:

```
@RuleName = "Send LDAP attributes"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
=> add(store = "Active Directory",
      types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
               "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"),
      query = ";mail,givenName;{0}",
      param = c.Value);
```

The `store = "Active Directory"` invokes the built-in AD attribute store which performs an LDAP lookup against the user's object. `query` is `;<attr-list>;<filter-template>`; `{0}` is replaced by `param` (here the windowsaccountname).

## Attribute stores

| Store name | Implementation | Query format |
|---|---|---|
| `Active Directory` | Built-in (`Microsoft.IdentityServer.ClaimsPolicy.AttributeStore.ActiveDirectoryAttributeStore`) | `;attr1,attr2;{0}` (filter template uses `{0}`) |
| `LDAP` | `LdapAttributeStore` — any LDAP server (configured via `Add-AdfsLdapServerConnection`) | Same as AD; distinguished name in query |
| `SQL` | `SqlAttributeStore` — System.Data.SqlClient; needs connection string in ADFS config | Full SQL SELECT returning column-per-claim |
| `Custom` | .NET class implementing `Microsoft.IdentityServer.ClaimsPolicy.IAttributeStore` | Implementation-specific |

### LDAP attribute store rule

```
@RuleName = "Lookup from external LDAP"
c:[Type == "http://schemas.xmlsoap.org/claims/UPN"]
=> issue(store = "LDAP",
         types = ("http://schemas.corp.example.com/claims/dept",
                  "http://schemas.corp.example.com/claims/manager"),
         query = "ou=people,dc=corp,dc=example,dc=com;department,manager;uid={0}",
         param = RegExReplace(c.Value, "@.*$", ""));
```

### SQL attribute store rule

```
@RuleName = "Lookup user role from SQL"
c:[Type == "http://schemas.xmlsoap.org/claims/UPN"]
=> issue(store = "SQL",
         types = ("http://schemas.corp.example.com/claims/role",
                  "http://schemas.corp.example.com/claims/department"),
         query = "SELECT role_name, department FROM dbo.v_user_roles WHERE upn = {0}",
         param = c.Value);
```

SQL query parameterization: `{0}` becomes `@param0` via `SqlParameter`; SQL injection-safe.

### Custom attribute store

```csharp
using System.Collections.Generic;
using Microsoft.IdentityServer.ClaimsPolicy;
using Microsoft.IdentityServer.ClaimsPolicy.AttributeStore;

public class CustomStore : IAttributeStore
{
    public void Initialize(Dictionary<string, string> config) { ... }
    public bool ReturnsUnicodeStrings => true;

    public string[][] ExecuteQuery(string query, string[] parameters)
    {
        // query is the template from the rule; parameters is the param= array
        // Return: one row per record; each row is a string[] matching the types[] count
        return new[] { new[] { "engineer" } };
    }
}
```

Register in ADFS:
```powershell
Add-AdfsAttributeStore -Name 'CustomStore' -Type 'Corp.Identity.Adfs.CustomStore, Corp.Identity.Adfs'
```

## Rule engine internals

The policy engine lives in `Microsoft.IdentityServer.dll`:

```
Microsoft.IdentityServer.PolicyEngine.PolicyEngine  (entry point per request)
  ├── Microsoft.IdentityServer.PolicyEngine.PolicyEvaluationContext  (the claim set + state)
  ├── Microsoft.IdentityServer.PolicyEngine.RuleCompilers.RuleCompilerBase
  │     ├── compiles CRL text to Expression<Func<...>> via System.Linq.Expressions
  │     └── caches compiled rules per trust (invalidated on trust update)
  ├── Microsoft.IdentityServer.PolicyEngine.AttributeStoreExecutor
  │     └── dispatches store= queries to IAttributeStore implementations
  └── Microsoft.IdentityServer.PolicyEngine.AuthorizationPolicyEvaluator
        └── evaluates permit/deny rules; stops on first deny
```

Rule compilation is cached per (TrustId, RuleHash). The compiled rule is a delegate `Func<ClaimSet, IEnumerable<Claim>>` evaluated against the current claim set.

The pipeline is single-threaded per request; attribute store queries are synchronous (SQL, LDAP) so a slow SQL query will block the entire SSO flow for that user. Mitigations: cache results in the attribute store implementation; pre-fetch via acceptance rules.

## Configuration / code examples

### PowerShell: dump all rules on every RP

```powershell
Get-AdfsRelyingPartyTrust | ForEach-Object {
    [PSCustomObject]@{
        Name                       = $_.Name
        Identifier                 = $_.Identifier
        IssuanceTransformRules     = $_.IssuanceTransformRules
        IssuanceAuthorizationRules = $_.IssuanceAuthorizationRules
        AcceptanceTransformRules   = '(n/a on RPT)'
    }
} | Format-List
```

### PowerShell: add a complex custom rule

```powershell
$rule = @'
@RuleName = "Inject admin claim for Domain Admins"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
       Value =~ "-512$"]   # Domain Admins SID ends in -512
=> issue(Type = "http://schemas.corp.example.com/claims/admin",
         Value = "true",
         ValueType = "http://www.w3.org/2001/XMLSchema#boolean");

@RuleName = "Permit Domain Admins"
c:[Type == "http://schemas.corp.example.com/claims/admin", Value == "true"]
=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",
         Value = "PermitUsersWithClaim");

@RuleName = "Permit Engineers"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
       Value =~ "-1127$"]   # Engineers group SID
=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",
         Value = "PermitUsersWithClaim");

@RuleName = "Deny everyone else"
=> issue(Type = "http://schemas.microsoft.com/authorization/claims/deny",
         Value = "Deny");
'@

Set-AdfsRelyingPartyTrust -TargetName 'CorpApp' `
    -IssuanceTransformRules $rule `
    -IssuanceAuthorizationRules $rule
```

### PowerShell: register a SQL attribute store

```powershell
$sql = "Data Source=sql01.corp.example.com;Initial Catalog=AppRoles;Integrated Security=True;"
Add-AdfsAttributeStore -Name 'AppRoles-SQL' -Type 'Microsoft.IdentityServer.ClaimsPolicy.AttributeStore.SqlAttributeStore, Microsoft.IdentityServer'
Set-AdfsAttributeStore -Name 'AppRoles-SQL' -Configuration @{ ConnectionString = $sql }
```

### Python: parse a claims rule for static analysis

```python
import re

# Naive CRL parser — extracts rule descriptions, conditions, and actions
rule_text = """
@RuleName = "Permit Engineers"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/group", Value == "Engineers"]
=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "PermitUsersWithClaim");
"""

# Pattern: optional @RuleName, then condition c:[ ... ], then action => ... ;
pat = re.compile(
    r'(?:@RuleName\s*=\s*"(?P<name>[^"]+)"\s+)?'      # optional rule name
    r'(?P<cond>\w+)\s*:\s*\[(?P<cond_body>[^\]]*)\]\s*' # condition: c:[...]
    r'=>\s*(?P<action>\w+)\s*\((?P<action_body>[^;]*)\);',
    re.MULTILINE
)

for m in pat.finditer(rule_text):
    print(f"Rule: {m.group('name') or '(unnamed)'}")
    print(f"  Condition variable: {m.group('cond')}")
    print(f"  Condition body: {m.group('cond_body').strip()}")
    print(f"  Action: {m.group('action')}({m.group('action_body').strip()})")
    print()

# Extract claim types from each rule
for m in re.finditer(r'Type\s*==\s*"([^"]+)"', rule_text):
    print(f"References claim type: {m.group(1)}")
```

## Troubleshooting

### Wireshark / network diagnostics

```
# Claim-rule-triggered LDAP query to DC
ldap.opcode == 0x03 and ldap.filter contains "(sAMAccountName="

# Claim-rule-triggered SQL query
tds.query contains "SELECT" or tds.packet_type == 0x01

# ADFS request/response (passive)
http.request.uri contains "/adfs/ls/" and http.request.uri contains "wa=wsignin1.0"

# Resulting assertion in the POSTed form data
http.file_data contains "AttributeStatement"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| Claim not present in issued token | Rule used `add` instead of `issue`; or rule condition didn't match any incoming claim | Change `add` to `issue`; verify incoming claim set via `Set-AdfsProperties -LogLevel verbose` and trace event |
| `MSIS9102 — The attribute store query returned an unexpected number of columns` | SQL/LDAP query returns more columns than `types=` array | Align column count: SQL `SELECT` returns N columns → `types=("t1","t2",..."tN")` |
| `MSIS9104 — Attribute store query failed` | SQL Server unreachable; or LDAP bind failed | Verify connection string; check ADFS service account has SQL connect permission |
| `MSIS7017 — Issuance authorization rule denied` | Last rule fired was a `deny` | Reorder rules or add `PermitUsersWithClaim` for expected group |
| Rule loops / slow performance | Rule issues a claim whose `Type` matches its own condition, causing re-entry | Use `add` for intermediate claims; the engine evaluates each rule once per pass |
| `Exist` keyword ignored | Use `Exists[c:[...]]` in condition to assert existence without binding the claim | Wrap the inner condition in `Exists[...]` |
| `RegExReplace` not recognized | Function name typo or quoting issue | Use exact name `RegExReplace(c.Value, "pattern", "replacement")`; escape backslashes |
| Issuer string unexpected | Use `special_issue(..., Issuer = "AD AUTHORITY")` to override | Default `Issuer` is `"AD AUTHORITY"` for AD-sourced claims, the CPT name for federated |

### Diagnostic commands

```
# List all rules on an RP
(Get-AdfsRelyingPartyTrust -Name 'CorpApp').IssuanceTransformRules

# Enable verbose tracing (causes high log volume)
Set-AdfsProperties -LogLevel {Errors, Warnings, Information, Verbose}

# Watch claims-pipeline events
wevtutil qe "AD FS/Tracing" /c:50 /rd:true /f:text

# Test a rule against a synthetic claim set (no built-in cmdlet; use the ADFS testing
# endpoint or a third-party tool like ADFS-Claims-Tester)
```

### Diagnostic event logs

```
AD FS/Admin
AD FS/Tracing   — see event 100+ for per-rule evaluation trace
```

## Cross-platform equivalents

| AD FS feature | macOS | Linux |
|---|---|---|
| Claims pipeline / rule engine | (no native equivalent; MDM-driven attribute injection in SSO extensions) — see `../08-macos-equivalents/04-platform-sso-extension.md` | Keycloak mappers (Hardcoded, User Attribute, Role, Script, Claim to Role); mod_auth_mellon attribute maps |
| Acceptance / Issuance Transform Rules | (n/a — macOS is an SP, not an IdP) | Keycloak "Protocol Mappers" per client; SAML attribute statements |
| Authorization rules | (n/a) | Keycloak authorization services (JS policy / role policy / permission) |
| LDAP attribute store | (n/a on macOS) | Keycloak User Federation (LDAP); SSSD for local mapping |
| SQL attribute store | (n/a) | Keycloak User Storage SPI (custom Java); or external sync (cron-driven) |
| Custom .NET attribute store | (none) | Keycloak User Storage SPI (Java) |

For Linux, Keycloak replaces both ADFS as IdP and the claims engine: Keycloak "mappers" (built-in or custom Java SPI) replace CRL rules. mod_auth_mellon maps SAML attributes to Apache environment variables (effectively a static rule set, no DSL).

For macOS, PSSO exposes a limited `userInfo` API for SSO extensions to inject claims into Kerberos tickets; there is no rule DSL — see `../08-macos-equivalents/04-platform-sso-extension.md`.

## References

- MS-ADFS — Active Directory Federation Services Protocols (`https://learn.microsoft.com/openspecs/windows_protocols/ms-adfs`)
- ADFS Claims Rule Language reference — `https://learn.microsoft.com/windows-server/identity/ad-fs/technical-reference/the-role-of-claims`
- ADFS Attribute Stores — `https://learn.microsoft.com/windows-server/identity/ad-fs/technical-reference/the-role-of-attribute-stores`
- `Microsoft.IdentityServer.dll!Microsoft.IdentityServer.PolicyEngine.PolicyEngine` (claim pipeline entry point)
- `Microsoft.IdentityServer.ClaimsPolicy.AttributeStore.IAttributeStore` interface
- `Microsoft.IdentityServer.ClaimsPolicy.AttributeStore.ActiveDirectoryAttributeStore` (built-in)
- `Microsoft.IdentityServer.ClaimsPolicy.AttributeStore.SqlAttributeStore` (built-in)
- OASIS SAML 2.0 Core — claim type URIs
- Windows Internals 7th Ed., Part 1, Chapter 9 — claim pipeline phases
- `https://learn.microsoft.com/windows-server/identity/ad-fs/operations/create-a-rule-to-send-ldap-attributes-as-claims`
