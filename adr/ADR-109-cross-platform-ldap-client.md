---
title: "ADR-109: Cross-Platform LDAP Client Library (Wldap32 Equivalent) in adrian-sdk"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-088
severity: high
unblocked_by: [workshop-decision-11]
tags: [adr, client-sdk, ldap, wldap32, openldap, ldap3, paging, signing, channel-binding, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-021-ldap-signing-channel-binding.md
  - ./ADR-051-kcm-linux-api-macos-cache-abstraction.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ./ADR-108-sspi-equivalent-auth-abstraction.md
  - ../catalog/08-client-sdk.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/02-protocols/02-ldap-protocol.md
  - ../docs/03-directory-schema/01-schema-attributes.md
last_updated: 2026-08-14
---

# ADR-109: Cross-Platform LDAP Client Library (Wldap32 Equivalent) in adrian-sdk

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK). Resolves the high-severity problem [PC-088](../catalog/08-client-sdk.md) (SSSD on Linux has GPO access control + ID mapping but no full GPO CSE support — the LDAP access layer is part of the SDK's `DirectoryModule` that enables full GPO CSE coverage). Implements the `DirectoryModule` surface specified in [ADR-107](./ADR-107-unified-rust-core-sdk.md) at the concrete LDAP-access level.

## Context

Windows applications access AD via `wldap32.dll` (Windows LDAP API): `ldap_initialize` / `ldap_bind_s` (with `LDAP_AUTH_NEGOTIATE` for GSS-SPNEGO bind), `ldap_search_ext_s` (with `LDAP_PAGED_RESULT_OID_STRING` for paged results, `LDAP_SERVER_DOMAIN_SCOPE_OID` for domain-only scope, `LDAP_SERVER_ASQ_OID` for attribute-scoped queries, `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` for cross-domain moves), `ldap_modify_s` / `ldap_add_s` / `ldap_delete_s`, plus extended controls like `LDAP_SERVER_NOTIFICATION_OID` (DirSync) and `LDAP_SERVER_TREE_DELETE_EX_OID` (bulk subtree delete). The library is a thin wrapper around the wire protocol defined in [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511) and [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts) §3.1.1 (LDAP extensions).

macOS and Linux have no equivalent of `wldap32.dll` that ships with the framework. macOS ships OpenDirectory's LDAPv3 plug-in (`DSP.LDAPv3.bundle`) which is OpenDirectory-internal and not a general-purpose LDAP client library. Linux ships OpenLDAP's `libldap.so.2` (C library, used by `ldapsearch`, `ldap-utils`, SSSD, `nslcd`); OpenLDAP is the de facto standard but has known issues with extended controls (the `ldap_create_page_control` API is awkward), GSS-SPNEGO bind (requires `cyrus-sasl-gssapi` plugin), and paged-result size negotiation (the library does not auto-negotiate; the application must handle the paged cookie). Cross-platform Rust LDAP libraries exist — `ldap3 = "0.11"` is pure-Rust, async, and supports paged results, GSS-SPNEGO bind via `gss-api`, and the standard RFC 4511 operations — but no library bundles the AD-specific extended controls (DirSync, ASQ, cross-domain move, tree-delete-ex) and the signing/channel-binding posture per [ADR-021](./ADR-021-ldap-signing-channel-binding.md).

Per [PC-088](../catalog/08-client-sdk.md) and [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md), a framework-native application wanting "search the directory for a user, return all attributes, follow paged results, sign the LDAP session, bind with Kerberos" today must call `wldap32.dll` on Windows, `libldap.so.2` on Linux, and OpenDirectory on macOS — three different APIs with three different control surfaces, three different paged-result idioms, and three different GSS-SPNEGO bind code paths. The framework's own consumers (the SDK's `AuthModule` for `tokenGroups` resolution, the `PolicyModule` for GPO fetch, the `CertModule` for cert profile lookup, the `FederationModule` for claims-based identity lookup) all need LDAP access; without a unified LDAP client library, each consumer forks three times.

Workshop Decision 11 §1 specifies that the Rust core `adrian-sdk` exposes a `DirectoryModule` (`pub fn directory(&self) -> &DirectoryModule`). This ADR locks the `DirectoryModule`'s public Rust API, the underlying `ldap3` crate usage, and the AD-specific extended-control implementations.

## Decision

The `adrian-sdk` Rust core ships a cross-platform LDAP client library in its `DirectoryModule`, built on the `ldap3 = "0.11"` pure-Rust LDAP crate, with AD-specific extended controls (DirSync, ASQ, cross-domain move, tree-delete-ex), GSS-SPNEGO bind via the framework's `AuthModule` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)), and LDAP signing + channel binding per [ADR-021](./ADR-021-ldap-signing-channel-binding.md). The library is the framework's Wldap32-equivalent — a single API surface for LDAP directory access on Windows, macOS, and Linux.

**Concrete specification**:

- The `DirectoryModule` exposes a single connection-acquisition entry point:
  ```rust
  impl DirectoryModule {
      pub fn connect(&self, server: &LdapServer) -> Result<LdapConnection, DirectoryError>;
      pub fn connect_with_cred(&self, server: &LdapServer, cred: &CredentialHandle)
          -> Result<LdapConnection, DirectoryError>;
  }
  pub struct LdapServer {
      pub host: String,
      pub port: u16,                              // 389 (ldap) or 636 (ldaps)
      pub use_tls: TlsMode,                       // None, StartTls, Ldaps
      pub signing: SigningMode,                   // per ADR-021: Sign, Seal, None
      pub channel_binding: ChannelBindingMode,    // per ADR-021: Require, Allow, None
  }
  ```
  `LdapConnection` wraps `ldap3::LdapConnAsync` (async) and exposes both async methods (`async fn search(...)`) and blocking methods (`fn search_blocking(...)`, via `tokio::runtime::Runtime::block_on`). The connection pool manages up to 8 concurrent connections per `AdrianClient`; pool sizing is configurable via `ClientConfig::directory_pool_size`.

- The `LdapConnection` exposes RFC 4511 operations:
  ```rust
  impl LdapConnection {
      pub async fn bind_gss_spnego(&self, cred: &CredentialHandle) -> Result<(), DirectoryError>;
      pub async fn bind_anonymous(&self) -> Result<(), DirectoryError>;
      pub async fn bind_simple(&self, dn: &str, password: &str) -> Result<(), DirectoryError>;
      pub async fn search(&self, base: &str, scope: Scope, filter: &str, attrs: &[&str])
          -> Result<SearchStream, DirectoryError>;
      pub async fn add(&self, dn: &str, attrs: Vec<(String, HashSet<String>)>) -> Result<(), DirectoryError>;
      pub async fn modify(&self, dn: &str, mods: Vec<Mod>) -> Result<(), DirectoryError>;
      pub async fn delete(&self, dn: &str) -> Result<(), DirectoryError>;
      pub async fn modify_dn(&self, dn: &str, new_dn: &str, delete_old: bool, new_superior: Option<&str>)
          -> Result<(), DirectoryError>;
      pub async fn extended(&self, oid: &str, payload: Option<&[u8]>) -> Result<ExtResult, DirectoryError>;
      pub async fn whoami(&self) -> Result<String, DirectoryError>;
      pub async fn unbind(&self) -> Result<(), DirectoryError>;
  }
  ```
  `SearchStream` is an async stream yielding `SearchEntry` values (per `ldap3::SearchEntry`) plus a final `SearchResultDone` carrying the paged-results cookie. The framework's paged-result handling is automatic: `search()` accepts a `page_size: usize` parameter (default 1000, matching AD's default page size limit); the `SearchStream` internally issues `ldap_search_ext_s` with the paged-results control and yields entries across pages until the cookie is empty. The application does not see the cookie.

- AD-specific extended controls are exposed via the `extended()` method and dedicated helpers:
  ```rust
  impl LdapConnection {
      pub async fn dirsync(&self, base: &str, flags: u32, max_bytes: u32, cookie: Option<&[u8]>) -> Result<DirSyncResult, DirectoryError>;
      pub async fn asq(&self, base: &str, attr: &str, scope: Scope, filter: &str) -> Result<SearchStream, DirectoryError>;
      pub async fn cross_domain_move(&self, dn: &str, target_dc: &str, target_dn: &str) -> Result<(), DirectoryError>;
      pub async fn tree_delete_ex(&self, base: &str, flags: u32) -> Result<(), DirectoryError>;
      pub async fn get_stats(&self) -> Result<LdapStats, DirectoryError>;          // LDAP_SERVER_GET_STATS_OID
      pub async fn verify_name(&self, dn: &str) -> Result<(), DirectoryError>;     // LDAP_SERVER_VERIFY_NAME_OID
      pub async fn quota_control(&self, dn: &str, sid: &Sid) -> Result<QuotaResult, DirectoryError>;
  }
  ```
  The control OIDs follow MS-ADTS §3.1.1.3: `LDAP_SERVER_DIRSYNC_OID = "1.2.840.113556.1.4.841"`, `LDAP_SERVER_ASQ_OID = "1.2.840.113556.1.4.1504"`, `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID = "1.2.840.113556.1.4.521"`, `LDAP_SERVER_TREE_DELETE_EX_OID = "1.2.840.113556.1.4.805"`, `LDAP_SERVER_GET_STATS_OID = "1.2.840.113556.1.4.840"`, `LDAP_SERVER_VERIFY_NAME_OID = "1.2.840.113556.1.4.1338"`, `LDAP_SERVER_QUOTA_CONTROL_OID = "1.2.840.113556.1.4.1852"`. The framework uses `ldap3`'s `RawControl` mechanism to build the BER-encoded control values per MS-ADTS.

- `bind_gss_spnego` uses the framework's `AuthModule::init_security_context` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)) to drive the SASL GSS-SPNEGO bind. The flow: (1) call `AuthModule::acquire_kerberos(Some("ldap/<dc-host>@<REALM>"))` to get a `CredentialHandle`; (2) call `init_security_context(cred, target=Spn("ldap/<dc-host>"), input=None, channel_bindings=Some(tls-server-end-point), flags={mutual_auth, integrity})` to get the first output token; (3) send the output token as the SASL credentials in an LDAP `BindRequest` with `mechanism = "GSS-SPNEGO"`; (4) on `BindResponse` with `resultCode = saslBindInProgress`, feed the response's `serverSaslCreds` back into `init_security_context`; (5) repeat until `is_complete()` returns `true`; (6) wrap the resulting `SecurityContext` in `ldap3`'s SASL `Gssapi` mechanism to enable per-message signing/sealing via `LDAP_AUTH_SASL`'s `sign`/`seal` flags.

- LDAP signing + channel binding per [ADR-021](./ADR-021-ldap-signing-channel-binding.md): the `LdapServer::signing` field controls whether the LDAP session is signed (`SigningMode::Sign` — SASL integrity, `LDAP_AUTH_SASL` with `sign` flag), sealed (`SigningMode::Seal` — SASL confidentiality, `LDAP_AUTH_SASL` with `seal` flag), or unsigned (`SigningMode::None` — simple bind only, rejected by the framework's directory per [ADR-021](./ADR-021-ldap-signing-channel-binding.md)). The `LdapServer::channel_binding` field controls whether TLS channel binding is required: `ChannelBindingMode::Require` sets `MsvAvChannelBindings` AV_PAIR value `SHA-256(tls-server-end-point)` (per RFC 5929) in the GSS-SPNEGO bind; `ChannelBindingMode::Allow` sets channel bindings if TLS is active; `ChannelBindingMode::None` omits channel bindings (rejected by the framework's directory per [ADR-021](./ADR-021-ldap-signing-channel-binding.md) for AD-interop mode). The default for framework-internal consumers (the SDK's `AuthModule`, `PolicyModule`, `CertModule`, `FederationModule`) is `SigningMode::Seal` + `ChannelBindingMode::Require`.

- `tokenGroups` resolution helper: the `DirectoryModule` exposes `get_token_groups(&self, principal_dn: &str) -> Result<Vec<Sid>, DirectoryError>` that performs an LDAP search with `base = principal_dn`, `scope = Base`, `filter = "(objectClass=*)"`, `attrs = ["tokenGroups", "tokenGroupsGlobalAndUniversal", "primaryGroupID"]` and parses the binary SID values via the `adrian-sid` crate. This is the canonical group-membership resolution path for the framework's `AuthModule` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)).

- The `DirectoryModule` caches LDAP search results per `AdrianClient` instance: an LRU cache (default 10K entries, configurable via `ClientConfig::directory_cache_size`) keyed by `(base, scope, filter, attrs_hash)`. Cache TTL is 60 seconds; cache invalidation is event-driven via the framework's WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)) when the directory notifies of changes. The cache is opt-in per query (`search_cached()` vs `search()`).

- The C ABI exposes the `DirectoryModule` as opaque-handle functions following the same pattern as `AuthModule` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) §C ABI):
  ```c
  typedef struct AdrianDirectory AdrianDirectory;
  typedef struct AdrianLdapConn AdrianLdapConn;
  typedef struct AdrianSearchIter AdrianSearchIter;
  int32_t adrian_directory_connect(AdrianDirectory*, const AdrianLdapServer*, AdrianLdapConn** out);
  int32_t adrian_ldap_bind_gss_spnego(AdrianLdapConn*, const AdrianCredHandle*);
  int32_t adrian_ldap_search(AdrianLdapConn*, const char* base, int scope, const char* filter, const char* const* attrs, AdrianSearchIter** out);
  int32_t adrian_search_iter_next(AdrianSearchIter*, char** out_dn, char** out_attrs_json);
  int32_t adrian_ldap_add(AdrianLdapConn*, const char* dn, const char* attrs_json);
  int32_t adrian_ldap_modify(AdrianLdapConn*, const char* dn, const char* mods_json);
  int32_t adrian_ldap_delete(AdrianLdapConn*, const char* dn);
  int32_t adrian_ldap_dirsync(AdrianLdapConn*, const char* base, uint32_t flags, uint32_t max_bytes, const uint8_t* cookie, size_t cookie_len, AdrianSearchIter** out);
  /* ... and so on for asq, cross_domain_move, tree_delete_ex, get_stats, verify_name, quota_control */
  int32_t adrian_ldap_close(AdrianLdapConn*);
  ```
  Strings are UTF-8 NUL-terminated; complex values (entries, mods) are JSON-encoded for simplicity at the C ABI (the bindings parse the JSON into language-native types).

- Audit logging: every `bind_gss_spnego`, `search` (with base and filter), `add`, `modify`, `delete`, `modify_dn`, `extended`, `dirsync`, `tree_delete_ex` call emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "sdk_ldap_op"`, `op`, `base_dn`, `scope`, `filter`, `attrs`, `result`, `result_code`, `source_ip`, `platform`. PII redaction: the framework's audit layer redacts `userPassword`, `unicodePwd`, `msDS-ResultantPSO` attribute values in the audit event (the attribute names are logged but not the values).

## Rationale

The choice to build the `DirectoryModule` on the `ldap3 = "0.11"` pure-Rust LDAP crate is forced by three considerations. First, `ldap3` is the only mature pure-Rust LDAP client library; it supports async I/O (via `tokio`), paged results, GSS-SPNEGO bind (via the `gss-api` crate), and TLS (via `rustls`). The framework cannot use `libldap.so.2` (OpenLDAP) because OpenLDAP is C and would require FFI wrapping; the framework cannot use `wldap32.dll` because it is Windows-only. Second, `ldap3`'s async design fits the framework's `tokio`-based runtime natively; the framework's `DirectoryModule` can issue concurrent LDAP searches without spawning threads. Third, `ldap3`'s `RawControl` mechanism allows the framework to implement AD-specific extended controls (DirSync, ASQ, cross-domain move, tree-delete-ex) without modifying `ldap3` itself — the controls are BER-encoded in the framework's code and attached to `ldap3`'s `SearchRequest` / `ModifyRequest` via `SearchOptions::raw_control()`.

The choice to implement AD-specific extended controls in the framework's code (rather than contributing them to `ldap3` upstream) is forced by the AD-specific nature of the controls. `ldap3`'s upstream targets RFC 4511 standard LDAP; AD-specific extensions (DirSync, ASQ, tree-delete-ex) are not in the upstream scope. The framework ships its control implementations in the `adrian-sdk` crate as helper methods on `LdapConnection`; the helper methods use `ldap3`'s public `RawControl` API, so no upstream contribution is required. If `ldap3` upstream later accepts the controls, the framework can switch to the upstream API without breaking framework consumers (the helper method signatures are stable).

The choice to delegate GSS-SPNEGO bind to the framework's `AuthModule` (rather than using `ldap3`'s built-in `Gssapi` mechanism directly) is forced by the framework's unified auth abstraction (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)). `ldap3`'s `Gssapi` mechanism uses the `gss-api` crate directly, which would bypass the framework's `AuthModule`'s audit logging, channel-binding enforcement, and PAC validation. By routing the GSS-SPNEGO bind through `AuthModule::init_security_context`, the framework gets unified audit logging, consistent channel-binding enforcement, and PAC validation via the unified PAC validator (per [ADR-049](./ADR-049-standardize-mit-krb5.md)).

The choice to enforce LDAP signing + channel binding by default for framework-internal consumers is forced by [ADR-021](./ADR-021-ldap-signing-channel-binding.md). The framework's directory rejects unsigned LDAP sessions and channel-binding-omitting sessions in AD-interop mode; the SDK's `DirectoryModule` defaults to the strictest mode (`SigningMode::Seal` + `ChannelBindingMode::Require`) to ensure framework-internal LDAP traffic is always protected. Framework applications that need looser settings (e.g., anonymous bind for public directory queries) must explicitly opt in via `LdapServer::signing = SigningMode::None` — the strict default prevents accidental misconfiguration.

The choice to expose `tokenGroups` resolution as a `DirectoryModule` helper (rather than leaving it to the application) is forced by the prevalence of `tokenGroups` queries in the framework's internal consumers. `AuthModule` queries `tokenGroups` for group-membership resolution (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)); `PolicyModule` queries `tokenGroups` for security-group-based policy targeting (per Decision 7); `FederationModule` queries `tokenGroups` for claims-based identity. Centralizing the `tokenGroups` query in `DirectoryModule` ensures consistent parsing (via `adrian-sid`), consistent caching (via the LRU cache), and consistent audit logging.

The choice to cache LDAP search results per `AdrianClient` instance (rather than relying on the directory server's caching) is forced by the frequency of repeated LDAP queries in the framework's internal consumers. `tokenGroups` is queried on every auth decision; group-membership is queried on every policy evaluation; cert profile is queried on every cert enrollment. Without caching, the directory server would see ~10× the LDAP traffic, increasing latency and load. The 60-second TTL matches the framework's KDC cache TTL (per ADR-018); event-driven invalidation via the WebSocket push (per ADR-028) ensures the cache is never stale for more than the WebSocket propagation delay (~100ms typical).

## Consequences

**Positive**. Framework-native applications have a single LDAP client library on Windows, macOS, and Linux, eliminating the tri-codebase LDAP cost. The AD-specific extended controls (DirSync, ASQ, tree-delete-ex) are available cross-platform for the first time — previously Windows-only via `wldap32.dll`. The default-strict signing/channel-binding posture eliminates accidental misconfiguration. The unified audit logging of LDAP operations provides operational visibility that `wldap32.dll` and `libldap.so.2` do not natively provide. The cache reduces directory server load by ~10× for the framework's internal consumers.

**Negative**. The `DirectoryModule` adds ~6MB to the SDK binary (the `ldap3` crate plus its transitive deps `rustls`, `tokio`, `gss-api`). The default-strict signing/channel-binding posture may break existing AD-interop scenarios where the AD DC does not require channel binding (the framework's directory requires it per [ADR-021](./ADR-021-ldap-signing-channel-binding.md), but third-party LDAP servers may not). The cache's 60-second TTL may be too long for some applications (e.g., real-time group-membership changes); applications can disable the cache per-query via `search()` (uncached) vs `search_cached()` (cached).

**Neutral**. The `DirectoryModule` is invisible to platform-native applications (`wldap32.dll`, `libldap.so.2`, OpenDirectory continue to work alongside the SDK). The `DirectoryModule` is invisible to end users (they do not interact with LDAP directly). The `DirectoryModule` is visible to framework-native applications (they call `directory.search()` directly).

**Implementation cost**. ~8 person-weeks. Breakdown: `DirectoryModule` Rust core + `ldap3` integration (2 pw), GSS-SPNEGO bind via `AuthModule` (1 pw), AD-specific extended controls (DirSync, ASQ, cross-domain move, tree-delete-ex, get-stats, verify-name, quota-control) (2 pw), cache layer (1 pw), C ABI surface (1 pw), audit logging integration (0.5 pw), test matrix (Windows + macOS + Linux, signed + sealed + unsigned, paged + non-paged) (0.5 pw).

**Operational impact**. Operations teams gain a single LDAP audit event type (`sdk_ldap_op`) across all platforms, queryable via OpenTelemetry. Operations teams gain metrics for LDAP operation latency (`adrian_ldap_op_duration_seconds{op, platform}`) and cache hit rate (`adrian_ldap_cache_hits_total{platform}` / `adrian_ldap_cache_misses_total{platform}`). Operations teams must understand the cache TTL and invalidation model for troubleshooting (the runbook includes a "DirectoryModule cache troubleshooting" section).

## Alternatives Considered

**Alternative 1: Wrap `wldap32.dll` on Windows and `libldap.so.2` on Linux/macOS.** The SDK exposes a unified Rust API that internally calls `wldap32.dll` on Windows (via the `windows = "0.54"` crate) and `libldap.so.2` on Linux/macOS (via FFI). **Rejection rationale**: `wldap32.dll` is Windows-only; `libldap.so.2` is C and requires FFI wrapping (defeating the memory-safety story); macOS does not ship `libldap.so.2` by default (it ships OpenDirectory, which is not a general-purpose LDAP client library). The pure-Rust `ldap3` crate avoids FFI wrapping and is cross-platform from a single codebase.

**Alternative 2: Use OpenLDAP's `libldap.so.2` everywhere (including Windows via a Windows port).** The SDK uses `libldap.so.2` on Linux/macOS and a Windows port of OpenLDAP (e.g., the `wldap32.dll`-compatible shim or the ApacheDS LDAP client) on Windows. **Rejection rationale**: OpenLDAP's Windows port is not maintained; the ApacheDS LDAP client is Java (not Rust); `wldap32.dll`-compatible shims do not support the AD-specific extended controls natively. The pure-Rust `ldap3` crate is the only viable cross-platform Rust LDAP library.

**Alternative 3: Implement LDAP from scratch in pure Rust in the framework's SDK (no `ldap3` dependency).** The framework implements RFC 4511 ASN.1 marshaling, BER encoding, the LDAP message exchange, and TLS wrapping from scratch in the `adrian-sdk` crate. **Rejection rationale**: This duplicates the `ldap3` crate's ~15K lines of mature code; the framework would inherit the entire LDAP defect surface (BER edge cases, control encoding, referral handling). The `ldap3` crate is mature, actively maintained, and MIT/Apache-2.0-licensed; using it directly is the lower-risk choice. The framework's value-add is the AD-specific extended controls and the unified `AuthModule` integration, both of which build on `ldap3` cleanly via the public `RawControl` API.

## Open Questions

None. The decision is fully specified. The implementation details (cache invalidation via WebSocket push, PII redaction in audit logs) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): The `DirectoryModule` is the framework's primary LDAP client for the Core Directory; the directory's AD-compatible schema (per Day 1 schema decision) and `memberOf` back-link (per [ADR-002](./ADR-002-memberof-back-link.md)) are consumed via `DirectoryModule::search()`.
- **Auth Provider** ([PC-029](../catalog/03-auth-provider.md)): The `AuthModule`'s password-validation path delegates to `DirectoryModule::bind_simple()` for AD-interop mode (where the Auth Provider is the directory's LDAP server).
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The `DirectoryModule` is the directory surface of the unified SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)).
- **Policy Engine** (Decision 7): The `PolicyModule` uses `DirectoryModule::search()` for security-group-based policy targeting and `DirectoryModule::get_token_groups()` for group-membership resolution.
- **Cert Service** (Decision 8): The `CertModule` uses `DirectoryModule::search()` to look up the host's cert profile assignments.
- **Federation Gateway** (Decision 9): The `FederationModule` uses `DirectoryModule::search()` for claims-based identity lookup.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): The `DirectoryModule`'s DirSync support is the migration path for "incremental directory sync from AD to the framework's directory" (per Decision 1 §DrSuapiReplicator).

## References

- [PC-088](../catalog/08-client-sdk.md) — problem statement
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings
- [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md) — LDAP protocol internals, AD extended controls, signing/channel binding
- [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md) — AD schema attributes (tokenGroups, memberOf, primaryGroupID, objectSid)
- [ADR-002](./ADR-002-memberof-back-link.md) — memberOf back-link
- [ADR-021](./ADR-021-ldap-signing-channel-binding.md) — LDAP signing + channel binding
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution (cache invalidation channel)
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization + unified PAC validator
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) — SSPI-equivalent auth abstraction (`AuthModule`)
- [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511) — LDAP: The Protocol
- [RFC 4513](https://www.rfc-editor.org/rfc/rfc4513) — LDAP: Authentication Methods and Security Mechanisms (GSS-SPNEGO bind)
- [MS-ADTS §3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts) — Active Directory Technical Specification (LDAP extensions)
- [ldap3 Rust crate](https://docs.rs/ldap3) — pure-Rust LDAP client library
- [gss-api Rust crate](https://docs.rs/gss-api) — Rust bindings to libgssapi_krb5
