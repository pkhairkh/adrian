---
title: "ADR-061: REST API for CRUD + gRPC for Streaming (GraphQL Deferred)"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-112
severity: high
tags: [adr, operations, api, rest, grpc, graphql, partial, tier-2-orq]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/11-code-examples/01-powershell-ad-cmdlets.md
  - ./ADR-057-prometheus-otel-observability.md
  - ./ADR-063-unified-cross-platform-cli.md
last_updated: 2026-08-13
---

# ADR-061: REST API for CRUD + gRPC for Streaming (GraphQL Deferred)

## Status

Accepted — 2026-08-13

## Context

AD's programmatic surface is three-tiered, all Windows-centric. (a) LDAP (RFC 4511) on TCP/389 / 636 / 3268 / 3269 with AD-specific controls (`LDAP_SERVER_SD_FLAGS_OID`, `LDAP_SERVER_NOTIFICATION_OID`, `LDAP_SERVER_TREE_DELETE_OID`, `LDAP_SERVER_DIRSYNC_OID`, `LDAP_SERVER_ASQ_OID`). (b) PowerShell `ActiveDirectory` module (`Microsoft.ActiveDirectory.Management.dll`) which wraps ADWS (Active Directory Web Services, `Microsoft.ActiveDirectory.WebServices.exe`) — ADWS exposes a SOAP interface (the `ADWS` endpoint on TCP/9389) that the cmdlets call. ADWS is itself a wrapper around LDAP + SAMR + DRSUAPI. (c) Direct DCE/RPC: SAMR (`12345778-1234-ABCD-EF00-0123456789AC`), LSARPC, DRSUAPI (`E3514235-8B63-11D0-A26C-00A0C92B955C`), Netlogon.

There is no REST. No gRPC. No GraphQL. Modern applications that want to query "give me all members of the Engineering group" must either speak LDAP (requires an LDAP client library, Kerberos auth setup, and an LDAP search filter syntax), or shell out to PowerShell (Windows-only). The `Microsoft.Graph` PowerShell SDK talks to Azure AD / Microsoft Graph, not on-prem AD. Microsoft's own modern management tooling (Microsoft Graph, Intune Graph API) explicitly avoids on-prem AD because there is no clean API.

The framework gap: modern apps expect REST/JSON or gRPC/protobuf. A Kubernetes operator that wants to provision a new user should call `POST /api/v1/users` not `ldapadd -x -D cn=admin -w ...`. Terraform providers, Pulumi components, and Kubernetes operators all assume REST or gRPC. The framework should provide a modern API layer over the directory: REST CRUD on objects, gRPC for streaming (replication status, event tail). GraphQL for flexible queries is a candidate but adds significant complexity (schema federation, query parsing, resolver layer); whether to ship GraphQL is deferred to Tier-2 ORQ-226.

This ADR is PARTIAL because the confident part (REST + gRPC) is implementable today, but the GraphQL question depends on Tier-2 ORQ-226 (graph query language evaluation), which will not be resolved in the v1 timeframe.

## Decision

The framework exposes a modern API surface with two transports: (1) REST/JSON over HTTPS for CRUD operations on directory objects, mirroring LDAP semantics but with a developer-friendly resource model; (2) gRPC/protobuf over HTTP/2 for streaming operations (replication status, change notifications, audit event tail). LDAP remains as a permanent compatibility shim for legacy apps; the new API is the primary surface for new development. GraphQL is deferred pending Tier-2 ORQ-226 (see Open Questions).

The REST API uses a resource-oriented model: `POST /api/v1/users` creates a user, `GET /api/v1/users/{id}` retrieves one, `PATCH /api/v1/users/{id}` modifies attributes, `DELETE /api/v1/users/{id}` deletes (with Recycle Bin semantics by default per ADR-059). The API is a higher-level abstraction over LDAP: `POST /api/v1/users` accepts a JSON body with `userName`, `displayName`, `email`, `memberOf` (array of group IDs), etc., and the framework translates this into the LDAP `add` operation with the `user` class and the appropriate attributes. The `id` is a stable framework identifier (UUID by default; SID-prefixed for AD-interop scenarios per the deferred PC-026 decision).

The gRPC API uses a streaming model: `ReplicationStatus` (server-streaming RPC, returns a stream of `ReplicationStatusEvent` messages), `ChangeNotification` (server-streaming RPC, returns a stream of `DirectoryChangeEvent` messages), `AuditEventTail` (server-streaming RPC, returns a stream of `AuditEvent` messages per ADR-060). The protobuf schema is published in the framework's source tree and is the contract for all gRPC clients.

Both REST and gRPC require OAuth2 bearer token auth (RFC 6750) for API clients; Kerberos SPNEGO is supported for AD-interop scenarios. The framework's identity provider (per the deferred federation layer decision, ORQ-132/133/134) issues the OAuth2 tokens; the API validates them via JWKS.

**Concrete specification**:

- The REST API MUST be exposed at `https://<dc>/api/v1/` over HTTPS (TLS 1.3 required; TLS 1.2 supported for compat).
- The REST API MUST support the following resource types: `users`, `groups`, `computers`, `serviceAccounts`, `organizationalUnits`, `domains`, `trusts`, `sites`, `subnets`, `schemaClasses`, `schemaAttributes`, `gpos`, `certificates`, `dnsZones`, `dnsRecords`.
- Each resource type MUST support `GET` (list with pagination), `GET /{id}` (retrieve one), `POST` (create), `PATCH /{id}` (partial update), `DELETE /{id}` (with `?hard=true` for permanent delete, default is Recycle-Bin delete per ADR-059).
- List endpoints MUST support `?page[size]=N&page[cursor]=<opaque>`, `?filter[<attr>]=<value>` (RFC 7644 SCIM-style filtering), and `?fields=<attr1>,<attr2>` (sparse fieldsets).
- The API MUST return JSON:API-style responses (https://jsonapi.org/) with `data`, `errors`, `meta`, `links` top-level members.
- Error responses MUST use RFC 9457 Problem Details for HTTP APIs (`application/problem+json`).
- The gRPC API MUST be exposed at `grpc://<dc>:443` over HTTP/2 with TLS.
- The gRPC API MUST support the following RPCs: `ReplicationStatus(stream ReplicationStatusEvent)`, `ChangeNotification(ChangeNotificationRequest, stream DirectoryChangeEvent)`, `AuditEventTail(AuditEventTailRequest, stream AuditEvent)`, `BackupStatus(BackupStatusRequest, stream BackupStatusEvent)`, `HealthCheck(HealthCheckRequest, HealthCheckResponse)`.
- Both REST and gRPC MUST require OAuth2 bearer token auth (RFC 6750); tokens are issued by the framework's identity provider.
- Both REST and gRPC MUST support Kerberos SPNEGO for AD-interop scenarios (the client negotiates via `Authorization: Negotiate <base64>` on REST; via `negotiate` SASL mechanism on gRPC).
- The REST API MUST emit one OTel server span per request (per ADR-057) with attributes `http.method`, `http.route`, `http.status_code`, `enduser.id`.
- The gRPC API MUST emit one OTel server span per RPC with attributes `rpc.method`, `rpc.grpc.status_code`, `enduser.id`.
- The REST API MUST support rate-limiting via `429 Too Many Requests` with `Retry-After` header; default rate is 1000 req/min per token.
- The framework MUST ship OpenAPI 3.1 specification for the REST API and a protobuf schema for the gRPC API, both published in the source tree and versioned with the framework.
- The framework MUST ship reference client libraries in Go, Python, TypeScript, and Rust.
- LDAP MUST remain supported on TCP/389 / 636 / 3268 / 3269 indefinitely; the REST/gRPC API runs alongside LDAP on the same DC.

## Rationale

REST + gRPC is the dominant modern API pattern. REST provides a developer-friendly CRUD surface that any HTTP client can consume; gRPC provides a high-performance streaming surface that modern observability and event-driven systems require. The two transports complement each other: REST for one-shot operations (create user, modify group), gRPC for long-lived streams (audit event tail, replication status).

JSON:API and RFC 9457 are open standards for REST response formatting and error reporting. They are widely supported by client libraries and provide a consistent developer experience. SCIM (RFC 7644) filtering is the standard for directory-service query filtering; adopting it reduces the learning curve for developers familiar with Okta, Azure AD, or other SCIM-compliant identity providers.

OAuth2 bearer tokens (RFC 6750) are the modern standard for API auth. Kerberos SPNEGO is supported for AD-interop scenarios but is not the primary auth model; SPNEGO requires a Kerberos client library and a TGT, which most modern API clients (Terraform, Pulumi, Kubernetes operators) do not have. OAuth2 requires only an HTTP client and a token from the identity provider.

The higher-level abstraction (`POST /api/v1/users` instead of `POST /api/v1/objects/{dn}`) is necessary because LDAP DN-based addressing is fragile (DNs change when objects are moved) and unfamiliar to modern developers. The framework maps the resource ID (UUID or SID) to the DN internally; the API client never sees a DN unless it explicitly requests the `distinguishedName` attribute.

GraphQL is deferred because (a) it adds significant complexity (schema federation, query parsing, resolver layer, query-cost analysis to prevent abuse), (b) the v1 API consumers (Kubernetes operators, Terraform providers) are CRUD-focused and do not need flexible queries, (c) Tier-2 ORQ-226 will evaluate whether GraphQL is worth the complexity for v2.

## Consequences

**Positive**: Modern apps can integrate with the framework via standard REST or gRPC; no LDAP client library required. Terraform providers, Pulumi components, Kubernetes operators can be built natively. OpenAPI 3.1 spec enables auto-generated client libraries in any language. OAuth2 bearer tokens are familiar to every modern developer.

**Negative**: The framework now has three API surfaces (LDAP, REST, gRPC) that must be kept in sync — schema changes must reflect in all three. The REST API's higher-level abstraction (`POST /api/v1/users`) introduces a translation layer that must be tested against LDAP semantics; edge cases (e.g. multi-valued attributes, binary attributes, controlled-access attributes) require care. OAuth2 token issuance requires the federation layer (ORQ-132/133/134) to be resolved before the API can be fully production-grade.

**Neutral**: The framework's REST API does not preclude GraphQL in the future; GraphQL can be layered on top of the REST resources (via a GraphQL-to-REST resolver) or implemented directly on the directory (via a GraphQL-to-LDAP resolver) once ORQ-226 is resolved.

**Implementation cost**: ~4 person-months for the REST API server (routing, auth, schema translation, OpenAPI generation); ~3 person-months for the gRPC API server (protobuf schema, streaming logic, auth); ~2 person-months for the OAuth2 integration; ~2 person-months for the reference client libraries. Total: ~11 person-months for v1.

**Operational impact**: API consumers get OpenAPI-generated client libraries and documented endpoints. SREs use the gRPC `HealthCheck` for liveness/readiness probes (per ADR-058). The unified CLI (ADR-063) is built on top of the REST/gRPC API.

## Alternatives Considered

**Alternative A: GraphQL only.** Expose a single GraphQL endpoint that subsumes both CRUD and streaming. Rejected for v1 because (a) GraphQL streaming (Subscriptions) requires WebSocket or SSE, which is more complex than gRPC streaming, (b) GraphQL query-cost analysis is non-trivial and abused queries can DoS the directory, (c) the v1 API consumers are CRUD-focused, (d) Tier-2 ORQ-226 will evaluate GraphQL properly. GraphQL may be added in v2.

**Alternative B: gRPC only.** Expose gRPC for all operations, including CRUD. Rejected because (a) gRPC requires a protobuf client library, which not all consumers have (e.g. `curl` from a shell script), (b) the Kubernetes ecosystem has a strong REST bias (CRDs, kubectl, controllers all speak REST), (c) Terraform and Pulumi providers prefer REST for developer experience.

**Alternative C: JSON-RPC over HTTPS.** A simpler protocol than REST. Rejected because (a) JSON-RPC lacks the resource-oriented model that makes REST intuitive, (b) the JSON:API ecosystem (client libraries, tooling, conventions) is larger, (c) OpenAPI 3.1 generation is well-supported for REST, less so for JSON-RPC.

**Alternative D: Microsoft Graph API compatibility.** Implement the Microsoft Graph API surface (`/v1.0/users`, `/v1.0/groups`) for direct compatibility with Microsoft Graph SDK clients. Rejected as the primary path because (a) Microsoft Graph is a moving target (new endpoints added monthly), (b) Microsoft Graph includes Azure AD-specific resources (applications, servicePrincipals, conditionalAccess) that the framework does not have, (c) Microsoft Graph's licensing requires compatibility testing that the framework cannot guarantee. Microsoft Graph compatibility may be added as an optional adapter in v2.

## Open Questions

**PARTIAL ADR — gating ORQ:**

- **ORQ-226 (graph query language evaluation, Tier-2)**: Should the framework expose a GraphQL endpoint for flexible queries? This question evaluates the complexity (schema federation, query parsing, resolver layer, abuse prevention) against the benefit (single-round-trip complex queries, client-driven field selection). The REST + gRPC decision in this ADR is stable regardless of ORQ-226's outcome; GraphQL, if adopted, layers on top.

Other Tier-2 ORQs that affect future iterations but do not gate v1:

- ORQ-227 (REST API versioning strategy): Should the API use URL-based versioning (`/api/v1/`, `/api/v2/`) or header-based versioning (`Accept: application/vnd.adrian.v2+json`)? Current spec uses URL-based.
- ORQ-228 (REST API rate-limiting strategy): Per-token vs. per-IP vs. per-client rate limits? Current spec uses per-token with a default of 1000 req/min.

## Cross-capability impact

- **Core Directory (PC-001 through PC-022)**: The REST API translates resource operations into LDAP operations; the translation layer must preserve LDAP semantics (atomicity, controls, transactions).
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — REST/gRPC server emits OTel server spans per request.
- **Operations (PC-111)**: ADR-060 (audit logs) — REST/gRPC requests emit audit log records.
- **Operations (PC-115)**: ADR-063 (unified CLI) — the CLI is built on top of the REST/gRPC API.
- **KDC (PC-023 through PC-035)**: The REST API exposes service account management (PC-035 gMSA) and SPN management.
- **Cert Service (PC-057 through PC-067)**: The REST API exposes certificate template management; the gRPC API streams certificate enrollment events.
- **Federation Gateway (PC-068 through PC-077)**: The federation layer (ORQ-132/133/134) issues OAuth2 tokens for the REST/gRPC API; the API depends on the federation layer.
- **Client SDK (PC-085 through PC-093)**: The Client SDK wraps the REST/gRPC API; the SDK is the recommended way for non-Kerberos clients to interact with the framework.
- **Migration (PC-126)**: Client switchover (PC-126, deferred) uses the REST API for migration tooling (bulk user import, group sync).

## References

- [PC-112](../catalog/10-operations.md) — problem statement (AD has no REST/gRPC API; only LDAP + PowerShell)
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — LDAP server front-end (`dsamain.dll`), DRSUAPI interface UUID, AD-specific LDAP controls
- [PowerShell AD cmdlets](../docs/11-code-examples/01-powershell-ad-cmdlets.md) — `ActiveDirectory` PowerShell module wraps ADWS (SOAP on TCP/9389); the closest existing "high-level API" for AD
- [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7644 — System for Cross-domain Identity Management (SCIM) Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
- [RFC 9457 — Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc9457)
- [OpenAPI 3.1 Specification](https://spec.openapis.org/oas/v3.1.0)
- [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
- [JSON:API Specification](https://jsonapi.org/)
