---
title: "ADR-063: Unified Cross-Platform CLI (Implementation Language Deferred)"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-115
severity: medium
tags: [adr, operations, cli, cross-platform, partial, tier-1-orq, dcdiag, repadmin, ntdsutil]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/00-overview/04-fsmo-roles.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/10-comparison-matrices/03-tool-function-matrix.md
  - ./ADR-058-container-native-dcs-operator.md
  - ./ADR-059-pitr-backup-dr-runbooks.md
  - ./ADR-061-rest-grpc-api.md
last_updated: 2026-08-13
---

# ADR-063: Unified Cross-Platform CLI (Implementation Language Deferred)

## Status

Accepted — 2026-08-13

## Context

The canonical AD operational CLI is Windows-only: `dcdiag.exe` (DC health check, 30+ test categories), `repadmin.exe` (replication administration: `/showrepl`, `/syncall`, `/kcc`, `/showutdvec`, `/removelingeringobjects`), `ntdsutil.exe` (metadata cleanup, IFM, semantic database analysis, FSMO seizure), `nltest.exe` (`/dsgetdc`, `/sc_query`, `/domain_trusts`, `/verify`), `ksetup.exe` (Kerberos realm configuration), `setspn.exe` (SPN registration and duplicate detection). All are shipped in RSAT (Remote Server Administration Tools) and run only on Windows. There is no macOS or Linux port. The Microsoft `ActiveDirectory` PowerShell module similarly requires Windows (it wraps ADWS SOAP).

The cross-platform alternatives are fragmented. Samba ships `samba-tool drs showrepl` (subset of `repadmin /showrepl`), `samba-tool domain demote`, `samba-tool fsmo show`, `samba-tool dns` — but no equivalent of `dcdiag`'s 30+ tests, no `ntdsutil` semantic database analysis, no `nltest /sc_query`. FreeIPA ships `ipa-replica-manage status`, `ipa-csreplica-manage status`, `ipa dnszone-show` — but these manage IPA-specific concepts (replica agreements, IPA-managed DNS zones), not the AD-interop surface. Python `impacket` provides low-level DRSUAPI/SAMR/LSARPC clients (`secretsdump.py` for DCSync, `GetUserSPNs.py` for Kerberoasting) but these are offensive-security oriented, not operational.

There is no unified operational CLI that runs on any OS and provides the full `dcdiag`/`repadmin`/`ntdsutil` surface against an AD or framework DC. A macOS admin working on a framework-managed forest must SSH into a Windows box to run `dcdiag`. A Linux admin must install Samba tooling (`samba-tool`) which covers ~30% of `repadmin` and ~0% of `dcdiag`.

The framework gap: a unified operational CLI written in Go or Rust, distributed as a single static binary for Windows/macOS/Linux, providing the full operational surface: replication status, FSMO queries, metadata cleanup, SPN management, dcdiag-equivalent health checks, IFM generation, semantic database analysis. This CLI should speak DRSUAPI/SAMR/LSARPC directly (not require ADWS) so it works against any framework DC.

This ADR is PARTIAL because the confident part (a unified cross-platform CLI with the operational surface) is implementable today, but the implementation language (Go vs Rust) and the base (`samba-tool` fork vs fresh implementation) depend on Tier-1 ORQ-169/170/175/176 (Client SDK architecture) and Tier-3 ORQ-231/232 (implementation language choice). The CLI shares its core with the Client SDK (ADR for PC-085), so the SDK's language decision constrains the CLI.

## Decision

The framework ships a single unified operational CLI named `adrian-cli`, distributed as a static binary for Windows (amd64, arm64), macOS (amd64, arm64), and Linux (amd64, arm64). The CLI provides the full operational surface of `dcdiag`, `repadmin`, `ntdsutil`, `nltest`, `setspn`, and `ksetup`, plus framework-specific commands (backup, restore, schema-upgrade, operator actions). The CLI speaks DRSUAPI, SAMR, LSARPC, and Netlogon directly via DCE/RPC — no ADWS dependency — so it works against any framework DC and against any AD DC. It also speaks the framework's REST/gRPC API (per ADR-061) for high-level operations, choosing the transport based on the operation (REST/gRPC for CRUD, DCE/RPC for low-level operations like replication metadata).

The CLI is structured as a single binary with subcommands: `adrian-cli dcdiag`, `adrian-cli repadmin`, `adrian-cli ntdsutil`, `adrian-cli nltest`, `adrian-cli setspn`, `adrian-cli ksetup`, `adrian-cli trust`, `adrian-cli backup`, `adrian-cli restore`, `adrian-cli schema`, `adrian-cli fsmo`, `adrian-cli dns`, `adrian-cli audit`, `adrian-cli operator`. Each subcommand has subcommands mirroring the legacy tool's flags (e.g. `adrian-cli repadmin showrepl`, `adrian-cli repadmin syncall`, `adrian-cli repadmin kcc`). Output is human-readable by default and JSON via `--output=json` for scripting. The CLI's exit code reflects success/failure for scripting.

The implementation language is deferred pending Tier-1 ORQ-169/170/175/176 (Client SDK architecture). The candidates are Go (most Kubernetes tooling, easy cross-compilation, large ecosystem) and Rust (memory safety, performance, growing Kubernetes tooling). The base (fresh implementation vs `samba-tool` fork) is also deferred pending Tier-3 ORQ-231/232; a fresh implementation is preferred to avoid the GPLv3 inheritance (Samba is GPLv3; the framework must remain MIT or Apache-2.0).

**Concrete specification**:

- The CLI MUST be distributed as a single static binary per platform: `adrian-cli-windows-amd64.exe`, `adrian-cli-windows-arm64.exe`, `adrian-cli-darwin-amd64`, `adrian-cli-darwin-arm64`, `adrian-cli-linux-amd64`, `adrian-cli-linux-arm64`.
- The CLI MUST support the following subcommand groups (each mirroring a legacy tool):
  - `dcdiag`: `dcdiag /test:connectivity`, `dcdiag /test:replications`, `dcdiag /test:services`, `dcdiag /test:advertising`, `dcdiag /test:frssysvol`, `dcdiag /test:kccEvent`, `dcdiag /test:knowsofroleholders`, `dcdiag /test:machineaccount`, `dcdiag /test:objectsreplication`, `dcdiag /test:ridmanager`, `dcdiag /test:frsevent`, `dcdiag /test:systemlog`, `dcdiag /test:verifyreplication`, `dcdiag /test:checksecurityerror`, `dcdiag /test:verifyreferences`, `dcdiag /test:verifyenterprisepermissions`, `dcdiag /test:crossrefvalidation`, `dcdiag /test:csschema`, `dcdiag /test:topology` — all 30+ tests from `dcdiag`.
  - `repadmin`: `showrepl`, `syncall`, `kcc`, `showutdvec`, `removelingeringobjects`, `showmeta`, `replsingleobj`, `queue`, `bind`, `options`, `replicate`, `rodcpurge`, `viewlist`.
  - `ntdsutil`: `metadata cleanup`, `ifm`, `semantic database analysis`, `fsmo maintenance`, `files maintenance`, `snapshot`.
  - `nltest`: `dsgetdc`, `sc_query`, `domain_trusts`, `verify`, `serverdigest`, `dsgetdc`.
  - `setspn`: `-S` (register with duplicate detection), `-L` (list), `-D` (find duplicates), `-X` (delete).
  - `ksetup`: `addrealm`, `addkdc`, `delrealm`, `mapuser`, `setrealm`, `serverstatus`.
  - `trust`: `verify`, `rotate`, `reset` (per ADR-062), `add`, `remove`, `list`, `show`.
  - `backup`: `create`, `restore-pitr`, `restore-object`, `ifm-export`, `ifm-import` (per ADR-059).
  - `restore`: `pitr`, `object`, `forest-root` (per ADR-059).
  - `schema`: `show-version`, `upgrade`, `list-classes`, `list-attributes`, `defunct`.
  - `fsmo`: `show`, `transfer`, `seize`.
  - `dns`: `zone list`, `zone add`, `zone delete`, `record add`, `record delete`, `record query`.
  - `audit`: `tail` (streaming), `query`, `export`.
  - `operator`: `promote`, `demote`, `backup-now`, `restore-now`, `schema-upgrade`, `fsmo-transfer` (per ADR-058).
- The CLI MUST accept `--output=[human | json | yaml]` flag; default is `human`.
- The CLI MUST accept `--dc=<hostname>` to target a specific DC; default is auto-discovery via DNS SRV records.
- The CLI MUST accept `--realm=<REALM>` for Kerberos auth; the CLI uses the local `KRB5CCNAME` for auth.
- The CLI MUST accept `--api-token=<token>` for REST/gRPC API auth (OAuth2 bearer token per ADR-061).
- The CLI MUST speak DCE/RPC over TCP/135 (endpoint mapper) + dynamic RPC ports for DRSUAPI, SAMR, LSARPC, Netlogon.
- The CLI MUST speak REST/HTTPS (per ADR-061) for high-level operations (list users, create group).
- The CLI MUST speak gRPC (per ADR-061) for streaming operations (audit tail, replication status).
- The CLI MUST emit one OTel client span per command invocation, propagated to the DC via the LDAP control or Kerberos auth-data (per ADR-057).
- The CLI MUST exit with code 0 on success, non-zero on failure (1 = operational error, 2 = auth error, 3 = network error, 4 = not found).
- The CLI MUST support shell completion (bash, zsh, fish, powershell) via `adrian-cli completion <shell>`.
- The CLI MUST support a `--dry-run` flag for mutating operations.
- The CLI's `--help` output MUST follow the POSIX `--help` convention with examples.
- The CLI's binary size MUST be <50 MB (static link, no runtime dependencies).
- The CLI MUST be signed (per ADR-067) — Sigstore cosign signature for Linux/macOS, Authenticode for Windows.

## Rationale

A unified cross-platform CLI is the single most impactful operational improvement. Today, every macOS and Linux admin who needs to run `dcdiag` must context-switch to a Windows VM. The framework's CLI eliminates this context switch. The single-binary distribution model is the standard for modern CLIs (`kubectl`, `helm`, `terraform`, `gh`, `docker`) — it eliminates installation friction.

The subcommand structure mirroring the legacy tools (`dcdiag`, `repadmin`, `ntdsutil`, `nltest`, `setspn`, `ksetup`) is deliberate: experienced AD admins can map their existing knowledge directly. `adrian-cli repadmin showrepl` produces the same output as `repadmin /showrepl` (modulo formatting). This reduces training cost during AD-to-framework migration.

Speaking DCE/RPC directly (not via ADWS) is necessary because (a) ADWS is Windows-only and SOAP-based — wrapping it would couple the CLI to Windows, (b) the framework's DCs expose DCE/RPC natively (DRSUAPI, SAMR, LSARPC, Netlogon), so the CLI can target any framework DC, (c) DCE/RPC is the wire protocol that the legacy tools use, so behaviour matches.

The JSON/YAML output is necessary for scripting. AD admins today parse `repadmin /showrepl` output with regex (fragile, brittle). The CLI's `--output=json` produces structured output that can be piped to `jq` or `yq`. This enables GitOps workflows where the CLI output is consumed by Terraform, Pulumi, or Argo CD.

The CLI shares its core with the Client SDK (PC-085) — both need to speak DCE/RPC, REST, and gRPC. Implementing them in the same language reduces code duplication. The implementation language decision (Go vs Rust) is deferred to the Client SDK ADR because the SDK has stricter constraints (it must be embeddable in other applications, which favours Rust's C-FFI story or Go's plugin story).

A fresh implementation is preferred over a `samba-tool` fork because (a) Samba is GPLv3, which would force the framework to GPLv3, incompatible with the MIT/Apache-2.0 license goal, (b) `samba-tool`'s code structure is Samba-specific (it shares code with the Samba AD-DC server), making it hard to extract as a standalone CLI, (c) a fresh implementation can use modern language features (async, type-safe RPC bindings) that Samba's C/Python codebase cannot. This is the Tier-3 ORQ-231/232 decision, deferred.

## Consequences

**Positive**: macOS and Linux admins can run operational commands directly without SSHing to Windows. CI/CD pipelines can run `adrian-cli` in any container. GitOps workflows can consume CLI output as JSON/YAML. The legacy tool knowledge (dcdiag, repadmin, ntdsutil) transfers directly. Shell completion reduces typo errors.

**Negative**: The CLI is a single binary that must be kept in sync with the framework's API version — schema changes, new audit events, new operator actions all require CLI updates. The DCE/RPC implementation is non-trivial (~10k lines for DRSUAPI + SAMR + LSARPC + Netlogon); the implementation language decision (deferred) affects the DCE/RPC library choice (Go has `go-dcerpc`, Rust has `dcerpc`).

**Neutral**: The CLI does not replace PowerShell for organisations that have invested in PowerShell automation. The framework ships a PowerShell wrapper module that calls `adrian-cli` under the hood, preserving existing PowerShell scripts. The CLI's JSON output enables PowerShell, Python, and Bash scripting equally.

**Implementation cost**: ~6 person-months for the DCE/RPC client (DRSUAPI, SAMR, LSARPC, Netlogon); ~4 person-months for the subcommand implementations (dcdiag tests, repadmin commands, ntdsutil flows); ~2 person-months for the REST/gRPC client and the OAuth2 token acquisition; ~2 person-months for the shell completion, signing, and distribution. Total: ~14 person-months for v1.

**Operational impact**: macOS and Linux admins get a single binary to install. Windows admins can use either `adrian-cli` or the legacy tools (the framework's DCs respond to both). The CLI's JSON output enables automated CI checks (e.g. "after schema upgrade, run `adrian-cli dcdiag /test:replications` and verify all replications are healthy").

## Alternatives Considered

**Alternative A: Wrap `samba-tool` and extend.** Fork Samba's `samba-tool`, add the missing functionality (dcdiag tests, ntdsutil semantic database analysis, nltest /sc_query). Rejected as the primary path because (a) GPLv3 inheritance, (b) `samba-tool`'s code structure is Samba-specific, (c) the fresh-implementation cost is comparable to the fork-and-extend cost once Samba-specific refactoring is accounted for. `samba-tool` may be used as a reference implementation for DCE/RPC bindings.

**Alternative B: PowerShell Core (cross-platform) only.** PowerShell Core runs on Linux and macOS; ship a PowerShell module that wraps the framework's API. Rejected as the primary path because (a) PowerShell requires PowerShell runtime installation (not a single static binary), (b) PowerShell's startup time (1-3 seconds) is too slow for ad-hoc CLI usage, (c) Linux/macOS admins typically prefer native shell tools over PowerShell. PowerShell module shipped as a wrapper on top of `adrian-cli` for organisations with PowerShell investment.

**Alternative C: Python CLI with `impacket` as the DCE/RPC library.** Python is cross-platform and `impacket` is a mature DCE/RPC library. Rejected because (a) Python requires Python runtime installation, (b) Python's startup time (200-500 ms) is slower than a compiled binary, (c) Python CLIs are harder to distribute as a single artifact (PyInstaller works but produces 50-100 MB binaries), (d) `impacket` is offensive-security-focused and not designed for operational tooling (no `dcdiag`-equivalent tests).

**Alternative D: Web UI only, no CLI.** Provide operational functionality via a web admin console. Rejected because (a) CI/CD pipelines cannot use a web UI, (b) GitOps requires CLI/API access, (c) SSH-based troubleshooting from a jump host requires a CLI, (d) scripting requires structured output. Web UI is shipped as a complementary tool, not a replacement.

## Open Questions

**PARTIAL ADR — gating ORQs:**

- **ORQ-169/170/175/176 (Client SDK architecture, Tier-1)**: The CLI shares its core with the Client SDK (PC-085). The SDK's architecture (single-language vs multi-language; embeddable in C/Rust/Go/Python/Java) constrains the CLI's implementation language. If the SDK is Rust-based, the CLI is Rust; if Go-based, the CLI is Go.
- **ORQ-231/232 (implementation language, Tier-3)**: Go vs Rust for the CLI/SDK. Go has stronger Kubernetes ecosystem and easier cross-compilation; Rust has stronger memory safety and performance. This is a Tier-3 ORQ (low-priority) because both languages can implement the CLI; the choice is one of engineering preference, not architectural necessity.

Other Tier-2/3 ORQs that affect future iterations but do not gate v1:

- ORQ-229 (CLI plugin architecture): Should the CLI support plugins (third-party extensions)? Current spec is monolithic.
- ORQ-230 (CLI output format stability): Should the JSON/YAML output be considered a stable API? Current spec: yes, versioned with `--api-version`.

## Cross-capability impact

- **Operations (PC-109)**: ADR-058 (container-native DCs + operator) — the CLI's `operator` subcommand invokes operator actions; the CLI is also the recommended tool for ad-hoc operator debugging.
- **Operations (PC-110)**: ADR-059 (PITR backup + DR runbooks) — the CLI's `backup` and `restore` subcommands expose the DR runbooks.
- **Operations (PC-112)**: ADR-061 (REST/gRPC API) — the CLI is the primary consumer of the REST/gRPC API; CLI commands map to API endpoints.
- **Operations (PC-114)**: ADR-062 (trust password auto-rotation) — the CLI's `trust` subcommand exposes trust verification and manual reset.
- **KDC (PC-035)**: The CLI's `setspn` and `ksetup` subcommands manage SPNs and Kerberos realm config.
- **Client SDK (PC-085 through PC-093)**: The CLI and the SDK share their core; the SDK's language decision (ORQ-169/170/175/176) gates the CLI's language.
- **Migration (PC-126)**: Client switchover (PC-126, deferred) uses the CLI for migration tooling (bulk user import, group sync, trust setup).
- **Migration (PC-129)**: ADR-069 (cross-realm capaths) — the CLI's `trust add` subcommand automates the cross-realm setup.

## References

- [PC-115](../catalog/10-operations.md) — problem statement (`dcdiag` / `repadmin` / `ntdsutil` are Windows-only; cross-platform tooling is fragmented)
- [FSMO roles](../docs/00-overview/04-fsmo-roles.md) — FSMO role holders, transfer/seizure procedures (which `ntdsutil` and the framework CLI must expose)
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — `repadmin /showrepl` output, USN vector inspection, replication metadata
- [Tool function matrix](../docs/10-comparison-matrices/03-tool-function-matrix.md) — Function × Tool matrix showing Windows-only tools and their partial Linux/macOS equivalents
- [MS-DRSR — Directory Replication Service Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/)
- [MS-SAMR — Security Account Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/)
- [MS-LSAD — Local Security Authority (Domain Policy) Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/)
- [MS-NRPC — Netlogon Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/)
- [DCE/RPC 1.1 — Distributed Computing Environment Remote Procedure Call](https://pubs.opengroup.org/onlinepubs/9629399/)
