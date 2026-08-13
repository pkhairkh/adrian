---
title: "ADR-046: Drop MS-RPRN; Adopt IPP Everywhere"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: File Gateway
problem: PC-083
severity: blocker
tags: [adr, file-gateway, print, ms-rprn, printnightmare, ipp-everywhere, cups]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/07-file-gateway.md
  - ../docs/07-file-print/03-print-services.md
  - ../docs/02-protocols/03-smb-cifs-protocol.md
last_updated: 2026-08-13
---

# ADR-046: Drop MS-RPRN; Adopt IPP Everywhere

## Status

Accepted — 2026-08-13

## Context

CVE-2021-34527 ("PrintNightmare") and its sibling CVE-2021-36958 exploited MS-RPRN's `RpcAddPrinterDriverEx` (opnum 109 on the Print System Remote Protocol interface `[uuid(0F30C728-D1DA-11D2-AE4F-00A0C92B955C)]`) to achieve SYSTEM code execution on any print server reachable over MS-RPRN RPC. The vector: a caller with `LoadDriver` privilege (or in some pre-patch configurations, any authenticated user) supplies a `DRIVER_CONTAINER` structure pointing to a UNC path containing an attacker-controlled DLL. The spooler service (`spoolsv.exe`, running as `NT AUTHORITY\NetworkService` but with a `LoadLibrary`-capable subsystem) copies the DLL to `C:\Windows\System32\spool\drivers\x64\3\` as SYSTEM and then loads it via `LoadLibrary`, achieving SYSTEM code execution in the spooler process, per the analysis in [docs/07-file-print/03-print-services.md](../docs/07-file-print/03-print-services.md). The patch (KB5004945) added path validation to `localspl.dll!SplAddPrinterDriver` that rejects UNC paths and verifies the requesting user can read the file directly — but the deeper architectural problem remains: MS-RPRN's Type 3 driver model loads third-party code (driver DLLs, renderers, port monitors) into the spooler process.

The PrintNightmare class is systemic. MS-RPRN driver install was the source of at least four CVEs in 2021-2022: CVE-2021-34527, CVE-2021-36958, CVE-2021-34483, CVE-2021-26878. Any framework that implements the MS-RPRN driver-install path inherits this attack surface. Microsoft's mitigation in Server 2012+ was Type 4 drivers (`PrinterDriverClass=v4` in the INF), which use the spooler's built-in XPS render pipeline and don't load third-party code; Type 4 + `PrintIsolationHost.exe` (driver isolation in a separate low-integrity process since Server 2008 R2) is the only safe Windows print architecture. The framework's print subsystem must not implement the MS-RPRN driver-install code path.

The cross-platform print landscape is already aligned with the PrintNightmare-safe architecture. macOS uses CUPS as its entire print stack (Apple acquired CUPS in 2007), exposing IPP on TCP 631 with driver filters stored in `/Library/Printers/` running as the `lp` user. Linux CUPS is identical. Samba's `cups` backend (`source3/printing/print_cups.c`) hands print jobs to CUPS via the IPP protocol; Samba itself does not load driver DLLs into a SYSTEM-equivalent process on Linux. Windows 10 21H2+ supports IPP class driver printing natively. The IPP Everywhere standard (RFC 8011 + PWG 5100.18) is the universal driverless print protocol supported by Windows 10 21H2+, macOS 11+, and Linux CUPS 1.5+. The framework's print subsystem must simply refuse to implement MS-RPRN driver install and standardize on IPP Everywhere.

The constraints from [PC-083](../catalog/07-file-gateway.md#pc-083--printnightmare-cve-2021-34527-exposed-ms-rprn-driver-install-as-system) are explicit. The framework must not implement `RpcAddPrinterDriverEx` (opnum 109) or `RpcAddPrinterDriver` (opnum 17) in any form. The framework must not load third-party driver code into the print spooler process — Type 4 (driverless) or CUPS filters only. If any subset of MS-RPRN is implemented for legacy compat (e.g. `RpcEnumPrinters` opnum 3 for printer discovery), the framework must enforce `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (auth level 6) on all MS-RPRN RPC calls. The framework must enforce `RestrictDriverInstallationToAdministrators = 1` registry equivalent and `RestrictAnonymousShareAccess = 1` for `\\server\print$` SMB share if driver distribution via `print$` is supported. The framework must support `printQueue` AD object publication for printer discovery without supporting driver-install over RPC.

## Decision

The framework's File Gateway will not implement MS-RPRN's `RpcAddPrinterDriverEx` (opnum 109), `RpcAddPrinterDriver` (opnum 17), or any other driver-install opnum. The framework's print subsystem will expose printing exclusively via IPP Everywhere (RFC 8011 + PWG 5100.18) on TCP 631, with CUPS-compatible filter pipelines for client-side rendering. Printers will be discovered via DNS-SD (Bonjour/Avahi mDNS) `_ipp._tcp` and `_ipps._tcp` service advertisements, optionally augmented by LDAP queries against `printQueue` AD objects for cross-subnet discovery. The framework will publish `printQueue` AD objects for AD-interop discovery but will not implement the MS-RPRN wire protocol. Legacy MS-RPRN-only Windows clients will be documented as out of scope; the migration path is Windows 10 21H2+ IPP class driver (built into Windows Update) or a CUPS-compatible driver model.

**Concrete specification**:

- The framework's print server MUST NOT implement `RpcAddPrinterDriverEx` (MS-RPRN opnum 109), `RpcAddPrinterDriver` (opnum 17), or any other driver-install opnum in the MS-RPRN interface `[uuid(0F30C728-D1DA-11D2-AE4F-00A0C92B955C)]`. The framework MUST NOT register this UUID in its RPC endpoint mapper (`rpcinfo -p` MUST NOT list the PrintSystem UUID).
- The framework's print server MUST expose IPP (RFC 8011) on TCP 631 and IPPS (IPP over TLS, RFC 8010) on TCP 632. The IPP server MUST support the `Get-Printer-Attributes`, `Validate-Job`, `Create-Job`, `Send-Document`, `Get-Jobs`, `Cancel-Job`, `Get-Job-Attributes`, and `Close-Job` operations per RFC 8011 §4.
- The framework's print server MUST advertise IPP Everywhere conformance per PWG 5100.18: the `printer-attributes` response MUST include `ipp-versions-supported = 2.0`, `operations-supported` covering the required operation set, `document-format-supported` including `application/pdf` (the IPP Everywhere canonical format), and the `media-col-database`, `print-quality-supported`, `sides-supported`, and `orientation-requested-supported` attributes per PWG 5100.18 §4.
- The framework's print server MUST advertise printers via DNS-SD `_ipp._tcp` (port 631) and `_ipps._tcp` (port 632) service records, with `rp` (resource path) TXT record set to `/printers/<queue>` per RFC 8011 §6.3. The DNS-SD advertisement MUST include `txtvers=1`, `qtotal=1`, `pdl=application/pdf,image/urf`, and `URF=none` (or the printer's actual URF capabilities) TXT records per PWG 5100.18 §6.
- The framework's print server MUST NOT load third-party driver code into the spooler process. Printer-specific rendering MUST use CUPS filter pipelines (`/usr/lib/cups/filter/*`) running as the `lp` user (or framework-equivalent low-privilege user). The framework's spooler process MUST NOT run as root/SYSTEM.
- The framework's print server MUST publish `printQueue` AD objects under `CN=<server>,CN=PrintQueues,CN=...` for each framework-hosted printer. The `printQueue` object MUST set `printerName`, `serverName`, `uNCName` (UNC path to the printer, e.g. `\\server\printer`), `portName`, `driverName` (set to a generic IPP Everywhere driver name, not a vendor-specific driver), `printShareName`, and `location` attributes. The `printQueue` object is for discovery only; the framework does not implement MS-RPRN RPC to serve driver-install requests.
- The framework's print server MUST enforce TLS 1.3 (per RFC 8446) for IPPS connections. The TLS certificate MUST be issued by the framework's Cert Service (per ADR-037, two-tier CA with HSM-bound root). IPP-only (TCP 631, plaintext) connections MUST be supported only for `127.0.0.1` and `::1` (loopback); remote plaintext IPP MUST be disabled by default with a configuration override for trusted-network deployments.
- The framework's documentation MUST include a "PrintNightmare-safe print deployment" guide: enable IPPS only, disable plaintext IPP for non-loopback, publish `printQueue` AD objects for discovery, deploy Windows 10 21H2+ IPP class drivers via Intune/MDM, deploy macOS `lpadmin`-configured queues via MDM profile (`com.apple.print.cups` payload), deploy Linux CUPS queues via Ansible.
- The framework's documentation MUST explicitly mark MS-RPRN-only legacy Windows clients (Windows 7, Windows 8/8.1, Windows 10 pre-21H2) as out of scope. The migration path is Windows 10 21H2+ upgrade (free for Windows 10 customers) or a CUPS-compatible third-party print server (e.g. PaperCut, Sepialine) as an MS-RPRN-to-IPP bridge for stranded clients.
- The framework's automated test suite MUST include a PrintNightmare regression test: a test client issues `RpcAddPrinterDriverEx` (opnum 109) against the framework's RPC endpoint mapper; the test asserts the RPC endpoint mapper returns `RPC_S_PROTSEQ_NOT_SUPPORTED` (or the framework's RPC listener returns `STATUS_ACCESS_DENIED` if the UUID is registered but the opnum is refused). The test MUST run on every CI build.

## Rationale

The decision is forced by the PrintNightmare attack class. MS-RPRN driver install is a recurring source of SYSTEM-level RCE; four CVEs in 2021-2022 alone. The framework cannot ship an MS-RPRN-capable print server without inheriting this attack surface; the only safe posture is to refuse the MS-RPRN driver-install path entirely. The migration cost is low because Windows 10 21H2+, macOS 11+, and Linux CUPS 1.5+ all support IPP Everywhere natively — the framework is aligning with the industry trajectory, not against it.

The decision is also forced by cross-platform alignment. macOS and Linux already use CUPS + IPP as their entire print stack; the framework's print server on those platforms is naturally CUPS-based. The decision extends the same architecture to Windows by requiring the IPP class driver (Windows 10 21H2+) for framework-hosted printers, eliminating the platform-divergent driver distribution problem. The Windows reference print architecture (Type 4 + `PrintIsolationHost.exe`) is conceptually equivalent to CUPS filter isolation, but Microsoft's Type 4 driver model is Windows-specific and not portable; IPP Everywhere is the cross-platform standard.

The decision preserves printer discovery via `printQueue` AD objects because the discovery path is not the security liability — the driver-install path is. Windows clients can still query AD for printers (`Get-Printer -Full` reads `printQueue` objects), Mac clients can still discover printers via Bonjour mDNS or via the `printQueue` LDAP query, and Linux clients can still discover printers via Avahi mDNS or via LDAP. The framework's discovery-only `printQueue` publication gives customers a migration path from existing AD-published printers without forcing them to rewrite discovery workflows.

The decision to mandate IPPS (TLS 1.3) for remote IPP is forced by the modern security posture. Print jobs contain potentially sensitive data (financial reports, HR documents, legal contracts); plaintext IPP over TCP 631 exposes this data to network sniffers. TLS 1.3 with framework-CA-issued certificates provides confidentiality and integrity. The loopback plaintext-IPP exception is for local administration tools (CUPS web UI, `lpadmin` CLI) that do not need TLS overhead.

The decision to document legacy Windows clients as out of scope is forced by the framework's commitment to a clean security posture. The cost of supporting MS-RPRN-only clients is the PrintNightmare attack surface; the cost of not supporting them is a Windows 10 21H2+ upgrade (free for Windows 10 customers, available since November 2021). The cost calculus is unambiguous.

## Consequences

**Positive**. The framework eliminates the PrintNightmare attack class from its print surface. The framework's print server is cross-platform (CUPS-derived on all platforms, or a fresh IPP server with CUPS-compatible filter pipelines). The framework's print discovery (DNS-SD + `printQueue` AD objects) is cross-platform and modern. The framework's TLS-only remote IPP posture matches modern security expectations.

**Negative**. The framework cannot serve MS-RPRN-only legacy Windows clients (Windows 7, 8/8.1, Windows 10 pre-21H2). Customers with stranded legacy clients must either upgrade (the recommended path) or run a third-party MS-RPRN-to-IPP bridge (PaperCut, Sepialine). The framework's documentation must be clear about this limitation; the proof-of-concept deployment must verify all client Windows versions are 21H2+.

**Neutral**. The framework's `printQueue` AD object publication is invisible to IPP clients (they use DNS-SD or direct hostname). The framework's IPPS posture is invisible to LAN-internal clients that already use TLS for everything else.

**Implementation cost**. Medium. Estimated 8-12 engineer-weeks for the IPP server (reusing CUPS on Linux/macOS, fresh Rust/Go implementation on Windows or wrapping Windows' IPP class driver infrastructure), the DNS-SD advertisement, the `printQueue` AD object publisher, the TLS configuration, the PrintNightmare regression test, and the documentation. The framework's RPC endpoint mapper must explicitly NOT register the PrintSystem UUID `[uuid(0F30C728-...)]`, which is a one-line configuration in most RPC frameworks.

**Operational impact**. Operations teams gain a single print protocol (IPP/ IPPS) instead of the Windows/Samba/CUPS mix. Operations teams lose the MS-RPRN management surface (`Add-PrinterDriver`, `Get-PrinterDriver`); the framework provides `framework-printer` CLI equivalents that wrap IPP `Create-Printer` and `Get-Printer-Attributes`. The framework's runbook must include a "PrintNightmare-safe print deployment" guide. The framework's Prometheus exporter MUST expose `ipp_jobs_total{printer="<name>",status="..."}` and `ipps_connections_total{result="..."}` metrics.

## Alternatives Considered

**Alternative 1: Read-only MS-RPRN subset for legacy discovery.** The framework implements `RpcEnumPrinters` (opnum 3) and `RpcGetPrinter` (opnum 2) for legacy Windows client discovery, refusing all write opnums. **Rejection rationale**: This adds complexity (the framework must implement the MS-RPRN RPC interface partially, with strict opnum allow/deny lists) for marginal benefit (legacy Windows clients can already query AD for `printQueue` objects via LDAP, which is simpler and does not require MS-RPRN). The partial MS-RPRN implementation is also a maintenance burden: future MS-RPRN CVEs (e.g. SpoolFool, CVE-2021-36958) may affect the read-only opnums, forcing framework patches.

**Alternative 2: Samba `cups` backend on Linux/macOS, MS-RPRN on Windows.** The framework uses CUPS as the print server on Linux/macOS (via Samba's `cups` backend) and implements MS-RPRN on Windows for native Windows client compat. **Rejection rationale**: This is a platform-divergent posture that the framework's cross-platform parity commitment rejects. The framework's print server must produce identical behavior on every platform; a Windows-only MS-RPRN implementation breaks that commitment and re-introduces the PrintNightmare surface on Windows. The IPP Everywhere standard exists precisely to enable cross-platform parity.

**Alternative 3: Provide an MS-RPRN-to-IPP bridge in the framework.** The framework ships an MS-RPRN RPC listener that translates MS-RPRN calls to IPP operations internally, never loading driver DLLs. **Rejection rationale**: This is a maintenance burden (the framework must track MS-RPRN protocol changes and CVEs indefinitely) for a feature that benefits only stranded legacy clients. The migration cost (Windows 10 21H2+ upgrade) is lower than the framework's ongoing maintenance cost. Customers who truly need an MS-RPRN bridge should use a dedicated third-party product (PaperCut, Sepialine) whose vendor specializes in print-server compat.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the SMB server implementation choice (Samba vs fresh vs platform-native, per ORQ-154/155), but the print subsystem is independent of the SMB server choice — IPP is a separate protocol from SMB.

## Cross-capability impact

- **File Gateway** ([PC-078](../catalog/07-file-gateway.md)): MS-RPRN over `\PIPE\SPOOLSS` is no longer served, so the SMB session's encryption posture does not affect spooler RPC auth (no spooler RPC to encrypt).
- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): `printQueue` object publication requires AD schema support for the `printQueue` object class (already in the AD schema).
- **Cert Service** ([PC-065](../catalog/05-cert-service.md)): IPPS TLS certificate issuance uses the framework's Cert Service (per ADR-037, two-tier CA with HSM-bound root).
- **Policy Engine** ([PC-050](../catalog/04-policy-engine.md)): Printer-configuration policy is distributed via MDM Configuration Profile (`com.apple.print.cups` on macOS), Group Policy Preferences (Windows), or Ansible (Linux) per the unified policy format.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): Client SDK's print client wrapper negotiates IPPS; the SDK does not implement MS-RPRN client calls.

## References

- [PC-083](../catalog/07-file-gateway.md) — problem statement
- [docs/07-file-print/03-print-services.md](../docs/07-file-print/03-print-services.md) — `spoolsv.exe` service architecture, MS-RPRN opnum table, Type 2/3/4 driver model, KB5004945 patch details
- [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md) — MS-RPRN over SMB named pipe `\PIPE\SPOOLSS`
- [RFC 8011](https://www.rfc-editor.org/rfc/rfc8011) — IPP/1.1: Implementer's Guide
- [RFC 8010](https://www.rfc-editor.org/rfc/rfc8010) — IPP/1.1: Encoding and Transport
- [PWG 5100.18](https://www.pwg.org/ipp/everywhere.html) — IPP Everywhere specification
- [CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527) — PrintNightmare vulnerability record
- [MS-RPRN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn) — Print System Remote Protocol (the framework refuses to implement)
