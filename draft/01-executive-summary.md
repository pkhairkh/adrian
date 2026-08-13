---
title: Executive Summary — Active Directory Research Deliverable
audience: architects-and-engineers
tags: [rough-draft, synthesis, executive-summary, framework-design, ad, cross-platform]
related:
  - ./README.md
  - ./01-executive-summary.md
  - ./02-kb-synthesis.md
  - ../catalog/README.md
  - ../docs/README.md
last_updated: 2026-08-13
---

# Executive Summary

This is the headline view of the Adrian research deliverable — an exhaustive study of Microsoft Active Directory and a catalog of every problem that must be solved to build a modern, cross-platform AD-equivalent framework. The deliverable comprises 88 Markdown files (~34,300 lines): a 72-file implementation-level knowledge base under [`docs/`](../docs/README.md), a 16-file framework problem catalog under [`catalog/`](../catalog/README.md), and this synthesis under [`draft/`](./README.md). This summary is the 5-minute version.

## What this research covers

Active Directory is not one product; it is a federation of five server roles — AD DS (directory + auth), AD CS (PKI), AD FS (federation), AD LDS (directory-only), AD RMS (rights management) — sharing a common ESE-backed directory, a Kerberos KDC, DNS, LDAP, SMB, and DCE/RPC substrate, with replication handled by DRSUAPI over MS-DRSR. Their internals are documented at implementation depth in [`docs/00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) and [`docs/00-overview/02-ad-architecture.md`](../docs/00-overview/02-ad-architecture.md). AD's design assumption is single-vendor Windows-only clients and DCs; cross-platform parity has been bolted on after the fact via OpenDirectory on macOS and three competing stacks (SSSD, Winbind, PBIS) on Linux, none of which achieves full parity.

The cross-platform challenge is the project's motivating problem. A framework that wants to support every AD feature — directory, Kerberos, GPO, PKI, federation, file/print, migration from existing AD forests — must run on Windows, macOS, and Linux as both server and client, interoperate with existing AD during migration, and match AD's threat surface without inheriting its 25 years of accumulated security debt. The 72-file KB documents what AD does; the 130-problem catalog documents what the framework must do. The design question: which of AD's choices should the framework inherit (interop), which invent fresh (clean-slate), and which shim (compat-with-extension)? Every protocol-level decision is gated by this trichotomy. The catalog identifies 12 framework capabilities, 130 distinct problems, 23 blockers that must be solved before any MVP ships, and 262 open research questions in [`catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md).

## Headline findings

- **130 distinct problems** across 12 framework capabilities, every problem cross-linked to ≥2 KB source files. See [`catalog/README.md`](../catalog/README.md).
- **23 blocker problems** must be solved before any MVP. They span Core Directory (DRSUAPI, replication, storage, schema), KDC (MS-KILE, krbtgt), Policy Engine (GPO format), Cert Service (enrollment), Federation Gateway (IdP choice), and Client SDK (unified cross-platform API).
- **262 open research questions**, 3-tier prioritization. **11 Tier-1 questions are architectural decisions that must be answered before design begins**; getting one wrong cascades across multiple capabilities.
- **macOS lacks native equivalents for GPO Preferences, NTLM, and AD-integrated DNS.** OpenDirectory handles binding + Kerberos; GPO requires MDM Configuration Profiles (a different format); NTLM requires third-party agents. PSSO (macOS 13+) and the Kerberos SSO Extension are the modern native surface; legacy agents (Enterprise Connect, NoMAD, Centrify) are EOL or deprecated.
- **Linux has three competing AD integration stacks** — SSSD (modern default), Winbind (legacy but capable), PBIS (commercial, deprecated 2023) — plus FreeIPA (alternative DC with AD cross-forest trust) and roll-your-own OpenLDAP + MIT Kerberos. None achieves full GPO parity.
- **No universal client SDK exists.** Windows uses SSPI + Wldap32 + NetAPI + gpsvc; macOS uses OpenDirectory + Authorization + SSO Extensions; Linux uses SSSD + PAM + NSS + libkrb5 + libldap. The framework must unify these behind one C/Rust/Go API. See [`catalog/08-client-sdk.md`](../catalog/08-client-sdk.md).
- **No open-source DRSUAPI server exists outside Samba (GPLv3).** A framework wanting AD-interop replication must inherit Samba's license, write a fresh ~5K-line NDR + state machine implementation, or accept clean-slate replication with no AD-interop. See [`catalog/01-core-directory.md`](../catalog/01-core-directory.md) PC-001.
- **No open-source MS-KILE-compliant KDC exists outside Samba's Heimdal fork.** MIT krb5 generates no PAC by default; FreeIPA's `ipa_kdb` generates MS-PAC for trust users only. The framework must generate the full PAC buffer set signed with the krbtgt key. See [`catalog/02-kdc.md`](../catalog/02-kdc.md) PC-023.
- **Cross-platform parity matrix: 95 Windows, 78 macOS, 82 Linux, 67 cross-platform-consistency problems** — roughly 30% are parity gaps. See [`catalog/14-cross-platform-parity-matrix.md`](../catalog/14-cross-platform-parity-matrix.md).
- **10 cross-cutting design tensions** (enumerated below) thread through every capability decision and must be resolved at the architecture level.

## The 5 most consequential problems

These five blocker problems are the highest-leverage decisions. Solving them unlocks the rest of the framework; punting them propagates ambiguity into every other capability.

**PC-001 — DRSUAPI replication protocol.** AD replication rides on the DRSUAPI DCE/RPC interface (`[uuid(E3514235-8B63-11D0-A26C-00A0C92B955C), version(4.0)]`), with `DRSGetNCChanges` (opnum 3) as the workhorse state-based pull. A framework wanting to peer-replicate with existing AD forests must implement the full MS-DRSR §4 wire protocol (NDR encoding, LZ-Express compression, `DRS_EXTENSIONS_INT` capability negotiation), reuse Samba's GPLv3 implementation, or accept loss of AD interop. See [`catalog/01-core-directory.md`](../catalog/01-core-directory.md) PC-001.

**PC-002 — Replication model choice.** AD's replication correctness rests on a four-tuple: per-DC `usnChanged` (monotonic counter allocated inside the ESE transaction), per-DC `invocationId` (UUID regenerated on USN-rollback detection), per-NC up-to-dateness vector, and per-NC high-watermark cursor. Together they implement idempotent replication with rollback protection. Raft's log truncation loses per-attribute originating metadata; 389-DS MMR lacks per-attribute versioning; OpenLDAP SYNCREPL lacks rollback detection. Any clean-slate protocol must preserve all three properties or accept silent divergence. See [`catalog/01-core-directory.md`](../catalog/01-core-directory.md) PC-002.

**PC-007 — Storage engine.** AD's `ntds.dit` is an ESE (Jet Blue) database — Windows-only, 32 KB pages, SHA-1 page checksums, ~50 tables (`datatable`, `linktable`, `sdtable`, `cursor`), with security-descriptor deduplication. Open-source alternatives (TDB, BerkeleyDB, LMDB, RocksDB, FoundationDB, SQLite) each match some subset of ESE's properties; none matches all. The wrong choice locks the framework into a scalability ceiling (TDB ~1M objects, LMDB single-writer). See [`catalog/01-core-directory.md`](../catalog/01-core-directory.md) PC-007.

**PC-023 — MS-KILE KDC profile.** AD's KDC (`kdcsvc.dll`) extends RFC 4120 with MS-KILE: a full PAC buffer set (`PAC_LOGON_INFO` 0x01, `PAC_SIGNATURE_DATA` 0x06/0x07, `PAC_UPN_DNS_INFO` 0x0C, Server 2016+ `PAC_BUFFER_TICKET_CHECKSUM` 0x0E, Server 2019+ `PAC_REQUESTER` 0x12), signed with the krbtgt long-term key. Samba's Heimdal fork is the only open-source server implementation (GPLv3); MIT krb5 generates no PAC by default; FreeIPA generates MS-PAC for trust users only. Without an MS-KILE-compliant KDC, AD-aware services cannot validate PACs and cross-forest trusts break. See [`catalog/02-kdc.md`](../catalog/02-kdc.md) PC-023.

**PC-030 — krbtgt rotation.** Anyone with the krbtgt NT hash can forge TGTs (golden ticket). Mitigation is dual-krbtgt mode (Server 2012+): rotate the password (current → previous), wait for TGT lifetime (default 10 hours), rotate again to drop the old key. The procedure is multi-step, painful, rarely done preventively. A framework must make rotation one-click, support dual-key overlap, and alert on old-key TGT usage. The krbtgt key must replicate atomically and urgently (PC-001 dependency). See [`catalog/02-kdc.md`](../catalog/02-kdc.md) PC-030.

## 10 cross-cutting design tensions

These tensions surface in multiple capabilities and must be resolved at the architecture level, not per-capability. Each is documented in [`catalog/README.md`](../catalog/README.md) §"Cross-cutting design tensions":

1. **AD-interop vs. clean-slate.** Full compat (speak MS-DRSR), compat-with-shim (MS-DRSR + extensions), or clean-slate (Raft/OT)? Pick a lane per protocol.
2. **Multi-master vs. consensus.** AD is multi-master with per-attribute version vectors; modern systems prefer Raft/Paxos for strong consistency.
3. **LDAP schema vs. typed schema.** AD's schema is dynamic, attribute-based, OID-keyed. Modern systems prefer typed schemas (protobuf, SQL DDL, JSON Schema). The choice cascades into the directory API, replication protocol, and client SDK.
4. **SIDs vs. UUIDs.** AD uses SIDs (`S-1-5-21-<domain>-<rid>`); modern systems prefer UUIDs. Both, with mapping?
5. **GPO format vs. declarative policy.** AD's GPO is INI / `Registry.pol`-based, fragile, no rollback. Modern alternatives (Salt, Ansible, K8s operators) are declarative, versioned, transactional. Keep GPO, adopt declarative, or hybrid?
6. **NTLM: drop or maintain.** NTLM is broken (pass-the-hash, relay) but legacy apps require it. Drop entirely, maintain, or maintain with hard mitigations (channel binding, EPA, signing)?
7. **PKI: AD CS protocols vs. ACME/EST.** AD CS uses MS-WCCE / MS-XCEP. Modern PKI uses ACME (RFC 8555) or EST (RFC 7030). Implement MS-WCCE, adopt ACME, or both with translation?
8. **Federation: AD FS topology vs. modern IdP.** AD FS is a separate farm with SQL/WID + WAP reverse proxy. Modern IdPs (Keycloak, Authentik, Ory, Zitadel) are lighter and cloud-native. Re-implement AD FS or wrap a modern IdP?
9. **Multi-tenancy: native vs. per-instance.** AD has no native multi-tenancy. Cloud-native systems expect it.
10. **Client SDK: per-platform or unified.** Unified C/Rust/Go SDK with platform bindings, or wrap existing per-platform libraries (SSSD, OpenDirectory, Wldap32)?

## Recommended next steps

1. **Answer the 11 Tier-1 open research questions.** Each is an architectural decision that cascades across multiple capabilities; each warrants a 1–2 week research spike. Tier-1 covers: replication protocol choice; storage engine choice; SID vs. UUID; LDAP vs. typed schema; KDC implementation (Samba Heimdal vs. MIT krb5 vs. fresh); NTLM decision; PKI enrollment (MS-WCCE vs. ACME); federation layer; SMB server; Client SDK architecture; Linux tier strategy (adopt FreeIPA vs. build native). See [`catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md) §Tier 1.
2. **Decide AD-interop vs. clean-slate per protocol.** Pick a lane for DRSUAPI, MS-KILE, MS-WCCE, MS-ADFSPIP, MS-RPRN. Each choice sets the framework's compatibility ceiling and the implementation surface area.
3. **Scope an MVP around the 23 blocker problems.** The MVP must demonstrate: a DC that stores objects and replicates; a KDC that issues PAC-bearing tickets; a policy engine that distributes configuration; a client SDK that authenticates from Windows, macOS, and Linux.
4. **Sequence v1 around the 64 high-severity problems** — production readiness for greenfield deployments that do not need AD interop.
5. **Stand up an AD-interop test forest** and use it to validate every interop claim. DRSUAPI, MS-KILE, MS-WCCE, and SAML/OIDC federation must be wire-compatible with a real Windows Server 2022 forest.

Continue to [`02-kb-synthesis.md`](./02-kb-synthesis.md) for the technical narrative, `03-catalog-synthesis.md` for the problem-space narrative (downstream task), or `04-prioritized-research-questions.md` for the prioritized research questions (downstream task).
