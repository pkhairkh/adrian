---
title: Domains, Forests, Trees — Topology and Trusts
audience: senior-engineers
tags: [domain, forest, tree, trust, topology]
related:
  - ./01-active-directory-overview.md
  - ./04-fsmo-roles.md
  - ../03-directory-schema/04-trusts-topology.md
last_updated: 2026-08-13
---

# Domains, Trees, Forests, and Trusts

AD topology has four nested layers: **forest**, **tree**, **domain**, **OU**. Each layer corresponds to a unit of (a) Kerberos realm, (b) replication scope, (c) administrative boundary, and (d) DNS namespace.

## The four layers

| Layer | Kerberos realm? | Replicates as | DNS namespace | Admin boundary |
|-------|-----------------|---------------|---------------|----------------|
| **Forest** | One realm per domain; all share a common root krbtgt by transitive trust | Schema NC + Configuration NC replicate forest-wide | Typically one or more trees, all sharing the forest-root domain's name | Trust boundary |
| **Tree** | (No standalone realm; tree is a DNS hierarchy concept) | (No standalone replication) | Contiguous DNS namespace (e.g. `corp.example.com`, `child.corp.example.com`) | None |
| **Domain** | One Kerberos realm | Domain NC replicates among DCs in the domain | The domain's DNS name | Auth + policy boundary |
| **OU** | (No realm) | (No replication; lives in Domain NC) | (No DNS namespace) | Group Policy + delegation boundary |

## Domain NC, Configuration NC, Schema NC

Every DC hosts exactly:

- **One Domain NC** (writable, e.g. `DC=corp,DC=example,DC=com`). Holds domain-local users, computers, groups, OUs, GPCs.
- **One Configuration NC** (writable, e.g. `CN=Configuration,DC=corp,DC=example,DC=com`). Holds sites, subnets, NTDS settings, inter-site transports, services containers, display specifiers, well-known security principals. Replicates forest-wide.
- **One Schema NC** (writable, `CN=Schema,CN=Configuration,...`). Forest-wide; the schema master (PDC emulator FSMO role) is the only DC that can write schema changes, but every DC has a writable copy that it can validate against.
- **Optionally, one or more Application NCs** (e.g. `DC=DomainDnsZones,DC=corp,DC=example,DC=com`, `DC=ForestDnsZones,DC=corp,DC=example,DC=com`). Scope is per-DC; you choose which DCs host each Application NC at creation time. AD-integrated DNS zones live here.

## DNS namespace rules

- A forest has exactly one forest root domain (`corp.example.com`). Its name is also the forest's root trust anchor.
- A tree is a set of domains sharing a contiguous DNS suffix rooted at the forest root. `corp.example.com` and `eu.corp.example.com` are in the same tree.
- A forest can contain multiple trees (e.g. `corp.example.com` and `fabrikam.com`); they are joined at the forest level by a tree-root trust.
- Domain NetBIOS names must be unique in the forest; DNS names must be unique globally.

## Trusts at a glance

Every trust in AD is represented by a `trustedDomain` object in the Domain NC of the trusting domain. The object's `trustDirection`, `trustType`, and `trustAttributes` flags encode the trust's semantics.

| Trust attribute | Meaning |
|-----------------|---------|
| `TRUST_ATTRIBUTE_NON_TRANSITIVE (0x1)` | Trust is one-hop only; A trusts B does not imply A trusts C if B trusts C. |
| `TRUST_ATTRIBUTE_UPGRADE_ONLY (0x2)` | Windows 2000 upgrade legacy marker. |
| `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x4)` | SID filtering enabled; SIDHistory is filtered. Used for untrusted-domain trusts. |
| `TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x8)` | Cross-forest trust; enables cross-forest Kerberos referral + select claims. |
| `TRUST_ATTRIBUTE_CROSS_ORGANIZATION (0x10)` | Selective authentication enabled; SID filtering forced. |
| `TRUST_ATTRIBUTE_WITHIN_FOREST (0x20)` | Trusted domain is in the same forest (auto-transitive). |
| `TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (0x40)` | Force external-trust behaviour even within forest (rare; used for migration quarantining). |
| `TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION (0x80)` | Trust key negotiated to RC4. |
| `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION (0x200)` | Disable TGT delegation across the trust (CVE-2020-1472 mitigation, „No TGT delegation”). |
| `TRUST_ATTRIBUTE_PIM_TRUST (0x400)` | Privileged Identity Management trust (Azure AD-related). |

## Intra-forest trust

Within a forest, every pair of domains has an automatic, two-way, transitive trust. The trust's authentication key is the `trustAuthBlob` attribute on the `trustedDomain` object — an encrypted blob containing the inter-domain trust account password. The blob is encrypted with the domain's `krbtgt` key; cross-domain TGT referrals use it as the cross-realm key.

Kerberos referral across an intra-forest trust:

1. User in `eu.corp.example.com` requests access to `child.corp.example.com\HTTP\web`.
2. Client's KDC (in `eu.corp`) cannot issue the TGS — the SPN is not in its domain. It returns a **referral TGT** encrypted to the next domain up the tree (`corp.example.com`) using the inter-domain trust key.
3. Client walks the chain. Each hop returns either a referral to the next domain up/down the tree, or the final TGS.

The whole referral chain is encoded in the `Transited` field of the resulting TGS ticket. Realm-canon order matters; the KDC checks it against the trust graph.

## Cross-forest trust

A cross-forest trust is a single trust object between forest roots, with `TRUST_ATTRIBUTE_FOREST_TRANSITIVE` set. It enables:

- Cross-forest Kerberos referral (one round-trip per forest boundary, not per domain).
- Cross-forest **SIDHistory** passthrough (subject to `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN` filtering).
- Cross-forest **selective claims** (claim type definitions exported from one forest and imported into the other; see MS-ADTS §3.1.1.3.2.7).

Selective authentication (`TRUST_ATTRIBUTE_CROSS_ORGANIZATION`) requires the `Allowed to Authenticate` extended right to be granted on the target object to the foreign principal; without it, the foreign principal's TGS is refused.

## External trust

An external trust is a non-transitive, one- or two-way trust between domains in **different** forests (or to NT4 / downlevel domains). SID filtering is always on. Use cases: migration, time-bounded collaboration.

## Shortcut trust

A shortcut trust is a manually-created transitive trust between two domains in the same forest that are not parent/child. It short-circuits the referral chain. Use case: `us.corp.example.com` and `ap.corp.example.com` both have heavy cross-traffic; a shortcut trust means referral goes one hop instead of two.

## Realm trust

A trust to a non-Windows MIT Kerberos realm. One-way inbound (Windows trusts MIT) or two-way. Key material is the password on the `trustedDomain` object, exported via `ksetup /AddRealmFlags`. Used to let MIT users access Windows resources via S4U2Proxy or interactive Kerberos.

## NetBIOS / DNS interplay

- Each domain has both a DNS name (`corp.example.com`) and a NetBIOS name (`CORP`).
- Downlevel clients (and Netlogon secure channel) use the NetBIOS name; modern clients use DNS.
- The `flatName` attribute on the `crossRef` object in the Partitions container (`CN=Partitions,CN=Configuration,...`) maps DNS → NetBIOS.

## The forest root

The forest root domain is special in three ways:

1. It hosts the **Schema Master** and **Domain Naming Master** FSMO roles (forest-wide).
2. Its **Enterprise Admins** group is a forest-wide admin group; its SID is well-known within the forest (it appears as `S-1-5-21-<forest-root-domain-sid>-519`).
3. Its `krbtgt` is the **forest root krbtgt**; compromising it = forest-wide golden ticket.

## Site topology

Sites are AD's answer to "things that share fast, cheap network". A site is a set of IP subnets; the site topology is used for:

- **DC location** — clients find a DC in their site first (via `_ldap._tcp.<sitename>._sites.dc._msdcs`).
- **Replication routing** — replication between sites is compressed and scheduled, using site-link costs.
- **DFS-N referral** — DFS-N prefers targets in the client's site.

Site objects live under `CN=Sites,CN=Configuration,...`. Subnets under `CN=Subnets,CN=Sites,...` reference the site via `siteObject`. Site links under `CN=IP,CN=Inter-Site Transports,CN=Sites,...` define cost/schedule for inter-site replication.

The **ISTG** (Inter-Site Topology Generator) is one DC per site; it computes the inter-site replication topology. The KCC on each DC computes the intra-site ring topology.

## Cross-platform equivalents

| AD concept | macOS | Linux (SSSD/Winbind) |
|------------|-------|----------------------|
| Forest | N/A (one realm per Mac, joined to one forest) | N/A (Linux hosts join one domain) |
| Domain | AD domain (via OpenDirectory binding or Jamf) | AD domain (via SSSD/realmd join) |
| Trust | n/a (Mac consumes trust via Kerberos) | n/a (Linux consumes trust via Kerberos referral) |
| Site | Site Name extension via MDM payload | `ad_site = FOO` in `sssd.conf` |
| OU | OD record path | `ldap_search_base` and `krb5_realm` config |
| GC | Not natively used | Optional via `ad_enable_gc = true` (default true) |

## References

- [MS-ADTS] §6.1.6 „Trusts”, §3.1.1.3.3 „Trust Processing”
- Microsoft — *How Domain and Forest Trusts Work* — <https://learn.microsoft.com/en-us/previous-versions/technet-magazine/cc731335(v=ws.10)>
- [MS-KILE] §3.3.5 „Cross-Realm TGT Referral”
