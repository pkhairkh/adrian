# Contributing to Adrian

This repository is a research deliverable covering Microsoft Active Directory and a framework problem catalog. Contributions are welcome via issues and pull requests.

## Repository layout

```
adrian/
├── README.md                # Top-level project overview
├── LICENSE                  # MIT
├── .gitignore
├── CHANGELOG.md             # Versioned release notes
├── CONTRIBUTING.md          # This file
├── docs/                    # 72-file implementation-level KB
│   ├── README.md            # KB master index
│   ├── 00-overview/         # AD overview, architecture, FSMO, glossary
│   ├── 01-ad-core/          # AD DS/CS/FS/LDS/RMS internals
│   ├── 02-protocols/        # Kerberos, LDAP, SMB, NTLM, DNS, DRSR, NTP, SPN/UPN/PAC
│   ├── 03-directory-schema/ # Schema attrs, OUs, GC, trusts, replication
│   ├── 04-group-policy/     # GPO architecture, processing, ADMX, CSEs, GPT/GPC
│   ├── 05-pki-certs/        # AD CS architecture, templates, autoenroll, OCSP
│   ├── 06-federation-sso/   # ADFS architecture, SAML/WS-Fed, claims, OIDC
│   ├── 07-file-print/       # SMB shares, DFS-N/DFS-R, print, offline files
│   ├── 08-macos-equivalents/# OpenDirectory, Jamf Connect, PSSO, etc.
│   ├── 09-linux-equivalents/# SSSD, Winbind, realmd, PBIS, FreeIPA, OpenLDAP, PAM
│   ├── 10-comparison-matrices/
│   ├── 11-code-examples/    # PowerShell, SSSD, macOS CLI, Wireshark, Python
│   └── 12-references/       # MS-* protocols, RFCs, source repos
├── catalog/                 # 16-file problem catalog (130 problems)
│   ├── README.md            # Catalog master index
│   ├── 00-framework-capabilities.md
│   ├── 01-core-directory.md  through 12-migration-and-coexistence.md
│   ├── 13-open-research-questions.md
│   └── 14-cross-platform-parity-matrix.md
├── draft/                   # Rough draft synthesis (~23K words)
│   ├── README.md
│   ├── 01-executive-summary.md
│   ├── 02-kb-synthesis.md
│   ├── 03-problem-catalog-synthesis.md
│   ├── 04-open-research-questions.md
│   ├── 05-cross-platform-parity.md
│   └── 06-roadmap.md
└── scripts/                 # Working scripts and extraction artifacts
    ├── problem-extraction.md
    └── fix_broken_xrefs.py
```

## How to contribute

### Reporting issues

Open a GitHub issue for:
- Factual errors in any KB file
- Missing protocol-level detail in the catalog
- Broken cross-references
- Suggestions for additional content

### Pull requests

1. Fork the repository
2. Create a feature branch: `git checkout -b add-new-section`
3. Make your changes following the file conventions below
4. Verify all cross-references resolve (see "Cross-reference verification" below)
5. Commit with a clear message (see "Commit message conventions" below)
6. Open a pull request

### File conventions

Every Markdown file in `docs/` and `catalog/` MUST have:

1. **YAML frontmatter** at the top:
   ```yaml
   ---
   title: <Human-readable title>
   audience: senior-engineers | architects-and-engineers
   tags: [lowercase, comma, separated]
   related:
     - ./<sibling-file>.md
     - ../<dir>/<file>.md
   last_updated: YYYY-MM-DD
   ---
   ```

2. **Opening sentence**: implementation-level, no boilerplate. State what the component does at the protocol/source-code level.

3. **Body sections**: architecture, protocol structures (with hex offsets), source-file paths in `path/to/file.c:function()` form, registry keys with full paths, IDL fragments where relevant, code/config examples, troubleshooting, cross-platform equivalents.

4. **Cross-references**: link to other files using relative paths. Use `[text](../dir/file.md)` syntax.

5. **References section**: at the end of every file, link to MS-* specs, RFCs, source repos.

### Cross-reference verification

Before committing, run:

```bash
# From the repo root
for referrer in $(find docs catalog draft -name '*.md'); do
  dir=$(dirname "$referrer")
  grep -ohE '\]\([0-9A-Za-z_./-]+\.md\)' "$referrer" | \
    sed -e 's/^](//' -e 's/)$//' | sort -u | while read ref; do
      target=$(realpath -m "$dir/$ref" 2>/dev/null)
      if [ -n "$target" ] && [ ! -f "$target" ]; then
        echo "BROKEN: $referrer -> $ref"
      fi
    done
done
```

No broken references should be reported.

### Commit message conventions

Follow the existing pattern:

```
<Wave N>: <short description>

<longer description if needed>

Files affected:
- path/to/file1.md
- path/to/file2.md
```

Or for small fixes:

```
Fix: <short description>
```

### Content depth standards

Every paragraph MUST contain at least 3-5 sentences. Single-sentence paragraphs are forbidden (except for transitional statements). Each section MUST contain a minimum of 150-200 words of body content. See the root project README for full standards.

### Adding a new KB file

1. Pick the appropriate subdirectory under `docs/`
2. Use the next available number prefix (e.g., if `02-protocols/` has files 01-08, use `09-`)
3. Follow the file conventions above
4. Add an entry to the relevant directory's table in `docs/README.md`
5. Add `related:` links to sibling files

### Adding a new catalog problem

1. Pick the appropriate capability file under `catalog/`
2. Use the next available PC-NNN ID (run `grep '^### PC-' catalog/*.md | sort | tail -1` to find the highest)
3. Follow the per-problem entry format documented in `catalog/README.md`
4. Update `catalog/README.md` statistics if needed
5. Update `catalog/14-cross-platform-parity-matrix.md` with the new row
6. If the problem has open questions, add them to `catalog/13-open-research-questions.md`

### Updating the draft

The `draft/` directory is a synthesis. Update it when:
- The underlying `docs/` or `catalog/` content changes substantively
- New cross-cutting findings emerge
- Roadmap phases shift

## License

By contributing, you agree that your contributions will be licensed under the MIT license.

## Contact

Open a GitHub issue for any questions.
