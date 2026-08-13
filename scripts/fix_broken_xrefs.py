#!/usr/bin/env python3
"""Fix broken .md cross-references in the AD KB."""
import re
import os
from pathlib import Path

KB_ROOT = Path("/home/z/my-project/download/ad-kb")

# Map of broken references -> correct references
# These are references that exist in the KB but point to files that don't exist,
# because subagents invented file names instead of using the canonical ones.
FIXES = {
    # Typo fixes
    "../09-linux-equals/05-samba-tool-net-ads.md": "../09-linux-equivalents/05-samba-tool-net-ads.md",

    # Wrong path fixes
    "../03-sssd-gpo-access.md": "../09-linux-equivalents/03-sssd-gpo-access.md",

    # Invented macOS filenames -> canonical ones
    "../08-macos-equivalents/03-file-services-smb-nfs.md": "../08-macos-equivalents/07-third-party-agents-mac.md",
    "../08-macos-equivalents/06-open-directory.md": "../08-macos-equivalents/01-opendirectory-internals.md",
    "../08-macos-equivalents/07-dns-mdns-bonjour.md": "../08-macos-equivalents/07-third-party-agents-mac.md",
    "../08-macos-equivalents/08-samba-heimdal-mac.md": "../08-macos-equivalents/07-third-party-agents-mac.md",
    "../08-macos-equivalents/08-time-services-ntp.md": "../08-macos-equivalents/07-third-party-agents-mac.md",

    # Invented Linux filenames -> canonical ones
    "../09-linux-equivalents/05-keycloak-saml.md": "../09-linux-equivalents/01-sssd-ad-provider.md",
    "../09-linux-equivalents/09-openldap-389ds.md": "../09-linux-equivalents/09-openldap-mit-kerberos.md",

    # Invented PKI filenames -> canonical ones
    "../05-pki-certs/01-pki-trust-chains.md": "../05-pki-certs/01-ad-cs-architecture.md",
    "../05-pki-certs/02-cryptographic-apis.md": "../05-pki-certs/02-certificate-templates.md",

    # Invented federation filenames -> canonical ones
    "../06-federation-sso/01-saml-protocol.md": "../06-federation-sso/02-saml-ws-fed.md",
}

# Iterate over all .md files
total_fixes_applied = 0
for md_file in sorted(KB_ROOT.rglob("*.md")):
    text = md_file.read_text(encoding="utf-8")
    original = text
    for broken, correct in FIXES.items():
        # Only replace when it appears in a markdown link or related-list context,
        # to avoid touching prose mentions.
        # Match in markdown link syntax: [text](path) or YAML list: - path
        text = re.sub(
            r'(\]\()' + re.escape(broken) + r'(\))',
            lambda m: m.group(1) + correct + m.group(2),
            text
        )
        text = re.sub(
            r'(^\s*-\s+)' + re.escape(broken) + r'(\s*$)',
            lambda m: m.group(1) + correct + m.group(2),
            text,
            flags=re.MULTILINE
        )
    if text != original:
        md_file.write_text(text, encoding="utf-8")
        diff_count = sum(1 for b in FIXES if b in original) - sum(1 for b in FIXES if b in text)
        total_fixes_applied += diff_count
        print(f"  fixed: {md_file.relative_to(KB_ROOT)}")

print(f"\nTotal files modified: {total_fixes_applied}")
