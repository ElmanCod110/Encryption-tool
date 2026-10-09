# Security Policy

## Scope

Reports are welcome for defects affecting the active application, package parsing, archive handling, authentication/session controls, upload and restore workflows, and release integrity.

## Reporting a vulnerability

**Do not publish sensitive reproduction details, credentials, recovery keys, private files, or a weaponized proof of concept in a public issue.**

1. Check whether GitHub's private vulnerability reporting / Security Advisories feature is enabled for this repository. If available, submit the report privately there.
2. If private reporting is unavailable, open a minimal public issue asking the maintainer for a private reporting channel. Do not include sensitive technical details in that issue.
3. Include the affected commit or release, realistic impact, prerequisites, and reproducible steps only through the private channel.

Please allow reasonable time to investigate and prepare a fix before public disclosure. Do not test systems or data you do not own or have permission to assess.

## What to include

- Affected file, endpoint, workflow, commit, or release.
- Preconditions and realistic attacker capabilities.
- Reproduction steps and expected versus actual behavior.
- Impact on confidentiality, integrity, availability, or trust boundaries.
- Suggested mitigation, if known.

Never include real user plaintext, passwords, patterns, recovery keys, server secrets, or private signing keys in a report.

## Security claims

A passing CI run or internal source review is not a guarantee of security certification. Distinguish reproducible findings from speculative concerns.
