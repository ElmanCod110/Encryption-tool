# Changelog

## V3.0.0 - 2026-09-08

### Security

- Introduced `SECURE-PKG-V3` format.
- Replaced project-specific namespace and identifiers with generic `SecurePackage` naming.
- Added strict KDF parameter validation to prevent attacker-controlled KDF cost selection.
- Added strict package structure allow-list validation.
- Added exact blob inventory validation against the decrypted manifest.
- Added one-time expiring restore tokens.
- Added locked file-backed rate-limit updates to reduce concurrent race conditions.
- Added stronger restored-name validation for Windows device names and trailing dot/space hazards.
- Added additional HTTP security headers and a Content Security Policy.

### Package handling

- Added atomic `.spkg` creation.
- Added bounded portable-package extraction.
- Added store-only packaging for already encrypted blobs.
- Added explicit package identifiers to the encrypted-package header.
- Added empty-directory package compatibility.

### Web workflow

- Added restored-result download endpoint.
- Added restore-token lifecycle handling.
- Improved package creation/opening interface.
- Added client-side password and pattern strength meters.

### Tooling

- Added Composer metadata.
- Added MIT license.
- Added new regression tests for package IDs, KDF parameters, and restore tokens.
- Updated documentation and threat model.

### Compatibility

V3 is intentionally not wire-compatible with the previous format. Future readers should reject unsupported package versions rather than attempting heuristic migration.
