# Secure Package Security Audit — 2026-09-30

## Scope

This document records the baseline audit of the supplied project and the remediation status in the hardened V13 tree. The review covered browser package parsing, cryptographic composition, authentication/session handling, upload ownership, archive extraction, filesystem restore, release verification, CI, dependencies, and version drift.

## Current disposition

The active browser surface is now `SECURE-BROWSER-V13`. Historical V7–V12 browser/API/source material is retained only under `archive/legacy/` and is denied by an archive-level `.htaccess` rule.

The complete regression suite and the fast V13 security suite pass in the development environment. JavaScript syntax checks also pass for the active browser client.

## Remediated findings

### Package parsing and resource exhaustion

- Header length is bounded before the header payload is read.
- Footer and manifest sizes are bounded.
- KDF parameters are exact and allowlisted before expensive derivation.
- File, chunk, path, and total-plaintext limits are explicit.
- Manifest validation uses indexed chunk lookup rather than a quadratic scan.
- Merkle verification is incremental to avoid retaining all leaf hashes at once.
- Empty-file chunks use the correct 16-byte AES-GCM tag-only ciphertext size.

### Integrity and restore

- Every ciphertext chunk is verified against its SHA-256 content address.
- The complete V13 Merkle root is recomputed and compared before restore output begins.
- Path components are normalized and checked against traversal, control-character, Windows-device, and trailing-dot/space hazards.
- Case-insensitive duplicate paths are rejected.
- Internal file/directory path conflicts are rejected before filesystem mutation.
- Existing destination files are rejected instead of silently overwritten.

### Upload and authorization

- V13 upload state is owner-bound.
- Ownership is checked before global ciphertext chunk-store mutation.
- Duplicate chunk submissions are idempotent without inflating accounting.
- Chunk size and actual request-body size are bounded.
- Upload admission and chunk-throughput rate limits are enforced.

### Session and transport

- Strict session mode, cookie-only sessions, `HttpOnly`, `SameSite=Strict`, origin checking, and optional HTTPS enforcement are active.
- Production configuration supports an explicit `SPK_PUBLIC_ORIGIN` and `SPK_REQUIRE_HTTPS=1`.

### Release integrity

- Release signing targets only the active V13 browser assets.
- The verifier validates manifest identity and asset paths/hashes.
- A release can be checked against an independently supplied Ed25519 trust root.
- An embedded release key is treated as self-consistency only and is not an independent trust anchor.

## Remaining high-assurance work

The following items remain release gates rather than hidden assumptions:

1. Browser-side memory-hard KDF: the current browser profile uses Web Crypto PBKDF2-HMAC-SHA-256 for portability. A future Argon2id/WASM profile requires a vetted implementation, test vectors, performance limits, and a separate format/version decision.
2. Dependency reproducibility: `composer.lock` must be committed and CI should use locked installs.
3. CI supply-chain pinning: GitHub Actions should be pinned to immutable commit SHAs.
4. Adversarial browser tests: malformed package/property/fuzz coverage should be expanded beyond syntax and PHP-side regression tests.
5. Independent review: high-assurance claims require a second-engineer or external cryptographic/code review and, ideally, penetration testing.
6. Production operations: HTTPS-only deployment, private storage, backups, key rotation, incident response, and release-key distribution need documented operational procedures.

## Important limitation

No internal test suite can establish an absolute security percentage. The appropriate security claim is bounded by the documented threat model, cryptographic design, implementation correctness, deployment configuration, and independent review.
