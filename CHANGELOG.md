# Changelog

## Unreleased — v1.0.0 readiness, API reliability, and storage hardening

- Put API configuration loading and service initialization inside the generic error boundary; typed authentication failures now return HTTP 401, and missing resources are separated from storage/programming failures.
- Added typed archive-step conflicts, rejected archive/package input, and storage faults so malformed input can return a documented 4xx while I/O failures remain generic 500 responses.
- Hardened restore rollback, controller path cleanup, portable archive publication, and resumable-upload deletion with ownership checks, no-overwrite publication, post-cleanup verification, and surfaced cleanup errors.
- Made catalog listings fail closed on malformed JSON, invalid records, and symlinked records instead of silently presenting an incomplete inventory.
- Added HTTP regressions for configuration failure privacy, method Allow headers, authentication, missing job/package privacy, catalog failure, and restore storage failure.
- Added regressions for corrupt ZIPs, archive traversal, existing-output preservation, catalog listing integrity, controller cleanup, and resumable-upload symlink safety.
- Separated V14 authentication/stream rejection from storage errors while preserving atomic link-based no-replace publication; temporary file identities and restrictive modes are checked before publication.
- Added the Composer-generated lockfile to the release-readiness work branch and made the manual lock refresh workflow fail before creating a PR when dependency audit fails.
- Ported the Windows source-audit self-path normalization and strengthened release-signing input/write verification.
- Reconciled the API error contract and reproducible QA matrix; manual Windows/XAMPP, real-browser, independently trusted signed-artifact, and independent security-review gates remain NOT RUN.
- Kept the stable binary package format isolated in PR #38; it is not the default production writer and is not yet approved for v1.0.0.
- Added a Windows CI smoke job for locked Composer install/audit, PHP syntax, self-check, source audit, V14 restore/archive safety, browser V13 compatibility, and external-trust-root signer verification.
- Added a release-readiness lockfile gate and full regression/security suite to the Security and Release Integrity workflow.
- Fixed a false-positive restore-safety test so an existing destination is accepted as rejected only when the expected typed storage exception is thrown, and verified its content remains unchanged.
- Documented V14/stable-format metadata leakage, offline password-and-pattern guessing, sender-authenticity limits, and the explicit legacy-reader/migration policy.

- Add an executable release-signing regression that verifies Ed25519 signatures against an independently pinned external trust root.
- Fail closed when the audit hash-chain head is missing or corrupt, verify chain integrity before appending, and redact sensitive audit context keys by normalized fragments.
- Stage all existing encrypted package representations before revoking access or deleting catalog metadata; roll back staged files on pre-commit failures and test injected deletion/cleanup failures.


- Expanded the authenticated account profile into a responsive encrypted-package dashboard with package inventory, storage metadata, access controls, and regression coverage.
- Zeroize each derived V14 per-file encryption key in a `finally` block, including when stream encryption throws.


- Established `VERSION` as the single source of truth for the application release version and documented the distinction between application versioning and package-format identifiers.
- Updated the main UI to display the canonical application version from shared configuration.
- Normalized versioned documentation filenames while retaining the historical Markdown change and validation records.
- Removed the superseded bundled source archive from the active repository tree.
- Added security reporting, contribution, support, and structured issue-reporting guidance.


## 0.14.1 — Compatibility and Server Reliability Fixes

- Fixed Browser Vault V13 self-produced package rejection caused by missing key-slot type/version metadata.
- Fixed server account creation/build initialization when `SPK_NAME_PEPPER` is not exported by generating a persistent local application secret under `storage/secrets/`.
- Fixed server build response so the one-time recovery key is returned correctly.
- Added cleanup when portable `.spkg14` packaging fails to prevent orphaned package directories.
- Server health now correctly reports the PHP Zip extension as required for the server workspace.
- Added a clearer Browser Vault restore diagnostic for unsupported/non-secure browser contexts.
- Added regression coverage for persistent application-secret bootstrap.

## 14.0.0 — V14 cryptographic package engine

### Security

- Introduced `SECURE-PKG-V14` with a random 256-bit package root key.
- Added independent Argon2id13 derivation for password and pattern credentials.
- Added HKDF-SHA-256 key separation for manifest, filenames, and file encryption.
- Added XChaCha20-Poly1305 authenticated key wrapping and metadata encryption.
- Added secretstream-authenticated file streaming with chunk-bound associated data.
- Added header binding and authenticated encrypted filenames.
- Added full ciphertext hash inventory verification and Merkle-root validation before restore.
- Added fail-closed path validation and no-overwrite restore behavior.
- Hardened outer ZIP package creation/extraction against unsafe paths, collision, and actual-byte expansion issues.
- Hardened release signing to cover the active source tree with an external trust-root verification mode.
- Hardened Composer policy by disabling Composer plugins and adding a release lockfile gate.

### Project maintenance

- Bundled superseded V6–V13 generation material into `archive/secure-package-legacy.zip` so the active tree stays compact and uncluttered.
- Added V14 UI for recovery-key creation and restore.
- Added V14 adversarial tests for header tampering, blob tampering, recovery, and restore safety.

### Compatibility

`SECURE-BROWSER-V13` remains available only as a separate legacy browser compatibility boundary.
