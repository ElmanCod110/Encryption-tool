# Changelog

## Unreleased — v1.0.0 release readiness

- Added a reproducible release QA matrix covering Windows/XAMPP, V14 server packages, browser V13 compatibility, cleanup, and restore safety; manual scenarios remain explicitly NOT RUN until evidence is recorded.
- Updated the API error audit to reflect the current centralized request policy and integration coverage, while documenting remaining broad controller catches.
- Made the Composer lock refresh workflow report the dependency-audit outcome and fail the workflow after opening the review PR when the audit fails.

## Unreleased — MVP readiness and repository maintenance

- Established `VERSION` as the single source of truth for the application release version and documented the distinction between application versioning and package-format identifiers.
- Updated the main UI to display the canonical application version from shared configuration.
- Normalized versioned documentation filenames while retaining the historical Markdown change and validation records.
- Removed the superseded bundled source archive from the active repository tree.
- Added security reporting, contribution, support, and structured issue-reporting guidance.


## 14.1.0 — Compatibility and Server Reliability Fixes

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
