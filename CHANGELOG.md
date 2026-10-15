# Changelog

## Unreleased — v1.0.0 release readiness

- Moved configuration loading inside the API initialization error boundary and added a real HTTP regression test proving config exceptions return a generic 500 without exposing exception details or filesystem paths.
- Added a canonical reproducible release QA matrix covering Windows/XAMPP, V14 server packages, browser V13 compatibility, cleanup, restore safety, and release integrity; unrun manual scenarios remain NOT RUN.
- Updated the API error audit to reflect the centralized request policy, integration coverage, and remaining classification risks.
- Made the Composer lock refresh workflow expose dependency-audit outcomes and fail the workflow when the audit fails; generated a real Composer lockfile and passed strict validation, dependency audit, and lockfile-PR CI.
- Added typed authentication-required handling (HTTP 401), package/job availability handling, stale archive-step conflicts (409), and typed invalid archive/package failures (422).
- Separated package-build validation failures (422) from unexpected build/storage failures (500), with shared cleanup for incomplete artifacts and preservation of the plaintext source job.
- Separated restore/outer-archive rejection from storage failures and verified cleanup of incomplete restore artifacts before returning client errors.
- Moved API service construction inside the centralized error boundary and added HTTP regression coverage for authentication, missing jobs, catalog initialization failure, and internal-detail privacy.
- Added regression coverage for corrupt catalog records, build/restore cleanup, wrong restore credentials, archive path/limit handling, and version metadata.
- Aligned VERSION and the changelog with the published v0.14.1 tag, separated application release version from the SECURE-PKG-V14 format identifier, and added consistency tests.
- Added a release-readiness lockfile gate and an explicit full regression/security-suite step to the release security workflow.
- Added a real HTTP regression test for restore-destination storage failure using a valid disposable V14 package; the response must remain a generic HTTP 500 without exposing package IDs, filesystem paths, or exception types.
- Made portable archive publication atomic and no-overwrite; added regression coverage that an existing destination remains byte-for-byte unchanged when archive creation is rejected.
- Made incomplete package-build cleanup fail closed and surface a typed storage error if generated artifacts cannot be removed; added an HTTP assertion that 405 responses advertise `Allow: POST`.
- Hardened release signing so it verifies all three written signature artifacts before reporting success; added a generated-key test that verifies the signed source manifest using an external trust root.
- Staged package deletion by atomic sibling renames before token/catalog mutation; failures before catalog deletion attempt reverse-order rollback, and token-revocation failures are no longer silently ignored.
- Added a Windows CI smoke job covering Composer validation/audit, PHP syntax, runtime and source checks, V14 package round-trip/restore safety, archive handling, and automated browser V13 compatibility.
- Established VERSION as the single source of truth for the application release version and documented the distinction between application versioning and package-format identifiers.
- Updated the main UI to display the canonical application version from shared configuration.
- Normalized versioned documentation filenames while retaining historical Markdown change and validation records.
- Removed the superseded bundled source archive from the active repository tree.
- Added security reporting, contribution, support, and structured issue-reporting guidance.

## 0.14.1 — Compatibility and Server Reliability Fixes

- Fixed Browser Vault V13 self-produced package rejection caused by missing key-slot type/version metadata.
- Fixed server account creation/build initialization when SPK_NAME_PEPPER is not exported by generating a persistent local application secret under storage/secrets/.
- Fixed server build response so the one-time recovery key is returned correctly.
- Added cleanup when portable .spkg14 packaging fails to prevent orphaned package directories.
- Server health now correctly reports the PHP Zip extension as required for the server workspace.
- Added a clearer Browser Vault restore diagnostic for unsupported/non-secure browser contexts.
- Added regression coverage for persistent application-secret bootstrap.

## 14.0.0 — V14 cryptographic package engine

### Security

- Introduced SECURE-PKG-V14 with a random 256-bit package root key.
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

- Bundled superseded V6–V13 generation material into archive/secure-package-legacy.zip so the active tree stays compact and uncluttered.
- Added V14 UI for recovery-key creation and restore.
- Added V14 adversarial tests for header tampering, blob tampering, recovery, and restore safety.

### Compatibility

SECURE-BROWSER-V13 remains available only as a separate legacy browser compatibility boundary.
