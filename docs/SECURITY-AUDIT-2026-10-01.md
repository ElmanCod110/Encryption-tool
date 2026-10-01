# Secure Package V14 Security Audit — 2026-10-01

## Scope

This audit covers the active V14 server package engine, package parser, authenticated metadata, file streaming, archive container handling, restore path validation, release signing tooling, Composer CI policy, and the retained V13 browser compatibility boundary.

## V14 cryptographic composition

- 256-bit random package root key per package.
- Separate password and pattern Argon2id13 derivation.
- HKDF-SHA-256 subkey separation.
- XChaCha20-Poly1305 for metadata and key slots.
- secretstream XChaCha20-Poly1305 for file contents.
- Header binding included in authenticated operations.
- Encrypted filenames bound to package ID, header binding, and node ID.

The composition is intentionally layered: credentials unlock a wrapping key, not the per-file key directly.

## Integrity findings remediated

- Manifest authentication is required before use.
- Complete ciphertext blob inventory is verified.
- Every referenced blob is hashed before restore.
- Unreachable blobs are rejected.
- Merkle root is recomputed and compared before restore output begins.
- Header binding is recomputed and compared.
- Completion record is size-bounded and bound to the manifest and header.
- Stream decryption requires the authenticated final record and exact plaintext length.
- Tampering with a ciphertext blob prevents restore and leaves no restore directory behind.

## Parser and filesystem findings remediated

- Exact allowlists are enforced for V14 header, crypto profile, key slots, and manifest nodes.
- Invalid timestamps are rejected rather than accepted by regex alone.
- Path traversal, control characters, Windows device names, unsafe trailing characters, and invalid UTF-8 names are rejected.
- Case-folded path collisions are detected.
- File/directory conflicts are rejected.
- Existing restore destinations are rejected before any child write.
- Directory creation is depth ordered; files are restored after directories exist.
- Atomic temporary file restore prevents partially written target files.
- Outer package extraction verifies declared and actual streamed byte counts and enforces an archive entry limit.

## Resource-safety controls

- Header, manifest, node, blob, file, plaintext package, archive entry, and extraction limits.
- Resumable upload ownership binding and rate limiting remain active.
- Package recovery and credential operations are rate controlled by the API layer.
- KDF memory usage is bounded to the declared V14 profile.

## Release and supply-chain controls

- Release signatures use Ed25519.
- Release manifests cover the active V14 source tree instead of only the browser client.
- Verification can require an external trusted public key.
- Composer plugin execution is disabled by default.
- CI validates Composer configuration, installs dependencies, and runs dependency audit.
- Tag release gates require a committed `composer.lock`.

## Test evidence

The current development environment passed:

- all active PHP syntax checks;
- all active JavaScript syntax checks;
- core cryptographic round-trip tests;
- V14 package round-trip;
- V14 recovery-key restore;
- V14 header tamper detection;
- V14 ciphertext tamper detection before restore;
- V14 no-overwrite restore safety;
- V14 descriptor/header validation;
- replay/race and upload tests;
- source security audit.

ZIP-specific V14 archive execution could not be exercised in this sandbox because the PHP Zip extension is unavailable there. GitHub Actions installs and tests with the Zip extension.

## Residual risks

This audit is not a certification. Remaining material risks include host compromise, malicious code already executing with sufficient local privileges, endpoint misconfiguration, loss or theft of credentials/recovery keys, browser compromise of the separate V13 client, dependency supply-chain compromise, and the absence of an independent third-party cryptographic audit.

The project should not use a percentage score as its security claim. Future acceptance should be expressed as explicit threat-model coverage, passing adversarial tests, reproducible builds, and independent review.
