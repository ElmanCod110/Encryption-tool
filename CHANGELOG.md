# Changelog

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

- Moved superseded V6–V13 generation material into `archive/legacy/` where it is not part of the active V14 runtime.
- Added V14 UI for recovery-key creation and restore.
- Added V14 adversarial tests for header tampering, blob tampering, recovery, and restore safety.

### Compatibility

`SECURE-BROWSER-V13` remains available as a separate browser compatibility boundary.
