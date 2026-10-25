# Secure Package Threat Model

This model covers the stable single-file binary format used for new server packages and the legacy V14 reader retained for compatibility. The browser V13 vault is a separate design.

## Assets

- Plaintext project contents
- Encryption password and pattern
- 256-bit package root keys
- Recovery keys
- Package metadata and filenames
- Package ownership and access tokens
- Release signing keys

## Adversaries

The server package boundary considers an attacker who can:

- upload or modify package/archive bytes
- submit malformed package metadata repeatedly
- tamper with ciphertext blobs
- replay upload requests
- attempt path traversal or platform-specific path tricks
- make repeated authentication attempts
- gain read access to public package artifacts without credentials
- replace a release artifact after publication

## Security goals

1. Confidentiality of package contents and filenames against storage-only attackers.
2. Integrity and authenticity of package metadata and ciphertext before restore.
3. No overwrite or path traversal during restore.
4. Bounded resource consumption for parsing and extraction.
5. Credential failure behavior that does not reveal which secret failed.
6. Keep application release versions and format-generation labels out of the stable binary package grammar.
6. Separation of release trust from the release package itself.

## Deliberate non-goals

- Protection against malware already executing with full host privileges.
- Recovery of a forgotten password or pattern.
- Recovery of a lost recovery key.
- A universal guarantee against every side channel or implementation flaw.
- Treating the V13 browser vault, stable binary format, and legacy V14 format as cryptographically identical.
- Hiding file sizes, file count, total data volume, or total package size in the stable format.

## Main controls

- Argon2id13 credential derivation
- Random package root keys
- XChaCha20-Poly1305 authenticated wrapping and metadata
- Secretstream-authenticated file chunks
- HKDF key separation
- Header binding
- Stable format: HMAC-authenticated fixed header, encrypted binary manifest, and per-file secretstream authentication
- Legacy V14: ciphertext hashing and complete Merkle verification
- Atomic writes and temporary-file restore
- Preflight path validation and no-overwrite behavior
- Resumable upload ownership and rate controls
- External release trust root
- Source and dependency checks in CI

## Residual risk

The dominant residual risks are endpoint/service misconfiguration, lost credentials, host compromise, browser-side compromise of the separate V13 vault, dependency supply-chain compromise, and lack of independent third-party audit. The stable binary format and legacy V14 reader should be treated as security-engineering implementations rather than certification claims. The stable format's fixed record grammar does not eliminate implementation risk, and an independent third-party audit has not been completed.
