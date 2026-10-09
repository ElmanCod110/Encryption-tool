# Secure Package V14 Threat Model

## Assets

- Plaintext project contents
- Encryption password and pattern
- 256-bit package root keys
- Recovery keys
- Package metadata and filenames
- Package ownership and access tokens
- Release signing keys

## Adversaries

V14 considers an attacker who can:

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
6. Separation of release trust from the release package itself.

## Deliberate non-goals

- Protection against malware already executing with full host privileges.
- Recovery of a forgotten password or pattern.
- Recovery of a lost recovery key.
- A universal guarantee against every side channel or implementation flaw.
- Treating the V13 browser vault and V14 server engine as cryptographically identical.

## Main controls

- Argon2id13 credential derivation
- Random package root keys
- XChaCha20-Poly1305 authenticated wrapping and metadata
- Secretstream-authenticated file chunks
- HKDF key separation
- Header binding
- Ciphertext hashing and complete Merkle verification
- Atomic writes and temporary-file restore
- Preflight path validation and no-overwrite behavior
- Resumable upload ownership and rate controls
- External release trust root
- Source and dependency checks in CI

## Residual risk

The dominant residual risks are endpoint/service misconfiguration, lost credentials, host compromise, browser-side compromise of the separate V13 vault, dependency supply-chain compromise, and lack of independent third-party audit. V14 should be treated as a security-engineering baseline rather than as a certification claim.
