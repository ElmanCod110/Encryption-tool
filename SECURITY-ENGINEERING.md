# Security Engineering

V9 treats security as a release property rather than a single encryption function.

## Release gates

1. PHP syntax must pass.
2. JavaScript syntax must pass.
3. Core cryptographic round trips must pass.
4. Tampering tests must pass.
5. Release signature verification must pass.
6. Signed asset hashes must match the release manifest.
7. No private release key may be committed.
8. The V9 browser package format must reject unsupported versions.

## Dependency policy

V9 intentionally minimizes runtime dependencies. PHP uses the standard Sodium extension and browser cryptography uses Web Crypto.

When dependencies are added, lock exact versions and review the generated lock file before a release.

## Release key policy

The Ed25519 release private key belongs outside the repository and should be stored in a protected signing environment. The repository carries only the public verification key and signed release metadata.

Do not reuse a development signing key for an official release.
