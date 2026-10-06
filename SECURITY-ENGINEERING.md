# Security Engineering — V14

Secure Package V14 treats the cryptographic engine, package parser, archive layer, filesystem restore path, authentication boundary, and release supply chain as one security system.

## Cryptographic boundary

The V14 server engine generates a fresh 256-bit package root key. User password and pattern are each processed through Argon2id13 using independent purpose-derived salts, then combined into a credential wrapping key. That wrapping key protects the package root key rather than directly encrypting every file.

Subkeys are derived from the package root using HKDF-SHA-256 for manifest data, encrypted filenames, and file roots. Individual file keys are derived from the file root and random per-record identifiers.

Small authenticated records use XChaCha20-Poly1305. File contents use libsodium secretstream with per-chunk associated data that binds the package, header, file identifier, chunk index, and expected plaintext size.

## Integrity boundary

The package header contains a canonical cryptographic profile and a SHA-256 header binding. The authenticated manifest contains the encrypted path graph, file sizes, ciphertext hashes, and Merkle root. Restore first validates the complete blob inventory, re-hashes every referenced ciphertext blob, verifies the Merkle root, and only then creates the restore destination.

Restore uses a preflight path walk to reject traversal, device names, unsafe characters, duplicate/case-colliding paths, file/directory conflicts, and existing targets before any package child is written.

## Recovery boundary

Recovery is an independent key slot wrapping the same random package root key. The recovery key is 256 bits of random data and is encoded for transport as unpadded base64url. The server never derives the recovery key from the user password or pattern.

The recovery key should be treated as a separate credential and stored offline. It is deliberately not recoverable from the package itself.

## Browser compatibility boundary

The browser vault remains V13 and is not silently treated as V14. This avoids mixing cryptographic assumptions between the server engine and the browser-only client.

## Release trust boundary

Release manifests cover the active V14 source tree and are signed with Ed25519. Verification supports an externally supplied public trust root through `SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX`. An embedded public key by itself proves only self-consistency; it is not an independent trust anchor.

## Supply chain

Composer configuration is validated in CI and dependency audit is executed after installation. A real `composer.lock` should be committed before a production release so the exact dependency graph can be reproduced.

## Operational baseline

Production should require HTTPS, keep secrets outside the public root, apply strict session and CSRF controls, use owner-bound uploads, limit package/archive resources, and retain security audit logs without storing package passwords, patterns, or recovery keys.

## Claims

V14 does not claim a percentage security score or guarantee against every attacker. The meaningful target is a documented threat model, well-defined cryptographic composition, fail-closed behavior, reproducible builds, adversarial tests, and independent review.
