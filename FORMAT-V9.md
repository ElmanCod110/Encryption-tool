# SECURE-BROWSER-V9 Format

## Purpose

V9 defines a browser-first encrypted package format. The browser derives keys from the user password and pattern, encrypts file content and path components locally, and can send only ciphertext to the remote API.

## Container

Magic prefix:

```text
SPK9BIN1\n
```

The binary container is ordered as:

```text
magic
header_length (uint32 big-endian)
header JSON
manifest_length (uint32 big-endian)
encrypted manifest
repeated chunk records:
  metadata_length (uint32 big-endian)
  metadata JSON
  ciphertext_length (uint32 big-endian)
  ciphertext
```

## Cryptography

- Password derivation: PBKDF2-HMAC-SHA-256, 1,000,000 iterations
- Pattern derivation: PBKDF2-HMAC-SHA-256, 1,000,000 iterations
- Key separation: HKDF-SHA-256
- Authenticated encryption: AES-256-GCM
- Hashing: SHA-256
- Integrity: SHA-256 Merkle tree
- Deterministic per-context IV derivation: HMAC-SHA-256 truncated to 96 bits
- Chunk size: 4 MiB

## Privacy Boundary

The browser package contains no plaintext filenames or plaintext paths. Path components are individually encrypted and authenticated as associated data-bound records.

The server-blind upload workflow accepts encrypted chunk material only. It cannot derive the browser package key from the package identifier.

## Important Security Property

Nonce derivation is bound to the package identifier, file identifier and chunk index. File identifiers are freshly random per package build. A local resumable build must therefore retain the package state and file identifiers until completion; reusing identifiers with different plaintext is not permitted.

## Integrity

Each chunk identifier is the SHA-256 digest of an explicit domain-separated ciphertext value. The manifest also commits to chunk metadata and the Merkle root commits to the ordered chunk inventory.
