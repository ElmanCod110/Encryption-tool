# Secure Package V11 Format

V11 is the large-file and reliability generation of Secure Package.

## Goals

- Browser-first local encryption.
- Streaming package creation without loading an entire input file into memory.
- Bounded memory for content-defined chunking.
- Incremental Merkle accumulation.
- Resumable opaque upload sessions.
- Crash-safe local build checkpoints.
- Local restore with streamed output where supported.
- V10 compatibility remains explicit and separate.

## Container

Magic: `SPK11BIN1`

The container is an append-only stream:

1. magic + header length + header
2. encrypted chunk records
3. encrypted manifest footer
4. footer length + footer marker

Chunk records contain only opaque chunk identifiers, authenticated metadata and ciphertext.
The encrypted manifest contains encrypted path components and the file/chunk index.

## Cryptography

V11 uses the V10 unified key schedule and standard WebCrypto primitives. It does not introduce a custom cipher.

- PBKDF2-HMAC-SHA-256 for credential derivation.
- HKDF-SHA-256 for key separation.
- AES-256-GCM for authenticated encryption.
- HMAC-derived nonces from an independent nonce domain.
- SHA-256 for chunk addressing and Merkle leaves.

## Large-file behavior

Input files are read as streams. The chunker retains at most the configured maximum chunk plus a small rolling state. Package records are written incrementally to a destination stream.

The browser implementation prefers the File System Access API or OPFS for durable output. Memory Blob fallback is intentionally limited.

## Upload protocol

Upload state is server-owned but opaque. The server stores ciphertext only and binds each session to an authenticated owner. A resumable client may ask for an inventory and upload missing chunk blobs. Finalization is idempotent and verifies declared counts, sizes and package checksum.

## Recovery

Recovery and primary credential slots wrap the same content root. Credential rotation changes slots only; file ciphertext is not re-encrypted.
