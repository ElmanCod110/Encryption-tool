# Secure Package V13 Format

V13 is the active browser-first, server-blind package format. Its purpose is to keep plaintext, credentials, decrypted filenames, and the package root key inside the browser while the server-side upload API handles opaque ciphertext chunks.

## Cryptographic profile

- KDF: PBKDF2-HMAC-SHA-256, exactly 1,500,000 iterations in the browser profile.
- Key separation: HKDF-SHA-256 with domain-separated information strings.
- Content encryption: AES-256-GCM.
- Ciphertext addressing/integrity: SHA-256(ciphertext).
- Package integrity: SHA-256 Merkle construction over authenticated chunk metadata + ciphertext.
- Recovery: independent 256-bit random recovery secret, wrapped into a separate authenticated key slot.
- Server plaintext exposure: false.

The PHP-native package engine remains a separate profile and uses libsodium's Argon2id-backed password hashing. V13 does not claim that the browser PBKDF2 profile and the PHP Argon2id profile are equivalent.

## Container layout

```text
SPK13BIN1\n
u32_be(header_json_length)
header_json

repeat encrypted chunk records:
  u32_be(metadata_json_length)
  metadata_json
  u32_be(ciphertext_length)
  ciphertext

encrypted_manifest
u32_be(encrypted_manifest_length)
SPK13FOOT
```

All lengths are bounded before allocation/read. The active implementation rejects packages above 4 GiB, headers above 2 MiB, manifests above 32 MiB, more than 100,000 files, or more than 1,000,000 chunks.

## Header authentication model

The primary slot wraps a 32-byte random package root using a credential-derived AES-256-GCM key. The slot AAD binds the wrap to:

```text
SecurePackage|V13|slot|primary|<package-id>
```

The recovery slot uses:

```text
SecurePackage|V13|slot|recovery|<package-id>
```

The manifest uses:

```text
SecurePackage|V13|manifest|13
```

## File records

Each encrypted chunk has exactly these metadata fields:

```json
{
  "id": "sha256(ciphertext)",
  "file_id": "128-bit identifier in hex",
  "index": 0,
  "plain_size": 0,
  "cipher_size": 16,
  "iv": "base64-encoded 96-bit IV"
}
```

For non-empty chunks, `plain_size` is between 1 MiB and 8 MiB. Empty files use one authenticated zero-byte chunk whose AES-GCM ciphertext is 16 bytes.

File AAD is:

```text
SecurePackage|V13|file|<file-id>|<chunk-index>
```

## Encrypted filenames

Each path component is encrypted separately. The component AAD is:

```text
SecurePackage|V13|name|<file-id>|<part-index>
```

Restore rejects traversal components, control characters, colon-containing components, Windows device names, trailing dot/space names, overlong path components, excessive path depth, and normalized case-insensitive collisions.

## Merkle construction

For every chunk, the leaf is:

```text
SHA256(
  "SecurePackage|V13|LEAF|" ||
  UTF8(canonical_chunk_metadata_json) ||
  ciphertext
)
```

Internal nodes are:

```text
SHA256("SecurePackage|V13|NODE|" || left || right)
```

For an odd node count, the final node at the level is paired with itself. Verification recomputes the leaf sequence and root before any restore output is created.

## Restore policy

V13 follows fail-closed restore semantics:

1. Parse and bound the container.
2. Authenticate credentials/key slot.
3. Decrypt and validate the manifest.
4. Read and validate the complete chunk inventory.
5. Recompute every ciphertext hash and the complete Merkle root.
6. Preflight all decrypted paths and destination conflicts.
7. Only then create output files.

Existing files are never silently overwritten.

## Compatibility

V13 is intentionally separate from V7–V12. Historical client implementations, endpoints, descriptors, tests, and signed release artifacts are retained under `archive/legacy/` and are not part of the active V13 browser surface.
