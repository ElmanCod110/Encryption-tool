# Secure Browser Package V7 Format

V7 uses an opaque binary container.

```text
MAGIC(8)
HEADER_LENGTH(4, big-endian)
HEADER(JSON)
MANIFEST_LENGTH(4, big-endian)
MANIFEST_CIPHERTEXT
REPEATED RECORDS:
  METADATA_LENGTH(4)
  METADATA(JSON)
  CIPHERTEXT_LENGTH(4)
  CIPHERTEXT
```

Magic: `SPK7BIN1`.

The plaintext header contains transport values only: version, package ID, salt, pinned KDF work factor, chunk size, manifest IV and record count.

The encrypted manifest contains the logical directory tree, encrypted path components, chunk references, plaintext sizes and the SHA-256 Merkle root.

Every chunk uses a fresh 96-bit AES-GCM IV. Additional authenticated data binds the package, file and chunk position.

The Merkle leaf is:

```text
SHA-256(JSON(record_metadata) || ciphertext)
```

An odd tree level duplicates its final node. The root is authenticated by the encrypted manifest.
