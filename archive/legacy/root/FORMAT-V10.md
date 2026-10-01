# Secure Package V10 Format

**Format:** `SECURE-BROWSER-V10`

**Container magic:** `SPK10BIN1`

**Extension:** `.spk10`

## Key hierarchy

```text
Password ──> password KDF ──┐
                            ├──> credential wrap key ──> primary slot
Pattern  ──> pattern KDF ──┘

Random content root key ──> HKDF domains
                         ├── manifest key
                         ├── filename key
                         ├── file key domains
                         └── nonce key domain

Optional recovery secret ──> recovery KDF ──> recovery slot
```

The encrypted content root key is the cryptographic pivot of the package. File ciphertext is derived from this root, not directly from the human credentials.

## Credential rotation

Credential rotation rewrites only the primary key slot. Existing file ciphertext and the encrypted manifest remain unchanged.

## Chunking

V10 uses content-defined chunking with the following bounds:

- minimum: 1 MiB
- target: 4 MiB
- maximum: 8 MiB

The boundary function is deterministic for the same plaintext stream.

## Encryption

Each file chunk is encrypted independently with AES-256-GCM using an HKDF-derived file key domain and a deterministic HMAC-derived 96-bit nonce context. A unique package/file/chunk context is included in AAD.

## Integrity

Each encrypted chunk receives a SHA-256 content address. A SHA-256 Merkle tree commits to the encrypted chunk inventory. The manifest records the root.

## Privacy

The V10 browser workflow keeps credentials, plaintext content, and original logical paths client-side. The server-side API can store ciphertext and package metadata without deriving the browser content key.

Package size, timing, transport metadata, and browser compromise remain outside this privacy guarantee.
