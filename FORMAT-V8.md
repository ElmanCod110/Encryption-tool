# Secure Package V8 Format

V8 is a browser-first encrypted package format. Plaintext files, plaintext path components, passwords, and patterns are processed locally and are not part of the remote upload protocol.

## Cryptographic profile

- KDF: PBKDF2-HMAC-SHA-256 with a fixed V8 iteration count of 1,200,000.
- Key separation: HKDF-SHA-256.
- Encryption: AES-256-GCM.
- Chunk size: 4 MiB.
- Chunk identifier: SHA-256 of `SECURE-BROWSER-V8|CHUNK|` concatenated with ciphertext.
- Integrity: SHA-256 Merkle tree over canonical chunk metadata plus ciphertext.

## Container

```text
SPK8BIN1
u32(header_length)
header_json
u32(encrypted_manifest_length)
encrypted_manifest
repeat:
  u32(metadata_length)
  metadata_json
  u32(ciphertext_length)
  ciphertext
```

The header and manifest do not contain plaintext paths. Path components are individually encrypted with authenticated additional data.

## Server-blind upload

The optional V8 upload API receives only:

- encrypted chunk bytes
- ciphertext chunk identifiers
- encrypted header
- encrypted manifest
- Merkle root

The API does not receive the password or pattern.

The server therefore cannot decrypt a V8 package using the upload protocol alone.

## Important boundary

Browser-first encryption is not automatically a complete zero-knowledge guarantee. A compromised origin that can replace the JavaScript served to a user could alter client-side behavior. Deployments requiring this trust boundary should use TLS, strict CSP, immutable/signed releases, asset integrity, dependency pinning, and preferably a separately reviewed static client distribution.
