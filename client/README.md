# Client-Side Decryption Adapter

The package format is intentionally designed so a future browser-only decryptor can consume an opaque package without changing the encrypted data model.

A production browser decryptor should use an audited WebAssembly binding for the same sodium primitives used by the PHP implementation. The repository does not ship a hand-written browser cipher or a substitute algorithm.

Required browser primitives:

- Argon2id
- XChaCha20-Poly1305
- XChaCha20-Poly1305 SecretStream
- Streaming file handling

The server API can provide opaque package bytes without exposing plaintext. A browser adapter can then derive keys locally and rebuild the manifest and files locally.
