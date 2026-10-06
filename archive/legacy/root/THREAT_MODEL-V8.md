# V8 Threat Model

## Protected secrets

- File contents
- Original relative paths
- Password
- Pattern
- Plaintext manifest

## Remote server assumption

The server is treated as untrusted with respect to plaintext V8 data. It may store, transport, delete, or observe ciphertext and package-level operational metadata.

## Defended attacks

- Ciphertext modification
- Chunk replacement
- Chunk duplication
- Chunk deletion
- Chunk reordering through manifest binding
- Manifest tampering
- Path traversal during restore
- Upload ownership confusion
- Cross-session upload injection
- Duplicate content-address identifiers
- Truncated package records

## Remaining trust assumptions

A browser cannot protect against a compromised JavaScript delivery origin that changes the crypto code before credentials are entered. V8 therefore separates cryptographic processing from the server API, but it does not claim immunity from a compromised client environment.
