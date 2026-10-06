# SECURE-PKG-V3 Format

`SECURE-PKG-V3` is the portable package format used by Secure Package.

## Container

A portable package is a ZIP container with the `.spkg` extension.

The internal layout is intentionally small and opaque:

```text
header.json
manifest.enc
blobs/<48-hex-character-id>.bin
```

No original filename or directory path is required to appear in plaintext.

## Header

`header.json` contains only package-format information needed to locate and interpret the encrypted package, including:

- Format identifier
- Format version
- Random package identifier
- Argon2id configuration identifier and fixed supported parameters
- Payload algorithm identifiers
- Package salt

The portable header never contains the password or pattern.

KDF parameters are validated against the implementation's approved V3 values. A modified package cannot request an arbitrary memory or time cost from the decryptor.

## Manifest

`manifest.enc` is an authenticated encrypted record.

Its plaintext structure contains:

```text
format
version
schema
node_count
nodes[]
```

Each node contains a random node identifier, parent relationship, node type, and encrypted name. File nodes additionally contain a random blob identifier and the original plaintext size required to remove encryption padding after authenticated decryption.

The manifest is never trusted before successful authenticated decryption and schema validation.

## Blob encryption

Every file has its own derived file key.

The file key is derived from the package file-root key and the random manifest node identifier.

Large file content is encrypted using XChaCha20-Poly1305 SecretStream. The encrypted file contains its stream header followed by length-prefixed authenticated chunks.

## Associated data

Cryptographic operations use purpose-bound associated data such as:

```text
manifest|3
name|<node-id>
file|<node-id>|v3
```

This prevents ciphertext created for one logical purpose from being silently accepted in another context.

## Randomness

Package identifiers, node identifiers, blob identifiers, salts, nonces, and temporary names use cryptographically secure random generation.

Re-encrypting identical plaintext with identical credentials therefore does not intentionally produce the same package contents.

## Compatibility

A V3 reader must reject unsupported versions instead of attempting heuristic decryption.

Future versions should use an explicitly versioned format identifier and should not silently reinterpret V3 data.
