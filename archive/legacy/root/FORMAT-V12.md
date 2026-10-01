# Secure Package V12 Format

Secure Package V12 is a browser-first, server-blind encrypted package format.

## Design goals

V12 is designed to keep plaintext, passwords, patterns, and decrypted filesystem paths in the browser while the server stores and transports opaque ciphertext records.

## Container

```text
SECURE-BROWSER-V12
SPK12BIN1
*.spk12
```

The binary container contains a JSON header, encrypted chunk records, an encrypted manifest, and a footer marker.

## Cryptography

- Credential derivation: Argon2id-backed independent password and pattern domains in the browser worker.
- Key separation: HKDF-SHA-256.
- Content encryption: AES-256-GCM.
- Chunk digest: SHA-256 of ciphertext.
- Package integrity: SHA-256 Merkle root over authenticated chunk records.
- Nonce domain separation: package, file, purpose, and chunk context.

V12 does not introduce a proprietary cipher.

## Chunking

Content-defined chunking is used with the following limits:

- Minimum: 1 MiB
- Target: 4 MiB
- Maximum: 8 MiB

The browser processes the active chunk instead of loading the complete source tree into memory.

## Manifest

The manifest is encrypted and authenticated. It contains the logical file inventory, encrypted path parts, chunk references, sizes, and Merkle root.

No original path is required to remain in plaintext inside the package.

## Server boundary

For V12 browser-built packages, the server API receives only:

- package identifier
- upload session metadata
- ciphertext chunk bytes
- ciphertext chunk identifiers
- operational state

Passwords, patterns, and plaintext file data are not sent by the V12 browser workflow.

## Resumable transport

The upload inventory uses one marker per received ciphertext chunk. This avoids scanning a potentially huge append-only list for every resume operation.

A chunk is accepted only if:

```text
SHA-256(ciphertext) == declared chunk ID
```

The upload is finalized only when the declared ciphertext count and byte total are both satisfied.

## Build-state protection

V12 includes an encrypted build-state envelope for crash-recovery metadata. Sensitive key material is never permitted in the state schema.

## Compatibility

V12 is a new package format. Previous package generations remain separate and are not silently interpreted as V12.
