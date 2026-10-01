# SECURE-PKG-V14 Format

## Overview

V14 is a directory-backed encrypted package format designed to be transported as a `.spkg14` ZIP archive.

Package root:

```text
header.json
manifest.enc
complete.json
blobs/
  <48-hex>.bin
```

## Header

`header.json` contains:

- format/version/schema
- random package identifier
- creation timestamp
- 32-byte salt
- explicit cryptographic profile
- SHA-256 header binding
- primary credential key slot
- optional recovery key slot

The binding is computed over the canonical header core and is included as associated data for wrapped keys and authenticated package records.

## Credential wrapping

The password and pattern each use Argon2id13 with a distinct purpose-derived salt. Their derived 256-bit values are combined through HKDF-SHA-256 into the credential wrapping key.

The wrapping key opens the primary slot, which contains the random package root key.

A recovery slot can independently wrap the same package root key using a random 256-bit recovery key.

## Subkeys

HKDF derives separate subkeys for:

- manifest encryption
- encrypted filenames
- the file-key root
- individual file keys

This prevents unrelated uses from sharing the same raw encryption key.

## Manifest

The authenticated plaintext manifest records a parent/child path graph. Filenames are encrypted. File nodes record the file identifier, blob name, plaintext size, ciphertext SHA-256 hash, and the package Merkle root.

## File stream

Each file is encrypted through libsodium secretstream. The package stores a small stream magic/header followed by length-delimited authenticated ciphertext records. Associated data binds each chunk to the package, header binding, file identifier, chunk index, and expected file size.

## Restore ordering

The reader performs all package, manifest, blob, hash, Merkle, and path preflight checks before writing. Directories are created in depth order, followed by file restoration into temporary files. Existing destination directories and existing child paths are rejected.

## Limits

The V14 descriptor defines maximum header size, manifest size, node count, file size, package plaintext size, blob count, and path depth. The outer `.spkg14` ZIP transport allows the V14 plaintext ceiling plus bounded authentication/format overhead. These are parser and resource-safety boundaries, not encryption parameters.
