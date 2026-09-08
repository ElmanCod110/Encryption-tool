# TCH-PKG-V2 Format

## Container

A portable `.tchpkg` file is a ZIP container holding:

```text
header.json
manifest.enc
blobs/<random-48-hex>.bin
```

`record.json` is never included in the portable container.

## Header

`header.json` contains public format parameters and a random per-package salt. It does not contain the password, pattern, filenames, paths, or file contents.

## Manifest

The manifest contains the complete directory tree. It is encrypted and authenticated with a manifest-specific key.

Each node contains a random ID, parent reference, node type, encrypted name, and for files an encrypted blob identifier and authenticated plaintext size.

## File blobs

Each blob uses a file-specific key derived from the master key and node ID. SecretStream is used for streaming authentication. Plaintext is padded to 1 MiB boundaries before encryption.

## Key separation

The master key is never used directly for package data. Separate subkeys are derived for:

- Manifest encryption.
- Filename encryption.
- File encryption root.
- Individual file encryption.

## Failure behavior

Manifest authentication failure, filename authentication failure, file authentication failure, malformed metadata, and invalid credentials are intentionally mapped to generic package-open failures at the web layer.
