# Secure Package Format V6

## Identity

```text
Format: SECURE-PKG-V6
Version: 5
Extension: .spkg
Author: ElmanCod110
```

## Package components

```text
header.json
manifest.enc
blobs/
```

Only a fixed allow-list of top-level entries is accepted.

## Header

The header contains non-secret format parameters required to interpret the package, including the package identifier, KDF algorithm/parameters, payload algorithms, and public salt.

Password, pattern, filenames, directory names, and plaintext content are not stored in the header.

## Manifest

The manifest is authenticated encrypted data. It contains the logical directory tree and encrypted filenames.

For files it also references:

- node identifier
- parent identifier
- encrypted filename
- randomized blob identifier
- original plaintext size

## Blob policy

Every blob must use the package's expected random-name format. The verifier compares the physical blob inventory against manifest references so unreferenced or missing blobs are rejected.

## KDF policy

V6 pins its supported KDF parameters. Package-controlled values are not allowed to arbitrarily increase or decrease the configured Argon2id workload.

## Evolution

Future versions must use a new package version and explicit compatibility rules rather than silently changing the interpretation of existing packages.
