# Stable Package Format Contract

Status: the stable binary writer/reader and server API integration are implemented on the integration branch, and automated PHP 8.2/8.3 plus Windows checks are being used as release gates. This is not yet a v1.0.0 release or an independent security audit; real shared-hosting validation remains NOT RUN.

## Goal

The v1.0.0 release must establish one durable on-disk format. Changing application release versions must never change the package byte grammar or make compatible old packages unreadable.

## Non-negotiable serialized-format rules

The stable package MUST NOT serialize:
- an application release version;
- a format-generation label such as V14 or SECURE-PKG-V14;
- a schema-version field used to distinguish package/application generations;
- browser/application build versions, release tags, or version-dependent extensions.

The rules apply to every byte written to the package, including the header, record envelopes, file-start and chunk records, and encrypted manifest. See the normative byte-level specification in STABLE-PACKAGE-FORMAT-BINARY.md for fixed field offsets, grammar, key domains, limits and acceptance rules.

A fixed opaque magic byte sequence may identify the file type if it remains constant and contains no version. Algorithm identifiers may describe the cryptographic algorithms required to decode the bytes, but they are allowlisted and must not serve as hidden generation identifiers.

## Security and correctness requirements

1. Authenticate the fixed header and all security-relevant framing before trusting it.
2. Reject unknown types, bad/reserved flags, malformed/truncated/oversized records, incorrect order and trailing bytes.
3. Use independent domain-separated keys for key wrapping, header authentication, manifest and each file stream.
4. Bind every chunk to the package core, intended file, sequence and declared file size.
5. Bound KDF cost, sizes, entry counts, depth and memory allocation before expensive work.
6. Validate the complete encrypted manifest, parent graph, canonical path order and all stream/manifest cross-references before creating the requested restore destination.
7. Never overwrite a pre-existing output. Fail closed if an atomic no-replace filesystem operation is unavailable.
8. Clean incomplete output only when ownership of the created paths can be established; surface cleanup failures.
9. Zeroize key material where the runtime supports it and never expose credentials or plaintext in diagnostics.
10. Preserve V14 server and browser V13 compatibility independently. Do not silently reinterpret or rewrite existing packages.

## Implementation boundary

The candidate implementation consists of these separate classes:
- app/Project/StablePackageDescriptor.php
- app/Project/StablePackageCrypto.php
- app/Project/StablePackageWriter.php
- app/Project/StablePackageReader.php

They are intentionally separate from the V14 builder/reader. This branch adds regression tests and CI coverage, but it must not change the production/default writer or route application endpoints to this format before review and platform validation. Legacy compatibility tests must continue to pass.

## Required acceptance gates

Automated tests must include round-trip coverage for empty, binary, nested and multi-chunk files; credential and recovery flows; tamper/truncation/trailing-data rejection; strict header/KDF checks; manifest graph and path attacks; no-overwrite behavior; and cleanup on failure. Run the PHP matrix and a Windows test that actually writes and restores a stable package. Any manual/shared-hosting test not run must be marked NOT RUN.

A green round-trip test alone is insufficient. Before v1.0.0, review the byte-level specification, the full writer/reader/service/controller diff, adversarial parser tests, Windows and real shared-hosting filesystem behavior, and the final release artifact. Do not claim zero defects or an independent cryptographic audit.
