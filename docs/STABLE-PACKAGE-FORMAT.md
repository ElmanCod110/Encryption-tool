# Stable Package Format Contract

Status: the SPKG writer/reader are integrated into the active API and storage path on this feature branch. This branch is not a release, target-host platform validation is still required, and this is not an independent security audit.

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
10. Do not ship V14 or V13 readers in the 1.0.0 active application. Release 0.14.1 is the final legacy-reader release; legacy packages must be explicitly exported/re-encrypted before upgrading.

## Metadata visibility and offline attack model

The stable format intentionally omits application release versions, format-generation labels, and schema-version fields, but it does not hide all metadata. The fixed header exposes the random package identifier, salt, bounded KDF parameters, algorithm identifiers, and whether a recovery slot is present. Each file-start record exposes a random file identifier and exact plaintext file size; record counts and total package length also reveal information about the package. The encrypted manifest protects filenames and the directory graph.

A copied package permits offline password-and-pattern guessing against the wrapped root key. Argon2id raises the cost per attempt but cannot prevent weak-credential guessing after an attacker obtains the package. Use a long, unique password and a separate non-reused pattern. Rate limiting in the application cannot stop offline attempts.

The format authenticates encrypted content to the key material, not the identity of the person who sent the package. Use a trusted transfer channel and verify any sender/publisher signature or checksum through an independently trusted channel when origin authenticity matters.

## KDF cost and deployment budget

The current writer profile uses Argon2id with 3 operations and 256 MiB; the parser accepts only the documented bounded range, up to 4 operations and 256 MiB. These parameters are checked before derivation, but the wrapped key cannot be authenticated until a credential-derived key has been tried. Consequently, a malformed or wrong-credential request can still consume the maximum permitted KDF cost.

Before production integration, benchmark wall-clock latency and peak process/container memory on the supported PHP versions and target Windows/XAMPP/shared-hosting environments. Test multiple concurrent failed unlocks against realistic memory limits. A profile that can exhaust the host is not acceptable merely because its parameters are cryptographically strong. Do not silently lower the KDF profile: any change must be reviewed against the binary contract, fixture, compatibility requirements and security goals.

## Implementation boundary

The candidate implementation consists of these separate classes:
- app/Project/StablePackageDescriptor.php
- app/Project/StablePackageCrypto.php
- app/Project/StablePackageWriter.php
- app/Project/StablePackageReader.php

They are the active writer/reader for SPKG on this branch. The active API creates and opens only SPKG files. Historical V14/V13 code may remain in repository history, but active application routes must not load it; legacy format support is retired in the 1.0.0 application.

## Required acceptance gates

Automated tests must include round-trip coverage for empty, binary, nested and multi-chunk files; credential and recovery flows; tamper/truncation/trailing-data rejection; strict header/KDF checks; manifest graph and path attacks; no-overwrite behavior; and cleanup on failure. Run the PHP matrix and a Windows test that actually writes and restores a stable package. Any manual/shared-hosting test not run must be marked NOT RUN.

A green round-trip test alone is insufficient. Before v1.0.0, review the byte-level specification, the full writer/reader diff, adversarial parser tests, platform filesystem behavior and final release artifact. Do not claim zero defects or an independent cryptographic audit.
