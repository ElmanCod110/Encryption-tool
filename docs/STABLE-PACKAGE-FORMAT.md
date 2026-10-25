# Stable Package Format Contract

Status: design contract for the first stable release; implementation is not yet approved.

## Goal

The first stable release must establish one durable on-disk package format. Application releases may evolve, but ordinary application version bumps must not change the serialized package format or make existing packages unreadable.

This document defines requirements and release gates. It does not claim that the new format has already been implemented or audited.

## Non-negotiable serialized-format rules

The stable package MUST NOT serialize any of the following:

- Application release version (for example, a value derived from the root `VERSION` file).
- Format-generation/version labels such as `V14`, `SECURE-PKG-V14`, or equivalent generation names.
- A package schema-version number used only to distinguish successive application/package generations.
- Browser/application build versions, release tags, or version-dependent extensions.

These rules apply to every serialized layer: package preamble/header, encrypted or plaintext manifest, per-file records, footer/completion records, and any nested metadata written into the package. Tests must inspect the complete serialized representation, not only the top-level header.

A fixed, version-independent magic byte sequence may be used for file-type recognition if needed. It must remain constant and must not encode an application or format-generation version. The exact byte layout and magic value must be decided and reviewed before implementation.

Cryptographic algorithm identifiers and parameters that are required to interpret and verify the data are not application version numbers. They may be represented only when necessary, must be strictly allowlisted, and must not be used as a hidden substitute for a format-generation identifier.

## Security and correctness requirements

1. **Authenticated framing:** all security-relevant framing and metadata must be cryptographically authenticated. No unauthenticated metadata may influence filesystem paths, output names, algorithm selection, or resource allocation.
2. **Strict parsing:** reject unknown, duplicate, malformed, truncated, oversized, or out-of-order fields/records. Apply explicit limits before allocating or processing attacker-controlled sizes.
3. **Cryptographic separation:** use independent, domain-separated keys for metadata, filenames, and file content; bind each chunk to its intended file and sequence; verify final stream completion and integrity before treating a restore as successful.
4. **Credential handling:** preserve the existing reviewed password/pattern derivation and key-wrapping properties only after validating them against the final format design. Never silently weaken KDF parameters or accept caller-controlled unsafe resource settings.
5. **Safe output:** restore must not overwrite existing destinations by default, must defend against traversal, symlinks and path collisions, and must clean incomplete output on failure without deleting user data.
6. **Atomic package creation:** do not publish a package until every required record, final integrity check, and completion marker has been written and validated.
7. **No false success:** wrong credentials, tampering, truncation, missing final records, and unsupported cryptographic parameters must fail closed with generic external errors and useful internal diagnostics that do not leak secrets.
8. **Determinism is not required:** salts, nonces, package identifiers, and encrypted layouts must remain unpredictable where cryptographically required; two encryptions of the same input should not be expected to produce identical package bytes.

## Compatibility and migration

- The existing server `SECURE-PKG-V14` and browser `SECURE-BROWSER-V13` formats are legacy compatibility boundaries. Do not reinterpret or silently rewrite their bytes as the new stable format.
- Keep legacy readers isolated and explicitly tested. New packages must be emitted only in the stable format after its release gate passes.
- Decide and document whether old packages can be migrated by decrypting and re-encrypting, or remain readable only through legacy readers. Never promise transparent compatibility until tested.
- Do not remove a legacy reader or change existing package extensions as a side effect of unrelated security fixes.
- Application release versioning remains independent of the package serialization. Changing `VERSION`, UI text, or Git tags must not alter the bytes emitted by the stable package writer.

## Required test matrix before release

### Format contract
- Inspect every serialized layer and assert that no application version, format-generation label, or schema-version field is present.
- Verify the fixed file-type marker (if adopted) is identical across application releases and contains no version label.
- Test strict rejection of malformed lengths, duplicate/unknown fields, unsupported algorithms, reordered records, truncated input, and trailing garbage.
- Add fixtures created by the final stable writer and ensure a later compatible build reads them unchanged.

### Cryptographic integrity
- Successful round-trip for empty files, nested paths, binary files, large/chunked files, and supported boundary sizes.
- Wrong password, wrong pattern, wrong recovery key, altered header, altered manifest, altered filename metadata, altered blob/chunk, missing chunk, reordered chunk, and missing final marker must all fail.
- Verify no plaintext is accepted as a valid package and no partially restored tree is reported as success.
- Check that package identifiers and key material are generated safely and that temporary secrets are cleared on all reachable paths where the runtime supports it.

### Filesystem and failure injection
- Existing restore destination remains byte-for-byte unchanged.
- Traversal paths, absolute paths, symlinks, duplicate/case-colliding paths, and reserved platform names are rejected safely.
- Inject failures during staging, writing, finalization, catalog update, cleanup, and rollback; preserve source data and avoid leaving a package that appears complete when it is not.
- Test cleanup failure explicitly and ensure it is surfaced instead of silently ignored.

### Compatibility and platforms
- Run server stable-format tests on supported PHP versions and Windows.
- Run browser compatibility tests separately; do not assume browser V13 and server V14 are the same format.
- Test shared-hosting constraints, filesystem semantics, ZIP extension behavior, and atomic no-overwrite behavior on actual supported environments.
- Keep unexecuted manual checks marked NOT RUN.

## Implementation sequence

1. Freeze this contract and agree on the byte-level format design before editing the writer.
2. Add a byte-level format specification and test fixtures.
3. Implement a new stable writer and reader behind explicit internal interfaces; avoid broad rewrites of the existing V14 implementation.
4. Add adversarial tests before switching any default writer.
5. Add migration/legacy compatibility tests and verify that old package fixtures remain readable through their designated readers.
6. Run the full security suite, PHP matrix, browser tests, Windows smoke tests, and failure-injection tests.
7. Review the complete diff and release artifact; publish only after all required checks pass.

## Release-blocking rule

A passing CI run alone does not authorize the stable-format release. The final candidate must pass the matrix above, and any unrun manual or platform-specific test must be explicitly disclosed. Do not claim an independent security audit unless one has actually occurred.
