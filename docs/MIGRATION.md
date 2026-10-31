# Migration to the unified SPKG format

## Release compatibility rule

Release 0.14.1 is the final release intended to open the previous formats:

- Server V14 packages (`.spkg14` ZIP transport and directory-backed storage).
- Browser V13 packages (`.spk13`).

The planned 1.0.0 application creates and opens only the unified stable binary `.spkg` format. It does not read, decrypt, convert, or automatically migrate V13/V14 or undocumented older development exports. It will not try a legacy parser after a wrong password, malformed header, or authentication failure.

## Before upgrading

1. Keep a working copy of release 0.14.1 and its required runtime dependencies.
2. Open every old package that must be retained using the matching 0.14.1 reader.
3. Restore/export the plaintext to a safe location under your control.
4. Upgrade to the new application and create a new .spkg package.
5. Verify that the new package opens successfully before deleting your exported plaintext or old package backup.

Do not rely on the new release to recover old files. Existing legacy files may remain on disk after upgrade; the 1.0.0 application marks their catalog entries unsupported and does not issue download links. Owners can delete those entries, which permanently removes the legacy artifacts if present.

## Unified package behavior

The hosted web deployment and local XAMPP deployment share the same .spkg grammar, PHP writer/reader, extension, and cryptographic profile. Hosted mode processes source plaintext and credentials on the server; local mode keeps that work local when the runtime and storage are local. Hosted mode is not client-side end-to-end encryption.

See [FORMAT-COMPATIBILITY.md](FORMAT-COMPATIBILITY.md), [STABLE-PACKAGE-FORMAT-BINARY.md](STABLE-PACKAGE-FORMAT-BINARY.md), and [THREAT-MODEL.md](THREAT-MODEL.md).
