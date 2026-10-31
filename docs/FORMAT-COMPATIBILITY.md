# Package Format Compatibility

This is the compatibility policy for the planned 1.0.0 release line.

## Active format

| Format | Extension | Writer/reader | 1.0.0 status |
| --- | --- | --- | --- |
| Unified stable binary package | `.spkg` | `StablePackageWriter` / `StablePackageReader` | Active for hosted PHP, local XAMPP, and standalone PHP CLI |

All three modes use the same byte-level grammar, extension, cryptographic profile, and PHP writer/reader. Local XAMPP keeps processing on the local machine when PHP, browser, and storage are local. The standalone CLI runs without a web server and never contacts a remote service. Hosted deployment performs package creation and restoration on the server.

The extension is only a filename convention. The reader checks the fixed binary magic and validates the authenticated grammar; it never chooses a parser from the extension alone.

## Retired formats

| Previous format | Extension | Last supported release | 1.0.0 behavior |
| --- | --- | --- | --- |
| Server V14 archive | `.spkg14` | `0.14.1` | Not parsed, decrypted, converted, or downloadable through the active application |
| Browser V13 | `.spk13` | `0.14.1` | Browser UI and API retired; the active UI does not load the V13 parser or worker |
| Undocumented development exports | V1–V12 labels | No compatibility promise | Unsupported |

Old catalog entries may be shown as unsupported and can be deleted by their owner. The active application does not open or automatically migrate them. It never retries a legacy parser after an SPKG password, authentication, or integrity failure.

## Upgrade procedure

Before upgrading from 0.14.1, use that release to open every legacy package you need to keep, restore/export the plaintext to a safe location, then create and verify a new SPKG package. Keep a backup of the 0.14.1 runtime and old package until the new package has been verified. Version 1.0.0 cannot recover legacy data for you.

## Security boundary

SPKG protects package bytes stored at rest. Hosted mode performs package creation and restoration on the server, so the server processes source plaintext and supplied credentials during those operations. This is not server-blind or end-to-end client encryption. Local XAMPP mode keeps that work local when the runtime and storage are local.
