# Package Format Compatibility

This document is the compatibility map for package files. These formats are deliberately separate cryptographic protocols; a reader must never guess another parser after authentication fails.

## Supported server-side formats

| Format | File/container | Reader | Compatibility status |
|---|---|---|---|
| Stable single-file binary | Fixed eight-byte magic `D3 82 A1 4F C7 5E 90 6B`; recommended extension `.spkg` | `StablePackageReader` | Implemented on the stable-format candidate branch; not yet the production/default writer or API format |
| Legacy server V14 | `.spkg14` ZIP transport containing `header.json`, `manifest.enc`, `complete.json`, and `blobs/`; the extracted directory form is also understood | `PackageArchive` + `V14PackageReader` | Existing server restore path remains enabled |

The `.spkg` extension is a filename convention, not an input requirement. The stable reader identifies the binary format by its fixed magic and validates the complete authenticated grammar. Renaming a valid file must not change its bytes or compatibility.

V14 compatibility includes the original package cryptography and serialized fields. The V14 reader now validates only the frozen credential byte contract (non-empty, valid UTF-8, no NUL, at most 4096 bytes) before using the V14 KDF. It does not apply today's password-strength or pattern-strength creation policy to old packages. New V14 package creation continues to use the current, stricter application policy. The regression test re-wraps a valid V14 root key using previously acceptable short credentials and proves that the V14 reader can restore it.

## Supported browser format

| Format | File/container | Reader | Compatibility status |
|---|---|---|---|
| Browser V13 | `.spk13`, container magic `SPK13BIN1` and footer `SPK13FOOT` | `public/client/v13/vault-v13.js` + `worker.js` | Existing browser-local reader remains available and is tested independently |

Browser V13 uses its own PBKDF2-HMAC-SHA-256 / AES-256-GCM profile and its own chunk and manifest grammar. It is not a V14 package and is not a stable binary package. The browser vault must continue to reject a `.spkg14` input with an explicit format-boundary message instead of attempting a different decryptor.

## Compatibility and migration rules

1. A stable binary package is read only by the stable binary reader; a V14 package is read by the V14 reader; a Browser V13 package is read by the Browser V13 client.
2. Do not route files by extension alone. Validate the relevant magic/container structure, then invoke exactly one format-specific parser.
3. Do not retry another parser after an authentication, credential, or integrity failure. This avoids downgrade ambiguity and format-confusion behavior.
4. Reading a legacy package does not rewrite or migrate it. Restored plaintext may be packaged into the stable format as a separate, explicit user operation after the stable format is approved for production.
5. The stable binary reader/writer are still isolated from the production API writer. The server currently creates V14 packages; changing the default requires a separately reviewed storage/catalog/download integration and completion of the platform and adversarial release gates.
6. V1–V12 were historical development-generation labels in the repository's version history; they are not evidence of additional currently supported serialized package formats. No compatibility claim is made for undocumented exports from those generations.

## Release validation

The automated compatibility checks include stable-format golden-fixture restore, stable writer/reader round trips and tamper rejection, V14 server round trips and restore safety, and Browser V13 round trips. Passing CI does not replace Windows/XAMPP and supported-browser manual checks or an independent review of the stable format.
