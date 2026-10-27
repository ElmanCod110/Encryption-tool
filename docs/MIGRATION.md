# V13 → V14 Migration

## Compatibility rule

V13 browser packages (`.spk13`) are a separate compatibility boundary. V14 server packages use `.spkg14` and `SECURE-PKG-V14`.

Do not reinterpret an existing V13 package as a V14 package. Keep the V13 browser client available for existing users during the migration window.

## New V14 key model

V14 does not derive the long-lived file encryption keys directly from the user password and pattern. It creates a random package root key and wraps it in an authenticated primary key slot derived from the user credentials.

An optional independent recovery key can wrap the same root key in a separate slot.

## Operational migration

1. Keep V13 browser tooling available.
2. Create new server packages using V14.
3. Preserve existing V13 packages as legacy input until a dedicated migration reader/export path is intentionally approved.
4. Store V14 recovery keys independently from the package.
5. Before a production V14 release, commit a real `composer.lock` and run the release security gate.

## No implicit conversion

There is intentionally no automatic V13-to-V14 conversion inside the V14 reader. Format migration must be an explicit, testable workflow so a parser never guesses the intended security profile.

## Stable single-file format and v1.0.0 compatibility policy

The planned stable binary format is a separate, version-independent format. Its writer/reader candidate is still isolated for review and is not the active/default server writer yet.

The compatibility policy is **read old formats explicitly; do not silently convert or reinterpret them**:

- Keep the V14 server reader for existing `.spkg14` packages during the supported migration window.
- Keep the browser V13 reader as a separate boundary for existing `.spk13` packages.
- Add the stable-format reader as a separate parser selected only by the stable format's exact fixed marker. Never try another parser as an automatic fallback after a parse/authentication failure.
- Keep new stable-format writing behind its own reviewed integration gate. Changing `VERSION` must not rewrite any package or change how old package bytes are interpreted.

A dedicated in-place converter is **not currently available**. It is not required merely to keep old packages readable because the legacy readers remain separate. If/when a conversion tool is added, it must restore the source package to a private temporary location, verify the restored files, write a new stable package to a distinct no-overwrite destination, verify the new package by restoring it to a second temporary location, and only then report success. It must preserve the original package and clean only temporary paths it can prove it owns. Never convert by changing a version field or overwriting the original package.

Until stable-format integration and compatibility tests are approved, do not promise that v1.0.0 can create or migrate to the stable format in the production UI/CLI.
