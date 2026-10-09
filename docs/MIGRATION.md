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
