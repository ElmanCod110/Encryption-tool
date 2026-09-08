# V13 Migration Guide

V13 is the final consolidated release.

## From V12

Existing V12 packages must be opened through the compatibility path documented
by the application. Do not rewrite or re-encrypt an existing package merely
for migration unless the application explicitly requests it.

## From V10/V11

Use the corresponding legacy package reader before performing any optional
repackaging into the current format.

## Credential Changes

Credential rotation changes the wrapping layer where supported. It does not
require re-encrypting content ciphertext.

## Recovery

Recovery material is independent of the primary password/pattern and must be
stored offline by the owner.

## Backup

Always preserve an encrypted package backup before destructive migration or
credential rotation.
