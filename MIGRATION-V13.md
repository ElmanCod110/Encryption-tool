# V13 Migration Guide

V13 is the current browser-vault format. Legacy browser/API generations are preserved under `archive/legacy/` and are not exposed by the active web surface.

## From V12

Existing V12 packages are legacy data. Keep a verified backup and use the archived V12 implementation only in an isolated migration environment. Re-encrypt into V13 only after successful offline verification of the original package.

## From V10/V11 and earlier

Use the corresponding archived reader in an isolated environment before optional re-encryption into V13. Do not mix historical readers with the active V13 web root.

## Credential changes

V13 uses a new package root and wrapping profile. Credential rotation should produce a new package or a separately defined authenticated key-rotation operation; do not edit package metadata manually.

## Recovery

The V13 recovery secret is independent of the primary password/pattern and should be stored offline. Treat it as a high-value secret.

## Backup

Preserve the original encrypted package before destructive migration. Verify the new V13 package by restoring it into a fresh directory before deleting any legacy copy.
