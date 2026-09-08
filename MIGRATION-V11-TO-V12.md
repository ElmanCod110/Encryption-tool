# Migration: V11 to V12

V12 is a security-hardening generation with a new browser descriptor and new resumable-upload inventory implementation.

## Package compatibility

V11 `.spk11` packages are not silently treated as V12 packages. Use the V11 reader for historical packages.

V12 browser packages use:

```text
SECURE-BROWSER-V12
SPK12BIN1
.spk12
```

## Server storage

V12 resumable uploads use marker files under the upload-inventory directory rather than a growing JSONL scan. Existing V11 upload sessions are not automatically migrated.

## Security checks

Before production deployment, run:

```bash
php bin/security-test.php
php bin/source-audit.php
php tests/ReleaseIntegrityTest.php
php bin/verify-release.php .
```

## Release keys

Release signing keys are external to the repository. Never copy the private signing key into the project tree or package archive.
