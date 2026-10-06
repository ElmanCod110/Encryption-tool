# V14 Validation Record

Date: 2026-10-01

## Passed

- 103 active PHP files passed `php -l`.
- Active JavaScript files passed `node --check`.
- `php bin/self-check.php` passed required PHP/Sodium/randomness/Argon2id checks.
- `php bin/security-test.php` passed all fast security tests.
- `php bin/source-audit.php` passed.
- V14 package round-trip passed.
- V14 recovery restore passed.
- V14 header binding and strict schema tests passed.
- V14 header/completion tamper tests passed.
- V14 blob tamper and pre-write integrity tests passed.
- V14 restore-safety and non-overwrite tests passed.
- Replay race, upload checksum, signed state, authorization and existing security regression tests passed.

## Environment limitations

- The current validation sandbox does not have the PHP Zip extension, so `tests/V14PackageArchiveTest.php` reports a skip. GitHub CI enables `zip` through `shivammathur/setup-php`.
- Composer is not installed in the current sandbox, so `composer validate` and `composer audit` were not executed locally.
- No synthetic `composer.lock` was generated. Release CI deliberately requires a real committed lockfile.
- The development tree is unsigned, so release-integrity tests that require an actual Ed25519 release artifact remain skipped until a real signing key is supplied through the documented release procedure.

## Security position

V14 is a high-assurance security-engineering baseline, not a percentage security claim or certification. Residual risk remains in deployment configuration, endpoint/host compromise, credential loss, dependency supply-chain compromise, browser-side V13 compatibility components, and the absence of an independent third-party audit.
