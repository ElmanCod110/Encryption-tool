# Contributing

Thank you for helping improve Secure Package. Changes to cryptographic code, parsing, archive extraction, authentication, filesystem handling, and release integrity require careful review.

## Before opening a change

1. Search existing issues and pull requests to avoid duplicates.
2. For substantial changes, open an issue first to discuss behavior and compatibility impact.
3. Keep changes focused and separate unrelated refactors, UI work, and security changes.
4. Never include credentials, recovery keys, generated package contents, private release keys, environment files, or runtime storage.
5. Do not change serialized package formats, magic values, extensions, or compatibility behavior as part of unrelated cleanup.

## Development environment

- PHP 8.2 or later.
- PHP Sodium and Zip extensions.
- Node.js for browser JavaScript syntax and compatibility tests.
- Composer for dependency installation and auditing.

Install dependencies from the committed lockfile when available:

```bash
composer install --no-interaction --prefer-dist --no-progress
```

## Checks to run

```bash
composer validate --strict --no-check-publish
composer audit --no-interaction
php bin/self-check.php
php bin/source-audit.php
php bin/security-test.php --full
find app bin public tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l
find public/client -type f -name '*.js' -print0 | xargs -0 -n1 node --check
node tests/BrowserV13RoundTripTest.mjs
```

Do not claim a command passed unless it was executed successfully. If an extension or dependency is missing, state the limitation.

## Pull request expectations

- Explain the problem and proposed solution.
- Link related issues.
- Include tests for changed behavior.
- Describe compatibility impact and migration requirements.
- Update documentation when user-visible behavior changes.
- Keep comments factual and actionable; do not add comments solely to increase activity counts.
- Never weaken a test merely to make CI pass.

## Versioning

The root `VERSION` file is the application release version source. Server and browser package-format identifiers are separate compatibility contracts; see [VERSIONING.md](VERSIONING.md).

For sensitive vulnerability details, follow [SECURITY.md](SECURITY.md) instead of posting them publicly.
