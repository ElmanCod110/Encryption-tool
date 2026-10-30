# Secure Package

**Author:** ElmanCod110

Secure Package is an open-source encrypted project-package engine focused on authenticated binary records, bounded parsing, safe restore, explicit deployment trust boundaries, and recovery.

## Unified SPKG package format

The planned 1.0.0 release line uses one stable binary format: `.spkg`. The hosted web application, local XAMPP deployment, and standalone PHP CLI use the same format, extension, writer/reader, and cryptographic profile. There is no separate local format or parser.

SPKG uses:

- Argon2id13 through PHP Sodium for password/pattern credential derivation.
- A random 256-bit package root key, independently wrapped by primary credentials and optionally by a recovery key.
- XChaCha20-Poly1305 for authenticated key wrapping.
- `secretstream_xchacha20poly1305` for authenticated file streaming.
- HKDF-SHA-256 for key separation.
- An authenticated fixed binary header and encrypted manifest.
- Strict record lengths, ordering, file-size limits, manifest graph/path validation, and trailing-byte rejection.
- Private staging and no-overwrite restore behavior.

The password and pattern derive wrapping material; they are not used directly as the long-lived file-encryption key.

## Deployment and privacy boundary

- **Hosted deployment:** package creation and restoration are server-side operations. The server processes source plaintext and the supplied credentials while the request is running. This is not server-blind or end-to-end client encryption.
- **Local XAMPP deployment:** processing stays on the local machine when Apache/PHP, browser, and storage are all local.

Do not advertise hosted mode as zero-knowledge or client-side encryption.

## Legacy compatibility policy

Release `0.14.1` is the last release intended to open the previous server V14 (`.spkg14`) and browser V13 (`.spk13`) formats. The planned 1.0.0 application does not open, decrypt, convert, or automatically migrate them. Before upgrading, use 0.14.1 to restore/export any legacy data you need, create a new SPKG package, and verify that it opens.

See [format compatibility](docs/FORMAT-COMPATIBILITY.md) and [migration notes](docs/MIGRATION.md).

## Runtime requirements

- PHP 8.2 or later, 64-bit runtime.
- PHP Sodium extension.
- PHP Zip extension for ZIP upload and restore workflows.
- A modern browser.
- PDO MySQL is optional unless a deployment enables MySQL-backed integration.

## Local run

Point Apache/XAMPP at the `public/` directory and open the application entry point. For a local-only setup, keep the runtime and storage on the local machine.

The standalone CLI tools use hidden interactive credential prompts and refuse to overwrite existing package or restore destinations. See the standalone local CLI section below for exact commands.

## Standalone local CLI

A web server is not required to create or restore a package locally:

- Create: `php bin/create-package.php <source-directory> <destination.spkg>`
- Restore: `php bin/decrypt-package.php <package.spkg> <output-directory>`
- Restore with the independent recovery key: append `--recovery`.

The CLI prompts for credentials without terminal echo. For automation, use the `SPK_PASSWORD` and `SPK_PATTERN` process environment variables, or `SPK_RECOVERY_KEY` in recovery mode. Do not pass secrets as command-line arguments. These tools use the same SPKG bytes and cryptographic implementation as the hosted and localhost paths.

## Production security baseline

Set deployment-appropriate values:

```text
SPK_REQUIRE_HTTPS=1
SPK_PUBLIC_ORIGIN=https://your-host.example
SPK_NAME_PEPPER=<long-random-server-secret>
```

Keep `storage/`, configuration, environment secrets, and release signing keys outside the public web root. Do not deploy an embedded release public key as the only trust root for high-assurance release verification.

## Testing and release gates

```bash
php bin/self-check.php
php bin/source-audit.php
php bin/security-test.php --full
find public/assets -type f -name '*.js' -print0 | xargs -0 -n1 node --check
node tests/LegacyBrowserRetirementTest.mjs
composer validate --strict --no-check-publish
composer audit --no-interaction
```

A real root `composer.lock` is required for reproducible dependency installation and the release gate intentionally blocks release while it is missing. Follow the [release QA matrix](docs/RELEASE-QA.md); manual Windows/XAMPP, shared-hosting, and browser checks must remain NOT RUN until actually performed.

## Security philosophy

Cryptography, parsing, filesystem handling, authentication, resource limits, and supply-chain integrity are one security boundary. Automated tests are not an independent cryptographic audit or proof of production readiness.

## Documentation

- [Versioning policy](VERSIONING.md)
- [Format specification](docs/FORMAT.md)
- [Binary layout](docs/STABLE-PACKAGE-FORMAT-BINARY.md)
- [Format compatibility](docs/FORMAT-COMPATIBILITY.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Migration notes](docs/MIGRATION.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Release QA](docs/RELEASE-QA.md)
- [Release procedure](docs/RELEASE-PROCEDURE.md)
- [Security reporting](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)
