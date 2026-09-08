# TCH Secure Package V2

TCH Secure Package V2 is a public-source PHP package encryption system designed around standard cryptography, authenticated encryption, key separation, encrypted manifests, randomized identifiers, safe archive processing, and strict failure handling.

## Security model

The source code is intentionally public. No security property depends on hiding the algorithm.

The effective secret is derived from both the encryption password and the encryption pattern through independent Argon2id operations followed by a dedicated key-combination step. A one-character pattern change produces a completely unrelated master key.

The system uses XChaCha20-Poly1305 for authenticated metadata and SecretStream XChaCha20-Poly1305 for large files. Each file receives a dedicated subkey. Names and the manifest use separate subkeys.

## Package privacy

A `.tchpkg` archive contains only the encrypted package header, encrypted manifest, and randomly named encrypted blobs. Original paths, filenames, file contents, and directory relationships are not stored in plaintext.

File contents are padded to fixed 1 MiB boundaries before streaming encryption. This reduces exact plaintext file-size leakage, although package size and padded size remain observable.

## Archive workflow

ZIP uploads are inspected and processed through a job-based workflow. Password-protected archives remain pending until the user supplies a password. Nested ZIP files are queued independently and can require their own passwords.

Archive extraction defends against path traversal, absolute paths, symbolic links, excessive depth, excessive entry count, excessive total output size, and excessive per-file size.

Extraction is staged so a failed archive password or corrupted archive does not leave a partially committed result.

## Web application

The `public/` directory contains a minimal English web interface and JSON API:

- `index.php` provides upload, archive password handling, package creation, and package opening controls.
- `api.php` exposes CSRF-protected actions.
- `download.php` serves the portable encrypted `.tchpkg` file.

Use `public/` as the web server document root. Do not expose `app/`, `config/`, or `storage/` directly.

## Runtime requirements

- PHP 8.2+.
- Sodium extension.
- Zip extension for ZIP processing and `.tchpkg` creation.
- PDO MySQL is optional. When it is not configured, project-name reservations use the file registry.

## Configuration

Copy `.env.example` into the deployment environment and configure a strong `TCH_NAME_PEPPER`.

When a database DSN is configured, execute `config/database.sql` and provide the database credentials.

## CLI examples

Generate a secret:

```bash
php bin/generate-secret.php 32
```

Encrypt a directory. The pattern is read from `TCH_PATTERN`:

```bash
TCH_PATTERN='gG7!xY2_Ab9#Qp' php bin/encrypt-directory.php ./source ./output 'Strong!Password2026'
```

Decrypt either a package directory or a `.tchpkg` file:

```bash
TCH_PATTERN='gG7!xY2_Ab9#Qp' php bin/decrypt-package.php ./output/<package-id> ./restored 'Strong!Password2026'
```

Run stale storage cleanup from cron or Task Scheduler:

```bash
php bin/cleanup.php
```

## Tests

```bash
php tests/CryptoRoundTripTest.php
php tests/FileRoundTripTest.php
php tests/SecurityInvariantTest.php
php tests/PackageRoundTripTest.php
php tests/TamperDetectionTest.php
php tests/NameRegistryTest.php
```

## Important limitation

Authenticated encryption intentionally does not produce useful plaintext for an incorrect key. V2 therefore does not attempt to detect a "wrong pattern" separately from other package-open failures. The web layer returns the same generic failure for invalid package credentials or corrupted encrypted content.

A password and project name do not reveal or recover the pattern. Making a secret pattern recoverable from public package metadata would weaken the security model.
