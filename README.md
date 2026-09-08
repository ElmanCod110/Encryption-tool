# Secure Package V3

Secure Package is an open-source PHP system for turning complete directory trees into portable encrypted packages.

**Author:** ElmanCod110  
**Current format:** `SECURE-PKG-V3`  
**Package extension:** `.spkg`

## What it does

Secure Package accepts a source directory or ZIP-driven workflow and produces a package whose file contents, filenames, and logical directory relationships are protected by authenticated encryption.

The V3 workflow adds stronger package validation, bounded KDF parameters, one-time restore tokens, staged archive handling, atomic package creation, safer web headers, improved rate limiting, and additional security regression tests.

## Architecture

```text
Source ZIP
    |
    v
Archive Scanner
    |
    +--> Protected archive? --> Password step
    |
    v
Safe staged extraction
    |
    v
Project validation
    |
    +--> Password ----> Argon2id --+
    |                               |
    +--> Pattern ----> Argon2id ----+--> Master key
                                    |
                 +------------------+------------------+
                 |                  |                  |
                 v                  v                  v
          Manifest key       Filename key        File root key
                 |                  |                  |
                 v                  v                  v
          Encrypted map      Encrypted names      Per-file keys
                 |                                     |
                 +----------------------+--------------+
                                        v
                                  Encrypted blobs
                                        |
                                        v
                                  Encrypted manifest
                                        |
                                        v
                                   Portable .spkg
```

## Cryptographic design

The project deliberately uses public, standard cryptographic primitives. The security model does not depend on hiding the implementation.

### Key derivation

Password and pattern are independently processed with Argon2id using package-specific salts. The derived material is combined and expanded into purpose-specific subkeys.

A one-character pattern change results in a different cryptographic key stream rather than a small modification of the previous key.

### Authenticated encryption

- XChaCha20-Poly1305 for encrypted metadata and compact records.
- XChaCha20-Poly1305 SecretStream for large file content.
- Independent file keys derived from the per-package file key root.
- Fresh cryptographic randomness for package and file encryption operations.
- Authentication failures never produce trusted plaintext.

### Key separation

Separate key material is derived for:

- Manifest encryption
- Filename encryption
- File encryption

This prevents one primitive's role from becoming another primitive's key source.

## Package privacy

A portable `.spkg` package does not store original directory names or paths in plaintext.

The package contains an opaque structure built from:

```text
header.json
manifest.enc
blobs/<random-id>.bin
```

The manifest is encrypted and authenticated, while blob names are random identifiers.

The project name used by the management layer is not embedded into the portable package.

## File size handling

Large files are processed as streams instead of being loaded into memory as a whole.

Plaintext data is padded to configurable block boundaries before streaming encryption to reduce exact file-size leakage. Padding reduces leakage but does not hide the total package size.

## Archive security

The archive workflow is bounded and staged.

It protects against common archive abuse such as:

- Path traversal
- Absolute paths
- NUL bytes and unsafe entry names
- Symbolic-link based escapes
- Excessive entry count
- Excessive decompressed output
- Oversized individual files
- Excessive nested archive depth
- Excessive nested archive count
- Partial extraction left behind after failure

Nested password-protected archives are processed independently.

## Web security

The web layer includes:

- Strict session cookies
- CSRF tokens for state-changing requests
- SameSite protection
- Strict session mode
- Security response headers
- Content Security Policy
- Generic package-open failures
- File-backed rate limiting with locking
- One-time, expiring restore tokens
- No-store caching for sensitive responses

## Restore flow

A successful server-side decryption creates a short-lived private restore directory and issues a random restore token.

The token is one-time and expires automatically. Downloading the restored result creates a ZIP and streams it to the client.

> V3 still performs decryption on the server. It is not a zero-knowledge or server-blind design.

## Project-name reservation

Project names are normalized for Unicode and case handling before being hashed with a server-side pepper.

Names can be reserved through either:

- A file-backed registry for simple deployments
- A MySQL-backed registry for multi-process deployments

A reserved name is intended to remain unavailable even if its associated package is later removed.

## Requirements

- PHP 8.2 or newer
- `sodium` extension
- `zip` extension for ZIP input and `.spkg` creation
- PDO MySQL is optional
- UTF-8 capable filesystem and database settings are recommended

## Installation

Clone or copy the repository and expose only `public/` through the web server.

For XAMPP, a local layout can be:

```text
C:\xampp\htdocs\secure-package-v3\
    app\
    bin\
    config\
    public\
    storage\
    tests\
```

Then open:

```text
http://localhost/secure-package-v3/public/
```

Do not expose `app/`, `config/`, or `storage/` directly to the browser.

## Configuration

Copy `.env.example` to `.env` and set a strong registry pepper.

Generate one with:

```bash
php bin/generate-secret.php 32
```

Example:

```env
SPK_NAME_PEPPER=replace-with-generated-random-secret
SPK_DB_DSN=mysql:host=127.0.0.1;dbname=secure_package;charset=utf8mb4
SPK_DB_USER=secure_package
SPK_DB_PASS=replace-with-a-strong-database-password
```

The `.env` file must never be committed.

## CLI usage

Encrypt a directory:

```bash
SPK_PATTERN='gG7!xY2_Ab9#Qp' php bin/encrypt-directory.php ./source ./output 'Strong!Password2026'
```

Decrypt a package directory or `.spkg` file:

```bash
SPK_PATTERN='gG7!xY2_Ab9#Qp' php bin/decrypt-package.php ./output/<package-id> ./restored 'Strong!Password2026'
```

Generate a secret:

```bash
php bin/generate-secret.php 32
```

Clean stale temporary data:

```bash
php bin/cleanup.php
```

## Web API

The initial web API supports:

```text
POST api.php?action=upload
POST api.php?action=archive-step
POST api.php?action=build
POST api.php?action=decrypt
GET  api.php?action=csrf
```

All state-changing actions require the current session CSRF token.

## Tests

Run the full lightweight regression set:

```bash
php tests/CryptoRoundTripTest.php
php tests/FileRoundTripTest.php
php tests/KdfParameterTest.php
php tests/NameRegistryTest.php
php tests/PackageIdTest.php
php tests/PackageRoundTripTest.php
php tests/RestoreTokenTest.php
php tests/SecurityInvariantTest.php
php tests/TamperDetectionTest.php
```

The tests cover:

- String and file round trips
- Large streaming files
- Pattern avalanche behavior
- KDF parameter restrictions
- Package round trips
- Wrong-pattern rejection
- Ciphertext and manifest tamper detection
- Project-name uniqueness
- Package identifier validation
- One-time restore tokens
- Core security invariants

The local build environment used for this release has `sodium` enabled. The PHP `zip` extension may need to be enabled separately before running ZIP-specific integration tests or the web upload workflow.

## Threat model

See `THREAT_MODEL.md` for the detailed assumptions and limitations.

The system assumes an attacker may know the source code and package format. It does not attempt to make the algorithm secret.

## Format

See `FORMAT.md` for the current `SECURE-PKG-V3` package structure and compatibility rules.

## Security

See `SECURITY.md` for security expectations, operational guidance, and disclosure instructions.

## Author

ElmanCod110

## License

MIT License.

See `LICENSE` for the full text.
