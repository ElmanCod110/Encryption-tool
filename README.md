# Secure Package V4

**Author:** ElmanCod110  
**Format:** `SECURE-PKG-V4`  
**Extension:** `.spkg`

Secure Package is an open-source PHP package protection system for turning complete directory trees into opaque, authenticated encrypted packages.

The project is designed so security does not depend on hiding the source code or inventing a secret cipher.

## V4 Highlights

- Password + pattern based key derivation with Argon2id
- XChaCha20-Poly1305 authenticated encryption
- XChaCha20-Poly1305 SecretStream for large files
- Independent purpose-derived keys
- Encrypted filenames
- Encrypted directory relationships
- Encrypted and authenticated manifest
- Randomized file blob identifiers
- Per-file derived encryption keys
- Padding to reduce exact file-size leakage
- Resumable uploads with owner binding
- Recursive and password-aware ZIP processing
- ZIP traversal and resource-abuse protections
- Permanent project-name reservation
- Account registration, login, logout, and session rotation
- Package ownership management
- Package expiration
- Package revocation
- Time-limited package access tokens
- One-time restore tokens
- Generic credential failure responses
- Rate limiting
- CSRF protection
- Same-origin validation
- Strict session cookies
- CSP and modern security headers
- Append-only style audit logging with secret-field filtering
- Atomic filesystem writes and staged operations
- Runtime self-checks
- CI workflow and security regression tests

## Security Model

The attacker may know the complete source code, package format, algorithms, and public application behavior.

The security boundary is the user's encryption password and pattern plus the authenticated cryptographic construction.

The package itself does not contain the password or pattern.

Changing a single pattern character produces unrelated derived key material through the KDF pipeline and does not create a small or predictable ciphertext change.

## Cryptographic Pipeline

```text
Password ──► Argon2id ──► Password Key ──┐
                                         ├─► Master Key ─► Purpose Subkeys
Pattern  ──► Argon2id ──► Pattern Key  ──┘              ├─ Manifest
                                                        ├─ Filenames
                                                        └─ File Root
                                                                  │
                                                                  └─ Per-file keys
```

The package format uses authenticated encryption. Modified ciphertext, corrupted manifests, invalid keys, and structurally invalid packages are rejected.

## Package Layout

A portable package is intentionally opaque:

```text
header.json
manifest.enc
blobs/
    <random-id>.bin
    <random-id>.bin
    ...
```

The original project name is not stored inside the portable package.

Original filenames and paths are represented only inside the encrypted manifest.

## Web Workflow

```text
ZIP upload
   │
   ├─ resumable chunks
   │
   ▼
archive inspection
   │
   ├─ protected archive ─► password step ─┐
   │                                      │
   └──────────────────────────────────────┘
                     │
                     ▼
              staged extraction
                     │
                     ▼
              project validation
                     │
                     ▼
                package build
                     │
                     ▼
                  .spkg
```

Restoration is similarly staged and never trusts the manifest before authenticated decryption and schema validation.

## Installation

Requirements:

- PHP 8.2+
- Sodium extension
- Zip extension
- Apache, Nginx, PHP built-in server, or another PHP-compatible web server
- PDO MySQL is optional for deployments that prefer a database-backed registry

Clone the repository:

```bash
git clone https://github.com/ElmanCod110/secure-package.git
cd secure-package
```

Create `.env` from `.env.example` and generate a strong server-side registry secret:

```bash
php bin/generate-secret.php 32
```

Set the value as:

```env
SPK_NAME_PEPPER=YOUR_GENERATED_SECRET
```

Do not commit `.env`.

## Local XAMPP Setup

Place the repository under:

```text
C:\xampp\htdocs\secure-package-v4\
```

The intended document root is:

```text
C:\xampp\htdocs\secure-package-v4\public\
```

For a simple local installation, the application can also be opened through:

```text
http://localhost/secure-package-v4/public/
```

V4 includes a lightweight runtime check at:

```text
http://localhost/secure-package-v4/public/health.php
```

This shows the PHP version and required extension state without exposing application secrets.

## Important Apache Note

The V3 root `.htaccess` contained a `<DirectoryMatch>` directive in a context where that directive can be invalid. On Apache configurations that reject the directive, this results in HTTP 500 before PHP is reached.

V4 removes that invalid directory-context rule and keeps the root `.htaccess` compatible with normal Apache per-directory configuration.

## Testing

Run all tests:

```bash
for test in tests/*.php; do php "$test"; done
```

Or run them individually on Windows:

```bat
php tests\CryptoRoundTripTest.php
php tests\FileRoundTripTest.php
php tests\KdfParameterTest.php
php tests\NameRegistryTest.php
php tests\PackageCatalogTest.php
php tests\PackageIdTest.php
php tests\PackageRoundTripTest.php
php tests\RestoreTokenTest.php
php tests\ResumableUploadTest.php
php tests\SecurityInvariantTest.php
php tests\TamperDetectionTest.php
```

Run the environment self-check:

```bash
php bin/self-check.php
```

## CLI

Encrypt a source directory:

```bash
SPK_PATTERN='gG7!xY2_Ab9#Qp' php bin/encrypt-directory.php ./source ./output 'Strong!Password2026'
```

Decrypt an extracted package directory or `.spkg` file:

```bash
SPK_PATTERN='gG7!xY2_Ab9#Qp' php bin/decrypt-package.php ./output/<package-id>.spkg ./restored 'Strong!Password2026'
```

Generate a deployment secret:

```bash
php bin/generate-secret.php 32
```

Clean stale temporary data:

```bash
php bin/cleanup.php
```

## Account Management

V4 includes an optional application identity layer for management actions.

Accounts use PHP's Argon2id password hashing, session regeneration, strict cookies, CSRF protection, and login rate limiting.

Encryption credentials remain separate from account credentials.

## Package Lifecycle

Packages can be:

- Created
- Listed for their owner
- Shared using short-lived access tokens
- Expired
- Revoked
- Restored using one-time restore tokens

Revoking a package invalidates issued package access tokens.

## Archive Security

ZIP input is treated as hostile.

The archive layer validates:

- Relative paths
- NUL bytes
- Absolute paths
- Drive-qualified paths
- Parent traversal
- Symbolic-link metadata
- Entry counts
- Single-file expansion limits
- Total decompressed size
- Nested archive depth
- Nested archive count

Extraction is staged so invalid archive passwords or malformed input do not leave a partially committed project tree.

## Source Layout

```text
app/
    Api/
    Archive/
    Crypto/
    Project/
    Security/
    Storage/

bin/
client/
config/
public/
storage/
tests/
tools/
```

The cryptographic layer is intentionally separated from the HTTP controllers and presentation layer.

## Client-Side Decryption Direction

The package format is designed so a future browser-only decryptor can consume opaque package bytes without changing the encrypted format.

A real browser decryptor should use an audited WebAssembly binding of the same sodium primitives. The project intentionally does not implement a hand-written JavaScript cipher or silently downgrade to a different algorithm.

Therefore, V4 is **not** marketed as zero-knowledge or server-blind storage.

## Production Guidance

For production deployments:

- Expose only `public/` through the web server.
- Prefer storing `storage/` outside the document root.
- Use HTTPS.
- Keep the application secret in a protected environment file or environment provider.
- Keep PHP and the host operating system updated.
- Schedule cleanup of temporary data.
- Use strong, unique encryption credentials.
- Use a persistent database registry when multiple application workers share the deployment.
- Restrict filesystem permissions.
- Monitor audit events without logging secrets.

## Limitations

No system can guarantee absolute security.

V4 still performs server-side decryption during restore. Plaintext can therefore exist transiently on the server during extraction and restoration.

The package size and other transport characteristics can still leak coarse information even when content and names are encrypted.

Deletion from flash storage should not be described as guaranteed cryptographic erasure.

## License

MIT License

Copyright (c) 2026 ElmanCod110
