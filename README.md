# Secure Package V14

**Author:** ElmanCod110

Secure Package V14 is an open-source encrypted project package engine built around explicit cryptographic boundaries, authenticated metadata, fail-closed parsing, bounded resource consumption, and safe restore semantics.

## V14 server package engine

The active server package format is `SECURE-PKG-V14` (`.spkg14`). V14 uses:

- Argon2id13 for password and pattern credential derivation through libsodium
- A random 256-bit package root key, wrapped independently from credentials
- XChaCha20-Poly1305 for authenticated metadata and key slots
- `secretstream_xchacha20poly1305` for authenticated file streaming
- HKDF-SHA-256 for explicit key separation
- Header binding authenticated into package operations
- Encrypted filenames and authenticated directory relationships
- SHA-256 ciphertext verification for every package blob
- Merkle-root verification over the complete file inventory before restore
- Fail-closed archive/package/path validation
- No-overwrite restore with preflight conflict detection
- Independent optional recovery-key slot
- Atomic temporary-file writes and secret zeroization where applicable

V14 is designed so that the password and pattern do not directly serve as the long-lived file-encryption key. They derive a wrapping key which unlocks the random package root key; subkeys are then derived for manifests, filenames, and file streams.

## Browser compatibility boundary

The browser-first vault remains `SECURE-BROWSER-V13` (`.spk13`). It is intentionally kept as a separate compatibility boundary rather than silently reinterpreted as V14.

The browser implementation uses the standards-based Web Crypto API and PBKDF2-HMAC-SHA-256. The server package engine uses Argon2id through libsodium. These are separate designs with separate threat assumptions.

## Repository layout

The repository root contains active V14 source and security tooling. Historical source and superseded generation material live under:

```text
archive/legacy/
```

The archive is not part of the active application surface.

## Runtime requirements

- PHP 8.2+
- Sodium extension
- Zip extension for ZIP package workflows
- PDO MySQL is optional for installations that enable MySQL-backed integration
- Modern browser for the separate V13 browser vault

## Local run

Point Apache/XAMPP at the `public/` directory and open the application entry point.

The V14 package engine is exposed through the main application UI and CLI helpers:

```text
php bin/encrypt-directory.php <source-dir> <package-dir> <password> <pattern>
php bin/decrypt-package.php <package-dir> <destination-dir> <password> <pattern>
```

A generated package may also expose a one-time recovery key. Keep that key outside the package and outside logs.

## Production security baseline

Set:

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
find public/client -type f -name '*.js' -print0 | xargs -0 -n1 node --check
composer validate --strict --no-check-publish
composer install --no-interaction --prefer-dist --no-progress
composer audit --no-interaction
```

For a reproducible release, generate and commit a real `composer.lock` from the normal development environment, then install with that lock in CI.

## Security philosophy

V14 treats cryptography, parsing, filesystem handling, authentication, resource limits, and supply-chain integrity as one security boundary. A stronger cipher alone does not make the system secure; every step between untrusted input and plaintext restore must fail closed.
