# Secure Package V13

**Author:** ElmanCod110

Secure Package is an open-source encryption project with two explicit cryptographic boundaries: an Argon2id-backed PHP package engine and a browser-first server-blind V13 vault.

## Current browser vault

The active browser format is `SECURE-BROWSER-V13` (`.spk13`). V13 hardens the package parser and restore path around the authenticated encryption layer:

- AES-256-GCM for package records
- HKDF-SHA-256 key separation
- SHA-256 ciphertext addressing
- Content-defined streaming chunks
- Full Merkle-root verification before restore output
- Fail-closed header/footer/metadata parsing
- Explicit package, manifest, file, path, and chunk limits
- Cross-platform path validation and collision detection
- Fail-on-existing-path restore policy
- Dedicated Web Worker for credential/key operations
- Optional independent recovery-key slot
- Resumable ciphertext-only uploads
- Owner-bound upload sessions and atomic rate limiting
- Optional HTTPS enforcement and configured public-origin validation

### KDF boundary

The PHP server-side package engine uses Argon2id through libsodium. The V13 browser vault uses PBKDF2-HMAC-SHA-256 through the standards-based Web Crypto API for broad offline browser compatibility. The two are documented separately; V13 does not claim that PBKDF2 is equivalent to Argon2id.

## Layout

The repository root contains only the active source and security tooling. Previous format generations are preserved under:

```text
archive/legacy/
```

Legacy code is not part of the active browser or API surface.

## Runtime requirements

- PHP 8.2+
- Sodium extension
- Zip extension for ZIP workflows
- PDO MySQL is optional
- Modern browser with Web Crypto, Web Workers, and File System Access API for large streamed restore/build workflows

## Local run

Point XAMPP/Apache at the `public/` directory and open:

```text
http://localhost/secure-package/public/
```

Browser Vault V13:

```text
http://localhost/secure-package/public/client-vault.html
```

V13 descriptor:

```text
http://localhost/secure-package/public/client-v13.php
```

V13 health check:

```text
http://localhost/secure-package/public/health-v13.php
```

## Production settings

Set these environment variables on production:

```text
SPK_REQUIRE_HTTPS=1
SPK_PUBLIC_ORIGIN=https://your-host.example
```

Expose only `public/` through the web server. Keep `.env`, `storage/`, package data, upload state, audit logs, and release-signing secrets outside the public web root.

## Security tests

Fast gate:

```bash
php bin/security-test.php
```

Full regression suite:

```bash
php bin/security-test.php --full
```

Source audit:

```bash
php bin/source-audit.php
```

Release verification requires an independently trusted public key:

```bash
php bin/verify-release.php .
```

For high-assurance release verification, set `SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX` instead of trusting a public key shipped with the package.

## Release signing

Release signatures are generated only from an external private key. Do not store a release private key in the repository or web server.

```bash
php bin/sign-release.php /secure/location/release-private-key.hex .
```

The signing workflow targets the current V13 browser assets.

## Security position

No software can provide an absolute security percentage. The project instead documents a concrete threat model, trust boundaries, cryptographic primitives, parser limits, authorization controls, test gates, and release-integrity procedures.

A compromised browser origin, endpoint, operating system, build pipeline, or user secret remains outside the protections of the package cryptographic format.

## License

MIT. See `LICENSE`.
