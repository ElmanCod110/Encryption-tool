# Secure Package V12

**Author:** ElmanCod110

Secure Package is an independent open-source browser-first encrypted package system focused on authenticated encryption, server-blind processing, resumable ciphertext transport, large-file streaming, and security testing.

## What V12 adds

V12 is the security-hardening generation before final release. It combines the earlier encrypted package architecture with a dedicated attack-and-verification layer:

- V12 browser package format (`.spk12`)
- Browser-side credential processing
- Password + pattern derived access
- AES-256-GCM content encryption
- HKDF key separation
- Content-defined chunking
- SHA-256 ciphertext addressing
- Merkle integrity
- Stream-oriented local processing
- Resumable ciphertext-only upload
- Owner-bound upload sessions
- Replay protection
- Encrypted build-state envelope
- Deterministic canonical JSON
- Runtime security diagnostics
- Source-code security audit
- Fuzz-style regression tests
- Race-condition regression tests
- Release integrity verification
- PHPStan / PHP-CS-Fixer configuration
- GitHub security CI

## Security position

The project does not rely on keeping its source code or algorithms secret. V12 uses standard cryptographic primitives and treats credentials as the main secret input.

The V12 browser workflow keeps password, pattern, and plaintext file content on the client side during package creation and restore. The server-side upload API handles opaque ciphertext only.

This is not an absolute-security guarantee. A compromised browser origin, compromised endpoint, or compromised build pipeline remains a meaningful threat.

## Runtime requirements

- PHP 8.2+
- Sodium extension
- Zip extension for ZIP workflows
- PDO MySQL is optional
- A modern browser for the V12 Browser Vault

## Local test

Place the project below the XAMPP document root:

```text
C:\xampp\htdocs\secure-package-v12\
```

Open:

```text
http://localhost/secure-package-v12/public/
```

V12 browser vault:

```text
http://localhost/secure-package-v12/public/client-vault-v12.html
```

V12 descriptor:

```text
http://localhost/secure-package-v12/public/client-v12.php
```

Runtime diagnostics:

```text
http://localhost/secure-package-v12/public/health-v12.php
```

## Test suite

Run the fast security gate:

```bash
php bin/security-test.php
```

Run the complete historical regression suite (slower because of expensive KDF tests):

```bash
php bin/security-test.php --full
```

Run source audit separately:

```bash
php bin/source-audit.php
```

Run the benchmark:

```bash
php bin/benchmark.php
```

## Important deployment rules

Expose only the `public/` directory through the web server. Keep `.env`, package storage, upload state, logs, and private operational data outside the public web root.

For production, use HTTPS and a hardened PHP deployment. Do not place private release-signing keys in the application repository or on the web server.

## License

MIT. See `LICENSE`.
