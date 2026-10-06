# Security Engineering

Secure Package is designed around authenticated encryption, explicit trust boundaries, fail-closed parsing, bounded resource consumption, and reproducible release verification.

## Current V13 browser boundary

Plaintext files and credentials remain in the browser during local package creation and restore. Server transport receives opaque ciphertext chunks only.

V13 verifies the complete encrypted chunk inventory and Merkle root before writing restored files. Existing destination files are never overwritten by the browser restore flow.

The browser KDF is PBKDF2-HMAC-SHA-256 because the Web Crypto API provides a portable built-in primitive. The PHP package engine uses Argon2id through libsodium. These are intentionally documented as different cryptographic backends rather than being presented as equivalent.

## Release trust

A release signature is meaningful only when the verifying public key is trusted independently from the signed package. `bin/sign-release.php` accepts an external private key, while `bin/verify-release.php` can require `SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX`.

Do not deploy with an embedded public key as the only trust root for high-assurance verification.

## Deployment controls

Set `SPK_REQUIRE_HTTPS=1` and `SPK_PUBLIC_ORIGIN=https://your-host.example` in production. Expose only `public/` through the web server and keep storage, configuration, and signing material outside the public root.
