# TCH Secure Package V1

A public-source PHP package encryption core designed for authenticated, password-and-pattern derived encryption without relying on secret algorithms.

## Security design

- KDF: Argon2id through PHP Sodium.
- Small authenticated payloads: XChaCha20-Poly1305.
- Large files: XChaCha20-Poly1305 SecretStream.
- Independent subkeys for manifest, names, and file content.
- Random salts, random file identifiers, and fresh nonces/stream headers.
- Encrypted manifest containing the original directory tree.
- Original file names and paths are not stored in plaintext inside the package.
- Uniform decryption failure behavior can be exposed at the HTTP layer so callers are not told whether a password or pattern was wrong.
- ZIP extraction limits and path traversal checks are included as a security boundary.

## Runtime requirements

- PHP 8.2 or newer recommended.
- `sodium` extension required.
- `zip` extension required for ZIP handling.

## Important boundary

A cryptographic design cannot make a secret safe solely by hiding the algorithm. The source code may be public. Security comes from strong secrets, memory-hard key derivation, authenticated encryption, key separation, careful randomness, and strict input handling.

## Current package layout

```text
app/
  Archive/
  Crypto/
  Project/
  Security/
  Storage/
config/
public/
bin/
tests/
storage/
```

## Test

Run:

```bash
php tests/CryptoRoundTripTest.php
```

The test verifies deterministic key derivation for identical credentials, complete avalanche behavior for a one-character pattern change, successful encryption/decryption, and authenticated failure with the wrong pattern.
