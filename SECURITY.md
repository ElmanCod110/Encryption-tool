# Security Policy

## Security principles

Secure Package is designed around standard cryptographic primitives and authenticated encryption. The implementation is intentionally public. Security does not depend on obscuring the source code.

Primary protections include:

- Argon2id for password and pattern processing
- XChaCha20-Poly1305 for authenticated records
- XChaCha20-Poly1305 SecretStream for large files
- Purpose-separated subkeys
- Per-file keys
- Random salts and nonces
- Encrypted manifests
- Encrypted filenames
- Randomized blob identifiers
- Staged and bounded archive processing
- Atomic output creation
- Tamper detection
- One-time restore tokens
- Rate limiting
- CSRF protection
- Strict session cookies
- Security response headers

## Credential secrecy

Passwords and patterns are not intentionally stored in package metadata or project records.

The portable package contains the salt required for KDF operation, but the credentials themselves are not embedded in the package.

## Failure behavior

Authenticated decryption rejects modified ciphertext and incorrect derived keys.

The web layer deliberately converts credential-related failures into a generic package-open failure rather than revealing which credential was incorrect.

## Archive threat model

Untrusted ZIP input is treated as hostile input. The extraction workflow applies limits to file count, individual size, aggregate decompressed size, nested archive count, and nesting depth.

Unsafe paths, absolute paths, NUL bytes, and symbolic-link based escapes are rejected.

## Storage threat model

The server currently performs encryption and decryption operations. Therefore, V3 is not a zero-knowledge or server-blind storage system.

Plaintext may exist transiently on the server during source extraction and restoration. Temporary locations are permission-restricted and subject to cleanup policies, but filesystem deletion on modern storage hardware should not be described as cryptographic secure erasure.

## Operational requirements

For production deployments:

- Use HTTPS.
- Keep `public/` as the only web-exposed directory.
- Keep `storage/` outside the document root when possible.
- Protect `.env` and deployment secrets.
- Use strong, unique passwords and patterns.
- Use a persistent multi-process registry such as MySQL when several application workers share one deployment.
- Run cleanup tasks regularly.
- Keep PHP and the operating system patched.
- Restrict filesystem permissions for application storage.
- Avoid storing decrypted restore directories longer than required.

## Reporting vulnerabilities

Do not publish an exploitable vulnerability together with a working proof of compromise before a fix is available.

Use GitHub Security Advisories or the project's private security contact for responsible disclosure.

## Important limitation

No software can guarantee absolute security or absolute resistance to every attack. Security depends on the implementation, deployment, credential entropy, host security, PHP configuration, and operational controls.
