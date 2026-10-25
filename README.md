# Secure Package

**Author:** ElmanCod110

Secure Package is an open-source encrypted project package engine built around explicit cryptographic boundaries, authenticated metadata, fail-closed parsing, bounded resource consumption, and safe restore semantics.

## Stable binary server package format

New server packages use the permanent single-file binary format (`.spkg`). Its frozen grammar contains no application release version, format-generation label, or schema-version field. The package starts with a fixed 253-byte header and uses:

- Argon2id13 for independent password and pattern credential derivation through libsodium
- A random nonzero 256-bit package root key, wrapped separately from the credentials
- XChaCha20-Poly1305-IETF for authenticated key wrapping and the encrypted binary manifest
- `secretstream_xchacha20poly1305` for authenticated per-file chunk streams
- HKDF-SHA-256 domain separation for the header MAC, manifest, and file-stream keys
- HMAC-SHA-256 authentication of the fixed header
- A strict encrypted manifest with canonical path ordering, bounded entry count, and cross-checked stream metadata
- Fail-closed parsing, bounded KDF/resource parameters, cross-platform path validation, and no-overwrite restore
- Atomic no-replace package publication and private staging with conservative rollback
- An optional independent recovery-key slot

The password and pattern do not directly become long-lived file-encryption keys. They derive a wrapping key that unlocks the random package root key. The manifest protects names and directory relationships, but **file sizes, file count, total data volume, and package size are not hidden** by this format.

The normative byte layout, field offsets, cryptographic domains, limits, and acceptance tests are documented in [the stable binary format specification](docs/STABLE-PACKAGE-FORMAT-BINARY.md). The implementation and release gate are tracked in [the stable format contract](docs/STABLE-PACKAGE-FORMAT.md).

## Legacy V14 server package compatibility

The previous `SECURE-PKG-V14` directory format and `.spkg14` ZIP transport remain available for restoring existing packages. They are not the default format for new packages. The legacy V14 format has its own specification in [docs/FORMAT.md](docs/FORMAT.md); it is not silently reinterpreted as the stable binary format.

## Browser compatibility boundary

The browser-first vault remains `SECURE-BROWSER-V13` (`.spk13`). It is intentionally kept as a separate compatibility boundary rather than silently reinterpreted as the server format.

The browser implementation uses the standards-based Web Crypto API and PBKDF2-HMAC-SHA-256. The server package engine uses Argon2id through libsodium. These are separate designs with separate threat assumptions.

## Repository layout

The repository root contains the active application source and security tooling. Superseded source bundles are intentionally excluded from the working tree; historical release and change explanations remain in Markdown documentation.

## Runtime requirements

- PHP 8.2+
- Sodium extension
- Zip extension for ZIP package workflows
- PDO MySQL is optional for installations that enable MySQL-backed integration
- Modern browser for the separate V13 browser vault

## Local run

Point Apache/XAMPP at the `public/` directory and open the application entry point.

The server package engine is exposed through the main application UI and CLI helpers:

```text
SPK_PATTERN='<high-entropy-pattern>' php bin/encrypt-directory.php <source-dir> <output-dir> <password>
SPK_PATTERN='<high-entropy-pattern>' php bin/decrypt-package.php <package-file-or-legacy-dir-or-spkg14> <destination-dir> <password> [recovery-key]
```

A generated stable package may also expose a one-time 43-character base64url recovery key. Keep it offline and outside logs. Existing V14 packages use their legacy recovery-key encoding.

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
composer audit --no-interaction
```

After a real root `composer.lock` has been generated with Composer and committed, install the locked dependency graph with `composer install --no-interaction --prefer-dist --no-progress`. Do not treat `composer install` without a lockfile as a reproducible dependency install; the release workflow intentionally fails while the lockfile is missing.

Before a release, work through the [reproducible release QA matrix](docs/RELEASE-QA.md). It separates CI evidence from manual Windows/XAMPP and real-browser checks; manual scenarios must remain NOT RUN until tested.

## Security philosophy

The application treats cryptography, parsing, filesystem handling, authentication, resource limits, and supply-chain integrity as one security boundary. A stronger cipher alone does not make the system secure; every step between untrusted input and plaintext restore must fail closed.


## Project policy and further documentation

- [Versioning policy](VERSIONING.md)
- [Security reporting](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Stable binary format specification](docs/STABLE-PACKAGE-FORMAT-BINARY.md)
- [Stable format contract](docs/STABLE-PACKAGE-FORMAT.md)
- [Legacy V14 format specification](docs/FORMAT.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Migration notes](docs/MIGRATION.md)
- [Release procedure](docs/RELEASE-PROCEDURE.md)
- [Release notes](docs/RELEASE-NOTES.md)
- [Reproducible release QA matrix](docs/RELEASE-QA.md)
- [Validation record](docs/VALIDATION.md)
- [Changelog](CHANGELOG.md)

---

## Like this project?

If Secure Package is useful to you, consider giving it a **star** on GitHub. ⭐ Your support helps more developers discover the project and encourages continued work on secure, reliable encryption tools.

**Found it interesting? [Star the repository](https://github.com/ElmanCod110/Encryption-tool)** — it only takes a second, and it means a lot.
