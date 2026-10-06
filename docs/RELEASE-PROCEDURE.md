# V14 Release Procedure

## 1. Prepare

Keep the Ed25519 private release key outside the repository and outside the web root. Ensure the working tree is clean and a real `composer.lock` has been generated from the normal development environment.

## 2. Run gates

```bash
composer validate --strict --no-check-publish
composer install --no-interaction --prefer-dist --no-progress
composer audit --no-interaction
php bin/self-check.php
php bin/source-audit.php
php bin/security-test.php --full
find public/client -type f -name '*.js' -print0 | xargs -0 -n1 node --check
```

## 3. Sign

```bash
php bin/sign-release.php /secure/location/release-private-key.hex .
```

The signing script hashes the active V14 source tree (`app/`, `bin/`, `config/`, `public/`, `bootstrap.php`, `composer.json`, `composer.lock` (when present), and `VERSION`) while excluding runtime-generated release material and storage content.

## 4. Verify with an external trust root

```bash
export SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX='<independently-distributed-64-hex-character-public-key>'
php bin/verify-release.php .
```

Do not treat the public key stored inside the release as the only trust anchor for high-assurance deployment.

## 5. Package and checksum

Create the release archive from the clean tree and publish its SHA-256 checksum alongside the independently distributed public trust key.

## 6. Publish

Expose only `public/`. Keep storage, environment secrets, signing keys, and legacy archive material out of the web root.

## 7. Post-release

Re-run release verification after transfer to the production host and record the verified archive checksum.
