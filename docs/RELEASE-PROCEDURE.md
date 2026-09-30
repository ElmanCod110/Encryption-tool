# V13 Release Procedure

## 1. Prepare

Keep the Ed25519 private release key outside the repository and outside the web root.

## 2. Run gates

```bash
php bin/self-check.php
php bin/source-audit.php
php bin/security-test.php --full
find public/client -type f -name '*.js' -print0 | xargs -0 -n1 node --check
```

## 3. Sign

```bash
php bin/sign-release.php /secure/location/release-private-key.hex .
```

The signing script hashes only the six active V13 browser release assets and writes `public/release/manifest.json`, `manifest.sig`, and the corresponding public key.

## 4. Verify with an external trust root

```bash
export SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX='<independently-distributed-64-hex-character-public-key>'
php bin/verify-release.php .
```

Do not treat the public key stored inside the signed package as the only trust anchor in a high-assurance deployment.

## 5. Publish

Expose only `public/` through the web server. Keep `storage/`, `.env`, signing keys, build files, and archived historical source outside the web root.

## 6. Deployment

Production should set:

```text
SPK_REQUIRE_HTTPS=1
SPK_PUBLIC_ORIGIN=https://your-host.example
```

## 7. Post-release

Publish the exact archive checksum and the independently distributed release public key together. Re-run verification after transfer to the production host.
