# V14 Deployment Guide

## Web root

Expose only the `public/` directory through Apache/XAMPP. Keep the repository root, `storage/`, environment files, dependency manifests, and signing material outside the public web root.

## Environment

```text
SPK_REQUIRE_HTTPS=1
SPK_PUBLIC_ORIGIN=https://your-host.example
SPK_NAME_PEPPER=<long-random-secret>
```

## PHP

Use PHP 8.2+ with Sodium and Zip enabled. Validate the real deployment platform before enabling production traffic.

## Composer

Before release, create a real lockfile in a normal development environment:

```bash
composer update
composer validate --strict --no-check-publish
composer audit --no-interaction
```

Commit `composer.lock`. CI should then use:

```bash
composer install --no-interaction --prefer-dist --no-progress
composer audit --no-interaction
```

## Release signing

Keep the Ed25519 private release key outside the repository. After signing the active source tree, distribute the exact SHA-256 archive checksum and the public trust key through an independent channel.

## Storage permissions

Use restrictive filesystem permissions for package, upload, temporary, catalog, account, rate-limit, and audit directories. Package files should not be executable.

## Recovery key handling

The V14 recovery key is displayed once. Store it offline and separately from the encrypted package. Never place it in issue trackers, source control, server logs, or application telemetry.
