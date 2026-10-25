# Deployment Guide

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

## Upload quotas

The server enforces both a per-upload size limit and active upload reservations per owner. The current configuration defaults to at most **3 active uploads** and **1 TiB of aggregate declared upload bytes per owner**. Upload initialization is also rate-limited by a hashed remote-address key. Tune `max_active_uploads_per_owner`, `max_active_upload_bytes_per_owner`, `max_upload_bytes`, and the upload TTL in `config/config.php` to fit the actual disk budget and expected workload. These controls complement, but do not replace, filesystem quotas and monitoring.

## Storage permissions

Use restrictive filesystem permissions for package, upload, temporary, catalog, account, rate-limit, and audit directories. Package files should not be executable.

## Recovery key handling

The stable-format recovery key is a canonical 43-character unpadded base64url value displayed once. Store it offline and separately from the encrypted `.spkg` file. Legacy V14 recovery keys use the legacy V14 encoding; do not interchange the two formats' recovery keys. Never place either key in issue trackers, source control, server logs, or application telemetry.


## Local secret bootstrap

`SPK_NAME_PEPPER` is recommended for managed production deployments. If it is not set, the application generates a persistent 256-bit local secret at `storage/secrets/name-pepper.bin` with restrictive permissions. Keep the entire `storage/` directory private and backed up with the application data it protects.

The server workspace requires PHP `ext-zip`; `/health.php` reports the deployment as degraded until it is available. `bin/self-check.php` treats `ext-zip` as a required application workflow component.


### Runtime preflight

The application requires PHP `ext-zip` to extract incoming ZIP uploads and to read legacy `.spkg14` archives. Stable `.spkg` packages are already single-file binary packages and do not require ZIP wrapping. The health endpoint still reports `ext-zip` as required for the full application workflow.
