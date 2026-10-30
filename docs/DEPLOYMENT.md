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

The SPKG recovery key is displayed once. Store it offline and separately from the encrypted package. Never place it in issue trackers, source control, server logs, or application telemetry.


## Local secret bootstrap

`SPK_NAME_PEPPER` is recommended for managed production deployments. If it is not set, the application generates a persistent 256-bit local secret at `storage/secrets/name-pepper.bin` with restrictive permissions. Keep the entire `storage/` directory private and backed up with the application data it protects.

The server workspace requires PHP `ext-zip`; `/health.php` reports the deployment as degraded until it is available. `bin/self-check.php` also treats `ext-zip` as a required SPKG runtime component.


### Runtime preflight

The main SPKG workspace requires PHP `ext-zip` because incoming ZIP archives and portable `.spkg14` releases are processed server-side. The application health endpoint and web UI report this as a required runtime component.


## Hosted versus local deployment

The hosted web deployment performs package creation and restoration on the server. The server therefore processes source plaintext and the submitted credentials during those operations; this is not a zero-knowledge or server-blind architecture.

For local use, run XAMPP and keep the browser, PHP runtime, and storage on the same machine. The local and hosted deployments share the same SPKG binary format and do not use separate extensions or grammars.
