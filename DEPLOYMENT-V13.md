# V13 Deployment Guide

## PHP

Use a currently supported PHP 8.x release with the required cryptographic
extensions enabled.

For server-side archive workflows, enable PHP ZipArchive.

## Web Server

Serve only the `public/` directory as the web root.

Do not expose:

- `app/`
- `config/`
- `tests/`
- `bin/`
- private keys
- build artifacts
- local state

## HTTPS

Production deployments must use HTTPS.

## Secrets

Never commit release private keys, application secrets, passwords, recovery
keys, or environment secrets.

## Headers

Keep the application's CSP and isolation/security headers enabled.

## Backups

Back up encrypted package data and required application metadata separately.
