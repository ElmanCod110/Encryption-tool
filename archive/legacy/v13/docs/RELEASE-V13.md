# Secure Package V13 Release Notes

V13 is the current browser-vault generation.

## Security hardening

- Fail-closed browser package parsing with explicit size and count bounds.
- Authenticated AES-256-GCM records with domain-separated HKDF keys.
- SHA-256 ciphertext addressing.
- Full Merkle-root verification before any restore output is created.
- Restore rejects existing destination paths instead of overwriting them.
- Windows-portable path validation and case-insensitive collision checks.
- Owner-bound resumable ciphertext uploads with atomic rate limits.
- Optional HTTPS enforcement and explicit public-origin configuration.
- Release signing is external-key based; application packages do not carry a self-trusted release root.

## KDF note

The PHP server-side package engine uses Argon2id through libsodium. The browser vault uses PBKDF2-HMAC-SHA-256 through the standards-based Web Crypto API for portable offline operation. V13 does not claim that PBKDF2 is equivalent to Argon2id; an Argon2id/WASM browser backend is a separate future format capability and must be introduced with independent test vectors before changing the format.
