# Threat Model — Secure Package V6

## Goals

Protect encrypted package contents, filenames, logical directory relationships, access tokens, and server-managed package lifecycle state.

## Adversary capabilities

The attacker may know the complete source code, package format, public endpoints, encrypted package bytes, and public cryptographic algorithm choices.

The attacker may also tamper with uploads, ciphertext, manifests, access tokens, and lifecycle requests.

## Security boundary

The server-native profile uses Argon2id and XChaCha20-Poly1305 authenticated encryption. The V6 browser profile is a separate Web Crypto profile intended for workflows where Password and Pattern remain in the browser.

The V6 release does not claim universal zero-knowledge behavior for every workflow. A workflow is server-blind only when the browser performs credential-based derivation and decryption locally without transmitting those credentials to the server.

## Explicit non-goals

No algorithm is assumed secure because it is proprietary or hidden. Absolute protection against a compromised endpoint, browser extension, malware, keylogger, or a fully compromised server is not claimed.
