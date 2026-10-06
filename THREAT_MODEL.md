# Threat Model

## Protected

- Plaintext file contents at rest in the package.
- Original filenames and directory paths inside the package.
- Package structure and manifest relationships.
- Package integrity and authenticated file content.
- Project-name uniqueness without storing the original name in the reservation registry.

## Assumptions

- The encryption password and pattern have sufficient entropy.
- The server runtime and Sodium implementation are trusted.
- PHP, the operating system, and hardware are not already compromised.

## Public source

An attacker may read the full source code. This is expected. No security mechanism depends on code secrecy.

## Online attacks

The web API applies per-package and per-archive failure rate limits. Deployments should additionally use upstream request throttling, authentication, logging, and network controls.

## Metadata leakage

Package size and padded blob size remain observable. File padding reduces exact size leakage but does not provide complete traffic-flow secrecy.

A random package ID is not a cryptographic decryption key. Possession of the package link does not reveal the password or pattern.

## Server-side decryption

The supplied server-side `decrypt` API creates restored plaintext on the server. A strict zero-knowledge architecture would require client-side decryption with a browser-compatible cryptographic implementation and should be treated as a separate deployment mode.
