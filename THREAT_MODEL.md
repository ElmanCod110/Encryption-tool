# Threat Model

## Intended attacker

The primary attacker is assumed to be able to obtain a copy of the public source code and an encrypted package.

The attacker may know:

- The package format
- The algorithms used
- The implementation details
- The public API behavior
- A complete encrypted package

Security must continue to hold without source-code secrecy.

## Secrets

The primary user secrets are:

1. Encryption password
2. Encryption pattern

Both contribute to key derivation.

A project-name registry also uses a server-side pepper for management-layer uniqueness checks, but that pepper is not part of portable package decryption.

## Protected assets

- File contents
- Original filenames
- Original directory hierarchy
- Logical parent-child relationships
- Package decryption keys
- Project management metadata

## Main attack classes

### Offline credential attacks

An attacker with a package can perform offline guesses. Argon2id increases the cost of each guess, but no KDF can compensate for weak credentials indefinitely.

### Ciphertext tampering

Authenticated encryption causes modified ciphertext to fail authentication instead of being accepted as trusted plaintext.

### Package manipulation

Manifest authentication, strict schema validation, identifier validation, and package structure checks reduce the ability to inject or redirect package content.

### Archive attacks

ZIP input is treated as hostile. Extraction is bounded and rejects unsafe paths, links, and excessive resource use.

### Web attacks

State-changing web actions use CSRF protection. Sessions use strict cookies. Rate limiting and generic errors reduce abuse and credential oracle information.

### Path attacks during restore

Restored names are validated against traversal, control-character, separator, Windows device-name, and trailing dot/space hazards.

## Out of scope

The following are not solved by the cryptographic layer alone:

- A compromised server that reads plaintext during server-side decryption
- Malware on the endpoint that captures credentials
- Weak or reused user credentials
- Physical compromise of an unlocked host
- Traffic analysis that reveals package size
- Guaranteed secure deletion from flash storage
- Denial of service against the operating system or PHP runtime beyond implemented application limits

## Future security direction

A future client-side decryption mode can reduce server trust by moving key derivation, manifest decryption, and file restoration into the user's environment. Such a mode must be designed as a separate security boundary rather than presented as an automatic property of the current server-side workflow.
