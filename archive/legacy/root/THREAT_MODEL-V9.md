# V9 Threat Model

## Protected Assets

- File contents
- Original filenames
- Logical directory relationships
- Password and pattern
- Package integrity
- Package access state

## Attacker Knowledge

Assume the attacker knows the full source code, package format, cryptographic algorithms, public release key, and all non-secret package metadata.

## Primary Adversaries

### Compromised storage

An attacker obtains the encrypted package and attempts offline recovery or modification.

### Malicious package modification

An attacker changes encrypted chunks, metadata, ordering, or the manifest.

### Credential guessing

An attacker attempts to guess the password and pattern offline.

### Malicious upload client

An attacker attempts to inject chunks into another user's resumable upload.

### Malicious browser state

An attacker attempts to manipulate local package state or restored paths.

### Compromised origin

An attacker controls the server that delivers HTML or JavaScript and attempts to replace the client runtime.

## Security Goals

V9 is designed to ensure that:

1. Authentication failure does not yield meaningful plaintext.
2. Ciphertext modifications are detected.
3. Chunk inventory modifications are detected.
4. Plaintext is not sent to the V9 ciphertext-only upload API.
5. Password and pattern are not stored in package metadata.
6. Different package builds use fresh package and file identifiers.
7. Published release assets can be verified using the release signature and hashes.

## Explicit Limitations

A compromised web origin can still serve malicious application code before a user performs local cryptography. Release signatures and asset hashes reduce accidental or unauthorized asset drift, but a web application cannot establish a perfect trust boundary against an origin that fully controls the initial document.

Browser memory, operating-system compromise, malicious browser extensions, and compromised user devices are outside the cryptographic package boundary.
