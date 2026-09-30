# Secure Package V13 — Proposed Threat Model

## Security objective

Protect package confidentiality and integrity while minimizing trust in the application server, and make browser/client cryptography independently verifiable.

## Assets

- Plaintext file contents
- Encrypted package contents
- Passwords, patterns, recovery secrets and derived keys
- File and directory names
- Package manifests and integrity metadata
- Account identity and package ownership
- Release authenticity
- Audit evidence

## Trust boundaries

### Browser boundary

The browser performs package encryption/decryption. Plaintext should remain local for the server-blind profile.

### Server boundary

The server may transport/store opaque ciphertext but must not receive browser credentials or plaintext for the server-blind profile.

### Release boundary

The browser must not treat arbitrary code served by the same origin as inherently trusted. High-assurance deployments must verify the exact release against an independently trusted release key.

### Endpoint boundary

Malware, hostile extensions, keyloggers, a compromised operating system, and compromised browser binaries are outside the cryptographic package guarantee.

## Adversaries

- Remote anonymous network attacker
- Authenticated malicious user
- Malicious package creator
- Ciphertext/storage tamperer
- Offline password-guessing attacker
- Compromised web origin
- Compromised CI/build worker
- Local same-user filesystem attacker
- Compromised endpoint

## Required guarantees

1. All security-sensitive package metadata is authenticated.
2. No attacker-controlled length field causes an unbounded allocation or read.
3. KDF parameters are allowlisted before expensive computation.
4. All AES-GCM nonces are unique under the key they protect.
5. Wrong credentials never produce trusted plaintext.
6. Package integrity is verified before filesystem writes.
7. Existing destination files are never overwritten by default.
8. Cross-user package management is owner-authorized.
9. Uploads are authorized before global storage mutation.
10. Resource consumption is bounded across bytes, records, paths, depth, and time.
11. Release authenticity has an external trust root.
12. CI is reproducible and dependency auditing is blocking.

## Explicit non-goals

- Protection against a compromised endpoint or browser process.
- Guaranteed secure deletion from SSD/NVMe media.
- Hiding all traffic metadata from a network observer.
- Making an unauthenticated bearer token behave like a non-transferable identity credential.

## V13 release gates

A release should not be called high-assurance until the following are all true:

- Full unit/integration/fuzz/adversarial test suite passes.
- Browser parser/property tests cover malformed package boundaries.
- Release binary/assets are reproducibly built.
- Complete release manifest is signed.
- Verification uses an independently pinned trust key.
- `composer.lock` exists and `composer audit --locked` is blocking.
- CI actions are commit-SHA pinned.
- HTTPS-only production deployment is enforced.
- A second engineer or independent reviewer has inspected the cryptographic format and trust model.
