# V7 Threat Model

## Primary goal

Keep plaintext content, plaintext paths and credentials outside the PHP server boundary during the browser V7 workflow.

## Protected against

- Server-side access to V7 plaintext during normal browser encryption/decryption
- Ciphertext modification
- Manifest modification
- Chunk substitution across files or positions
- Missing, duplicate or unreferenced encrypted chunks
- Package truncation and malformed length fields
- Basic restore path traversal
- Client-side KDF parameter tampering

## Not protected against

- A compromised endpoint
- Malware or a privileged browser extension
- A compromised origin serving modified JavaScript
- Credential theft before derivation
- Weak passwords or patterns
- Browser engine vulnerabilities
- Side-channel attacks outside the application threat model
