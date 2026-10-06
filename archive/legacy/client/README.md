# Client-Side Cryptography Profile

Version 6 introduces an isolated browser cryptography profile for operations that must not send the Password or Pattern to the server.

The client profile uses the browser Web Crypto API with:

- PBKDF2-HMAC-SHA-256
- 900,000 iterations by default
- AES-256-GCM
- Unique 256-bit salts
- Unique 96-bit IVs
- Authenticated additional data
- Web Worker isolation

This profile is intentionally separate from the server-native XChaCha20-Poly1305 package format. It is not safe to claim that the entire ZIP workflow is server-blind until the browser package builder/reader is used end-to-end.

The server must never receive browser-side Password or Pattern values in a client-side workflow.
