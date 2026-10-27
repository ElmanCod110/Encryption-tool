# Secure Package Release Notes

V14 moves the active server package engine to `SECURE-PKG-V14` and introduces a separate random package root key with independently authenticated credential and recovery wrapping.

### Security changes

- Argon2id13 password/pattern derivation
- Random 256-bit package root key
- HKDF subkey separation
- Header-binding authenticated metadata
- XChaCha20-Poly1305 key slots and manifest
- secretstream-authenticated file streaming
- complete ciphertext inventory hashing
- Merkle-root verification before restore
- preflight no-overwrite restore
- stronger archive extraction validation
- V14 release manifest covering active source
- CI Composer validation/install/audit flow

### Compatibility

`SECURE-BROWSER-V13` remains available as a separate browser compatibility boundary. It is not silently upgraded to the V14 server format.

### Release validation

Use the [reproducible release QA matrix](RELEASE-QA.md) to record automated CI evidence separately from manual Windows/XAMPP and real-browser checks. The checklist intentionally starts manual scenarios as NOT RUN; do not infer browser or deployment compatibility from syntax checks alone.

### Known release prerequisites

A Composer-generated `composer.lock` is now present on the reconciliation candidate branch and the workflow that refreshes it fails before opening a PR when dependency auditing fails. Strict validation and dependency audit must still pass on the exact release candidate. Production publication also requires an independently trusted Ed25519 release public key, completed adversarial/fuzzing gates, Windows/XAMPP and real-browser QA, and explicit release approval. Do not bypass a failing lockfile or audit gate. The stable binary format remains isolated in PR #38; the production writer has not been switched.
