# V11 Threat Model

V11 focuses on large-file reliability while preserving the V10 server-blind boundary.

## Protected

- Password and pattern.
- Content root key.
- Plaintext files and paths.
- Recovery secret.
- Package integrity.

## Server trust boundary

The server receives ciphertext, opaque identifiers and operational metadata required for storage. It must not receive browser plaintext or credential secrets during the V11 local workflow.

## New risks

- Disk exhaustion from very large packages.
- Browser crashes during long builds.
- Interrupted uploads.
- Duplicate chunk races.
- Partial package files.
- Resource exhaustion through pathological package indexes.

## Mitigations

- Explicit file and package limits.
- Bounded chunk buffers.
- Incremental hashing and Merkle accumulation.
- Atomic checkpoint state.
- Per-upload locking.
- Idempotent chunk storage.
- Strict count/size validation.
- Expiring upload sessions.
- Fail-closed package parsing.

## Residual risks

A compromised web origin can still replace browser code before execution. V11 therefore relies on release integrity, CSP, SRI, dependency pinning and external deployment controls in addition to cryptographic design.
