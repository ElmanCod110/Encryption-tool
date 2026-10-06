# Secure Package — Hardening Roadmap

## Stage 0 — Completed

- Atomic login/rate-limit admission.
- IP and username-bound login throttling.
- Username-enumeration timing mitigation.
- Request-body size gates using both declared and actual byte counts.
- Upload ownership checks before global chunk-store mutation.
- Upload/chunk admission limits.
- Actual-byte ZIP extraction limits.
- Portable archive path validation and case-insensitive collision checks.
- External release trust-root support in the verifier.
- Active V13 JavaScript syntax checks in CI.
- Regression tests for the implemented controls.
- Legacy V7–V12 browser/API/source material moved under `archive/legacy/`.

## Stage 1 — V13 package parser and integrity hardening — Completed

- Strict header/footer parser with bounded reads.
- Exact V13 KDF parameter allowlist before derivation.
- Manifest count, size, path, and identifier limits.
- Exact chunk metadata schema validation.
- Duplicate file/chunk/path rejection.
- Indexed manifest chunk lookup to avoid quadratic validation.
- Incremental Merkle verification to avoid retaining all leaf hashes.
- Full package integrity verification before filesystem writes.
- Fail-on-existing restore semantics.
- Preflight path-topology collision checks before output mutation.
- Zero-byte file support with correct AES-GCM tag-length accounting.
- Secret lifetime minimization in the browser worker.

## Stage 2 — Cryptographic profile — In progress

- Browser profile currently uses PBKDF2-HMAC-SHA-256 through standards-based Web Crypto.
- Evaluate a vetted Argon2id WebAssembly implementation or a future format profile with independently reviewed test vectors.
- Add formal nonce-context uniqueness/property tests.
- Expand explicit authenticated metadata coverage.
- Add key rotation semantics and multiple-recipient design only after the core V13 profile is stable.

## Stage 3 — Identity and access control

- WebAuthn/passkey second factor for administration.
- Device/session inventory and revocation.
- Distributed rate limiting.
- Per-account and global resource quotas.
- Abuse-resistant cleanup and revocation jobs.

## Stage 4 — Supply-chain assurance

- Commit `composer.lock`.
- Use locked dependency installation in CI.
- Keep `composer audit` blocking.
- Pin GitHub Actions to immutable commit SHAs.
- Reproducible release pipeline.
- SBOM and provenance.
- Hardware-backed release signing.
- Independent release-key distribution documentation.

## Stage 5 — Adversarial verification

- Structured parser fuzzing.
- Differential V12/V13 reader testing during migration window.
- Large-file and memory-pressure stress tests.
- Concurrent upload/rate-limit race tests.
- ZIP bomb and nested archive corpora.
- Windows/Linux path-collision corpus.
- Fault injection for atomic writes and finalization.
- Browser cryptographic worker fault-injection tests.

## Stage 6 — Operational security

- HTTPS-only production mode.
- HSTS at the reverse proxy.
- Private storage outside the public root.
- Central audit-log anchoring.
- Backup/restore runbooks.
- Key rotation runbooks.
- Incident-response and disclosure procedures.

## Stage 7 — Independent review

The final security claim should be based on independent code review and penetration testing against the documented threat model, not an internal percentage score.
