# Secure Package V12 Threat Model

## Assets

- Plaintext files
- Original filenames and paths
- Password
- Pattern
- Recovery credentials
- Package integrity
- Upload ownership and lifecycle state

## Adversaries

### Offline package attacker

The attacker can obtain the complete `.spk12` file and the source code.

Expected result: without valid credentials, the package cannot yield authenticated plaintext.

### Server storage attacker

The attacker can read stored ciphertext chunks and operational metadata.

Expected result: server storage alone must not reveal plaintext or credentials.

### Network attacker

The attacker can observe or interrupt ciphertext transport.

Expected result: transport is TLS-dependent and ciphertext is independently authenticated.

### Malicious client input

The attacker can supply malformed files, paths, package records, and upload metadata.

Expected result: validators fail closed and bounded resource policies prevent unbounded processing.

### Compromised web origin

A hostile server can attempt to deliver modified client JavaScript.

This remains an important trust boundary. V12 reduces supply-chain risk with CSP, same-origin loading, release integrity tooling, and no third-party crypto scripts, but a compromised origin can still undermine a browser application.

## Explicit non-goals

- Absolute security guarantees
- Protection against a fully compromised endpoint device
- Recovery of forgotten credentials
- Hiding all traffic-level information such as total ciphertext transfer size

## Security invariants

1. Plaintext credentials never become server package fields.
2. Browser-built V12 package data is authenticated.
3. Ciphertext chunk identifiers are content-derived and verified.
4. Upload sessions are owner-bound.
5. Replayable one-time operation state is guarded.
6. Release source and assets can be audited independently.
7. Sensitive build-state keys are rejected by schema validation.
