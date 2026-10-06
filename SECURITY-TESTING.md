# V12 Security Testing

V12 separates fast security gates from the full historical regression suite because some legacy cryptographic tests intentionally use expensive password hashing parameters.

## Fast gate

```bash
php bin/security-test.php
```

The fast gate covers:

- deterministic canonical JSON
- 10,000 canonicalization fuzz cases
- malformed package identifier cases
- replay protection
- replay race behavior
- encrypted build-state envelope
- V12 format invariants
- archive path policy
- source security audit
- runtime security diagnostics

## Full regression

```bash
php bin/security-test.php --full
```

The full command additionally runs the historical generation tests. Duration depends strongly on the configured password-hashing cost and CPU/RAM resources.

## Source audit

```bash
php bin/source-audit.php
```

This scans the application tree for accidental legacy branding, private-key markers, and a conservative list of dangerous dynamic execution calls.

## Release integrity

```bash
php tests/ReleaseIntegrityTest.php
php bin/verify-release.php .
```

These verify the Ed25519-signed release manifest and SHA-256 asset hashes.

## Benchmark

```bash
php bin/benchmark.php
```

The benchmark reports local AEAD throughput. It is a diagnostic, not a security claim or cross-machine performance guarantee.
