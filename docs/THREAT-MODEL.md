# SPKG Threat Model

## Security boundary

SPKG protects package bytes stored at rest. It does not make a hosted server blind to source data.

- **Hosted deployment:** PHP receives the source archive and supplied password/pattern, extracts source files, builds the encrypted SPKG, and later restores plaintext on the server before offering the restore archive. A compromised host, malicious administrator, vulnerable PHP process, or server-side code execution can access plaintext and live credentials.
- **Local XAMPP deployment:** processing remains local only while the application, PHP runtime, browser, and storage are on the user's own machine and no remote service is used.
- **Stored package:** the file contains encrypted records and a protected manifest. The random package identifier, salt, bounded KDF parameters, recovery-slot presence, record counts, file sizes, and total package length may be observable. Filenames and directory graph are protected by the encrypted manifest.
- **Offline attacker:** someone who obtains a package can attempt offline password/pattern guesses. Argon2id raises the cost per attempt but does not make weak credentials safe.
- **Endpoint attacker:** malware, a compromised browser, keylogger, or local administrator can capture credentials or restored plaintext.
- **Filesystem attacker:** symlink, path traversal, destination collision, tampering, and malformed manifest attacks are in scope for parser and restore checks. PHP does not provide a fully portable race-free openat/O_NOFOLLOW directory walk; hostile concurrent source-tree mutation remains a documented limitation.

## Assets

- Source files and restored plaintext
- Password, pattern, recovery key, and random 256-bit package root key
- Encrypted package bytes and protected manifest
- Package ownership, expiry, revocation, and download-token state
- Audit integrity and application configuration

## Security goals

1. Use Argon2id with bounded, allowlisted parameters for credential derivation.
2. Separate keys with HKDF-SHA-256 and authenticate wrapped root-key slots.
3. Authenticate file streams, sequence/order, declared sizes, and the final encrypted manifest.
4. Reject malformed headers, oversized records, truncation, trailing bytes, unsafe names, invalid graph structure, and authentication failures before exposing restored output.
5. Never overwrite an existing restore destination or silently retry a legacy parser.
6. Keep stored packages outside the public document root, use private staging, owner-scoped catalog operations, CSRF protection, rate limiting, and short-lived access/restore tokens.
7. Make legacy compatibility boundaries explicit; never infer format identity from the extension alone.

## Residual risks

- A compromised hosted server or malicious administrator observing live plaintext/credentials.
- Weak credentials and offline guessing against a copied package.
- Secure deletion limitations on SSDs, snapshots, backups, or copy-on-write filesystems.
- Compromise of the PHP runtime, OS, browser, Composer dependencies, or deployment configuration.
- Portable elimination of every filesystem TOCTOU race.
- Sender identity: authenticated encryption does not prove who created or sent a package. Use a separately trusted signature/channel when origin authenticity matters.

## Validation status

Automated tests cover the binary format and adversarial parser/restore behavior. CI is not a substitute for real XAMPP/shared-hosting benchmarks, supported-browser/manual testing, or an independent cryptographic review. Any test not run on the target environment must be marked NOT RUN.
