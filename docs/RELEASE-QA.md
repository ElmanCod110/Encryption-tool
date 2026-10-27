# Reproducible Release QA Matrix

This checklist separates automated checks from manual deployment and browser checks. A checkbox is not evidence of a pass: record the run URL, environment, date, commit and outcome when the test actually runs.

## Result vocabulary

- **PASS** — the documented procedure ran and the expected result was observed.
- **FAIL** — the procedure ran and exposed a defect.
- **NOT RUN** — no result has been collected. Keep this status until evidence exists.
- **BLOCKED** — the procedure could not run because a prerequisite was unavailable; record the blocker.

Never place real user data, passwords, patterns, recovery keys, plaintext, or production secrets in evidence.

## Automated checks

For a clean checkout with PHP 8.2+ and required extensions:

| Check | Procedure | Expected result | Candidate status |
| --- | --- | --- | --- |
| Composer manifest and lock | `composer validate --strict --no-check-publish` | Manifest and committed lockfile agree | NOT RUN for a final release candidate; CI must validate the exact head |
| Dependency audit | `composer audit --no-interaction` | No unreviewed advisories | NOT RUN for the final candidate; a Composer-generated `composer.lock` is now present on the reconciliation branch |
| PHP syntax | `find app bin public tests -type f -name '*.php' -print0 \| xargs -0 -n1 php -l` | Every PHP file parses | Run linked CI for the exact head |
| JavaScript syntax | `find public/client -type f -name '*.js' -print0 \| xargs -0 -n1 node --check` | Every JavaScript file parses | Run linked CI for the exact head |
| Runtime self-check | `php bin/self-check.php` | Required runtime capabilities pass | Run linked CI for the exact head |
| Source audit | `php bin/source-audit.php` | Source audit exits successfully | Run linked CI for the exact head |
| Full security suite | `php bin/security-test.php --full` | Full security/regression suite exits successfully | Run linked CI for the exact head |
| PHP regression suite | `for test in tests/*.php; do php "$test" || exit 1; done` | Every PHP test exits successfully | Run linked CI for the exact head |
| Windows smoke | CI workflow `windows-smoke` job | Composer lock validation/audit, PHP syntax, runtime self-check, source audit, V14 round-trip/restore/archive safety, browser V13 round-trip, and external-trust-root signer test pass on a Windows runner | Run linked CI for the exact head |
| Browser V13 round-trip | `node tests/BrowserV13RoundTripTest.mjs` | Compatibility regression passes | Run linked CI for the exact head |
| Stable binary format | `php tests/StablePackageFormatTest.php` | Fixture, adversarial and round-trip assertions pass | Require the PHP 8.2/8.3 and Windows stable-format jobs on the exact PR #38 head; local XAMPP/shared-hosting behavior remains NOT RUN and this format is not the production/default writer |
| Stable-format KDF budget | Benchmark the fixed default (3 operations, 256 MiB) and maximum accepted KDF cost under supported PHP, Windows, XAMPP/shared hosting, and concurrent failed unlocks | No unexpected process termination or host memory exhaustion; latency fits the deployment budget | NOT RUN on a real target host; do not change the binary KDF profile without a reviewed compatibility/security decision |
| Catalog-list integrity | `php tests/PackageCatalogListingTest.php` | Corrupt or symlinked catalog records are rejected, not silently skipped | Run linked CI for the exact head |
| Upload cleanup | `php tests/ResumableUploadCleanupTest.php` | Owned files are removed, nested symlinks are not followed, failures are surfaced | Linux coverage added; Windows/shared-hosting confirmation NOT RUN |
| Signed release artifact | Build and verify with an independently distributed trusted public key | Signature and hashes verify independently of the build tree | NOT RUN; no v1.0.0 release artifact has been signed and published |

A Composer-generated lockfile was reused from the readiness work because the current `composer.json` has the same blob SHA as that candidate's manifest. The lockfile is committed on the reconciliation branch; strict validation and dependency audit still must pass in CI on the exact candidate. Do not mark the current candidate PASS based on an older Actions run.

## Windows / XAMPP deployment

Record the Windows and XAMPP versions, PHP version, enabled extensions, commit, and test evidence.

| Scenario | Expected result | Result |
| --- | --- | --- |
| Fresh setup from a clean checkout | Setup completes without source edits | NOT RUN |
| Runtime requirements | PHP 8.2+, Sodium and Zip are present; self-check is clear | NOT RUN |
| Storage permissions | Disposable create/read/remove succeeds without broad permissions | NOT RUN |
| Restart behavior | Apache restart does not invalidate configuration or normal operation | NOT RUN |
| Missing extension | A required extension causes a clear, generic failure without secrets leaking | NOT RUN |
| Disk/permission failure | Failed operations report no false success and clean owned temporary data | NOT RUN |
| Stable-format round trip | Candidate writer and reader operate correctly on Windows filesystems | NOT RUN for local Windows/XAMPP |
| Stable-format KDF resource budget | KDF unlock cost and peak memory remain within the actual host limits, including concurrent invalid attempts | NOT RUN; GitHub Windows CI is not a substitute for the target shared-hosting budget |

## Server package build and restore

Use disposable fixtures only. Never use production data or credentials.

| Scenario | Expected result | Result |
| --- | --- | --- |
| Password and pattern | Exact fixture round trip | NOT RUN manually |
| Recovery-key flow | Recovery independently restores the fixture | NOT RUN manually |
| Wrong password/pattern or recovery key | Restore fails safely; no plaintext or secret is returned | Automated tests exist; re-run on final candidate |
| Empty files and nested directories | Structure and content match source | Automated coverage exists; manual cross-platform confirmation NOT RUN |
| Unicode filenames | Documented normalization/fallback rules hold on the tested filesystem | Linux regression coverage exists; Windows confirmation NOT RUN |
| Size and count boundaries | Over-limit input is rejected before unsafe resource use | Automated coverage exists; re-run on final candidate |
| Existing destination | Existing files/directories remain untouched | Automated no-overwrite tests exist; re-run on final candidate |
| Malformed/truncated/tampered package | Rejected; no incomplete plaintext output remains | Automated regression coverage exists; re-run on final candidate |
| Interrupted extraction/cleanup failure | Remaining owned temporary data is detected and cleanup failure is surfaced | Automated tests exist; cross-platform confirmation NOT RUN |

## Browser compatibility

Run in real browsers; JavaScript syntax tests alone are not browser compatibility evidence. Record the browser name/version, OS, commit and console errors.

| Scenario | Expected result | Result |
| --- | --- | --- |
| Browser V13 build and restore | Browser package round-trips a disposable fixture | Automated regression exists; real-browser test NOT RUN |
| V13/V14 format boundary | Formats are not silently reinterpreted | NOT RUN manually |
| Wrong credentials and tampering | No plaintext or secrets leak | Automated regression exists; real-browser test NOT RUN |
| Keyboard navigation | All controls work and visible focus is retained | NOT RUN |
| Responsive layout | Views remain usable at narrow and wide viewports | NOT RUN |
| Reduced motion | Reduced-motion preference is respected | NOT RUN |
| Error states | Messages are understandable without stack traces, paths or secrets | NOT RUN |

## Release evidence required

Before release approval, attach:

- CI runs for the exact release-candidate commit.
- Strict Composer validation and dependency audit from the committed lockfile.
- Windows/XAMPP manual results.
- Real-browser compatibility and accessibility results.
- Signed release artifact and independent trusted public key/checksum verification.
- Sanitized reproduction/evidence for every FAIL or BLOCKED result.
- Release notes that describe untested platforms, limitations and outstanding blockers.

**Current decision:** this document is a test plan, not a claim that the listed manual scenarios have passed. This branch remains an integration/reconciliation draft, not a release candidate. PR #21 remains open and must not be merged without explicit approval. Windows/XAMPP and real-browser validation, independent security review and signed release-artifact verification remain release blockers. Do not change the default writer or create/publish a v1.0.0 tag or release until the explicit release gates are satisfied.
