# Reproducible Release QA Matrix

This checklist separates automated checks from manual deployment and browser checks. A checkbox is not evidence of a pass: record the run URL, environment, date, and outcome when the test is actually performed.

## Result vocabulary

- **PASS** — the documented procedure ran and the expected result was observed.
- **FAIL** — the procedure ran and exposed a defect.
- **NOT RUN** — no result has been collected. Keep this status until evidence exists.
- **BLOCKED** — the procedure could not run because a prerequisite was unavailable; record the blocker.

Do not put real user data, passwords, patterns, recovery keys, plaintext, or production secrets in evidence.

## Automated checks

For a local checkout with PHP 8.2+ and the required extensions:

| Check | Procedure | Expected result | Result / evidence |
| --- | --- | --- | --- |
| Composer manifest | `composer validate --strict --no-check-publish` | Manifest validates strictly | PASS in lockfile generator run; rerun on final candidate |
| Dependency audit | `composer audit --no-interaction` | No unreviewed advisories | PASS in lockfile generator run; no advisories reported; rerun on final candidate |
| PHP syntax | `find app bin public tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l` | Every PHP file parses | PASS on commit `2737b0e`; [CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983); rerun on final candidate |
| JavaScript syntax | `find public/client -type f -name '*.js' -print0 | xargs -0 -n1 node --check` | Every JavaScript file parses | PASS on commit `2737b0e`; [CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983); rerun on final candidate |
| Runtime self-check | `php bin/self-check.php` | Required runtime capabilities pass | PASS on commit `2737b0e`; [CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983); rerun on final candidate |
| Windows smoke suite | Windows runner: Composer validation/audit, PHP syntax, self-check, source audit, V14 round-trip/restore safety, archive tests, and browser V13 automated round-trip | All listed checks pass on Windows | PASS on commit `2737b0e`; [Windows CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983); this does not replace manual XAMPP QA |
| Source audit | `php bin/source-audit.php` | Source audit exits successfully | PASS on commit `2737b0e`; [Security and Release Integrity run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330991); rerun on final candidate |
| Full security suite | `php bin/security-test.php --full` | Full regression/security suite exits successfully | PASS on commit `2737b0e`; [Security and Release Integrity run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330991); rerun on final candidate |
| PHP regression tests | `for test in tests/*.php; do php "$test" || exit 1; done` | Every PHP test exits successfully | PASS on commit `2737b0e`; [CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983); rerun on final candidate |
| Archive no-overwrite | `php tests/V14PackageArchiveTest.php` | Existing destination remains byte-for-byte unchanged and publication fails closed | PASS on `2737b0e`; [CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983) |
| Release signer external trust root | `php tests/ReleaseSignerExternalTrustTest.php` | Generated-key signature verifies against a separately supplied public key | PASS on `2737b0e`; [Linux/Windows CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983) |
| Package deletion rollback | `php tests/PackageDeleteRollbackTest.php` | Staging precedes revocation/catalog deletion and rollback is attempted on pre-commit failure | PASS on `2737b0e`; [CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38730330983) |
| Browser V13 round-trip | `node tests/BrowserV13RoundTripTest.mjs` | Compatibility test passes | PASS on commit `f3b8c1c`; [Security and Release Integrity run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38725570471); this is automated coverage, not a real-browser manual test |
| Signed release artifact / external trust root | Build and verify a signed release artifact with an independently distributed public key | Signature and file hashes verify | NOT RUN — the current development tree is unsigned; the signature test skipped |

Evidence on the last fully green tested commit is `f3b8c1c`. It passed [CI](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38725570267), [Client Security](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38725570377), and [Security and Release Integrity](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38725570471). The exact current candidate must be retested after documentation changes. [CI](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38725570267), [Client Security](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38725570377), and [Security and Release Integrity](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38725570471) all passed for that commit. The Composer-generated lockfile was strictly validated and audited in [the lockfile generation workflow](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38636009471). The generated-lock PR passed [CI](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38636121662), [Client Security](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38636121633), and [Security and Release Integrity](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38636121775). These results apply to the generated-lock PR head; rerun checks on the final candidate commit. The CI workflow may run some of these checks automatically. Link the actual Actions run rather than copying a previous result or marking this table PASS by assumption. The current endpoint response mapping and known error-contract gaps are tracked in [API Error Contract Audit](API-ERROR-CONTRACT.md); use that audit to add concrete integration scenarios rather than treating source-text checks as end-to-end proof.

## Composer lockfile review

The root composer.lock was generated by Composer in [the lockfile generation workflow](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38636009471), not hand-written. Strict manifest/lock validation and composer audit passed in that run; the audit reported no advisories at the time of generation.

| Review item | Observed result |
| --- | --- |
| Runtime packages | 0 external Composer packages; runtime requirement is PHP >= 8.2 |
| Development packages | 64 locked packages |
| Declared package licenses | 39 MIT, 25 BSD-3-Clause; no package had an unspecified license field |
| Composer plugins | Disabled in composer.json |
| Reproducibility | CI uses composer install when the lockfile exists; release-readiness checks require the committed lockfile |

This inventory is based on the committed lockfile metadata and is not a substitute for a legal review. Re-run validation and the dependency audit on the exact release candidate because package advisories and dependency metadata can change over time.

## Windows / XAMPP deployment

Record the Windows version, XAMPP version, PHP version, enabled extensions, and tested commit.

| Scenario | Procedure / expected result | Result / evidence |
| --- | --- | --- |
| Fresh setup | Follow the deployment guide from a clean checkout; setup completes without manual source edits | NOT RUN |
| Runtime requirements | Confirm PHP 8.2+, Sodium, and Zip are available; self-check reports required capabilities | NOT RUN |
| Storage permissions | Create, read, and remove a disposable test artifact using the configured storage location; no broader permissions are needed | NOT RUN |
| Restart behavior | Restart Apache and repeat the health/self-check procedure; configuration remains usable | NOT RUN |
| Missing extension | Disable a required extension in a disposable test environment; startup/check fails clearly without leaking secrets | NOT RUN |
| Disk or permission failure | Use a disposable unwritable/full test destination where safely reproducible; operation fails cleanly and reports no false success | NOT RUN |

## Server package build and restore

Use disposable fixtures only. Never use production data or real credentials.

| Scenario | Expected result | Result / evidence |
| --- | --- | --- |
| Password + pattern | A package created with the intended credential flow restores the exact fixture | NOT RUN |
| Independent recovery key | The documented recovery flow restores the fixture independently of the normal credential path | NOT RUN |
| Wrong password / pattern | Restore fails safely; no plaintext is emitted | NOT RUN |
| Wrong recovery key | Recovery fails safely; no plaintext is emitted | NOT RUN |
| Empty file and nested directories | Restored structure and file contents match the fixture | NOT RUN |
| Unicode filenames | Unicode names and contents survive the round trip on the tested filesystem | NOT RUN |
| File size boundaries | Valid files within configured limits work; over-limit files are rejected before unsafe resource use | NOT RUN |
| Existing destination collision | Restore refuses to overwrite existing files or directories | NOT RUN |
| Malformed or truncated package | Restore rejects the input and cleans temporary artifacts | NOT RUN |
| Tampered header, blob, or manifest | Integrity verification rejects modified data before restored output is accepted | NOT RUN |
| Interrupted write / extraction | Operation reports failure and removes incomplete temporary output where safe | NOT RUN |

## Browser compatibility package

Run in real browsers; JavaScript syntax checks alone are not browser compatibility evidence.

Record browser name/version, operating system, commit, and console errors.

| Scenario | Expected result | Result / evidence |
| --- | --- | --- |
| Browser V13 build and restore | Browser package round-trips a disposable fixture | NOT RUN |
| Format boundary | Browser V13 package is not accepted as a server V14 package, and vice versa unless explicitly documented | NOT RUN |
| Wrong credentials and tampering | Operation fails without exposing plaintext or secret values | NOT RUN |
| Keyboard-only navigation | Controls can be reached and used with a keyboard; focus remains visible | NOT RUN |
| Responsive layout | Main and browser compatibility views remain usable at narrow and wide viewport sizes | NOT RUN |
| Reduced motion | Reduced-motion preference is respected | NOT RUN |
| Error states | Failure messages are understandable and do not expose stack traces, filesystem paths, or secrets | NOT RUN |

## Release evidence

Before marking a release ready, attach or link:

- CI workflow run(s) for the exact candidate commit.
- Dependency validation and audit output from the committed lockfile.
- Windows/XAMPP manual results.
- Browser manual results for supported browsers.
- Reproducible steps and sanitized logs for any FAIL or BLOCKED result.
- A release note listing any untested platforms, known limitations, and outstanding blockers.

**Current status:** automated Linux and Windows smoke checks passed on commit `f3b8c1c`; this document is still a test plan, not a claim that the listed manual scenarios have passed. A genuine Composer-generated `composer.lock` is present on the release-readiness branch, and its generator validation/audit plus PR CI passed. Re-run automated checks on the final candidate. Windows/XAMPP and real-browser scenarios remain **NOT RUN** until evidence is recorded.
