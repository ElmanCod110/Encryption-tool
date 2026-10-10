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
| Composer manifest | `composer validate --strict --no-check-publish` | Manifest validates strictly | NOT RUN — record CI run |
| Dependency audit | `composer audit --no-interaction` | No unreviewed advisories | BLOCKED until a real `composer.lock` is committed |
| PHP syntax | `find app bin public tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l` | Every PHP file parses | NOT RUN — record CI run |
| JavaScript syntax | `find public/client -type f -name '*.js' -print0 | xargs -0 -n1 node --check` | Every JavaScript file parses | NOT RUN — record CI run |
| Runtime self-check | `php bin/self-check.php` | Required runtime capabilities pass | NOT RUN — record CI run |
| Source audit | `php bin/source-audit.php` | Source audit exits successfully | NOT RUN — record CI run |
| Full security suite | `php bin/security-test.php --full` | Security suite exits successfully | NOT RUN — record CI run |
| PHP regression tests | `for test in tests/*.php; do php "$test" || exit 1; done` | Every PHP test exits successfully | NOT RUN — record CI run |
| Browser V13 round-trip | `node tests/BrowserV13RoundTripTest.mjs` | Compatibility test passes | NOT RUN — record CI run |

The CI workflow may run some of these checks automatically. Link the actual Actions run rather than copying a previous result or marking this table PASS by assumption. The current endpoint response mapping and known error-contract gaps are tracked in [API Error Contract Audit](API-ERROR-CONTRACT.md); use that audit to add concrete integration scenarios rather than treating source-text checks as end-to-end proof.

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

**Current status:** this document is a test plan, not a claim that the listed manual scenarios have passed. The missing root `composer.lock` remains a release blocker until a genuine lockfile is generated with Composer, reviewed, and committed.
