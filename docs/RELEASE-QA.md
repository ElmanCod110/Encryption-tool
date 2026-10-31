# Reproducible Release QA Matrix

This checklist separates automated checks from manual deployment and browser checks. A checkbox is not evidence of a pass: record the run URL, environment, date, and outcome when the test is actually performed.

This matrix is not a claim that the listed manual scenarios have passed. Manual scenarios remain NOT RUN until their results are supported by recorded evidence.

## Result vocabulary

- **PASS** — the documented procedure ran and the expected result was observed.
- **FAIL** — the procedure ran and exposed a defect.
- **NOT RUN** — no result has been collected. Keep this status until evidence exists.
- **BLOCKED** — the procedure could not run because a prerequisite was unavailable; record the blocker.

Do not put real user data, passwords, patterns, recovery keys, plaintext, or production secrets in evidence.

## Automated checks

Candidate commit: `b79b852dc5561c6250a314a0a35e1923d1b912f8` (31 October 2026).

| Check | Procedure | Expected result | Result / evidence |
| --- | --- | --- | --- |
| Composer manifest | `composer validate --no-check-publish` | Manifest validates | **PASS** — [Security and Release Integrity run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783386), php-security job |
| Strict Composer lock validation | `composer validate --strict --no-check-publish` | A committed lock and manifest validate strictly | **BLOCKED** — no root `composer.lock` is committed; the release workflow correctly refuses to treat an unlocked dependency graph as release-ready |
| Dependency audit | `composer audit --no-interaction` | Locked dependency graph has no unreviewed advisories | **BLOCKED** — a genuine reviewed lockfile is still required; the passing CI dependency step is not evidence for a locked graph |
| PHP syntax | `find app bin public tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l` | Every PHP file parses | **PASS** — [CI run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783054), PHP 8.2 and 8.3; also [release gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| JavaScript syntax | `find public/assets -type f -name '*.js' -print0 | xargs -0 -n1 node --check` | Every active JavaScript file parses | **PASS** — [Client Security run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783106) |
| Runtime self-check | `php bin/self-check.php` | Required runtime capabilities pass | **PASS** — [Security and Release Integrity run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783386) and [release gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Source audit | `php bin/source-audit.php` | Source audit exits successfully | **PASS** — [Security and Release Integrity run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783386) and [release gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Full security suite | `php bin/security-test.php --full` | Security suite exits successfully | **PASS** — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118), PHP 8.2 and 8.3 |
| PHP regression tests | `for test in tests/*.php; do php "$test" || exit 1; done` | Every PHP test exits successfully | **PASS** — [CI run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783054) and [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Active SPKG routing boundary | `php tests/ActiveSpkgRoutingTest.php` | API, download, and UI do not expose active legacy readers | **PASS** — [Client Security run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783106) and [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Windows icon safeguards | `php tests/WindowsSpk13IconIntegrationTest.php` plus PowerShell parse | The optional per-user icon association validates a real ICO and fails safely | **PASS** — [CI run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783054) |
| Unicode fail-closed fallback | `php -n tests/StablePackageUnicodeFallbackTest.php` | Unsupported optional Unicode runtime fails closed | **PASS** — [CI run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783054) and [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |

The listed Actions runs completed successfully for the candidate commit. They establish automated CI results only; they do not establish Windows/XAMPP deployment, shared-hosting performance, real-browser behavior, or independent cryptographic review. The current endpoint response mapping and known error-contract gaps are tracked in [API Error Contract Audit](API-ERROR-CONTRACT.md); broad exception catches still need a deliberate typed-error treatment and live HTTP failure tests.

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

## SPKG package build and restore

Use disposable fixtures only. Never use production data or real credentials.

| Scenario | Expected result | Result / evidence |
| --- | --- | --- |
| Password + pattern | A package created with the intended credential flow restores the exact fixture | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118); manual XAMPP/hosted validation NOT RUN |
| Independent recovery key | The documented recovery flow restores the fixture independently of the normal credential path | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118); manual XAMPP/hosted validation NOT RUN |
| Wrong password / pattern | Restore fails safely; no plaintext is emitted | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118); manual deployment validation NOT RUN |
| Wrong recovery key | Recovery fails safely; no plaintext is emitted | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118); manual deployment validation NOT RUN |
| Empty file and nested directories | Restored structure and file contents match the fixture | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Unicode filenames | Unicode names and contents survive the round trip on the tested filesystem | Automated regression PASS for supported CI runtime; Windows/XAMPP filesystem validation NOT RUN |
| File size boundaries | Valid files within configured limits work; over-limit files are rejected before unsafe resource use | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Existing destination collision | Restore refuses to overwrite existing files or directories | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Malformed or truncated package | Restore rejects the input and cleans temporary artifacts | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Tampered header, blob, or manifest | Integrity verification rejects modified data before restored output is accepted | Automated regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Interrupted write / extraction | Operation reports failure and removes incomplete temporary output where safe | Automated regression PASS for covered injected-failure tests; real disk-full/power-loss scenarios NOT RUN |

## Browser compatibility package

Run in real browsers; JavaScript syntax checks alone are not browser compatibility evidence.

Record browser name/version, operating system, commit, and console errors.

| Scenario | Expected result | Result / evidence |
| --- | --- | --- |
| Standalone local CLI round-trip | `php tests/LocalCliSpkgTest.php` creates/restores `.spkg` without a web server and uses hidden credential prompts | Automated Linux CLI regression PASS — [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118); Windows/XAMPP CLI test NOT RUN |
| Legacy-format refusal | `php tests/ApiHttpIntegrationTest.php` and `node tests/LegacyBrowserRetirementTest.mjs` reject legacy routes and parser assets | Automated HTTP and source-boundary regression PASS — [Client Security run #1351](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783106) and [SPKG v1 Release Gate run #343](https://github.com/ElmanCod110/Encryption-tool/actions/runs/41109783118) |
| Wrong credentials and tampering | Operation fails without exposing plaintext or secret values | Automated regression PASS; real-browser behavior NOT RUN |
| Keyboard-only navigation | Controls can be reached and used with a keyboard; focus remains visible | NOT RUN |
| Responsive layout | Main workspace remains usable at narrow and wide viewport sizes | NOT RUN |
| Reduced motion | Reduced-motion preference is respected | NOT RUN |
| Error states | Failure messages are understandable and do not expose stack traces, filesystem paths, or secrets | NOT RUN — live browser checks and the API error-contract follow-up remain |

## Release evidence

Before marking a release ready, attach or link:

- CI workflow runs for the exact candidate commit (linked above).
- Dependency validation and audit output from a genuine committed lockfile.
- Windows/XAMPP and target shared-hosting manual results.
- Real-browser manual results for supported browsers.
- Independent cryptographic format review.
- Reproducible steps and sanitized logs for any FAIL or BLOCKED result.
- A release note listing any untested platforms, known limitations, and outstanding blockers.

**Current status:** automated CI and regression checks pass on the candidate commit, but this is not a release approval. A genuine root `composer.lock`, XAMPP/hosted deployment and resource tests, real-browser QA, the API error-contract follow-up, and independent cryptographic review remain outstanding. Keep the PR in Draft and do not publish v1.0.0 until the required gates are closed.
