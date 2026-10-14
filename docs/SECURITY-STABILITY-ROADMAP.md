# Security and Stability Roadmap — V1.0.0 Initiative

> **Status:** Initial implementation and verification in progress  
> **Current stable release:** `v0.14.1`  
> **Important:** Initial fixes and regression tests are now being added in small commits. The branch is not release-ready, and no fix is considered fully verified until the relevant tests pass.

## Initial implementation progress — 2026-10-14

- Connected the stricter archive path policy to the actual extraction workflow and added an integration regression test for a path containing a colon.
- Added root-to-child archive depth tracking, enforced `maxDepth`, and added a nested-archive regression test.
- Added plaintext job cleanup after successful package creation and an attempted cleanup after build failures; cleanup now checks whether the job path remains.
- Added a build-cleanup regression check.
- Added the missing archive staging-directory cleanup method after the integration test exposed its absence.

**Validation note:** An earlier CI run exposed a missing cleanup method and a later run exposed a PHP namespace-separator syntax error in that method. Both were corrected in subsequent commits. The latest branch still requires a fresh successful CI run before these changes can be considered validated.

## Phase 2 progress — 2026-10-14

The first API/authentication hardening pass is being reviewed in PR #18 (`security/phase-2-api-auth-hardening`).

- Single-use download tokens now persist a consumed marker while holding the exclusive lock, preventing concurrent replay against an already-open inode.
- Account storage now rejects malformed or structurally invalid JSON rather than treating it as an empty account list; password-hash rehash writes use the account-store lock.
- Session naming now uses PHP's `session_name()` API; URL-based session propagation is disabled.
- API actions enforce POST and the expected request media type.
- Package catalog create/expiry/revoke/delete operations serialize with per-package locks, and catalog reads validate record shape.
- Regression tests cover token replay, corrupt account storage, session settings, and catalog mutation/ownership.
- CI has started for PR #18. The phase is not considered verified until the latest branch head passes all applicable workflows and live HTTP tests are added.

See [Phase 2 API and Authentication Audit](PHASE-2-API-AUTH-AUDIT.md) for finding-level evidence and remaining work.

## Goals

Prepare the project for a carefully validated V1.0.0 milestone by reviewing security-sensitive code paths, fixing confirmed defects, and recording reproducible test evidence.

## Work sequence

1. **Establish a baseline**
   - Inspect the current source tree and existing security documentation.
   - Run the available self-check, source audit, and security test suites.
   - Record exact commands, results, environment, and any tests that could not run.

2. **Review high-risk boundaries**
   - Plaintext lifecycle, temporary files, cleanup, and secret handling.
   - Archive/package parsing, nested archives, path validation, and resource limits.
   - Authentication, authorization, quotas, and rate limiting where applicable.
   - Password and pattern handling, credential derivation, and error behavior.
   - CLI, browser/V13 compatibility, CI, dependency integrity, and release workflow.

3. **Verify before changing**
   - Reproduce each reported issue against the current code.
   - Distinguish confirmed vulnerabilities from hypotheses or environment-specific observations.
   - Avoid treating an audit report as proof until its claims have been checked.

4. **Fix in small, reviewable changes**
   - Address confirmed high-impact issues first.
   - Keep changes focused and avoid unrelated rewrites.
   - Add regression tests for each confirmed defect.
   - Preserve compatibility boundaries unless a deliberate migration is documented.

5. **Validate release readiness**
   - Run the project self-checks, source audit, full security tests, JavaScript syntax checks, Composer validation, and dependency audit where supported.
   - Complete the manual release QA matrix; do not mark untested scenarios as passed.
   - Review deployment defaults, secret handling, release notes, and versioning.
   - Publish V1.0.0 only when its release criteria are met.

## Evidence log

For each finding, record:

- Identifier and severity
- Affected file/function and relevant code path
- Reproduction steps and observed result
- Fix commit and regression test
- Validation command and actual result
- Remaining limitations or follow-up work

## Release principle

A version number or release title is not evidence of security. Security and stability claims must match the code that was changed and the tests that were actually completed.
