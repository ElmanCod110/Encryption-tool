# Initial Security Audit Findings

**Audit status:** Initial archive/storage fixes from PR #17 are merged to `master`; phase-2 API/auth fixes are under review in PR #18.  
**Reviewed baseline:** `master` after merge commit `75c413172d39118e1b886166e3c96c4ca0aff494`; phase-2 findings are tracked separately in [Phase 2 API and Authentication Audit](PHASE-2-API-AUTH-AUDIT.md).  
**Runtime validation:** CI is running for PR #18; manual production-host validation remains NOT RUN.  
**Important:** Merged code and branch-only changes are distinguished below; a successful source review is not a substitute for passing tests.

## Finding SPK-SEC-001 — Extracted plaintext persists after package creation

**Preliminary severity:** High  
**Confidence:** High for the lifecycle gap; runtime reproduction still required.

### Evidence

- `app/Archive/ArchiveWorkflow.php` extracts archive entries into a staging directory and merges successfully extracted content into the job's `source/` directory (see `process()`, particularly the stage creation, `mergeDirectory()`, and state transition).
- `app/Api/PackageController.php` builds the encrypted package from `$this->archives->sourceDirectory($jobId)` (in `build()`), but the successful path does not remove the job directory or its `source/` plaintext afterward.
- `app/Storage/JobStore.php` creates job directories with `source/` and `archives/`, but the inspected class has no job expiration or cleanup method.
- `config/config.php` declares `job_ttl_seconds`, but the inspected job storage and API paths do not enforce that setting.

### Impact

Plaintext extracted from user-provided archives can remain in application temporary storage after the encrypted package has been created. A failed package build can also leave the already-extracted source in the job directory. This increases exposure if temporary storage is readable by another local account, backed up, copied, or later misconfigured.

### Recommended remediation

1. Add a single, carefully scoped job cleanup operation that removes the job's plaintext source, staged files, and uploaded archive copies after successful package creation.
2. Ensure failure paths and abandoned jobs are cleaned by a bounded TTL cleanup routine; do not rely on the TTL configuration existing without an executing cleanup path.
3. Preserve the intended user-visible package and recovery-key result before cleanup, and do not remove the encrypted package artifact.
4. Add regression tests proving cleanup after success, cleanup after failure, and expiry cleanup for abandoned jobs.
5. Record cleanup failures safely and avoid logging file contents, passwords, patterns, or recovery keys.

### Validation plan

- Create a test archive containing a unique sentinel plaintext file.
- Run the archive-processing and package-build workflow.
- Verify the encrypted package is available and the sentinel plaintext no longer exists under the job/temp tree.
- Force package-build failure after extraction and verify the cleanup policy is applied.
- Create an expired job and verify the cleanup worker removes it without touching active jobs.
- Run the full security and regression suites.

**Current status:** Initial lifecycle fixes are implemented on the V1.0.0 branch: successful build and failed restore/download paths now attempt plaintext cleanup; restore-token expiry and resumable-upload TTL cleanup have dedicated handling. Fresh CI and additional failure-injection coverage are still required.

## Finding SPK-SEC-002 — Archive extraction bypasses the stricter path policy

**Preliminary severity:** High for cross-platform deployments; confirm impact on supported operating systems.  
**Confidence:** High that the policy is not wired into this extraction path.

### Evidence

- `app/Archive/ArchiveWorkflow.php` calls its private `validateEntryPath()`, which rejects empty, absolute, NUL-containing, and dot-segment traversal paths.
- That validator does not reject all platform-sensitive names such as colon-containing path segments, Windows device names, control characters, or trailing dots/spaces.
- `app/Archive/ArchivePolicy.php` has stricter checks for those cases, and `tests/ZipPolicyTest.php` tests that policy, but the inspected `ArchiveWorkflow::process()` path does not call `$this->policy->assertSafePath($name)`.

### Impact

The tested path policy does not necessarily protect the actual uploaded-archive extraction flow. Depending on the host OS and filesystem, unusual names may cause unsafe or inconsistent extraction behavior, including Windows-specific path interpretation.

### Recommended remediation

Use the central policy in the real extraction path and add integration tests that submit malicious ZIP entries through `ArchiveWorkflow`, not only unit tests against `ArchivePolicy`. Preserve the existing traversal checks and ensure nested entries follow the same policy.

**Current status:** The central path policy is now called by the real extraction workflow, with an integration regression test for a colon-containing path. Platform-specific filesystem behavior still needs supported-OS testing.

## Finding SPK-SEC-003 — Configured nested archive depth is not enforced in the workflow

**Preliminary severity:** Medium  
**Confidence:** High for the missing enforcement in the inspected workflow.

### Evidence

- `config/config.php` sets `max_archive_depth`.
- `ArchivePolicy` stores `maxDepth`.
- `app/Archive/ArchiveWorkflow.php` checks the nested archive count, but the inspected state and processing logic do not track a nesting depth or compare it with `$this->policy->maxDepth`.

### Impact

The configured depth limit does not constrain nested archive processing as intended. The total nested archive count still provides a separate bound, but it is not equivalent to a maximum nesting depth and does not enforce the documented policy.

### Recommended remediation

Persist and validate each pending archive's depth, reject entries exceeding `maxDepth`, and test both just-under-limit and over-limit nested archive chains.

**Current status:** Root-to-child depth is now tracked and compared against `maxDepth`, with a nested-archive regression test. Latest CI verification is pending.

## Additional initial safeguards implemented

- **Actual streamed ZIP bytes:** Added a bounded stream copier to enforce per-file and remaining-total limits while bytes are read, rather than trusting central-directory sizes alone.
- **Rate-limit state:** Corrupt persisted limiter state now fails closed; successful-authentication resets occur under an exclusive file lock.
- **Temporary data lifecycle:** Failed archive initialization removes its partial job; failed extraction removes nested archive copies not committed to job state; expired restore tokens clean their associated `restore-*` plaintext directory; restore downloads remove their generated ZIP and validated restore directory in a `finally` path.
- **Upload lifecycle:** Resumable uploads expire from their recorded creation time, and cleanup avoids traversing symlinked upload directories.
- **UI honesty:** The password/pattern meter is explicitly described as a length indicator; server-side validation remains authoritative.

These changes are on the review branch and must not be treated as release verification until the latest CI jobs pass. Production-host behavior, crash/power-loss cleanup, and operating-system-specific path semantics remain follow-up validation items.
## Follow-up review queue

- Verify ZIP extraction bounds against actual streamed bytes, not only archive metadata.
- Review rate limiting and authentication/quota enforcement in the API.
- Review credential normalization/validation and UI claims against actual enforcement.
- Review V13, CLI, CI, and release verification paths after high-priority storage cleanup is addressed.
