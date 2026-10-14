# Initial Security Audit Findings

**Audit status:** Static source review in progress  
**Reviewed ref:** `master` at `d66aa69f735b6472ab9d55dab9673e1d3f2e4a95`  
**Runtime validation:** NOT RUN in this review  
**Important:** Findings below are based on the inspected source paths. They are not a substitute for reproducing the behavior in a controlled test environment.

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

**Current status:** Confirmed as a source-level lifecycle gap; fix not yet applied.

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

**Current status:** Source-level integration gap identified; exploitability and platform impact require integration testing. Fix not yet applied.

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

**Current status:** Source-level enforcement gap identified; integration test not run. Fix not yet applied.

## Follow-up review queue

- Verify ZIP extraction bounds against actual streamed bytes, not only archive metadata.
- Review rate limiting and authentication/quota enforcement in the API.
- Review credential normalization/validation and UI claims against actual enforcement.
- Review V13, CLI, CI, and release verification paths after high-priority storage cleanup is addressed.
