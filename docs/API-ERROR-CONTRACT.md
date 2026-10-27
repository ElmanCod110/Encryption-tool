# API Error Contract Audit

**Status:** source-reviewed contract with HTTP integration coverage on the release-reconciliation branch. CI for the exact candidate commit must pass before this is treated as release evidence.  
**Scope:** `public/api.php`, `app/Api/Request.php`, `app/Api/HttpException.php`, `app/Security/WebSecurity.php`, `app/Api/PackageController.php`, archive/package storage and restore exception types.

## Public response rules

Unexpected configuration, filesystem, permission, storage, or programming errors must reach the central API error boundary. They return a generic HTTP 500 JSON response without exception messages, stack traces, absolute paths, credential values, or package identifiers. Expected user/domain failures may return 4xx only where the controller catches an explicit typed exception or a documented validation error.

| Condition | Expected status | Public response | Implementation / verification |
| --- | ---: | --- | --- |
| Unknown action | 404 | `Unknown action.` | Explicit dispatch allowlist. |
| Known action with non-POST method | 405 | `Method not allowed.` | API request policy; includes `Allow: POST`. Live HTTP test checks the header. |
| Wrong or missing content type | 415 | `Unsupported media type.` | Request policy requires JSON for JSON endpoints and octet-stream for chunk endpoints. |
| Invalid JSON / non-array JSON | 400 | `Invalid JSON request.` | `Request::json()`. |
| Oversized JSON body | 413 | `Request body is too large.` | Declared and actual body size are bounded. |
| CSRF / same-origin rejection | 403 | Generic request-validation message | `WebSecurity` and `HttpException`. |
| HTTPS required but unavailable | 503 | `Service is not configured for this connection.` | Only when `SPK_REQUIRE_HTTPS=1`. |
| Unauthenticated private-package management request | 401 | `Authentication required.` | Typed `AuthenticationRequiredException`; HTTP integration test checks unauthenticated package listing. |
| Unknown or unavailable package/job | 404 | Generic “not available” response | Typed `PackageNotAvailableException` / `JobNotAvailableException`; intentionally avoids exposing ownership/existence. |
| Expired/revoked package or upload | 404 / 410 | Generic unavailable/expired response | Expiry/revocation checks precede access; upload store retains its documented 410 for expired uploads. |
| Invalid registration input | 422 | `Invalid account details.` | Validation failure is distinct from unexpected account-store failure. |
| Duplicate account registration | 409 | `Unable to create account.` | Typed conflict; username is not echoed. |
| Invalid upload size/checksum/empty chunk | 422 | Upload input error | Typed `UploadException`. |
| Upload offset conflict / incomplete upload | 409 | Upload state error | Typed `UploadException`. |
| Upload/quota rate limits | 429 | Rate-limit message | Rate limiter and quota exception. |
| Upload filesystem/storage failure | 500 | `Internal server error.` | Unexpected `RuntimeException` is rethrown to API boundary, not mapped to 4xx. |
| Missing archive job | 404 | `Archive job was not found.` | `JobNotAvailableException`. |
| Archive step state conflict | 409 | `Archive step is no longer available.` | `ArchiveStepConflictException`. |
| Malformed archive, invalid path, bad password, archive limits | 422 | Generic archive-open failure | `ArchiveProcessingException`; hostile archive names are rejected. |
| Archive read/write/rollback/cleanup failure | 500 | `Internal server error.` | Unexpected storage errors are rethrown; rollback and private-stage cleanup errors are no longer silently swallowed. |
| Package build input validation | 422 | `Unable to build package.` | Explicit validation exception; missing job is 404. |
| Package build/catalog/storage/runtime failure | 500 | `Internal server error.` | Not mislabeled as a bad request; incomplete artifacts are cleaned with post-cleanup verification. Plaintext source job is preserved if build fails before commit. |
| Missing package during restore | 404 | `Package not available.` | Typed `PackageNotAvailableException`. |
| Invalid credentials, damaged package, invalid manifest / ZIP path | 422 | `Unable to open package.` | Typed `PackageRestoreRejectedException`; restore failures invoke centralized plaintext cleanup. |
| Restore destination, catalog I/O, archive extraction or cleanup failure | 500 | `Internal server error.` | Typed `PackageStorageException` or unexpected exception reaches the API boundary. Partial restore output must be removed before returning. |
| Access-token / expiry / revoke / delete for unavailable package | 404 | Generic `Package not available.` | Typed unavailable-package response preserves privacy. |
| Package-management storage failure | 500 | `Internal server error.` | Storage/program errors are not converted to 404 by broad catches. |
| Unhandled API exception | 500 | `Internal server error.` | Central boundary logs only safe exception-class metadata; public response omits exception details. |

## Cleanup and data-preservation rules

1. A failed package build must not remove the plaintext source job unless package creation and catalog creation have committed.
2. A failed restore must not yield a restore token. All owned partial plaintext output is removed, and cleanup failure itself is raised as a storage failure.
3. Archive extraction only removes the destination directory it created after checking the recorded directory identity; cleanup does not follow a replaced root symlink.
4. Archive rollback attempts all known reverse moves. A failed rollback or remaining staging path is a server/storage error rather than an ordinary invalid-password response.
5. A pre-existing package archive or restore destination must not be overwritten.
6. Public 404 responses may hide missing versus unauthorized resources. They must not hide a disk, permission, catalog I/O, or programming error.

## Integration evidence

`tests/ApiHttpIntegrationTest.php` includes live HTTP checks for configuration initialization failure privacy, the `Allow: POST` header, unauthenticated package listing, missing archive job/package response, catalog initialization failure privacy, and a real encrypted package restore-storage fault where the filesystem enforces the permission change. The restore fault test explicitly reports a skip on hosts that do not enforce the temporary directory-mode change.

`tests/V14PackageArchiveTest.php` covers round trip, malformed non-ZIP rejection, path traversal rejection, cleanup, and preservation of a pre-existing extraction destination. `tests/PackageCatalogListingTest.php` rejects corrupt catalog records and symlink records. `tests/ResumableUploadCleanupTest.php` checks direct cleanup, nested symlink safety and invalid identifiers. `tests/PackageAuthorizationTest.php`, `tests/PackageBuildCleanupTest.php`, and `tests/RestoreFailureCleanupTest.php` guard the typed error and cleanup contracts.

Automated test results are evidence only for the exact commit and environment linked by GitHub Actions. Windows/XAMPP, real-browser, accessibility and shared-hosting filesystem behavior still require manual validation; this document does not claim those manual tests have passed.

## Remaining audit work

- Validate the strict `ResumableUploadStore::remove()` locking, expiry marking, directory-identity and post-cleanup checks on Windows/non-POSIX filesystems. The Linux test covers direct removal and a nested symlink; cross-platform execution is still NOT RUN.
- Test logging behavior under all major internal failure paths and verify that no secret or raw exception message is written.
- Review the complete exception taxonomy and each endpoint's actual response mapping on the exact release candidate.
- Re-run all regression/security workflows on the latest head after any further source or documentation change.
