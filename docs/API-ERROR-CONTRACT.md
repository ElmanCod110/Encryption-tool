# API Error Contract and Audit

**Application version:** see the root VERSION file.  
**Audit status:** source review updated for release-readiness work. Existing policy and HTTP integration tests cover representative boundary cases; this is not proof that every controller path has correct classification.

## Boundary contract

The API entry point is public/api.php. It applies the centralized ApiRequestPolicy before dispatch and handles HttpException separately from unexpected Throwable failures.

| Condition | Expected status | Public response policy | Evidence / remaining work |
| --- | ---: | --- | --- |
| Unknown action | 404 | Generic unknown-action message | Covered by ApiHttpIntegrationTest.php |
| Unsupported method | 405 | Generic method message and Allow: POST | Covered by ApiHttpIntegrationTest.php |
| Unsupported content type | 415 | Generic media-type message | Covered by ApiHttpIntegrationTest.php |
| Invalid JSON | 400 | Generic malformed-request message | Covered by ApiHttpIntegrationTest.php |
| Oversized JSON body | 413 | Generic body-size message | Request-level regression coverage |
| CSRF / origin failure | 403 | Generic request-validation message | Covered by HTTP integration and policy tests |
| Authentication failure | 401 | Generic sign-in message; no username enumeration | Covered for malformed username path |
| Rate limit | 429 | Generic retry-later message | Controller and rate-limiter tests |
| Typed upload failure | Status carried by UploadException | Safe, typed public message | Upload controller paths use UploadException |
| Unexpected exception at API boundary | 500 | Internal server error only | Integration test checks that implementation details are not exposed |
| Unexpected account-store failure | 500 | Internal server error only | HTTP integration test corrupts an isolated fixture store and checks response privacy |

## Confirmed controller classification risks

The following broad catches remain and should be replaced with typed domain failures where the underlying services can distinguish them safely:

- **archive-step:** a nested catch maps any Throwable from archive processing to 422, while an outer catch maps any Throwable (including storage/programming failures) to 404. This can mislabel an internal outage as invalid archive input or not-found.
- **build:** a broad catch returns 422 for validation, archive/ZIP, storage, catalog, and other failures. Cleanup behavior must be preserved while separating expected package/input failures from internal failures.
- **decrypt:** a broad catch returns 422 for all restore failures. Public privacy should remain generic, but internal failures must not be represented as client errors without a typed reason.
- **package availability / expiry / revoke / delete:** broad catches return 404 for any failure. A 404 may be appropriate for missing or unauthorized resources to prevent enumeration, but disk and programming errors should reach the internal-error boundary.
- **upload paths:** UploadException and QuotaExceededException already provide a better basis for classification; unexpected exceptions are rethrown to the API boundary. Keep this typed approach consistent.

Do not simply expose exception messages or stack traces to solve these issues. They may contain filesystem paths, credentials, recovery material, or attacker-controlled input.

## Logging and response requirements

1. Public error responses must not contain stack traces, exception messages, storage paths, credentials, recovery keys, session identifiers, or plaintext.
2. Unexpected errors should be logged with a safe event identifier and exception class. Do not log exception messages or traces unless a reviewed redaction strategy proves that secrets cannot leak.
3. Expected user/domain failures must use explicit exception types or result objects with a documented status and safe public message.
4. Keep not-found and unauthorized package responses indistinguishable when needed to avoid resource enumeration, but do not collapse unrelated infrastructure failures into 404.
5. Cleanup must be tested independently: a generic error response is not sufficient evidence that temporary files were removed or original data was preserved.
6. Keep the central method and content-type policy in ApiRequestPolicy. Any action-specific exception (such as the CSRF bootstrap) must be explicit and covered by tests.

## Required follow-up tests

- Real HTTP tests for malformed input, unsupported methods/media types, authentication, and unexpected storage failures.
- Controller/service tests proving invalid package input maps to a client error while simulated disk or permission failure reaches HTTP 500.
- Assertions that public response bodies do not reveal exception class, message, paths, or secrets.
- Cleanup tests for interrupted upload, package build, restore, and token operations.
- Ownership/privacy tests that preserve the 404 boundary for missing and unauthorized package identifiers without swallowing genuine internal failures.

## Verification record

- Source inspection: updated against public/api.php, app/Api/ApiRequestPolicy.php, app/Api/PackageController.php, and the current HTTP integration test.
- Existing automated HTTP integration test: included in the repository security workflow; the current source has not been executed by this documentation update.
- Windows/XAMPP and real-browser release QA: NOT RUN until evidence is recorded in docs/RELEASE-QA-MATRIX.md.
- Composer lockfile and dependency audit: BLOCKED until the generated lockfile is reviewed and committed.
