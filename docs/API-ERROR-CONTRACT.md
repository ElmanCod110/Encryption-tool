# API Error Contract Audit

**Status:** source audit baseline; not a claim that every scenario has been exercised at runtime.  
**Scope:** `public/api.php`, `app/Api/Request.php`, `app/Api/HttpException.php`, `app/Security/WebSecurity.php`, and `app/Api/PackageController.php`.

## Current observable contract

| Condition / action | Current response status | Public response | Audit note |
| --- | ---: | --- | --- |
| Unknown `action` | 404 | `Unknown action.` | Explicit route fallback. |
| Invalid JSON / non-array JSON | 400 | `Invalid JSON request.` | Implemented by `Request::json()`. |
| Request JSON body exceeds configured parser limit | 413 | `Request body is too large.` | Checks declared and actual body length. |
| CSRF token or same-origin validation failure | 403 | `Request validation failed.` or `Request origin is not allowed.` | Implemented with `HttpException`. |
| HTTPS required but request is not HTTPS | 503 | `Service is not configured for this connection.` | Only when `SPK_REQUIRE_HTTPS=1`. |
| Login rate limit exceeded | 429 | `Too many login attempts.` | Controller sends response directly. |
| Archive password attempt rate limit | 429 | `Too many archive password attempts.` | Controller sends response directly. |
| Package restore rate limit | 429 | `Too many failed attempts.` | Controller sends response directly. |
| Unhandled API exception | 500 | `Internal server error.` | API boundary logs exception class only. |
| Registration exception | 422 | `Unable to create account.` | Broad catch currently also maps unexpected failures to 422. |
| Upload initialization exception | 422 | `Unable to initialize upload.` | Broad catch currently also maps unexpected failures to 422. |
| Upload chunk exception | 409 | `Upload chunk rejected.` | Broad catch currently also maps unexpected failures to 409. |
| Upload finalization exception | 422 | `Unable to finalize upload.` | Broad catch currently also maps unexpected failures to 422. |
| Archive processing failure | 422 | `Unable to open archive with the supplied password.` | Broad catch; does not distinguish invalid input from server/storage failures. |
| Archive job ownership/read failure | 404 | `Archive job was not found.` | Intentionally hides existence/ownership, but broad catch can hide internal failures too. |
| Package build exception | 422 | `Unable to build package.` | Broad catch currently also maps unexpected failures to 422. |
| Package restore exception | 422 | `Unable to open package.` | Failed restore output cleanup was added; error categories remain collapsed. |
| Access token / expiry / revoke / delete exception | 404 | Generic package/action-specific message | Broad catches hide ownership/existence but can also hide internal failures. |

## Confirmed follow-up work

1. **Separate expected domain failures from unexpected failures.** Avoid catching every `Throwable` and returning 4xx for disk, permission, programming, or storage failures. Keep public messages generic and log a safe event identifier plus exception class; never log secrets, exception messages, or traces that may contain sensitive data.
2. **Document and enforce HTTP methods.** The API currently dispatches primarily by `action`; this audit did not find a central per-action HTTP-method contract. Decide and test allowed methods before claiming method-mismatch coverage.
3. **Decide content-type policy.** The JSON parser validates body shape but this audit did not confirm a consistent `Content-Type: application/json` requirement for every JSON action.
4. **Exercise failures with integration tests.** Source-text regression tests are useful guards, but do not prove the real HTTP status, response body, filesystem cleanup, or log behavior under a live PHP server.
5. **Preserve privacy on package ownership checks.** Where 404 is intentional to avoid revealing package existence, maintain that behavior for not-found and unauthorized resources while ensuring genuine internal failures are not silently mislabeled as 404.

## Verification record

- Source inspection: completed against the repository files listed above.
- Live HTTP integration tests: **NOT RUN** by this document.
- Windows/XAMPP and real-browser tests: **NOT RUN** unless separate evidence is linked in the release QA matrix.
- Dependency validation/audit: blocked until a real root `composer.lock` is committed and Composer checks pass.

Update this document only when the code and regression evidence support the changed contract.
