# Phase 2 — API and Authentication Audit

**Status:** Source review and initial fixes implemented on `security/phase-2-api-auth-hardening`; CI and live HTTP verification pending.  
**Baseline:** `master` after the V1.0.0 initial-security PR merge.  
**Scope:** API action dispatch, request methods and media types, session setup, account-store integrity, and package download-token consumption.

## Findings and changes

### SPK-API-001 — Single-use download-token replay race

**Evidence:** `PackageAccessTokenStore::consume()` previously unlinked a one-time token while holding a lock but left the open inode's contents intact. A concurrent request that had already opened the same file could wait for the lock and then read the original token record after the first request unlinked the path.

**Change:** A one-time token is now replaced with a consumed marker and flushed while the exclusive lock is held. Requests already waiting on the same inode observe the marker and reject replay. Token files are opened without create semantics, symlink token paths are rejected, and malformed token records fail closed.

**Regression test:** `tests/PackageAccessTokenStoreTest.php` covers successful one-time use, replay rejection, reusable-token behavior, and malformed input.

**Status:** Fix and regression test committed on this branch; CI is required to validate them.

### SPK-API-002 — Corrupt account JSON could be treated as an empty account database

**Evidence:** `AccountStore::read()` previously converted invalid JSON to an empty array. A later registration could then overwrite the existing account file, potentially discarding account records instead of surfacing storage corruption.

**Change:** Account storage now fails closed on unreadable, malformed, non-list, or structurally invalid data. Password-hash rehash writes now acquire the same exclusive lock used by registration, preventing read-modify-write updates from racing with account creation.

**Regression test:** `tests/AccountStoreCorruptionTest.php` verifies that corrupted account data is rejected and left unchanged.

**Status:** Fix and regression test committed on this branch; CI is required to validate them.

### SPK-API-003 — Session cookie name was configured using an invalid INI key

**Evidence:** `session.cookie_name` is not the PHP setting used to select the session name. The code could therefore continue using the default session cookie name despite documenting an application-specific name.

**Change:** The session name is now set through `session_name('SECUREPKGSESSID')` before the session starts. Cookie-only mode, strict mode, disabled URL session propagation, HttpOnly, and SameSite settings remain explicitly configured.

**Regression test:** `tests/WebSecuritySessionConfigurationTest.php` checks the active session name and key cookie/session settings.

**Status:** Fix and regression test committed on this branch; runtime/CI verification is pending.

### SPK-API-004 — API action dispatch lacked a central method and media-type contract

**Evidence:** The API dispatched by action name without centrally rejecting unsupported HTTP methods or consistently checking the request media type.

**Change:** Known API actions now require POST. JSON actions require `application/json`, and chunk uploads require `application/octet-stream`; mismatches return 405 or 415 without initializing storage-backed controllers. Unknown actions remain 404. The CSRF bootstrap action does not parse a request body.

**Documentation:** `docs/API-ERROR-CONTRACT.md` records the new observable contract.

**Status:** Source change committed; live HTTP tests are still required to verify statuses, headers, and request behavior end-to-end.

## Remaining phase-2 work

- Add live HTTP integration coverage for 405/415, CSRF/origin rejection, malformed JSON, and generic internal-error responses.
- Continue reviewing ownership enforcement and account/session boundaries across every management action.
- Review rate-limit identity scope and storage/quota exhaustion behavior.
- Review package catalog mutation races, expiry/revocation behavior, and cleanup after failed operations.
- Distinguish expected domain errors from unexpected storage/programming failures without leaking internal details.
- Record actual CI run links and outcomes for the exact branch head; do not mark this phase verified until the checks finish successfully.

## Validation status

- Source review: completed for the files named above.
- Regression tests added: token replay, account-store corruption, and session configuration.
- CI for this branch: pending.
- Live HTTP integration tests: NOT RUN.
- Windows/XAMPP and production-host checks: NOT RUN.

This audit is an engineering record, not a security certification or a claim that all API/authentication risks have been eliminated.
