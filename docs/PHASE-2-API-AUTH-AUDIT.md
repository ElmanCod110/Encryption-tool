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

### SPK-API-006 — Archive and restore rate limits were scoped to an owner/session key

**Evidence:** The per-job/per-package limiter keys included an owner identity that can differ across anonymous sessions. This left room to spread repeated attempts across fresh session identities from the same network address.

**Change:** Archive-password and package-restore attempts now also use a hashed remote-address rate-limit key. Successful operations reset the corresponding scoped keys. The raw IP address is not written into the limiter filename.

**Status:** Controller change committed on this branch; CI verification is pending. Proxy deployments must configure the web server so `REMOTE_ADDR` represents the intended client boundary; forwarded headers are deliberately not trusted directly.

### SPK-API-005 — Package catalog mutations could overwrite concurrent state

**Evidence:** Package expiry and revocation used read-modify-write operations without a shared per-package lock. Concurrent updates could write stale records over one another. Package creation also replaced an existing record if an identifier collision or repeated create reached the same path.

**Change:** Catalog create, expiry, revoke, and delete now serialize on a per-package lock. Creation refuses to replace an existing record, reads reject symlinked or malformed records, and owner-list enumeration skips symlink entries.

**Regression test:** `tests/PackageCatalogMutationTest.php` covers duplicate creation, preserving expiry while revoking, wrong-owner mutation rejection, and revoked-package availability.

**Status:** Fix and regression test committed on this branch; CI is required to validate them. Concurrent-process stress testing remains pending.

### SPK-API-007 — Upload initialization had no per-owner reservation quota

**Evidence:** Each upload was individually bounded, but a caller could create multiple active upload directories and reserve arbitrarily large declared totals. There was no atomic per-owner cap on concurrent uploads or aggregate reserved bytes.

**Change:** Upload initialization now serializes quota checks with a root-level lock, enforces configured active-upload count and aggregate declared-byte limits per owner, and cleans up partially initialized upload directories. Upload creation is also rate-limited by a hashed remote-address key. Quota rejection returns 429.

**Configuration:** `max_active_uploads_per_owner` defaults to 3; `max_active_upload_bytes_per_owner` defaults to 1 TiB, matching the current single-upload ceiling. Adjust these values to the actual deployment's disk budget.

**Regression test:** `tests/ResumableUploadQuotaTest.php` covers active-count enforcement, aggregate-byte enforcement, and quota isolation between owners.

**Status:** Fix and regression test committed on this branch; fresh CI is required.

## Remaining phase-2 work

- Run the isolated live HTTP integration test for 404/405/415, CSRF/origin rejection, malformed JSON, and generic internal-error responses; keep deployment-specific behavior separate.
- Continue reviewing ownership enforcement and account/session boundaries across every management action.
- Review rate-limit identity scope and storage/quota exhaustion behavior.
- Perform concurrent-process stress testing for catalog mutation races, expiry/revocation behavior, and cleanup after failed operations.
- Distinguish expected domain errors from unexpected storage/programming failures without leaking internal details.
- Record actual CI run links and outcomes for the exact branch head; do not mark this phase verified until the checks finish successfully.

## Validation status

- Source review: completed for the files named above.
- Regression tests added: token replay, account-store corruption, session configuration, package catalog mutation/ownership, API method/media-type policy, and upload count/byte quotas.
- CI passed for the full phase-2 code at commit `1b8980e7e07f24c52ae184354940cb1cb6fa589d`: [CI run](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38603168996), [Security and Release Integrity](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38603168923), and [Client Security](https://github.com/ElmanCod110/Encryption-tool/actions/runs/38603168886). All three completed successfully.
- Isolated PHP built-in-server integration test covers 404/405/415, CSRF/origin, malformed JSON, and generic internal-error responses without exposing internal paths/classes; it passed in the CI run above.\n- Manual Windows/XAMPP and production-host HTTP checks: NOT RUN.
- Windows/XAMPP and production-host checks: NOT RUN.

This audit is an engineering record, not a security certification or a claim that all API/authentication risks have been eliminated.
