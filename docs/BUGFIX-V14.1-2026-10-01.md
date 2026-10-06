# Secure Package V14.1 — Bug Fix Report

## Fixed client failure

The Browser Vault V13 builder produced `key_slots.primary` and `key_slots.recovery` without the `type` and `version` fields that the V13 parser required. As a result, a package created by the browser vault could not be opened by the same vault and the UI showed the generic `Unable to open or restore the package.` message.

The builder now writes the exact slot schema expected by the parser:

- primary: `type=password-pattern`, `version=1`
- recovery: `type=recovery`, `version=1`

A real browser-code round-trip was executed after the change: build → header parse → credential unlock → manifest authentication → chunk/hash verification → Merkle verification → restore.

## Fixed server initialization

Server registration and server package-name reservation previously required `SPK_NAME_PEPPER` to be exported in the PHP process environment. The project did not load `.env`, so a normal XAMPP/Apache setup could return `Unable to create account.` immediately.

The server now accepts an explicitly configured `SPK_NAME_PEPPER` and otherwise creates a persistent random 256-bit secret in `storage/secrets/name-pepper.bin` with restrictive permissions. This is a local bootstrap fallback, not a replacement for controlled production secret management.

## Fixed server recovery key response

`V14PackageBuilder` already generated a recovery key, but `V14PackageService` returned it only inside `stats`. The API controller expected it at the top level, so the web UI did not receive the one-time recovery key.

The service now promotes `recovery_key` to the top-level build result and the API returns it correctly.

## Fixed packaging failure cleanup

If the V14 package directory was successfully built but portable `.spkg14` creation failed, the old flow could leave an orphaned package directory behind. The API now removes the portable archive and package directory when the packaging step fails before catalog registration.

## Runtime diagnostics

The server workspace requires PHP `ext-zip` because it accepts ZIP source archives and emits portable `.spkg14` packages. `/health.php` and the main UI now report Zip as a required runtime component. `bin/self-check.php` uses the same requirement.

Browser Vault V13 remains a separate compatibility boundary and accepts `.spk13`; it does not silently interpret V14 `.spkg14` packages.

## Validation performed

- All active PHP regression tests: PASS
- Browser Vault V13 build/restore round-trip: PASS
- V14 server password restore: PASS
- V14 server recovery-key restore: PASS
- JavaScript syntax checks: PASS
- Source security audit: PASS
- Server registration/session/CSRF smoke test: PASS
- Runtime health in the current sandbox: DEGRADED only because `ext-zip` is not installed there
