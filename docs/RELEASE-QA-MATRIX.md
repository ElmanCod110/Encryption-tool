# Release QA Matrix

**Release target:** v1.0.0 (planned; not published)  
**Current application version:** read from the root VERSION file.  
**Rule:** never mark a scenario PASS without recording the command or procedure and observed result. Use **NOT RUN** when the environment or evidence is unavailable.

## Evidence record

For each run, record:

- Date and timezone
- Commit SHA and application version
- Operating system, PHP version, and relevant extension versions
- Exact command/procedure
- PASS / FAIL / NOT RUN
- Short result and a link to CI logs or a sanitized screenshot when applicable

Never attach real project data, passwords, recovery keys, session cookies, or unredacted server logs.

## Automated checks

| Check | Procedure / evidence | Status |
| --- | --- | --- |
| PHP syntax | Run the syntax-check step in CI on supported PHP versions | Pending current release candidate |
| JavaScript syntax | Run the JavaScript syntax-check step in CI | Pending current release candidate |
| Core regression suite | Run all PHP test scripts and the browser-format regression script | Pending current release candidate |
| Self-check | Run php bin/self-check.php | Pending current release candidate |
| Source security audit | Run php bin/source-audit.php | Pending current release candidate |
| Composer manifest and lock | Run composer validate --strict --no-check-publish with a Composer-generated composer.lock | BLOCKED until the real lockfile is reviewed and committed |
| Dependency audit | Run composer audit --no-interaction; investigate every finding | BLOCKED until the real lockfile is reviewed and committed |
| Release integrity | Run release-integrity tests and verify the built artifact/checksum | Pending current release candidate |

CI green status is evidence only for the checks actually executed by that workflow; it does not imply that manual scenarios passed.

## Windows / XAMPP deployment

| Scenario | Expected result | Status |
| --- | --- | --- |
| Fresh install on a supported PHP 8.2+ runtime | Requirements are detected; setup completes without warnings being hidden | NOT RUN |
| Required Sodium and Zip extensions unavailable | Clear actionable health/configuration failure; no partial sensitive operation | NOT RUN |
| Storage directories missing or not writable | Safe failure; no plaintext or secret material exposed | NOT RUN |
| Restart after interrupted request | State remains consistent and recoverable | NOT RUN |
| Logs and generated storage | No passwords, recovery keys, session identifiers, or plaintext contents | NOT RUN |

## Server package (SECURE-PKG-V14 / .spkg14)

| Scenario | Expected result | Status |
| --- | --- | --- |
| Build and restore with password + pattern | Round-trip preserves file bytes and relative paths | NOT RUN |
| Restore with independent recovery key | Restore succeeds without requiring the original password + pattern | NOT RUN |
| Wrong credentials / malformed header | Restore fails closed with a generic public error | NOT RUN |
| Tampered header, encrypted metadata, or blob | Authentication/integrity validation rejects the package | NOT RUN |
| Empty files, nested directories, Unicode names | Supported entries round-trip byte-for-byte | NOT RUN |
| Large file within configured limits | Operation completes within limits without unbounded memory use | NOT RUN |
| Existing destination collision | Restore refuses to overwrite existing files | NOT RUN |
| Interrupted upload/build/restore | Temporary artifacts are cleaned up; original user data remains intact | NOT RUN |
| Disk-full or permission failure | Safe failure, no false success response, no destructive cleanup of the only source copy | NOT RUN |
| Path traversal / malformed inventory | Unsafe paths are rejected before writing outside the restore root | NOT RUN |

## Browser compatibility (SECURE-BROWSER-V13 / .spk13)

| Scenario | Expected result | Status |
| --- | --- | --- |
| Build and restore in a real supported browser | Files round-trip correctly | NOT RUN |
| Unsupported or non-secure browser context | Clear compatibility diagnostic | NOT RUN |
| V13 package passed to V14 server path and vice versa | Formats remain explicitly separated; no silent cross-format interpretation | NOT RUN |
| Keyboard navigation, visible focus, reduced motion | Main actions remain usable and understandable | NOT RUN |
| Responsive layouts and failure states | UI remains usable at narrow widths and errors are visible | NOT RUN |

## Release decision

A release candidate is **not ready** while any required automated check fails, the Composer lockfile is missing/unreviewed, or any critical manual scenario remains untested without an explicitly approved limitation.

Before publishing:

1. Replace only statuses supported by actual evidence.
2. Link workflow runs and sanitized manual evidence.
3. Review the dependency audit and package-format compatibility notes.
4. Update VERSION, CHANGELOG.md, and release notes together.
5. Build and verify the release artifact and checksum.
6. Confirm the release does not claim a security audit or certification that did not occur.
