# Changelog

## 4.0.0

- Renamed the package format to `SECURE-PKG-V4`.
- Added resumable uploads with owner binding.
- Added account registration, login, logout, and session rotation.
- Added package catalog, ownership checks, revocation, and access tokens.
- Added audit logging with secret-field filtering.
- Added stronger security headers and same-origin validation.
- Added a production-oriented package management UI.
- Fixed the root `.htaccess` configuration that could cause HTTP 500 errors when invalid directory context directives were processed.
- Added CI, runtime self-checks, and client-side decryption architecture documentation.
