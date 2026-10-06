# Migration from V4 to V6

V6 changes the package format to `SECURE-PKG-V6`. V4 packages are not silently treated as V6 packages.

Important changes:

- Crypto context changed to V6.
- Package format version is 5.
- Management operations use centralized authorization.
- Resumable uploads use per-upload locking.
- Uploads can carry a SHA-256 integrity claim.
- Restore token consumption is lock-protected.
- Access token filenames are derived from token hashes.
- Audit events are hash chained.
- Package deletion is a management operation and does not release the reserved project name.

A dedicated migration or compatibility reader should be added before deploying a mixed V4/V6 environment.
