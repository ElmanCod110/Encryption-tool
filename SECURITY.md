# Security Policy

## Supported generation

V12 is the active release-candidate security generation.

## Reporting

Please report suspected vulnerabilities privately through GitHub Security Advisories or the repository security contact. Do not publish an exploitable proof of concept before a fix or coordinated disclosure is possible.

## Security principles

- Use standard cryptographic primitives.
- Keep credentials out of persistent storage.
- Authenticate before trusting decrypted data.
- Fail closed on malformed package input.
- Bound archive, upload, memory, and file-processing resources.
- Treat browser JavaScript integrity as a security boundary.
- Never place private release keys in the repository.
