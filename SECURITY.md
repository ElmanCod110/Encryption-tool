# Security Notes

This project intentionally uses public, reviewed cryptographic primitives. The custom part is the package composition and key separation, not a custom cipher.

## Secret handling

Passwords and patterns must exist only in process memory for as long as needed. Do not log them, put them in URLs, write them to database fields, or include them in error messages.

## Pattern confidentiality

The package format does not store the pattern, a plaintext pattern hash, or a pattern-derived verifier. A wrong pattern produces a different master key and therefore fails authenticated decryption.

## Error uniformity

The HTTP layer should return the same external failure response for bad credentials, tampered packages, corrupted manifests, and other authentication failures. Detailed exceptions should go only to protected server logs and should not contain user secrets.

## Client-side decryption

For a zero-knowledge deployment, decrypt the package in the client after downloading it. Server-side decryption means the server can see plaintext during the restore operation.
