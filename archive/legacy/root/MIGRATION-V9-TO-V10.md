# Migration: V9 to V10

V10 introduces a new unified browser package format and does not silently reinterpret V9 packages.

## Compatibility

- V9 `.spk9` packages remain readable by the V9 workflow.
- V10 uses `.spk10` and the `SECURE-BROWSER-V10` format identifier.
- No automatic in-place conversion of ciphertext is performed.

## Credential model

V10 encrypts a random content root key and stores one or more credential slots that wrap that root key.

This enables credential rotation without re-encrypting file ciphertext.

## Recommended migration

1. Open the existing V9 package using the V9 workflow.
2. Restore or export the plaintext locally.
3. Create a new V10 package entirely in the browser.
4. Store the generated recovery key separately from the package.
5. Verify the V10 package before deleting the old V9 copy.
