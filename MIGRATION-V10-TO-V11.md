# V10 to V11 Migration

V11 introduces a new `SPK11BIN1` container. V10 packages remain readable only by their V10 workflow and are not silently rewritten.

V11 package creation is browser-first and streams file input into authenticated encrypted chunk records. V11 server transport stores opaque ciphertext chunks and resumable inventory only.

Credential rotation remains a slot operation and does not require re-encrypting file ciphertext.
