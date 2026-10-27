# Stable Single-File Package Format — Binary Specification

**Status:** normative implementation candidate for review; not yet the release default. This document defines the bytes written by 'StablePackageWriter' and accepted by 'StablePackageReader'. Existing V14 server and browser V13 readers are separate legacy compatibility boundaries; they must not be repurposed for this format.

This document uses MUST, MUST NOT, SHOULD, and MAY as normative requirements. Every multibyte integer is unsigned big-endian unless explicitly stated otherwise. Lengths are measured in bytes.

## 1. Permanent-format invariants

The package is one self-contained binary file, not ZIP and not a sidecar directory. The grammar is defined by this document and the fixed constants in 'StablePackageDescriptor'.

No application-release version, format-generation label, schema-version number, Git tag, build identifier, or field whose purpose is distinguishing application/package generations is serialized. This applies to the clear header, record envelopes, and decrypted manifest grammar. A fixed opaque magic marker identifies file type but is neither a version nor readable format name.

Algorithm identifiers name cryptographic algorithms only; bounded parameters describe the work needed to use them. They are not package-generation numbers. Unknown identifiers, reserved bits and unsafe KDF parameters MUST be rejected before KDF use.

Header offsets, byte order, record values, key-derivation domains, path rules, and grammar in this document are frozen. Application version changes MUST NOT change package bytes or alter the grammar. Readers may reject algorithms they do not support; they MUST NOT reinterpret an identifier.

## 2. Cryptographic profile and limits

| Purpose | Fixed value |
|---|---|
| Password KDF | Argon2id version 1.3 |
| Header/manifest AEAD | XChaCha20-Poly1305-IETF |
| File stream | libsodium secretstream XChaCha20-Poly1305 |
| Hash / HMAC / HKDF digest | SHA-256 |
| Root key | 32 random bytes |
| Header salt | 32 random bytes |
| AEAD nonce | 24 bytes |
| AEAD tag | 16 bytes |
| Secretstream message overhead | 17 bytes |
| Plaintext chunk size | exactly 4 MiB except final chunk |
| Writer KDF profile | ops=3; memory=268435456 bytes (256 MiB) |
| Accepted KDF operations | 2 through 4 inclusive |
| Accepted KDF memory | 64 MiB through 256 MiB inclusive, aligned to 1024 bytes |
| Maximum single file | 16 GiB |
| Maximum total plaintext | 100 GiB |
| Maximum manifest plaintext | 4 MiB |
| Maximum entries | 10,000 |
| Maximum filename component | 255 UTF-8 bytes |
| Maximum relative path | 4096 UTF-8 bytes |
| Maximum nesting | 256 components |

Password and pattern are independently processed using Argon2id. KDF fields are attacker-controlled until the header is authenticated and MUST be range-checked before invoking Argon2id. The current implementation requires 64-bit PHP, libsodium with Argon2id/secretstream support, and HKDF.

All cryptographic randomness MUST come from the operating system CSPRNG through the cryptographic runtime. Failure of any required API MUST fail closed.


### Explicit metadata-leakage boundary

This format encrypts the manifest (names, parent relationships and directory entries), but it does **not** hide traffic shape. The clear header exposes the fixed marker, algorithm identifiers, KDF cost, package identifier, and whether a recovery slot exists. Record boundaries and chunk lengths expose the number of file streams, approximate and often exact file sizes, total plaintext volume, and the package's total size. The fixed 4 MiB chunking does not prevent a final-chunk length from revealing the remaining bytes. This format does not claim padding-based size confidentiality. If hiding sizes or file counts is a requirement, that needs a separately designed and reviewed padding/framing scheme; it must not be improvised by changing this frozen grammar.

## 3. Fixed 253-byte header

There is exactly one 253-byte header. No padding, optional header extension, variable-length header, or footer follows it.

Opaque magic bytes (hex): **D3 82 A1 4F C7 5E 90 6B**.

| Absolute offset | Length | Field | Canonical rule |
|---:|---:|---|---|
| 0 | 8 | Magic | exact bytes shown above |
| 8 | 1 | Flags | bit 0 means recovery slot present; all other bits zero |
| 9 | 1 | KDF ID | 0x01 = Argon2id 1.3 |
| 10 | 1 | AEAD ID | 0x01 = XChaCha20-Poly1305-IETF |
| 11 | 1 | Stream ID | 0x01 = secretstream XChaCha20-Poly1305 |
| 12 | 1 | Hash ID | 0x01 = SHA-256 |
| 13 | 4 | KDF ops | u32 big-endian, bounded before use |
| 17 | 4 | KDF memory bytes | u32 big-endian, bounded before use |
| 21 | 24 | Package ID | opaque 24-byte identifier; random by default, or supplied by the integrating application; nonzero and not a secret |
| 45 | 32 | Salt | random; reject all-zero |
| 77 | 24 | Primary nonce | AEAD nonce |
| 101 | 48 | Primary wrapped root key | 32-byte ciphertext plus 16-byte tag |
| 149 | 24 | Recovery nonce | all-zero when recovery is disabled |
| 173 | 48 | Recovery wrapped root key | all-zero when recovery is disabled |
| 221 | 32 | Header MAC | HMAC-SHA-256 of bytes 0–220 inclusive |

The 'core' is exact bytes 0–76 (77 bytes). The 'header_without_mac' is exact bytes 0–220 (221 bytes). The header MAC is bytes 221–252 (32 bytes).

Readers MUST reject an incorrect magic, unsupported/reserved bits, unsupported algorithm identifiers, out-of-range KDF parameters, a zero package ID, zero salt, zero primary nonce, and a missing/incorrectly sized wrapped key. With recovery disabled, both recovery fields MUST be all zero. With recovery enabled, the recovery nonce MUST be nonzero and the wrapped-key field MUST be exactly 48 bytes; ciphertext bytes are not constrained to a particular bit pattern. Every field, including the slot not used for the current decrypt, is authenticated by the header MAC.

### 3.1 Credential derivation

Let 'salt' be the header's 32-byte salt and 'package_id' be the 24 raw bytes.

1. 'password_salt = SHA256(ASCII("SPKG/PWHASH/PASSWORD") || 0x00 || salt)[0:16]'.
2. 'pattern_salt = SHA256(ASCII("SPKG/PWHASH/PATTERN") || 0x00 || salt)[0:16]'.
3. 'password_key = Argon2id13(password, password_salt, ops, memory_bytes, output=32)'.
4. 'pattern_key = Argon2id13(pattern, pattern_salt, ops, memory_bytes, output=32)'.
5. 'credential_key = HKDF-SHA-256(IKM=password_key || pattern_key, length=32, info=ASCII("SPKG/CREDENTIAL-WRAP") || 0x00 || package_id, salt=salt)'.

The frozen format-level byte contract for each credential is: nonempty, at most 4096 bytes, valid UTF-8, and contains no NUL byte. The exact supplied bytes are used; they are not trimmed, case-folded, normalized, or transcoded implicitly. A writer MAY apply a stricter application password-strength policy when creating new packages, but a reader MUST NOT apply a version-dependent strength policy to an existing package credential: future UI policy changes must not make previously valid packages unreadable. Password and pattern KDF keys MUST be zeroized as soon as possible after the combined key is derived.

### 3.2 Root-key wrapping and header authentication

The writer generates a random, nonzero 32-byte 'root_key'. Readers MUST reject an all-zero unwrapped root key.

- 'primary_cipher = AEAD_Encrypt(key=credential_key, nonce=primary_nonce, plaintext=root_key, aad=ASCII("SPKG/KEYWRAP/PRIMARY") || 0x00 || core)', using XChaCha20-Poly1305-IETF.
- If recovery is enabled, 'recovery_cipher = AEAD_Encrypt(key=recovery_key_raw, nonce=recovery_nonce, plaintext=root_key, aad=ASCII("SPKG/KEYWRAP/RECOVERY") || 0x00 || core)', using XChaCha20-Poly1305-IETF, where 'recovery_key_raw' is a random 32-byte secret.
- 'header_mac_key = HKDF-SHA-256(IKM=root_key, length=32, info=ASCII("SPKG/HEADER-MAC") || 0x00, salt=package_id)'.
- 'header_mac = HMAC-SHA-256(header_mac_key, header_without_mac)'.

Each wrapped key is exactly 48 bytes. A reader unwraps the root key through one slot, then compares the header MAC using a constant-time comparison. No record may be processed until both steps succeed. This authenticates the unused slot as well. Recovery keys are encoded as canonical unpadded base64url outside the package; decode MUST reject noncanonical encodings, an all-zero value, and any result not exactly 32 bytes. A recovery key MUST fail if the recovery slot flag is clear.

## 4. Record envelope and parser state machine

Every record starts with five bytes:

| Relative offset | Length | Field |
|---:|---:|---|
| 0 | 1 | type |
| 1 | 4 | body length, u32 big-endian |
| 5 | body length | body |

The length excludes the envelope. Readers MUST validate the type-specific length before reading a body, reject truncated/oversized records, and enforce the state machine rather than accepting arbitrary record permutations.

Recognized types:
- 0x01 — file start
- 0x02 — encrypted file chunk
- 0x7F — final encrypted manifest

The canonical package sequence is header, then each file stream in the order of file entries in the decrypted manifest (file-start followed by all of that file's chunks), then exactly one manifest record, then EOF. Unknown records, a manifest while a stream is active, a chunk outside a stream, missing manifest, extra manifest, and trailing bytes after manifest MUST be rejected. EOF immediately after the authenticated final manifest is the completion boundary.

## 5. File-start record (type 0x01)

The body is exactly 48 bytes:

| Body offset | Length | Field |
|---:|---:|---|
| 0 | 16 | random file ID |
| 16 | 8 | declared plaintext size, u64 big-endian |
| 24 | 24 | secretstream header |

The file ID is unique and nonzero; the secretstream header MUST not be all-zero. A size MUST be at most 16 GiB. No second file-start record may appear until the prior stream has supplied its authenticated final chunk. File streams MUST appear in canonical manifest file order, verified after manifest authentication.

## 6. Chunk record (type 0x02)

The body is:

'file_id[16] || sequence[4] || ciphertext_and_secretstream_tag'

Sequence is u32 big-endian, starts at zero for each file and increases by exactly one. The cipher body contains the secretstream ciphertext and its 17-byte message overhead. A record body is at least 37 bytes and no more than 4,194,341 bytes.

Each per-file encryption key is derived independently:

'file_key = HKDF-SHA-256(IKM=file_root_key, length=32, info=ASCII("SPKG/FILE") || 0x00 || lowercase_hex(file_id), salt=package_id)'.

'file_root_key = HKDF-SHA-256(IKM=root_key, length=32, info=ASCII("SPKG/FILE-ROOT") || 0x00, salt=package_id)'.

Chunk AAD is exact concatenation of:

'ASCII("SPKG/CHUNK") || 0x00 || core_hash[32] || package_id[24] || file_id[16] || sequence_u32be || file_size_u64be'.

'core_hash = SHA256(core)'.

For a nonempty file, each non-final plaintext chunk MUST be exactly 4 MiB and have the MESSAGE tag. The final chunk MUST have the FINAL tag, the plaintext bytes from all chunks MUST equal the declared file size, and no more chunks may appear for that file. An empty file has exactly one zero-length FINAL-tag chunk. Readers MUST reject missing final tags, unexpected tags, out-of-order sequences, cross-file chunks, chunk lengths inconsistent with the declared size, and trailing bytes after the final record.

## 7. Final manifest record (type 0x7F)

The body is:

'manifest_nonce[24] || manifest_ciphertext_and_tag'.

Manifest plaintext is at most 4,194,304 bytes. The encrypted body is plaintext length plus 40 bytes (24-byte nonce plus 16-byte AEAD tag); the maximum body is 4,194,344 bytes.

'manifest_key = HKDF-SHA-256(IKM=root_key, length=32, info=ASCII("SPKG/MANIFEST") || 0x00, salt=package_id)'.

'manifest_ciphertext_and_tag = AEAD_Encrypt(key=manifest_key, nonce=manifest_nonce, plaintext=manifest_plain, aad=ASCII("SPKG/MANIFEST") || 0x00 || core_hash)' using XChaCha20-Poly1305-IETF.

Manifest associated data is 'ASCII("SPKG/MANIFEST") || 0x00 || core_hash'. The nonce is fresh random 24-byte data and MUST not be all-zero. Manifest is custom binary, not JSON and not string-valued metadata.

### 7.1 Manifest grammar

The plaintext begins with 'entry_count:u32be', followed by exactly that many entries, no padding and no trailing bytes.

Every entry begins with:
- 'entry_type:u8': 0x01 directory or 0x02 regular file;
- 'entry_id[16]': unique, random and nonzero;
- 'parent_id[16]': parent directory ID; 16 zero bytes denotes package root;
- 'name_length:u16be': 1–255 bytes;
- 'name[name_length]': UTF-8 filename component, not NUL-terminated.

A regular-file entry appends 'plaintext_size:u64be' (at most 16 GiB) and 'chunk_count:u32be'. Chunk count MUST equal 'max(1, ceil(plaintext_size / 4 MiB))'. Directory entries have no suffix. No version, schema, archive name, release tag, generation, or extension fields exist in the grammar. All names and tree structure remain encrypted because the full manifest is AEAD-encrypted.

Entry count is 1–10,000; at least one entry is a regular file. Total declared plaintext is at most 100 GiB. Readers MUST reject unknown entry types, duplicate IDs, truncated fields, trailing data, invalid UTF-8, invalid names, invalid sizes/counts, missing parents, non-directory parents, cycles, excessive depth, paths above 4096 bytes, and colliding siblings.

### 7.2 Canonical manifest order and path graph

Entries are strictly sorted by resolved relative path using raw UTF-8 byte ordering equivalent to strcmp. Root names have no prefix slash. A child path is parent path, slash, and name. Readers MUST recompute every path from parent IDs and reject noncanonical order.

A nonzero parent ID must resolve to exactly one directory. All IDs are unique across files and directories. The complete graph is validated before the requested output directory is created. Maximum depth is 256 components and maximum resolved path size is 4096 bytes.

Cross-platform path validation rejects empty names, '.' and '..', NUL/control characters, slash, backslash, colon, Windows forbidden characters '<', '>', '"', '|', '?', '*', trailing spaces/dots, and reserved device names CON, PRN, AUX, NUL, CLOCK$, CONIN$, CONOUT$, COM1–COM9, LPT1–LPT9 and the superscript-digit COM/LPT variants (including extensions and names with spaces or dots immediately after the reserved base). If runtime extensions needed for Unicode normalization/case folding are missing, non-ASCII names MUST be rejected rather than checked incompletely. Otherwise names must be NFC and sibling names checked with Unicode-aware case folding.

## 8. Resource and filesystem rules

Hard limits are checked before allocation, long loops, file creation, or KDF invocation. Use exact-read/exact-write loops and check stream/filesystem results. A runtime unable to safely represent u64 values MUST reject the format; reference implementation requires 64-bit PHP.

Creation enumerates and validates the source tree before publication, writes to a random temporary file created exclusively in the destination directory, verifies the open handle's device/inode against the path before trusting it, enforces mode 0600 and verifies the resulting POSIX permission bits where supported, flushes and synchronizes it where supported, and publishes without replacing an existing path. Temporary-file cleanup and publication may unlink only a name verified to refer to the inode created by this writer. Destination must not be a symlink or existing file. If atomic no-replace publication cannot be achieved, creation MUST fail rather than fall back to an overwrite-prone rename. PHP does not expose a portable Windows ACL API, so Windows permissions remain subject to the host's ACL configuration; deployments must not infer a POSIX-style confidentiality guarantee from `chmod` alone on Windows.

Source symlinks, special filesystem entries, unsafe names, and case-colliding siblings are rejected. While encrypting a source file, the writer computes SHA-256 over the exact plaintext bytes passed to the authenticated stream, then performs a second bounded-memory streaming read and compares the digest and file identity/metadata before publication. This deliberate extra read detects persistent same-size content changes that coarse filesystem timestamps can miss, at the cost of additional source I/O. It is not an atomic filesystem snapshot: PHP does not expose a portable, race-free `openat(O_NOFOLLOW)` tree walk, so a hostile actor concurrently mutating source directories can still exploit platform-specific race windows; deployments requiring protection against a same-user active filesystem attacker should use an immutable snapshot or quiesce writes during packaging. Temporary key material is zeroized where PHP/libsodium supports it. A package is not published until all file streams and the final encrypted manifest are fully written and the stream has been closed successfully.

## 9. Restore and failure behavior

A reader authenticates the header and verifies its MAC before reading records. Decrypted file content is written only to a private, random staging directory, with mode 0700 for the directory and mode 0600 for staged files on POSIX systems, verified where supported; staging filenames are based on random IDs. The reader binds staged files to the identities of the exclusive-create handles, computes a digest over plaintext emitted by the authenticated secretstream, checks the staged path/inode before use, and recomputes the digest while copying staged bytes into the final output. A changed staging path or digest MUST fail closed. The user-requested destination tree MUST NOT be created before the final manifest has been authenticated, decoded, graph-validated, cross-checked against all observed streams, and strict EOF verified.

After validation, restore may create a destination that did not previously exist. It creates directories and files without overwrite, uses restrictive permissions, does not intentionally follow symlinks, and records filesystem identities for paths created so rollback deletes only owned paths. It MUST NOT recursively delete unknown data. If cleanup cannot safely complete, this must be surfaced as a failed restore; never report success on partial output.

Wrong password/pattern/recovery key, malformed recovery key, changed header or either key slot, wrong header MAC, altered chunks, wrong tags, missing/truncated chunks, changed manifest, unsupported algorithms, invalid paths, and trailing bytes fail closed. External API responses may use a generic error. Diagnostics MUST NOT leak credentials, keys, recovery secrets, or decrypted file contents.

## 10. Acceptance matrix and release gates

The implementation MUST have automated tests for:
- exact magic/header size and every field offset, reserved bits, unknown algorithm IDs, KDF bounds and recovery enabled/disabled slots;
- zero-byte, one-byte, exactly 4 MiB, and multi-chunk files; binary and nested files; file hashes identical after restore;
- primary credentials and recovery round trips, wrong password/pattern, malformed key, and recovery disabled;
- header/MAC/slot tampering, file-start tampering, chunk bit flips/reordering/missing chunks, invalid tags, malformed lengths, unknown records, truncation, missing manifest, duplicate manifest, and trailing bytes;
- malformed manifest entries, duplicate IDs, invalid names/UTF-8, directory graph cycles, missing parents, file-as-parent, case collisions, over-limit path/depth/chunk counts;
- existing destinations remaining byte-for-byte untouched; failure cleanup leaving no partial output or private staging directory;
- canonical record order and one-to-one correspondence between observed streams and manifest entries;
- CI on supported PHP versions and Windows testing of encryption, restore, and atomic no-overwrite behavior;
- unchanged server V14 and browser V13 compatibility tests.

A green round trip alone is not enough. This is an implementation candidate, not release authorization, independent audit, or a promise of zero defects. The format must remain isolated behind an explicit interface until full CI and platform checks pass. Do not tag v1.0.0 until review of the byte-level spec, complete writer/reader diff, parser boundary and failure-injection tests, Windows/shared-hosting behavior, and release artifact.
