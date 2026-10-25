<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/**
 * Frozen binary grammar and primitive codecs for the stable, single-file package.
 *
 * This class deliberately contains no application-release or format-generation
 * version. Algorithm identifiers identify algorithms only; they do not select a
 * parser generation.
 */
final class StablePackageDescriptor
{
    public const MAGIC = "\xD3\x82\xA1\x4F\xC7\x5E\x90\x6B"; // opaque 8-byte marker; no readable format name or version.

    public const HEADER_BYTES = 253;
    public const CORE_BYTES = 77;
    public const HEADER_WITHOUT_MAC_BYTES = 221;
    public const PACKAGE_ID_BYTES = 24;
    public const SALT_BYTES = 32;
    public const KEY_BYTES = 32;
    public const NONCE_BYTES = 24;
    public const AEAD_TAG_BYTES = 16;
    public const WRAPPED_KEY_BYTES = self::KEY_BYTES + self::AEAD_TAG_BYTES;
    public const SLOT_BYTES = self::NONCE_BYTES + self::WRAPPED_KEY_BYTES;
    public const HEADER_MAC_BYTES = 32;

    public const FLAG_RECOVERY_SLOT = 0x01;
    public const KDF_ARGON2ID13 = 0x01;
    public const AEAD_XCHACHA20POLY1305 = 0x01;
    public const STREAM_SECRETSTREAM_XCHACHA20POLY1305 = 0x01;
    public const HASH_SHA256 = 0x01;

    public const RECORD_FILE_START = 0x01;
    public const RECORD_FILE_CHUNK = 0x02;
    public const RECORD_MANIFEST = 0x7F;
    public const RECORD_HEADER_BYTES = 5; // type:u8 || body_length:u32be
    public const FILE_ID_BYTES = 16;
    public const STREAM_HEADER_BYTES = 24;
    public const CHUNK_BYTES = 4_194_304; // exactly 4 MiB; all non-final chunks use this size.
    public const MAX_CIPHER_CHUNK_BYTES = self::CHUNK_BYTES + 17;

    public const MIN_KDF_OPS = 2;
    public const MAX_KDF_OPS = 4;
    public const DEFAULT_KDF_OPS = 3;
    public const DEFAULT_KDF_MEM_BYTES = 268_435_456; // 256 MiB
    public const MIN_KDF_MEM_BYTES = 67_108_864; // 64 MiB
    public const MAX_KDF_MEM_BYTES = 268_435_456; // 256 MiB

    public const MAX_FILE_CHUNK_RECORD_BYTES = self::CHUNK_BYTES + self::FILE_ID_BYTES + 4 + 17;
    public const MAX_MANIFEST_BYTES = 4_194_304; // 4 MiB; above the grammar's maximum for 10,000 entries
    public const MAX_MANIFEST_RECORD_BYTES = self::MAX_MANIFEST_BYTES + self::NONCE_BYTES + self::AEAD_TAG_BYTES;
    // Conservative upper bound for plaintext bytes plus worst-case per-record framing and manifest.
    public const MAX_PACKAGE_BYTES = 107_452_366_757; // 100 GiB data + bounded framing/manifest overhead
    public const MAX_NODES = 10_000; // conservative to bound PHP array/graph-validation memory
    public const MAX_FILE_BYTES = 17_179_869_184; // 16 GiB
    public const MAX_TOTAL_PLAIN_BYTES = 107_374_182_400; // 100 GiB
    public const MAX_FILENAME_BYTES = 255;
    public const MAX_PATH_BYTES = 4096;
    public const MAX_DEPTH = 256;

    private const ZERO_ID = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    public static function assertRuntime(): void
    {
        if (PHP_INT_SIZE < 8) {
            throw new RuntimeException('The stable package format requires a 64-bit PHP runtime.');
        }
        $requiredFunctions = [
            'sodium_crypto_pwhash',
            'sodium_memzero',
            'sodium_crypto_aead_xchacha20poly1305_ietf_encrypt',
            'sodium_crypto_aead_xchacha20poly1305_ietf_decrypt',
            'sodium_crypto_secretstream_xchacha20poly1305_init_push',
            'sodium_crypto_secretstream_xchacha20poly1305_init_pull',
            'sodium_crypto_secretstream_xchacha20poly1305_push',
            'sodium_crypto_secretstream_xchacha20poly1305_pull',
            'hash_hkdf',
            'hash_hmac',
        ];
        if (!extension_loaded('sodium') || !defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13')) {
            throw new RuntimeException('The sodium extension with Argon2id support is required.');
        }
        foreach ($requiredFunctions as $function) {
            if (!function_exists($function)) {
                throw new RuntimeException('The cryptographic runtime is missing a required function.');
            }
        }
    }

    public static function zeroId(): string
    {
        return self::ZERO_ID;
    }

    public static function isZeroBytes(string $value): bool
    {
        return $value !== '' && hash_equals(str_repeat("\0", strlen($value)), $value);
    }

    public static function randomNonZeroBytes(int $length): string
    {
        if ($length < 1 || $length > 1024) {
            throw new RuntimeException('Invalid random-byte length.');
        }
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $value = random_bytes($length);
            if (!self::isZeroBytes($value)) {
                return $value;
            }
        }
        throw new RuntimeException('Unable to generate nonzero cryptographic randomness.');
    }

    public static function assertKdfParameters(int $ops, int $memoryBytes): void
    {
        // Bounds are checked before Argon2id is invoked. Header bytes are attacker-controlled
        // until the wrapped root key and header MAC have been authenticated.
        if ($ops < self::MIN_KDF_OPS || $ops > self::MAX_KDF_OPS
            || $memoryBytes < self::MIN_KDF_MEM_BYTES || $memoryBytes > self::MAX_KDF_MEM_BYTES
            || ($memoryBytes % 1024) !== 0) {
            throw new RuntimeException('Unsupported or unsafe password-hashing parameters.');
        }
    }

    public static function packUint64(int $value): string
    {
        if ($value < 0 || PHP_INT_SIZE < 8) {
            throw new RuntimeException('Invalid unsigned 64-bit integer.');
        }
        $base = 4_294_967_296;
        $high = intdiv($value, $base);
        $low = $value % $base;
        return pack('N2', $high, $low);
    }

    public static function unpackUint64(string $bytes): int
    {
        if (strlen($bytes) !== 8 || PHP_INT_SIZE < 8) {
            throw new RuntimeException('Invalid unsigned 64-bit integer.');
        }
        $parts = unpack('Nhigh/Nlow', $bytes);
        if (!is_array($parts)) {
            throw new RuntimeException('Invalid unsigned 64-bit integer.');
        }
        $value = ((int) $parts['high'] * 4_294_967_296) + (int) $parts['low'];
        if ($value < 0 || $value > PHP_INT_MAX) {
            throw new RuntimeException('Unsigned 64-bit integer exceeds this runtime.');
        }
        return $value;
    }

    public static function writeAll($handle, string $bytes): void
    {
        $offset = 0;
        $length = strlen($bytes);
        while ($offset < $length) {
            $written = fwrite($handle, substr($bytes, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Unable to write package data.');
            }
            $offset += $written;
        }
    }

    public static function readExact($handle, int $length): string
    {
        if ($length < 0) {
            throw new RuntimeException('Invalid read length.');
        }
        $data = '';
        while (strlen($data) < $length && !feof($handle)) {
            $chunk = fread($handle, $length - strlen($data));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $data .= $chunk;
        }
        if (strlen($data) !== $length) {
            // A short read may contain partial plaintext when this helper is used by
            // the writer. Clear it before surfacing truncation.
            if ($data !== '' && function_exists('sodium_memzero')) {
                sodium_memzero($data);
            }
            throw new RuntimeException('Package is truncated.');
        }
        return $data;
    }

    /** Parse the fixed header and reject unsafe algorithm or KDF parameters before derivation. */
    public static function parseHeader(string $raw): array
    {
        self::assertRuntime();
        if (strlen($raw) !== self::HEADER_BYTES || !hash_equals(self::MAGIC, substr($raw, 0, 8))) {
            throw new RuntimeException('Unable to open package.');
        }

        $flags = ord($raw[8]);
        $kdfId = ord($raw[9]);
        $aeadId = ord($raw[10]);
        $streamId = ord($raw[11]);
        $hashId = ord($raw[12]);
        $ops = unpack('Nvalue', substr($raw, 13, 4))['value'] ?? 0;
        $memoryBytes = unpack('Nvalue', substr($raw, 17, 4))['value'] ?? 0;
        $packageId = substr($raw, 21, self::PACKAGE_ID_BYTES);
        $salt = substr($raw, 45, self::SALT_BYTES);
        $primaryNonce = substr($raw, 77, self::NONCE_BYTES);
        $primaryCipher = substr($raw, 101, self::WRAPPED_KEY_BYTES);
        $recoveryNonce = substr($raw, 149, self::NONCE_BYTES);
        $recoveryCipher = substr($raw, 173, self::WRAPPED_KEY_BYTES);
        $headerMac = substr($raw, 221, self::HEADER_MAC_BYTES);

        if (($flags & ~self::FLAG_RECOVERY_SLOT) !== 0
            || $kdfId !== self::KDF_ARGON2ID13
            || $aeadId !== self::AEAD_XCHACHA20POLY1305
            || $streamId !== self::STREAM_SECRETSTREAM_XCHACHA20POLY1305
            || $hashId !== self::HASH_SHA256) {
            throw new RuntimeException('Unsupported package cryptographic parameters.');
        }
        self::assertKdfParameters((int) $ops, (int) $memoryBytes);
        if (self::isZeroBytes($packageId) || self::isZeroBytes($salt)
            || self::isZeroBytes($primaryNonce)) {
            throw new RuntimeException('Unable to open package.');
        }

        $hasRecovery = ($flags & self::FLAG_RECOVERY_SLOT) !== 0;
        if ($hasRecovery) {
            if (self::isZeroBytes($recoveryNonce)) {
                throw new RuntimeException('Unable to open package.');
            }
        } elseif (!self::isZeroBytes($recoveryNonce) || !self::isZeroBytes($recoveryCipher)) {
            throw new RuntimeException('Unable to open package.');
        }

        return [
            'raw' => $raw,
            'core' => substr($raw, 0, self::CORE_BYTES),
            'core_hash' => hash('sha256', substr($raw, 0, self::CORE_BYTES), true),
            'flags' => $flags,
            'has_recovery' => $hasRecovery,
            'kdf_id' => $kdfId,
            'aead_id' => $aeadId,
            'stream_id' => $streamId,
            'hash_id' => $hashId,
            'ops' => (int) $ops,
            'memory_bytes' => (int) $memoryBytes,
            'package_id' => $packageId,
            'package_id_hex' => bin2hex($packageId),
            'salt' => $salt,
            'primary_nonce' => $primaryNonce,
            'primary_cipher' => $primaryCipher,
            'recovery_nonce' => $recoveryNonce,
            'recovery_cipher' => $recoveryCipher,
            'header_mac' => $headerMac,
        ];
    }

    /** Build a manifest with no application or format-version fields. */
    public static function encodeManifest(array $entries): string
    {
        if (count($entries) > self::MAX_NODES) {
            throw new RuntimeException('Package contains too many entries.');
        }
        $bytes = pack('N', count($entries));
        $files = 0;
        $directories = 0;
        foreach ($entries as $entry) {
            $type = $entry['type'] ?? 0;
            $id = $entry['id'] ?? '';
            $parent = $entry['parent_id'] ?? '';
            $name = $entry['name'] ?? '';
            if (!in_array($type, [1, 2], true) || !is_string($id) || strlen($id) !== self::FILE_ID_BYTES
                || self::isZeroBytes($id) || !is_string($parent) || strlen($parent) !== self::FILE_ID_BYTES
                || !is_string($name)) {
                throw new RuntimeException('Invalid manifest entry.');
            }
            self::assertName($name);
            $nameLength = strlen($name);
            if ($nameLength < 1 || $nameLength > self::MAX_FILENAME_BYTES) {
                throw new RuntimeException('Invalid manifest entry name.');
            }
            $bytes .= chr($type) . $id . $parent . pack('n', $nameLength) . $name;
            if ($type === 2) {
                $size = $entry['size'] ?? -1;
                $chunks = $entry['chunks'] ?? 0;
                if (!is_int($size) || $size < 0 || $size > self::MAX_FILE_BYTES || !is_int($chunks)
                    || $chunks !== self::expectedChunkCount($size)) {
                    throw new RuntimeException('Invalid manifest file metadata.');
                }
                $bytes .= self::packUint64($size) . pack('N', $chunks);
                $files++;
            } else {
                $directories++;
            }
            if (strlen($bytes) > self::MAX_MANIFEST_BYTES) {
                throw new RuntimeException('Manifest exceeds the stable format limit.');
            }
        }
        if ($files < 1) {
            throw new RuntimeException('A package must contain at least one regular file.');
        }
        return $bytes;
    }

    /** Decode the binary manifest, validate the graph, and return canonical entries with paths. */
    public static function decodeManifest(string $plain): array
    {
        $length = strlen($plain);
        if ($length < 4 || $length > self::MAX_MANIFEST_BYTES) {
            throw new RuntimeException('Manifest length is invalid.');
        }
        $count = unpack('Nvalue', substr($plain, 0, 4))['value'] ?? 0;
        if ($count < 1 || $count > self::MAX_NODES) {
            throw new RuntimeException('Manifest entry count is invalid.');
        }

        $offset = 4;
        $entries = [];
        $byId = [];
        $files = 0;
        $directories = 0;
        $declaredTotal = 0;
        for ($i = 0; $i < $count; $i++) {
            if ($offset + 35 > $length) {
                throw new RuntimeException('Manifest is truncated.');
            }
            $type = ord($plain[$offset]);
            $offset++;
            $id = substr($plain, $offset, self::FILE_ID_BYTES);
            $offset += self::FILE_ID_BYTES;
            $parentId = substr($plain, $offset, self::FILE_ID_BYTES);
            $offset += self::FILE_ID_BYTES;
            $nameLength = unpack('nvalue', substr($plain, $offset, 2))['value'] ?? 0;
            $offset += 2;
            if (!in_array($type, [1, 2], true) || self::isZeroBytes($id)
                || isset($byId[bin2hex($id)]) || $nameLength < 1 || $nameLength > self::MAX_FILENAME_BYTES
                || $offset + $nameLength > $length) {
                throw new RuntimeException('Manifest entry is invalid.');
            }
            $name = substr($plain, $offset, $nameLength);
            $offset += $nameLength;
            self::assertName($name);
            $entry = ['type' => $type, 'id' => $id, 'id_hex' => bin2hex($id), 'parent_id' => $parentId,
                'parent_hex' => bin2hex($parentId), 'name' => $name, 'size' => null, 'chunks' => null];
            if ($type === 2) {
                if ($offset + 12 > $length) {
                    throw new RuntimeException('Manifest file metadata is truncated.');
                }
                $size = self::unpackUint64(substr($plain, $offset, 8));
                $offset += 8;
                $chunks = unpack('Nvalue', substr($plain, $offset, 4))['value'] ?? 0;
                $offset += 4;
                if ($size > self::MAX_FILE_BYTES || $chunks !== self::expectedChunkCount($size)) {
                    throw new RuntimeException('Manifest file metadata is invalid.');
                }
                $entry['size'] = $size;
                $entry['chunks'] = (int) $chunks;
                $declaredTotal += $size;
                if ($declaredTotal > self::MAX_TOTAL_PLAIN_BYTES) {
                    throw new RuntimeException('Manifest exceeds the total data limit.');
                }
                $files++;
            } else {
                $directories++;
            }
            $byId[$entry['id_hex']] = count($entries);
            $entries[] = $entry;
        }
        if ($offset !== $length || $files < 1 || count($entries) !== $count) {
            throw new RuntimeException('Manifest contains trailing or missing data.');
        }

        $states = [];
        $paths = [];
        $foldedNames = [];
        foreach ($entries as $entry) {
            $parentHex = $entry['parent_hex'];
            if ($parentHex !== str_repeat('0', self::FILE_ID_BYTES * 2)) {
                if (!isset($byId[$parentHex])) {
                    throw new RuntimeException('Manifest references a missing parent.');
                }
                $parent = $entries[$byId[$parentHex]];
                if ($parent['type'] !== 1 || $parent['id_hex'] === $entry['id_hex']) {
                    throw new RuntimeException('Manifest parent reference is invalid.');
                }
            }
            $fold = self::foldName($entry['name']);
            $siblingKey = $parentHex . "\0" . $fold;
            if (isset($foldedNames[$siblingKey])) {
                throw new RuntimeException('Manifest contains colliding names.');
            }
            $foldedNames[$siblingKey] = true;
        }

        foreach ($entries as $entry) {
            $idHex = $entry['id_hex'];
            $paths[$idHex] = self::resolvePath($idHex, $entries, $byId, $states, $paths, 1);
        }
        $previousPath = null;
        foreach ($entries as &$entry) {
            $path = $paths[$entry['id_hex']];
            if ($previousPath !== null && strcmp($previousPath, $path) >= 0) {
                throw new RuntimeException('Manifest entries are not in canonical path order.');
            }
            $previousPath = $path;
            $entry['path'] = $path;
            $entry['depth'] = substr_count($path, '/') + 1;
        }
        unset($entry);

        return ['entries' => $entries, 'file_count' => $files, 'directory_count' => $directories,
            'total_plain_bytes' => $declaredTotal];
    }

    public static function expectedChunkCount(int $size): int
    {
        if ($size < 0) {
            throw new RuntimeException('Invalid file size.');
        }
        return max(1, (int) ceil($size / self::CHUNK_BYTES));
    }

    public static function assertName(string $name): void
    {
        if ($name === '' || $name === '.' || $name === '..' || strlen($name) > self::MAX_FILENAME_BYTES
            || preg_match('//u', $name) !== 1 || str_contains($name, "\0")
            || str_contains($name, '/') || str_contains($name, '\\')
            || preg_match('/[\x00-\x1F\x7F:<>"|?*]/u', $name) === 1
            || str_ends_with($name, ' ') || str_ends_with($name, '.')
            || preg_match('/^(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:[ .].*)?$/iu', $name) === 1) {
            throw new RuntimeException('Unsafe or unsupported filesystem name.');
        }
        self::foldName($name); // Ensure collision checking is safe on this runtime.
    }

    public static function foldName(string $name): string
    {
        $hasNonAscii = preg_match('/[^\x00-\x7F]/', $name) === 1;
        if ($hasNonAscii) {
            // Unicode normalization and case-folding vary across filesystems. To avoid
            // generating packages whose paths collide after transfer, require both APIs
            // for non-ASCII names and accept only already-normalized NFC names.
            if (!function_exists('mb_strtolower') || !class_exists('Normalizer')) {
                throw new RuntimeException('Non-ASCII names require mbstring and intl for portable path validation.');
            }
            $normalized = \Normalizer::normalize($name, \Normalizer::FORM_C);
            if (!is_string($normalized) || !hash_equals($normalized, $name)) {
                throw new RuntimeException('Non-ASCII filenames must use Unicode NFC normalization.');
            }
        }
        if (function_exists('mb_convert_case') && defined('MB_CASE_FOLD')) {
            return mb_convert_case($name, MB_CASE_FOLD, 'UTF-8');
        }
        if (function_exists('mb_strtolower')) {
            return mb_strtolower($name, 'UTF-8');
        }
        return strtolower($name);
    }

    private static function resolvePath(string $idHex, array $entries, array $byId, array &$states, array &$paths, int $depth): string
    {
        if (($states[$idHex] ?? 0) === 1) {
            throw new RuntimeException('Manifest directory graph contains a cycle.');
        }
        if (($states[$idHex] ?? 0) === 2) {
            return $paths[$idHex];
        }
        if ($depth > self::MAX_DEPTH || !isset($byId[$idHex])) {
            throw new RuntimeException('Manifest directory depth is invalid.');
        }
        $states[$idHex] = 1;
        $entry = $entries[$byId[$idHex]];
        $zeroParent = str_repeat('0', self::FILE_ID_BYTES * 2);
        if ($entry['parent_hex'] === $zeroParent) {
            $path = $entry['name'];
        } else {
            $parentPath = self::resolvePath($entry['parent_hex'], $entries, $byId, $states, $paths, $depth + 1);
            $path = $parentPath . '/' . $entry['name'];
        }
        if (strlen($path) > self::MAX_PATH_BYTES) {
            throw new RuntimeException('Manifest path exceeds the supported limit.');
        }
        $states[$idHex] = 2;
        $paths[$idHex] = $path;
        return $path;
    }
}