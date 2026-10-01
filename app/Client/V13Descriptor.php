<?php
declare(strict_types=1);

namespace SecurePackage\Client;

use RuntimeException;

/**
 * Canonical V13 browser-package descriptor.
 *
 * V13 is deliberately fail-closed around untrusted package metadata. Browser
 * KDF uses Web Crypto PBKDF2-HMAC-SHA-256 for portability; the server-side
 * package engine continues to use Argon2id through libsodium.
 */
final class V13Descriptor
{
    public const FORMAT = 'SECURE-BROWSER-V13';
    public const VERSION = 13;
    public const MAGIC = 'SPK13BIN1';
    public const FOOTER = 'SPK13FOOT';
    public const EXTENSION = '.spk13';

    public const KDF = 'PBKDF2-HMAC-SHA-256';
    public const KDF_ITERATIONS = 1_500_000;

    public const CHUNK_MIN = 1024 * 1024;
    public const CHUNK_TARGET = 4 * 1024 * 1024;
    public const CHUNK_MAX = 8 * 1024 * 1024;

    public const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;
    public const MAX_HEADER_BYTES = 2 * 1024 * 1024;
    public const MAX_MANIFEST_BYTES = 32 * 1024 * 1024;
    public const MAX_FILES = 100_000;
    public const MAX_CHUNKS = 1_000_000;
    public const MAX_NAME_PARTS = 256;
    public const MAX_NAME_BYTES = 4096;
    public const MAX_TOTAL_PLAIN_BYTES = 64 * 1024 * 1024 * 1024;

    public static function descriptor(): array
    {
        return [
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'container_magic' => self::MAGIC,
            'footer_magic' => self::FOOTER,
            'extension' => self::EXTENSION,
            'transport' => 'opaque-ciphertext-stream',
            'server_plaintext' => false,
            'kdf' => self::KDF,
            'kdf_iterations' => self::KDF_ITERATIONS,
            'key_separation' => 'HKDF-SHA-256',
            'content_encryption' => 'AES-256-GCM',
            'chunk_integrity' => 'SHA-256',
            'package_integrity' => 'SHA-256-Merkle',
            'restore_policy' => 'fail-on-existing-path',
            'chunking' => [
                'algorithm' => 'content-defined-streaming',
                'min' => self::CHUNK_MIN,
                'target' => self::CHUNK_TARGET,
                'max' => self::CHUNK_MAX,
            ],
            'limits' => [
                'max_package_bytes' => self::MAX_PACKAGE_BYTES,
                'max_header_bytes' => self::MAX_HEADER_BYTES,
                'max_manifest_bytes' => self::MAX_MANIFEST_BYTES,
                'max_files' => self::MAX_FILES,
                'max_chunks' => self::MAX_CHUNKS,
                'max_name_parts' => self::MAX_NAME_PARTS,
                'max_name_bytes' => self::MAX_NAME_BYTES,
                'max_total_plain_bytes' => self::MAX_TOTAL_PLAIN_BYTES,
            ],
            'security_stage' => 'hardened-v13-development',
        ];
    }

    public static function validatePackageId(string $packageId): void
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $packageId)) {
            throw new RuntimeException('Invalid package identifier.');
        }
    }
}
