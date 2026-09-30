<?php
declare(strict_types=1);

namespace SecurePackage\Client;

use RuntimeException;

final class UnifiedBrowserPackage
{
    public const FORMAT = 'SECURE-BROWSER-V7';
    public const MAGIC = 'SPK7BIN1';
    public const VERSION = 7;
    public const CHUNK_SIZE = 4 * 1024 * 1024;
    public const PBKDF2_ITERATIONS = 900000;
    public const SALT_BYTES = 32;
    public const IV_BYTES = 12;

    public static function descriptor(): array
    {
        return [
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'transport' => 'opaque-binary',
            'key_derivation' => 'PBKDF2-HMAC-SHA-256',
            'kdf_iterations' => self::PBKDF2_ITERATIONS,
            'key_separation' => 'HKDF-SHA-256',
            'content_encryption' => 'AES-256-GCM',
            'integrity' => 'SHA-256-Merkle',
            'chunk_size' => self::CHUNK_SIZE,
            'server_plaintext' => false,
        ];
    }

    public static function validatePackageId(string $packageId): void
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $packageId)) {
            throw new RuntimeException('Invalid package identifier.');
        }
    }
}
