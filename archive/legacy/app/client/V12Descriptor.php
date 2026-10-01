<?php
declare(strict_types=1);

namespace SecurePackage\Client;

use RuntimeException;

/**
 * Canonical V12 browser-package descriptor.
 */
final class V12Descriptor
{
    public const FORMAT = 'SECURE-BROWSER-V12';
    public const VERSION = 12;
    public const MAGIC = 'SPK12BIN1';
    public const FOOTER = 'SPK12FOOT';
    public const EXTENSION = '.spk12';
    public const CHUNK_MIN = 1024 * 1024;
    public const CHUNK_TARGET = 4 * 1024 * 1024;
    public const CHUNK_MAX = 8 * 1024 * 1024;
    public const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;
    public const MAX_MANIFEST_BYTES = 256 * 1024 * 1024;

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
            'credentials_to_server' => false,
            'kdf' => 'PBKDF2-HMAC-SHA-256',
            'key_separation' => 'HKDF-SHA-256',
            'content_encryption' => 'AES-256-GCM',
            'chunk_integrity' => 'SHA-256',
            'package_integrity' => 'SHA-256-Merkle',
            'chunking' => [
                'algorithm' => 'content-defined',
                'min' => self::CHUNK_MIN,
                'target' => self::CHUNK_TARGET,
                'max' => self::CHUNK_MAX,
            ],
            'security_stage' => 'release-candidate-hardening',
        ];
    }

    public static function validatePackageId(string $packageId): void
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $packageId)) {
            throw new RuntimeException('Invalid package identifier.');
        }
    }
}
