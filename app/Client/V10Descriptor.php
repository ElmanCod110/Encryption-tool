<?php
declare(strict_types=1);

namespace SecurePackage\Client;

final class V10Descriptor
{
    public const FORMAT = 'SECURE-BROWSER-V10';
    public const VERSION = 10;
    public const MAGIC = 'SPK10BIN1';
    public const CHUNK_MIN = 1024 * 1024;
    public const CHUNK_TARGET = 4 * 1024 * 1024;
    public const CHUNK_MAX = 8 * 1024 * 1024;
    public const PBKDF2_ITERATIONS = 1200000;

    public static function descriptor(): array
    {
        return [
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'magic' => self::MAGIC,
            'kdf' => 'PBKDF2-HMAC-SHA-256',
            'iterations' => self::PBKDF2_ITERATIONS,
            'key_schedule' => 'HKDF-SHA-256',
            'content_encryption' => 'AES-256-GCM',
            'nonce_derivation' => 'HMAC-SHA-256',
            'chunking' => 'content-defined',
            'chunk_min' => self::CHUNK_MIN,
            'chunk_target' => self::CHUNK_TARGET,
            'chunk_max' => self::CHUNK_MAX,
            'integrity' => 'SHA-256-Merkle',
            'server_plaintext' => false,
            'recovery_slots' => true,
            'credential_rotation' => true,
        ];
    }
}
