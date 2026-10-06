<?php
declare(strict_types=1);

namespace SecurePackage\Client;

final class BrowserV8
{
    public const FORMAT = 'SECURE-BROWSER-V8';
    public const MAGIC = 'SPK8BIN1';
    public const VERSION = 8;
    public const CHUNK_SIZE = 4 * 1024 * 1024;
    public const PBKDF2_ITERATIONS = 1200000;
    public const SALT_BYTES = 32;
    public const IV_BYTES = 12;

    public static function descriptor(): array
    {
        return [
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'container' => 'SPK8BIN1',
            'key_derivation' => 'PBKDF2-HMAC-SHA-256',
            'kdf_iterations' => self::PBKDF2_ITERATIONS,
            'key_separation' => 'HKDF-SHA-256',
            'content_encryption' => 'AES-256-GCM',
            'chunk_hash' => 'SHA-256',
            'integrity' => 'SHA-256-Merkle',
            'chunking' => 'fixed-4MiB',
            'content_addressing' => 'ciphertext-hash',
            'server_plaintext' => false,
            'server_receives_credentials' => false,
        ];
    }

    public static function validId(string $id): bool
    {
        return (bool) preg_match('/^[a-f0-9]{48}$/', $id);
    }
}
