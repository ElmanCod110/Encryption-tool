<?php
declare(strict_types=1);

namespace SecurePackage\Client;

final class BrowserV9
{
    public const FORMAT = 'SECURE-BROWSER-V9';
    public const MAGIC = 'SPK9BIN1';
    public const VERSION = 9;
    public const CHUNK_SIZE = 4 * 1024 * 1024;
    public const PBKDF2_ITERATIONS = 1_000_000;
    public const SALT_BYTES = 32;
    public const IV_BYTES = 12;
    public const PACKAGE_ID_HEX_LENGTH = 48;

    public static function descriptor(): array
    {
        return [
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'container' => self::MAGIC,
            'extension' => 'spk9',
            'key_derivation' => 'PBKDF2-HMAC-SHA-256',
            'kdf_iterations' => self::PBKDF2_ITERATIONS,
            'key_separation' => 'HKDF-SHA-256',
            'content_encryption' => 'AES-256-GCM',
            'filename_encryption' => 'AES-256-GCM',
            'manifest_encryption' => 'AES-256-GCM',
            'chunk_hash' => 'SHA-256',
            'integrity' => 'SHA-256-Merkle',
            'nonce_derivation' => 'HMAC-SHA-256',
            'chunk_size' => self::CHUNK_SIZE,
            'resumable_local_build' => true,
            'ciphertext_only_upload' => true,
            'server_plaintext' => false,
            'server_receives_credentials' => false,
            'release_integrity' => 'Ed25519 + SHA-256 + SRI',
        ];
    }

    public static function validPackageId(string $id): bool
    {
        return (bool) preg_match('/^[a-f0-9]{'.self::PACKAGE_ID_HEX_LENGTH.'}$/', $id);
    }
}
