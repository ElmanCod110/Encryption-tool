<?php
declare(strict_types=1);

namespace SecurePackage\Client;

use RuntimeException;

/**
 * Builds a browser-compatible encryption envelope. The browser profile is intentionally
 * separate from the server-native XChaCha20 package profile and uses WebCrypto AES-GCM.
 * Password material is never sent to this class by the browser API.
 */
final class BrowserEnvelope
{
    public const FORMAT = 'SECURE-BROWSER-V6';
    public const PBKDF2_ITERATIONS = 900000;
    public const SALT_BYTES = 32;
    public const IV_BYTES = 12;

    public static function descriptor(string $packageId): array
    {
        if (!preg_match('/^[a-f0-9]{48}$/', $packageId)) {
            throw new RuntimeException('Invalid package identifier.');
        }
        return [
            'format' => self::FORMAT,
            'version' => 6,
            'key_derivation' => [
                'name' => 'PBKDF2-HMAC-SHA-256',
                'iterations' => self::PBKDF2_ITERATIONS,
                'salt_bytes' => self::SALT_BYTES,
            ],
            'content_encryption' => 'AES-256-GCM',
            'iv_bytes' => self::IV_BYTES,
            'package_id' => $packageId,
        ];
    }
}
