<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

/**
 * Persistent local secrets used for non-user, server-side derivations.
 *
 * Production deployments may provide SPK_NAME_PEPPER explicitly. For local
 * XAMPP-style deployments, a random 256-bit secret is generated once and
 * stored outside public/ with restrictive permissions so the application is
 * usable without a fragile manual environment setup step.
 */
final class ApplicationSecrets
{
    private const ENV_NAME_PEPPER = 'SPK_NAME_PEPPER';
    private const MIN_PEPPER_BYTES = 32;
    private const MAX_PEPPER_BYTES = 4096;

    public static function namePepper(string $storageRoot): string
    {
        $configured = getenv(self::ENV_NAME_PEPPER);
        if ($configured !== false && trim($configured) !== '') {
            $pepper = (string) $configured;
            self::assertPepper($pepper);
            return $pepper;
        }

        if ($storageRoot === '' || str_contains($storageRoot, "\0")) {
            throw new RuntimeException('Invalid storage root.');
        }
        $secretsDir = rtrim($storageRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'secrets';
        if (!is_dir($secretsDir) && !mkdir($secretsDir, 0700, true) && !is_dir($secretsDir)) {
            throw new RuntimeException('Unable to initialize application secrets.');
        }
        @chmod($secretsDir, 0700);

        $path = $secretsDir . DIRECTORY_SEPARATOR . 'name-pepper.bin';
        if (!is_file($path)) {
            $fresh = random_bytes(self::MIN_PEPPER_BYTES);
            $handle = @fopen($path, 'xb');
            if ($handle !== false) {
                try {
                    @chmod($path, 0600);
                    $written = fwrite($handle, $fresh);
                    if ($written !== strlen($fresh)) {
                        throw new RuntimeException('Unable to initialize application secret.');
                    }
                    fflush($handle);
                } finally {
                    fclose($handle);
                    sodium_memzero($fresh);
                }
            } else {
                sodium_memzero($fresh);
            }
        }

        $pepper = @file_get_contents($path);
        if ($pepper === false) {
            throw new RuntimeException('Unable to read application secret.');
        }
        @chmod($path, 0600);
        self::assertPepper($pepper);
        return $pepper;
    }

    private static function assertPepper(string $pepper): void
    {
        $length = strlen($pepper);
        if ($length < self::MIN_PEPPER_BYTES || $length > self::MAX_PEPPER_BYTES || str_contains($pepper, "\0")) {
            throw new RuntimeException('SPK_NAME_PEPPER must contain at least 32 non-null bytes.');
        }
    }
}
