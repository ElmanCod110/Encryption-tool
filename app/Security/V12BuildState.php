<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

/**
 * Encrypts non-secret build checkpoints for crash recovery.
 * The checkpoint stores state only; credentials and plaintext are never accepted.
 */
final class V12BuildState
{
    private const MAGIC = 'SPK12STATE1';
    private const INFO = 'SecurePackage|V12|build-state';

    public static function seal(array $state, string $password, string $pattern, string $salt): string
    {
        if ($password === '' || $pattern === '' || strlen($salt) !== 32) {
            throw new RuntimeException('Invalid build-state inputs.');
        }
        self::assertSafeState($state);
        $key = self::deriveKey($password, $pattern, $salt);
        try {
            $iv = random_bytes(12);
            $aad = self::MAGIC . '|' . hash('sha256', $salt);
            $plain = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
            if ($cipher === false) {
                throw new RuntimeException('Unable to encrypt build state.');
            }
            return base64_encode($iv . $tag . $cipher);
        } finally {
            sodium_memzero($key);
        }
    }

    public static function open(string $sealed, string $password, string $pattern, string $salt): array
    {
        $raw = base64_decode($sealed, true);
        if ($raw === false || strlen($raw) < 28 || strlen($salt) !== 32) {
            throw new RuntimeException('Invalid build-state envelope.');
        }
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $cipher = substr($raw, 28);
        $key = self::deriveKey($password, $pattern, $salt);
        try {
            $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, self::MAGIC . '|' . hash('sha256', $salt));
            if ($plain === false) {
                throw new RuntimeException('Unable to authenticate build state.');
            }
            $state = json_decode($plain, true, 64, JSON_THROW_ON_ERROR);
            if (!is_array($state)) {
                throw new RuntimeException('Invalid build state.');
            }
            self::assertSafeState($state);
            return $state;
        } finally {
            sodium_memzero($key);
        }
    }

    private static function deriveKey(string $password, string $pattern, string $salt): string
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Cryptographic runtime unavailable.');
        }
        $a = sodium_crypto_pwhash(32, $password, substr(hash('sha256', self::INFO . '|password|' . $salt, true), 0, 16), SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $b = sodium_crypto_pwhash(32, $pattern, substr(hash('sha256', self::INFO . '|pattern|' . $salt, true), 0, 16), SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        try {
            return hash_hmac('sha256', $b, $a, true);
        } finally {
            sodium_memzero($a);
            sodium_memzero($b);
        }
    }

    private static function assertSafeState(array $state): void
    {
        foreach (['password', 'pattern', 'plaintext', 'root_key', 'content_root_key'] as $forbidden) {
            if (array_key_exists($forbidden, $state)) {
                throw new RuntimeException('Sensitive data is not permitted in build state.');
            }
        }
        $encoded = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (strlen($encoded) > 4 * 1024 * 1024) {
            throw new RuntimeException('Build state is too large.');
        }
    }
}
