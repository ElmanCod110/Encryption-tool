<?php
declare(strict_types=1);

namespace TCH\Crypto;

use RuntimeException;

final class KeyDerivation
{
    public const MASTER_KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    public const SALT_BYTES = 32;
    public const CONTEXT = 'TCH-PKG-V1';

    public static function deriveMasterKey(string $password, string $pattern, string $salt): string
    {
        self::assertRuntime();
        if (strlen($salt) !== self::SALT_BYTES) {
            throw new RuntimeException('Invalid KDF salt length.');
        }
        $passwordSalt = substr(hash('sha256', self::CONTEXT . '|password|' . $salt, true), 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $passwordKey = sodium_crypto_pwhash(
            self::MASTER_KEY_BYTES,
            $password,
            $passwordSalt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        $patternSalt = substr(hash('sha256', self::CONTEXT . '|pattern|' . $salt, true), 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $patternKey = sodium_crypto_pwhash(
            self::MASTER_KEY_BYTES,
            $pattern,
            $patternSalt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );

        return self::hkdfX(
            hash_hmac('sha256', $patternKey, $passwordKey, true),
            'master',
            self::MASTER_KEY_BYTES,
            $salt
        );
    }

    public static function deriveSubkey(string $masterKey, string $purpose, string $context = ''): string
    {
        if (strlen($masterKey) !== self::MASTER_KEY_BYTES) {
            throw new RuntimeException('Invalid master key length.');
        }
        return self::hkdfX($masterKey, $purpose, self::MASTER_KEY_BYTES, $context);
    }

    private static function hkdfX(string $ikm, string $info, int $length, string $salt): string
    {
        $prk = hash_hmac('sha256', $ikm, $salt !== '' ? $salt : str_repeat("\0", 32), true);
        $result = '';
        $previous = '';
        $counter = 1;
        while (strlen($result) < $length) {
            $previous = hash_hmac('sha256', $previous . $info . chr($counter), $prk, true);
            $result .= $previous;
            $counter++;
        }
        return substr($result, 0, $length);
    }

    private static function assertRuntime(): void
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('The sodium extension is required.');
        }
    }
}
