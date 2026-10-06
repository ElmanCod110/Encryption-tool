<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

/**
 * Versioned V10 key schedule. Password and pattern are independent KDF domains.
 */
final class KeyDerivationV10
{
    public const CONTEXT = 'SECURE-PKG-V10';
    public const MASTER_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    public const SALT_BYTES = 32;
    public const DEFAULT_OPSLIMIT = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
    public const DEFAULT_MEMLIMIT = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;

    public static function deriveContentRootKey(string $password, string $pattern, string $salt): string
    {
        self::validate($password, $pattern, $salt);
        $passwordKey = self::pwhash($password, self::purposeSalt($salt, 'password'));
        $patternKey = self::pwhash($pattern, self::purposeSalt($salt, 'pattern'));
        try {
            $combined = hash_hmac('sha256', $patternKey, $passwordKey, true);
            return self::hkdf($combined, 'content-root', self::MASTER_BYTES, $salt);
        } finally {
            sodium_memzero($passwordKey);
            sodium_memzero($patternKey);
        }
    }

    public static function deriveCredentialWrapKey(string $password, string $pattern, string $salt): string
    {
        self::validate($password, $pattern, $salt);
        $passwordKey = self::pwhash($password, self::purposeSalt($salt, 'credential-password'));
        $patternKey = self::pwhash($pattern, self::purposeSalt($salt, 'credential-pattern'));
        try {
            $combined = hash_hmac('sha256', $passwordKey, $patternKey, true);
            return self::hkdf($combined, 'credential-wrap', self::MASTER_BYTES, $salt);
        } finally {
            sodium_memzero($passwordKey);
            sodium_memzero($patternKey);
        }
    }

    public static function deriveRecoveryWrapKey(string $recoveryKey, string $salt): string
    {
        if ($recoveryKey === '' || strlen($salt) !== self::SALT_BYTES) {
            throw new RuntimeException('Invalid recovery key material.');
        }
        $passwordSalt = self::purposeSalt($salt, 'recovery');
        return sodium_crypto_pwhash(self::MASTER_BYTES, $recoveryKey, $passwordSalt, self::DEFAULT_OPSLIMIT, self::DEFAULT_MEMLIMIT, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    }

    public static function deriveSubkey(string $contentRootKey, string $purpose, string $context = ''): string
    {
        if (strlen($contentRootKey) !== self::MASTER_BYTES || $purpose === '') {
            throw new RuntimeException('Invalid key derivation request.');
        }
        return self::hkdf($contentRootKey, $purpose, self::MASTER_BYTES, $context);
    }

    public static function deriveFileKey(string $fileRootKey, string $fileId): string
    {
        return self::deriveSubkey($fileRootKey, 'file-key', 'file-id:' . $fileId);
    }

    private static function pwhash(string $secret, string $salt): string
    {
        return sodium_crypto_pwhash(self::MASTER_BYTES, $secret, $salt, self::DEFAULT_OPSLIMIT, self::DEFAULT_MEMLIMIT, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    }

    private static function validate(string $password, string $pattern, string $salt): void
    {
        if (!extension_loaded('sodium') || $password === '' || $pattern === '' || strlen($salt) !== self::SALT_BYTES) {
            throw new RuntimeException('Invalid credential material.');
        }
    }

    private static function purposeSalt(string $salt, string $purpose): string
    {
        return substr(hash('sha256', self::CONTEXT . '|salt|' . $purpose . '|' . $salt, true), 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
    }

    private static function hkdf(string $ikm, string $info, int $length, string $salt): string
    {
        $prk = hash_hmac('sha256', $ikm, $salt !== '' ? $salt : str_repeat("\0", 32), true);
        $result = '';
        $previous = '';
        for ($counter = 1; strlen($result) < $length; $counter++) {
            $previous = hash_hmac('sha256', $previous . $info . chr($counter), $prk, true);
            $result .= $previous;
        }
        return substr($result, 0, $length);
    }
}
