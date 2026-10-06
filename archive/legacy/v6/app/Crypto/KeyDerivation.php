<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

final class KeyDerivation
{
    public const MASTER_KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    public const SALT_BYTES = 32;
    public const CONTEXT = 'SECURE-PKG-V6';
    public const DEFAULT_OPSLIMIT = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
    public const DEFAULT_MEMLIMIT = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;

    public static function deriveMasterKey(string $password, string $pattern, string $salt, int $opslimit = self::DEFAULT_OPSLIMIT, int $memlimit = self::DEFAULT_MEMLIMIT): string
    {
        if (!extension_loaded('sodium')) throw new RuntimeException('The sodium extension is required.');
        if ($password === '' || $pattern === '' || strlen($salt) !== self::SALT_BYTES) throw new RuntimeException('Invalid credential material.');
        if ($opslimit !== self::DEFAULT_OPSLIMIT || $memlimit !== self::DEFAULT_MEMLIMIT) throw new RuntimeException('Unsupported KDF parameters.');
        $passwordSalt = self::purposeSalt($salt, 'password');
        $patternSalt = self::purposeSalt($salt, 'pattern');
        $passwordKey = sodium_crypto_pwhash(self::MASTER_KEY_BYTES, $password, $passwordSalt, $opslimit, $memlimit, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $patternKey = sodium_crypto_pwhash(self::MASTER_KEY_BYTES, $pattern, $patternSalt, $opslimit, $memlimit, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $combined = hash_hmac('sha256', $patternKey, $passwordKey, true);
        sodium_memzero($passwordKey); sodium_memzero($patternKey);
        return self::hkdf($combined, 'master', self::MASTER_KEY_BYTES, $salt);
    }
    public static function deriveSubkey(string $masterKey, string $purpose, string $context = ''): string
    {
        if (strlen($masterKey) !== self::MASTER_KEY_BYTES || $purpose === '') throw new RuntimeException('Invalid key derivation request.');
        return self::hkdf($masterKey, $purpose, self::MASTER_KEY_BYTES, $context);
    }
    public static function deriveFileKey(string $fileRootKey, string $fileId): string
    {
        return self::deriveSubkey($fileRootKey, 'file', 'file-id:' . $fileId);
    }
    private static function purposeSalt(string $salt, string $purpose): string
    {
        return substr(hash('sha256', self::CONTEXT . '|salt|' . $purpose . '|' . $salt, true), 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
    }
    private static function hkdf(string $ikm, string $info, int $length, string $salt): string
    {
        $prk = hash_hmac('sha256', $ikm, $salt !== '' ? $salt : str_repeat("\0", 32), true);
        $result = ''; $previous = '';
        for ($counter = 1; strlen($result) < $length; $counter++) {
            $previous = hash_hmac('sha256', $previous . $info . chr($counter), $prk, true);
            $result .= $previous;
        }
        return substr($result, 0, $length);
    }
}
