<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;
use SecurePackage\Project\V14Descriptor;

final class V14KeyDerivation
{
    public static function credentialWrapKey(string $password, string $pattern, string $salt): string
    {
        self::assertRuntime();
        Validator::secret($password, 'Password');
        Validator::secret($pattern, 'Pattern');
        if (strlen($salt) !== V14Descriptor::SALT_BYTES) throw new RuntimeException('Invalid KDF salt.');
        $profile = V14Descriptor::kdfProfile();
        $passwordSalt = self::purposeSalt($salt, 'password');
        $patternSalt = self::purposeSalt($salt, 'pattern');
        $passwordKey = sodium_crypto_pwhash(V14Descriptor::KEY_BYTES, $password, $passwordSalt, $profile['ops'], $profile['mem'], SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $patternKey = sodium_crypto_pwhash(V14Descriptor::KEY_BYTES, $pattern, $patternSalt, $profile['ops'], $profile['mem'], SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        try {
            return self::hkdf($passwordKey . $patternKey, 'SecurePackage|V14|credential-wrap', $salt);
        } finally {
            sodium_memzero($passwordKey);
            sodium_memzero($patternKey);
        }
    }

    public static function deriveSubkey(string $root, string $purpose, string $context = ''): string
    {
        if (strlen($root) !== V14Descriptor::KEY_BYTES || $purpose === '' || strlen($context) > 1024) throw new RuntimeException('Invalid key derivation request.');
        return self::hkdf($root, 'SecurePackage|V14|subkey|' . $purpose . '|' . $context, '');
    }

    public static function deriveFileKey(string $fileRoot, string $fileId): string
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $fileId)) throw new RuntimeException('Invalid file identifier.');
        return self::deriveSubkey($fileRoot, 'file', 'id:' . $fileId);
    }

    public static function headerBinding(array $headerCore): string
    {
        return hash('sha256', \SecurePackage\Security\CanonicalJson::encode($headerCore));
    }

    private static function purposeSalt(string $salt, string $purpose): string
    {
        return substr(hash('sha256', 'SecurePackage|V14|salt|' . $purpose . '|' . $salt, true), 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
    }

    private static function hkdf(string $ikm, string $info, string $salt, int $length = 32): string
    {
        if (!function_exists('hash_hkdf')) throw new RuntimeException('HKDF is unavailable.');
        $result = hash_hkdf('sha256', $ikm, $length, $info, $salt);
        if (!is_string($result) || strlen($result) !== $length) throw new RuntimeException('Key derivation failed.');
        return $result;
    }

    private static function assertRuntime(): void
    {
        if (!extension_loaded('sodium') || !defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13')) throw new RuntimeException('The sodium extension with Argon2id is required.');
    }
}

final class Validator
{
    public static function secret(string $value, string $label): void
    {
        if ($value === '' || strlen($value) > 4096 || str_contains($value, "\0") || preg_match('//u', $value) !== 1) {
            throw new RuntimeException($label . ' is invalid.');
        }
    }
}
