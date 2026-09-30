<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

/**
 * Wraps a content root key under one or more credential slots.
 * The wrapped key allows credential rotation without re-encrypting file data.
 */
final class KeyEnvelope
{
    private const CONTEXT = 'SecurePackage|V10|key-envelope|';
    private const SLOT_VERSION = 1;

    public static function create(string $contentRootKey, string $password, string $pattern, string $salt): array
    {
        self::assertKey($contentRootKey);
        $wrapKey = KeyDerivationV10::deriveCredentialWrapKey($password, $pattern, $salt);
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $wrapped = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $contentRootKey,
                self::CONTEXT . 'primary',
                $nonce,
                $wrapKey
            );
            return [
                'version' => self::SLOT_VERSION,
                'type' => 'password-pattern',
                'nonce' => base64_encode($nonce),
                'wrapped_key' => base64_encode($wrapped),
            ];
        } finally {
            sodium_memzero($wrapKey);
        }
    }

    public static function createRecoverySlot(string $contentRootKey, string $recoveryKey, string $salt): array
    {
        self::assertKey($contentRootKey);
        if (strlen($recoveryKey) < 24) {
            throw new RuntimeException('Recovery key is too short.');
        }
        $wrapKey = KeyDerivationV10::deriveRecoveryWrapKey($recoveryKey, $salt);
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $wrapped = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $contentRootKey,
                self::CONTEXT . 'recovery',
                $nonce,
                $wrapKey
            );
            return [
                'version' => self::SLOT_VERSION,
                'type' => 'recovery',
                'nonce' => base64_encode($nonce),
                'wrapped_key' => base64_encode($wrapped),
            ];
        } finally {
            sodium_memzero($wrapKey);
        }
    }

    public static function unwrapCredentialSlot(array $slot, string $password, string $pattern, string $salt): string
    {
        if (($slot['type'] ?? '') !== 'password-pattern') {
            throw new RuntimeException('Unsupported key slot.');
        }
        $wrapKey = KeyDerivationV10::deriveCredentialWrapKey($password, $pattern, $salt);
        try {
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                base64_decode((string) ($slot['wrapped_key'] ?? ''), true),
                self::CONTEXT . 'primary',
                base64_decode((string) ($slot['nonce'] ?? ''), true),
                $wrapKey
            );
            if ($plain === false) {
                throw new RuntimeException('Unable to unwrap content key.');
            }
            self::assertKey($plain);
            return $plain;
        } finally {
            sodium_memzero($wrapKey);
        }
    }

    public static function rotateCredentialSlot(array $slot, string $oldPassword, string $oldPattern, string $newPassword, string $newPattern, string $salt): array
    {
        $contentRootKey = self::unwrapCredentialSlot($slot, $oldPassword, $oldPattern, $salt);
        try {
            return self::create($contentRootKey, $newPassword, $newPattern, $salt);
        } finally {
            sodium_memzero($contentRootKey);
        }
    }

    private static function assertKey(string $key): void
    {
        if (!extension_loaded('sodium') || strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new RuntimeException('Invalid content key.');
        }
    }
}
