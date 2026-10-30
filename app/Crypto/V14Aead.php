<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;
use SecurePackage\Project\V14Descriptor;

final class V14Aead
{
    public static function seal(string $plaintext, string $key, string $aad): string
    {
        self::assertKey($key);
        if (strlen($aad) > 16 * 1024) throw new RuntimeException('AAD is too large.');
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
        return $nonce . $cipher;
    }

    public static function open(string $packed, string $key, string $aad): string
    {
        self::assertKey($key);
        $min = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        if (strlen($packed) < $min) throw new RuntimeException('Unable to authenticate package data.');
        $nonce = substr($packed, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = substr($packed, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $aad, $nonce, $key);
        if ($plain === false) throw new RuntimeException('Unable to authenticate package data.');
        return $plain;
    }

    public static function wrapKey(string $rootKey, string $wrappingKey, string $aad): array
    {
        if (strlen($rootKey) !== V14Descriptor::KEY_BYTES) throw new RuntimeException('Invalid package key.');
        $packed = self::seal($rootKey, $wrappingKey, $aad);
        return [
            'nonce' => base64_encode(substr($packed, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)),
            'wrapped_key' => base64_encode(substr($packed, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)),
        ];
    }

    public static function unwrapKey(array $slot, string $wrappingKey, string $aad): string
    {
        if (!isset($slot['nonce'], $slot['wrapped_key'])) throw new RuntimeException('Invalid key slot.');
        $nonce = base64_decode((string) $slot['nonce'], true);
        $cipher = base64_decode((string) $slot['wrapped_key'], true);
        if ($nonce === false || strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES || $cipher === false || strlen($cipher) !== V14Descriptor::KEY_BYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) throw new RuntimeException('Invalid key slot.');
        return self::open($nonce . $cipher, $wrappingKey, $aad);
    }

    private static function assertKey(string $key): void
    {
        if (!extension_loaded('sodium') || strlen($key) !== V14Descriptor::KEY_BYTES) throw new RuntimeException('Invalid cryptographic runtime.');
    }
}
