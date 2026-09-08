<?php
declare(strict_types=1);

namespace TCH\Crypto;

use RuntimeException;

final class CryptoEngine
{
    public static function encryptString(string $plaintext, string $key, string $aad = ''): string
    {
        self::assertKey($key);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
        return self::pack($nonce, $ciphertext);
    }

    public static function decryptString(string $packed, string $key, string $aad = ''): string
    {
        self::assertKey($key);
        [$nonce, $ciphertext] = self::unpack($packed);
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key);
        if ($plaintext === false) {
            throw new RuntimeException('Unable to authenticate encrypted data.');
        }
        return $plaintext;
    }

    public static function encryptFile(string $source, string $destination, string $key, string $aad = ''): void
    {
        self::assertKey($key);
        $in = fopen($source, 'rb');
        $out = fopen($destination, 'wb');
        if ($in === false || $out === false) {
            throw new RuntimeException('Unable to open file streams.');
        }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $stream = $state[0];
        fwrite($out, $state[1]);
        $chunkSize = 1024 * 1024;
        $first = true;
        try {
            while (!feof($in)) {
                $chunk = fread($in, $chunkSize);
                if ($chunk === false) {
                    throw new RuntimeException('Unable to read source file.');
                }
                if ($chunk === '' && feof($in)) {
                    if ($first) {
                        $chunk = '';
                    } else {
                        break;
                    }
                }
                $tag = feof($in) ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, $aad, $tag);
                fwrite($out, pack('N', strlen($encrypted)) . $encrypted);
                $first = false;
                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    break;
                }
            }
        } finally {
            fclose($in);
            fclose($out);
        }
    }

    public static function decryptFile(string $source, string $destination, string $key, string $aad = ''): void
    {
        self::assertKey($key);
        $in = fopen($source, 'rb');
        $out = fopen($destination, 'wb');
        if ($in === false || $out === false) {
            throw new RuntimeException('Unable to open file streams.');
        }
        $header = fread($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if ($header === false || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new RuntimeException('Invalid encrypted file header.');
        }
        $stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        if ($stream === false) {
            throw new RuntimeException('Invalid encrypted stream state.');
        }
        $finalSeen = false;
        try {
            while (!feof($in)) {
                $lengthBytes = fread($in, 4);
                if ($lengthBytes === '' || $lengthBytes === false) {
                    break;
                }
                if (strlen($lengthBytes) !== 4) {
                    throw new RuntimeException('Truncated encrypted file.');
                }
                $length = unpack('Nlength', $lengthBytes)['length'];
                if ($length < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $length > 2 * 1024 * 1024) {
                    throw new RuntimeException('Invalid encrypted chunk length.');
                }
                $encrypted = fread($in, $length);
                if ($encrypted === false || strlen($encrypted) !== $length) {
                    throw new RuntimeException('Truncated encrypted chunk.');
                }
                $result = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $encrypted, $aad);
                if ($result === false) {
                    throw new RuntimeException('Encrypted file authentication failed.');
                }
                fwrite($out, $result[0]);
                if ($result[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    $finalSeen = true;
                    break;
                }
            }
        } catch (\Throwable $e) {
            @unlink($destination);
            throw $e;
        } finally {
            fclose($in);
            fclose($out);
        }
        if (!$finalSeen) {
            @unlink($destination);
            throw new RuntimeException('Encrypted stream is incomplete.');
        }
    }

    private static function pack(string $nonce, string $ciphertext): string
    {
        return 'AE1' . pack('C', strlen($nonce)) . $nonce . $ciphertext;
    }

    private static function unpack(string $packed): array
    {
        if (strlen($packed) < 4 || substr($packed, 0, 3) !== 'AE1') {
            throw new RuntimeException('Invalid encrypted payload.');
        }
        $nonceLength = ord($packed[3]);
        $nonce = substr($packed, 4, $nonceLength);
        $ciphertext = substr($packed, 4 + $nonceLength);
        if (strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES || $ciphertext === '') {
            throw new RuntimeException('Invalid encrypted payload structure.');
        }
        return [$nonce, $ciphertext];
    }

    private static function assertKey(string $key): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new RuntimeException('Invalid encryption key.');
        }
    }
}
