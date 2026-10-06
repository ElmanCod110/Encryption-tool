<?php
declare(strict_types=1);

namespace TCH\Crypto;

use RuntimeException;

final class CryptoEngine
{
    private const STRING_MAGIC = 'TCHS2';
    private const STREAM_MAGIC = 'TCHF2';
    private const MAX_CHUNK = 4_194_304;

    public static function encryptString(string $plaintext, string $key, string $aad = ''): string
    {
        self::assertKey($key);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
        return self::STRING_MAGIC . $nonce . $ciphertext;
    }

    public static function decryptString(string $packed, string $key, string $aad = ''): string
    {
        self::assertKey($key);
        $min = strlen(self::STRING_MAGIC) + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        if (strlen($packed) < $min || !hash_equals(self::STRING_MAGIC, substr($packed, 0, strlen(self::STRING_MAGIC)))) {
            throw new RuntimeException('Unable to authenticate encrypted data.');
        }
        $offset = strlen(self::STRING_MAGIC);
        $nonce = substr($packed, $offset, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = substr($packed, $offset + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key);
        if ($plaintext === false) {
            throw new RuntimeException('Unable to authenticate encrypted data.');
        }
        return $plaintext;
    }

    public static function encryptFile(string $source, string $destination, string $key, string $aad = '', int $plainSize = -1, int $padBlockBytes = 1048576): void
    {
        self::assertKey($key);
        self::ensureParentDirectory($destination);
        $in = fopen($source, 'rb');
        if ($in === false) {
            throw new RuntimeException('Unable to open source file.');
        }
        $temp = $destination . '.partial.' . bin2hex(random_bytes(8));
        $out = fopen($temp, 'wb');
        if ($out === false) {
            fclose($in);
            throw new RuntimeException('Unable to create encrypted file.');
        }

        try {
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
            $stream = $state[0];
            self::writeAll($out, self::STREAM_MAGIC . $state[1]);
            $chunkSize = $padBlockBytes;
            if ($plainSize < 0) {
                $stat = fstat($in);
                $plainSize = (int) ($stat['size'] ?? 0);
            }
            if ($plainSize < 0 || $padBlockBytes < 1024 || $padBlockBytes > 16 * 1024 * 1024) {
                throw new RuntimeException('Invalid padding configuration.');
            }
            $remaining = $plainSize;
            if ($remaining === 0) {
                $chunk = random_bytes($padBlockBytes);
                $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push(
                    $stream,
                    $chunk,
                    $aad . '|chunk',
                    SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                );
                self::writeAll($out, pack('N', strlen($encrypted)) . $encrypted);
            } else {
                while ($remaining > 0) {
                    $want = min($chunkSize, $remaining);
                    $chunk = self::readExact($in, $want);
                    $remaining -= strlen($chunk);
                    if ($remaining === 0) {
                        $remainder = strlen($chunk) % $padBlockBytes;
                        $padLength = $remainder === 0 ? 0 : $padBlockBytes - $remainder;
                        if ($padLength > 0) {
                            $chunk .= random_bytes($padLength);
                        }
                        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
                    } else {
                        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                    }
                    $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, $aad . '|chunk', $tag);
                    self::writeAll($out, pack('N', strlen($encrypted)) . $encrypted);
                }
            }
            fflush($out);
            fclose($out);
            fclose($in);
            if (!rename($temp, $destination)) {
                throw new RuntimeException('Unable to finalize encrypted file.');
            }
        } catch (\Throwable $e) {
            fclose($out);
            fclose($in);
            @unlink($temp);
            throw $e;
        }
    }

    public static function decryptFile(string $source, string $destination, string $key, string $aad = '', int $expectedPlainSize = -1): void
    {
        self::assertKey($key);
        self::ensureParentDirectory($destination);
        $in = fopen($source, 'rb');
        if ($in === false) {
            throw new RuntimeException('Unable to open encrypted file.');
        }
        $temp = $destination . '.partial.' . bin2hex(random_bytes(8));
        $out = fopen($temp, 'wb');
        if ($out === false) {
            fclose($in);
            throw new RuntimeException('Unable to create destination file.');
        }
        try {
            $magic = fread($in, strlen(self::STREAM_MAGIC));
            if ($magic !== self::STREAM_MAGIC) {
                throw new RuntimeException('Invalid encrypted stream.');
            }
            $header = self::readExact($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
            $stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
            if ($stream === false) {
                throw new RuntimeException('Invalid encrypted stream state.');
            }

            $finalSeen = false;
            while (!feof($in)) {
                $lengthBytes = fread($in, 4);
                if ($lengthBytes === '' || $lengthBytes === false) {
                    break;
                }
                if (strlen($lengthBytes) !== 4) {
                    throw new RuntimeException('Truncated encrypted file.');
                }
                $length = unpack('Nlength', $lengthBytes)['length'];
                if ($length < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $length > self::MAX_CHUNK) {
                    throw new RuntimeException('Invalid encrypted chunk length.');
                }
                $encrypted = self::readExact($in, $length);
                $result = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $encrypted, $aad . '|chunk');
                if ($result === false) {
                    throw new RuntimeException('Encrypted file authentication failed.');
                }
                self::writeAll($out, $result[0]);
                if ($result[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    $finalSeen = true;
                    $trailing = fread($in, 1);
                    if ($trailing !== '' && $trailing !== false) {
                        throw new RuntimeException('Trailing data after final encrypted chunk.');
                    }
                    break;
                }
            }
            if (!$finalSeen) {
                throw new RuntimeException('Encrypted stream is incomplete.');
            }
            fflush($out);
            if ($expectedPlainSize >= 0) {
                if (!ftruncate($out, $expectedPlainSize)) {
                    throw new RuntimeException('Unable to remove encrypted padding.');
                }
            }
            fclose($out);
            fclose($in);
            if (!rename($temp, $destination)) {
                throw new RuntimeException('Unable to finalize restored file.');
            }
        } catch (\Throwable $e) {
            fclose($out);
            fclose($in);
            @unlink($temp);
            @unlink($destination);
            throw $e;
        }
    }

    private static function assertKey(string $key): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new RuntimeException('Invalid encryption key.');
        }
    }

    private static function ensureParentDirectory(string $path): void
    {
        $parent = dirname($path);
        if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) {
            throw new RuntimeException('Unable to initialize destination directory.');
        }
    }

    private static function writeAll($stream, string $data): void
    {
        $length = strlen($data);
        $offset = 0;
        while ($offset < $length) {
            $written = fwrite($stream, substr($data, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Unable to write encrypted data.');
            }
            $offset += $written;
        }
    }

    private static function readExact($stream, int $length): string
    {
        $data = '';
        while (strlen($data) < $length && !feof($stream)) {
            $part = fread($stream, $length - strlen($data));
            if ($part === false || $part === '') {
                break;
            }
            $data .= $part;
        }
        if (strlen($data) !== $length) {
            throw new RuntimeException('Unexpected end of encrypted data.');
        }
        return $data;
    }
}
