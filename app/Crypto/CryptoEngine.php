<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;

final class CryptoEngine
{
    private const STRING_MAGIC = 'SPKS6';
    private const STREAM_MAGIC = 'SPKF6';

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
        $magicLength = strlen(self::STRING_MAGIC);
        $min = $magicLength + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        if (strlen($packed) < $min || !hash_equals(self::STRING_MAGIC, substr($packed, 0, $magicLength))) {
            throw new RuntimeException('Unable to authenticate encrypted data.');
        }
        $nonce = substr($packed, $magicLength, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = substr($packed, $magicLength + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
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
        if ($in === false) throw new RuntimeException('Unable to open source file.');
        $temp = $destination . '.partial.' . bin2hex(random_bytes(8));
        $out = fopen($temp, 'wb');
        if ($out === false) { fclose($in); throw new RuntimeException('Unable to create encrypted file.'); }
        try {
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
            $stream = $state[0];
            self::writeAll($out, self::STREAM_MAGIC . $state[1]);
            if ($plainSize < 0) {
                $stat = fstat($in);
                $plainSize = (int) ($stat['size'] ?? 0);
            }
            if ($plainSize < 0 || $padBlockBytes < 1024 || $padBlockBytes > 16 * 1024 * 1024) throw new RuntimeException('Invalid padding configuration.');
            $remaining = $plainSize;
            if ($remaining === 0) {
                $chunk = random_bytes($padBlockBytes);
                $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, $aad . '|chunk|0', SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
                self::writeAll($out, pack('N', strlen($encrypted)) . $encrypted);
            } else {
                while ($remaining > 0) {
                    $want = min($padBlockBytes, $remaining);
                    $chunk = self::readExact($in, $want);
                    $remaining -= strlen($chunk);
                    if ($remaining === 0) {
                        $padLength = ($padBlockBytes - ($plainSize % $padBlockBytes)) % $padBlockBytes;
                        if ($plainSize % $padBlockBytes === 0) $padLength = 0;
                        if ($padLength > 0) $chunk .= random_bytes($padLength);
                        $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, $aad . '|chunk|' . $plainSize, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
                    } else {
                        $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, $aad . '|chunk|' . $plainSize, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);
                    }
                    self::writeAll($out, pack('N', strlen($encrypted)) . $encrypted);
                }
            }
            fflush($out);
            fclose($out); $out = null;
            fclose($in); $in = null;
            if (!rename($temp, $destination)) throw new RuntimeException('Unable to finalize encrypted file.');
            @chmod($destination, 0600);
        } catch (\Throwable $e) {
            if (is_resource($in)) fclose($in);
            if (is_resource($out)) fclose($out);
            @unlink($temp);
            @unlink($destination);
            throw $e;
        }
    }

    public static function decryptFile(string $source, string $destination, string $key, string $aad = '', int $expectedPlainSize = -1): void
    {
        self::assertKey($key);
        $in = fopen($source, 'rb');
        if ($in === false) throw new RuntimeException('Unable to open encrypted file.');
        $temp = $destination . '.partial.' . bin2hex(random_bytes(8));
        self::ensureParentDirectory($destination);
        $out = fopen($temp, 'wb');
        if ($out === false) { fclose($in); throw new RuntimeException('Unable to create restored file.'); }
        try {
            $header = self::readExact($in, strlen(self::STREAM_MAGIC) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
            if (!hash_equals(self::STREAM_MAGIC, substr($header, 0, strlen(self::STREAM_MAGIC)))) throw new RuntimeException('Unable to authenticate encrypted stream.');
            $streamHeader = substr($header, strlen(self::STREAM_MAGIC));
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($streamHeader, $key);
            $written = 0; $final = false;
            while (!feof($in)) {
                $lengthBytes = fread($in, 4);
                if ($lengthBytes === '' || $lengthBytes === false) break;
                if (strlen($lengthBytes) !== 4) throw new RuntimeException('Encrypted stream is truncated.');
                $length = unpack('Nlen', $lengthBytes)['len'] ?? 0;
                if ($length < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $length > 8 * 1024 * 1024) throw new RuntimeException('Encrypted stream chunk is invalid.');
                $cipher = self::readExact($in, $length);
                $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher, $aad . '|chunk|' . max($expectedPlainSize, 0));
                if ($result === false) throw new RuntimeException('Unable to authenticate encrypted stream.');
                [$plain, $tag] = $result;
                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) $final = true;
                $remainingAllowed = $expectedPlainSize >= 0 ? max(0, $expectedPlainSize - $written) : PHP_INT_MAX;
                if (strlen($plain) > $remainingAllowed) {
                    $plain = substr($plain, 0, $remainingAllowed);
                }
                if ($plain !== '') self::writeAll($out, $plain);
                $written += strlen($plain);
            }
            if (!$final || ($expectedPlainSize >= 0 && $written !== $expectedPlainSize)) throw new RuntimeException('Encrypted stream length is invalid.');
            fflush($out); fclose($out); $out = null; fclose($in); $in = null;
            if (!rename($temp, $destination)) throw new RuntimeException('Unable to finalize restored file.');
            @chmod($destination, 0600);
        } catch (\Throwable $e) {
            if (is_resource($in)) fclose($in);
            if (is_resource($out)) fclose($out);
            @unlink($temp); @unlink($destination);
            throw $e;
        }
    }

    private static function assertKey(string $key): void
    {
        if (!extension_loaded('sodium') || strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) throw new RuntimeException('Invalid cryptographic runtime.');
    }
    private static function ensureParentDirectory(string $path): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('Unable to initialize destination directory.');
    }
    private static function writeAll($handle, string $data): void
    {
        $offset = 0; $length = strlen($data);
        while ($offset < $length) {
            $written = fwrite($handle, substr($data, $offset));
            if ($written === false || $written === 0) throw new RuntimeException('Unable to write encrypted data.');
            $offset += $written;
        }
    }
    private static function readExact($handle, int $length): string
    {
        $data = '';
        while (strlen($data) < $length && !feof($handle)) {
            $chunk = fread($handle, $length - strlen($data));
            if ($chunk === false || $chunk === '') break;
            $data .= $chunk;
        }
        if (strlen($data) !== $length) throw new RuntimeException('Encrypted data is truncated.');
        return $data;
    }
}
