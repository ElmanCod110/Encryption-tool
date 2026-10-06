<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;
use SecurePackage\Project\V14Descriptor;

final class V14Stream
{
    private const MAGIC = 'SPK14STR';
    private const LENGTH_BYTES = 4;
    private const MAX_CIPHER_CHUNK = 8 * 1024 * 1024 + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    public static function encryptFile(string $source, string $destination, string $key, string $aad, int $plainSize, int $chunkBytes = 4 * 1024 * 1024): void
    {
        if (strlen($key) !== V14Descriptor::KEY_BYTES || $plainSize < 0 || $chunkBytes < 64 * 1024 || $chunkBytes > 8 * 1024 * 1024) throw new RuntimeException('Invalid stream configuration.');
        if (!is_file($source)) throw new RuntimeException('Source file does not exist.');
        $in = fopen($source, 'rb');
        if ($in === false) throw new RuntimeException('Unable to open source file.');
        $tmp = $destination . '.partial.' . bin2hex(random_bytes(12));
        self::ensureParent($destination);
        $out = fopen($tmp, 'wb');
        if ($out === false) { fclose($in); throw new RuntimeException('Unable to create encrypted file.'); }
        try {
            [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
            self::writeAll($out, self::MAGIC . $header);
            $remaining = $plainSize;
            $index = 0;
            if ($remaining === 0) {
                $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($state, '', $aad . '|chunk|0|0', SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
                self::writeRecord($out, $index, $cipher);
            } else {
                while ($remaining > 0) {
                    $want = min($chunkBytes, $remaining);
                    $plain = self::readExact($in, $want);
                    if (strlen($plain) !== $want) throw new RuntimeException('Source file changed during encryption.');
                    $remaining -= $want;
                    $tag = $remaining === 0 ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                    $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($state, $plain, $aad . '|chunk|' . $index . '|' . $plainSize, $tag);
                    self::writeRecord($out, $index, $cipher);
                    sodium_memzero($plain);
                    $index++;
                }
            }
            fflush($out);
            fclose($out); $out = null;
            fclose($in); $in = null;
            if (!rename($tmp, $destination)) throw new RuntimeException('Unable to finalize encrypted file.');
            @chmod($destination, 0600);
        } catch (\Throwable $e) {
            if (is_resource($in)) fclose($in);
            if (is_resource($out)) fclose($out);
            @unlink($tmp);
            @unlink($destination);
            throw $e;
        }
    }

    public static function decryptFile(string $source, string $destination, string $key, string $aad, int $expectedPlainSize): void
    {
        if (strlen($key) !== V14Descriptor::KEY_BYTES || $expectedPlainSize < 0) throw new RuntimeException('Invalid stream configuration.');
        $in = fopen($source, 'rb');
        if ($in === false) throw new RuntimeException('Unable to open encrypted file.');
        $tmp = $destination . '.partial.' . bin2hex(random_bytes(12));
        self::ensureParent($destination);
        $out = fopen($tmp, 'wb');
        if ($out === false) { fclose($in); throw new RuntimeException('Unable to create restored file.'); }
        try {
            $header = self::readExact($in, strlen(self::MAGIC) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
            if (!hash_equals(self::MAGIC, substr($header, 0, strlen(self::MAGIC)))) throw new RuntimeException('Invalid encrypted stream.');
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($header, strlen(self::MAGIC)), $key);
            $written = 0;
            $index = 0;
            $final = false;
            while (!feof($in)) {
                $lenBytes = fread($in, self::LENGTH_BYTES);
                if ($lenBytes === '' || $lenBytes === false) break;
                if (strlen($lenBytes) !== self::LENGTH_BYTES) throw new RuntimeException('Encrypted stream is truncated.');
                $length = unpack('Nlen', $lenBytes)['len'] ?? 0;
                if ($length < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $length > self::MAX_CIPHER_CHUNK) throw new RuntimeException('Encrypted stream chunk is invalid.');
                $cipher = self::readExact($in, $length);
                $plainResult = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher, $aad . '|chunk|' . $index . '|' . $expectedPlainSize);
                if ($plainResult === false) throw new RuntimeException('Unable to authenticate encrypted stream.');
                [$plain, $tag] = $plainResult;
                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) $final = true;
                elseif ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE) throw new RuntimeException('Unexpected stream tag.');
                $written += strlen($plain);
                if ($written > $expectedPlainSize) throw new RuntimeException('Encrypted stream length is invalid.');
                if ($plain !== '') self::writeAll($out, $plain);
                sodium_memzero($plain);
                $index++;
                if ($final) {
                    $tail = fread($in, 1);
                    if ($tail !== '' && $tail !== false) throw new RuntimeException('Encrypted stream contains trailing data.');
                    break;
                }
            }
            if (!$final || $written !== $expectedPlainSize) throw new RuntimeException('Encrypted stream length is invalid.');
            fflush($out);
            fclose($out); $out = null;
            fclose($in); $in = null;
            if (!rename($tmp, $destination)) throw new RuntimeException('Unable to finalize restored file.');
            @chmod($destination, 0600);
        } catch (\Throwable $e) {
            if (is_resource($in)) fclose($in);
            if (is_resource($out)) fclose($out);
            @unlink($tmp);
            @unlink($destination);
            throw $e;
        }
    }

    private static function writeRecord($out, int $index, string $cipher): void
    {
        if ($index < 0 || strlen($cipher) < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || strlen($cipher) > self::MAX_CIPHER_CHUNK) throw new RuntimeException('Invalid encrypted stream record.');
        self::writeAll($out, pack('N', strlen($cipher)) . $cipher);
    }

    private static function ensureParent(string $path): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('Unable to initialize destination directory.');
    }

    private static function writeAll($handle, string $data): void
    {
        $offset = 0;
        $len = strlen($data);
        while ($offset < $len) {
            $n = fwrite($handle, substr($data, $offset));
            if ($n === false || $n === 0) throw new RuntimeException('Unable to write encrypted data.');
            $offset += $n;
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
