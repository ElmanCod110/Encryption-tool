<?php
declare(strict_types=1);

namespace SecurePackage\Crypto;

use RuntimeException;
use SecurePackage\Project\PackageStorageException;
use SecurePackage\Project\V14Descriptor;

final class V14Stream
{
    private const MAGIC = 'SPK14STR';
    private const LENGTH_BYTES = 4;
    private const MAX_CIPHER_CHUNK = 8 * 1024 * 1024 + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    public static function encryptFile(string $source, string $destination, string $key, string $aad, int $plainSize, int $chunkBytes = 4 * 1024 * 1024): void
    {
        if (strlen($key) !== V14Descriptor::KEY_BYTES || $plainSize < 0 || $chunkBytes < 64 * 1024 || $chunkBytes > 8 * 1024 * 1024) throw new RuntimeException('Invalid stream configuration.');
        if (file_exists($destination) || is_link($destination)) throw new PackageStorageException('Encrypted destination already exists.');
        if (!is_file($source)) throw new PackageStorageException('Source file does not exist.');
        $in = fopen($source, 'rb');
        if ($in === false) throw new PackageStorageException('Unable to open source file.');
        $tmp = $destination . '.partial.' . bin2hex(random_bytes(12));
        self::ensureParent($destination);
        $out = @fopen($tmp, 'x+b');
        if ($out === false) { fclose($in); throw new PackageStorageException('Unable to create encrypted file.'); }
        $tmpHandleStat = fstat($out);
        if (!is_array($tmpHandleStat) || (((int) ($tmpHandleStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($tmpHandleStat['ino'] ?? 0) === 0) {
            fclose($out);
            fclose($in);
            if (!@unlink($tmp) && (file_exists($tmp) || is_link($tmp))) throw new PackageStorageException('Unable to clean unverified encrypted temporary file.');
            throw new PackageStorageException('Unable to verify encrypted temporary file.');
        }
        $tmpIdentity = ['dev' => (int) ($tmpHandleStat['dev'] ?? -1), 'ino' => (int) $tmpHandleStat['ino']];
        $published = false;
        $state = null;
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
                    if (strlen($plain) !== $want) throw new PackageStorageException('Source file changed during encryption.');
                    $remaining -= $want;
                    $tag = $remaining === 0 ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                    try {
                        $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($state, $plain, $aad . '|chunk|' . $index . '|' . $plainSize, $tag);
                        self::writeRecord($out, $index, $cipher);
                    } finally {
                        if ($plain !== '') sodium_memzero($plain);
                    }
                    $index++;
                }
            }
            if (is_string($state)) sodium_memzero($state);
            $state = null;
            if (!fflush($out)) throw new PackageStorageException('Unable to flush encrypted temporary file.');
            if (function_exists('fsync') && !fsync($out)) throw new PackageStorageException('Unable to synchronize encrypted temporary file.');
            fclose($out); $out = null;
            fclose($in); $in = null;
            clearstatcache(true, $tmp);
            $tmpStat = @lstat($tmp);
            if (!is_array($tmpStat) || is_link($tmp)
                || (int) ($tmpStat['dev'] ?? -2) !== $tmpIdentity['dev']
                || (int) ($tmpStat['ino'] ?? 0) !== $tmpIdentity['ino']
                || (((int) ($tmpStat['mode'] ?? 0) & 0170000) !== 0100000)) {
                throw new PackageStorageException('Encrypted temporary file identity changed before publication.');
            }
            // link() atomically creates the final path and fails rather than replacing an existing file.
            if (!@link($tmp, $destination)) throw new PackageStorageException('Unable to finalize encrypted file without overwriting an existing destination.');
            $published = true;
            clearstatcache(true, $destination);
            $destinationStat = @lstat($destination);
            if (!is_array($destinationStat) || is_link($destination)
                || (int) ($destinationStat['dev'] ?? -2) !== $tmpIdentity['dev']
                || (int) ($destinationStat['ino'] ?? 0) !== $tmpIdentity['ino']) {
                throw new PackageStorageException('Published encrypted file identity could not be verified.');
            }
            if (!@unlink($tmp) && (file_exists($tmp) || is_link($tmp))) throw new PackageStorageException('Unable to remove encrypted temporary file.');
            if (file_exists($tmp) || is_link($tmp)) throw new PackageStorageException('Encrypted temporary file remains after publication.');
            $published = false;
            @chmod($destination, 0600);
        } catch (\Throwable $e) {
            if (is_resource($in)) fclose($in);
            if (is_resource($out)) fclose($out);
            if (isset($state) && is_string($state)) sodium_memzero($state);
            self::cleanupFailedStream($tmp, $destination, $published, $tmpIdentity, $e);
            throw $e;
        }
    }

    public static function decryptFile(string $source, string $destination, string $key, string $aad, int $expectedPlainSize): void
    {
        if (strlen($key) !== V14Descriptor::KEY_BYTES || $expectedPlainSize < 0) throw new RuntimeException('Invalid stream configuration.');
        if (file_exists($destination) || is_link($destination)) throw new PackageStorageException('Restored destination already exists.');
        $in = fopen($source, 'rb');
        if ($in === false) throw new PackageStorageException('Unable to open encrypted file.');
        $tmp = $destination . '.partial.' . bin2hex(random_bytes(12));
        self::ensureParent($destination);
        $out = @fopen($tmp, 'x+b');
        if ($out === false) { fclose($in); throw new PackageStorageException('Unable to create restored file.'); }
        $tmpHandleStat = fstat($out);
        if (!is_array($tmpHandleStat) || (((int) ($tmpHandleStat['mode'] ?? 0) & 0170000) !== 0100000)
            || (int) ($tmpHandleStat['ino'] ?? 0) === 0) {
            fclose($out);
            fclose($in);
            if (!@unlink($tmp) && (file_exists($tmp) || is_link($tmp))) throw new PackageStorageException('Unable to clean unverified restored temporary file.');
            throw new PackageStorageException('Unable to verify restored temporary file.');
        }
        $tmpIdentity = ['dev' => (int) ($tmpHandleStat['dev'] ?? -1), 'ino' => (int) $tmpHandleStat['ino']];
        $published = false;
        $state = null;
        try {
            try {
                $header = self::readExact($in, strlen(self::MAGIC) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
            } catch (PackageStorageException $exception) {
                throw $exception;
            } catch (RuntimeException $exception) {
                throw new V14StreamRejectedException('Encrypted stream is truncated.', 0, $exception);
            }
            if (!hash_equals(self::MAGIC, substr($header, 0, strlen(self::MAGIC)))) throw new V14StreamRejectedException('Invalid encrypted stream.');
            try {
                $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($header, strlen(self::MAGIC)), $key);
            } catch (\SodiumException $exception) {
                throw new V14StreamRejectedException('Invalid encrypted stream header.', 0, $exception);
            }
            $written = 0;
            $index = 0;
            $final = false;
            while (!feof($in)) {
                $lenBytes = fread($in, self::LENGTH_BYTES);
                if ($lenBytes === false) throw new PackageStorageException('Unable to read encrypted stream.');
                if ($lenBytes === '') {
                    if (!feof($in)) throw new PackageStorageException('Unable to read encrypted stream.');
                    break;
                }
                if (strlen($lenBytes) !== self::LENGTH_BYTES) throw new V14StreamRejectedException('Encrypted stream is truncated.');
                $length = unpack('Nlen', $lenBytes)['len'] ?? 0;
                if ($length < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $length > self::MAX_CIPHER_CHUNK) throw new V14StreamRejectedException('Encrypted stream chunk is invalid.');
                try {
                    $cipher = self::readExact($in, $length);
                } catch (PackageStorageException $exception) {
                    throw $exception;
                } catch (RuntimeException $exception) {
                    throw new V14StreamRejectedException('Encrypted stream is truncated.', 0, $exception);
                }
                try {
                    $plainResult = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher, $aad . '|chunk|' . $index . '|' . $expectedPlainSize);
                } catch (\SodiumException $exception) {
                    throw new V14StreamRejectedException('Unable to authenticate encrypted stream.', 0, $exception);
                }
                if ($plainResult === false) throw new V14StreamRejectedException('Unable to authenticate encrypted stream.');
                [$plain, $tag] = $plainResult;
                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) $final = true;
                elseif ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE) throw new V14StreamRejectedException('Unexpected stream tag.');
                $written += strlen($plain);
                if ($written > $expectedPlainSize) throw new V14StreamRejectedException('Encrypted stream length is invalid.');
                if ($plain !== '') self::writeAll($out, $plain);
                sodium_memzero($plain);
                $index++;
                if ($final) {
                    $tail = fread($in, 1);
                    if ($tail !== '' && $tail !== false) throw new V14StreamRejectedException('Encrypted stream contains trailing data.');
                    break;
                }
            }
            if (!$final || $written !== $expectedPlainSize) throw new V14StreamRejectedException('Encrypted stream length is invalid.');
            if (is_string($state)) sodium_memzero($state);
            $state = null;
            if (!fflush($out)) throw new PackageStorageException('Unable to flush restored temporary file.');
            if (function_exists('fsync') && !fsync($out)) throw new PackageStorageException('Unable to synchronize restored temporary file.');
            fclose($out); $out = null;
            fclose($in); $in = null;
            clearstatcache(true, $tmp);
            $tmpStat = @lstat($tmp);
            if (!is_array($tmpStat) || is_link($tmp)
                || (int) ($tmpStat['dev'] ?? -2) !== $tmpIdentity['dev']
                || (int) ($tmpStat['ino'] ?? 0) !== $tmpIdentity['ino']
                || (((int) ($tmpStat['mode'] ?? 0) & 0170000) !== 0100000)) {
                throw new PackageStorageException('Restored temporary file identity changed before publication.');
            }
            // link() atomically creates the final path and fails rather than replacing an existing file.
            if (!@link($tmp, $destination)) throw new PackageStorageException('Unable to finalize restored file without overwriting an existing destination.');
            $published = true;
            clearstatcache(true, $destination);
            $destinationStat = @lstat($destination);
            if (!is_array($destinationStat) || is_link($destination)
                || (int) ($destinationStat['dev'] ?? -2) !== $tmpIdentity['dev']
                || (int) ($destinationStat['ino'] ?? 0) !== $tmpIdentity['ino']) {
                throw new PackageStorageException('Published restored file identity could not be verified.');
            }
            if (!@unlink($tmp) && (file_exists($tmp) || is_link($tmp))) throw new PackageStorageException('Unable to remove restored temporary file.');
            if (file_exists($tmp) || is_link($tmp)) throw new PackageStorageException('Restored temporary file remains after publication.');
            $published = false;
            @chmod($destination, 0600);
        } catch (\Throwable $e) {
            if (is_resource($in)) fclose($in);
            if (is_resource($out)) fclose($out);
            if (isset($state) && is_string($state)) sodium_memzero($state);
            self::cleanupFailedStream($tmp, $destination, $published, $tmpIdentity, $e);
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
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) throw new PackageStorageException('Unable to initialize destination directory.');
    }

    private static function writeAll($handle, string $data): void
    {
        $offset = 0;
        $len = strlen($data);
        while ($offset < $len) {
            $n = fwrite($handle, substr($data, $offset));
            if ($n === false || $n === 0) throw new PackageStorageException('Unable to write encrypted data.');
            $offset += $n;
        }
    }

    private static function cleanupFailedStream(string $temporaryPath, string $destinationPath, bool $published, array $temporaryIdentity, \Throwable $previous): void
    {
        $cleanupFailed = false;

        if ($published) {
            clearstatcache(true, $destinationPath);
            $destinationStat = @lstat($destinationPath);
            if (is_array($destinationStat) && !is_link($destinationPath)
                && (int) ($destinationStat['dev'] ?? -2) === $temporaryIdentity['dev']
                && (int) ($destinationStat['ino'] ?? 0) === $temporaryIdentity['ino']
                && (((int) ($destinationStat['mode'] ?? 0) & 0170000) === 0100000)) {
                if (!@unlink($destinationPath) && (file_exists($destinationPath) || is_link($destinationPath))) {
                    $cleanupFailed = true;
                }
            } elseif (file_exists($destinationPath) || is_link($destinationPath)) {
                // Never delete a path whose identity changed after our atomic publication.
                $cleanupFailed = true;
            }
        }

        clearstatcache(true, $temporaryPath);
        if (file_exists($temporaryPath) || is_link($temporaryPath)) {
            $temporaryStat = @lstat($temporaryPath);
            if (is_array($temporaryStat) && !is_link($temporaryPath)
                && (int) ($temporaryStat['dev'] ?? -2) === $temporaryIdentity['dev']
                && (int) ($temporaryStat['ino'] ?? 0) === $temporaryIdentity['ino']
                && (((int) ($temporaryStat['mode'] ?? 0) & 0170000) === 0100000)) {
                if (!@unlink($temporaryPath) && (file_exists($temporaryPath) || is_link($temporaryPath))) {
                    $cleanupFailed = true;
                }
            } else {
                // Do not unlink a symlink or unexpected file that replaced our temporary file.
                $cleanupFailed = true;
            }
        }

        clearstatcache(true, $temporaryPath);
        clearstatcache(true, $destinationPath);
        if (file_exists($temporaryPath) || is_link($temporaryPath)
            || ($published && (file_exists($destinationPath) || is_link($destinationPath)))) {
            $cleanupFailed = true;
        }
        if ($cleanupFailed) {
            throw new PackageStorageException('Unable to clean failed stream output safely.', 0, $previous);
        }
    }

    private static function readExact($handle, int $length): string
    {
        $data = '';
        while (strlen($data) < $length && !feof($handle)) {
            $chunk = fread($handle, $length - strlen($data));
            if ($chunk === false) {
                if ($data !== '') sodium_memzero($data);
                throw new PackageStorageException('Unable to read stream data.');
            }
            if ($chunk === '') break;
            $data .= $chunk;
        }
        if (strlen($data) !== $length) {
            if ($data !== '') sodium_memzero($data);
            throw new RuntimeException('Encrypted data is truncated.');
        }
        return $data;
    }
}
