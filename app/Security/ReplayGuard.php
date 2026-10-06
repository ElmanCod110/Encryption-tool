<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

/**
 * File-backed replay guard for short-lived operation identifiers.
 * The guard is deliberately minimal: it stores only a keyed digest and expiry.
 */
final class ReplayGuard
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize replay guard.');
        }
    }

    public function consume(string $identifier, int $ttlSeconds = 900): bool
    {
        if ($identifier === '' || $ttlSeconds < 1) {
            return false;
        }
        $key = hash('sha256', $identifier);
        $path = $this->directory . DIRECTORY_SEPARATOR . $key . '.json';
        $now = time();
        $fp = @fopen($path, 'c+');
        if ($fp === false) {
            throw new RuntimeException('Unable to initialize replay state.');
        }
        try {
            if (!flock($fp, LOCK_EX)) {
                throw new RuntimeException('Unable to lock replay state.');
            }
            rewind($fp);
            $raw = stream_get_contents($fp);
            if ($raw !== false && trim($raw) !== '') {
                $data = json_decode($raw, true);
                if (is_array($data) && (int)($data['expires_at'] ?? 0) >= $now) {
                    flock($fp, LOCK_UN);
                    return false;
                }
            }
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode([
                'consumed_at' => $now,
                'expires_at' => $now + $ttlSeconds,
            ], JSON_THROW_ON_ERROR));
            fflush($fp);
            flock($fp, LOCK_UN);
            return true;
        } finally {
            fclose($fp);
        }
    }
}
