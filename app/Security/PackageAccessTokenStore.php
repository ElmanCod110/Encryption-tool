<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;
use SecurePackage\Storage\AtomicFile;

final class PackageAccessTokenStore
{
    public function __construct(private readonly string $directory, private readonly int $ttlSeconds = 900)
    {
        if ($ttlSeconds < 1) {
            throw new RuntimeException('Invalid token lifetime policy.');
        }
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize token storage.');
        }
        @chmod($directory, 0700);
    }

    public function issue(string $packageId, string $ownerId, bool $oneTime = false): string
    {
        if ($packageId === '' || $ownerId === '') {
            throw new RuntimeException('Invalid access-token subject.');
        }

        $token = bin2hex(random_bytes(32));
        $now = time();
        AtomicFile::write($this->file($token), json_encode([
            'package_id' => $packageId,
            'owner_id_hash' => hash('sha256', $ownerId),
            'created_at' => $now,
            'expires_at' => $now + $this->ttlSeconds,
            'one_time' => $oneTime,
        ], JSON_THROW_ON_ERROR));
        return $token;
    }

    public function consume(string $token): array
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
            throw new RuntimeException('Invalid or expired access token.');
        }

        $file = $this->file($token);
        if (is_link($file) || !is_file($file)) {
            throw new RuntimeException('Invalid or expired access token.');
        }

        // r+ avoids creating an empty token file if it disappears between the
        // existence check and open. Every consumer locks the same inode.
        $handle = @fopen($file, 'r+');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Invalid or expired access token.');
        }

        $removeAfterUnlock = false;
        try {
            rewind($handle);
            $raw = stream_get_contents($handle);
            try {
                $data = json_decode((string) $raw, true, 16, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                throw new RuntimeException('Invalid or expired access token.');
            }

            if (!is_array($data)
                || ($data['consumed'] ?? false) === true
                || !is_string($data['package_id'] ?? null)
                || $data['package_id'] === ''
                || !is_string($data['owner_id_hash'] ?? null)
                || !preg_match('/^[a-f0-9]{64}$/', $data['owner_id_hash'])
                || !is_int($data['expires_at'] ?? null)
                || $data['expires_at'] <= time()
                || !is_bool($data['one_time'] ?? null)) {
                throw new RuntimeException('Invalid or expired access token.');
            }

            if ($data['one_time']) {
                // Unlinking alone is not enough: a concurrent request may
                // already have opened the same inode and be waiting on flock.
                // Persist a consumed marker before releasing the lock so that
                // every waiter observes the token as unusable.
                $marker = json_encode(['consumed' => true], JSON_THROW_ON_ERROR);
                rewind($handle);
                if (!ftruncate($handle, 0) || fwrite($handle, $marker) !== strlen($marker) || !fflush($handle)) {
                    throw new RuntimeException('Unable to consume access token safely.');
                }
                $removeAfterUnlock = true;
            }

            return $data;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
            if ($removeAfterUnlock) {
                @unlink($file);
            }
        }
    }

    public function revokeForPackage(string $packageId): void
    {
        foreach (glob($this->directory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
            if (is_link($file) || !is_file($file)) continue;
            $data = json_decode((string) @file_get_contents($file), true);
            if (is_array($data) && ($data['package_id'] ?? '') === $packageId) {
                @unlink($file);
            }
        }
    }

    private function file(string $token): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    }
}
