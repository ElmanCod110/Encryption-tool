<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;
use SecurePackage\Storage\AtomicFile;

final class PackageAccessTokenStore
{
    public function __construct(private readonly string $directory, private readonly int $ttlSeconds = 900)
    {
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize token storage.');
        }
    }

    public function issue(string $packageId, string $ownerId, bool $oneTime = false): string
    {
        $token = bin2hex(random_bytes(32));
        AtomicFile::write($this->file($token), json_encode([
            'package_id' => $packageId,
            'owner_id_hash' => hash('sha256', $ownerId),
            'created_at' => time(),
            'expires_at' => time() + $this->ttlSeconds,
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
        if (!is_file($file)) {
            throw new RuntimeException('Invalid or expired access token.');
        }
        $handle = fopen($file, 'c+');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            throw new RuntimeException('Invalid or expired access token.');
        }
        try {
            $data = json_decode((string) stream_get_contents($handle), true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($data) || (int) ($data['expires_at'] ?? 0) < time()) {
                @unlink($file);
                throw new RuntimeException('Invalid or expired access token.');
            }
            if (($data['one_time'] ?? false) === true) {
                @unlink($file);
            }
            return $data;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    public function revokeForPackage(string $packageId): void
    {
        foreach (glob($this->directory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
            $data = json_decode((string) @file_get_contents($file), true);
            if (is_array($data) && ($data['package_id'] ?? '') === $packageId) {
                @unlink($file);
            }
        }
    }

    private function file(string $token): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . $token . '.json';
    }
}
