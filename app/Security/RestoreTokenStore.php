<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

final class RestoreTokenStore
{
    public function __construct(private readonly string $directory, private readonly int $ttlSeconds = 900)
    {
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize restore token storage.');
        }
    }

    public function issue(string $restoreDirectory): string
    {
        if (!is_dir($restoreDirectory)) {
            throw new RuntimeException('Restore directory does not exist.');
        }
        $token = bin2hex(random_bytes(32));
        $record = [
            'directory' => realpath($restoreDirectory),
            'created_at' => time(),
            'expires_at' => time() + $this->ttlSeconds,
        ];
        $file = $this->file($token);
        if (file_put_contents($file, json_encode($record, JSON_THROW_ON_ERROR), LOCK_EX) === false) {
            throw new RuntimeException('Unable to issue restore token.');
        }
        @chmod($file, 0600);
        return $token;
    }

    public function consume(string $token): string
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
            throw new RuntimeException('Restore token is invalid or expired.');
        }
        $file = $this->file($token);
        if (!is_file($file)) {
            throw new RuntimeException('Restore token is invalid or expired.');
        }
        $record = json_decode((string) file_get_contents($file), true);
        @unlink($file);
        if (!is_array($record) || (int) ($record['expires_at'] ?? 0) < time()) {
            throw new RuntimeException('Restore token is invalid or expired.');
        }
        $directory = (string) ($record['directory'] ?? '');
        if ($directory === '' || !is_dir($directory) || is_link($directory)) {
            throw new RuntimeException('Restore token is invalid or expired.');
        }
        return $directory;
    }

    public function cleanup(): void
    {
        foreach (glob($this->directory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
            $record = json_decode((string) @file_get_contents($file), true);
            if (!is_array($record) || (int) ($record['expires_at'] ?? 0) < time()) {
                @unlink($file);
            }
        }
    }

    private function file(string $token): string
    {
        return rtrim($this->directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    }
}
