<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;
use SecurePackage\Storage\AtomicFile;

final class RestoreTokenStore
{
    public function __construct(private readonly string $directory, private readonly int $ttlSeconds = 900)
    {
        if ($ttlSeconds < 1) {
            throw new RuntimeException('Invalid restore-token lifetime policy.');
        }
        if (is_link($directory)) {
            throw new RuntimeException('Restore token storage is invalid.');
        }
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize restore token storage.');
        }
        @chmod($directory, 0700);
    }

    public function issue(string $restoreDirectory): string
    {
        if (!is_dir($restoreDirectory) || is_link($restoreDirectory)) {
            throw new RuntimeException('Restore directory does not exist.');
        }
        $resolvedDirectory = realpath($restoreDirectory);
        if ($resolvedDirectory === false) {
            throw new RuntimeException('Restore directory does not exist.');
        }

        $token = bin2hex(random_bytes(32));
        $now = time();
        $record = [
            'directory' => $resolvedDirectory,
            'created_at' => $now,
            'expires_at' => $now + $this->ttlSeconds,
        ];
        AtomicFile::write($this->file($token), json_encode($record, JSON_THROW_ON_ERROR));
        return $token;
    }

    public function consume(string $token): string
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
            throw new RuntimeException('Restore token is invalid or expired.');
        }

        $file = $this->file($token);
        if (is_link($file) || !is_file($file)) {
            throw new RuntimeException('Restore token is invalid or expired.');
        }

        // Use r+ so a race cannot create a new empty token file after the existence check.
        // Every consumer locks the same inode, and the consumed marker makes waiters fail closed.
        $handle = @fopen($file, 'r+');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Restore token is invalid or expired.');
        }

        $removeAfterUnlock = false;
        $directory = null;
        try {
            rewind($handle);
            $raw = stream_get_contents($handle);
            try {
                $record = json_decode(is_string($raw) ? $raw : '', true, 16, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                throw new RuntimeException('Restore token is invalid or expired.');
            }

            if (!is_array($record)
                || ($record['consumed'] ?? false) === true
                || !is_string($record['directory'] ?? null)
                || $record['directory'] === ''
                || !is_int($record['created_at'] ?? null)
                || $record['created_at'] <= 0
                || !is_int($record['expires_at'] ?? null)
                || $record['expires_at'] <= $record['created_at']) {
                throw new RuntimeException('Restore token is invalid or expired.');
            }

            if ($record['expires_at'] <= time()) {
                $this->removeExpiredRestoreDirectory($record);
                @unlink($file);
                throw new RuntimeException('Restore token is invalid or expired.');
            }

            $marker = json_encode(['consumed' => true], JSON_THROW_ON_ERROR);
            rewind($handle);
            if (!ftruncate($handle, 0)
                || fwrite($handle, $marker) !== strlen($marker)
                || !fflush($handle)) {
                throw new RuntimeException('Unable to consume restore token safely.');
            }

            $directory = $record['directory'];
            $removeAfterUnlock = true;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
            if ($removeAfterUnlock) {
                @unlink($file);
            }
        }

        if (!is_string($directory) || $directory === '' || !is_dir($directory) || is_link($directory)) {
            throw new RuntimeException('Restore token is invalid or expired.');
        }
        return $directory;
    }

    public function cleanup(): void
    {
        foreach (glob($this->directory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
            if (is_link($file) || !is_file($file)) continue;
            $record = json_decode((string) @file_get_contents($file), true);
            if (!is_array($record) || (int) ($record['expires_at'] ?? 0) <= time()) {
                if (is_array($record)) $this->removeExpiredRestoreDirectory($record);
                @unlink($file);
            }
        }
    }

    private function removeExpiredRestoreDirectory(array $record): void
    {
        $candidate = (string) ($record['directory'] ?? '');
        $tempRoot = realpath(dirname(rtrim($this->directory, DIRECTORY_SEPARATOR)));
        $restorePath = $candidate !== '' ? realpath($candidate) : false;
        if ($tempRoot === false || $restorePath === false || is_link($candidate)
            || dirname($restorePath) !== $tempRoot
            || !str_starts_with(basename($restorePath), 'restore-')) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($restorePath, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $itemPath = $item->getPathname();
            if ($item->isLink() || !$item->isDir()) {
                @unlink($itemPath);
            } else {
                @rmdir($itemPath);
            }
        }
        @rmdir($restorePath);
    }

    private function file(string $token): string
    {
        return rtrim($this->directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    }
}
