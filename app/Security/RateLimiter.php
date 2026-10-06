<?php
declare(strict_types=1);

namespace SecurePackage\Security;

use RuntimeException;

final class RateLimiter
{
    public function __construct(
        private readonly string $directory,
        private readonly int $maxFailures = 12,
        private readonly int $windowSeconds = 900
    ) {
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize rate-limit storage.');
        }
    }

    public function check(string $key): bool
    {
        $record = $this->read($key);
        $now = time();
        if (($now - $record['window_start']) >= $this->windowSeconds) {
            return true;
        }
        return $record['failures'] < $this->maxFailures;
    }

    public function failure(string $key): void
    {
        $file = $this->file($key);
        $handle = fopen($file, 'c+');
        if ($handle === false) {
            return;
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                return;
            }
            $contents = stream_get_contents($handle) ?: '';
            $record = json_decode($contents, true);
            if (!is_array($record)) {
                $record = ['failures' => 0, 'window_start' => time()];
            }
            $now = time();
            if (($now - (int) ($record['window_start'] ?? $now)) >= $this->windowSeconds) {
                $record = ['failures' => 0, 'window_start' => $now];
            }
            $record['failures'] = (int) ($record['failures'] ?? 0) + 1;
            rewind($handle);
            ftruncate($handle, 0);
            fwrite($handle, json_encode($record, JSON_THROW_ON_ERROR));
            fflush($handle);
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }
        @chmod($file, 0600);
    }

    public function success(string $key): void
    {
        @unlink($this->file($key));
    }

    private function read(string $key): array
    {
        $file = $this->file($key);
        if (!is_file($file)) {
            return ['failures' => 0, 'window_start' => time()];
        }
        $record = json_decode((string) file_get_contents($file), true);
        if (!is_array($record)) {
            return ['failures' => 0, 'window_start' => time()];
        }
        return [
            'failures' => max(0, (int) ($record['failures'] ?? 0)),
            'window_start' => (int) ($record['window_start'] ?? time()),
        ];
    }

    private function file(string $key): string
    {
        return rtrim($this->directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.json';
    }
}
