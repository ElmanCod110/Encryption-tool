<?php
declare(strict_types=1);

namespace TCH\Security;

final class RateLimiter
{
    public function __construct(
        private readonly string $directory,
        private readonly int $maxFailures = 12,
        private readonly int $windowSeconds = 900
    ) {
        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }
    }

    public function check(string $key): bool
    {
        $record = $this->read($key);
        return $record['failures'] < $this->maxFailures || (time() - $record['window_start']) >= $this->windowSeconds;
    }

    public function failure(string $key): void
    {
        $record = $this->read($key);
        $now = time();
        if (($now - $record['window_start']) >= $this->windowSeconds) {
            $record = ['failures' => 0, 'window_start' => $now];
        }
        $record['failures']++;
        $this->write($key, $record);
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
        return ['failures' => (int) ($record['failures'] ?? 0), 'window_start' => (int) ($record['window_start'] ?? time())];
    }

    private function write(string $key, array $record): void
    {
        $file = $this->file($key);
        file_put_contents($file, json_encode($record, JSON_THROW_ON_ERROR), LOCK_EX);
        @chmod($file, 0600);
    }

    private function file(string $key): string
    {
        return rtrim($this->directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.json';
    }
}
