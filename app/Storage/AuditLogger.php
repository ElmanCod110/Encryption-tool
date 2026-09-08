<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

/**
 * Appends tamper-evident JSONL security events using a SHA-256 hash chain.
 */
final class AuditLogger
{
    private string $headFile;

    public function __construct(private readonly string $file)
    {
        $directory = dirname($file);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize audit storage.');
        }
        $this->headFile = $file . '.head';
        if (!is_file($this->headFile)) {
            AtomicFile::write($this->headFile, str_repeat('0', 64));
        }
    }

    public function event(string $event, array $context = []): void
    {
        if ($event === '' || strlen($event) > 120) {
            throw new RuntimeException('Invalid audit event.');
        }
        $handle = fopen($this->file, 'c+b');
        $headHandle = fopen($this->headFile, 'c+b');
        if ($handle === false || $headHandle === false) {
            if (is_resource($handle)) fclose($handle);
            if (is_resource($headHandle)) fclose($headHandle);
            throw new RuntimeException('Unable to open audit log.');
        }
        try {
            if (!flock($handle, LOCK_EX) || !flock($headHandle, LOCK_EX)) {
                throw new RuntimeException('Unable to lock audit log.');
            }
            rewind($headHandle);
            $previous = trim((string) stream_get_contents($headHandle));
            if (!preg_match('/^[a-f0-9]{64}$/', $previous)) {
                $previous = str_repeat('0', 64);
            }
            $record = [
                'time' => gmdate('c'),
                'event' => $event,
                'context' => $this->sanitize($context),
                'previous_hash' => $previous,
            ];
            $canonical = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $hash = hash('sha256', $canonical);
            $record['hash'] = $hash;
            $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . PHP_EOL;
            fseek($handle, 0, SEEK_END);
            if (fwrite($handle, $line) !== strlen($line)) {
                throw new RuntimeException('Unable to append audit log.');
            }
            fflush($handle);
            ftruncate($headHandle, 0);
            rewind($headHandle);
            fwrite($headHandle, $hash);
            fflush($headHandle);
            flock($headHandle, LOCK_UN);
            flock($handle, LOCK_UN);
        } finally {
            fclose($headHandle);
            fclose($handle);
        }
        @chmod($this->file, 0600);
        @chmod($this->headFile, 0600);
    }

    public function verify(): bool
    {
        if (!is_file($this->file)) {
            return true;
        }
        $previous = str_repeat('0', 64);
        $lines = file($this->file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return false;
        }
        foreach ($lines as $line) {
            try {
                $record = json_decode($line, true, 32, JSON_THROW_ON_ERROR);
            } catch (\Throwable) {
                return false;
            }
            if (!is_array($record)) return false;
            $hash = (string) ($record['hash'] ?? '');
            $recordWithoutHash = $record;
            unset($recordWithoutHash['hash']);
            if (!hash_equals($previous, (string) ($recordWithoutHash['previous_hash'] ?? ''))) return false;
            $canonical = json_encode($recordWithoutHash, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            if (!hash_equals($hash, hash('sha256', $canonical))) return false;
            $previous = $hash;
        }
        $head = trim((string) @file_get_contents($this->headFile));
        return hash_equals($previous, $head);
    }

    private function sanitize(array $context): array
    {
        $blocked = ['password', 'pattern', 'secret', 'token', 'csrf', 'authorization', 'cookie'];
        $result = [];
        foreach ($context as $key => $value) {
            if (in_array(strtolower((string) $key), $blocked, true)) continue;
            if (is_scalar($value) || $value === null) $result[(string) $key] = $value;
        }
        ksort($result);
        return $result;
    }
}
