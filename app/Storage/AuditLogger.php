<?php
declare(strict_types=1);

namespace SecurePackage\Storage;

use RuntimeException;

final class AuditLogger
{
    public function __construct(private readonly string $file) {}

    public function event(string $event, array $context = []): void
    {
        $record = [
            'time' => gmdate('c'),
            'event' => $event,
            'context' => $this->sanitize($context),
        ];
        $directory = dirname($this->file);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to initialize audit storage.');
        }
        $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . PHP_EOL;
        $handle = fopen($this->file, 'ab');
        if ($handle === false) {
            throw new RuntimeException('Unable to open audit log.');
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Unable to lock audit log.');
            }
            fwrite($handle, $line);
            fflush($handle);
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }
        @chmod($this->file, 0600);
    }

    private function sanitize(array $context): array
    {
        $blocked = ['password', 'pattern', 'secret', 'token', 'csrf'];
        $result = [];
        foreach ($context as $key => $value) {
            if (in_array(strtolower((string) $key), $blocked, true)) {
                continue;
            }
            if (is_scalar($value) || $value === null) {
                $result[(string) $key] = $value;
            }
        }
        return $result;
    }
}
