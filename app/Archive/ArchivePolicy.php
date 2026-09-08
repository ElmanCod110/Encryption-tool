<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;

/**
 * Central archive safety policy. Validation is fail-closed and independent from extraction.
 */
final class ArchivePolicy
{
    public function __construct(
        public readonly int $maxEntries = 100000,
        public readonly int $maxSingleFileBytes = 536870912,
        public readonly int $maxTotalUncompressedBytes = 5368709120,
        public readonly int $maxDepth = 8,
        public readonly int $maxNestedArchives = 64,
        public readonly int $maxPathLength = 1024
    ) {}

    public function assertSafePath(string $path): void
    {
        if ($path === '' || strlen($path) > $this->maxPathLength || str_contains($path, "\0")) {
            throw new RuntimeException('Unsafe archive path.');
        }
        $normalized = str_replace('\\', '/', $path);
        if (str_starts_with($normalized, '/') || preg_match('/^[A-Za-z]:\//', $normalized)) {
            throw new RuntimeException('Unsafe archive path.');
        }
        foreach (explode('/', $normalized) as $segment) {
            if ($segment === '..' || $segment === '' || $segment === '.') {
                if ($segment === '..' || $segment === '') throw new RuntimeException('Unsafe archive path.');
                continue;
            }
            if (preg_match('/[\x00-\x1F\x7F]/', $segment)) throw new RuntimeException('Unsafe archive path.');
        }
    }
}
