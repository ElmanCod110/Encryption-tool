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
        $segments = explode('/', $normalized);
        if (end($segments) === '') array_pop($segments);
        foreach ($segments as $segment) {
            if ($segment === '..' || $segment === '' || $segment === '.') {
                throw new RuntimeException('Unsafe archive path.');
            }
            if (strlen($segment) > 255 || preg_match('/[\x00-\x1F\x7F]/', $segment) === 1 || str_contains($segment, ':') || str_ends_with($segment, '.') || str_ends_with($segment, ' ')) {
                throw new RuntimeException('Unsafe archive path.');
            }
            if (preg_match('/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i', $segment) === 1) {
                throw new RuntimeException('Unsafe archive path.');
            }
        }
    }
}
