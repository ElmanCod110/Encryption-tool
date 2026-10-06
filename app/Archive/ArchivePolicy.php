<?php
declare(strict_types=1);

namespace TCH\Archive;

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
}
