<?php
declare(strict_types=1);

namespace TCH\Storage;

use RuntimeException;

final class FileStore
{
    public function __construct(private readonly string $root)
    {
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
            throw new RuntimeException('Unable to initialize storage directory.');
        }
    }

    public function createPackageDirectory(string $packageId): string
    {
        $path = $this->root . DIRECTORY_SEPARATOR . $packageId;
        if (!mkdir($path, 0700, true) && !is_dir($path)) {
            throw new RuntimeException('Unable to create package directory.');
        }
        mkdir($path . DIRECTORY_SEPARATOR . 'blobs', 0700, true);
        return $path;
    }
}
