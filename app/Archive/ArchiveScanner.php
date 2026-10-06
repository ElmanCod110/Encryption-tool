<?php
declare(strict_types=1);

namespace TCH\Archive;

use RuntimeException;
use ZipArchive;

final class ArchiveScanner
{
    public function __construct(private readonly ArchivePolicy $policy = new ArchivePolicy()) {}

    public function scan(string $zipPath): array
    {
        if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
            throw new RuntimeException('PHP Zip extension is required.');
        }
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new RuntimeException('Unable to open ZIP archive.');
        }
        try {
            if ($zip->numFiles > $this->policy->maxEntries) {
                throw new RuntimeException('Archive entry limit exceeded.');
            }
            $entries = [];
            $total = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) {
                    throw new RuntimeException('Unable to inspect archive entry.');
                }
                $name = str_replace('\\', '/', (string) ($stat['name'] ?? ''));
                $this->validateEntryPath($name);
                $size = max(0, (int) ($stat['size'] ?? 0));
                $isDir = str_ends_with($name, '/');
                if (!$isDir) {
                    if ($size > $this->policy->maxSingleFileBytes) {
                        throw new RuntimeException('Single file extraction limit exceeded.');
                    }
                    $total += $size;
                    if ($total > $this->policy->maxTotalUncompressedBytes) {
                        throw new RuntimeException('Total extraction limit exceeded.');
                    }
                }
                $entries[] = ['name' => $name, 'size' => $size, 'index' => $i, 'is_dir' => $isDir, 'encrypted' => (($stat['encryption_method'] ?? 0) !== 0)];
            }
            return ['entries' => $entries, 'total_uncompressed' => $total, 'requires_password' => $this->requiresPassword($zip)];
        } finally {
            $zip->close();
        }
    }

    private function requiresPassword(ZipArchive $zip): bool
    {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
            if ($stat !== false && (($stat['encryption_method'] ?? 0) !== 0)) {
                return true;
            }
        }
        return false;
    }

    private function validateEntryPath(string $path): void
    {
        if ($path === '' || str_starts_with($path, '/') || preg_match('/^[A-Za-z]:\//', $path) === 1 || str_contains($path, "\0")) {
            throw new RuntimeException('Archive contains an unsafe path.');
        }
        foreach (explode('/', $path) as $part) {
            if ($part === '.' || $part === '..') {
                throw new RuntimeException('Archive contains an unsafe path.');
            }
        }
        if (strlen($path) > $this->policy->maxPathLength) {
            throw new RuntimeException('Archive path is too long.');
        }
    }
}
