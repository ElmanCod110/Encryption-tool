<?php
declare(strict_types=1);

namespace TCH\Archive;

use RuntimeException;
use ZipArchive;

final class ArchiveScanner
{
    public function scan(string $zipPath): array
    {
        if (!class_exists(ZipArchive::class)) {
            throw new RuntimeException('PHP Zip extension is required.');
        }
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new RuntimeException('Unable to open ZIP archive.');
        }
        $files = [];
        try {
            if ($zip->numFiles > 100000) {
                throw new RuntimeException('Archive contains too many entries.');
            }
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) {
                    throw new RuntimeException('Unable to inspect archive entry.');
                }
                $name = str_replace('\\', '/', $stat['name']);
                if ($this->isUnsafePath($name)) {
                    throw new RuntimeException('Archive contains an unsafe path.');
                }
                $files[] = [
                    'name' => $name,
                    'size' => (int) ($stat['size'] ?? 0),
                    'index' => $i,
                    'is_dir' => str_ends_with($name, '/'),
                ];
            }
        } finally {
            $zip->close();
        }
        return $files;
    }

    private function isUnsafePath(string $path): bool
    {
        if ($path === '' || str_starts_with($path, '/') || preg_match('/^[A-Za-z]:\//', $path)) {
            return true;
        }
        foreach (explode('/', $path) as $part) {
            if ($part === '..' || $part === '.') {
                return true;
            }
        }
        return str_contains($path, "\0");
    }
}
