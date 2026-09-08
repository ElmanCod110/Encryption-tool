<?php
declare(strict_types=1);

namespace TCH\Archive;

use RuntimeException;
use ZipArchive;

final class SafeZipExtractor
{
    public function __construct(
        private readonly int $maxEntries = 100000,
        private readonly int $maxSingleFileBytes = 512000000,
        private readonly int $maxTotalUncompressedBytes = 5368709120
    ) {}

    public function extract(string $zipPath, string $destinationDir, ?string $password = null): void
    {
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new RuntimeException('Unable to open ZIP archive.');
        }
        if ($password !== null) {
            $zip->setPassword($password);
        }
        try {
            if ($zip->numFiles > $this->maxEntries) {
                throw new RuntimeException('Archive contains too many entries.');
            }
            $total = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) {
                    throw new RuntimeException('Unable to inspect archive entry.');
                }
                $name = str_replace('\\', '/', (string) $stat['name']);
                if ($this->unsafePath($name)) {
                    throw new RuntimeException('Archive contains an unsafe path.');
                }
                $size = (int) ($stat['size'] ?? 0);
                if ($size > $this->maxSingleFileBytes || ($total += max(0, $size)) > $this->maxTotalUncompressedBytes) {
                    throw new RuntimeException('Archive exceeds extraction limits.');
                }
                $stream = $zip->getStream($name);
                if ($stream === false) {
                    throw new RuntimeException('Unable to read archive entry.');
                }
                $target = $destinationDir . DIRECTORY_SEPARATOR . $name;
                if (str_ends_with($name, '/')) {
                    if (!mkdir($target, 0700, true) && !is_dir($target)) {
                        fclose($stream);
                        throw new RuntimeException('Unable to create directory.');
                    }
                    fclose($stream);
                    continue;
                }
                $parent = dirname($target);
                if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) {
                    fclose($stream);
                    throw new RuntimeException('Unable to create extraction directory.');
                }
                $out = fopen($target, 'wb');
                if ($out === false) {
                    fclose($stream);
                    throw new RuntimeException('Unable to create extracted file.');
                }
                stream_copy_to_stream($stream, $out);
                fclose($stream);
                fclose($out);
            }
        } finally {
            $zip->close();
        }
    }

    private function unsafePath(string $path): bool
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
