<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use ZipArchive;

final class PackageArchive
{
    public function create(string $packageDir, string $outputFile): void
    {
        $this->assertZipRuntime();
        if (!is_dir($packageDir)) {
            throw new RuntimeException('Package directory does not exist.');
        }
        $tmpOutput = $outputFile . '.partial.' . bin2hex(random_bytes(12));
        $zip = new ZipArchive();
        if ($zip->open($tmpOutput, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            @unlink($tmpOutput);
            throw new RuntimeException('Unable to create package archive.');
        }
        try {
            $root = realpath($packageDir);
            if ($root === false) {
                throw new RuntimeException('Invalid package directory.');
            }
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if (!$file->isFile() || $file->isLink() || $file->getFilename() === 'record.json') continue;
                $path = $file->getPathname();
                $relative = str_replace('\\', '/', substr($path, strlen(rtrim($root, DIRECTORY_SEPARATOR)) + 1));
                if ($relative === '' || str_contains($relative, "\0") || preg_match('#(?:^|/)\.\.(?:/|$)#', $relative)) {
                    throw new RuntimeException('Invalid package archive path.');
                }
                if (!$zip->addFile($path, $relative)) {
                    throw new RuntimeException('Unable to add package file to archive.');
                }
                $zip->setCompressionName($relative, ZipArchive::CM_STORE);
            }
            if (!$zip->close()) {
                throw new RuntimeException('Unable to finalize package archive.');
            }
            if (!rename($tmpOutput, $outputFile)) {
                throw new RuntimeException('Unable to finalize package archive.');
            }
        } catch (\Throwable $e) {
            @$zip->close();
            @unlink($tmpOutput);
            @unlink($outputFile);
            throw $e;
        }
        @chmod($outputFile, 0600);
    }

    public function extract(string $archiveFile, string $destinationDir): void
    {
        $this->assertZipRuntime();
        if (!is_file($archiveFile)) throw new RuntimeException('Package archive does not exist.');
        if (file_exists($destinationDir)) throw new RuntimeException('Destination directory already exists.');
        if (!mkdir($destinationDir, 0700, true)) throw new RuntimeException('Unable to create extraction directory.');
        $zip = new ZipArchive();
        if ($zip->open($archiveFile) !== true) throw new RuntimeException('Unable to open package archive.');
        try {
            if ($zip->numFiles > 2048) throw new RuntimeException('Package archive is invalid.');
            $totalUncompressed = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) throw new RuntimeException('Package archive is invalid.');
                $totalUncompressed += (int) ($stat['size'] ?? 0);
                if ($totalUncompressed > 8 * 1024 * 1024 * 1024) throw new RuntimeException('Package archive is invalid.');
                $name = str_replace('\\', '/', (string) ($stat['name'] ?? ''));
                if ($name === '' || str_starts_with($name, '/') || preg_match('/^[A-Za-z]:\//', $name) === 1 || str_contains($name, "\0") || preg_match('#(?:^|/)\.\.(?:/|$)#', $name)) {
                    throw new RuntimeException('Package archive contains an unsafe path.');
                }
                $target = $destinationDir . DIRECTORY_SEPARATOR . $name;
                if (str_ends_with($name, '/')) {
                    if (!mkdir($target, 0700, true) && !is_dir($target)) throw new RuntimeException('Unable to recreate package directory.');
                    continue;
                }
                $parent = dirname($target);
                if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) throw new RuntimeException('Unable to recreate package directory.');
                if (file_exists($target)) throw new RuntimeException('Package archive contains a duplicate path.');
                $stream = $zip->getStream($name);
                if ($stream === false) throw new RuntimeException('Unable to read package archive.');
                $out = fopen($target, 'xb');
                if ($out === false) { fclose($stream); throw new RuntimeException('Unable to create package file.'); }
                try {
                    if (stream_copy_to_stream($stream, $out) === false) throw new RuntimeException('Unable to extract package file.');
                } finally { fclose($stream); fclose($out); }
            }
        } catch (\Throwable $e) {
            $zip->close();
            $this->removeDirectory($destinationDir);
            throw $e;
        }
        $zip->close();
    }

    private function assertZipRuntime(): void
    {
        if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) throw new RuntimeException('PHP Zip extension is required.');
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) return;
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($path);
    }
}
