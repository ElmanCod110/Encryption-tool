<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;
use ZipArchive;

final class PackageArchive
{
    private const MAX_ENTRIES = 2048;
    private const MAX_UNCOMPRESSED_BYTES = V14Descriptor::MAX_TOTAL_PLAIN_BYTES + 256 * 1024 * 1024;
    private const COPY_BUFFER_BYTES = 1024 * 1024;

    public function create(string $packageDir, string $outputFile): void
    {
        $this->assertZipRuntime();
        $root = realpath($packageDir);
        if ($root === false || !is_dir($root)) throw new RuntimeException('Package directory does not exist.');
        $tmpOutput = $outputFile . '.partial.' . bin2hex(random_bytes(12));
        $zip = new ZipArchive();
        if ($zip->open($tmpOutput, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            @unlink($tmpOutput);
            throw new RuntimeException('Unable to create package archive.');
        }
        try {
            $count = 0;
            $used = [];
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if (!$file->isFile() || $file->isLink() || $file->getFilename() === 'record.json') continue;
                if (++$count > self::MAX_ENTRIES) throw new RuntimeException('Package archive contains too many entries.');
                $path = $file->getPathname();
                $relative = str_replace('\\', '/', substr($path, strlen(rtrim($root, DIRECTORY_SEPARATOR)) + 1));
                $this->assertArchivePath($relative);
                $normalized = function_exists('mb_strtolower') ? mb_strtolower($relative, 'UTF-8') : strtolower($relative);
                if (isset($used[$normalized])) throw new RuntimeException('Package archive contains colliding paths.');
                $used[$normalized] = true;
                if (!$zip->addFile($path, $relative)) throw new RuntimeException('Unable to add package file to archive.');
                $zip->setCompressionName($relative, ZipArchive::CM_STORE);
            }
            if (!$zip->close()) throw new RuntimeException('Unable to finalize package archive.');
            if (!rename($tmpOutput, $outputFile)) throw new RuntimeException('Unable to finalize package archive.');
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
        if ($zip->open($archiveFile) !== true) {
            $this->removeDirectory($destinationDir);
            throw new RuntimeException('Unable to open package archive.');
        }
        try {
            if ($zip->numFiles < 1 || $zip->numFiles > self::MAX_ENTRIES) throw new RuntimeException('Package archive is invalid.');
            $entries = [];
            $totalDeclared = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) throw new RuntimeException('Package archive is invalid.');
                $name = str_replace('\\', '/', (string) ($stat['name'] ?? ''));
                $isDir = str_ends_with($name, '/');
                if ($isDir) $name = rtrim($name, '/');
                if ($name === '') continue;
                $this->assertArchivePath($name);
                $size = (int) ($stat['size'] ?? -1);
                if ($size < 0) throw new RuntimeException('Package archive is invalid.');
                if (!$isDir && $size > self::MAX_UNCOMPRESSED_BYTES) throw new RuntimeException('Package archive is invalid.');
                $totalDeclared += $size;
                if ($totalDeclared > self::MAX_UNCOMPRESSED_BYTES) throw new RuntimeException('Package archive is invalid.');
                $normalized = function_exists('mb_strtolower') ? mb_strtolower($name, 'UTF-8') : strtolower($name);
                if (isset($entries[$normalized])) throw new RuntimeException('Package archive contains duplicate paths.');
                $entries[$normalized] = ['name' => $name, 'is_dir' => $isDir, 'size' => $size, 'index' => $i];
            }
            ksort($entries, SORT_STRING);
            $entryTypes = [];
            foreach ($entries as $entry) $entryTypes[$entry['name']] = $entry['is_dir'] ? 'dir' : 'file';
            foreach ($entries as $entry) {
                if ($entry['is_dir']) continue;
                $segments = explode('/', $entry['name']);
                array_pop($segments);
                $ancestor = '';
                foreach ($segments as $segment) {
                    $ancestor = $ancestor === '' ? $segment : $ancestor . '/' . $segment;
                    $ancestorKey = function_exists('mb_strtolower') ? mb_strtolower($ancestor, 'UTF-8') : strtolower($ancestor);
                    foreach ($entryTypes as $entryName => $entryType) {
                        $entryKey = function_exists('mb_strtolower') ? mb_strtolower($entryName, 'UTF-8') : strtolower($entryName);
                        if ($entryKey === $ancestorKey && $entryType === 'file') throw new RuntimeException('Package archive contains a file/directory conflict.');
                    }
                    $parentPath = $destinationDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $ancestor);
                    if (file_exists($parentPath) && !is_dir($parentPath)) throw new RuntimeException('Package archive contains a file/directory conflict.');
                }
            }
            // Create directories in path-depth order before any file writes.
            $dirs = array_filter($entries, static fn(array $entry): bool => $entry['is_dir']);
            usort($dirs, static fn(array $a, array $b): int => (substr_count($a['name'], '/') <=> substr_count($b['name'], '/')) ?: strcmp($a['name'], $b['name']));
            foreach ($dirs as $entry) {
                $target = $destinationDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $entry['name']);
                if (!mkdir($target, 0700, true) && !is_dir($target)) throw new RuntimeException('Unable to recreate package directory.');
            }

            $copiedTotal = 0;
            foreach ($entries as $entry) {
                if ($entry['is_dir']) continue;
                $name = $entry['name'];
                $target = $destinationDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $name);
                $parent = dirname($target);
                if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) throw new RuntimeException('Unable to recreate package directory.');
                if (file_exists($target) || is_link($target)) throw new RuntimeException('Package archive contains a duplicate path.');
                $stream = $zip->getStream($name);
                if ($stream === false) throw new RuntimeException('Unable to read package archive.');
                $out = fopen($target, 'xb');
                if ($out === false) { fclose($stream); throw new RuntimeException('Unable to create package file.'); }
                $copied = 0;
                try {
                    while (!feof($stream)) {
                        $chunk = fread($stream, self::COPY_BUFFER_BYTES);
                        if ($chunk === false) throw new RuntimeException('Unable to extract package file.');
                        if ($chunk === '') break;
                        $copied += strlen($chunk);
                        $copiedTotal += strlen($chunk);
                        if ($copied > $entry['size'] || $copiedTotal > self::MAX_UNCOMPRESSED_BYTES) throw new RuntimeException('Package archive exceeds extraction limits.');
                        $this->writeAll($out, $chunk);
                    }
                    if ($copied !== $entry['size']) throw new RuntimeException('Package archive size mismatch.');
                } finally {
                    fclose($stream);
                    fclose($out);
                }
                @chmod($target, 0600);
            }
        } catch (\Throwable $e) {
            $zip->close();
            $this->removeDirectory($destinationDir);
            throw $e;
        }
        $zip->close();
    }

    private function assertArchivePath(string $name): void
    {
        if ($name === '' || strlen($name) > 4096 || str_starts_with($name, '/') || preg_match('/^[A-Za-z]:\//', $name) === 1 || str_contains($name, "\0") || preg_match('#(?:^|/)\.\.(?:/|$)#', $name) || preg_match('/[\x00-\x1F\x7F:]/u', $name) === 1) {
            throw new RuntimeException('Package archive contains an unsafe path.');
        }
        foreach (explode('/', $name) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..' || str_ends_with($segment, ' ') || str_ends_with($segment, '.') || preg_match('/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i', $segment) === 1) {
                throw new RuntimeException('Package archive contains an unsafe path.');
            }
        }
    }

    private function writeAll($handle, string $data): void
    {
        $offset = 0;
        $length = strlen($data);
        while ($offset < $length) {
            $written = fwrite($handle, substr($data, $offset));
            if ($written === false || $written === 0) throw new RuntimeException('Unable to write package data.');
            $offset += $written;
        }
    }

    private function assertZipRuntime(): void
    {
        if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) throw new RuntimeException('PHP Zip extension is required.');
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) return;
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \FilesystemIterator::CHILD_FIRST);
        foreach ($iterator as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($path);
    }
}
