<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;
use ZipArchive;

final class SafeZipExtractor
{
    public function __construct(private readonly ArchivePolicy $policy = new ArchivePolicy()) {}

    public function extractRecursive(string $zipPath, string $destinationDir, ArchivePasswordProvider $passwordProvider): array
    {
        if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
            throw new RuntimeException('PHP Zip extension is required.');
        }
        $state = ['archives' => 0, 'files' => 0, 'bytes' => 0, 'password_cache' => []];
        $root = $this->canonicalFile($zipPath);
        $destinationDir = $this->prepareDestination($destinationDir);
        $this->extractOne($root, $destinationDir, $passwordProvider, $state, 0);
        return $state;
    }

    private function extractOne(string $zipPath, string $destinationDir, ArchivePasswordProvider $provider, array &$state, int $depth): void
    {
        if ($depth > $this->policy->maxDepth) {
            throw new RuntimeException('Nested archive depth limit exceeded.');
        }
        if (++$state['archives'] > $this->policy->maxNestedArchives) {
            throw new RuntimeException('Nested archive count limit exceeded.');
        }

        $zip = new ZipArchive();
        $openResult = $zip->open($zipPath);
        if ($openResult !== true) {
            throw new RuntimeException('Unable to open ZIP archive.');
        }

        try {
            $seenPaths = [];
            if ($zip->numFiles > $this->policy->maxEntries) {
                throw new RuntimeException('Archive entry limit exceeded.');
            }
            $password = $provider->passwordFor($zipPath, $depth);
            if ($password !== '') {
                $zip->setPassword($password);
            }

            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) {
                    throw new RuntimeException('Unable to inspect archive entry.');
                }
                $name = str_replace('\\', '/', (string) ($stat['name'] ?? ''));
                $this->validateEntryPath($name);
                if (strlen($name) > $this->policy->maxPathLength) {
                    throw new RuntimeException('Archive path is too long.');
                }
                if ($this->isSymbolicLink($zip, $i)) {
                    throw new RuntimeException('Symbolic links are not supported in archives.');
                }

                $isDir = str_ends_with($name, '/');
                $collisionKey = strtolower(rtrim($name, '/'));
                if ($collisionKey !== '' && isset($seenPaths[$collisionKey])) {
                    throw new RuntimeException('Archive contains a case-insensitive path collision.');
                }
                if ($collisionKey !== '') {
                    $seenPaths[$collisionKey] = true;
                }
                $declaredSize = max(0, (int) ($stat['size'] ?? 0));
                if (!$isDir && $declaredSize > $this->policy->maxSingleFileBytes) {
                    throw new RuntimeException('Single file extraction limit exceeded.');
                }

                $target = $destinationDir . DIRECTORY_SEPARATOR . $name;
                if ($isDir) {
                    if (!mkdir($target, 0700, true) && !is_dir($target)) {
                        throw new RuntimeException('Unable to create archive directory.');
                    }
                    continue;
                }

                $parent = dirname($target);
                if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) {
                    throw new RuntimeException('Unable to create extraction directory.');
                }
                if (file_exists($target)) {
                    throw new RuntimeException('Archive contains duplicate output paths.');
                }

                $stream = $zip->getStream($name);
                if ($stream === false) {
                    throw new RuntimeException('Unable to read ZIP entry. The archive may require a different password.');
                }
                $out = fopen($target, 'xb');
                if ($out === false) {
                    fclose($stream);
                    throw new RuntimeException('Unable to create extracted file.');
                }
                try {
                    $copied = 0;
                    while (!feof($stream)) {
                        $buffer = fread($stream, 1024 * 1024);
                        if ($buffer === false) {
                            throw new RuntimeException('Unable to extract archive entry.');
                        }
                        if ($buffer === '') {
                            continue;
                        }
                        $length = strlen($buffer);
                        $copied += $length;
                        if ($copied > $this->policy->maxSingleFileBytes) {
                            throw new RuntimeException('Single file extraction limit exceeded.');
                        }
                        $newTotal = $state['bytes'] + $length;
                        if ($newTotal > $this->policy->maxTotalUncompressedBytes) {
                            throw new RuntimeException('Total extraction limit exceeded.');
                        }
                        $written = fwrite($out, $buffer);
                        if ($written !== $length) {
                            throw new RuntimeException('Unable to extract archive entry.');
                        }
                        $state['bytes'] = $newTotal;
                    }
                    if ($copied !== $declaredSize) {
                        throw new RuntimeException('Archive entry size mismatch.');
                    }
                    $state['files']++;
                } finally {
                    fclose($stream);
                    fclose($out);
                }

                if ($this->looksLikeZip($target)) {
                    $nestedDir = $target . '.contents.' . bin2hex(random_bytes(6));
                    if (!mkdir($nestedDir, 0700) || !is_dir($nestedDir)) {
                        throw new RuntimeException('Unable to create nested archive workspace.');
                    }
                    try {
                        $this->extractOne($target, $nestedDir, $provider, $state, $depth + 1);
                        @unlink($target);
                        $this->mergeDirectory($nestedDir, $destinationDir . DIRECTORY_SEPARATOR . preg_replace('/\.zip$/i', '', $name));
                    } finally {
                        $this->removeDirectory($nestedDir);
                    }
                }
            }
        } finally {
            $zip->close();
        }
    }

    private function looksLikeZip(string $path): bool
    {
        if (!is_file($path) || filesize($path) < 4) {
            return false;
        }
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }
        $signature = fread($handle, 4);
        fclose($handle);
        return $signature === "PK\x03\x04" || $signature === "PK\x05\x06" || $signature === "PK\x07\x08";
    }

    private function validateEntryPath(string $path): void
    {
        $this->policy->assertSafePath($path);
    }

    private function isSymbolicLink(ZipArchive $zip, int $index): bool
    {
        if (!method_exists($zip, 'getExternalAttributesIndex')) {
            return false;
        }
        $opsys = 0;
        $attributes = 0;
        if (!$zip->getExternalAttributesIndex($index, $opsys, $attributes, ZipArchive::FL_UNCHANGED)) {
            return false;
        }
        if ($opsys === ZipArchive::OPSYS_UNIX) {
            return (($attributes >> 16) & 0xF000) === 0xA000;
        }
        return false;
    }

    private function canonicalFile(string $path): string
    {
        $real = realpath($path);
        if ($real === false || !is_file($real)) {
            throw new RuntimeException('ZIP file does not exist.');
        }
        return $real;
    }

    private function prepareDestination(string $path): string
    {
        if (file_exists($path)) {
            throw new RuntimeException('Destination directory already exists.');
        }
        if (!mkdir($path, 0700, true)) {
            throw new RuntimeException('Unable to create destination directory.');
        }
        return realpath($path) ?: $path;
    }

    private function mergeDirectory(string $source, string $target): void
    {
        if (!is_dir($target) && !mkdir($target, 0700, true)) {
            throw new RuntimeException('Unable to merge nested archive contents.');
        }
        $existing = [];
        $targetIterator = new \FilesystemIterator($target, \FilesystemIterator::SKIP_DOTS);
        foreach ($targetIterator as $item) {
            $existing[strtolower($item->getFilename())] = true;
        }
        $iterator = new \FilesystemIterator($source, \FilesystemIterator::SKIP_DOTS);
        foreach ($iterator as $item) {
            $name = $item->getFilename();
            $collision = strtolower($name);
            $destination = $target . DIRECTORY_SEPARATOR . $name;
            if (isset($existing[$collision]) || file_exists($destination)) {
                throw new RuntimeException('Nested archive path collision detected.');
            }
            $existing[$collision] = true;
            if ($item->isDir()) {
                rename($item->getPathname(), $destination);
            } else {
                rename($item->getPathname(), $destination);
            }
        }
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($path);
    }
}
