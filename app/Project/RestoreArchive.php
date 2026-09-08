<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use ZipArchive;

final class RestoreArchive
{
    public function create(string $sourceDir, string $outputFile): void
    {
        if (!is_dir($sourceDir)) {
            throw new RuntimeException('Restore directory does not exist.');
        }
        if (file_exists($outputFile)) {
            throw new RuntimeException('Restore archive already exists.');
        }
        if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
            throw new RuntimeException('PHP Zip extension is required.');
        }
        $zip = new ZipArchive();
        if ($zip->open($outputFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException('Unable to create restore archive.');
        }
        try {
            $root = realpath($sourceDir);
            if ($root === false) {
                throw new RuntimeException('Invalid restore directory.');
            }
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iterator as $item) {
                if ($item->isLink()) {
                    throw new RuntimeException('Symbolic links are not supported in restored output.');
                }
                $path = $item->getPathname();
                $relative = str_replace('\\', '/', substr($path, strlen(rtrim($root, DIRECTORY_SEPARATOR)) + 1));
                if ($relative === '' || str_contains($relative, "\0") || preg_match('#(?:^|/)\.\.(?:/|$)#', $relative)) {
                    throw new RuntimeException('Invalid restore path.');
                }
                if ($item->isDir()) {
                    $zip->addEmptyDir($relative);
                } elseif ($item->isFile()) {
                    if (!$zip->addFile($path, $relative)) {
                        throw new RuntimeException('Unable to add restored file.');
                    }
                }
            }
            if (!$zip->close()) {
                throw new RuntimeException('Unable to finalize restore archive.');
            }
        } catch (\Throwable $e) {
            @$zip->close();
            @unlink($outputFile);
            throw $e;
        }
        @chmod($outputFile, 0600);
    }
}
