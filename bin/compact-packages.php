#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageArchive;

$root = dirname(__DIR__);
$config = require $root . '/config/config.php';
$packages = $config['storage']['packages'];
$dryRun = in_array('--dry-run', $argv, true);

if (!is_dir($packages)) {
    echo "No package storage directory found.
";
    exit(0);
}

$count = 0;
foreach (glob($packages . DIRECTORY_SEPARATOR . '*', GLOB_NOSORT) ?: [] as $dir) {
    if (!is_dir($dir) || is_link($dir)) continue;
    $packageId = basename($dir);
    if (!preg_match('/^[a-f0-9]{48}$/', $packageId)) continue;
    $archive = $packages . DIRECTORY_SEPARATOR . $packageId . '.spkg14';
    if (is_file($archive)) {
        if ($dryRun) { echo "WOULD REMOVE duplicate directory: {$packageId}
"; } else {
            removeDirectory($dir);
            echo "Compacted: {$packageId}
";
        }
        $count++;
        continue;
    }
    if ($dryRun) {
        echo "WOULD ARCHIVE: {$packageId}
";
        continue;
    }
    (new PackageArchive())->create($dir, $archive);
    removeDirectory($dir);
    echo "Archived and compacted: {$packageId}
";
    $count++;
}

echo ($dryRun ? 'Dry run complete. ' : 'Compaction complete. ') . $count . " package(s) processed.
";

function removeDirectory(string $path): void
{
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    @rmdir($path);
}
