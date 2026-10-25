<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageArchive;

if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
    echo "Package archive no-overwrite test skipped: Zip extension unavailable.\n";
    exit(0);
}

$root = sys_get_temp_dir() . '/securepkg-archive-no-overwrite-' . bin2hex(random_bytes(6));
$package = $root . '/package';
$output = $root . '/existing.spkg14';
$sentinel = "preserve-this-existing-archive\n";

mkdir($package . '/blobs', 0700, true);
file_put_contents($package . '/header.json', '{"format":"SECURE-PKG-V14"}');
file_put_contents($output, $sentinel);

try {
    try {
        (new PackageArchive())->create($package, $output);
        throw new RuntimeException('Existing archive destination was overwritten or accepted.');
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() === 'Existing archive destination was overwritten or accepted.') {
            throw $exception;
        }
        if (file_get_contents($output) !== $sentinel) {
            throw new RuntimeException('Existing archive content was changed after a rejected create operation.');
        }
    }

    echo "Package archive no-overwrite test passed.\n";
} finally {
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $item) {
            $item->isDir() && !$item->isLink()
                ? @rmdir($item->getPathname())
                : @unlink($item->getPathname());
        }
        @rmdir($root);
    }
}
