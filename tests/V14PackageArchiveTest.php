<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageArchive;

if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
    echo "V14 package archive test skipped: Zip extension unavailable.\n";
    exit(0);
}

$root = sys_get_temp_dir() . '/securepkg-v14-archive-' . bin2hex(random_bytes(6));
$package = $root . '/package';
$archive = $root . '/package.spkg14';
$restore = $root . '/restore';
mkdir($package . '/blobs', 0700, true);
file_put_contents($package . '/header.json', '{"format":"SECURE-PKG-V14"}');
file_put_contents($package . '/manifest.enc', random_bytes(96));
file_put_contents($package . '/complete.json', '{"version":14}');
file_put_contents($package . '/blobs/' . str_repeat('a', 48) . '.bin', random_bytes(4096));

try {
    $service = new PackageArchive();
    $service->create($package, $archive);
    $service->extract($archive, $restore);
    foreach (['header.json', 'manifest.enc', 'complete.json', 'blobs/' . str_repeat('a', 48) . '.bin'] as $relative) {
        $path = $restore . '/' . $relative;
        if (!is_file($path)) throw new RuntimeException('Archive round-trip missing: ' . $relative);
    }
    echo "V14 package archive round-trip test passed.\n";
} finally {
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
