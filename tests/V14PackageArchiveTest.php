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
    // Malformed ZIP containers and hostile paths are rejected as invalid package input,
    // and every owned plaintext extraction tree is removed before returning the error.
    $corruptArchive = $root . '/corrupt.spkg14';
    file_put_contents($corruptArchive, "not a ZIP archive");
    $corruptDestination = $root . '/corrupt-restore';
    try {
        $service->extract($corruptArchive, $corruptDestination);
        throw new RuntimeException('Non-ZIP package archive was accepted.');
    } catch (\SecurePackage\Project\PackageRestoreRejectedException) {
        if (file_exists($corruptDestination) || is_link($corruptDestination)) {
            throw new RuntimeException('Rejected non-ZIP archive left an extraction directory behind.');
        }
    }

    $unsafeArchive = $root . '/unsafe-path.spkg14';
    $malicious = new ZipArchive();
    if ($malicious->open($unsafeArchive, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true
        || !$malicious->addFromString('../escape.txt', 'must not escape')
        || !$malicious->close()) {
        throw new RuntimeException('Unable to create unsafe-path archive fixture.');
    }
    $unsafeDestination = $root . '/unsafe-restore';
    try {
        $service->extract($unsafeArchive, $unsafeDestination);
        throw new RuntimeException('Archive path traversal was accepted.');
    } catch (\SecurePackage\Project\PackageRestoreRejectedException) {
        if (file_exists($unsafeDestination) || is_link($unsafeDestination)
            || file_exists($root . '/escape.txt')) {
            throw new RuntimeException('Rejected traversal archive left output behind.');
        }
    }

    // A pre-existing restore directory is never modified, even if its name collides with
    // the caller's requested output path.
    $existingDestination = $root . '/existing-restore';
    mkdir($existingDestination, 0700, true);
    file_put_contents($existingDestination . '/keep.txt', 'preserve existing output');
    try {
        $service->extract($archive, $existingDestination);
        throw new RuntimeException('Existing extraction destination was overwritten.');
    } catch (\SecurePackage\Project\PackageStorageException) {
        if (file_get_contents($existingDestination . '/keep.txt') !== 'preserve existing output') {
            throw new RuntimeException('Existing extraction destination was modified.');
        }
    }

    echo "V14 package archive round-trip and rejection tests passed.\n";
} finally {
    if (is_dir($root)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $item) $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}
