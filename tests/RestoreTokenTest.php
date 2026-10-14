<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\RestoreTokenStore;

$root = sys_get_temp_dir() . '/securepkg-token-' . bin2hex(random_bytes(6));
if (!mkdir($root, 0700, true)) {
    throw new RuntimeException('Unable to create restore-token test directory.');
}
$restore = $root . '/restore';
mkdir($restore, 0700, true);
file_put_contents($restore . '/sample.txt', 'restore-token-test');
$store = new RestoreTokenStore($root . '/tokens', 60);

try {
    $token = $store->issue($restore);
    $resolved = $store->consume($token);
    if ($resolved !== realpath($restore)) {
        throw new RuntimeException('Restore token resolution failed.');
    }

    $reused = false;
    try {
        $store->consume($token);
        $reused = true;
    } catch (RuntimeException) {
        // Expected: restore tokens are single-use.
    }
    if ($reused) {
        throw new RuntimeException('Restore token was reusable.');
    }

    echo "Restore token single-use tests passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $item->isDir() && !$item->isLink() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }
    @rmdir($root);
}
