<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\RestoreTokenStore;

$root = sys_get_temp_dir() . '/securepkg-token-' . bin2hex(random_bytes(6));
mkdir($root, 0700, true);
$restore = $root . '/restore';
mkdir($restore, 0700, true);
file_put_contents($restore . '/sample.txt', 'restore-token-test');
$store = new RestoreTokenStore($root . '/tokens', 60);
$token = $store->issue($restore);
$resolved = $store->consume($token);
if ($resolved !== realpath($restore)) {
    throw new RuntimeException('Restore token resolution failed.');
}
try {
    $store->consume($token);
    throw new RuntimeException('Restore token was reusable.');
} catch (RuntimeException) {
}

$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
foreach ($iterator as $item) {
    $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
}
@rmdir($root);

echo "Restore token tests passed.\n";
