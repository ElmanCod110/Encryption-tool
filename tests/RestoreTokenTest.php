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
    $preview = $store->resolve($token);
    if ($preview !== realpath($restore)) {
        throw new RuntimeException('Non-consuming restore-token resolution failed.');
    }
    $tokenFile = $root . '/tokens/' . hash('sha256', $token) . '.json';
    $waitingHandle = fopen($tokenFile, 'r+');
    if ($waitingHandle === false) {
        throw new RuntimeException('Unable to open token inode for replay-race regression test.');
    }

    try {
        $resolved = $store->consume($token);
        if ($resolved !== realpath($restore)) {
            throw new RuntimeException('Restore token resolution failed.');
        }

        // A concurrent request may already have opened the same inode before unlink.
        // It must observe a consumed marker after it obtains the exclusive lock.
        rewind($waitingHandle);
        $waitingRecord = json_decode((string) stream_get_contents($waitingHandle), true);
        if (!is_array($waitingRecord) || ($waitingRecord['consumed'] ?? false) !== true) {
            throw new RuntimeException('An already-open token handle did not observe the consumed marker.');
        }
    } finally {
        fclose($waitingHandle);
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
