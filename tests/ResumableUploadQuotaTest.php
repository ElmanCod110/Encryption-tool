<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Storage\QuotaExceededException;
use SecurePackage\Storage\ResumableUploadStore;

$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-upload-quota-' . bin2hex(random_bytes(8));
$bytesRoot = $base . DIRECTORY_SEPARATOR . 'bytes';
$countRoot = $base . DIRECTORY_SEPARATOR . 'count';
if (!mkdir($bytesRoot, 0700, true) || !mkdir($countRoot, 0700, true)) {
    throw new RuntimeException('Unable to create upload quota fixtures.');
}

try {
    $byteStore = new ResumableUploadStore($bytesRoot, 1000, 3600, 3, 70);
    $byteStore->initialize(40, 'owner-a');
    $byteStore->initialize(30, 'owner-a');
    $bytesRejected = false;
    try {
        $byteStore->initialize(1, 'owner-a');
    } catch (QuotaExceededException) {
        $bytesRejected = true;
    }
    if (!$bytesRejected) {
        throw new RuntimeException('Per-owner reserved-byte quota was not enforced.');
    }

    $otherOwner = $byteStore->initialize(60, 'owner-b');
    if (($otherOwner['total_bytes'] ?? null) !== 60) {
        throw new RuntimeException('One owner incorrectly consumed another owner\'s quota.');
    }

    $countStore = new ResumableUploadStore($countRoot, 1000, 3600, 2, 1000);
    $countStore->initialize(10, 'owner-c');
    $countStore->initialize(10, 'owner-c');
    $countRejected = false;
    try {
        $countStore->initialize(10, 'owner-c');
    } catch (QuotaExceededException) {
        $countRejected = true;
    }
    if (!$countRejected) {
        throw new RuntimeException('Per-owner active-upload count quota was not enforced.');
    }

    $cleanupRoot = $base . DIRECTORY_SEPARATOR . 'cleanup';
    $cleanupStore = new ResumableUploadStore($cleanupRoot, 1000, 1, 3, 1000);
    $expired = $cleanupStore->initialize(10, 'owner-cleanup');
    sleep(2);
    $cleanupStore->cleanup();
    if (file_exists($cleanupRoot . DIRECTORY_SEPARATOR . $expired['id'])) {
        throw new RuntimeException('Expired upload data was not cleaned up.');
    }

    echo "Resumable upload quota tests passed.\n";
} finally {
    foreach ([$bytesRoot, $countRoot, $base . DIRECTORY_SEPARATOR . 'cleanup'] as $root) {
        if (!is_dir($root)) continue;
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir() && !$item->isLink()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }
        @rmdir($root);
    }
    @rmdir($base);
}
