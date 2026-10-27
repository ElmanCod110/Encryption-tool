<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\PackageId;

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-catalog-list-' . bin2hex(random_bytes(8));
$owner = 'account:list-owner';
$other = 'account:other-owner';
if (!mkdir($root, 0700, true)) {
    throw new RuntimeException('Unable to create package catalog listing fixture.');
}

try {
    $catalog = new PackageCatalog($root);
    $firstId = PackageId::generate();
    $secondId = PackageId::generate();
    $otherId = PackageId::generate();
    $catalog->create($firstId, $owner, 'First package');
    usleep(1000);
    $catalog->create($secondId, $owner, 'Second package');
    $catalog->create($otherId, $other, 'Other owner package');

    $listed = $catalog->listForOwner($owner);
    if (count($listed) !== 2
        || !hash_equals(hash('sha256', $owner), (string) $listed[0]['owner_hash'])
        || !hash_equals(hash('sha256', $owner), (string) $listed[1]['owner_hash'])) {
        throw new RuntimeException('Package catalog listing did not return only valid records for the requested owner.');
    }

    $corruptId = PackageId::generate();
    $corruptPath = $root . DIRECTORY_SEPARATOR . $corruptId . '.json';
    if (file_put_contents($corruptPath, '{"package_id":') === false) {
        throw new RuntimeException('Unable to create corrupt catalog record fixture.');
    }
    $corruptRejected = false;
    try {
        $catalog->listForOwner($owner);
    } catch (RuntimeException $exception) {
        $corruptRejected = str_contains($exception->getMessage(), 'corrupt');
    }
    if (!$corruptRejected) {
        throw new RuntimeException('Catalog listing silently skipped a corrupt record.');
    }
    @unlink($corruptPath);

    $validRecordPath = $root . DIRECTORY_SEPARATOR . $firstId . '.json';
    $symlinkId = PackageId::generate();
    $symlinkPath = $root . DIRECTORY_SEPARATOR . $symlinkId . '.json';
    if (@symlink($validRecordPath, $symlinkPath)) {
        $symlinkRejected = false;
        try {
            $catalog->listForOwner($owner);
        } catch (RuntimeException $exception) {
            $symlinkRejected = str_contains($exception->getMessage(), 'non-regular');
        }
        if (!$symlinkRejected) {
            throw new RuntimeException('Catalog listing followed or silently ignored a record symlink.');
        }
        @unlink($symlinkPath);
    }

    echo "Package catalog listing integrity tests passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isLink() || !$item->isDir()) {
            @unlink($item->getPathname());
        } else {
            @rmdir($item->getPathname());
        }
    }
    @rmdir($root);
}
