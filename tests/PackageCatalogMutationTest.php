<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageCatalog;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-package-catalog-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700, true)) {
    throw new RuntimeException('Unable to create package catalog test directory.');
}

$packageId = str_repeat('a', 48);
$owner = 'account:owner-a';
try {
    $catalog = new PackageCatalog($directory);
    $catalog->create($packageId, $owner, 'Research package');

    $duplicateRejected = false;
    try {
        $catalog->create($packageId, 'account:owner-b', 'Replacement');
    } catch (RuntimeException) {
        $duplicateRejected = true;
    }
    if (!$duplicateRejected || !hash_equals(hash('sha256', $owner), $catalog->get($packageId)['owner_hash'])) {
        throw new RuntimeException('Duplicate package creation overwrote the existing owner record.');
    }

    $catalog->setExpiry($packageId, $owner, time() + 3600);
    $catalog->revoke($packageId, $owner);
    $record = $catalog->get($packageId);
    if (($record['revoked_at'] ?? null) === null || (int) ($record['expires_at'] ?? 0) <= time()) {
        throw new RuntimeException('Package catalog mutation lost expiry or revocation state.');
    }

    $wrongOwnerRejected = false;
    try {
        $catalog->setExpiry($packageId, 'account:owner-b', null);
    } catch (RuntimeException) {
        $wrongOwnerRejected = true;
    }
    if (!$wrongOwnerRejected || $catalog->get($packageId)['expires_at'] === null) {
        throw new RuntimeException('Unauthorized catalog mutation was accepted.');
    }

    $unavailableRejected = false;
    try {
        $catalog->assertAvailable($packageId);
    } catch (RuntimeException) {
        $unavailableRejected = true;
    }
    if (!$unavailableRejected) {
        throw new RuntimeException('Revoked package remained available.');
    }

    echo "Package catalog mutation regression tests passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }
    @rmdir($directory);
}
