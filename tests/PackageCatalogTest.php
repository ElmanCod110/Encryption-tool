<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\PackageId;
use SecurePackage\Project\PackageNotAvailableException;

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'securepkg-catalog-test-' . bin2hex(random_bytes(6));
$id = PackageId::generate();
$catalog = new PackageCatalog($root);

$removeTree = static function (string $path) use (&$removeTree): void {
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) return;
    foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) {
        $removeTree($entry->getPathname());
    }
    @rmdir($path);
};

try {
    $catalog->create($id, 'account:a', 'demo');
    $catalog->setExpiry($id, 'account:a', time() + 3600);

    $wrongOwnerFailure = null;
    try {
        $catalog->assertOwner($id, 'account:b');
    } catch (PackageNotAvailableException $exception) {
        $wrongOwnerFailure = $exception;
    }
    if (!$wrongOwnerFailure instanceof PackageNotAvailableException) {
        throw new RuntimeException('Cross-owner catalog access was accepted.');
    }

    $missingFailure = null;
    try {
        $catalog->assertOwner(PackageId::generate(), 'account:a');
    } catch (PackageNotAvailableException $exception) {
        $missingFailure = $exception;
    }
    if (!$missingFailure instanceof PackageNotAvailableException) {
        throw new RuntimeException('Missing package did not use the privacy-preserving unavailable response.');
    }
    if (get_class($wrongOwnerFailure) !== get_class($missingFailure)
        || $wrongOwnerFailure->getMessage() !== $missingFailure->getMessage()) {
        throw new RuntimeException('Missing and unauthorized package lookups expose different failure details.');
    }

    $catalog->revoke($id, 'account:a');
    $record = $catalog->get($id);
    if ($record['revoked_at'] === null) {
        throw new RuntimeException('Package was not revoked.');
    }

    echo "Package catalog tests passed.\n";
} finally {
    $removeTree($root);
}
