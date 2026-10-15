<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageDeletionTransaction;
use SecurePackage\Project\PackageStorageException;

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-delete-transaction-' . bin2hex(random_bytes(8));
if (!mkdir($root, 0700, true)) {
    throw new RuntimeException('Unable to create package-deletion test fixture.');
}

$removeTree = static function (string $path) use (&$removeTree): void {
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) {
        $removeTree($entry->getPathname());
    }
    @rmdir($path);
};

$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

try {
    // A catalog failure after access revocation must restore every staged representation.
    $portable = $root . DIRECTORY_SEPARATOR . 'rollback.spkg14';
    $packageDirectory = $root . DIRECTORY_SEPARATOR . 'rollback-package';
    file_put_contents($portable, 'portable package bytes');
    mkdir($packageDirectory, 0700);
    file_put_contents($packageDirectory . DIRECTORY_SEPARATOR . 'header.json', '{}');
    $revoked = false;
    $catalogFailureObserved = false;

    try {
        (new PackageDeletionTransaction())->execute(
            [$portable, $packageDirectory],
            static function () use (&$revoked): void { $revoked = true; },
            static function (): void { throw new RuntimeException('injected catalog deletion failure'); }
        );
    } catch (RuntimeException $exception) {
        $catalogFailureObserved = $exception->getMessage() === 'injected catalog deletion failure';
    }

    $assert($catalogFailureObserved, 'The injected catalog failure was not propagated.');
    $assert($revoked, 'Access-token revocation should occur after staging and before catalog deletion.');
    $assert(is_file($portable) && is_dir($packageDirectory), 'Catalog failure did not restore both package representations.');
    $assert(file_get_contents($portable) === 'portable package bytes', 'Rollback changed the portable package bytes.');
    $assert(file_get_contents($packageDirectory . DIRECTORY_SEPARATOR . 'header.json') === '{}', 'Rollback changed package-directory contents.');

    // A deterministic second-stage rename failure must roll back the first staged path
    // and must not revoke access or delete the catalog record.
    $portable2 = $root . DIRECTORY_SEPARATOR . 'stage-failure.spkg14';
    $packageDirectory2 = $root . DIRECTORY_SEPARATOR . 'stage-failure-package';
    file_put_contents($portable2, 'second portable package');
    mkdir($packageDirectory2, 0700);
    $failedSecondStage = false;
    $revocationAttempted = false;
    $catalogDeleteAttempted = false;
    $rename = static function (string $from, string $to) use ($packageDirectory2, &$failedSecondStage): bool {
        if ($from === $packageDirectory2 && !$failedSecondStage) {
            $failedSecondStage = true;
            return false;
        }
        return rename($from, $to);
    };
    $stageFailureObserved = false;

    try {
        (new PackageDeletionTransaction($rename))->execute(
            [$portable2, $packageDirectory2],
            static function () use (&$revocationAttempted): void { $revocationAttempted = true; },
            static function () use (&$catalogDeleteAttempted): void { $catalogDeleteAttempted = true; }
        );
    } catch (PackageStorageException) {
        $stageFailureObserved = true;
    }

    $assert($stageFailureObserved, 'The injected second-stage failure was not reported as a storage failure.');
    $assert(is_file($portable2) && is_dir($packageDirectory2), 'A stage failure did not restore the first staged representation.');
    $assert(!$revocationAttempted && !$catalogDeleteAttempted, 'Access/catalog mutation ran before all representations were staged.');

    // Post-commit cleanup must fail closed if a staged artifact remains on disk.
    $cleanupSource = $root . DIRECTORY_SEPARATOR . 'cleanup.spkg14';
    file_put_contents($cleanupSource, 'cleanup fixture');
    $staged = (new PackageDeletionTransaction())->execute(
        [$cleanupSource],
        static function (): void {},
        static function (): void {}
    );
    $cleanupFailureObserved = false;
    try {
        (new PackageDeletionTransaction())->cleanupCommitted($staged, static function (string $path): void {
            // Deliberately leave the artifact behind to simulate a cleanup failure.
        });
    } catch (PackageStorageException) {
        $cleanupFailureObserved = true;
    }
    $assert($cleanupFailureObserved, 'Post-commit cleanup did not report a leftover staged artifact.');
    $assert(isset($staged[0]) && is_file($staged[0]['staged']), 'Cleanup failure fixture was not left in the expected staged state.');

    echo "Package deletion transaction fault-injection tests passed.\n";
} finally {
    $removeTree($root);
}
