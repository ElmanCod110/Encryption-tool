<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Storage\JobStore;
use SecurePackage\Storage\JobNotAvailableException;

$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-job-store-integrity-' . bin2hex(random_bytes(8));
$root = $base . DIRECTORY_SEPARATOR . 'jobs';
$outside = $base . DIRECTORY_SEPARATOR . 'outside';
if (!mkdir($base, 0700, true) || !mkdir($outside, 0700, true)) {
    throw new RuntimeException('Unable to create job-store test fixture.');
}

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
    $store = new JobStore($root);
    $job = $store->create('owner-token');
    $jobPath = $job['path'];
    $id = $job['id'];

    if (!is_dir($jobPath . DIRECTORY_SEPARATOR . 'source')
        || !is_dir($jobPath . DIRECTORY_SEPARATOR . 'archives')) {
        throw new RuntimeException('Job creation did not initialize required directories.');
    }
    if (($store->readState($id)['owner_hash'] ?? null) !== hash('sha256', 'owner-token')) {
        throw new RuntimeException('Created job owner state is inconsistent.');
    }

    $store->writeState($id, [
        'status' => 'processing',
        'created_at' => 1,
        'owner_hash' => hash('sha256', 'owner-token'),
    ]);
    if (($store->readState($id)['status'] ?? null) !== 'processing') {
        throw new RuntimeException('Job state update did not commit the complete replacement.');
    }

    $outsideFile = $outside . DIRECTORY_SEPARATOR . 'preserve.txt';
    file_put_contents($outsideFile, 'outside data must survive');
    $nestedLink = $jobPath . DIRECTORY_SEPARATOR . 'source' . DIRECTORY_SEPARATOR . 'outside-link';
    if (@symlink($outside, $nestedLink)) {
        $store->remove($id);
        if (file_exists($jobPath) || is_link($jobPath)) {
            throw new RuntimeException('Job cleanup left owned storage behind.');
        }
        if (!is_file($outsideFile) || file_get_contents($outsideFile) !== 'outside data must survive') {
            throw new RuntimeException('Job cleanup followed a nested symlink.');
        }
    } else {
        $store->remove($id);
        if (file_exists($jobPath) || is_link($jobPath)) {
            throw new RuntimeException('Job cleanup failed without symlink support.');
        }
    }

    $missingRejected = false;
    try {
        $store->readState($id);
    } catch (JobNotAvailableException) {
        $missingRejected = true;
    }
    if (!$missingRejected) {
        throw new RuntimeException('Removed job remained available.');
    }

    $corrupt = $store->create('corrupt-owner');
    if (file_put_contents($corrupt['path'] . DIRECTORY_SEPARATOR . 'state.json', '{"broken":') === false) {
        throw new RuntimeException('Unable to prepare corrupt job state fixture.');
    }
    $corruptRejected = false;
    try {
        $store->readState($corrupt['id']);
    } catch (RuntimeException $exception) {
        $corruptRejected = str_contains($exception->getMessage(), 'corrupt')
            || str_contains($exception->getMessage(), 'identity');
    }
    if (!$corruptRejected) {
        throw new RuntimeException('Corrupt job state was silently accepted.');
    }

    $invalidIdentifierRejected = false;
    try {
        $store->remove('../outside');
    } catch (RuntimeException) {
        $invalidIdentifierRejected = true;
    }
    if (!$invalidIdentifierRejected) {
        throw new RuntimeException('Invalid job identifier was accepted for cleanup.');
    }

    echo "Job store integrity tests passed.\n";
} finally {
    $removeTree($base);
}
