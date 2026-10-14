<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Archive\ArchivePolicy;
use SecurePackage\Archive\ArchiveWorkflow;
use SecurePackage\Storage\JobStore;

if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
    throw new RuntimeException('The archive workflow policy test requires ext-zip.');
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-archive-policy-' . bin2hex(random_bytes(8));
if (!mkdir($root, 0700, true)) {
    throw new RuntimeException('Unable to create test directory.');
}

try {
    $inputZip = $root . DIRECTORY_SEPARATOR . 'unsafe.zip';
    $zip = new ZipArchive();
    if ($zip->open($inputZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create test archive.');
    }
    $zip->addFromString('folder:alternate-stream.txt', 'test');
    $zip->close();

    $jobs = new JobStore($root . DIRECTORY_SEPARATOR . 'jobs');
    $workflow = new ArchiveWorkflow(
        $jobs,
        new ArchivePolicy(maxEntries: 10, maxSingleFileBytes: 1024, maxTotalUncompressedBytes: 4096)
    );
    $job = $workflow->initialize($inputZip);
    $archiveId = $job['state']['pending'][0]['id'];

    $rejected = false;
    try {
        $workflow->process($job['job_id'], $archiveId, '');
    } catch (RuntimeException $error) {
        $rejected = str_contains($error->getMessage(), 'Unable to extract archive.');
    }
    if (!$rejected) {
        throw new RuntimeException('ArchiveWorkflow accepted a path rejected by ArchivePolicy.');
    }

    echo "Archive workflow policy integration test passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isLink() || !$item->isDir()) {
            unlink($item->getPathname());
        } else {
            rmdir($item->getPathname());
        }
    }
    rmdir($root);
}
