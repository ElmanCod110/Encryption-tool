<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Archive\ArchivePolicy;
use SecurePackage\Archive\ArchiveWorkflow;
use SecurePackage\Storage\JobStore;

if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
    throw new RuntimeException('The archive depth test requires ext-zip.');
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-archive-depth-' . bin2hex(random_bytes(8));
if (!mkdir($root, 0700, true)) {
    throw new RuntimeException('Unable to create test directory.');
}

try {
    $innerPath = $root . DIRECTORY_SEPARATOR . 'inner.zip';
    $inner = new ZipArchive();
    if ($inner->open($innerPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create nested test archive.');
    }
    $inner->addFromString('payload.txt', 'nested payload');
    $inner->close();

    $outerPath = $root . DIRECTORY_SEPARATOR . 'outer.zip';
    $outer = new ZipArchive();
    if ($outer->open($outerPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create root test archive.');
    }
    $outer->addFile($innerPath, 'inner.zip');
    $outer->close();

    $jobs = new JobStore($root . DIRECTORY_SEPARATOR . 'jobs');
    $workflow = new ArchiveWorkflow(
        $jobs,
        new ArchivePolicy(maxEntries: 10, maxSingleFileBytes: 4096, maxTotalUncompressedBytes: 8192, maxDepth: 0, maxNestedArchives: 4)
    );
    $job = $workflow->initialize($outerPath);
    $archiveId = $job['state']['pending'][0]['id'];

    $rejected = false;
    try {
        $workflow->process($job['job_id'], $archiveId, '');
    } catch (RuntimeException $error) {
        $rejected = str_contains($error->getMessage(), 'Unable to extract archive.');
    }
    if (!$rejected) {
        throw new RuntimeException('ArchiveWorkflow accepted nesting beyond maxDepth.');
    }

    echo "Archive workflow depth test passed.\n";
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
