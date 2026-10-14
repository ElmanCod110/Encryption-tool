<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Archive\ArchivePolicy;
use SecurePackage\Archive\ArchiveWorkflow;
use SecurePackage\Storage\JobStore;

if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
    throw new RuntimeException('Archive initialization cleanup test requires ext-zip.');
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-init-cleanup-' . bin2hex(random_bytes(8));
$jobsRoot = $root . DIRECTORY_SEPARATOR . 'jobs';
if (!mkdir($root, 0700, true)) throw new RuntimeException('Unable to create test root.');

try {
    $jobs = new JobStore($jobsRoot);
    $workflow = new ArchiveWorkflow($jobs, new ArchivePolicy());
    $rejected = false;
    try {
        $workflow->initialize($root . DIRECTORY_SEPARATOR . 'missing-input.zip');
    } catch (RuntimeException $error) {
        $rejected = str_contains($error->getMessage(), 'Unable to initialize archive job.');
    }
    if (!$rejected) throw new RuntimeException('Missing upload did not fail initialization as expected.');
    $remaining = is_dir($jobsRoot) ? iterator_count(new FilesystemIterator($jobsRoot, FilesystemIterator::SKIP_DOTS)) : 0;
    if ($remaining !== 0) throw new RuntimeException('Failed initialization left an abandoned job directory.');

    echo "Archive initialization cleanup tests passed.\n";
} finally {
    if (is_dir($jobsRoot)) @rmdir($jobsRoot);
    @rmdir($root);
}
