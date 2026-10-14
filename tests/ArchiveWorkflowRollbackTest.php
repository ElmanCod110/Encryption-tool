<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Archive\ArchivePolicy;
use SecurePackage\Archive\ArchiveWorkflow;
use SecurePackage\Storage\JobStore;

if (!extension_loaded('zip') || !class_exists(ZipArchive::class)) {
    throw new RuntimeException('Zip extension is required for archive rollback test.');
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-archive-rollback-' . bin2hex(random_bytes(6));
$zipPath = $root . DIRECTORY_SEPARATOR . 'fixture.zip';
if (!mkdir($root, 0700, true)) {
    throw new RuntimeException('Unable to create archive rollback fixture.');
}

$zip = new ZipArchive();
if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    throw new RuntimeException('Unable to create archive rollback ZIP.');
}
$zip->addFromString('a.txt', 'new a');
$zip->addFromString('z.txt', 'new z');
$zip->close();

$jobs = new JobStore($root . DIRECTORY_SEPARATOR . 'jobs');
$workflow = new ArchiveWorkflow($jobs, new ArchivePolicy(100, 1024 * 1024, 4 * 1024 * 1024, 3, 10));
$jobId = null;

try {
    $initialized = $workflow->initialize($zipPath);
    $jobId = $initialized['job_id'];
    $archiveId = $initialized['state']['pending'][0]['id'];
    $source = $jobs->path($jobId) . DIRECTORY_SEPARATOR . 'source';
    file_put_contents($source . DIRECTORY_SEPARATOR . 'z.txt', 'keep existing');

    try {
        $workflow->process($jobId, $archiveId, '');
        throw new RuntimeException('Expected archive output collision was not rejected.');
    } catch (RuntimeException $exception) {
        if (!str_contains($exception->getMessage(), 'Unable to extract archive')) {
            throw $exception;
        }
    }

    if (file_exists($source . DIRECTORY_SEPARATOR . 'a.txt')) {
        throw new RuntimeException('Failed archive processing left partially merged output.');
    }
    if (file_get_contents($source . DIRECTORY_SEPARATOR . 'z.txt') !== 'keep existing') {
        throw new RuntimeException('Failed archive processing altered pre-existing source data.');
    }
    $state = $jobs->readState($jobId);
    if (($state['status'] ?? null) !== 'awaiting_archive_password'
        || count($state['pending'] ?? []) !== 1
        || ($state['pending'][0]['id'] ?? null) !== $archiveId) {
        throw new RuntimeException('Failed archive processing incorrectly committed job state.');
    }

    echo "Archive rollback regression test passed.\n";
} finally {
    if (is_string($jobId)) {
        try { $jobs->remove($jobId); } catch (Throwable) {}
    }
    $remove = static function (string $path) use (&$remove): void {
        if (is_link($path) || is_file($path)) {
            @unlink($path);
            return;
        }
        if (!is_dir($path)) return;
        foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) {
            $remove($entry->getPathname());
        }
        @rmdir($path);
    };
    $remove($root);
}
