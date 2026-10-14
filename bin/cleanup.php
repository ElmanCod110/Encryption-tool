#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';
$config = require dirname(__DIR__) . '/config/config.php';
$jobTtl = max(60, (int) ($config['limits']['job_ttl_seconds'] ?? 3600));
$roots = [
    $config['storage']['temp'],
    $config['storage']['rate_limits'],
];
$now = time();
$removed = 0;

// Expire each job using its own creation timestamp, not the shared jobs/ directory mtime.
$jobRoot = $config['storage']['temp'] . DIRECTORY_SEPARATOR . 'jobs';
if (is_dir($jobRoot) && !is_link($jobRoot)) {
    $jobs = new FilesystemIterator($jobRoot, FilesystemIterator::SKIP_DOTS);
    foreach ($jobs as $job) {
        $jobId = $job->getFilename();
        if (!preg_match('/^[a-f0-9]{48}$/', $jobId) || !$job->isDir() || $job->isLink()) continue;

        $jobPath = $job->getPathname();
        $statePath = $jobPath . DIRECTORY_SEPARATOR . 'state.json';
        $state = is_file($statePath) ? json_decode((string) @file_get_contents($statePath), true) : null;
        $createdAt = is_array($state) ? (int) ($state['created_at'] ?? 0) : 0;
        if ($createdAt <= 0) $createdAt = (int) @filemtime($statePath);
        if ($createdAt <= 0) $createdAt = $job->getMTime();
        if ($now - $createdAt <= $jobTtl) continue;

        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($jobPath, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $child) {
            if ($child->isLink() || !$child->isDir()) {
                @unlink($child->getPathname());
            } else {
                @rmdir($child->getPathname());
            }
        }
        @rmdir($jobPath);
        if (!file_exists($jobPath) && !is_link($jobPath)) $removed++;
    }
}

foreach ($roots as $root) {
    if (!is_dir($root)) continue;
    $isRateLimitRoot = $root === $config['storage']['rate_limits'];
    $maxAge = $isRateLimitRoot
        ? max(60, (int) ($config['rate_limit']['window_seconds'] ?? 900))
        : $jobTtl;
    $iterator = new FilesystemIterator($root, FilesystemIterator::SKIP_DOTS);
    foreach ($iterator as $item) {
        if ($item->getFilename() === '.gitkeep') continue;
        // Jobs are handled individually above so one old parent mtime cannot delete active jobs.
        if (!$isRateLimitRoot && $item->getFilename() === 'jobs') continue;
        if ($item->isLink()) {
            if ($item->getMTime() <= $now - $maxAge && @unlink($item->getPathname())) $removed++;
            continue;
        }
        if ($item->getMTime() > $now - $maxAge) continue;
        if ($item->isDir()) {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($item->getPathname(), FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $child) {
                if ($child->isLink() || !$child->isDir()) {
                    @unlink($child->getPathname());
                } else {
                    @rmdir($child->getPathname());
                }
            }
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
        $removed++;
    }
}
echo "Removed {$removed} stale storage entries.\n";
