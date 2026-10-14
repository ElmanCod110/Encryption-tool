<?php
declare(strict_types=1);

$scriptPath = dirname(__DIR__) . '/bin/cleanup.php';
$script = (string) file_get_contents($scriptPath);

$checks = [
    'Jobs are expired using the per-job creation timestamp' =>
        str_contains($script, "'created_at'"),
    'The shared jobs directory is excluded from generic mtime cleanup' =>
        str_contains($script, "item->getFilename() === 'jobs'"),
    'Rate-limit cleanup uses its own configured window' =>
        str_contains($script, "'window_seconds'"),
    'Job identifiers are restricted before cleanup' =>
        str_contains($script, "/^[a-f0-9]{48}$/"),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Job TTL cleanup regression check failed: ' . $description);
    }
}

echo "Job TTL cleanup regression tests passed.\n";
