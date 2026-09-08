<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use TCH\Api\JsonResponse;
use TCH\Api\PackageController;
use TCH\Archive\ArchivePolicy;
use TCH\Archive\ArchiveWorkflow;
use TCH\Security\RateLimiter;
use TCH\Security\WebSecurity;
use TCH\Storage\JobStore;

$config = require dirname(__DIR__) . '/config/config.php';
WebSecurity::startSession();
WebSecurity::csrfToken();

$jobs = new JobStore($config['storage']['temp'] . DIRECTORY_SEPARATOR . 'jobs');
$policy = new ArchivePolicy(
    $config['limits']['max_archive_entries'],
    $config['limits']['max_single_file_bytes'],
    $config['limits']['max_total_uncompressed_bytes'],
    $config['limits']['max_archive_depth'],
    $config['limits']['max_nested_archives']
);
$archives = new ArchiveWorkflow($jobs, $policy);
$limiter = new RateLimiter(
    $config['storage']['temp'] . DIRECTORY_SEPARATOR . 'rate',
    $config['rate_limit']['max_failures_per_window'],
    $config['rate_limit']['window_seconds']
);
$controller = new PackageController($config, $jobs, $limiter, $archives);

try {
    switch ((string) ($_GET['action'] ?? '')) {
        case 'upload': $controller->upload();
        case 'archive-step': $controller->archiveStep();
        case 'build': $controller->build();
        case 'decrypt': $controller->decrypt();
        case 'csrf': JsonResponse::send(['ok' => true, 'csrf' => WebSecurity::csrfToken()]);
        default: JsonResponse::send(['ok' => false, 'error' => 'Unknown action.'], 404);
    }
} catch (Throwable $e) {
    JsonResponse::send(['ok' => false, 'error' => 'Request failed.'], 400);
}
