<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Api\JsonResponse;
use SecurePackage\Api\PackageController;
use SecurePackage\Archive\ArchivePolicy;
use SecurePackage\Archive\ArchiveWorkflow;
use SecurePackage\Security\AccountStore;
use SecurePackage\Security\PackageAccessTokenStore;
use SecurePackage\Security\RateLimiter;
use SecurePackage\Security\WebSecurity;
use SecurePackage\Project\PackageCatalog;
use SecurePackage\Storage\AuditLogger;
use SecurePackage\Storage\JobStore;
use SecurePackage\Storage\ResumableUploadStore;

$config = require dirname(__DIR__) . '/config/config.php';
WebSecurity::startSession();
WebSecurity::applyHeaders();

$jobs = new JobStore($config['storage']['temp'] . DIRECTORY_SEPARATOR . 'jobs');
$policy = new ArchivePolicy(
    $config['limits']['max_archive_entries'],
    $config['limits']['max_single_file_bytes'],
    $config['limits']['max_total_uncompressed_bytes'],
    $config['limits']['max_archive_depth'],
    $config['limits']['max_nested_archives']
);
$archives = new ArchiveWorkflow($jobs, $policy);
$limiter = new RateLimiter($config['storage']['rate_limits'], $config['rate_limit']['max_failures_per_window'], $config['rate_limit']['window_seconds']);
$uploads = new ResumableUploadStore($config['storage']['uploads'], $config['limits']['max_upload_bytes']);
$catalog = new PackageCatalog($config['storage']['catalog']);
$accessTokens = new PackageAccessTokenStore($config['storage']['temp'] . DIRECTORY_SEPARATOR . 'download-tokens', $config['limits']['download_token_ttl_seconds']);
$accounts = new AccountStore($config['storage']['accounts'] . DIRECTORY_SEPARATOR . 'users.json');
$audit = new AuditLogger($config['storage']['audit'] . DIRECTORY_SEPARATOR . 'events.jsonl');
$controller = new PackageController($config, $jobs, $limiter, $archives, $uploads, $catalog, $accessTokens, $accounts, $audit);

try {
    switch ((string) ($_GET['action'] ?? '')) {
        case 'me': $controller->me();
        case 'register': $controller->register();
        case 'login': $controller->login();
        case 'logout': $controller->logout();
        case 'upload-init': $controller->uploadInit();
        case 'upload-chunk': $controller->uploadChunk();
        case 'upload-complete': $controller->uploadComplete();
        case 'archive-step': $controller->archiveStep();
        case 'build': $controller->build();
        case 'decrypt': $controller->decrypt();
        case 'packages': $controller->listPackages();
        case 'access-token': $controller->accessToken();
        case 'set-expiry': $controller->setExpiry();
        case 'revoke': $controller->revoke();
        case 'csrf': JsonResponse::send(['ok' => true, 'csrf' => WebSecurity::csrfToken()]);
        default: JsonResponse::send(['ok' => false, 'error' => 'Unknown action.'], 404);
    }
} catch (Throwable) {
    JsonResponse::send(['ok' => false, 'error' => 'Request failed.'], 400);
}
