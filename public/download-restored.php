<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\RestoreArchive;
use SecurePackage\Security\RestoreTokenStore;

$config = require dirname(__DIR__) . '/config/config.php';
$token = (string) ($_GET['token'] ?? '');

try {
    $store = new RestoreTokenStore(
        $config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-tokens',
        (int) $config['limits']['restore_ttl_seconds']
    );
    $directory = $store->consume($token);
    $archive = $config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-download-' . bin2hex(random_bytes(16)) . '.zip';
    (new RestoreArchive())->create($directory, $archive);

    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="restored-files.zip"');
    header('Content-Length: ' . filesize($archive));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    readfile($archive);
    @unlink($archive);
} catch (Throwable) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Restore token is invalid or expired.';
}
