<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\PackageId;
use SecurePackage\Security\PackageAccessTokenStore;
use SecurePackage\Security\WebSecurity;
$config = require dirname(__DIR__) . '/config/config.php';
WebSecurity::startSession(); WebSecurity::applyHeaders();
try {
    $store = new PackageAccessTokenStore($config['storage']['temp'] . DIRECTORY_SEPARATOR . 'download-tokens', $config['limits']['download_token_ttl_seconds']);
    $data = $store->consume((string) ($_GET['token'] ?? ''));
    $packageId = (string) ($data['package_id'] ?? '');
    PackageId::assert($packageId);
    $record = (new PackageCatalog($config['storage']['catalog']))->get($packageId);
    if (($record['revoked_at'] ?? null) !== null || (($record['expires_at'] ?? null) !== null && (int) $record['expires_at'] <= time())) throw new RuntimeException('Unavailable.');
    $file = $config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId . '.spkg';
    if (is_link($file) || !is_file($file)) throw new RuntimeException('Unavailable.');
    $size = filesize($file); if ($size === false) throw new RuntimeException('Unavailable.');
    header('Content-Type: application/octet-stream'); header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, private'); header('Content-Disposition: attachment; filename="' . $packageId . '.spkg"');
    header('Content-Length: ' . $size); header('Content-Transfer-Encoding: binary'); readfile($file);
} catch (Throwable) {
    http_response_code(404); header('Content-Type: text/plain; charset=utf-8'); echo 'Package is unavailable.';
}
