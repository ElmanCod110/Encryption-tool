<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageCatalog;
use SecurePackage\Security\PackageAccessTokenStore;
use SecurePackage\Security\WebSecurity;

$config = require dirname(__DIR__) . '/config/config.php';
WebSecurity::startSession();
WebSecurity::applyHeaders();

try {
    $token = (string) ($_GET['token'] ?? '');
    $store = new PackageAccessTokenStore($config['storage']['temp'] . DIRECTORY_SEPARATOR . 'download-tokens', $config['limits']['download_token_ttl_seconds']);
    $data = $store->consume($token);
    $packageId = (string) ($data['package_id'] ?? '');
    $record = (new PackageCatalog($config['storage']['catalog']))->get($packageId);
    if (($record['revoked_at'] ?? null) !== null || ($record['expires_at'] ?? null) !== null && (int) $record['expires_at'] < time()) throw new RuntimeException('Unavailable.');
    $file = $config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId . '.spkg14';
    if (!is_file($file)) {
        $legacy = $config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId . '.spkg';
        if (is_file($legacy)) $file = $legacy;
    }
    if (!is_file($file)) {
        $dir = $config['storage']['packages'] . DIRECTORY_SEPARATOR . $packageId;
        $file = $dir . DIRECTORY_SEPARATOR . $packageId . '.spkg14';
        if (!is_file($file)) $file = $dir . DIRECTORY_SEPARATOR . $packageId . '.spkg';
    }
    if (!is_file($file)) throw new RuntimeException('Unavailable.');
    $size = filesize($file);
    if ($size === false) throw new RuntimeException('Unavailable.');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $packageId . '.spkg14"');
    header('Content-Length: ' . $size);
    header('Content-Transfer-Encoding: binary');
    readfile($file);
} catch (Throwable) {
    http_response_code(404);
    echo 'Package is unavailable.';
}
