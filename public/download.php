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
    $root = $config['storage']['packages'];
    $stable = $root . DIRECTORY_SEPARATOR . $packageId . '.spkg';
    $legacyArchive = $root . DIRECTORY_SEPARATOR . $packageId . '.spkg14';
    $legacyDirectory = $root . DIRECTORY_SEPARATOR . $packageId;
    if (file_exists($stable) || is_link($stable)) {
        if (is_link($stable) || !is_file($stable)) throw new RuntimeException('Unavailable.');
        $file = $stable;
        $downloadName = $packageId . '.spkg';
    } elseif (file_exists($legacyArchive) || is_link($legacyArchive)) {
        if (is_link($legacyArchive) || !is_file($legacyArchive)) throw new RuntimeException('Unavailable.');
        $file = $legacyArchive;
        $downloadName = $packageId . '.spkg14';
    } elseif (file_exists($legacyDirectory) || is_link($legacyDirectory)) {
        if (is_link($legacyDirectory) || !is_dir($legacyDirectory)) throw new RuntimeException('Unavailable.');
        $file = $legacyDirectory . DIRECTORY_SEPARATOR . $packageId . '.spkg14';
        if (!file_exists($file) && !is_link($file)) {
            $file = $legacyDirectory . DIRECTORY_SEPARATOR . $packageId . '.spkg';
        }
        if (is_link($file) || !is_file($file)) throw new RuntimeException('Unavailable.');
        $downloadName = str_ends_with($file, '.spkg14') ? $packageId . '.spkg14' : $packageId . '.spkg';
    } else {
        throw new RuntimeException('Unavailable.');
    }
    $size = filesize($file);
    if ($size === false) throw new RuntimeException('Unavailable.');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $downloadName . '"');
    header('Content-Length: ' . $size);
    header('Content-Transfer-Encoding: binary');
    readfile($file);
} catch (Throwable) {
    http_response_code(404);
    echo 'Package is unavailable.';
}
