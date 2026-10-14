<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\RestoreArchive;
use SecurePackage\Security\RestoreTokenStore;

$config = require dirname(__DIR__) . '/config/config.php';
$token = (string) ($_GET['token'] ?? '');
$directory = null;
$archive = null;
$downloadComplete = false;

$removeTree = static function (?string $path): void {
    if ($path === null || $path === '') return;
    if (is_link($path) || !is_dir($path)) {
        if (file_exists($path) || is_link($path)) @unlink($path);
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $itemPath = $item->getPathname();
        if ($item->isLink() || !$item->isDir()) {
            @unlink($itemPath);
        } else {
            @rmdir($itemPath);
        }
    }
    @rmdir($path);
};

try {
    $store = new RestoreTokenStore(
        $config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-tokens',
        (int) $config['limits']['restore_ttl_seconds']
    );
    $candidateDirectory = $store->resolve($token);

    // Validate the token target before allowing cleanup to touch the directory.
    $tempRoot = realpath($config['storage']['temp']);
    $restorePath = realpath($candidateDirectory);
    if ($tempRoot === false || $restorePath === false
        || dirname($restorePath) !== $tempRoot
        || !str_starts_with(basename($restorePath), 'restore-')
        || is_link($candidateDirectory)) {
        throw new RuntimeException('Restore directory is invalid.');
    }
    $directory = $restorePath;

    $archive = $config['storage']['temp'] . DIRECTORY_SEPARATOR . 'restore-download-' . bin2hex(random_bytes(16)) . '.zip';
    (new RestoreArchive())->create($directory, $archive);

    // Consume only after archive creation succeeds, so disk/ZIP failures do not
    // invalidate the only download token or erase the restored plaintext.
    $consumedDirectory = realpath($store->consume($token));
    if ($consumedDirectory === false || !hash_equals($restorePath, $consumedDirectory)) {
        throw new RuntimeException('Restore token is invalid or expired.');
    }

    $archiveSize = filesize($archive);
    if ($archiveSize === false) throw new RuntimeException('Unable to read restored archive.');
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="restored-files.zip"');
    header('Content-Length: ' . $archiveSize);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    $bytesSent = readfile($archive);
    $downloadComplete = $bytesSent !== false && $bytesSent === $archiveSize;
} catch (Throwable) {
    if (!headers_sent()) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
    }
    echo 'Restore token is invalid or expired.';
} finally {
    $removeTree($archive);
    // Keep plaintext available if archive creation or streaming fails. The token
    // remains usable when archive creation fails; failed streams preserve data for
    // operational recovery rather than deleting the only restored copy.
    if ($downloadComplete) $removeTree($directory);
}
